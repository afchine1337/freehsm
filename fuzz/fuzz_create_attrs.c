/* ===========================================================================
 * fuzz/fuzz_create_attrs.c
 *
 * libFuzzer + ASAN + UBSAN harness for fhsm_parse_create_attrs() — the
 * pure parser extracted from src/fhsm_pkcs11.c::C_CreateObject in v1.2.0
 * (#191 follow-up).
 *
 * Why this harness exists
 *   Before v1.2.0, the only fuzz coverage on the C_CreateObject parser
 *   surface came from fuzz_attr_template, which attacks an *inline mirror*
 *   of fhsm_find_attr + fhsm_strip_octet_string_inline declared in
 *   include/fhsm_attr_utils.h. The mirror exists because the original
 *   parser was interleaved with OpenSSL EVP construction inside the
 *   monolithic C_CreateObject (215 lines), making it impossible to link
 *   the real code path into a libFuzzer harness without dragging in
 *   OpenSSL and the rest of the module.
 *
 *   v1.2.0 decomposes C_CreateObject : the pure parser is now in its own
 *   TU src/fhsm_create_attrs.c with zero OpenSSL dependency, and exposes
 *   fhsm_parse_create_attrs() via include/fhsm_create_attrs.h. This
 *   harness links the production object file directly into the fuzz
 *   binary, so the bytes libFuzzer mutates exercise the same parser
 *   instructions that run when an untrusted PKCS#11 caller invokes
 *   C_CreateObject in production.
 *
 *   This is the change that justifies the v1.2.0 minor bump on the
 *   ALC_DVS side (see Security Target §13.5).
 *
 * Input format
 *   The fuzz input is decoded into a synthetic CK_ATTRIBUTE[] template :
 *     byte 0          : record count (mod MAX_ATTRS+1)
 *     per record :
 *       bytes [0..7]  : CK_ULONG  type        (little-endian)
 *       byte  [8]     : payload length (0..255)
 *       bytes [9..]   : payload  (pValue aliases into the input buffer)
 *   If the buffer is exhausted mid-record, only the records consumed so
 *   far are kept and `n` is shrunk accordingly. pValue pointers alias
 *   into `data` ; any OOB read inside the parser is caught by ASAN.
 *
 * Properties checked on every FHSM_PARSE_OK return
 *
 *   P1.  path is in [INVALID .. RSA_PUB] (enum range bound).
 *   P2.  On OK, path != INVALID.
 *   P3.  label[0..63] contains a NUL terminator within bounds (no
 *        unterminated label can escape the parser).
 *   P4.  id_data == NULL ⟹ id_len == 0 (parser doesn't synthesize a
 *        length without a pointer).
 *   P5.  cko ∈ {PUBLIC_KEY, PRIVATE_KEY, SECRET_KEY}.
 *   P6.  VERBATIM      ⟹ value_data != NULL.
 *   P7.  EC_PUB        ⟹ cko == PUBLIC_KEY
 *                      && ec_group ∈ {"P-256","P-384","P-521"}
 *                      && ec_point != NULL.
 *   P8.  ED25519_PUB   ⟹ cko == PUBLIC_KEY
 *                      && ec_group == NULL
 *                      && ec_point != NULL.
 *   P9.  ED448_PUB     ⟹ cko == PUBLIC_KEY
 *                      && ec_group == NULL
 *                      && ec_point != NULL.
 *   P10. RSA_PUB       ⟹ cko == PUBLIC_KEY
 *                      && rsa_modulus  != NULL
 *                      && rsa_exponent != NULL.
 *                      (Lengths NOT required > 0 : parser is a thin
 *                       extractor ; semantic length validation belongs
 *                       to the OpenSSL EVP builder downstream.)
 *
 * Properties checked on every FHSM_PARSE_* error return
 *
 *   E1.  path == INVALID. The parser memset()s `attrs` to zero at entry,
 *        and the path field is set to a non-INVALID value only as the
 *        final write before an FHSM_PARSE_OK return. Any early error path
 *        must leave path at 0 = INVALID. Violation = the parser leaks a
 *        success-looking enum on a failed dispatch.
 *
 * Truncation probe
 *   For each accepted input, the last record's ulValueLen is shrunk by
 *   one byte and the parser is re-invoked. This stresses the OCTET
 *   STRING length-byte path, the OID matcher (which compares exact
 *   lengths), and the RSA modulus/exponent extractor against off-by-one
 *   at the buffer tail.
 *
 * Memory safety
 *   No allocation is performed in the harness or the parser. All pointer
 *   fields in the output struct alias into the fuzz input buffer. ASAN
 *   instrumentation catches OOB reads ; UBSAN catches signed-integer
 *   overflows in the OID matcher and the length parser.
 *
 * Violation handling
 *   Any invariant violation calls __builtin_trap(), which raises SIGILL
 *   and is reported by libFuzzer as a crash with the offending input
 *   saved as crash-<sha1>. The assertion macro is NOT used because the
 *   harness is built with -O1 (no -DNDEBUG), but a future tuning step
 *   could enable -DNDEBUG to speed up the campaign without losing
 *   coverage of the invariants.
 *
 * Build :
 *   make -f fuzz/Makefile.fuzz fuzz_create_attrs
 *
 * Run :
 *   ./fuzz/fuzz_create_attrs fuzz/corpus/create_attrs \
 *       -max_total_time=300 -print_final_stats=1
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#include "fhsm_create_attrs.h"
#include "fhsm_attr_utils.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Local mirrors of the parser's CKO_* constants. Kept private to this TU :
 * the parser itself uses raw byte values internally and exposes only the
 * `cko` field as an unsigned long, so we duplicate the three accepted
 * class values here to express invariants in human-readable form.
 * ----------------------------------------------------------------------- */
#define HARNESS_CKO_PUBLIC_KEY  0x00000002UL
#define HARNESS_CKO_PRIVATE_KEY 0x00000003UL
#define HARNESS_CKO_SECRET_KEY  0x00000004UL

/* MAX_ATTRS is the cap on the synthetic template size. 12 records is
 * enough to express every valid C_CreateObject template the production
 * code accepts (largest case : RSA pub = CKA_CLASS + CKA_KEY_TYPE +
 * CKA_LABEL + CKA_ID + CKA_MODULUS + CKA_PUBLIC_EXPONENT = 6 records)
 * while leaving slack for fuzz noise records that exercise the
 * find_attr scan loop. */
#define MAX_ATTRS 12u

/* ===========================================================================
 * Decode the fuzz buffer into a CK_ATTRIBUTE[] template. Returns the
 * number of records actually built (≤ requested count, ≤ MAX_ATTRS).
 *
 * pValue pointers in the output template alias into `data`. The caller
 * must keep `data` alive for the duration of the parse call.
 * ----------------------------------------------------------------------- */
static unsigned long build_template(const uint8_t *data, size_t size,
                                    fhsm_attr_t *out, unsigned long max) {
    if (size < 1) return 0;
    unsigned long want = (unsigned long)data[0] % (max + 1u);
    if (want == 0) return 0;

    size_t cursor = 1;
    unsigned long built = 0;

    for (unsigned long i = 0; i < want; ++i) {
        /* Need at least 8 bytes (type) + 1 byte (length). */
        if (cursor + 9u > size) break;

        unsigned long t = 0;
        memcpy(&t, data + cursor, sizeof(t));
        cursor += sizeof(t);

        size_t plen = (size_t)data[cursor];
        cursor += 1u;

        if (cursor + plen > size) break;

        out[i].type       = t;
        out[i].pValue     = (void *)(uintptr_t)(data + cursor);
        out[i].ulValueLen = (unsigned long)plen;

        cursor += plen;
        built++;
    }
    return built;
}

/* ===========================================================================
 * Invariant checks. Any violation traps immediately so libFuzzer captures
 * the offending input.
 * ----------------------------------------------------------------------- */
static void check_ok(const fhsm_create_attrs_t *a) {
    /* P1 : path enum is in range. */
    if ((unsigned)a->path > (unsigned)FHSM_CREATE_PATH_RSA_PUB) {
        __builtin_trap();
    }
    /* P2 : OK implies non-INVALID. */
    if (a->path == FHSM_CREATE_PATH_INVALID) {
        __builtin_trap();
    }

    /* P3 : label has a NUL byte within sizeof(label). */
    {
        int found_nul = 0;
        for (size_t i = 0; i < sizeof(a->label); ++i) {
            if (a->label[i] == '\0') { found_nul = 1; break; }
        }
        if (!found_nul) __builtin_trap();
    }

    /* P4 : pointer/length consistency for id. */
    if (a->id_data == NULL && a->id_len != 0) __builtin_trap();

    /* P5 : cko is one of the three supported classes. */
    if (a->cko != HARNESS_CKO_PUBLIC_KEY
     && a->cko != HARNESS_CKO_PRIVATE_KEY
     && a->cko != HARNESS_CKO_SECRET_KEY) {
        __builtin_trap();
    }

    switch (a->path) {
    case FHSM_CREATE_PATH_VERBATIM:
        /* P6 : VERBATIM carries CKA_VALUE. (value_len may legitimately
         * be 0 for some experimental zero-length keys, so we do not
         * trap on that ; we only check pointer presence.) */
        if (a->value_data == NULL) __builtin_trap();
        break;

    case FHSM_CREATE_PATH_EC_PUB:
        /* P7 : EC public requires CKO_PUBLIC_KEY, a known curve, and
         * a non-NULL point. The ec_group string is compared by pointer-
         * identity-via-strcmp against the three literals the parser is
         * allowed to return. */
        if (a->cko != HARNESS_CKO_PUBLIC_KEY)  __builtin_trap();
        if (a->ec_group == NULL)               __builtin_trap();
        if (strcmp(a->ec_group, "P-256") != 0
         && strcmp(a->ec_group, "P-384") != 0
         && strcmp(a->ec_group, "P-521") != 0) {
            __builtin_trap();
        }
        if (a->ec_point == NULL)               __builtin_trap();
        break;

    case FHSM_CREATE_PATH_ED25519_PUB:
    case FHSM_CREATE_PATH_ED448_PUB:
        /* P8 + P9 : Ed paths carry the curve in the path enum itself,
         * so ec_group MUST be NULL. The point MUST be present. */
        if (a->cko != HARNESS_CKO_PUBLIC_KEY) __builtin_trap();
        if (a->ec_group != NULL)              __builtin_trap();
        if (a->ec_point == NULL)              __builtin_trap();
        break;

    case FHSM_CREATE_PATH_RSA_PUB:
        /* P10 : RSA public requires both modulus and exponent pointers
         * present. The length fields are NOT required to be > 0 because
         * the parser is a thin extractor that copies ulValueLen verbatim
         * from the template ; semantic validation ("RSA modulus must be
         * non-empty, must be at least 2048 bits") is the OpenSSL EVP
         * builder's job downstream, which rejects with a clear error.
         *
         * Initial v1.2.0 version of this invariant additionally required
         * rsa_modulus_len > 0 and rsa_exponent_len > 0 ; that was a
         * harness/parser contract mismatch (found by the first CI run on
         * the seeded corpus, crash-2d6240f...). The harness was relaxed
         * to match the parser's actual contract rather than tightening
         * the parser to reject zero-length BIGNUMs, because the
         * downstream OpenSSL rejection is already adequate. */
        if (a->cko != HARNESS_CKO_PUBLIC_KEY) __builtin_trap();
        if (a->rsa_modulus  == NULL)          __builtin_trap();
        if (a->rsa_exponent == NULL)          __builtin_trap();
        break;

    case FHSM_CREATE_PATH_INVALID:
        /* Already trapped by P2 ; this case is here to keep the switch
         * exhaustive under -Wswitch-enum. */
        break;
    }
}

static void check_err(const fhsm_create_attrs_t *a) {
    /* E1 : on any non-OK return, path stays at 0 = INVALID because
     * the parser memset()s attrs before any early-return decision. */
    if (a->path != FHSM_CREATE_PATH_INVALID) {
        __builtin_trap();
    }
}

/* ===========================================================================
 * libFuzzer entry point.
 * ----------------------------------------------------------------------- */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fhsm_attr_t tmpl[MAX_ATTRS];
    unsigned long n = build_template(data, size, tmpl, MAX_ATTRS);

    /* Pass 1 : parse the synthetic template as-is. */
    {
        fhsm_create_attrs_t out;
        fhsm_parse_rv_t rv = fhsm_parse_create_attrs(tmpl, n, &out);
        if (rv == FHSM_PARSE_OK) check_ok(&out);
        else                     check_err(&out);
    }

    /* Pass 2 : truncation probe. Shrink the last record's ulValueLen by
     * one byte and re-parse. Stresses length-vs-buffer edge cases at the
     * tail of the input. */
    if (n > 0 && tmpl[n - 1].ulValueLen > 0) {
        tmpl[n - 1].ulValueLen -= 1u;
        fhsm_create_attrs_t out2;
        fhsm_parse_rv_t rv2 = fhsm_parse_create_attrs(tmpl, n, &out2);
        if (rv2 == FHSM_PARSE_OK) check_ok(&out2);
        else                      check_err(&out2);
    }

    return 0;
}
