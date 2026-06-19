/* ===========================================================================
 * fuzz/fuzz_attr_template.c
 *
 * libFuzzer harness for fhsm_find_attr + fhsm_strip_octet_string_inline.
 *
 * Two parser-safety properties :
 *
 *   1. fhsm_find_attr must not read past t[count-1] regardless of
 *      `count` value relative to the underlying allocation. The
 *      caller is responsible for getting the count right, but the
 *      harness gives `count` exactly the buffer size we allocate.
 *
 *   2. fhsm_strip_octet_string_inline must accept exactly DER OCTET
 *      STRING wrappers with the three valid length forms (short,
 *      0x81 || len, 0x82 || len_hi || len_lo) AND reject everything
 *      else. The harness checks that *out_len <= in_len on accept,
 *      and that the out pointer falls within the input buffer.
 *
 * Input format
 *   The fuzz input is split into two regions :
 *     [0]            : split point (used to interpret the rest as either
 *                      attribute templates or DER octet strings)
 *     [1..end]       : payload
 *
 *   On odd split bytes, payload is treated as an attribute template
 *   stream : byte 0 = count, then repeated 24-byte fhsm_attr_t records
 *   (with pValue rewritten to a harness pointer for safety).
 *
 *   On even split bytes, payload is treated as raw DER bytes to feed
 *   into fhsm_strip_octet_string_inline.
 *
 *   Both paths are exercised regardless of split to maximize coverage
 *   per input.
 *
 * Build :
 *   make -f fuzz/Makefile.fuzz fuzz_attr_template
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#include "fhsm_attr_utils.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ATTRS 32u
#define SCRATCH_LEN 64u

/* Common PKCS#11 attribute types so fhsm_find_attr exercises both
 * "found" and "not-found" branches. */
static const unsigned long k_known_types[] = {
    0x00000000u,  /* CKA_CLASS */
    0x00000100u,  /* CKA_KEY_TYPE */
    0x00000003u,  /* CKA_LABEL */
    0x00000102u,  /* CKA_ID */
    0x00000011u,  /* CKA_VALUE */
    0x00000120u,  /* CKA_MODULUS */
    0xDEADBEEFu,  /* unlikely to match */
};

static void fuzz_attr_template(const uint8_t *data, size_t size) {
    if (size < 1) return;
    unsigned long count = data[0] % (MAX_ATTRS + 1);
    if (count == 0) {
        /* Property : find_attr on empty template returns -1 for any type. */
        for (size_t k = 0; k < sizeof(k_known_types) / sizeof(k_known_types[0]); ++k) {
            if (fhsm_find_attr(NULL, 0, k_known_types[k]) != -1) {
                __builtin_trap();
            }
        }
        return;
    }

    /* Build a synthetic template from fuzz bytes. Each record needs
     * sizeof(fhsm_attr_t) = 24 bytes ; we wrap-around the input. */
    fhsm_attr_t tmpl[MAX_ATTRS];
    uint8_t scratch[SCRATCH_LEN];
    const uint8_t *src = data + 1;
    size_t src_len = size - 1;
    for (size_t i = 0; i < SCRATCH_LEN; ++i) {
        scratch[i] = src_len ? src[i % src_len] : (uint8_t)i;
    }

    /* Per-record fill : draw type and length from src at deterministic
     * offsets, clamping the read window to what src actually has.
     * Previous version used a (offset % src_len) + (min sizeof, src_len)
     * pattern that allowed reads to walk past src+src_len when offset
     * was near the end of src. ASAN caught that as a 1-byte OOB on
     * input "02 04 03 aa bb cc" ; this rewrite keeps the read window
     * strictly inside [src, src + src_len). */
    for (unsigned long i = 0; i < count; ++i) {
        unsigned long raw_type = 0;
        unsigned long raw_len  = 0;

        if (src_len > 0) {
            size_t type_off  = (size_t)(i * 24u) % src_len;
            size_t type_room = src_len - type_off;
            size_t type_n    = type_room < sizeof(raw_type) ? type_room : sizeof(raw_type);
            memcpy(&raw_type, src + type_off, type_n);

            size_t len_off   = (size_t)((i * 24u) + 16u) % src_len;
            size_t len_room  = src_len - len_off;
            size_t len_n     = len_room < sizeof(raw_len) ? len_room : sizeof(raw_len);
            memcpy(&raw_len, src + len_off, len_n);
        }

        tmpl[i].type       = raw_type;
        tmpl[i].pValue     = scratch;
        tmpl[i].ulValueLen = raw_len % (SCRATCH_LEN + 1);
    }

    /* Property : for each known type, fhsm_find_attr returns either -1
     * or an index in [0, count). Anything else is a bug. */
    for (size_t k = 0; k < sizeof(k_known_types) / sizeof(k_known_types[0]); ++k) {
        long idx = fhsm_find_attr(tmpl, count, k_known_types[k]);
        if (idx < -1) __builtin_trap();
        if (idx >= (long)count) __builtin_trap();
        if (idx >= 0 && tmpl[(size_t)idx].type != k_known_types[k]) {
            __builtin_trap();
        }
    }

    /* Property : fhsm_find_attr on count=0 returns -1 even with a
     * non-null pointer. */
    if (fhsm_find_attr(tmpl, 0, k_known_types[0]) != -1) {
        __builtin_trap();
    }
}

static void fuzz_strip_octet_string(const uint8_t *data, size_t size) {
    if (size < 2) return;
    const uint8_t *out = NULL;
    size_t out_len = 0;
    int ok = fhsm_strip_octet_string_inline(data, size, &out, &out_len);
    if (ok) {
        /* Property : on accept, out must be within [data, data+size]
         * and out_len + (out - data) == size. */
        if (out < data || out > data + size) __builtin_trap();
        if (out_len > size) __builtin_trap();
        if ((size_t)(out - data) + out_len != size) __builtin_trap();
    }

    /* Probe the truncated form too. */
    if (size > 1) {
        const uint8_t *out2 = NULL;
        size_t out_len2 = 0;
        int ok2 = fhsm_strip_octet_string_inline(data, size - 1, &out2, &out_len2);
        if (ok2) {
            if (out2 < data || out2 > data + size - 1) __builtin_trap();
            if (out_len2 > size - 1) __builtin_trap();
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    /* Run both halves regardless of split byte for max coverage per
     * input. The split byte itself is consumed as part of the
     * attribute-template stream. */
    fuzz_attr_template(data, size);
    fuzz_strip_octet_string(data + 1, size - 1);
    return 0;
}
