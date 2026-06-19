/* ===========================================================================
 * fuzz/fuzz_ecdsa_raw.c
 *
 * libFuzzer harness for fhsm_ecdsa_der_to_raw / fhsm_ecdsa_raw_to_der.
 *
 * Exercises two properties :
 *
 *   1. Memory safety on adversarial DER inputs : fhsm_ecdsa_der_to_raw
 *      must not crash, leak, or read out of bounds when fed arbitrary
 *      bytes that claim to be a DER ECDSA-Sig-Value.
 *
 *   2. Round-trip closure on raw inputs : when we feed a 2*nlen-byte
 *      buffer through raw_to_der and then back through der_to_raw, we
 *      must recover the original bytes. Property holds for all
 *      well-formed raw r||s with components <= curve_order.
 *
 * Input format
 *   The fuzz input is sliced into three parts :
 *     [0]                    : nlen selector (0->32 / 1->48 / 2->66
 *                              for P-256 / P-384 / P-521)
 *     [1..2*nlen]            : raw r||s candidate
 *     [2*nlen+1..end]        : DER candidate
 *
 *   If the input is too short to carry both, we still run the safe
 *   path that fits.
 *
 * Build :
 *   make -f fuzz/Makefile.fuzz fuzz_ecdsa_raw
 *
 * Run :
 *   ./fuzz/fuzz_ecdsa_raw fuzz/corpus/ecdsa_raw \
 *       -max_total_time=300 -print_final_stats=1
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#include "fhsm_ecdsa_raw.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/crypto.h>

static size_t pick_nlen(uint8_t sel) {
    switch (sel % 3) {
        case 0:  return 32;   /* P-256 */
        case 1:  return 48;   /* P-384 */
        default: return 66;   /* P-521 */
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    const size_t nlen = pick_nlen(data[0]);
    const uint8_t *body = data + 1;
    const size_t   body_len = size - 1;

    /* --- Path A : DER-side fuzz. Feed an arbitrary buffer claiming
     *             to be a DER ECDSA-Sig-Value. fhsm_ecdsa_der_to_raw
     *             must not crash, leak, or read out of bounds. ----- */
    {
        uint8_t out[2 * 66];   /* big enough for P-521 */
        (void)fhsm_ecdsa_der_to_raw(body, body_len, nlen, out, sizeof(out));
    }

    /* --- Path B : raw-side round trip. Take the first 2*nlen bytes
     *             of the body (if available), pass through raw_to_der
     *             then der_to_raw, assert bit-equality. -------------- */
    if (body_len >= 2 * nlen) {
        uint8_t raw[2 * 66];
        memcpy(raw, body, 2 * nlen);

        uint8_t *der = NULL;
        size_t der_len = fhsm_ecdsa_raw_to_der(raw, 2 * nlen, nlen, &der);
        if (der_len > 0 && der != NULL) {
            uint8_t raw2[2 * 66];
            size_t got = fhsm_ecdsa_der_to_raw(der, der_len, nlen,
                                                raw2, sizeof(raw2));
            if (got != 0) {
                /* Round-trip must close bit-for-bit. */
                if (memcmp(raw, raw2, 2 * nlen) != 0) {
                    /* libFuzzer-friendly abort : __builtin_trap surfaces
                     * to the sanitizer with a clean stack. */
                    __builtin_trap();
                }
            }
            OPENSSL_free(der);
        }
    }

    /* --- Path C : truncated-DER probe. Same buffer as Path A but
     *             with the last byte chopped. Validates that the
     *             length-vs-buffer accounting is consistent. ---------- */
    if (body_len > 1) {
        uint8_t out[2 * 66];
        (void)fhsm_ecdsa_der_to_raw(body, body_len - 1, nlen,
                                     out, sizeof(out));
    }

    return 0;
}
