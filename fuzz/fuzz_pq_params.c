/* ===========================================================================
 * fuzz/fuzz_pq_params.c
 *
 * libFuzzer harness for fhsm_parse_pq_params (CK_ML_DSA_PARAMS /
 * CK_SLH_DSA_PARAMS parser, PKCS#11 v3.2 §6.18 / §6.19).
 *
 * Exercises the parser's bounds-check policy on a synthetic 24-byte
 * struct constructed from fuzz bytes :
 *
 *     [0..7]   hedgeVariant     (CK_ULONG)
 *     [8..15]  pContext         (CK_BYTE_PTR, encoded as integer)
 *     [16..23] ulContextLen     (CK_ULONG)
 *
 * The fuzzer cannot dereference an arbitrary user-controlled pointer
 * without SEGV'ing on every input. The harness therefore replaces
 * the pContext field with a pointer to a harness-owned scratch buffer
 * whose CONTENT is also drawn from the fuzz input. The
 * ulContextLen field is left fully fuzz-controlled so the parser's
 * bounds checks (len > 0, len <= cap, len == 0) are all exercised.
 *
 * Properties checked :
 *
 *   1. No crash, no leak, no out-of-bounds memcpy regardless of
 *      ulContextLen value.
 *
 *   2. When *out_have is non-zero, *out_ctx_len <= ctx_cap and the
 *      first *out_ctx_len bytes of out_ctx match the scratch buffer
 *      (i.e. the parser writes the right slice).
 *
 *   3. When *out_have is zero, *out_ctx_len is zero (the parser must
 *      not leave a partial context in the output).
 *
 * Build :
 *   make -f fuzz/Makefile.fuzz fuzz_pq_params
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#include "fhsm_pq_params.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define CTX_CAP 256u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need at least 24 bytes for the params struct + at least 1 byte
     * for the (optional) scratch buffer. */
    if (size < 24) return 0;

    /* Build a synthetic 24-byte CK_ML_DSA_PARAMS / CK_SLH_DSA_PARAMS
     * block. We copy the fuzz bytes into a local because the input
     * buffer is `const uint8_t *` and we want to rewrite p[1]
     * (pContext) to a harness-owned pointer. */
    unsigned long params[3];
    memcpy(params, data, 24);

    /* Harness-owned scratch buffer for the pContext field. Filled
     * with fuzz bytes (rotating if too short). */
    uint8_t scratch[CTX_CAP];
    const uint8_t *src = data + 24;
    size_t src_len = size - 24;
    for (size_t i = 0; i < CTX_CAP; ++i) {
        scratch[i] = src_len ? src[i % src_len] : (uint8_t)i;
    }

    /* Rewrite pContext to point at our scratch buffer. */
    params[1] = (unsigned long)(uintptr_t)scratch;
    /* params[2] = ulContextLen stays fuzz-controlled. */

    /* Call the parser. */
    uint8_t out_ctx[CTX_CAP];
    size_t out_ctx_len = 0;
    int out_have = 0;
    unsigned long out_hedge = 0;
    fhsm_parse_pq_params(params, sizeof(params),
                         out_ctx, sizeof(out_ctx),
                         &out_ctx_len, &out_have, &out_hedge);

    /* Property 2 : if "have" then "len <= cap" and the content matches
     * the first ctx_len bytes of scratch. */
    if (out_have) {
        if (out_ctx_len > sizeof(out_ctx)) __builtin_trap();
        if (out_ctx_len > 0 &&
            memcmp(out_ctx, scratch, out_ctx_len) != 0) {
            __builtin_trap();
        }
    } else {
        /* Property 3 : if not "have" then len must be zero. */
        if (out_ctx_len != 0) __builtin_trap();
    }

    /* Property 4 : the parser must record hedgeVariant verbatim when
     * the parameter block is large enough. */
    if (out_have && out_hedge != params[0]) {
        __builtin_trap();
    }

    /* Property 5 (negative test) : passing NULL or a too-small block
     * must always result in *out_have = 0. */
    int have2 = 1;
    size_t len2 = 99;
    unsigned long hedge2 = 0;
    fhsm_parse_pq_params(NULL, 0,
                         out_ctx, sizeof(out_ctx),
                         &len2, &have2, &hedge2);
    if (have2 != 0 || len2 != 0) __builtin_trap();

    have2 = 1;
    len2 = 99;
    fhsm_parse_pq_params(params, 23,    /* < 24 bytes : short block */
                         out_ctx, sizeof(out_ctx),
                         &len2, &have2, &hedge2);
    if (have2 != 0 || len2 != 0) __builtin_trap();

    return 0;
}
