/* ===========================================================================
 * src/fhsm_pq_params.c
 *
 * CK_ML_DSA_PARAMS / CK_SLH_DSA_PARAMS parser : implementation.
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#include "fhsm_pq_params.h"

#include <string.h>

/* PKCS#11 CK_ULONG is exactly sizeof(unsigned long) on every 64-bit ABI
 * we target. The 24-byte struct described in the header header comment
 * lays out as three CK_ULONGs back to back. We re-derive the type
 * locally to avoid pulling in the full PKCS#11 header in this small
 * translation unit. */
typedef unsigned long fhsm_pq_ck_ulong;

void fhsm_parse_pq_params(const void *param_ptr, size_t param_len,
                          uint8_t *out_ctx, size_t out_ctx_cap,
                          size_t *out_ctx_len, int *out_have,
                          unsigned long *out_hedge_variant) {
    /* Default outputs : no parameter, no context, hedge unknown. */
    if (out_ctx_len)       *out_ctx_len       = 0;
    if (out_have)          *out_have          = 0;
    if (out_hedge_variant) *out_hedge_variant = 0;

    if (!param_ptr || param_len < 3 * sizeof(fhsm_pq_ck_ulong)) {
        return;
    }

    const fhsm_pq_ck_ulong *p = (const fhsm_pq_ck_ulong *)param_ptr;
    /* p[0] = hedgeVariant (recorded ; not applied)
     * p[1] = pContext (as integer-encoded pointer)
     * p[2] = ulContextLen */
    const unsigned long hedge   = p[0];
    const size_t        ctx_len = (size_t)p[2];
    const void *ctx_ptr = (const void *)(uintptr_t)p[1];

    if (out_hedge_variant) *out_hedge_variant = hedge;

    if (ctx_len == 0) {
        /* Explicit empty context is the same as the default ; record
         * "have" so the caller can distinguish "parsed empty" from
         * "absent" if desired. */
        if (out_have) *out_have = 1;
        return;
    }

    if (ctx_len > out_ctx_cap || !ctx_ptr) {
        /* FIPS 204 §5.2.1 and FIPS 205 §5.2.1 bound the context string
         * at 255 octets ; oversize values fall through to a "no
         * parameter" outcome, matching the original behavior in
         * src/fhsm_pkcs11.c. OpenSSL then receives no override and
         * itself rejects the eventual sign/verify. */
        return;
    }

    memcpy(out_ctx, ctx_ptr, ctx_len);
    if (out_ctx_len) *out_ctx_len = ctx_len;
    if (out_have)    *out_have    = 1;
}
