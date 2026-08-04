/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm_composite.c --- Composite ML-DSA signature combiner (#112).
 *
 *  M' = Prefix || Label || len(ctx) || ctx || PH( M )
 *
 *  draft-ietf-lamps-pq-composite-sigs-19 §2.2 and §3.2. Validated against the
 *  worked examples of Appendix D, which are in the tree as
 *  kat/composite/mprime_appendix_d.txt and were reproduced before this file
 *  was written. See docs/COMPOSITE_SIGS_GAP.md for why that ordering matters.
 * ========================================================================= */

#include "fhsm_composite.h"

#include <openssl/evp.h>
#include <string.h>

/* Parameters from draft §6, which pulls them in from src/algParams.md upstream.
 *
 * The label is ASCII. §6: "Labels are represented here as ASCII strings, but
 * implementers MUST convert them to byte strings according to their ASCII
 * values prior to concatenating them with other byte values." The plausible
 * wrong reading is a DER encoding of the OID; it is not that. */
static const fhsm_composite_params_t g_params[] = {
    {
        .alg       = FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
        .name      = "id-MLDSA65-Ed25519-SHA512",
        .oid       = "1.3.6.1.5.5.7.6.48",
        .label     = "COMPSIG-MLDSA65-Ed25519-SHA512",
        .label_len = 30,
        .ph_name   = "SHA512",
        .ph_len    = 64,
    },
};

const fhsm_composite_params_t *fhsm_composite_params(fhsm_composite_alg_t alg) {
    for (size_t i = 0; i < sizeof(g_params) / sizeof(g_params[0]); ++i) {
        if (g_params[i].alg == alg) return &g_params[i];
    }
    return NULL;
}

size_t fhsm_composite_mprime_len(fhsm_composite_alg_t alg, size_t ctx_len) {
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    if (!p || ctx_len > FHSM_COMPOSITE_CTX_MAX) return 0;
    return FHSM_COMPOSITE_PREFIX_LEN + p->label_len + 1u + ctx_len + p->ph_len;
}

fhsm_rv_t fhsm_composite_mprime(fhsm_composite_alg_t alg,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *ctx, size_t ctx_len,
                                 uint8_t *out, size_t *out_len)
{
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    if (!p || !out || !out_len)          return FHSM_RV_ARGUMENTS_BAD;
    if (!msg && msg_len)                 return FHSM_RV_ARGUMENTS_BAD;
    if (!ctx && ctx_len)                 return FHSM_RV_ARGUMENTS_BAD;

    /* §3.2 step 1, and the reason len(ctx) is a single byte in §2.2. This is a
     * hard refusal, not a truncation: silently shortening an application's
     * context would change what gets signed without telling anyone. */
    if (ctx_len > FHSM_COMPOSITE_CTX_MAX) return FHSM_RV_DATA_LEN_RANGE;

    const size_t need = fhsm_composite_mprime_len(alg, ctx_len);
    if (need == 0)                       return FHSM_RV_ARGUMENTS_BAD;
    if (*out_len < need)                 { *out_len = need; return FHSM_RV_BUFFER_TOO_SMALL; }

    /* PH( M ). Computed straight into its final position so the digest is not
     * copied around; the layout below is written in draft order so the code
     * reads like the specification. */
    uint8_t *cur = out;

    memcpy(cur, FHSM_COMPOSITE_PREFIX, FHSM_COMPOSITE_PREFIX_LEN);
    cur += FHSM_COMPOSITE_PREFIX_LEN;

    memcpy(cur, p->label, p->label_len);
    cur += p->label_len;

    *cur++ = (uint8_t)ctx_len;              /* single unsigned byte, §2.2 */

    if (ctx_len) { memcpy(cur, ctx, ctx_len); cur += ctx_len; }

    unsigned int dlen = 0;
    EVP_MD *md = EVP_MD_fetch(NULL, p->ph_name, NULL);
    if (!md) return FHSM_RV_FUNCTION_FAILED;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_MD_free(md); return FHSM_RV_HOST_MEMORY; }

    int ok = EVP_DigestInit_ex(mdctx, md, NULL) == 1
          && (msg_len == 0 || EVP_DigestUpdate(mdctx, msg, msg_len) == 1)
          && EVP_DigestFinal_ex(mdctx, cur, &dlen) == 1;

    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);

    if (!ok || dlen != p->ph_len) {
        /* Leave nothing half-built behind: a partially written M' that a
         * caller ignored the return code on would sign the wrong thing. */
        memset(out, 0, need);
        return FHSM_RV_FUNCTION_FAILED;
    }

    *out_len = need;
    return FHSM_RV_OK;
}
