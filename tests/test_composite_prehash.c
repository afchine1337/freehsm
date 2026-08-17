/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * The prehashed path must be indistinguishable from the one-shot path.
 *
 * If it is not, a signature produced from a stream verifies against nothing --
 * and the defect only shows in use, on a file too large to appear in a test,
 * which is the worst place to find it.
 * ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "fhsm_composite.h"

#define ALG FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
static int fails = 0;
static void ck(const char *w, int c) { printf("  [%s] %s\n", c?"PASS":"FAIL", w); if(!c) fails++; }

/* SHA-512 in blocks, the way C_SignUpdate would. */
static int stream_digest(const uint8_t *m, size_t n, size_t chunk, uint8_t *out) {
    EVP_MD *md = EVP_MD_fetch(NULL, fhsm_composite_ph_name(ALG), NULL);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned int l = 0;
    int ok = md && c && EVP_DigestInit_ex(c, md, NULL) == 1;
    for (size_t off = 0; ok && off < n; off += chunk) {
        size_t k = (n - off < chunk) ? n - off : chunk;
        ok = EVP_DigestUpdate(c, m + off, k) == 1;
    }
    ok = ok && EVP_DigestFinal_ex(c, out, &l) == 1 && l == 64;
    EVP_MD_CTX_free(c); EVP_MD_free(md);
    return ok;
}

int main(void) {
    static uint8_t priv[FHSM_COMPOSITE_PRIV_MAX], pub[FHSM_COMPOSITE_PUB_MAX];
    size_t pl = sizeof priv, bl = sizeof pub;
    if (fhsm_composite_keygen(ALG, priv, &pl, pub, &bl) != FHSM_RV_OK) {
        printf("keygen failed\n"); return 1;
    }

    static uint8_t msg[300000];
    for (size_t i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 31 + 7);
    const uint8_t ctx[] = { 'f','h','s','m','-','s','i','g','n' };

    printf("== M': the two paths ==\n");
    for (size_t cl = 0; cl <= 9; cl += 9) {
        uint8_t a[512], b[512]; size_t la = sizeof a, lb = sizeof b;
        uint8_t ph[64];
        ck("digest computed in 4096-byte blocks", stream_digest(msg, sizeof msg, 4096, ph));
        fhsm_rv_t r1 = fhsm_composite_mprime(ALG, msg, sizeof msg, cl?ctx:NULL, cl, a, &la);
        fhsm_rv_t r2 = fhsm_composite_mprime_prehashed(ALG, ph, 64, cl?ctx:NULL, cl, b, &lb);
        char m[80]; snprintf(m, sizeof m, "M' identical byte for byte (ctx=%zu)", cl);
        ck(m, r1 == FHSM_RV_OK && r2 == FHSM_RV_OK && la == lb && memcmp(a, b, la) == 0);
    }

    printf("\n== signatures are interchangeable ==\n");
    {
        uint8_t ph[64];
        stream_digest(msg, sizeof msg, 1, ph);   /* one byte at a time: worst case */
        static uint8_t s1[FHSM_COMPOSITE_SIG_MAX], s2[FHSM_COMPOSITE_SIG_MAX];
        size_t l1 = sizeof s1, l2 = sizeof s2;
        ck("one-shot signature",
           fhsm_composite_sign(ALG, priv, pl, msg, sizeof msg, ctx, 9, s1, &l1) == FHSM_RV_OK);
        ck("prehashed signature",
           fhsm_composite_sign_prehashed(ALG, priv, pl, ph, 64, ctx, 9, s2, &l2) == FHSM_RV_OK);
        /* ML-DSA is randomised, so the bytes differ and that is expected.
         * What has to hold is cross-verification, in both directions. */
        ck("one-shot verified through the prehashed path",
           fhsm_composite_verify_prehashed(ALG, pub, bl, ph, 64, ctx, 9, s1, l1) == FHSM_RV_OK);
        ck("prehashed verified through the one-shot path",
           fhsm_composite_verify(ALG, pub, bl, msg, sizeof msg, ctx, 9, s2, l2) == FHSM_RV_OK);
        ck("a different context breaks verification",
           fhsm_composite_verify(ALG, pub, bl, msg, sizeof msg, ctx, 8, s2, l2) != FHSM_RV_OK);
        ph[0] ^= 1;
        ck("a modified digest breaks verification",
           fhsm_composite_verify_prehashed(ALG, pub, bl, ph, 64, ctx, 9, s1, l1) != FHSM_RV_OK);
    }

    printf("\n== a wrong pre-hash length is refused, not patched up ==\n");
    {
        uint8_t ph[64] = {0}, out[512]; size_t lo = sizeof out;
        ck("63 bytes refused",
           fhsm_composite_mprime_prehashed(ALG, ph, 63, NULL, 0, out, &lo) == FHSM_RV_ARGUMENTS_BAD);
        lo = sizeof out;
        ck("65 bytes refused",
           fhsm_composite_mprime_prehashed(ALG, ph, 65, NULL, 0, out, &lo) == FHSM_RV_ARGUMENTS_BAD);
        lo = sizeof out;
        ck("NULL refused",
           fhsm_composite_mprime_prehashed(ALG, NULL, 64, NULL, 0, out, &lo) == FHSM_RV_ARGUMENTS_BAD);
        ck("the pre-hash is named SHA512",
           strcmp(fhsm_composite_ph_name(ALG), "SHA512") == 0 && fhsm_composite_ph_len(ALG) == 64);
    }

    printf("\n%s\n", fails ? "FAILURES" : "all checks passed");
    return fails ? 1 : 0;
}
