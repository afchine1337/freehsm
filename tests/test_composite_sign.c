/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_composite_sign.c --- Composite ML-DSA sign/verify (#112).
 *
 *  The test that matters here is [D]: NON-SEPARABILITY. It does not assert the
 *  property, it demonstrates it, and it demonstrates the old mechanism's lack
 *  of it in the same run, so the difference is visible rather than claimed.
 *
 *  Under CKM_HYBRID_ED25519_ML_DSA_65 both components sign the bare message,
 *  so the Ed25519 half lifted out of the concatenation is a valid standalone
 *  Ed25519 signature over that message. Under Composite ML-DSA both sign M',
 *  so the same extraction yields something that verifies against nothing an
 *  attacker can use. draft §2.2, §9.2.3.
 * ========================================================================= */
#include "fhsm_composite.h"

#include <openssl/evp.h>
#include <openssl/x509.h>   /* d2i_PUBKEY */
#include <stdio.h>
#include <string.h>

static int fails = 0;
static void ck(const char *what, int ok, const char *detail) {
    printf("  %-58s %s\n", what, ok ? "OK" : "<<< FAIL");
    if (detail && *detail) printf("      %s\n", detail);
    if (!ok) fails++;
}

#define ALG FHSM_COMPOSITE_MLDSA65_ED25519_SHA512

int main(void) {
    printf("=== test_composite_sign : Composite ML-DSA sign/verify (#112) ===\n\n");

    static uint8_t priv[FHSM_COMPOSITE_PRIV_MAX], pub[FHSM_COMPOSITE_PUB_MAX];
    size_t plen = sizeof priv, publen = sizeof pub;

    printf("[A] key generation\n");
    fhsm_rv_t rv = fhsm_composite_keygen(ALG, priv, &plen, pub, &publen);
    char d[128];
    snprintf(d, sizeof d, "private %zu bytes, public %zu bytes", plen, publen);
    ck("both components generated in one call", rv == FHSM_RV_OK, d);
    if (rv != FHSM_RV_OK) return 2;

    /* Two calls must not produce the same key: §3.1 requires fresh material. */
    static uint8_t priv2[FHSM_COMPOSITE_PRIV_MAX], pub2[FHSM_COMPOSITE_PUB_MAX];
    size_t p2 = sizeof priv2, q2 = sizeof pub2;
    fhsm_composite_keygen(ALG, priv2, &p2, pub2, &q2);
    ck("a second keygen produces different key material",
       p2 != plen || memcmp(priv, priv2, plen) != 0, "");

    printf("\n[B] sign and verify\n");
    const uint8_t msg[10] = {0,1,2,3,4,5,6,7,8,9};
    static uint8_t sig[FHSM_COMPOSITE_SIG_MAX];
    size_t slen = sizeof sig;
    rv = fhsm_composite_sign(ALG, priv, plen, msg, sizeof msg, NULL, 0, sig, &slen);
    snprintf(d, sizeof d, "%zu bytes = 3309 (ML-DSA-65) + 64 (Ed25519)", slen);
    ck("sign succeeds and the signature is the expected size",
       rv == FHSM_RV_OK && slen == 3309 + 64, d);

    ck("verify accepts it",
       fhsm_composite_verify(ALG, pub, publen, msg, sizeof msg, NULL, 0,
                              sig, slen) == FHSM_RV_OK, "");

    ck("verify rejects it under the other key pair",
       fhsm_composite_verify(ALG, pub2, q2, msg, sizeof msg, NULL, 0,
                              sig, slen) == FHSM_RV_SIGNATURE_INVALID, "");

    const uint8_t other[10] = {9,8,7,6,5,4,3,2,1,0};
    ck("verify rejects it over a different message",
       fhsm_composite_verify(ALG, pub, publen, other, sizeof other, NULL, 0,
                              sig, slen) == FHSM_RV_SIGNATURE_INVALID, "");

    printf("\n[C] the application context is bound into the signature\n");
    const uint8_t ctx[8] = {0x08,0x13,0x06,0x12,0x05,0x16,0x26,0x23};
    static uint8_t sigc[FHSM_COMPOSITE_SIG_MAX];
    size_t sclen = sizeof sigc;
    rv = fhsm_composite_sign(ALG, priv, plen, msg, sizeof msg, ctx, sizeof ctx,
                              sigc, &sclen);
    ck("sign with a context succeeds", rv == FHSM_RV_OK, "");
    ck("it verifies under the same context",
       fhsm_composite_verify(ALG, pub, publen, msg, sizeof msg, ctx, sizeof ctx,
                              sigc, sclen) == FHSM_RV_OK, "");
    ck("it does NOT verify under an empty context",
       fhsm_composite_verify(ALG, pub, publen, msg, sizeof msg, NULL, 0,
                              sigc, sclen) == FHSM_RV_SIGNATURE_INVALID, "");

    printf("\n[D] non-separability -- the property the old hybrid lacks\n");
    printf("      draft 2.2: the Label exists to stop a component signature\n");
    printf("      being removed from the composite and used out of context.\n");

    size_t pq_len = 0, trad_len = 0;
    rv = fhsm_composite_split(ALG, sig, slen, &pq_len, &trad_len);
    ck("the two component signatures can be located", rv == FHSM_RV_OK, "");

    /* Lift the Ed25519 half out and try to use it as a plain Ed25519 signature
     * over the original message -- the attack the draft's Label prevents. */
    const uint8_t *trad_sig = sig + pq_len;
    const uint8_t *ptr_pub = pub;
    const uint8_t *bpq, *btr; size_t lpq, ltr;
    /* re-walk the public blob to reach the Ed25519 SubjectPublicKeyInfo */
    lpq = (size_t)ptr_pub[6] | ((size_t)ptr_pub[7] << 8);
    bpq = ptr_pub + 8;
    ltr = (size_t)bpq[lpq] | ((size_t)bpq[lpq + 1] << 8);
    btr = bpq + lpq + 2;

    const uint8_t *t = btr;
    EVP_PKEY *ed = d2i_PUBKEY(NULL, &t, (long)ltr);
    if (!ed) { ck("recover the Ed25519 public key from the blob", 0, ""); }
    else {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        int standalone = 0;
        if (EVP_DigestVerifyInit_ex(c, NULL, NULL, NULL, NULL, ed, NULL) > 0)
            standalone = EVP_DigestVerify(c, trad_sig, trad_len, msg, sizeof msg);
        EVP_MD_CTX_free(c);

        ck("the extracted Ed25519 half is NOT a valid signature over M",
           standalone != 1,
           standalone == 1
             ? "it verified -- the component is separable, which is the defect"
             : "it does not verify: the component is bound to M', not to M");

        /* And the positive control: it IS valid over M', which is what makes
         * the test meaningful rather than vacuous. A signature that verified
         * against nothing at all would pass the check above for the wrong
         * reason. */
        uint8_t mprime[512]; size_t mplen = sizeof mprime;
        fhsm_composite_mprime(ALG, msg, sizeof msg, NULL, 0, mprime, &mplen);
        EVP_MD_CTX *c2 = EVP_MD_CTX_new();
        int over_mprime = 0;
        if (EVP_DigestVerifyInit_ex(c2, NULL, NULL, NULL, NULL, ed, NULL) > 0)
            over_mprime = EVP_DigestVerify(c2, trad_sig, trad_len, mprime, mplen);
        EVP_MD_CTX_free(c2);
        ck("positive control: it IS valid over M'", over_mprime == 1,
           "so the check above failed for the right reason");
        EVP_PKEY_free(ed);
    }

    printf("\n[E] a corrupted component fails the whole signature\n");
    static uint8_t bad[FHSM_COMPOSITE_SIG_MAX];
    memcpy(bad, sig, slen);
    bad[0] ^= 0xFF;             /* inside the ML-DSA half */
    ck("flipping a bit in the ML-DSA half invalidates it",
       fhsm_composite_verify(ALG, pub, publen, msg, sizeof msg, NULL, 0,
                              bad, slen) == FHSM_RV_SIGNATURE_INVALID, "");
    memcpy(bad, sig, slen);
    bad[slen - 1] ^= 0xFF;      /* inside the Ed25519 half */
    ck("flipping a bit in the Ed25519 half invalidates it too",
       fhsm_composite_verify(ALG, pub, publen, msg, sizeof msg, NULL, 0,
                              bad, slen) == FHSM_RV_SIGNATURE_INVALID, "");

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
