/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * probe_hash_ml_dsa.c --- can OpenSSL 3.5 make HashML-DSA, and how?
 *
 * FreeHSM offers CKM_ML_DSA and none of the HashML-DSA mechanisms of
 * PKCS#11 v3.2 (CKM_HASH_ML_DSA, CKM_HASH_ML_DSA_<hash>). HashML-DSA is
 * FIPS 204 Algorithm 4: ML-DSA.Sign_internal over
 *
 *     M' = 0x01 || len(ctx) || ctx || OID(hash) || PH(M)
 *
 * where pure ML-DSA (Algorithm 2) signs M' = 0x00 || len(ctx) || ctx || M.
 * Before building it, three questions, asked of the default provider and of
 * the FIPS provider loaded the way the module loads it:
 *
 *   1. native  -- does an ML-DSA key take a digest name at
 *                 EVP_DigestSignInit, i.e. does OpenSSL do HashML-DSA itself?
 *   2. raw     -- does it take message-encoding = 0, i.e. sign M' as given
 *                 (Sign_internal)?
 *   3. framing -- with deterministic signing, is raw(0x00||len||ctx||M)
 *                 byte for byte the pure signature of M under ctx? If so,
 *                 building M' here is right, and HashML-DSA differs only in
 *                 the prefix and in OID || PH(M).
 *
 * A probe, not a test: it links OpenSSL alone and prints what it finds.
 *
 *   tests/probe_hash_ml_dsa            the default provider
 *   tests/probe_hash_ml_dsa fips       the FIPS provider (and base)
 * ========================================================================= */
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static void err_line(void) {
    unsigned long e = ERR_peek_last_error();
    char buf[200] = "";
    if (e) ERR_error_string_n(e, buf, sizeof buf);
    printf("      (%s)\n", e ? buf : "no OpenSSL error recorded");
    ERR_clear_error();
}

/* Sign `m` with ML-DSA under the given message encoding (-1: provider
 * default, i.e. pure), deterministically, with context `ctx`. */
static int sign(EVP_PKEY *k, int encoding, const unsigned char *ctx, size_t ctxlen,
                const unsigned char *m, size_t mlen, unsigned char *sig, size_t *siglen) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int det = 1, ok = 0;
    OSSL_PARAM p[4]; int n = 0;
    p[n++] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    if (encoding >= 0) p[n++] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encoding);
    if (ctxlen) p[n++] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                           (void *)ctx, ctxlen);
    p[n] = OSSL_PARAM_construct_end();
    if (c && EVP_DigestSignInit_ex(c, &pc, NULL, NULL, NULL, k, p) == 1
        && EVP_DigestSign(c, sig, siglen, m, mlen) == 1)
        ok = 1;
    EVP_MD_CTX_free(c);
    return ok;
}

int main(int argc, char **argv) {
    int fips = argc > 1 && !strcmp(argv[1], "fips");
    printf("HashML-DSA on %s, provider: %s\n\n", OpenSSL_version(OPENSSL_VERSION),
           fips ? "fips (+ base)" : "default");
    if (fips) {
        if (!OSSL_PROVIDER_load(NULL, "fips") || !OSSL_PROVIDER_load(NULL, "base")
            || !EVP_set_default_properties(NULL, "fips=yes")) {
            printf("  the FIPS provider does not load\n"); err_line();
            return 2;
        }
    }
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
    if (!k) { printf("  no ML-DSA-65 key\n"); err_line(); return 2; }

    static const unsigned char ctx[] = "probe context";
    static const unsigned char msg[] = "the message to be signed";
    const size_t ctxlen = sizeof ctx - 1, mlen = sizeof msg - 1;
    unsigned char s1[5000], s2[5000];
    size_t l1 = sizeof s1, l2 = sizeof s2;

    /* 1 */
    {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        int r = EVP_DigestSignInit_ex(c, NULL, "SHA2-256", NULL, NULL, k, NULL);
        printf("  1. native: EVP_DigestSignInit with SHA2-256 on an ML-DSA key: %s\n",
               r == 1 ? "ACCEPTED" : "refused");
        if (r != 1) err_line();
        EVP_MD_CTX_free(c);
        ERR_clear_error();
    }

    /* 2 */
    int raw_ok = sign(k, 0, NULL, 0, msg, mlen, s2, &l2);
    printf("  2. raw: message-encoding = 0 accepted for signing: %s\n", raw_ok ? "yes" : "NO");
    if (!raw_ok) err_line();

    /* 3 */
    if (raw_ok) {
        unsigned char mp[600];
        size_t mpl = 0;
        mp[mpl++] = 0x00;
        mp[mpl++] = (unsigned char)ctxlen;
        memcpy(mp + mpl, ctx, ctxlen); mpl += ctxlen;
        memcpy(mp + mpl, msg, mlen);   mpl += mlen;
        l1 = sizeof s1; l2 = sizeof s2;
        int a = sign(k, -1, ctx, ctxlen, msg, mlen, s1, &l1);
        int b = sign(k, 0, NULL, 0, mp, mpl, s2, &l2);
        int same = a && b && l1 == l2 && !memcmp(s1, s2, l1);
        printf("  3. framing: pure(M, ctx) == raw(0x00||len||ctx||M), deterministic: %s\n",
               same ? "IDENTICAL" : a && b ? "DIFFERENT" : "could not sign both");
        if (!(a && b)) err_line();

        /* And the raw signature verifies as pure. */
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        int det = 1; (void)det;
        OSSL_PARAM p[2] = { OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                              (void *)ctx, ctxlen),
                            OSSL_PARAM_construct_end() };
        int v = c && EVP_DigestVerifyInit_ex(c, NULL, NULL, NULL, NULL, k, p) == 1
                && EVP_DigestVerify(c, s2, l2, msg, mlen) == 1;
        printf("     the raw signature verifies as pure ML-DSA under ctx: %s\n", v ? "yes" : "NO");
        EVP_MD_CTX_free(c);
        ERR_clear_error();

        /* Verification with message-encoding = 0, which HashML-DSA verify needs. */
        c = EVP_MD_CTX_new();
        int enc = 0;
        OSSL_PARAM q[2] = { OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &enc),
                            OSSL_PARAM_construct_end() };
        v = c && EVP_DigestVerifyInit_ex(c, NULL, NULL, NULL, NULL, k, q) == 1
            && EVP_DigestVerify(c, s2, l2, mp, mpl) == 1;
        printf("     raw verification of M' (message-encoding = 0): %s\n", v ? "yes" : "NO");
        if (!v) err_line();
        EVP_MD_CTX_free(c);
    }
    EVP_PKEY_free(k);
    return 0;
}
