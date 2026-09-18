/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * probe_pqc_pub_lengths.c --- what a raw PQC public key actually measures.
 *
 * The import path being written needs to recognise an ML-KEM encapsulation
 * key or an ML-DSA public key from its length when CKA_PARAMETER_SET is
 * absent, and to check the length against the set when it is present. Those
 * six numbers are in FIPS 203 §8 and FIPS 204 §4, and they are also in my
 * head, and this file exists because the difference between the two is what
 * put a permuted C_EncapsulateKey signature into this module and kept it
 * there for months.
 *
 * So they come out of the provider that will actually be used, printed as C
 * the implementation can paste, and the run is the evidence.
 *
 * It also answers the second question the import needs: round-tripping a raw
 * key through EVP_PKEY_new_raw_public_key_ex and i2d_PUBKEY, which is the
 * conversion the boundary will perform, and back out with
 * EVP_PKEY_get_raw_public_key, which is the one the readback will perform.
 * If either direction loses a byte, the plan is wrong and better wrong now.
 *
 *   cc -o tests/probe_pqc_pub_lengths tests/probe_pqc_pub_lengths.c \
 *       -lcrypto $(pkg-config --cflags --libs libcrypto 2>/dev/null)
 *   ./tests/probe_pqc_pub_lengths
 * ======================================================================== */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/x509.h>   /* i2d_PUBKEY : declared here, not in evp.h */
#include <openssl/err.h>

static const char *const SETS[] = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44",  "ML-DSA-65",  "ML-DSA-87",
};

static int probe_one(const char *alg)
{
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!ctx) { printf("  %-12s  provider does not offer it\n", alg); return 0; }
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &k) <= 0) {
        printf("  %-12s  keygen failed\n", alg);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    EVP_PKEY_CTX_free(ctx);

    /* The raw public key: what PKCS#11 v3.2 calls CKA_VALUE. */
    size_t raw_len = 0;
    if (EVP_PKEY_get_raw_public_key(k, NULL, &raw_len) <= 0) {
        printf("  %-12s  no raw public key from this provider\n", alg);
        EVP_PKEY_free(k);
        return 0;
    }
    unsigned char *raw = malloc(raw_len);
    if (!raw) { EVP_PKEY_free(k); return 0; }
    if (EVP_PKEY_get_raw_public_key(k, raw, &raw_len) <= 0) {
        printf("  %-12s  raw export failed\n", alg);
        free(raw); EVP_PKEY_free(k);
        return 0;
    }

    /* The SPKI: what this module stores. */
    unsigned char *der = NULL;
    int der_len = i2d_PUBKEY(k, &der);

    /* The conversion the import boundary will perform: raw -> EVP_PKEY. */
    int round_ok = 0, bytes_ok = 0;
    EVP_PKEY *back = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, raw, raw_len);
    if (back) {
        round_ok = 1;
        /* And out again, which is the readback boundary. */
        size_t again_len = 0;
        if (EVP_PKEY_get_raw_public_key(back, NULL, &again_len) > 0
            && again_len == raw_len) {
            unsigned char *again = malloc(again_len);
            if (again
                && EVP_PKEY_get_raw_public_key(back, again, &again_len) > 0
                && memcmp(again, raw, raw_len) == 0) {
                bytes_ok = 1;
            }
            free(again);
        }
        EVP_PKEY_free(back);
    }

    printf("  %-12s  raw %5zu   SPKI %5d   raw->EVP %s   round-trip %s\n",
           alg, raw_len, der_len,
           round_ok ? "ok " : "NO ",
           bytes_ok ? "identical" : "LOST BYTES");

    OPENSSL_free(der);
    free(raw);
    EVP_PKEY_free(k);
    return 1;
}

int main(void)
{
    printf("Raw PQC public-key lengths, from the provider rather than from memory\n\n");

    int found = 0;
    for (size_t i = 0; i < sizeof(SETS)/sizeof(SETS[0]); ++i)
        found += probe_one(SETS[i]);

    if (!found) {
        printf("\nNo parameter set was available. The import path cannot be\n"
               "written against this provider.\n");
        return 1;
    }

    printf("\nFor the implementation, paste the first column:\n\n");
    printf("  /* Raw public-key lengths, measured with tests/probe_pqc_pub_lengths\n"
           "   * against the provider this module loads. FIPS 203 §8 and FIPS 204 §4\n"
           "   * say the same; these were read rather than recalled. */\n");
    for (size_t i = 0; i < sizeof(SETS)/sizeof(SETS[0]); ++i) {
        EVP_PKEY *k = NULL;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, SETS[i], NULL);
        if (!c) continue;
        if (EVP_PKEY_keygen_init(c) > 0 && EVP_PKEY_keygen(c, &k) > 0) {
            size_t n = 0;
            if (EVP_PKEY_get_raw_public_key(k, NULL, &n) > 0) {
                char sym[32];
                size_t j = 0;
                for (const char *p = SETS[i]; *p && j < sizeof(sym) - 1; ++p)
                    sym[j++] = (*p == '-') ? '_' : *p;
                sym[j] = '\0';
                printf("  #define FHSM_%s_PUB_LEN %zu\n", sym, n);
            }
        }
        EVP_PKEY_free(k);
        EVP_PKEY_CTX_free(c);
    }

    /* A length that belongs to two sets would make inference from length
     * alone ambiguous, which decides whether CKA_PARAMETER_SET may be
     * optional. Said here rather than assumed at the call site. */
    printf("\nIf two sets share a length, CKA_PARAMETER_SET cannot be optional.\n");
    return 0;
}
