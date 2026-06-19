/* diag_aes_gcm_tc14.c
 *
 * Standalone diagnostic for the AES-GCM-256/SP800-38D-TC14 KAT failure
 * observed in dev mode on OpenSSL 3.5.6 (no FIPS provider).
 *
 * Reproduces the exact EVP sequence from src/fhsm_crypto.c
 * fhsm_aes_gcm_encrypt() with the boot-KAT vectors from
 * kat/fhsm_kat_vectors.c. Prints the OpenSSL error chain at every
 * potential failure point so we know which call rejected the input
 * and why.
 *
 * Build : cc diag_aes_gcm_tc14.c -lcrypto -o /tmp/diag_tc14
 * Run   : /tmp/diag_tc14
 *
 * Expected output if the KAT works :
 *   ENCRYPT OK : 60 bytes CT match, 16 bytes tag match
 *
 * Expected output if the KAT fails :
 *   EncryptInit_ex2 returned 0
 *   OpenSSL error chain :
 *     [whatever the chain reveals]
 *
 * License : Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>     /* OSSL_PROVIDER_available */

static const unsigned char K[32] = {
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
    0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
    0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
};
static const unsigned char IV[12] = {
    0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
    0xde,0xca,0xf8,0x88
};
static const unsigned char AAD[20] = {
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xab,0xad,0xda,0xd2
};
static const unsigned char PT[60] = {
    0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
    0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
    0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
    0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
    0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
    0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
    0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
    0xba,0x63,0x7b,0x39
};
static const unsigned char EXP_CT[60] = {
    0x52,0x2d,0xc1,0xf0,0x99,0x56,0x7d,0x07,
    0xf4,0x7f,0x37,0xa3,0x2a,0x84,0x42,0x7d,
    0x64,0x3a,0x8c,0xdc,0xbf,0xe5,0xc0,0xc9,
    0x75,0x98,0xa2,0xbd,0x25,0x55,0xd1,0xaa,
    0x8c,0xb0,0x8e,0x48,0x59,0x0d,0xbb,0x3d,
    0xa7,0xb0,0x8b,0x10,0x56,0x82,0x88,0x38,
    0xc5,0xf6,0x1e,0x63,0x93,0xba,0x7a,0x0a,
    0xbc,0xc9,0xf6,0x62
};
static const unsigned char EXP_TAG[16] = {
    0x76,0xfc,0x6e,0xce,0x0f,0x4e,0x17,0x68,
    0xcd,0xdf,0x88,0x53,0xbb,0x2d,0x55,0x1b
};

static void dump_err(const char *who) {
    fprintf(stderr, "  %s returned 0\n", who);
    fprintf(stderr, "  OpenSSL error chain :\n");
    ERR_print_errors_fp(stderr);
}

int main(void) {
    printf("OpenSSL version : %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("Provider mode   : %s\n",
           OSSL_PROVIDER_available(NULL, "fips") ? "FIPS available"
                                                 : "default provider only");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { fprintf(stderr, "EVP_CIPHER_CTX_new failed\n"); return 1; }

    unsigned char ct[60];
    unsigned char tag[16];
    int outl = 0;

    /* Step 1 : init with cipher + key + iv (the call that's suspected
     *           to fail under OpenSSL 3.5.6 default provider). */
    if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), K, IV, NULL) != 1) {
        dump_err("EVP_EncryptInit_ex2");
        EVP_CIPHER_CTX_free(ctx);
        return 2;
    }
    printf("Step 1 OK : EVP_EncryptInit_ex2\n");

    /* Step 2 : feed AAD. */
    if (EVP_EncryptUpdate(ctx, NULL, &outl, AAD, sizeof(AAD)) != 1) {
        dump_err("EVP_EncryptUpdate(AAD)");
        EVP_CIPHER_CTX_free(ctx);
        return 3;
    }
    printf("Step 2 OK : AAD fed (%d bytes)\n", (int)sizeof(AAD));

    /* Step 3 : encrypt PT. */
    if (EVP_EncryptUpdate(ctx, ct, &outl, PT, sizeof(PT)) != 1) {
        dump_err("EVP_EncryptUpdate(PT)");
        EVP_CIPHER_CTX_free(ctx);
        return 4;
    }
    int n1 = outl;
    printf("Step 3 OK : PT encrypted (%d bytes produced)\n", n1);

    /* Step 4 : finalize. */
    if (EVP_EncryptFinal_ex(ctx, ct + n1, &outl) != 1) {
        dump_err("EVP_EncryptFinal_ex");
        EVP_CIPHER_CTX_free(ctx);
        return 5;
    }
    printf("Step 4 OK : finalize (%d bytes produced)\n", outl);

    /* Step 5 : get tag. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        dump_err("EVP_CIPHER_CTX_ctrl(GET_TAG)");
        EVP_CIPHER_CTX_free(ctx);
        return 6;
    }
    printf("Step 5 OK : tag retrieved\n");

    EVP_CIPHER_CTX_free(ctx);

    /* Compare against expected values. */
    int ct_match  = memcmp(ct,  EXP_CT,  60) == 0;
    int tag_match = memcmp(tag, EXP_TAG, 16) == 0;
    printf("CT match   : %s\n", ct_match  ? "YES" : "NO");
    printf("TAG match  : %s\n", tag_match ? "YES" : "NO");

    if (!ct_match) {
        printf("Got CT  : ");
        for (int i = 0; i < 60; i++) printf("%02x ", ct[i]);
        printf("\n");
        printf("Want CT : ");
        for (int i = 0; i < 60; i++) printf("%02x ", EXP_CT[i]);
        printf("\n");
    }
    if (!tag_match) {
        printf("Got TAG : ");
        for (int i = 0; i < 16; i++) printf("%02x ", tag[i]);
        printf("\n");
        printf("Want TAG: ");
        for (int i = 0; i < 16; i++) printf("%02x ", EXP_TAG[i]);
        printf("\n");
    }

    return (ct_match && tag_match) ? 0 : 7;
}
