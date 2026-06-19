/* diag_aes_gcm_tc14_v2.c
 *
 * v2 : reproduce the dev-mode init sequence from
 *      src/fhsm_crypto.c::crypto_init_once before invoking the EVP
 *      sequence. The original diag worked because OpenSSL auto-loaded
 *      the default provider ; this v2 explicitly does what FreeHSM
 *      does in dev mode to see if that setup is the trigger.
 *
 * Build : cc disabled/diag_aes_gcm_tc14_v2.c -lcrypto -o /tmp/diag_tc14v2
 * Run   : /tmp/diag_tc14v2
 *
 * License : Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>

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
static const unsigned char EXP_TAG[16] = {
    0x76,0xfc,0x6e,0xce,0x0f,0x4e,0x17,0x68,
    0xcd,0xdf,0x88,0x53,0xbb,0x2d,0x55,0x1b
};

static void dump_err(const char *who) {
    fprintf(stderr, "  %s returned 0\n", who);
    fprintf(stderr, "  OpenSSL error chain :\n");
    ERR_print_errors_fp(stderr);
}

static int run_evp_sequence(const char *phase) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { fprintf(stderr, "  [%s] EVP_CIPHER_CTX_new failed\n", phase); return 0; }

    unsigned char ct[60], tag[16];
    int outl = 0;

    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    if (!cipher) {
        fprintf(stderr, "  [%s] EVP_aes_256_gcm() returned NULL\n", phase);
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_EncryptInit_ex2(ctx, cipher, K, IV, NULL) != 1) {
        fprintf(stderr, "  [%s] ", phase);
        dump_err("EVP_EncryptInit_ex2");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (EVP_EncryptUpdate(ctx, NULL, &outl, AAD, sizeof(AAD)) != 1) {
        fprintf(stderr, "  [%s] ", phase);
        dump_err("EVP_EncryptUpdate(AAD)");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (EVP_EncryptUpdate(ctx, ct, &outl, PT, sizeof(PT)) != 1) {
        fprintf(stderr, "  [%s] ", phase);
        dump_err("EVP_EncryptUpdate(PT)");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    int n1 = outl;
    if (EVP_EncryptFinal_ex(ctx, ct + n1, &outl) != 1) {
        fprintf(stderr, "  [%s] ", phase);
        dump_err("EVP_EncryptFinal_ex");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "  [%s] ", phase);
        dump_err("EVP_CIPHER_CTX_ctrl(GET_TAG)");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    EVP_CIPHER_CTX_free(ctx);

    if (memcmp(tag, EXP_TAG, 16) != 0) {
        fprintf(stderr, "  [%s] TAG mismatch !\n", phase);
        return 0;
    }
    fprintf(stderr, "  [%s] OK : TAG matches expected\n", phase);
    return 1;
}

int main(void) {
    printf("OpenSSL version : %s\n\n", OpenSSL_version(OPENSSL_VERSION));

    /* ------ Phase 1 : pristine, no provider setup (= original diag) ------ */
    printf("Phase 1 : pristine init (auto-loaded default provider)\n");
    int ok1 = run_evp_sequence("phase1");
    printf("\n");

    /* ------ Phase 2 : reproduce FreeHSM C dev-mode init sequence ------ */
    printf("Phase 2 : after EVP_default_properties_enable_fips(NULL, 0)\n");
    if (EVP_default_properties_enable_fips(NULL, 0) != 1) {
        fprintf(stderr, "  EVP_default_properties_enable_fips(NULL, 0) failed\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("  EVP_default_properties_enable_fips(NULL, 0) OK\n");
    }
    int ok2 = run_evp_sequence("phase2");
    printf("\n");

    /* ------ Phase 3 : explicit OSSL_PROVIDER_load(NULL, \"default\") ------ */
    printf("Phase 3 : after explicit OSSL_PROVIDER_load(NULL, \"default\")\n");
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    if (!def) {
        fprintf(stderr, "  OSSL_PROVIDER_load(NULL, \"default\") returned NULL\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("  OSSL_PROVIDER_load(NULL, \"default\") OK\n");
    }
    int ok3 = run_evp_sequence("phase3");
    printf("\n");

    /* ------ Phase 4 : retry with EVP_CIPHER_fetch instead of legacy ------ */
    printf("Phase 4 : EVP_CIPHER_fetch(\"AES-256-GCM\") instead of legacy\n");
    EVP_CIPHER *fetched = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (!fetched) {
        fprintf(stderr, "  EVP_CIPHER_fetch returned NULL\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("  EVP_CIPHER_fetch OK\n");
        /* Use the fetched cipher inline (no helper) since the helper uses
         * the legacy EVP_aes_256_gcm() reference. */
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char ct[60], tag[16];
        int outl = 0;
        int ok = 1;
        if (EVP_EncryptInit_ex2(ctx, fetched, K, IV, NULL) != 1) { dump_err("phase4-Init"); ok = 0; }
        if (ok && EVP_EncryptUpdate(ctx, NULL, &outl, AAD, sizeof(AAD)) != 1) { dump_err("phase4-AAD"); ok = 0; }
        if (ok && EVP_EncryptUpdate(ctx, ct, &outl, PT, sizeof(PT)) != 1) { dump_err("phase4-PT"); ok = 0; }
        int n1 = outl;
        if (ok && EVP_EncryptFinal_ex(ctx, ct + n1, &outl) != 1) { dump_err("phase4-Final"); ok = 0; }
        if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) { dump_err("phase4-TAG"); ok = 0; }
        if (ok) {
            int match = memcmp(tag, EXP_TAG, 16) == 0;
            printf("  [phase4] TAG match : %s\n", match ? "YES" : "NO");
        }
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(fetched);
    }

    if (def) OSSL_PROVIDER_unload(def);

    printf("\nSummary :\n");
    printf("  phase1 (pristine)                 : %s\n", ok1 ? "OK" : "FAIL");
    printf("  phase2 (after enable_fips(0))     : %s\n", ok2 ? "OK" : "FAIL");
    printf("  phase3 (after provider_load)      : %s\n", ok3 ? "OK" : "FAIL");
    printf("  phase4 (EVP_CIPHER_fetch dynamic) : see above\n");

    return 0;
}
