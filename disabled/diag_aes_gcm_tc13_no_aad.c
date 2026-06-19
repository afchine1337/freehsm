/* diag_aes_gcm_tc13_no_aad.c
 *
 * v3 : after the ex2 rewrite of run_aesgcm_vec, the no-AAD case
 * (NIST SP 800-38D TC13) still fails. This diag isolates the
 * problem to the no-AAD code path : reproduces run_aesgcm_vec
 * exactly for both TC13 (no AAD) and TC14 (with AAD), prints the
 * actual CT and TAG, then probes a candidate fix : force an
 * EVP_EncryptUpdate AAD call with 0 bytes to explicitly transition
 * the cipher state from post-init to AAD-done.
 *
 * Build : cc disabled/diag_aes_gcm_tc13_no_aad.c -lcrypto -o /tmp/diag_tc13
 * Run   : /tmp/diag_tc13
 *
 * License : Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

/* Identical to cavp_extended.c globals. */
static const unsigned char kK[32] = {
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
/* Expected TC13 (no AAD) tag — 0xb094dac5...  */
static const unsigned char EXP_TAG_TC13[16] = {
    0xb0,0x94,0xda,0xc5,0xd9,0x34,0x71,0xbd,
    0xec,0x1a,0x50,0x22,0x70,0xe3,0xcc,0x6c
};
/* Expected TC14 (with AAD) tag — 0x76fc6ece... */
static const unsigned char EXP_TAG_TC14[16] = {
    0x76,0xfc,0x6e,0xce,0x0f,0x4e,0x17,0x68,
    0xcd,0xdf,0x88,0x53,0xbb,0x2d,0x55,0x1b
};

static void hexdump(const char *label, const unsigned char *p, size_t n) {
    printf("  %s = ", label);
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
    printf("\n");
}

/* Variant 1 : exact run_aesgcm_vec after the ex2 rewrite (AAD update
 *             skipped when aad_len == 0). */
static int run_variant1(const unsigned char *aad, size_t aad_len,
                         unsigned char *out_ct, unsigned char *out_tag) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return 0;
    int outl = 0, tmpl = 0;
    if (EVP_EncryptInit_ex2(c, EVP_aes_256_gcm(), kK, IV, NULL) != 1) {
        EVP_CIPHER_CTX_free(c); return 0;
    }
    if (aad_len &&
        EVP_EncryptUpdate(c, NULL, &tmpl, aad, (int)aad_len) != 1) {
        EVP_CIPHER_CTX_free(c); return 0;
    }
    if (EVP_EncryptUpdate(c, out_ct, &outl, PT, sizeof(PT)) != 1) {
        EVP_CIPHER_CTX_free(c); return 0;
    }
    int n1 = outl;
    if (EVP_EncryptFinal_ex(c, out_ct + n1, &outl) != 1) {
        EVP_CIPHER_CTX_free(c); return 0;
    }
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out_tag) != 1) {
        EVP_CIPHER_CTX_free(c); return 0;
    }
    EVP_CIPHER_CTX_free(c);
    return 1;
}

/* Variant 2 : ALWAYS call AAD update, even with 0 bytes. Some OpenSSL
 *             versions require this to transition the cipher state. */
static int run_variant2(const unsigned char *aad, size_t aad_len,
                         unsigned char *out_ct, unsigned char *out_tag) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return 0;
    int outl = 0, tmpl = 0;
    const unsigned char dummy = 0;
    const unsigned char *aad_ptr = aad ? aad : &dummy;
    if (EVP_EncryptInit_ex2(c, EVP_aes_256_gcm(), kK, IV, NULL) != 1) {
        EVP_CIPHER_CTX_free(c); return 0;
    }
    /* Force AAD update even when len=0. */
    if (EVP_EncryptUpdate(c, NULL, &tmpl, aad_ptr, (int)aad_len) != 1) {
        EVP_CIPHER_CTX_free(c); return 0;
    }
    if (EVP_EncryptUpdate(c, out_ct, &outl, PT, sizeof(PT)) != 1) {
        EVP_CIPHER_CTX_free(c); return 0;
    }
    int n1 = outl;
    if (EVP_EncryptFinal_ex(c, out_ct + n1, &outl) != 1) {
        EVP_CIPHER_CTX_free(c); return 0;
    }
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out_tag) != 1) {
        EVP_CIPHER_CTX_free(c); return 0;
    }
    EVP_CIPHER_CTX_free(c);
    return 1;
}

int main(void) {
    printf("OpenSSL : %s\n\n", OpenSSL_version(OPENSSL_VERSION));

    unsigned char ct[64], tag[16];

    /* === TC13 no AAD === */
    printf("=== TC13 : NO AAD ===\n");
    printf("Expected:\n");
    hexdump("TAG", EXP_TAG_TC13, 16);

    printf("Variant 1 (AAD update SKIPPED) :\n");
    if (!run_variant1(NULL, 0, ct, tag)) { printf("  EVP failed\n"); return 1; }
    hexdump("CT (first 16)", ct, 16);
    hexdump("TAG", tag, 16);
    printf("  TAG match : %s\n\n",
           memcmp(tag, EXP_TAG_TC13, 16) == 0 ? "YES" : "NO");

    printf("Variant 2 (AAD update FORCED with 0 bytes) :\n");
    if (!run_variant2(NULL, 0, ct, tag)) { printf("  EVP failed\n"); return 2; }
    hexdump("CT (first 16)", ct, 16);
    hexdump("TAG", tag, 16);
    printf("  TAG match : %s\n\n",
           memcmp(tag, EXP_TAG_TC13, 16) == 0 ? "YES" : "NO");

    /* === TC14 with AAD (sanity : should be correct in both variants) === */
    printf("=== TC14 : 20-byte AAD ===\n");
    printf("Expected:\n");
    hexdump("TAG", EXP_TAG_TC14, 16);

    printf("Variant 1 (AAD update called) :\n");
    if (!run_variant1(AAD, sizeof(AAD), ct, tag)) { printf("  EVP failed\n"); return 3; }
    hexdump("CT (first 16)", ct, 16);
    hexdump("TAG", tag, 16);
    printf("  TAG match : %s\n\n",
           memcmp(tag, EXP_TAG_TC14, 16) == 0 ? "YES" : "NO");

    printf("Variant 2 (AAD update called) :\n");
    if (!run_variant2(AAD, sizeof(AAD), ct, tag)) { printf("  EVP failed\n"); return 4; }
    hexdump("CT (first 16)", ct, 16);
    hexdump("TAG", tag, 16);
    printf("  TAG match : %s\n",
           memcmp(tag, EXP_TAG_TC14, 16) == 0 ? "YES" : "NO");

    return 0;
}
