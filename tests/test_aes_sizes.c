/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_aes_sizes.c --- every AES mechanism, at every AES key size, against
 * OpenSSL.
 *
 * The other AES tests are about behaviour -- error codes, parameter blocks,
 * operation state -- almost all on 128-bit keys, and CCM, CTR and CMAC had no
 * C test at all: their correctness rested on Wycheproof and on pkcs11-check's
 * ACVP sets, run elsewhere. This one asks the module for an answer and checks
 * it against OpenSSL computing the same thing independently, for 128, 192
 * and 256-bit keys, so that a key size routed to the wrong cipher name, or a
 * mode that worked only at one size, shows here.
 *
 * What is asserted:
 *   (1) C_GenerateKey makes 16, 24 and 32-byte AES keys, CKA_VALUE_LEN reads
 *       back as asked, and a GCM round trip through each works
 *   (2) C_GenerateKey refuses 0, 15, 20, 33 and 64 with CKR_KEY_SIZE_RANGE
 *   (3) for an imported key of each size, the module's output equals
 *       OpenSSL's for ECB, CBC, CBC-PAD, CTR, GCM, CCM, KW and KWP (through
 *       C_Encrypt), and C_Decrypt gives the plaintext back
 *   (4) CMAC and GMAC through C_Sign equal OpenSSL's EVP_MAC
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
/* OASIS v3.2 layouts. */
typedef struct { void *pIv; CK_ULONG ulIvLen; CK_ULONG ulIvBits;
                 void *pAAD; CK_ULONG ulAADLen; CK_ULONG ulTagBits; } CK_GCM_PARAMS;
typedef struct { CK_ULONG ulDataLen; void *pNonce; CK_ULONG ulNonceLen;
                 void *pAAD; CK_ULONG ulAADLen; CK_ULONG ulMACLen; } CK_CCM_PARAMS;
typedef struct { CK_ULONG ulCounterBits; CK_BYTE cb[16]; } CK_AES_CTR_PARAMS;

#define CKR_OK              0UL
#define CKR_KEY_SIZE_RANGE  0x62UL
#define CKF_RW              6UL
#define CKA_CLASS           0x000UL
#define CKA_TOKEN           0x001UL
#define CKA_VALUE           0x011UL
#define CKA_KEY_TYPE        0x100UL
#define CKA_ENCRYPT         0x104UL
#define CKA_DECRYPT         0x105UL
#define CKA_SIGN            0x108UL
#define CKA_VERIFY          0x10AUL
#define CKA_VALUE_LEN       0x161UL
#define CKO_SECRET_KEY      4UL
#define CKK_AES             0x1FUL
#define CKM_AES_KEY_GEN     0x1080UL
#define CKM_AES_ECB         0x1081UL
#define CKM_AES_CBC         0x1082UL
#define CKM_AES_CBC_PAD     0x1085UL
#define CKM_AES_CTR         0x1086UL
#define CKM_AES_GCM         0x1087UL
#define CKM_AES_CCM         0x1088UL
#define CKM_AES_CMAC        0x108AUL
#define CKM_AES_GMAC        0x108EUL
#define CKM_AES_KEY_WRAP    0x2109UL
#define CKM_AES_KEY_WRAP_KWP 0x210BUL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Decrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);

static CK_SESSION_HANDLE s;

/* -------------------------------------------------------------- the module */

static CK_OBJECT_HANDLE import_aes(const CK_BYTE *key, CK_ULONG len)
{
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES;
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE t[] = {
        { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
        { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 }, { CKA_DECRYPT, &yes, 1 },
        { CKA_SIGN, &yes, 1 }, { CKA_VERIFY, &yes, 1 },
        { CKA_VALUE, (void *)key, len },
    };
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, sizeof t / sizeof t[0], &h) == CKR_OK ? h : 0;
}

static CK_RV encrypt(CK_OBJECT_HANDLE k, CK_MECHANISM *m, const CK_BYTE *in, CK_ULONG in_len,
                     CK_BYTE *out, CK_ULONG *out_len)
{
    CK_RV rv = C_EncryptInit(s, m, k);
    return rv != CKR_OK ? rv : C_Encrypt(s, (CK_BYTE *)in, in_len, out, out_len);
}

static CK_RV decrypt(CK_OBJECT_HANDLE k, CK_MECHANISM *m, const CK_BYTE *in, CK_ULONG in_len,
                     CK_BYTE *out, CK_ULONG *out_len)
{
    CK_RV rv = C_DecryptInit(s, m, k);
    return rv != CKR_OK ? rv : C_Decrypt(s, (CK_BYTE *)in, in_len, out, out_len);
}

/* ------------------------------------------------------- OpenSSL, directly */

static const char *mode_name(size_t key_len, const char *mode, char *buf, size_t n)
{
    snprintf(buf, n, "AES-%zu-%s", key_len * 8, mode);
    return buf;
}

/* ECB, CBC, CTR, WRAP and WRAP-PAD: one call. pad is for CBC-PAD. */
static int ref_cipher(const char *name, const CK_BYTE *key, const CK_BYTE *iv, int pad,
                      const CK_BYTE *in, int in_len, CK_BYTE *out, int *out_len)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int n = 0, f = 0, r = c && x;
    if (r) EVP_CIPHER_CTX_set_flags(x, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    r = r && EVP_EncryptInit_ex(x, c, NULL, key, iv) == 1
          && EVP_CIPHER_CTX_set_padding(x, pad) == 1
          && EVP_EncryptUpdate(x, out, &n, in, in_len) == 1
          && EVP_EncryptFinal_ex(x, out + n, &f) == 1;
    *out_len = n + f;
    EVP_CIPHER_CTX_free(x);
    EVP_CIPHER_free(c);
    return r;
}

/* GCM and CCM, ciphertext followed by the 16-byte tag, as PKCS#11 returns. */
static int ref_aead(const char *name, int ccm, const CK_BYTE *key, const CK_BYTE *iv, int iv_len,
                    const CK_BYTE *aad, int aad_len, const CK_BYTE *in, int in_len,
                    CK_BYTE *out, int *out_len)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int n = 0, f = 0, len = 0;
    int r = c && x && EVP_EncryptInit_ex(x, c, NULL, NULL, NULL) == 1
            && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL) == 1
            && (!ccm || EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_TAG, 16, NULL) == 1)
            && EVP_EncryptInit_ex(x, NULL, NULL, key, iv) == 1
            && (!ccm || EVP_EncryptUpdate(x, NULL, &len, NULL, in_len) == 1)
            && EVP_EncryptUpdate(x, NULL, &len, aad, aad_len) == 1
            && EVP_EncryptUpdate(x, out, &n, in, in_len) == 1
            && EVP_EncryptFinal_ex(x, out + n, &f) == 1
            && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, 16, out + n + f) == 1;
    *out_len = n + f + 16;
    EVP_CIPHER_CTX_free(x);
    EVP_CIPHER_free(c);
    return r;
}

static int ref_mac(const char *mac, const char *cipher, const CK_BYTE *key, size_t key_len,
                   const CK_BYTE *iv, size_t iv_len, const CK_BYTE *in, size_t in_len,
                   CK_BYTE out[16])
{
    EVP_MAC *m = EVP_MAC_fetch(NULL, mac, NULL);
    EVP_MAC_CTX *x = m ? EVP_MAC_CTX_new(m) : NULL;
    OSSL_PARAM p[3];
    int i = 0;
    p[i++] = OSSL_PARAM_construct_utf8_string("cipher", (char *)cipher, 0);
    if (iv) p[i++] = OSSL_PARAM_construct_octet_string("iv", (void *)iv, iv_len);
    p[i] = OSSL_PARAM_construct_end();
    size_t n = 0;
    int r = x && EVP_MAC_init(x, key, key_len, p) == 1
            && EVP_MAC_update(x, in, in_len) == 1
            && EVP_MAC_final(x, out, &n, 16) == 1 && n == 16;
    EVP_MAC_CTX_free(x);
    EVP_MAC_free(m);
    return r;
}

/* ---------------------------------------------------------------- the cases */

/* Encrypt with the module, compare with OpenSSL, decrypt back. */
static void check_mode(const char *label, CK_OBJECT_HANDLE k, CK_MECHANISM *m,
                       const CK_BYTE *pt, CK_ULONG pt_len, const CK_BYTE *ref, int ref_len,
                       int ref_ok)
{
    CK_BYTE ct[256], back[256];
    CK_ULONG ct_len = sizeof ct, back_len = sizeof back;
    char what[96];
    CK_RV rv = encrypt(k, m, pt, pt_len, ct, &ct_len);
    snprintf(what, sizeof what, "(3) %s: equals OpenSSL (rv 0x%lx)", label, rv);
    ok(ref_ok && rv == CKR_OK && ct_len == (CK_ULONG)ref_len && !memcmp(ct, ref, ct_len), what);
    if (rv != CKR_OK) return;
    rv = decrypt(k, m, ct, ct_len, back, &back_len);
    snprintf(what, sizeof what, "(3) %s: decrypts back (rv 0x%lx)", label, rv);
    ok(rv == CKR_OK && back_len == pt_len && !memcmp(back, pt, pt_len), what);
}

static void one_size(CK_ULONG key_len)
{
    CK_BYTE key[32], iv[16], aad[20], pt[37];
    for (size_t i = 0; i < sizeof key; i++) key[i] = (CK_BYTE)(0x10 + 7 * i);
    for (size_t i = 0; i < sizeof iv; i++)  iv[i]  = (CK_BYTE)(0xA0 + i);
    for (size_t i = 0; i < sizeof aad; i++) aad[i] = (CK_BYTE)(0x30 + 3 * i);
    for (size_t i = 0; i < sizeof pt; i++)  pt[i]  = (CK_BYTE)(0x55 ^ (5 * i));

    char label[48], name[32], what[96];
    CK_OBJECT_HANDLE k = import_aes(key, key_len);
    snprintf(what, sizeof what, "AES-%lu key imported", key_len * 8);
    ok(k != 0, what);
    if (!k) return;

    CK_BYTE ref[256];
    int ref_len = 0, r;

    /* ECB and CBC take whole blocks: 32 of the 37 bytes. */
    CK_MECHANISM m = { CKM_AES_ECB, NULL, 0 };
    r = ref_cipher(mode_name(key_len, "ECB", name, sizeof name), key, NULL, 0, pt, 32, ref, &ref_len);
    snprintf(label, sizeof label, "AES-%lu-ECB", key_len * 8);
    check_mode(label, k, &m, pt, 32, ref, ref_len, r);

    m = (CK_MECHANISM){ CKM_AES_CBC, iv, 16 };
    r = ref_cipher(mode_name(key_len, "CBC", name, sizeof name), key, iv, 0, pt, 32, ref, &ref_len);
    snprintf(label, sizeof label, "AES-%lu-CBC", key_len * 8);
    check_mode(label, k, &m, pt, 32, ref, ref_len, r);

    m = (CK_MECHANISM){ CKM_AES_CBC_PAD, iv, 16 };
    r = ref_cipher(name, key, iv, 1, pt, (int)sizeof pt, ref, &ref_len);
    snprintf(label, sizeof label, "AES-%lu-CBC-PAD", key_len * 8);
    check_mode(label, k, &m, pt, sizeof pt, ref, ref_len, r);

    CK_AES_CTR_PARAMS ctr = { 128, {0} };
    memcpy(ctr.cb, iv, 16);
    m = (CK_MECHANISM){ CKM_AES_CTR, &ctr, sizeof ctr };
    r = ref_cipher(mode_name(key_len, "CTR", name, sizeof name), key, iv, 0, pt, (int)sizeof pt, ref, &ref_len);
    snprintf(label, sizeof label, "AES-%lu-CTR", key_len * 8);
    check_mode(label, k, &m, pt, sizeof pt, ref, ref_len, r);

    CK_GCM_PARAMS gcm = { iv, 12, 96, aad, sizeof aad, 128 };
    m = (CK_MECHANISM){ CKM_AES_GCM, &gcm, sizeof gcm };
    r = ref_aead(mode_name(key_len, "GCM", name, sizeof name), 0, key, iv, 12,
                 aad, (int)sizeof aad, pt, (int)sizeof pt, ref, &ref_len);
    snprintf(label, sizeof label, "AES-%lu-GCM", key_len * 8);
    check_mode(label, k, &m, pt, sizeof pt, ref, ref_len, r);

    CK_CCM_PARAMS ccm = { sizeof pt, iv, 12, aad, sizeof aad, 16 };
    m = (CK_MECHANISM){ CKM_AES_CCM, &ccm, sizeof ccm };
    r = ref_aead(mode_name(key_len, "CCM", name, sizeof name), 1, key, iv, 12,
                 aad, (int)sizeof aad, pt, (int)sizeof pt, ref, &ref_len);
    snprintf(label, sizeof label, "AES-%lu-CCM", key_len * 8);
    check_mode(label, k, &m, pt, sizeof pt, ref, ref_len, r);

    /* KW takes a multiple of 8 bytes, at least 16; KWP any length. */
    m = (CK_MECHANISM){ CKM_AES_KEY_WRAP, NULL, 0 };
    r = ref_cipher(mode_name(key_len, "WRAP", name, sizeof name), key, NULL, 0, pt, 32, ref, &ref_len);
    snprintf(label, sizeof label, "AES-%lu-KW (C_Encrypt)", key_len * 8);
    check_mode(label, k, &m, pt, 32, ref, ref_len, r);

    m = (CK_MECHANISM){ CKM_AES_KEY_WRAP_KWP, NULL, 0 };
    r = ref_cipher(mode_name(key_len, "WRAP-PAD", name, sizeof name), key, NULL, 0,
                   pt, (int)sizeof pt, ref, &ref_len);
    snprintf(label, sizeof label, "AES-%lu-KWP (C_Encrypt)", key_len * 8);
    check_mode(label, k, &m, pt, sizeof pt, ref, ref_len, r);

    /* (4) MACs. */
    CK_BYTE mac[16], refmac[16];
    CK_ULONG mac_len = sizeof mac;
    m = (CK_MECHANISM){ CKM_AES_CMAC, NULL, 0 };
    CK_RV rv = C_SignInit(s, &m, k);
    if (rv == CKR_OK) rv = C_Sign(s, pt, sizeof pt, mac, &mac_len);
    r = ref_mac("CMAC", mode_name(key_len, "CBC", name, sizeof name), key, key_len,
                NULL, 0, pt, sizeof pt, refmac);
    snprintf(what, sizeof what, "(4) AES-%lu-CMAC: equals OpenSSL (rv 0x%lx)", key_len * 8, rv);
    ok(r && rv == CKR_OK && mac_len == 16 && !memcmp(mac, refmac, 16), what);

    CK_GCM_PARAMS gm = { iv, 12, 96, NULL, 0, 128 };
    m = (CK_MECHANISM){ CKM_AES_GMAC, &gm, sizeof gm };
    mac_len = sizeof mac;
    rv = C_SignInit(s, &m, k);
    if (rv == CKR_OK) rv = C_Sign(s, aad, sizeof aad, mac, &mac_len);
    r = ref_mac("GMAC", mode_name(key_len, "GCM", name, sizeof name), key, key_len,
                iv, 12, aad, sizeof aad, refmac);
    snprintf(what, sizeof what, "(4) AES-%lu-GMAC: equals OpenSSL (rv 0x%lx)", key_len * 8, rv);
    ok(r && rv == CKR_OK && mac_len == 16 && !memcmp(mac, refmac, 16), what);
}

static CK_RV generate(CK_ULONG len, CK_OBJECT_HANDLE *out)
{
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES;
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE t[] = {
        { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
        { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 }, { CKA_DECRYPT, &yes, 1 },
        { CKA_VALUE_LEN, &len, sizeof len },
    };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL, 0 };
    return C_GenerateKey(s, &m, t, sizeof t / sizeof t[0], out);
}

int main(void)
{
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_GenerateKey);
    SYM(C_GetAttributeValue); SYM(C_EncryptInit); SYM(C_Encrypt);
    SYM(C_DecryptInit); SYM(C_Decrypt); SYM(C_SignInit); SYM(C_Sign);
    if (!C_CreateObject || !C_GenerateKey || !C_Encrypt || !C_Decrypt || !C_Sign) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("AES at 128, 192 and 256 bits, every mechanism, against OpenSSL\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "aessizes")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    char what[96];
    static const CK_ULONG sizes[] = { 16, 24, 32 };
    for (size_t i = 0; i < 3; i++) {
        CK_OBJECT_HANDLE k = 0;
        CK_RV rv = generate(sizes[i], &k);
        CK_ULONG got = 0;
        CK_ATTRIBUTE a = { CKA_VALUE_LEN, &got, sizeof got };
        if (rv == CKR_OK) rv = C_GetAttributeValue(s, k, &a, 1);
        snprintf(what, sizeof what, "(1) C_GenerateKey AES-%lu, CKA_VALUE_LEN %lu (rv 0x%lx)",
                 sizes[i] * 8, got, rv);
        ok(rv == CKR_OK && got == sizes[i], what);
        if (rv != CKR_OK) continue;

        CK_BYTE iv[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, pt[40] = "generated key, round trip", ct[64], back[64];
        CK_GCM_PARAMS gcm = { iv, 12, 96, NULL, 0, 128 };
        CK_MECHANISM m = { CKM_AES_GCM, &gcm, sizeof gcm };
        CK_ULONG ct_len = sizeof ct, back_len = sizeof back;
        rv = encrypt(k, &m, pt, sizeof pt, ct, &ct_len);
        if (rv == CKR_OK) rv = decrypt(k, &m, ct, ct_len, back, &back_len);
        snprintf(what, sizeof what, "(1) AES-%lu generated key: GCM round trip (rv 0x%lx)",
                 sizes[i] * 8, rv);
        ok(rv == CKR_OK && back_len == sizeof pt && !memcmp(back, pt, sizeof pt), what);
    }
    static const CK_ULONG bad[] = { 0, 15, 20, 33, 64 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        CK_OBJECT_HANDLE k = 0;
        CK_RV rv = generate(bad[i], &k);
        snprintf(what, sizeof what, "(2) C_GenerateKey AES of %lu bytes: CKR_KEY_SIZE_RANGE (0x%lx)",
                 bad[i], rv);
        ok(rv == CKR_KEY_SIZE_RANGE, what);
    }
    printf("\n");
    for (size_t i = 0; i < 3; i++) one_size(sizes[i]);

    (void)C_Finalize(NULL);
    printf("\n%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
