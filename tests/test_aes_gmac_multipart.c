/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_aes_gmac_multipart.c --- CKM_AES_GMAC through C_SignUpdate /
 * C_SignFinal and C_VerifyUpdate / C_VerifyFinal.
 *
 * Multipart GMAC answered CKR_MECHANISM_INVALID at the first Update, while
 * C_SignInit accepted the mechanism for the one-shot path: pkcs11-check's
 * TestMultipartSign scored it advertised but not operational.
 *
 * The reference is OpenSSL's EVP_MAC "GMAC" called directly, as
 * test_aes_sizes and test_rsa_oaep use OpenSSL, and one published anchor
 * that depends on neither: GCM specification (McGrew-Viega) Test Case 1,
 * K = 0^128, IV = 0^96, nothing authenticated, T = 58e2fcce...e7455a.
 *
 * What is asserted, for AES-128, -192 and -256, tags of 128 and 96 bits
 * (CK_GCM_PARAMS.ulTagBits), and messages of 0, 13 and 100 bytes:
 *   (1) one-shot C_Sign gives OpenSSL's tag, truncated to the length asked
 *   (2) multipart, in three parts (one empty), gives the same tag, and
 *       C_SignFinal with a NULL buffer reports that length
 *   (3) C_VerifyUpdate / C_VerifyFinal accepts it, and answers
 *       CKR_SIGNATURE_INVALID with one bit changed or with the full 16
 *       bytes when 12 were asked for
 * and (0) Test Case 1, one-shot and with no C_SignUpdate at all.
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
typedef struct { CK_BYTE *pIv; CK_ULONG ulIvLen, ulIvBits; CK_BYTE *pAAD;
                 CK_ULONG ulAADLen, ulTagBits; } CK_GCM_PARAMS;

#define CKR_OK                0UL
#define CKR_SIGNATURE_INVALID 0xC0UL
#define CKF_RW                6UL
#define CKA_CLASS             0x000UL
#define CKA_TOKEN             0x001UL
#define CKA_VALUE             0x011UL
#define CKA_KEY_TYPE          0x100UL
#define CKA_SIGN              0x108UL
#define CKA_VERIFY            0x10AUL
#define CKO_SECRET_KEY        4UL
#define CKK_AES               0x1FUL
#define CKM_AES_GMAC          0x108EUL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);

/* OpenSSL's GMAC, the full 16-byte tag. */
static int ref_gmac(const CK_BYTE *key, size_t kl, const CK_BYTE *iv, size_t ivl,
                    const CK_BYTE *m, size_t ml, CK_BYTE out[16]) {
    const char *cn = kl == 16 ? "AES-128-GCM" : kl == 24 ? "AES-192-GCM" : "AES-256-GCM";
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "GMAC", NULL);
    EVP_MAC_CTX *c = mac ? EVP_MAC_CTX_new(mac) : NULL;
    OSSL_PARAM p[3] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, (char *)cn, 0),
        OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV, (void *)iv, ivl),
        OSSL_PARAM_construct_end(),
    };
    size_t ol = 0;
    int r = c && EVP_MAC_init(c, key, kl, p) == 1 && EVP_MAC_update(c, m, ml) == 1
            && EVP_MAC_final(c, out, &ol, 16) == 1 && ol == 16;
    EVP_MAC_CTX_free(c);
    EVP_MAC_free(mac);
    return r;
}

static CK_OBJECT_HANDLE import_aes(CK_SESSION_HANDLE s, CK_BYTE *key, CK_ULONG kl) {
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES;
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE t[] = {
        { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
        { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 }, { CKA_VERIFY, &yes, 1 },
        { CKA_VALUE, key, kl },
    };
    CK_OBJECT_HANDLE k = 0;
    return C_CreateObject(s, t, sizeof t / sizeof t[0], &k) == CKR_OK ? k : 0;
}

static CK_RV sign_mp(CK_SESSION_HANDLE s, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                     CK_BYTE *msg, CK_ULONG ml, CK_BYTE *out, CK_ULONG *ol, CK_ULONG *q) {
    CK_ULONG a = ml < 5 ? ml : 5;
    CK_RV rv = C_SignInit(s, m, k);
    if (rv == CKR_OK && ml) rv = C_SignUpdate(s, msg, a);
    if (rv == CKR_OK && ml) rv = C_SignUpdate(s, msg + a, 0);
    if (rv == CKR_OK && ml) rv = C_SignUpdate(s, msg + a, ml - a);
    if (rv == CKR_OK) rv = C_SignFinal(s, NULL, q);
    if (rv == CKR_OK) rv = C_SignFinal(s, out, ol);
    return rv;
}

static CK_RV verify_mp(CK_SESSION_HANDLE s, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                       CK_BYTE *msg, CK_ULONG ml, CK_BYTE *tag, CK_ULONG tl) {
    CK_ULONG half = ml / 2;
    CK_RV rv = C_VerifyInit(s, m, k);
    if (rv == CKR_OK) rv = C_VerifyUpdate(s, msg, half);
    if (rv == CKR_OK) rv = C_VerifyUpdate(s, msg + half, ml - half);
    if (rv == CKR_OK) rv = C_VerifyFinal(s, tag, tl);
    return rv;
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
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    if (!C_CreateObject || !C_SignInit || !C_Sign || !C_SignUpdate || !C_SignFinal
        || !C_VerifyInit || !C_VerifyUpdate || !C_VerifyFinal) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("AES-GMAC, one-shot and multipart\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "gmac")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    char what[112];

    /* (0) GCM specification, Test Case 1. */
    {
        static const CK_BYTE T1[16] = { 0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
                                        0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a };
        CK_BYTE key[16] = { 0 }, iv[12] = { 0 }, out[16];
        CK_OBJECT_HANDLE k = import_aes(s, key, sizeof key);
        CK_GCM_PARAMS gp = { iv, sizeof iv, 96, NULL, 0, 128 };
        CK_MECHANISM m = { CKM_AES_GMAC, &gp, sizeof gp };
        CK_ULONG ol = sizeof out, q = 0;
        CK_RV rv = k ? C_SignInit(s, &m, k) : 0x6UL;
        if (rv == CKR_OK) rv = C_Sign(s, (CK_BYTE *)"", 0, out, &ol);
        snprintf(what, sizeof what, "(0) Test Case 1, one-shot (rv 0x%lx)", rv);
        ok(rv == CKR_OK && ol == 16 && !memcmp(out, T1, 16), what);
        ol = sizeof out;
        rv = k ? sign_mp(s, &m, k, NULL, 0, out, &ol, &q) : 0x6UL;
        snprintf(what, sizeof what, "(0) Test Case 1, no Update (rv 0x%lx)", rv);
        ok(rv == CKR_OK && ol == 16 && !memcmp(out, T1, 16), what);
    }

    static const size_t KEYS[] = { 16, 24, 32 };
    static const CK_ULONG TAGS[] = { 128, 96 };
    static const size_t LENS[] = { 0, 13, 100 };
    CK_BYTE msg[100], iv[12];
    for (size_t i = 0; i < sizeof msg; ++i) msg[i] = (CK_BYTE)(i * 31 + 7);
    for (size_t i = 0; i < sizeof iv; ++i) iv[i] = (CK_BYTE)(0xA0 + i);

    for (size_t ki = 0; ki < 3; ++ki) {
        CK_BYTE key[32];
        for (size_t i = 0; i < KEYS[ki]; ++i) key[i] = (CK_BYTE)(i * 7 + ki);
        CK_OBJECT_HANDLE k = import_aes(s, key, KEYS[ki]);
        if (!k) { ok(0, "AES key imports"); continue; }
        for (size_t ti = 0; ti < 2; ++ti) {
            const CK_ULONG tl = TAGS[ti] / 8;
            CK_GCM_PARAMS gp = { iv, sizeof iv, 96, NULL, 0, TAGS[ti] };
            CK_MECHANISM m = { CKM_AES_GMAC, &gp, sizeof gp };
            for (size_t li = 0; li < 3; ++li) {
                const CK_ULONG ml = LENS[li];
                CK_BYTE ref[16], out[16];
                char name[48];
                snprintf(name, sizeof name, "AES-%zu, %lu-bit tag, %lu bytes",
                         KEYS[ki] * 8, TAGS[ti], ml);
                if (!ref_gmac(key, KEYS[ki], iv, sizeof iv, msg, ml, ref)) {
                    ok(0, "OpenSSL reference GMAC"); continue;
                }
                /* (1) */
                CK_ULONG ol = sizeof out;
                CK_RV rv = C_SignInit(s, &m, k);
                if (rv == CKR_OK) rv = C_Sign(s, msg, ml, out, &ol);
                snprintf(what, sizeof what, "(1) %s: one-shot (rv 0x%lx)", name, rv);
                ok(rv == CKR_OK && ol == tl && !memcmp(out, ref, tl), what);
                /* (2) */
                CK_ULONG q = 0;
                ol = sizeof out;
                rv = sign_mp(s, &m, k, msg, ml, out, &ol, &q);
                snprintf(what, sizeof what, "(2) %s: multipart (rv 0x%lx)", name, rv);
                ok(rv == CKR_OK && q == tl && ol == tl && !memcmp(out, ref, tl), what);
                /* (3) */
                rv = verify_mp(s, &m, k, msg, ml, ref, tl);
                snprintf(what, sizeof what, "(3) %s: verified (rv 0x%lx)", name, rv);
                ok(rv == CKR_OK, what);
                CK_BYTE bad[16];
                memcpy(bad, ref, 16); bad[3] ^= 0x01;
                rv = verify_mp(s, &m, k, msg, ml, bad, tl);
                snprintf(what, sizeof what, "(3) %s: one bit changed, rejected (rv 0x%lx)", name, rv);
                ok(rv == CKR_SIGNATURE_INVALID, what);
                if (tl < 16) {
                    rv = verify_mp(s, &m, k, msg, ml, ref, 16);
                    snprintf(what, sizeof what, "(3) %s: the 16-byte tag, rejected (rv 0x%lx)", name, rv);
                    ok(rv == CKR_SIGNATURE_INVALID, what);
                }
            }
        }
    }

    (void)C_Finalize(NULL);
    printf("\n%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
