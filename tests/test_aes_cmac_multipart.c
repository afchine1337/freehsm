/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_aes_cmac_multipart.c --- CKM_AES_CMAC through C_SignUpdate /
 * C_SignFinal and C_VerifyUpdate / C_VerifyFinal, against NIST SP 800-38B's
 * examples (also RFC 4493 §4).
 *
 * Multipart CMAC answered CKR_MECHANISM_INVALID at the first Update, while
 * C_SignInit accepted the mechanism for the one-shot path: pkcs11-check's
 * TestMultipartSign scored it advertised but not operational.
 *
 * What is asserted, for each example:
 *   (1) one-shot C_Sign gives the example's tag
 *   (2) multipart, the message in three parts (one of them empty), gives the
 *       same tag; C_SignFinal with a NULL buffer reports 16 and leaves the
 *       operation active
 *   (3) multipart with no C_SignUpdate at all gives the empty message's tag
 *   (4) C_VerifyUpdate / C_VerifyFinal accepts the tag, and answers
 *       CKR_SIGNATURE_INVALID with one bit changed or one byte short
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

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
#define CKM_AES_CMAC          0x108AUL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static const char *MSG64 =
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

/* SP 800-38B Appendix D, Examples 1-4 (AES-128), 8 (AES-192), 9 and 12
 * (AES-256). Message lengths are prefixes of MSG64. */
static const struct { const char *name, *key; size_t mlen; const char *tag; } EX[] = {
    { "AES-128, 0 bytes",  "2b7e151628aed2a6abf7158809cf4f3c", 0,  "bb1d6929e95937287fa37d129b756746" },
    { "AES-128, 16 bytes", "2b7e151628aed2a6abf7158809cf4f3c", 16, "070a16b46b4d4144f79bdd9dd04a287c" },
    { "AES-128, 40 bytes", "2b7e151628aed2a6abf7158809cf4f3c", 40, "dfa66747de9ae63030ca32611497c827" },
    { "AES-128, 64 bytes", "2b7e151628aed2a6abf7158809cf4f3c", 64, "51f0bebf7e3b9d92fc49741779363cfe" },
    { "AES-192, 64 bytes", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 64,
                           "a1d5df0eed790f794d77589659f39a11" },
    { "AES-256, 0 bytes",  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 0,
                           "028962f61b7bf89efc6b551f4667d983" },
    { "AES-256, 64 bytes", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 64,
                           "e1992190549f6ed5696a2c056c315410" },
};
#define NEX (sizeof EX / sizeof EX[0])

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

static size_t unhex(const char *h, CK_BYTE *out) {
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; ++i) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (CK_BYTE)v; }
    return n;
}

static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);

static CK_RV verify_mp(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k, CK_BYTE *m, CK_ULONG ml,
                       CK_BYTE *tag, CK_ULONG tl) {
    CK_MECHANISM mech = { CKM_AES_CMAC, NULL, 0 };
    CK_ULONG half = ml / 2;
    CK_RV rv = C_VerifyInit(s, &mech, k);
    if (rv == CKR_OK) rv = C_VerifyUpdate(s, m, half);
    if (rv == CKR_OK) rv = C_VerifyUpdate(s, m + half, ml - half);
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
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    if (!C_CreateObject || !C_SignInit || !C_Sign || !C_SignUpdate || !C_SignFinal
        || !C_VerifyInit || !C_VerifyUpdate || !C_VerifyFinal) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("AES-CMAC, one-shot and multipart, against SP 800-38B\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "cmac")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    CK_BYTE msg[64];
    unhex(MSG64, msg);
    char what[112];

    for (size_t i = 0; i < NEX; ++i) {
        CK_BYTE key[32], tag[16], out[32];
        CK_ULONG kl = unhex(EX[i].key, key), ml = EX[i].mlen;
        unhex(EX[i].tag, tag);

        CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES;
        CK_BYTE yes = 1, no = 0;
        CK_ATTRIBUTE t[] = {
            { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
            { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 }, { CKA_VERIFY, &yes, 1 },
            { CKA_VALUE, key, kl },
        };
        CK_OBJECT_HANDLE k = 0;
        if (C_CreateObject(s, t, sizeof t / sizeof t[0], &k) != CKR_OK) {
            snprintf(what, sizeof what, "%s: key imports", EX[i].name);
            ok(0, what); continue;
        }
        CK_MECHANISM mech = { CKM_AES_CMAC, NULL, 0 };

        /* (1) */
        CK_ULONG ol = sizeof out;
        CK_RV rv = C_SignInit(s, &mech, k);
        if (rv == CKR_OK) rv = C_Sign(s, msg, ml, out, &ol);
        snprintf(what, sizeof what, "(1) %s, one-shot: the example's tag (rv 0x%lx)", EX[i].name, rv);
        ok(rv == CKR_OK && ol == 16 && !memcmp(out, tag, 16), what);

        /* (2) or (3) */
        CK_ULONG q = 0;
        ol = sizeof out;
        rv = C_SignInit(s, &mech, k);
        if (ml) {
            CK_ULONG a = ml < 7 ? ml : 7;
            if (rv == CKR_OK) rv = C_SignUpdate(s, msg, a);
            if (rv == CKR_OK) rv = C_SignUpdate(s, msg + a, 0);
            if (rv == CKR_OK) rv = C_SignUpdate(s, msg + a, ml - a);
        }
        CK_RV rq = rv == CKR_OK ? C_SignFinal(s, NULL, &q) : rv;
        if (rq == CKR_OK) rv = C_SignFinal(s, out, &ol);
        snprintf(what, sizeof what, "(%d) %s, %s: the same tag (rv 0x%lx)", ml ? 2 : 3,
                 EX[i].name, ml ? "three parts" : "no Update", rv);
        ok(rq == CKR_OK && q == 16 && rv == CKR_OK && ol == 16 && !memcmp(out, tag, 16), what);

        /* (4) */
        rv = verify_mp(s, k, msg, ml, tag, 16);
        snprintf(what, sizeof what, "(4) %s, multipart verify: accepted (rv 0x%lx)", EX[i].name, rv);
        ok(rv == CKR_OK, what);
        CK_BYTE bad[16];
        memcpy(bad, tag, 16); bad[5] ^= 0x01;
        rv = verify_mp(s, k, msg, ml, bad, 16);
        snprintf(what, sizeof what, "(4) %s, one bit changed: rejected (rv 0x%lx)", EX[i].name, rv);
        ok(rv == CKR_SIGNATURE_INVALID, what);
        rv = verify_mp(s, k, msg, ml, tag, 15);
        snprintf(what, sizeof what, "(4) %s, 15 bytes: rejected (rv 0x%lx)", EX[i].name, rv);
        ok(rv == CKR_SIGNATURE_INVALID, what);
    }

    (void)C_Finalize(NULL);
    printf("\n%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
