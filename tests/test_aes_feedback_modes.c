/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_aes_feedback_modes.c --- CKM_AES_OFB, CKM_AES_CFB1, CKM_AES_CFB8 and
 * CKM_AES_CFB128 (2.8.0).
 *
 *   (V) the SP 800-38A F.3 and F.4 vectors (AES-128, and AES-256 for OFB and
 *       CFB8): C_Encrypt gives the ciphertext, C_Decrypt the plaintext, and
 *       C_EncryptUpdate / C_DecryptUpdate in uneven parts give the same.
 *   (L) a 37-byte message, not a whole number of blocks, under OFB and
 *       CFB128: the ciphertext is 37 bytes and the expected one.
 *   (P) no IV, or an IV of 15 bytes, is CKR_MECHANISM_PARAM_INVALID; a
 *       generic secret key is CKR_KEY_TYPE_INCONSISTENT.
 * The expected values were computed with a pure-Python AES checked against
 * FIPS 197 C.1, not with OpenSSL, and agree with SP 800-38A's appendix F.
 * Approved modes: the same results in both builds.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                       0x000UL
#define CKR_KEY_TYPE_INCONSISTENT    0x063UL
#define CKR_MECHANISM_PARAM_INVALID  0x071UL
#define CKF_RW                       6UL
#define CKO_SECRET_KEY               4UL
#define CKK_GENERIC_SECRET           0x10UL
#define CKK_AES                      0x1FUL
#define CKA_CLASS                    0x000UL
#define CKA_TOKEN                    0x001UL
#define CKA_VALUE                    0x011UL
#define CKA_KEY_TYPE                 0x100UL
#define CKA_ENCRYPT                  0x104UL
#define CKA_DECRYPT                  0x105UL
#define CKM_AES_OFB                  0x2104UL
#define CKM_AES_CFB8                 0x2106UL
#define CKM_AES_CFB128               0x2107UL
#define CKM_AES_CFB1                 0x2108UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;

static size_t unhex(const char *h, CK_BYTE *out) {
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (CK_BYTE)v;
    }
    return n;
}

static CK_OBJECT_HANDLE key_of(const char *hex, CK_ULONG kt) {
    CK_BYTE v[32];
    size_t vl = unhex(hex, v);
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 },
                         { CKA_DECRYPT, &yes, 1 }, { CKA_VALUE, v, (CK_ULONG)vl } };
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, 6, &h) == CKR_OK ? h : 0;
}

static int listed(CK_ULONG mech) {
    CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
    CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
    C_GetMechanismList(0, ml, &n);
    int found = 0;
    for (CK_ULONG i = 0; i < n; i++) if (ml[i] == mech) found = 1;
    free(ml);
    return found;
}

/* In parts of 5 bytes, then the rest; encrypt (enc = 1) or decrypt. */
static CK_RV in_parts(int enc, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                      const CK_BYTE *in, CK_ULONG il, CK_BYTE *out, CK_ULONG *ol) {
    CK_RV rv = enc ? C_EncryptInit(s, m, k) : C_DecryptInit(s, m, k);
    CK_ULONG done = 0, cut = il < 5 ? il : 5;
    CK_ULONG pieces[2] = { cut, il - cut };
    CK_ULONG off = 0;
    for (int i = 0; i < 2 && rv == CKR_OK; i++) {
        CK_ULONG l = 64;
        rv = enc ? C_EncryptUpdate(s, (CK_BYTE*)in + off, pieces[i], out + done, &l)
                 : C_DecryptUpdate(s, (CK_BYTE*)in + off, pieces[i], out + done, &l);
        off += pieces[i];
        done += l;
    }
    if (rv == CKR_OK) {
        CK_ULONG l = 16;
        rv = enc ? C_EncryptFinal(s, out + done, &l) : C_DecryptFinal(s, out + done, &l);
        done += l;
    }
    *ol = done;
    return rv;
}

static void vector(const char *name, CK_ULONG mech, CK_OBJECT_HANDLE k,
                   const char *pthex, const char *cthex) {
    char what[128];
    CK_BYTE iv[16], pt[64], ct[64], out[96];
    for (int i = 0; i < 16; i++) iv[i] = (CK_BYTE)i;
    size_t pl = unhex(pthex, pt), cl = unhex(cthex, ct);
    CK_MECHANISM m = { mech, iv, sizeof iv };
    CK_ULONG ol = sizeof out;
    CK_RV rv = C_EncryptInit(s, &m, k);
    if (rv == CKR_OK) rv = C_Encrypt(s, pt, (CK_ULONG)pl, out, &ol);
    snprintf(what, sizeof what, "%s: C_Encrypt, %zu bytes (0x%lx)", name, pl, rv);
    ok(rv == CKR_OK && ol == cl && memcmp(out, ct, cl) == 0, what);
    ol = sizeof out;
    rv = C_DecryptInit(s, &m, k);
    if (rv == CKR_OK) rv = C_Decrypt(s, ct, (CK_ULONG)cl, out, &ol);
    snprintf(what, sizeof what, "%s: C_Decrypt (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == pl && memcmp(out, pt, pl) == 0, what);
    rv = in_parts(1, &m, k, pt, (CK_ULONG)pl, out, &ol);
    snprintf(what, sizeof what, "%s: encrypt in parts (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == cl && memcmp(out, ct, cl) == 0, what);
    rv = in_parts(0, &m, k, ct, (CK_ULONG)cl, out, &ol);
    snprintf(what, sizeof what, "%s: decrypt in parts (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == pl && memcmp(out, pt, pl) == 0, what);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_EncryptInit); SYM(C_Encrypt); SYM(C_EncryptUpdate);
    SYM(C_EncryptFinal); SYM(C_DecryptInit); SYM(C_Decrypt); SYM(C_DecryptUpdate);
    SYM(C_DecryptFinal);
    if (!C_DecryptFinal || !C_EncryptFinal) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("AES OFB, CFB1, CFB8 and CFB128\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "aesfb", 5);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    CK_OBJECT_HANDLE k128 = key_of("2b7e151628aed2a6abf7158809cf4f3c", CKK_AES);
    CK_OBJECT_HANDLE k256 = key_of("603deb1015ca71be2b73aef0857d7781"
                                   "1f352c073b6108d72d9810a30914dff4", CKK_AES);
    CK_OBJECT_HANDLE gen  = key_of("2b7e151628aed2a6abf7158809cf4f3c", CKK_GENERIC_SECRET);
    if (!k128 || !k256 || !gen) { fprintf(stderr, "key import\n"); return 2; }

    static const CK_ULONG mechs[] = { CKM_AES_OFB, CKM_AES_CFB1, CKM_AES_CFB8, CKM_AES_CFB128 };
    static const char *const names[] = { "OFB", "CFB1", "CFB8", "CFB128" };
    for (size_t i = 0; i < 4; i++) {
        char what[64];
        snprintf(what, sizeof what, "AES %s listed", names[i]);
        ok(listed(mechs[i]), what);
    }

    /* (V) */
    static const char PT[] = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
    vector("(V) OFB AES-128", CKM_AES_OFB, k128, PT,
           "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825");
    vector("(V) OFB AES-256", CKM_AES_OFB, k256, PT,
           "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d");
    vector("(V) CFB128 AES-128", CKM_AES_CFB128, k128, PT,
           "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b");
    vector("(V) CFB8 AES-128", CKM_AES_CFB8, k128, "6bc1bee22e409f96e93d7e117393172aae2d",
           "3b79424c9c0dd436bace9e0ed4586a4f32b9");
    vector("(V) CFB8 AES-256", CKM_AES_CFB8, k256, "6bc1bee22e409f96e93d7e117393172aae2d",
           "dc1f1a8520a64db55fcc8ac554844e889700");
    vector("(V) CFB1 AES-128", CKM_AES_CFB1, k128, "6bc1", "68b3");

    /* (L) */
    static const char M37[] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                               "2021222324";
    vector("(L) OFB, 37 bytes", CKM_AES_OFB, k128, M37,
           "50ff65cf9d6834b1d2003de297a2e26fc9b5c8c91c8735887392276d9cfc486b87a93b7b1b");
    vector("(L) CFB128, 37 bytes", CKM_AES_CFB128, k128, M37,
           "50ff65cf9d6834b1d2003de297a2e26f73b15dd3f6575d3e4994d4ca738acb36571768c63b");

    /* (P) */
    for (size_t i = 0; i < 4; i++) {
        char what[128];
        CK_BYTE iv[16] = { 0 };
        CK_MECHANISM none = { mechs[i], NULL, 0 }, shrt = { mechs[i], iv, 15 },
                     good = { mechs[i], iv, 16 };
        CK_RV r0 = C_EncryptInit(s, &none, k128);
        CK_RV r15 = C_DecryptInit(s, &shrt, k128);
        snprintf(what, sizeof what, "(P) %s: no IV, 15-byte IV: PARAM_INVALID (0x%lx, 0x%lx)",
                 names[i], r0, r15);
        ok(r0 == CKR_MECHANISM_PARAM_INVALID && r15 == CKR_MECHANISM_PARAM_INVALID, what);
        CK_RV rk = C_EncryptInit(s, &good, gen);
        snprintf(what, sizeof what, "(P) %s: generic secret key: KEY_TYPE_INCONSISTENT (0x%lx)",
                 names[i], rk);
        ok(rk == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
