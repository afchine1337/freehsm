/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_aes_cts.c --- CKM_AES_CTS, CBC with ciphertext stealing, variant CS3
 * (2.8.0).
 *
 *   (V) the RFC 3962 Appendix B vectors (AES-128, zero IV) at 16, 17, 31 and
 *       32 bytes, and 47, 48 and 64 bytes of another message, and 37 bytes
 *       under AES-256 with a non-zero IV: C_Encrypt gives the ciphertext,
 *       C_Decrypt the plaintext, and the multipart forms, in parts of 5
 *       bytes and the rest, the same.
 *   (L) fewer than 16 bytes: CKR_DATA_LEN_RANGE to encrypt,
 *       CKR_ENCRYPTED_DATA_LEN_RANGE to decrypt, single-part and multipart.
 *   (P) no IV is CKR_MECHANISM_PARAM_INVALID; a generic secret key is
 *       CKR_KEY_TYPE_INCONSISTENT.
 * The expected values were computed with a pure-Python AES checked against
 * FIPS 197 C.1, not with OpenSSL; at 17, 31 and 32 bytes they are RFC
 * 3962's. Approved: the same results in both builds.
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

#define CKR_OK                         0x000UL
#define CKR_DATA_LEN_RANGE             0x021UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE   0x041UL
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_DECRYPT                    0x105UL
#define CKM_AES_CTS                    0x1089UL

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

static CK_OBJECT_HANDLE key_of(const CK_BYTE *v, CK_ULONG vl, CK_ULONG kt) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 },
                         { CKA_DECRYPT, &yes, 1 }, { CKA_VALUE, (void*)v, vl } };
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

/* In parts of 5 bytes and the rest; encrypt (enc = 1) or decrypt. */
static CK_RV in_parts(int enc, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                      const CK_BYTE *in, CK_ULONG il, CK_BYTE *out, CK_ULONG *ol) {
    CK_RV rv = enc ? C_EncryptInit(s, m, k) : C_DecryptInit(s, m, k);
    CK_ULONG cut = il < 5 ? il : 5, done = 0;
    CK_ULONG pieces[2] = { cut, il - cut }, off = 0;
    for (int i = 0; i < 2 && rv == CKR_OK; i++) {
        CK_ULONG l = 128;
        rv = enc ? C_EncryptUpdate(s, (CK_BYTE*)in + off, pieces[i], out + done, &l)
                 : C_DecryptUpdate(s, (CK_BYTE*)in + off, pieces[i], out + done, &l);
        off += pieces[i];
        done += l;
    }
    if (rv == CKR_OK) {
        CK_ULONG l = 128;
        rv = enc ? C_EncryptFinal(s, out + done, &l) : C_DecryptFinal(s, out + done, &l);
        done += l;
    }
    *ol = done;
    return rv;
}

static void vector(const char *name, CK_OBJECT_HANDLE k, CK_BYTE *iv,
                   const CK_BYTE *pt, size_t pl, const char *cthex) {
    char what[128];
    CK_BYTE ct[128], out[256];
    size_t cl = unhex(cthex, ct);
    CK_MECHANISM m = { CKM_AES_CTS, iv, 16 };
    CK_ULONG ol = sizeof out;
    CK_RV rv = C_EncryptInit(s, &m, k);
    if (rv == CKR_OK) rv = C_Encrypt(s, (CK_BYTE*)pt, (CK_ULONG)pl, out, &ol);
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

    printf("AES-CTS (CS3)\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "aescts", 6);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    ok(listed(CKM_AES_CTS), "CKM_AES_CTS listed");
    static const CK_BYTE teriyaki[] = "chicken teriyaki";
    CK_BYTE k256v[32];
    unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", k256v);
    CK_OBJECT_HANDLE k = key_of(teriyaki, 16, CKK_AES), k256 = key_of(k256v, 32, CKK_AES),
                     gk = key_of(teriyaki, 16, CKK_GENERIC_SECRET);
    if (!k || !k256 || !gk) { fprintf(stderr, "key import\n"); return 2; }

    /* (V) */
    CK_BYTE msg[64], ziv[16] = { 0 }, iv[16], seq[37];
    unhex("4920776f756c64206c696b65207468652047656e6572616c20476175277320"
          "4368696b656e2c20706c656173652c20616e64207768656e2077652068617665"
          "20", msg);
    for (int i = 0; i < 16; i++) iv[i] = (CK_BYTE)i;
    for (int i = 0; i < 37; i++) seq[i] = (CK_BYTE)i;
    static const struct { size_t n; const char *ct; } V[] = {
        { 16, "97687268d6ecccc0c07b25e25ecfe584" },
        { 17, "c6353568f2bf8cb4d8a580362da7ff7f97" },
        { 31, "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5" },
        { 32, "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584" },
        { 47, "97687268d6ecccc0c07b25e25ecfe584d2d3987a151f067a7b08eb6638ea8cbf"
              "39312523a78662d5be7fcbcc98ebf5" },
        { 48, "97687268d6ecccc0c07b25e25ecfe58486881537f0df9725c427559c9679f9b7"
              "39312523a78662d5be7fcbcc98ebf5a8" },
        { 64, "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8"
              "a584abc154fc78a9297ad379a504c8da86881537f0df9725c427559c9679f9b7" },
    };
    for (size_t i = 0; i < sizeof V / sizeof V[0]; i++) {
        char name[48];
        snprintf(name, sizeof name, "(V) AES-128, %zu bytes", V[i].n);
        vector(name, k, ziv, msg, V[i].n, V[i].ct);
    }
    vector("(V) AES-256, IV 00..0f, 37 bytes", k256, iv, seq, 37,
           "e568f68194cf76d6174d4cc04310a854fdde819483f78ec647dcdf7602927954d09ef932b9");

    /* (L) */
    {
        char what[128];
        CK_MECHANISM m = { CKM_AES_CTS, ziv, 16 };
        CK_BYTE out[64]; CK_ULONG ol = sizeof out;
        CK_RV re = C_EncryptInit(s, &m, k);
        if (re == CKR_OK) re = C_Encrypt(s, msg, 15, out, &ol);
        ol = sizeof out;
        CK_RV rd = C_DecryptInit(s, &m, k);
        if (rd == CKR_OK) rd = C_Decrypt(s, msg, 15, out, &ol);
        snprintf(what, sizeof what, "(L) 15 bytes: DATA_LEN_RANGE, ENCRYPTED_DATA_LEN_RANGE (0x%lx 0x%lx)",
                 re, rd);
        ok(re == CKR_DATA_LEN_RANGE && rd == CKR_ENCRYPTED_DATA_LEN_RANGE, what);
        CK_RV pe = in_parts(1, &m, k, msg, 15, out, &ol);
        CK_RV pd = in_parts(0, &m, k, msg, 15, out, &ol);
        snprintf(what, sizeof what, "(L) 15 bytes in parts: the same (0x%lx 0x%lx)", pe, pd);
        ok(pe == CKR_DATA_LEN_RANGE && pd == CKR_ENCRYPTED_DATA_LEN_RANGE, what);
    }

    /* (P) */
    {
        char what[128];
        CK_MECHANISM none = { CKM_AES_CTS, NULL, 0 }, good = { CKM_AES_CTS, ziv, 16 };
        CK_RV r0 = C_EncryptInit(s, &none, k);
        snprintf(what, sizeof what, "(P) no IV: PARAM_INVALID (0x%lx)", r0);
        ok(r0 == CKR_MECHANISM_PARAM_INVALID, what);
        CK_RV rk = C_EncryptInit(s, &good, gk);
        snprintf(what, sizeof what, "(P) generic secret key: KEY_TYPE_INCONSISTENT (0x%lx)", rk);
        ok(rk == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
