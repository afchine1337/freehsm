/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_des3_modes.c --- CKM_DES3_ECB, CKM_DES3_CBC and CKM_DES3_CBC_PAD,
 * single-part and in parts (2.8.0).
 *
 *   (E) ECB: the SP 800-67 example, three blocks, both ways.
 *   (C) CBC with a non-zero IV over the same blocks: the expected value is
 *       chained by hand from single ECB blocks, so the chaining is checked
 *       against the vector ECB was checked against.
 *   (P) CBC-PAD over 21 and 24 bytes: CBC over the data with its PKCS#7
 *       padding (3 bytes of 03, a whole block of 08).
 *       Each of the above through C_Encrypt, C_Decrypt, and both in parts of
 *       5 bytes and the rest.
 *   (L) 20 bytes of ECB: CKR_DATA_LEN_RANGE single-part and at
 *       C_EncryptFinal in parts, CKR_ENCRYPTED_DATA_LEN_RANGE to decrypt;
 *       an empty CBC-PAD ciphertext, CKR_ENCRYPTED_DATA_LEN_RANGE; a CBC-PAD
 *       ciphertext whose padding does not check out,
 *       CKR_ENCRYPTED_DATA_INVALID.
 *   (I) CBC-PAD without an IV is CKR_MECHANISM_PARAM_INVALID; an AES key is
 *       CKR_KEY_TYPE_INCONSISTENT.
 *   (N) in the nist-approved-only build, neither new mode is listed and
 *       C_EncryptInit is CKR_MECHANISM_INVALID.
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
#define CKR_ENCRYPTED_DATA_INVALID     0x040UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE   0x041UL
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_DES3                       0x15UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_DECRYPT                    0x105UL
#define CKM_DES3_ECB                   0x132UL
#define CKM_DES3_CBC                   0x133UL
#define CKM_DES3_CBC_PAD               0x136UL
#define CKM_DES3_KEY_GEN               0x131UL

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

static CK_RV one_shot(int enc, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                      const CK_BYTE *in, CK_ULONG il, CK_BYTE *out, CK_ULONG *ol) {
    CK_RV rv = enc ? C_EncryptInit(s, m, k) : C_DecryptInit(s, m, k);
    if (rv != CKR_OK) return rv;
    return enc ? C_Encrypt(s, (CK_BYTE*)in, il, out, ol) : C_Decrypt(s, (CK_BYTE*)in, il, out, ol);
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

static void vector(const char *name, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                   const CK_BYTE *pt, CK_ULONG pl, const CK_BYTE *ct, CK_ULONG cl) {
    char what[128];
    CK_BYTE out[256];
    CK_ULONG ol = sizeof out;
    CK_RV rv = one_shot(1, m, k, pt, pl, out, &ol);
    snprintf(what, sizeof what, "%s: C_Encrypt, %lu bytes (0x%lx)", name, pl, rv);
    ok(rv == CKR_OK && ol == cl && memcmp(out, ct, cl) == 0, what);
    ol = sizeof out;
    rv = one_shot(0, m, k, ct, cl, out, &ol);
    snprintf(what, sizeof what, "%s: C_Decrypt (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == pl && memcmp(out, pt, pl) == 0, what);
    rv = in_parts(1, m, k, pt, pl, out, &ol);
    snprintf(what, sizeof what, "%s: encrypt in parts (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == cl && memcmp(out, ct, cl) == 0, what);
    rv = in_parts(0, m, k, ct, cl, out, &ol);
    snprintf(what, sizeof what, "%s: decrypt in parts (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == pl && memcmp(out, pt, pl) == 0, what);
}

/* CBC built from single ECB blocks: c_i = E(p_i ^ c_{i-1}), c_0 = IV. */
static int cbc_by_hand(CK_OBJECT_HANDLE k, const CK_BYTE *iv, const CK_BYTE *p, CK_ULONG n,
                       CK_BYTE *c) {
    CK_MECHANISM ecb = { CKM_DES3_ECB, NULL, 0 };
    const CK_BYTE *prev = iv;
    for (CK_ULONG i = 0; i < n; i += 8) {
        CK_BYTE x[8];
        for (int j = 0; j < 8; j++) x[j] = (CK_BYTE)(p[i + (CK_ULONG)j] ^ prev[j]);
        CK_ULONG l = 8;
        if (one_shot(1, &ecb, k, x, 8, c + i, &l) != CKR_OK || l != 8) return 0;
        prev = c + i;
    }
    return 1;
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

    printf("3DES ECB, CBC, CBC-PAD\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "des3modes", 9);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    /* (N) The nist-approved-only build lists no 3DES key generator. */
    if (!listed(CKM_DES3_KEY_GEN)) {
        char what[128];
        CK_BYTE av[16] = { 0 };
        CK_OBJECT_HANDLE ak = key_of(av, 16, CKK_AES);
        CK_MECHANISM m = { CKM_DES3_ECB, NULL, 0 };
        CK_RV rv = C_EncryptInit(s, &m, ak);
        ok(!listed(CKM_DES3_ECB) && !listed(CKM_DES3_CBC_PAD), "(N) DES3_ECB, DES3_CBC_PAD not listed");
        snprintf(what, sizeof what, "(N) C_EncryptInit: MECHANISM_INVALID (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_INVALID, what);
        C_Finalize(NULL);
        printf("\n%s\n", fails ? "FAILURES" : "all good");
        return fails ? 1 : 0;
    }
    ok(listed(CKM_DES3_ECB) && listed(CKM_DES3_CBC_PAD), "DES3_ECB, DES3_CBC_PAD listed");

    CK_BYTE kv[24], fox[24], ct[24], av[16] = { 0 };
    unhex("0123456789abcdef23456789abcdef01456789abcdef0123", kv);
    memcpy(fox, "The qufck brown fox jump", 24);
    unhex("a826fd8ce53b855fcce21c8112256fe668d5c05dd9b6b900", ct);
    CK_OBJECT_HANDLE k = key_of(kv, 24, CKK_DES3), ak = key_of(av, 16, CKK_AES);
    if (!k || !ak) { fprintf(stderr, "key import\n"); return 2; }

    /* (E) */
    CK_MECHANISM ecb = { CKM_DES3_ECB, NULL, 0 };
    vector("(E) ECB, SP 800-67", &ecb, k, fox, 24, ct, 24);

    /* (C) */
    CK_BYTE iv[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, cbc_ct[24];
    ok(cbc_by_hand(k, iv, fox, 24, cbc_ct), "(C) CBC chained by hand from ECB blocks");
    CK_MECHANISM cbc = { CKM_DES3_CBC, iv, 8 };
    vector("(C) CBC, IV 01..08", &cbc, k, fox, 24, cbc_ct, 24);

    /* (P) */
    CK_MECHANISM pad = { CKM_DES3_CBC_PAD, iv, 8 };
    {
        CK_BYTE p21[24], c21[24], p32[32], c32[32];
        memcpy(p21, fox, 21); memset(p21 + 21, 3, 3);
        memcpy(p32, fox, 24); memset(p32 + 24, 8, 8);
        int built = cbc_by_hand(k, iv, p21, 24, c21) && cbc_by_hand(k, iv, p32, 32, c32);
        ok(built, "(P) padded CBC chained by hand");
        vector("(P) CBC-PAD, 21 bytes", &pad, k, fox, 21, c21, 24);
        vector("(P) CBC-PAD, 24 bytes", &pad, k, fox, 24, c32, 32);
    }

    /* (L) */
    {
        char what[160];
        CK_BYTE out[64]; CK_ULONG ol = sizeof out;
        CK_RV r1 = one_shot(1, &ecb, k, fox, 20, out, &ol);
        ol = sizeof out;
        CK_RV r2 = in_parts(1, &ecb, k, fox, 20, out, &ol);
        ol = sizeof out;
        CK_RV r3 = one_shot(0, &ecb, k, ct, 20, out, &ol);
        ol = sizeof out;
        CK_RV r4 = one_shot(0, &pad, k, ct, 0, out, &ol);
        snprintf(what, sizeof what,
                 "(L) 20 bytes ECB, in parts, to decrypt; empty CBC-PAD (0x%lx 0x%lx 0x%lx 0x%lx)",
                 r1, r2, r3, r4);
        ok(r1 == CKR_DATA_LEN_RANGE && r2 == CKR_DATA_LEN_RANGE
           && r3 == CKR_ENCRYPTED_DATA_LEN_RANGE && r4 == CKR_ENCRYPTED_DATA_LEN_RANGE, what);
        /* The CBC ciphertext of the fox ends in 'p' (0x70), not a padding. */
        ol = sizeof out;
        CK_RV r5 = one_shot(0, &pad, k, cbc_ct, 24, out, &ol);
        ol = sizeof out;
        CK_RV r6 = in_parts(0, &pad, k, cbc_ct, 24, out, &ol);
        snprintf(what, sizeof what, "(L) bad padding: ENCRYPTED_DATA_INVALID, single and in parts (0x%lx 0x%lx)",
                 r5, r6);
        ok(r5 == CKR_ENCRYPTED_DATA_INVALID && r6 == CKR_ENCRYPTED_DATA_INVALID, what);
    }

    /* (I) */
    {
        char what[128];
        CK_MECHANISM none = { CKM_DES3_CBC_PAD, NULL, 0 };
        CK_RV r1 = C_EncryptInit(s, &none, k);
        CK_RV r2 = C_EncryptInit(s, &ecb, ak);
        snprintf(what, sizeof what, "(I) no IV: PARAM_INVALID; AES key: KEY_TYPE_INCONSISTENT (0x%lx 0x%lx)",
                 r1, r2);
        ok(r1 == CKR_MECHANISM_PARAM_INVALID && r2 == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
