/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_des3_mac_family.c --- CKM_DES3_CMAC, CKM_DES3_CMAC_GENERAL,
 * CKM_DES3_MAC and CKM_DES3_MAC_GENERAL (2.8.0).
 *
 *   (C) CMAC over 0, 8, 13, 16, 24 and 37 bytes: CKM_DES3_CMAC gives 8
 *       bytes, CKM_DES3_CMAC_GENERAL the leading 4 and 8 of them.
 *   (M) CBC-MAC with a zero IV over the data padded with zero bytes:
 *       CKM_DES3_MAC gives 4 bytes, CKM_DES3_MAC_GENERAL the leading 3 and 8.
 *       Each through C_Sign, C_Sign in parts of 5 bytes and the rest,
 *       C_Verify and C_Verify in parts. A changed message, and a MAC of
 *       another length, are CKR_SIGNATURE_INVALID.
 *   (P) a GENERAL length of 0 or 9, or none, is CKR_MECHANISM_PARAM_INVALID.
 *   (K) an AES key is CKR_KEY_TYPE_INCONSISTENT.
 *   (N) where NIST's rules apply, C_SignInit is CKR_MECHANISM_INVALID; the
 *       nist-approved-only build lists none of the four.
 * The expected MACs are built here from single CKM_DES3_ECB blocks -- the
 * SP 800-38B subkeys (Rb = 0x1B) and chaining for CMAC, zero padding and
 * chaining for CBC-MAC -- and ECB is checked against the SP 800-67 example
 * first, so every MAC rests on that vector and not on OpenSSL's CMAC.
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
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKR_SIGNATURE_INVALID          0x0C0UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_DES3                       0x15UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKM_DES3_KEY_GEN               0x131UL
#define CKM_DES3_ECB                   0x132UL
#define CKM_DES3_MAC                   0x134UL
#define CKM_DES3_MAC_GENERAL           0x135UL
#define CKM_DES3_CMAC_GENERAL          0x137UL
#define CKM_DES3_CMAC                  0x138UL

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
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;
static CK_OBJECT_HANDLE k;

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
                         { CKA_SIGN, &yes, 1 }, { CKA_VERIFY, &yes, 1 },
                         { CKA_VALUE, (void*)v, vl } };
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, 7, &h) == CKR_OK ? h : 0;
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

/* --- the reference, on single ECB blocks ------------------------------- */
static int ecb_ok = 1;
static void E(const CK_BYTE in[8], CK_BYTE out[8]) {
    CK_MECHANISM m = { CKM_DES3_ECB, NULL, 0 };
    CK_ULONG l = 8;
    if (C_EncryptInit(s, &m, k) != CKR_OK || C_Encrypt(s, (CK_BYTE*)in, 8, out, &l) != CKR_OK
        || l != 8)
        ecb_ok = 0;
}

static void dbl(const CK_BYTE in[8], CK_BYTE out[8]) {
    int msb = in[0] >> 7;
    for (int i = 0; i < 7; i++) out[i] = (CK_BYTE)((in[i] << 1) | (in[i + 1] >> 7));
    out[7] = (CK_BYTE)(in[7] << 1);
    if (msb) out[7] ^= 0x1B;
}

static void ref_cmac(const CK_BYTE *m, size_t n, CK_BYTE t[8]) {
    CK_BYTE z[8] = { 0 }, L[8], K1[8], K2[8], c[8] = { 0 }, x[8], last[8];
    E(z, L); dbl(L, K1); dbl(K1, K2);
    size_t nb = n ? (n + 7) / 8 : 1;
    int complete = n && n % 8 == 0;
    for (size_t b = 0; b + 1 < nb; b++) {
        for (int i = 0; i < 8; i++) x[i] = (CK_BYTE)(c[i] ^ m[b * 8 + (size_t)i]);
        E(x, c);
    }
    size_t off = (nb - 1) * 8, r = n - off;
    memset(last, 0, 8);
    memcpy(last, m + off, r);
    if (!complete) last[r] = 0x80;
    for (int i = 0; i < 8; i++)
        x[i] = (CK_BYTE)(c[i] ^ last[i] ^ (complete ? K1[i] : K2[i]));
    E(x, t);
}

static void ref_cbcmac(const CK_BYTE *m, size_t n, CK_BYTE t[8]) {
    CK_BYTE c[8] = { 0 }, x[8], blk[8];
    size_t nb = n ? (n + 7) / 8 : 1;
    for (size_t b = 0; b < nb; b++) {
        size_t r = n - b * 8 < 8 ? n - b * 8 : 8;
        memset(blk, 0, 8);
        if (r) memcpy(blk, m + b * 8, r);
        for (int i = 0; i < 8; i++) x[i] = (CK_BYTE)(c[i] ^ blk[i]);
        E(x, c);
    }
    memcpy(t, c, 8);
}

/* --- the module -------------------------------------------------------- */
static CK_RV sign(int parts, CK_MECHANISM *m, CK_OBJECT_HANDLE key, const CK_BYTE *d, CK_ULONG n,
                  CK_BYTE *sig, CK_ULONG *sl) {
    CK_RV rv = C_SignInit(s, m, key);
    if (rv != CKR_OK) return rv;
    if (!parts) return C_Sign(s, (CK_BYTE*)d, n, sig, sl);
    CK_ULONG cut = n < 5 ? n : 5;
    rv = C_SignUpdate(s, (CK_BYTE*)d, cut);
    if (rv == CKR_OK) rv = C_SignUpdate(s, (CK_BYTE*)d + cut, n - cut);
    if (rv == CKR_OK) rv = C_SignFinal(s, sig, sl);
    return rv;
}

static CK_RV verify(int parts, CK_MECHANISM *m, const CK_BYTE *d, CK_ULONG n,
                    const CK_BYTE *sig, CK_ULONG sl) {
    CK_RV rv = C_VerifyInit(s, m, k);
    if (rv != CKR_OK) return rv;
    if (!parts) return C_Verify(s, (CK_BYTE*)d, n, (CK_BYTE*)sig, sl);
    CK_ULONG cut = n < 5 ? n : 5;
    rv = C_VerifyUpdate(s, (CK_BYTE*)d, cut);
    if (rv == CKR_OK) rv = C_VerifyUpdate(s, (CK_BYTE*)d + cut, n - cut);
    if (rv == CKR_OK) rv = C_VerifyFinal(s, (CK_BYTE*)sig, sl);
    return rv;
}

static void mac_case(const char *name, CK_MECHANISM *m, const CK_BYTE *d, CK_ULONG n,
                     const CK_BYTE *want, CK_ULONG wl) {
    char what[128];
    for (int parts = 0; parts < 2; parts++) {
        CK_BYTE sig[16]; CK_ULONG sl = sizeof sig;
        CK_RV rv = sign(parts, m, k, d, n, sig, &sl);
        snprintf(what, sizeof what, "%s, %lu bytes: sign%s (0x%lx)", name, n,
                 parts ? " in parts" : "", rv);
        ok(rv == CKR_OK && sl == wl && memcmp(sig, want, wl) == 0, what);
        rv = verify(parts, m, d, n, want, wl);
        snprintf(what, sizeof what, "%s, %lu bytes: verify%s (0x%lx)", name, n,
                 parts ? " in parts" : "", rv);
        ok(rv == CKR_OK, what);
    }
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_EncryptInit); SYM(C_Encrypt);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_Verify); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    if (!C_VerifyFinal || !C_SignFinal) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("3DES MACs\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "des3mac", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    CK_BYTE av[16] = { 0 };
    CK_OBJECT_HANDLE ak = key_of(av, 16, CKK_AES);
    if (!ak) { fprintf(stderr, "AES key import\n"); return 2; }
    const char *mode = getenv("FHSM_MODE");
    const int nist_build = !listed(CKM_DES3_KEY_GEN);
    const int nist = nist_build || (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips")));

    /* (N) */
    if (nist) {
        char what[128];
        CK_MECHANISM m = { CKM_DES3_CMAC, NULL, 0 };
        CK_RV rv = C_SignInit(s, &m, ak);
        int any = listed(CKM_DES3_MAC) || listed(CKM_DES3_MAC_GENERAL)
                  || listed(CKM_DES3_CMAC) || listed(CKM_DES3_CMAC_GENERAL);
        ok(nist_build ? !any : 1, "(N) none of the four listed in the nist build");
        snprintf(what, sizeof what, "(N) C_SignInit: MECHANISM_INVALID (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_INVALID, what);
        C_Finalize(NULL);
        printf("\n%s\n", fails ? "FAILURES" : "all good");
        return fails ? 1 : 0;
    }
    ok(listed(CKM_DES3_MAC) && listed(CKM_DES3_MAC_GENERAL) && listed(CKM_DES3_CMAC)
       && listed(CKM_DES3_CMAC_GENERAL), "all four listed");

    CK_BYTE kv[24], fox[24], got[24];
    unhex("0123456789abcdef23456789abcdef01456789abcdef0123", kv);
    k = key_of(kv, 24, CKK_DES3);
    if (!k) { fprintf(stderr, "3DES key import\n"); return 2; }
    memcpy(fox, "The qufck brown fox jump", 24);
    for (int b = 0; b < 3; b++) E(fox + 8 * b, got + 8 * b);
    {
        CK_BYTE want[24];
        unhex("a826fd8ce53b855fcce21c8112256fe668d5c05dd9b6b900", want);
        ok(ecb_ok && memcmp(got, want, 24) == 0, "the reference: DES3_ECB gives SP 800-67's blocks");
    }

    CK_BYTE msg[37];
    for (int i = 0; i < 37; i++) msg[i] = (CK_BYTE)((i * 11 + 5) & 0xFF);
    static const CK_ULONG lens[] = { 0, 8, 13, 16, 24, 37 };

    /* (C) */
    for (size_t li = 0; li < sizeof lens / sizeof lens[0]; li++) {
        CK_BYTE t[8];
        ref_cmac(msg, lens[li], t);
        CK_MECHANISM full = { CKM_DES3_CMAC, NULL, 0 };
        mac_case("(C) DES3_CMAC", &full, msg, lens[li], t, 8);
        static const CK_ULONG GL[] = { 4, 8 };
        for (size_t g = 0; g < 2; g++) {
            CK_ULONG l = GL[g];
            CK_MECHANISM gm = { CKM_DES3_CMAC_GENERAL, &l, sizeof l };
            char name[48];
            snprintf(name, sizeof name, "(C) DES3_CMAC_GENERAL %lu", l);
            mac_case(name, &gm, msg, lens[li], t, l);
        }
    }

    /* (M) */
    for (size_t li = 0; li < sizeof lens / sizeof lens[0]; li++) {
        CK_BYTE t[8];
        ref_cbcmac(msg, lens[li], t);
        CK_MECHANISM half = { CKM_DES3_MAC, NULL, 0 };
        mac_case("(M) DES3_MAC", &half, msg, lens[li], t, 4);
        static const CK_ULONG GL[] = { 3, 8 };
        for (size_t g = 0; g < 2; g++) {
            CK_ULONG l = GL[g];
            CK_MECHANISM gm = { CKM_DES3_MAC_GENERAL, &l, sizeof l };
            char name[48];
            snprintf(name, sizeof name, "(M) DES3_MAC_GENERAL %lu", l);
            mac_case(name, &gm, msg, lens[li], t, l);
        }
    }
    ok(ecb_ok, "the reference's ECB calls all succeeded");

    /* Changed message, other length. */
    {
        char what[128];
        CK_BYTE t[8], other[37];
        ref_cmac(msg, 37, t);
        memcpy(other, msg, 37); other[36] ^= 1;
        CK_MECHANISM full = { CKM_DES3_CMAC, NULL, 0 }, half = { CKM_DES3_MAC, NULL, 0 };
        CK_RV r1 = verify(0, &full, other, 37, t, 8);
        CK_RV r2 = verify(1, &full, msg, 37, t, 7);
        ref_cbcmac(msg, 37, t);
        CK_RV r3 = verify(0, &half, other, 37, t, 4);
        CK_RV r4 = verify(1, &half, msg, 37, t, 8);
        snprintf(what, sizeof what, "changed message, other length: SIGNATURE_INVALID (0x%lx 0x%lx 0x%lx 0x%lx)",
                 r1, r2, r3, r4);
        ok(r1 == CKR_SIGNATURE_INVALID && r2 == CKR_SIGNATURE_INVALID
           && r3 == CKR_SIGNATURE_INVALID && r4 == CKR_SIGNATURE_INVALID, what);
    }

    /* (P) */
    {
        char what[128];
        CK_ULONG zero = 0, nine = 9;
        CK_MECHANISM m0 = { CKM_DES3_CMAC_GENERAL, &zero, sizeof zero },
                     m9 = { CKM_DES3_MAC_GENERAL, &nine, sizeof nine },
                     mn = { CKM_DES3_CMAC_GENERAL, NULL, 0 };
        CK_RV r0 = C_SignInit(s, &m0, k), r9 = C_SignInit(s, &m9, k), rn = C_SignInit(s, &mn, k);
        snprintf(what, sizeof what, "(P) length 0, 9, none: PARAM_INVALID (0x%lx 0x%lx 0x%lx)", r0, r9, rn);
        ok(r0 == CKR_MECHANISM_PARAM_INVALID && r9 == CKR_MECHANISM_PARAM_INVALID
           && rn == CKR_MECHANISM_PARAM_INVALID, what);
    }

    /* (K) */
    {
        char what[128];
        CK_MECHANISM m1 = { CKM_DES3_CMAC, NULL, 0 }, m2 = { CKM_DES3_MAC, NULL, 0 };
        CK_RV r1 = C_SignInit(s, &m1, ak), r2 = C_VerifyInit(s, &m2, ak);
        snprintf(what, sizeof what, "(K) AES key: KEY_TYPE_INCONSISTENT (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_KEY_TYPE_INCONSISTENT && r2 == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
