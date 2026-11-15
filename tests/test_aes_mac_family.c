/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_aes_mac_family.c --- CKM_AES_CMAC_GENERAL, CKM_AES_MAC and
 * CKM_AES_MAC_GENERAL (2.8.0).
 *
 *   (C) CKM_AES_CMAC_GENERAL over the RFC 4493 messages (0, 16, 40 and 64
 *       bytes): the MAC is the leading bytes of the RFC's, at 16, 8 and (where
 *       NIST's rules do not apply) 4 bytes; single-part and in parts, sign
 *       and verify. No parameter, 0 or 17 bytes, and 4 bytes under NIST's
 *       rules are CKR_MECHANISM_PARAM_INVALID. A MAC of another length is
 *       CKR_SIGNATURE_INVALID.
 *   (M) CKM_AES_MAC (8 bytes) and CKM_AES_MAC_GENERAL (12 and 16 bytes),
 *       CBC-MAC with a zero IV over the data padded with zero bytes, over
 *       0, 16, 20, 37 and 64 bytes; single-part and in parts. A changed
 *       message is CKR_SIGNATURE_INVALID. Where NIST's rules apply both are
 *       CKR_MECHANISM_INVALID.
 *   (K) a generic secret key is CKR_KEY_TYPE_INCONSISTENT.
 * The expected values were computed with a pure-Python AES checked against
 * FIPS 197 C.1, not with OpenSSL; its CMAC gives RFC 4493's four tags.
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
#define CKR_MECHANISM_INVALID        0x070UL
#define CKR_MECHANISM_PARAM_INVALID  0x071UL
#define CKR_SIGNATURE_INVALID        0x0C0UL
#define CKF_RW                       6UL
#define CKO_SECRET_KEY               4UL
#define CKK_GENERIC_SECRET           0x10UL
#define CKK_AES                      0x1FUL
#define CKA_CLASS                    0x000UL
#define CKA_TOKEN                    0x001UL
#define CKA_VALUE                    0x011UL
#define CKA_KEY_TYPE                 0x100UL
#define CKA_SIGN                     0x108UL
#define CKA_VERIFY                   0x10AUL
#define CKM_RSA_PKCS                 0x001UL
#define CKM_AES_MAC                  0x1083UL
#define CKM_AES_MAC_GENERAL          0x1084UL
#define CKM_AES_CMAC_GENERAL         0x108BUL

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
static CK_BYTE M[64];

static size_t unhex(const char *h, CK_BYTE *out) {
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (CK_BYTE)v;
    }
    return n;
}

static CK_OBJECT_HANDLE key_of(CK_ULONG kt) {
    CK_BYTE v[16];
    unhex("2b7e151628aed2a6abf7158809cf4f3c", v);
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 },
                         { CKA_VERIFY, &yes, 1 }, { CKA_VALUE, v, sizeof v } };
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

/* Sign, verify, sign in parts, verify in parts; the expected MAC is the
 * first `len` bytes of `fullhex`. */
static void mac_case(const char *name, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                     CK_ULONG n, CK_ULONG len, const char *fullhex) {
    char what[128];
    CK_BYTE want[16], sig[32];
    unhex(fullhex, want);
    CK_ULONG sl = sizeof sig;
    CK_RV rv = C_SignInit(s, m, k);
    if (rv == CKR_OK) rv = C_Sign(s, M, n, sig, &sl);
    snprintf(what, sizeof what, "%s, %lu-byte message: %lu-byte MAC (0x%lx)", name, n, len, rv);
    ok(rv == CKR_OK && sl == len && memcmp(sig, want, len) == 0, what);
    rv = C_VerifyInit(s, m, k);
    if (rv == CKR_OK) rv = C_Verify(s, M, n, want, len);
    snprintf(what, sizeof what, "%s, %lu bytes: verifies (0x%lx)", name, n, rv);
    ok(rv == CKR_OK, what);
    CK_ULONG cut = n < 7 ? n : 7;
    sl = sizeof sig;
    rv = C_SignInit(s, m, k);
    if (rv == CKR_OK && cut) rv = C_SignUpdate(s, M, cut);
    if (rv == CKR_OK && n > cut) rv = C_SignUpdate(s, M + cut, n - cut);
    if (rv == CKR_OK) rv = C_SignFinal(s, sig, &sl);
    snprintf(what, sizeof what, "%s, %lu bytes: in parts, the same MAC (0x%lx)", name, n, rv);
    ok(rv == CKR_OK && sl == len && memcmp(sig, want, len) == 0, what);
    rv = C_VerifyInit(s, m, k);
    if (rv == CKR_OK && cut) rv = C_VerifyUpdate(s, M, cut);
    if (rv == CKR_OK && n > cut) rv = C_VerifyUpdate(s, M + cut, n - cut);
    if (rv == CKR_OK) rv = C_VerifyFinal(s, want, len);
    snprintf(what, sizeof what, "%s, %lu bytes: verifies in parts (0x%lx)", name, n, rv);
    ok(rv == CKR_OK, what);
    if (n) {
        rv = C_VerifyInit(s, m, k);
        if (rv == CKR_OK) rv = C_Verify(s, M, n - 1, want, len);
        snprintf(what, sizeof what, "%s, %lu bytes: one byte less: SIGNATURE_INVALID (0x%lx)",
                 name, n, rv);
        ok(rv == CKR_SIGNATURE_INVALID, what);
    }
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate);
    SYM(C_SignFinal); SYM(C_VerifyInit); SYM(C_Verify); SYM(C_VerifyUpdate);
    SYM(C_VerifyFinal);
    if (!C_VerifyFinal || !C_SignFinal) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("AES CMAC_GENERAL, MAC and MAC_GENERAL\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "aesmac", 6);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    int nist = !listed(CKM_RSA_PKCS);
    const char *mode = getenv("FHSM_MODE");
    if (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips"))) nist = 1;
    unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", M);
    CK_OBJECT_HANDLE k = key_of(CKK_AES), gk = key_of(CKK_GENERIC_SECRET);
    if (!k || !gk) { fprintf(stderr, "key import\n"); return 2; }
    char what[128];
    CK_RV rv;

    /* (C) */
    ok(listed(CKM_AES_CMAC_GENERAL), "(C) CKM_AES_CMAC_GENERAL listed");
    static const struct { CK_ULONG n; const char *tag; } C[] = {
        { 0,  "bb1d6929e95937287fa37d129b756746" }, { 16, "070a16b46b4d4144f79bdd9dd04a287c" },
        { 40, "dfa66747de9ae63030ca32611497c827" }, { 64, "51f0bebf7e3b9d92fc49741779363cfe" },
    };
    static const CK_ULONG CL[] = { 16, 8, 4 };
    for (size_t li = 0; li < 3; li++) {
        CK_ULONG len = CL[li];
        CK_MECHANISM m = { CKM_AES_CMAC_GENERAL, &len, sizeof len };
        if (len < 8 && nist) {
            rv = C_SignInit(s, &m, k);
            snprintf(what, sizeof what, "(C) 4 bytes under NIST's rules: PARAM_INVALID (0x%lx)", rv);
            ok(rv == CKR_MECHANISM_PARAM_INVALID, what);
            continue;
        }
        for (size_t i = 0; i < 4; i++) {
            char name[48];
            snprintf(name, sizeof name, "(C) CMAC_GENERAL/%lu", len);
            mac_case(name, &m, k, C[i].n, len, C[i].tag);
        }
        CK_BYTE sig[16];
        unhex(C[2].tag, sig);
        rv = C_VerifyInit(s, &m, k);
        if (rv == CKR_OK) rv = C_Verify(s, M, 40, sig, len == 16 ? 15UL : 16UL);
        snprintf(what, sizeof what, "(C) CMAC_GENERAL/%lu: a MAC of another length: INVALID (0x%lx)",
                 len, rv);
        ok(rv == CKR_SIGNATURE_INVALID, what);
    }
    {
        CK_ULONG zero = 0, big = 17;
        CK_MECHANISM none = { CKM_AES_CMAC_GENERAL, NULL, 0 },
                     mz = { CKM_AES_CMAC_GENERAL, &zero, sizeof zero },
                     mb = { CKM_AES_CMAC_GENERAL, &big, sizeof big };
        CK_RV r0 = C_SignInit(s, &none, k), r1 = C_SignInit(s, &mz, k), r2 = C_VerifyInit(s, &mb, k);
        snprintf(what, sizeof what, "(C) no parameter, 0, 17: PARAM_INVALID (0x%lx 0x%lx 0x%lx)",
                 r0, r1, r2);
        ok(r0 == CKR_MECHANISM_PARAM_INVALID && r1 == CKR_MECHANISM_PARAM_INVALID
           && r2 == CKR_MECHANISM_PARAM_INVALID, what);
        CK_ULONG l16 = 16;
        CK_MECHANISM m = { CKM_AES_CMAC_GENERAL, &l16, sizeof l16 };
        rv = C_SignInit(s, &m, gk);
        snprintf(what, sizeof what, "(K) CMAC_GENERAL, generic secret: KEY_TYPE_INCONSISTENT (0x%lx)", rv);
        ok(rv == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    /* (M) */
    static const struct { CK_ULONG n; const char *mac; } B[] = {
        { 0,  "7df76b0c1ab899b33e42f047b91b546f" }, { 16, "3ad77bb40d7a3660a89ecaf32466ef97" },
        { 20, "6e88a8636087aac6a0507cfa4d958581" }, { 37, "a80a831d688b109428c7c727666c95ad" },
        { 64, "a7356e1207bb406639e5e5ceb9a9ed93" },
    };
    if (nist) {
        CK_ULONG l = 16;
        CK_MECHANISM m1 = { CKM_AES_MAC, NULL, 0 }, m2 = { CKM_AES_MAC_GENERAL, &l, sizeof l };
        CK_RV r1 = C_SignInit(s, &m1, k), r2 = C_VerifyInit(s, &m2, k);
        snprintf(what, sizeof what, "(M) AES_MAC, AES_MAC_GENERAL under NIST's rules: INVALID (0x%lx 0x%lx)",
                 r1, r2);
        ok(r1 == CKR_MECHANISM_INVALID && r2 == CKR_MECHANISM_INVALID, what);
    } else {
        ok(listed(CKM_AES_MAC) && listed(CKM_AES_MAC_GENERAL), "(M) AES_MAC, AES_MAC_GENERAL listed");
        CK_MECHANISM m = { CKM_AES_MAC, NULL, 0 };
        for (size_t i = 0; i < 5; i++) mac_case("(M) AES_MAC", &m, k, B[i].n, 8, B[i].mac);
        static const CK_ULONG GL[] = { 12, 16 };
        for (size_t li = 0; li < 2; li++) {
            CK_ULONG len = GL[li];
            CK_MECHANISM g = { CKM_AES_MAC_GENERAL, &len, sizeof len };
            char name[48];
            snprintf(name, sizeof name, "(M) AES_MAC_GENERAL/%lu", len);
            for (size_t i = 0; i < 5; i++) mac_case(name, &g, k, B[i].n, len, B[i].mac);
        }
        CK_ULONG big = 17;
        CK_MECHANISM gb = { CKM_AES_MAC_GENERAL, &big, sizeof big }, gn = { CKM_AES_MAC_GENERAL, NULL, 0 };
        CK_RV r1 = C_SignInit(s, &gb, k), r2 = C_SignInit(s, &gn, k);
        snprintf(what, sizeof what, "(M) AES_MAC_GENERAL 17, none: PARAM_INVALID (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_MECHANISM_PARAM_INVALID && r2 == CKR_MECHANISM_PARAM_INVALID, what);
        rv = C_SignInit(s, &m, gk);
        snprintf(what, sizeof what, "(K) AES_MAC, generic secret: KEY_TYPE_INCONSISTENT (0x%lx)", rv);
        ok(rv == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
