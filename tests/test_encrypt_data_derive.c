/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_encrypt_data_derive.c --- key derivation by encryption:
 * CKM_AES_ECB_ENCRYPT_DATA, CKM_AES_CBC_ENCRYPT_DATA,
 * CKM_DES3_ECB_ENCRYPT_DATA and CKM_DES3_CBC_ENCRYPT_DATA (2.8.0).
 *
 *   (V) the derived key's value is the data encrypted under the base key:
 *       FIPS 197 C.1 and C.3 (AES-128 and AES-256 ECB), SP 800-38A F.2.1
 *       (AES-128 CBC, two blocks), the SP 800-67 example (3DES ECB, three
 *       blocks). 3DES CBC gives what C_Encrypt with CKM_DES3_CBC gives, and
 *       with a zero IV its first block is the ECB one. CKA_VALUE_LEN keeps
 *       the leading bytes; CKK_AES without it takes the whole output.
 *   (L) no parameter, data that is not whole blocks, and a CBC parameter
 *       too short are CKR_MECHANISM_PARAM_INVALID.
 *   (T) CKA_VALUE_LEN past the output, or CKK_AES of 20 bytes, is
 *       CKR_ATTRIBUTE_VALUE_INVALID.
 *   (K) a generic secret base key with the AES form, and an AES base key
 *       with the 3DES form, are CKR_KEY_TYPE_INCONSISTENT.
 *   (N) where NIST's rules apply, C_DeriveKey is CKR_MECHANISM_INVALID, and
 *       the nist-approved-only build lists none of the four.
 * The AES values are the published ones, also recomputed with a pure-Python
 * AES; the 3DES ECB value is SP 800-67's.
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
typedef struct { CK_BYTE *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;
typedef struct { CK_BYTE iv[16]; CK_BYTE *pData; CK_ULONG length; } CK_AES_CBC_ENCRYPT_DATA_PARAMS;
typedef struct { CK_BYTE iv[8]; CK_BYTE *pData; CK_ULONG length; } CK_DES_CBC_ENCRYPT_DATA_PARAMS;

#define CKR_OK                         0x000UL
#define CKR_ATTRIBUTE_VALUE_INVALID    0x013UL
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_DES3                       0x15UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_DECRYPT                    0x105UL
#define CKA_DERIVE                     0x10CUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_DES3_CBC                   0x0133UL
#define CKM_DES3_ECB_ENCRYPT_DATA      0x1102UL
#define CKM_DES3_CBC_ENCRYPT_DATA      0x1103UL
#define CKM_AES_ECB_ENCRYPT_DATA       0x1104UL
#define CKM_AES_CBC_ENCRYPT_DATA       0x1105UL

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
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);

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
                         { CKA_DECRYPT, &yes, 1 }, { CKA_DERIVE, &yes, 1 },
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

/* Derive with mechanism m from base, as key type kt with CKA_VALUE_LEN vl
 * (none if 0); the value, readable, into out. */
static CK_RV derive(CK_MECHANISM *m, CK_OBJECT_HANDLE base, CK_ULONG kt, CK_ULONG vl,
                    CK_BYTE *out, CK_ULONG *ol) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 },
                         { CKA_EXTRACTABLE, &yes, 1 }, { CKA_VALUE_LEN, &vl, sizeof vl } };
    CK_OBJECT_HANDLE h = 0;
    CK_RV rv = C_DeriveKey(s, m, base, t, vl ? 6 : 5, &h);
    if (rv != CKR_OK || !out) return rv;
    CK_ATTRIBUTE a = { CKA_VALUE, out, *ol };
    rv = C_GetAttributeValue(s, h, &a, 1);
    *ol = a.ulValueLen;
    return rv;
}

static void expect(const char *name, CK_MECHANISM *m, CK_OBJECT_HANDLE base, CK_ULONG kt,
                   CK_ULONG vl, const char *hex) {
    char what[128];
    CK_BYTE want[64], got[64];
    size_t wl = unhex(hex, want);
    CK_ULONG gl = sizeof got;
    CK_RV rv = derive(m, base, kt, vl, got, &gl);
    snprintf(what, sizeof what, "%s (0x%lx)", name, rv);
    ok(rv == CKR_OK && gl == wl && memcmp(got, want, wl) == 0, what);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_DeriveKey); SYM(C_GetAttributeValue);
    SYM(C_EncryptInit); SYM(C_Encrypt);
    if (!C_DeriveKey || !C_GetAttributeValue || !C_Encrypt) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("Key derivation by encryption\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "encdata", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const int nist_build = !listed(CKM_RSA_PKCS);
    int nist = nist_build;
    const char *mode = getenv("FHSM_MODE");
    if (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips"))) nist = 1;

    CK_BYTE k128v[16], k256v[32], kcbcv[16];
    for (int i = 0; i < 16; i++) k128v[i] = (CK_BYTE)i;
    for (int i = 0; i < 32; i++) k256v[i] = (CK_BYTE)i;
    unhex("2b7e151628aed2a6abf7158809cf4f3c", kcbcv);
    CK_OBJECT_HANDLE k128 = key_of(k128v, 16, CKK_AES), k256 = key_of(k256v, 32, CKK_AES),
                     kcbc = key_of(kcbcv, 16, CKK_AES),
                     gen  = key_of(k128v, 16, CKK_GENERIC_SECRET);
    if (!k128 || !k256 || !kcbc || !gen) { fprintf(stderr, "key import\n"); return 2; }

    CK_BYTE d32[32];
    unhex("00112233445566778899aabbccddeeff6bc1bee22e409f96e93d7e117393172a", d32);
    CK_KEY_DERIVATION_STRING_DATA sd16 = { d32, 16 }, sd32 = { d32, 32 };
    CK_MECHANISM ecb16 = { CKM_AES_ECB_ENCRYPT_DATA, &sd16, sizeof sd16 },
                 ecb32 = { CKM_AES_ECB_ENCRYPT_DATA, &sd32, sizeof sd32 };

    /* (N) */
    if (nist) {
        char what[128];
        int any = listed(CKM_AES_ECB_ENCRYPT_DATA) || listed(CKM_AES_CBC_ENCRYPT_DATA)
                  || listed(CKM_DES3_ECB_ENCRYPT_DATA) || listed(CKM_DES3_CBC_ENCRYPT_DATA);
        /* The nist-approved-only build does not list them; strict mode in
         * the all-mechanisms build lists them and refuses them. */
        ok(nist_build ? !any : 1, "(N) none of the four listed in the nist build");
        CK_RV rv = derive(&ecb16, k128, CKK_GENERIC_SECRET, 16, NULL, NULL);
        snprintf(what, sizeof what, "(N) C_DeriveKey: MECHANISM_INVALID (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_INVALID, what);
        C_Finalize(NULL);
        printf("\n%s\n", fails ? "FAILURES" : "all good");
        return fails ? 1 : 0;
    }

    ok(listed(CKM_AES_ECB_ENCRYPT_DATA) && listed(CKM_AES_CBC_ENCRYPT_DATA)
       && listed(CKM_DES3_ECB_ENCRYPT_DATA) && listed(CKM_DES3_CBC_ENCRYPT_DATA),
       "all four listed");

    /* (V) AES */
    expect("(V) AES-128 ECB, FIPS 197 C.1, 16 bytes", &ecb16, k128, CKK_GENERIC_SECRET, 16,
           "69c4e0d86a7b0430d8cdb78070b4c55a");
    expect("(V) AES-128 ECB, 32 bytes, CKK_AES without CKA_VALUE_LEN", &ecb32, k128, CKK_AES, 0,
           "69c4e0d86a7b0430d8cdb78070b4c55a47c58d5e21caaf840d015b7d9b910981");
    expect("(V) AES-256 ECB, FIPS 197 C.3 then a second block", &ecb32, k256,
           CKK_GENERIC_SECRET, 32,
           "8ea2b7ca516745bfeafc49904b496089e0a8f50ec76a04d5a96a175aa870ef63");
    CK_BYTE f21[32];
    unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", f21);
    CK_AES_CBC_ENCRYPT_DATA_PARAMS ap;
    for (int i = 0; i < 16; i++) ap.iv[i] = (CK_BYTE)i;
    ap.pData = f21; ap.length = 32;
    CK_MECHANISM acbc = { CKM_AES_CBC_ENCRYPT_DATA, &ap, sizeof ap };
    expect("(V) AES-128 CBC, SP 800-38A F.2.1, 32 bytes", &acbc, kcbc, CKK_GENERIC_SECRET, 32,
           "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2");
    expect("(V) the same, CKA_VALUE_LEN 16: the leading bytes", &acbc, kcbc,
           CKK_GENERIC_SECRET, 16, "7649abac8119b246cee98e9b12e9197d");

    /* (V) 3DES */
    CK_BYTE k3v[24], fox[24];
    unhex("0123456789abcdef23456789abcdef01456789abcdef0123", k3v);
    memcpy(fox, "The qufck brown fox jump", 24);
    CK_OBJECT_HANDLE k3 = key_of(k3v, 24, CKK_DES3);
    ok(k3 != 0, "3DES base key imported");
    CK_KEY_DERIVATION_STRING_DATA sdf = { fox, 24 };
    CK_MECHANISM decb = { CKM_DES3_ECB_ENCRYPT_DATA, &sdf, sizeof sdf };
    expect("(V) 3DES ECB, SP 800-67 example, 24 bytes", &decb, k3, CKK_GENERIC_SECRET, 24,
           "a826fd8ce53b855fcce21c8112256fe668d5c05dd9b6b900");
    {
        static const CK_BYTE ivs[2][8] = { { 0 }, { 1, 2, 3, 4, 5, 6, 7, 8 } };
        for (int v = 0; v < 2; v++) {
            char what[128];
            CK_DES_CBC_ENCRYPT_DATA_PARAMS dp;
            memcpy(dp.iv, ivs[v], 8); dp.pData = fox; dp.length = 24;
            CK_MECHANISM dcbc = { CKM_DES3_CBC_ENCRYPT_DATA, &dp, sizeof dp };
            CK_BYTE got[64], enc[64];
            CK_ULONG gl = sizeof got, el = sizeof enc;
            CK_RV rv = derive(&dcbc, k3, CKK_GENERIC_SECRET, 24, got, &gl);
            CK_MECHANISM cbc = { CKM_DES3_CBC, (void*)ivs[v], 8 };
            CK_RV re = C_EncryptInit(s, &cbc, k3);
            if (re == CKR_OK) re = C_Encrypt(s, fox, 24, enc, &el);
            snprintf(what, sizeof what, "(V) 3DES CBC, IV %s: as C_Encrypt with DES3_CBC (0x%lx 0x%lx)",
                     v ? "01..08" : "zero", rv, re);
            int same = rv == CKR_OK && re == CKR_OK && gl == 24 && el == 24
                       && memcmp(got, enc, 24) == 0;
            if (v == 0) {
                CK_BYTE first[8];
                unhex("a826fd8ce53b855f", first);
                same = same && memcmp(got, first, 8) == 0;
            }
            ok(same, what);
        }
    }

    /* (L) */
    {
        char what[128];
        CK_KEY_DERIVATION_STRING_DATA sd15 = { d32, 15 }, sd12 = { fox, 12 };
        CK_MECHANISM none = { CKM_AES_ECB_ENCRYPT_DATA, NULL, 0 },
                     e15  = { CKM_AES_ECB_ENCRYPT_DATA, &sd15, sizeof sd15 },
                     d12  = { CKM_DES3_ECB_ENCRYPT_DATA, &sd12, sizeof sd12 },
                     shrt = { CKM_AES_CBC_ENCRYPT_DATA, &ap, 16 };
        CK_RV r1 = derive(&none, k128, CKK_GENERIC_SECRET, 16, NULL, NULL);
        CK_RV r2 = derive(&e15,  k128, CKK_GENERIC_SECRET, 15, NULL, NULL);
        CK_RV r3 = derive(&d12,  k3,   CKK_GENERIC_SECRET, 8,  NULL, NULL);
        CK_RV r4 = derive(&shrt, kcbc, CKK_GENERIC_SECRET, 16, NULL, NULL);
        snprintf(what, sizeof what, "(L) no param, 15 and 12 bytes, short CBC param (0x%lx 0x%lx 0x%lx 0x%lx)",
                 r1, r2, r3, r4);
        ok(r1 == CKR_MECHANISM_PARAM_INVALID && r2 == CKR_MECHANISM_PARAM_INVALID
           && r3 == CKR_MECHANISM_PARAM_INVALID && r4 == CKR_MECHANISM_PARAM_INVALID, what);
    }

    /* (T) */
    {
        char what[128];
        CK_RV r1 = derive(&ecb32, k128, CKK_GENERIC_SECRET, 48, NULL, NULL);
        CK_RV r2 = derive(&ecb32, k128, CKK_AES, 20, NULL, NULL);
        snprintf(what, sizeof what, "(T) 48 of 32 bytes, CKK_AES of 20: ATTRIBUTE_VALUE_INVALID (0x%lx 0x%lx)",
                 r1, r2);
        ok(r1 == CKR_ATTRIBUTE_VALUE_INVALID && r2 == CKR_ATTRIBUTE_VALUE_INVALID, what);
    }

    /* (K) */
    {
        char what[128];
        CK_RV r1 = derive(&ecb16, gen, CKK_GENERIC_SECRET, 16, NULL, NULL);
        CK_KEY_DERIVATION_STRING_DATA sd8 = { d32, 16 };
        CK_MECHANISM d16 = { CKM_DES3_ECB_ENCRYPT_DATA, &sd8, sizeof sd8 };
        CK_RV r2 = derive(&d16, k128, CKK_GENERIC_SECRET, 16, NULL, NULL);
        snprintf(what, sizeof what, "(K) generic base for AES, AES base for 3DES (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_KEY_TYPE_INCONSISTENT && r2 == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
