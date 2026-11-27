/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_derive_aux_allowed.c --- CKA_ALLOWED_MECHANISMS on the keys a
 * C_DeriveKey parameter names (#47).
 *
 * C_DeriveKey checked the list of hBaseKey only. A key named in the
 * parameter is used with the mechanism as much as the base key is (§4.9),
 * and its list was not read: an AES key listing CKM_AES_GCM alone could be
 * concatenated onto a known base, cut a byte at a time, and recovered.
 *
 * For each mechanism, the key in the parameter is a generic secret with
 * CKA_DERIVE=TRUE, made three times: with no list, with a list naming the
 * mechanism, and with a list leaving it out. The first two are taken, the
 * third is CKR_MECHANISM_INVALID, as the same key is as a base key.
 *   (C) CKM_CONCATENATE_BASE_AND_KEY, the second key; and the reproducer: an
 *       AES-256 key, sensitive, unextractable, listing CKM_AES_GCM.
 *   (H) CKM_HKDF_DERIVE and CKM_HKDF_DATA, hSaltKey.
 *   (I) CKM_IKE_PRF_DERIVE hNewKey, CKM_IKE1_PRF_DERIVE hKeygxy and hPrevKey,
 *       CKM_IKE2_PRF_PLUS_DERIVE hSeedKey, CKM_IKE1_EXTENDED_DERIVE hKeygxy;
 *       each where the build lists it.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS, CK_MECHANISM_TYPE;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_BYTE bExtract, bExpand; CK_ULONG prfHashMechanism, ulSaltType;
                 void *pSalt; CK_ULONG ulSaltLen; CK_OBJECT_HANDLE hSaltKey;
                 void *pInfo; CK_ULONG ulInfoLen; } CK_HKDF_PARAMS;
typedef struct { CK_ULONG prfMechanism; CK_BYTE bDataAsKey, bRekey; CK_BYTE *pNi; CK_ULONG ulNiLen;
                 CK_BYTE *pNr; CK_ULONG ulNrLen; CK_OBJECT_HANDLE hNewKey; } CK_IKE_PRF_DERIVE_PARAMS;
typedef struct { CK_ULONG prfMechanism; CK_BYTE bHasPrevKey; CK_OBJECT_HANDLE hKeygxy, hPrevKey;
                 CK_BYTE *pCKYi; CK_ULONG ulCKYiLen; CK_BYTE *pCKYr; CK_ULONG ulCKYrLen;
                 CK_BYTE keyNumber; } CK_IKE1_PRF_DERIVE_PARAMS;
typedef struct { CK_ULONG prfMechanism; CK_BYTE bHasKeygxy; CK_OBJECT_HANDLE hKeygxy;
                 CK_BYTE *pExtraData; CK_ULONG ulExtraDataLen; } CK_IKE1_EXTENDED_DERIVE_PARAMS;
typedef struct { CK_ULONG prfMechanism; CK_BYTE bHasSeedKey; CK_OBJECT_HANDLE hSeedKey;
                 CK_BYTE *pSeedData; CK_ULONG ulSeedDataLen; } CK_IKE2_PRF_PLUS_DERIVE_PARAMS;

#define CKR_OK                         0x000UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_AES                        0x1FUL
#define CKK_SHA256_HMAC                0x2BUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_DERIVE                     0x10CUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKA_ALLOWED_MECHANISMS         0x40000600UL
#define CKM_SHA256                     0x0250UL
#define CKM_SHA256_HMAC                0x0251UL
#define CKM_CONCATENATE_BASE_AND_KEY   0x0360UL
#define CKM_CONCATENATE_BASE_AND_DATA  0x0362UL
#define CKM_AES_GCM                    0x1087UL
#define CKM_HKDF_DERIVE                0x402AUL
#define CKM_HKDF_DATA                  0x402BUL
#define CKM_IKE2_PRF_PLUS_DERIVE       0x402EUL
#define CKM_IKE_PRF_DERIVE             0x402FUL
#define CKM_IKE1_PRF_DERIVE            0x4030UL
#define CKM_IKE1_EXTENDED_DERIVE       0x4031UL
#define CKF_HKDF_SALT_KEY              0x04UL

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

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;

static int listed(CK_ULONG mech) {
    CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
    CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
    C_GetMechanismList(0, ml, &n);
    int found = 0;
    for (CK_ULONG i = 0; i < n; i++) if (ml[i] == mech) found = 1;
    free(ml);
    return found;
}

/* A secret key of type kt, CKA_DERIVE=TRUE. `allow` NULL: no list; else the
 * list of n mechanisms. `prot`: sensitive and unextractable. */
static CK_OBJECT_HANDLE key(CK_ULONG kt, CK_BYTE fill, CK_ULONG vl,
                            const CK_MECHANISM_TYPE *allow, CK_ULONG n, int prot) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_BYTE v[32];
    for (CK_ULONG i = 0; i < vl; i++) v[i] = (CK_BYTE)(fill + i);
    CK_ATTRIBUTE t[8] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                          { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, prot ? &yes : &no, 1 },
                          { CKA_EXTRACTABLE, prot ? &no : &yes, 1 }, { CKA_DERIVE, &yes, 1 },
                          { CKA_VALUE, v, vl } };
    CK_ULONG c = 7;
    if (allow) { t[c].type = CKA_ALLOWED_MECHANISMS; t[c].pValue = (void*)allow;
                 t[c].ulValueLen = n * sizeof(CK_MECHANISM_TYPE); c++; }
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, c, &h) == CKR_OK ? h : 0;
}

/* The three versions of the key a parameter names, for mechanism `mech`:
 * no list, a list naming it, a list leaving it out. */
static void three(CK_ULONG mech, CK_OBJECT_HANDLE out[3]) {
    CK_MECHANISM_TYPE with[1] = { mech }, without[1] = { CKM_CONCATENATE_BASE_AND_DATA };
    out[0] = key(CKK_GENERIC_SECRET, 0x40, 32, NULL, 0, 0);
    out[1] = key(CKK_GENERIC_SECRET, 0x40, 32, with, 1, 0);
    out[2] = key(CKK_GENERIC_SECRET, 0x40, 32, without, 1, 0);
}

static void report(const char *name, CK_RV r[3]) {
    char what[160];
    snprintf(what, sizeof what, "%s, no list: taken (0x%lx)", name, r[0]);
    ok(r[0] == CKR_OK, what);
    snprintf(what, sizeof what, "%s, listed: taken (0x%lx)", name, r[1]);
    ok(r[1] == CKR_OK, what);
    snprintf(what, sizeof what, "%s, left out: CKR_MECHANISM_INVALID (0x%lx)", name, r[2]);
    ok(r[2] == CKR_MECHANISM_INVALID, what);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_DeriveKey);
    if (!C_DeriveKey || !C_CreateObject) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("CKA_ALLOWED_MECHANISMS on the keys a derivation's parameter names (#47)\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "auxallow", 8);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    CK_ULONG cls = CKO_SECRET_KEY, gen = CKK_GENERIC_SECRET, l32 = 32;
    /* A derived generic secret of 32 bytes; [0..4] without a length, for the
     * IKE derivations whose length is the prf's. */
    CK_ATTRIBUTE dt[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &gen, sizeof gen },
                          { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 },
                          { CKA_EXTRACTABLE, &yes, 1 }, { CKA_VALUE_LEN, &l32, sizeof l32 } };
    /* CKM_HKDF_DATA's data object, as tests/test_derive_hkdf.c (6) asks it. */
    CK_ATTRIBUTE dd[] = { { CKA_VALUE_LEN, &l32, sizeof l32 }, { CKA_EXTRACTABLE, &yes, 1 },
                          { CKA_SENSITIVE, &no, 1 } };
    CK_OBJECT_HANDLE h = 0, k[3];
    CK_RV r[3];
    char what[160];

    /* --- (C) CKM_CONCATENATE_BASE_AND_KEY ------------------------------- */
    {
        CK_MECHANISM_TYPE bl[1] = { CKM_CONCATENATE_BASE_AND_KEY };
        CK_OBJECT_HANDLE base = key(CKK_GENERIC_SECRET, 0x10, 16, bl, 1, 0);
        three(CKM_CONCATENATE_BASE_AND_KEY, k);
        if (!base || !k[0] || !k[1] || !k[2]) { fprintf(stderr, "keys\n"); return 2; }
        CK_ATTRIBUTE ct[] = { dt[0], dt[1], dt[2], dt[3], dt[4] };
        for (int i = 0; i < 3; i++) {
            CK_MECHANISM m = { CKM_CONCATENATE_BASE_AND_KEY, &k[i], sizeof k[i] };
            r[i] = C_DeriveKey(s, &m, base, ct, 5, &h);
        }
        report("(C) the second key", r);

        /* The report's victim: AES-256, sensitive, unextractable, listing
         * CKM_AES_GCM. As the base key it was refused; as the second key it
         * was taken, and the result could be cut and read. */
        CK_MECHANISM_TYPE gcm[1] = { CKM_AES_GCM };
        CK_OBJECT_HANDLE victim = key(CKK_AES, 0xA0, 32, gcm, 1, 1);
        CK_OBJECT_HANDLE known = key(CKK_GENERIC_SECRET, 0x10, 16, NULL, 0, 0);
        if (!victim || !known) { fprintf(stderr, "victim\n"); return 2; }
        CK_MECHANISM as_base = { CKM_CONCATENATE_BASE_AND_KEY, &known, sizeof known };
        CK_RV rb = C_DeriveKey(s, &as_base, victim, ct, 5, &h);
        CK_MECHANISM as_second = { CKM_CONCATENATE_BASE_AND_KEY, &victim, sizeof victim };
        CK_RV rs = C_DeriveKey(s, &as_second, known, ct, 5, &h);
        snprintf(what, sizeof what, "(C) an AES-GCM-only key, as the base: refused (0x%lx)", rb);
        ok(rb == CKR_MECHANISM_INVALID, what);
        snprintf(what, sizeof what, "(C) and as the second key: refused too (0x%lx)", rs);
        ok(rs == CKR_MECHANISM_INVALID, what);
    }

    /* --- (H) HKDF, hSaltKey ---------------------------------------------- */
    {
        const CK_ULONG mechs[2] = { CKM_HKDF_DERIVE, CKM_HKDF_DATA };
        const char *names[2] = { "(H) CKM_HKDF_DERIVE hSaltKey", "(H) CKM_HKDF_DATA hSaltKey" };
        CK_BYTE info[4] = { 1, 2, 3, 4 };
        for (int j = 0; j < 2; j++) {
            if (!listed(mechs[j])) { printf("  %s: not in this build\n", names[j]); continue; }
            CK_MECHANISM_TYPE bl[1] = { mechs[j] };
            CK_OBJECT_HANDLE base = key(CKK_GENERIC_SECRET, 0x20, 32, bl, 1, 0);
            three(mechs[j], k);
            for (int i = 0; i < 3; i++) {
                CK_HKDF_PARAMS p = { 1, 1, CKM_SHA256, CKF_HKDF_SALT_KEY, NULL, 0, k[i],
                                     info, sizeof info };
                CK_MECHANISM m = { mechs[j], &p, sizeof p };
                r[i] = j == 0 ? C_DeriveKey(s, &m, base, dt, 6, &h)
                              : C_DeriveKey(s, &m, base, dd, 3, &h);
            }
            report(names[j], r);
        }
    }

    /* --- (I) the IKE derivations ----------------------------------------- */
    CK_BYTE ni[16], nr[16], ckyi[8], ckyr[8], extra[8];
    for (int i = 0; i < 16; i++) { ni[i] = (CK_BYTE)(i * 3); nr[i] = (CK_BYTE)(0xF0 - i); }
    for (int i = 0; i < 8; i++) { ckyi[i] = (CK_BYTE)(0x11 * i); ckyr[i] = (CK_BYTE)(0x80 | i);
                                  extra[i] = (CK_BYTE)i; }
    if (listed(CKM_IKE_PRF_DERIVE)) {
        CK_MECHANISM_TYPE bl[1] = { CKM_IKE_PRF_DERIVE };
        CK_OBJECT_HANDLE base = key(CKK_SHA256_HMAC, 0x30, 32, bl, 1, 0);
        three(CKM_IKE_PRF_DERIVE, k);
        for (int i = 0; i < 3; i++) {
            CK_IKE_PRF_DERIVE_PARAMS p = { CKM_SHA256_HMAC, 0, 1, ni, 16, nr, 16, k[i] };
            CK_MECHANISM m = { CKM_IKE_PRF_DERIVE, &p, sizeof p };
            r[i] = C_DeriveKey(s, &m, base, dt, 5, &h);
        }
        report("(I) CKM_IKE_PRF_DERIVE hNewKey", r);
    } else printf("  (I) CKM_IKE_PRF_DERIVE: not in this build\n");

    if (listed(CKM_IKE1_PRF_DERIVE)) {
        CK_MECHANISM_TYPE bl[1] = { CKM_IKE1_PRF_DERIVE };
        CK_OBJECT_HANDLE base = key(CKK_SHA256_HMAC, 0x30, 32, bl, 1, 0);
        CK_OBJECT_HANDLE gxy = key(CKK_GENERIC_SECRET, 0x50, 32, NULL, 0, 0);
        three(CKM_IKE1_PRF_DERIVE, k);
        for (int i = 0; i < 3; i++) {
            CK_IKE1_PRF_DERIVE_PARAMS p = { CKM_SHA256_HMAC, 0, k[i], 0, ckyi, 8, ckyr, 8, 0 };
            CK_MECHANISM m = { CKM_IKE1_PRF_DERIVE, &p, sizeof p };
            r[i] = C_DeriveKey(s, &m, base, dt, 5, &h);
        }
        report("(I) CKM_IKE1_PRF_DERIVE hKeygxy", r);
        for (int i = 0; i < 3; i++) {
            CK_IKE1_PRF_DERIVE_PARAMS p = { CKM_SHA256_HMAC, 1, gxy, k[i], ckyi, 8, ckyr, 8, 1 };
            CK_MECHANISM m = { CKM_IKE1_PRF_DERIVE, &p, sizeof p };
            r[i] = C_DeriveKey(s, &m, base, dt, 5, &h);
        }
        report("(I) CKM_IKE1_PRF_DERIVE hPrevKey", r);
    } else printf("  (I) CKM_IKE1_PRF_DERIVE: not in this build\n");

    if (listed(CKM_IKE2_PRF_PLUS_DERIVE)) {
        CK_MECHANISM_TYPE bl[1] = { CKM_IKE2_PRF_PLUS_DERIVE };
        CK_OBJECT_HANDLE base = key(CKK_SHA256_HMAC, 0x30, 32, bl, 1, 0);
        three(CKM_IKE2_PRF_PLUS_DERIVE, k);
        for (int i = 0; i < 3; i++) {
            CK_IKE2_PRF_PLUS_DERIVE_PARAMS p = { CKM_SHA256_HMAC, 1, k[i], extra, sizeof extra };
            CK_MECHANISM m = { CKM_IKE2_PRF_PLUS_DERIVE, &p, sizeof p };
            r[i] = C_DeriveKey(s, &m, base, dt, 6, &h);
        }
        report("(I) CKM_IKE2_PRF_PLUS_DERIVE hSeedKey", r);
    } else printf("  (I) CKM_IKE2_PRF_PLUS_DERIVE: not in this build\n");

    const char *mode = getenv("FHSM_MODE");
    const int strict = mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips"));
    if (listed(CKM_IKE1_EXTENDED_DERIVE) && !strict) {
        CK_MECHANISM_TYPE bl[1] = { CKM_IKE1_EXTENDED_DERIVE };
        CK_OBJECT_HANDLE base = key(CKK_SHA256_HMAC, 0x30, 32, bl, 1, 0);
        three(CKM_IKE1_EXTENDED_DERIVE, k);
        for (int i = 0; i < 3; i++) {
            CK_IKE1_EXTENDED_DERIVE_PARAMS p = { CKM_SHA256_HMAC, 1, k[i], extra, sizeof extra };
            CK_MECHANISM m = { CKM_IKE1_EXTENDED_DERIVE, &p, sizeof p };
            r[i] = C_DeriveKey(s, &m, base, dt, 6, &h);
        }
        report("(I) CKM_IKE1_EXTENDED_DERIVE hKeygxy", r);
    } else printf("  (I) CKM_IKE1_EXTENDED_DERIVE: not in this build or mode\n");

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
