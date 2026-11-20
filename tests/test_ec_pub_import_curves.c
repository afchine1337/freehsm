/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_ec_pub_import_curves.c --- an EC public key imports on every curve
 * the module generates on (#39).
 *
 * C_CreateObject resolved a public key's curve with the parser's table of
 * three NIST curves, where key generation and private-key import use
 * match_curve, which takes secp256k1 and brainpool in the all-mechanisms
 * build. A secp256k1 or brainpool public key -- a peer's, or the pair's own
 * CKA_EC_POINT read back -- was CKR_CURVE_NOT_SUPPORTED on a token that had
 * just generated on that curve. Reported by AlexLaroche (KerckhoffsLabs
 * PKCS#11 test suite, Wycheproof secp256k1 ECDSA vectors).
 *
 * For P-256, secp256k1, brainpoolP256r1 and brainpoolP384r1:
 *   (1) C_GenerateKeyPair and C_CreateObject of the pair's own public key
 *       agree: both CKR_OK, or both CKR_CURVE_NOT_SUPPORTED where the build,
 *       the mode or the provider does not serve the curve;
 *   (2) where they succeed, a CKM_ECDSA signature by the private key verifies
 *       under the imported public key, and the imported key's CKA_EC_PARAMS
 *       reads back as given;
 *   (3) the same point with one byte of Y changed -- off the curve -- is
 *       CKR_ATTRIBUTE_VALUE_INVALID, so the point is still checked on the
 *       resolved curve.
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
#define CKR_ATTRIBUTE_VALUE_INVALID    0x013UL
#define CKR_CURVE_NOT_SUPPORTED        0x140UL
#define CKF_RW                         6UL
#define CKO_PUBLIC_KEY                 2UL
#define CKK_EC                         0x03UL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_EC_PARAMS                  0x180UL
#define CKA_EC_POINT                   0x181UL
#define CKM_EC_KEY_PAIR_GEN            0x1040UL
#define CKM_ECDSA                      0x1041UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static const struct { const char *name; CK_BYTE oid[12]; CK_ULONG len; } CURVES[] = {
    { "P-256",           { 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 }, 10 },
    { "secp256k1",       { 0x06,0x05,0x2b,0x81,0x04,0x00,0x0a }, 7 },
    { "brainpoolP256r1", { 0x06,0x09,0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07 }, 11 },
    { "brainpoolP384r1", { 0x06,0x09,0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0b }, 11 },
};

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;

static CK_RV import_pub(const CK_BYTE *oid, CK_ULONG ol, const CK_BYTE *pt, CK_ULONG pl,
                        CK_OBJECT_HANDLE *h) {
    CK_ULONG cls = CKO_PUBLIC_KEY, kt = CKK_EC;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_EC_PARAMS, (void*)oid, ol },
                         { CKA_EC_POINT, (void*)pt, pl }, { CKA_VERIFY, &yes, 1 } };
    return C_CreateObject(s, t, 6, h);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject);
    SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_CreateObject || !C_Verify) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("EC public key import on every curve the module generates on (#39)\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "ecpub", 5);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    char what[160];
    int p256_ok = 0;
    for (size_t c = 0; c < sizeof CURVES / sizeof CURVES[0]; c++) {
        const CK_BYTE *oid = CURVES[c].oid;
        const CK_ULONG ol = CURVES[c].len;
        CK_MECHANISM gm = { CKM_EC_KEY_PAIR_GEN, NULL, 0 }, em = { CKM_ECDSA, NULL, 0 };
        CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_EC_PARAMS, (void*)oid, ol },
                              { CKA_VERIFY, &yes, 1 } };
        CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
        CK_OBJECT_HANDLE pub = 0, prv = 0, imp = 0;
        CK_RV g = C_GenerateKeyPair(s, &gm, pt, 3, vt, 2, &pub, &prv);
        if (g != CKR_OK) {
            /* Not served here: the import must be refused the same way. */
            static const CK_BYTE any_pt[67] = { 0x04, 0x41, 0x04 };
            CK_RV r = import_pub(oid, ol, any_pt, sizeof any_pt, &imp);
            snprintf(what, sizeof what, "(1) %s not generated (0x%lx), import refused alike (0x%lx)",
                     CURVES[c].name, g, r);
            ok(g == CKR_CURVE_NOT_SUPPORTED && r == CKR_CURVE_NOT_SUPPORTED, what);
            continue;
        }
        if (c == 0) p256_ok = 1;
        CK_BYTE point[160];
        CK_ATTRIBUTE pa = { CKA_EC_POINT, point, sizeof point };
        CK_RV ar = C_GetAttributeValue(s, pub, &pa, 1);
        CK_RV r = ar == CKR_OK ? import_pub(oid, ol, point, pa.ulValueLen, &imp) : ar;
        snprintf(what, sizeof what, "(1) %s: generated, its public key imports (0x%lx)", CURVES[c].name, r);
        ok(r == CKR_OK, what);
        if (r != CKR_OK) continue;

        CK_BYTE hash[32], sig[160];
        CK_ULONG sl = sizeof sig;
        memset(hash, 0xAB, sizeof hash);
        CK_RV sr = C_SignInit(s, &em, prv);
        if (sr == CKR_OK) sr = C_Sign(s, hash, sizeof hash, sig, &sl);
        CK_RV vr = sr == CKR_OK ? C_VerifyInit(s, &em, imp) : sr;
        if (vr == CKR_OK) vr = C_Verify(s, hash, sizeof hash, sig, sl);
        CK_BYTE rp[16];
        CK_ATTRIBUTE ra = { CKA_EC_PARAMS, rp, sizeof rp };
        CK_RV pr = C_GetAttributeValue(s, imp, &ra, 1);
        snprintf(what, sizeof what, "(2) %s: signature verifies under the imported key (0x%lx)",
                 CURVES[c].name, vr);
        ok(vr == CKR_OK && pr == CKR_OK && ra.ulValueLen == ol && !memcmp(rp, oid, ol), what);

        point[pa.ulValueLen - 1] ^= 0x01;   /* the last byte of Y */
        r = import_pub(oid, ol, point, pa.ulValueLen, &imp);
        snprintf(what, sizeof what, "(3) %s: a point off the curve refused (0x%lx)", CURVES[c].name, r);
        ok(r == CKR_ATTRIBUTE_VALUE_INVALID, what);
    }
    ok(p256_ok, "P-256, the control, generated");

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
