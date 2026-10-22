/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_ec_curve_refusal.c --- a curve the module does not take is
 * CKR_CURVE_NOT_SUPPORTED; a CKA_EC_PARAMS that names no curve is
 * CKR_ATTRIBUTE_VALUE_INVALID.
 *
 * Every refusal of a curve was CKR_ATTRIBUTE_VALUE_INVALID, so a caller could
 * not tell "this token does not do brainpool" from "your value is broken",
 * and pkcs11-check scored some 13 100 Wycheproof vectors per profile as
 * advertised-but-not-operational instead of absent (PKCS11_CHECK_FINDINGS,
 * 2026-10-21).
 *
 * The curves used are refused in every build and profile, so the test means
 * the same everywhere: secp224r1 is under FHSM_EC_MIN_BITS, sect283k1 is a
 * binary field. What is asserted:
 *   (1) C_CreateObject, EC private key on either: CKR_CURVE_NOT_SUPPORTED
 *   (2) C_CreateObject, EC public key on either: CKR_CURVE_NOT_SUPPORTED
 *   (3) C_GenerateKeyPair, CKM_EC_KEY_PAIR_GEN on either:
 *       CKR_CURVE_NOT_SUPPORTED
 *   (4) the same three with CKA_EC_PARAMS the OID of SHA-256, which names no
 *       curve, and with bytes that are not DER: CKR_ATTRIBUTE_VALUE_INVALID
 *   (5) the control: P-256 still imports and generates
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                      0UL
#define CKR_ATTRIBUTE_VALUE_INVALID 0x13UL
#define CKR_CURVE_NOT_SUPPORTED     0x140UL
#define CKF_RW                      6UL
#define CKA_CLASS                   0x000UL
#define CKA_TOKEN                   0x001UL
#define CKA_VALUE                   0x011UL
#define CKA_KEY_TYPE                0x100UL
#define CKA_SIGN                    0x108UL
#define CKA_VERIFY                  0x10AUL
#define CKA_EC_PARAMS               0x180UL
#define CKA_EC_POINT                0x181UL
#define CKO_PUBLIC_KEY              2UL
#define CKO_PRIVATE_KEY             3UL
#define CKK_EC                      3UL
#define CKM_EC_KEY_PAIR_GEN         0x1040UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static const struct { const char *name; CK_BYTE der[16]; CK_ULONG len; CK_RV want; } PARAMS[] = {
    { "secp224r1 (224 bits)",  { 0x06,0x05,0x2B,0x81,0x04,0x00,0x21 }, 7, CKR_CURVE_NOT_SUPPORTED },
    { "sect283k1 (binary)",    { 0x06,0x05,0x2B,0x81,0x04,0x00,0x10 }, 7, CKR_CURVE_NOT_SUPPORTED },
    { "the OID of SHA-256",    { 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01 }, 11,
                               CKR_ATTRIBUTE_VALUE_INVALID },
    { "bytes that are not DER", { 0x13,0x37,0x00,0xFF }, 4, CKR_ATTRIBUTE_VALUE_INVALID },
};
#define NPARAMS (sizeof PARAMS / sizeof PARAMS[0])
static const CK_BYTE P256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-70s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);

static CK_RV import_priv(CK_SESSION_HANDLE s, const CK_BYTE *p, CK_ULONG pl) {
    /* d = 1: a valid scalar on every curve, so the curve is the only
     * thing that can be refused. */
    CK_BYTE d[32] = { 0 }; d[31] = 1;
    CK_ULONG cls = CKO_PRIVATE_KEY, kt = CKK_EC;
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE t[] = {
        { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
        { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 },
        { CKA_EC_PARAMS, (void*)p, pl }, { CKA_VALUE, d, sizeof d },
    };
    CK_OBJECT_HANDLE h;
    return C_CreateObject(s, t, sizeof t / sizeof t[0], &h);
}

static CK_RV import_pub(CK_SESSION_HANDLE s, const CK_BYTE *p, CK_ULONG pl) {
    /* The P-256 generator, DER OCTET STRING wrapped: a real point, so for
     * P-256 the import succeeds and for the others only the curve fails. */
    static const CK_BYTE pt[] = { 0x04,0x41,0x04,
        0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,
        0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96,
        0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,
        0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5 };
    CK_ULONG cls = CKO_PUBLIC_KEY, kt = CKK_EC;
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE t[] = {
        { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
        { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
        { CKA_EC_PARAMS, (void*)p, pl }, { CKA_EC_POINT, (void*)pt, sizeof pt },
    };
    CK_OBJECT_HANDLE h;
    return C_CreateObject(s, t, sizeof t / sizeof t[0], &h);
}

static CK_RV keygen(CK_SESSION_HANDLE s, const CK_BYTE *p, CK_ULONG pl) {
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                          { CKA_EC_PARAMS, (void*)p, pl } };
    CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE pub, priv;
    return C_GenerateKeyPair(s, &m, pt, 3, kt, 2, &pub, &priv);
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
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN);
    SYM(C_CreateObject); SYM(C_GenerateKeyPair);
    if (!C_CreateObject || !C_GenerateKeyPair) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("EC curves the module does not take: CKR_CURVE_NOT_SUPPORTED\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "eccurves")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    char what[128];
    for (size_t i = 0; i < NPARAMS; ++i) {
        const int n = PARAMS[i].want == CKR_CURVE_NOT_SUPPORTED ? 0 : 1;
        const char *code = n ? "CKR_ATTRIBUTE_VALUE_INVALID" : "CKR_CURVE_NOT_SUPPORTED";
        CK_RV rv = import_priv(s, PARAMS[i].der, PARAMS[i].len);
        snprintf(what, sizeof what, "(%d) private key, %s: %s (rv 0x%lx)", n ? 4 : 1,
                 PARAMS[i].name, code, rv);
        ok(rv == PARAMS[i].want, what);
        rv = import_pub(s, PARAMS[i].der, PARAMS[i].len);
        snprintf(what, sizeof what, "(%d) public key, %s: %s (rv 0x%lx)", n ? 4 : 2,
                 PARAMS[i].name, code, rv);
        ok(rv == PARAMS[i].want, what);
        rv = keygen(s, PARAMS[i].der, PARAMS[i].len);
        snprintf(what, sizeof what, "(%d) key pair, %s: %s (rv 0x%lx)", n ? 4 : 3,
                 PARAMS[i].name, code, rv);
        ok(rv == PARAMS[i].want, what);
    }

    CK_RV rv = import_priv(s, P256, sizeof P256);
    snprintf(what, sizeof what, "(5) P-256 private key imports (rv 0x%lx)", rv);
    ok(rv == CKR_OK, what);
    rv = import_pub(s, P256, sizeof P256);
    snprintf(what, sizeof what, "(5) P-256 public key imports (rv 0x%lx)", rv);
    ok(rv == CKR_OK, what);
    rv = keygen(s, P256, sizeof P256);
    snprintf(what, sizeof what, "(5) P-256 key pair generates (rv 0x%lx)", rv);
    ok(rv == CKR_OK, what);

    (void)C_Finalize(NULL);
    printf("\n%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
