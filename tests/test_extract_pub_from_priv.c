/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_extract_pub_from_priv.c --- CKM_EXTRACT_KEY_FROM_KEY and
 * CKM_PUB_KEY_FROM_PRIV_KEY (2.8.0).
 *
 * CKM_EXTRACT_KEY_FROM_KEY (all-mechanisms, permissive mode):
 *   (X) PKCS#11's own example: base 0x329F84A9, bit 21, two bytes, 0x9526;
 *       bits 0 and 128 of a 32-byte base, 16 bytes each, its two halves;
 *       bit 252, two bytes, wrapping round the end: 0xF000.
 *   (R) no CKA_VALUE_LEN for a generic secret is CKR_TEMPLATE_INCOMPLETE; a
 *       bit past the end, or no parameter, CKR_MECHANISM_PARAM_INVALID; an
 *       AES base CKR_KEY_TYPE_INCONSISTENT; CKA_SENSITIVE=FALSE from a
 *       sensitive base CKR_TEMPLATE_INCONSISTENT.
 *   (C) fewer bytes than a sensitive base holds: CKR_KEY_FUNCTION_NOT_PERMITTED
 *       (#48); all of them, rotated, are taken.
 * CKM_PUB_KEY_FROM_PRIV_KEY (both builds):
 *   (P) from a generated P-256, RSA-2048 and Ed25519 private key, a public
 *       key object whose CKA_EC_POINT / CKA_EC_PARAMS, or CKA_MODULUS /
 *       CKA_PUBLIC_EXPONENT, are the generated public key's, with CKA_LOCAL
 *       FALSE; an ECDSA signature by the private key verifies under it.
 *   (Q) a parameter, a CKO_SECRET_KEY template, a key type other than the
 *       private key's: refused; a public key as the base:
 *       CKR_KEY_TYPE_INCONSISTENT.
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
#define CKR_KEY_FUNCTION_NOT_PERMITTED 0x068UL
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKR_TEMPLATE_INCOMPLETE        0x0D0UL
#define CKR_TEMPLATE_INCONSISTENT      0x0D1UL
#define CKF_RW                         6UL
#define CKO_PUBLIC_KEY                 2UL
#define CKO_SECRET_KEY                 4UL
#define CKK_RSA                        0x00UL
#define CKK_EC                         0x03UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_DERIVE                     0x10CUL
#define CKA_MODULUS                    0x120UL
#define CKA_MODULUS_BITS               0x121UL
#define CKA_PUBLIC_EXPONENT            0x122UL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKA_LOCAL                      0x163UL
#define CKA_EC_PARAMS                  0x180UL
#define CKA_EC_POINT                   0x181UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x0000UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_EXTRACT_KEY_FROM_KEY       0x0365UL
#define CKM_EC_KEY_PAIR_GEN            0x1040UL
#define CKM_ECDSA_SHA256               0x1044UL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN    0x1055UL
#define CKM_PUB_KEY_FROM_PRIV_KEY      0x403AUL

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
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);
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

static int listed(CK_ULONG mech) {
    CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
    CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
    C_GetMechanismList(0, ml, &n);
    int found = 0;
    for (CK_ULONG i = 0; i < n; i++) if (ml[i] == mech) found = 1;
    free(ml);
    return found;
}

static CK_OBJECT_HANDLE secret(const CK_BYTE *v, CK_ULONG vl, CK_ULONG kt, CK_BYTE sens) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_DERIVE, &yes, 1 },
                         { CKA_SENSITIVE, &sens, 1 }, { CKA_EXTRACTABLE, &yes, 1 },
                         { CKA_VALUE, (void*)v, vl } };
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, 7, &h) == CKR_OK ? h : 0;
}

/* CKM_EXTRACT_KEY_FROM_KEY at `bit`; a generic secret of vl bytes (none if
 * 0), readable; its value into out. */
static CK_RV extract(CK_OBJECT_HANDLE base, CK_ULONG bit, CK_ULONG vl, CK_BYTE sens,
                     CK_BYTE *out, CK_ULONG *ol) {
    CK_MECHANISM m = { CKM_EXTRACT_KEY_FROM_KEY, &bit, sizeof bit };
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &sens, 1 },
                         { CKA_EXTRACTABLE, &yes, 1 }, { CKA_VALUE_LEN, &vl, sizeof vl } };
    CK_OBJECT_HANDLE h = 0;
    CK_RV rv = C_DeriveKey(s, &m, base, t, vl ? 6 : 5, &h);
    if (rv != CKR_OK || !out) return rv;
    CK_ATTRIBUTE a = { CKA_VALUE, out, *ol };
    rv = C_GetAttributeValue(s, h, &a, 1);
    *ol = a.ulValueLen;
    return rv;
}

static CK_RV pub_from(CK_OBJECT_HANDLE priv, CK_ULONG cls, CK_ULONG kt, CK_OBJECT_HANDLE *h) {
    CK_MECHANISM m = { CKM_PUB_KEY_FROM_PRIV_KEY, NULL, 0 };
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 } };
    *h = 0;
    return C_DeriveKey(s, &m, priv, t, 4, h);
}

/* Read one attribute of up to 600 bytes; its length, or 0 on failure. */
static CK_ULONG attr(CK_OBJECT_HANDLE h, CK_ULONG type, CK_BYTE *buf) {
    CK_ATTRIBUTE a = { type, buf, 600 };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? a.ulValueLen : 0;
}

static int same_attr(CK_OBJECT_HANDLE a, CK_OBJECT_HANDLE b, CK_ULONG type) {
    static CK_BYTE x[600], y[600];
    CK_ULONG lx = attr(a, type, x), ly = attr(b, type, y);
    return lx > 0 && lx == ly && memcmp(x, y, lx) == 0;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_GenerateKeyPair); SYM(C_DeriveKey); SYM(C_GetAttributeValue);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_DeriveKey || !C_GenerateKeyPair || !C_Verify) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("EXTRACT_KEY_FROM_KEY, PUB_KEY_FROM_PRIV_KEY\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "extractpub", 10);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const char *mode = getenv("FHSM_MODE");
    const int nist_build = !listed(CKM_RSA_PKCS);
    const int nist = nist_build || (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips")));

    /* --- CKM_EXTRACT_KEY_FROM_KEY ---------------------------------------- */
    static const CK_BYTE ex[4] = { 0x32, 0x9F, 0x84, 0xA9 };
    CK_BYTE b32[32];
    for (int i = 0; i < 32; i++) b32[i] = (CK_BYTE)i;
    CK_OBJECT_HANDLE gex = secret(ex, 4, CKK_GENERIC_SECRET, 0),
                     g32 = secret(b32, 32, CKK_GENERIC_SECRET, 0),
                     gsens = secret(b32, 32, CKK_GENERIC_SECRET, 1),
                     aes = secret(b32, 16, CKK_AES, 0);
    if (!gex || !g32 || !gsens || !aes) { fprintf(stderr, "key import\n"); return 2; }
    if (nist) {
        char what[128];
        CK_RV rv = extract(g32, 0, 16, 0, NULL, NULL);
        ok(nist_build ? !listed(CKM_EXTRACT_KEY_FROM_KEY) : 1,
           "(N) EXTRACT_KEY_FROM_KEY not listed in the nist build");
        snprintf(what, sizeof what, "(N) EXTRACT_KEY_FROM_KEY: MECHANISM_INVALID (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_INVALID, what);
    } else {
        ok(listed(CKM_EXTRACT_KEY_FROM_KEY), "EXTRACT_KEY_FROM_KEY listed");
        static const struct { const char *name; int which; CK_ULONG bit, len; CK_BYTE want[16]; } X[] = {
            { "PKCS#11's example: bit 21 of 0x329F84A9", 0, 21, 2, { 0x95, 0x26 } },
            { "bit 0, 16 bytes",      1, 0,   16, { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 } },
            { "bit 128, 16 bytes",    1, 128, 16, { 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 } },
            { "bit 252, wrapping",    1, 252, 2,  { 0xF0, 0x00 } },
        };
        for (size_t i = 0; i < sizeof X / sizeof X[0]; i++) {
            char what[128];
            CK_BYTE out[32]; CK_ULONG ol = sizeof out;
            CK_RV rv = extract(X[i].which ? g32 : gex, X[i].bit, X[i].len, 0, out, &ol);
            snprintf(what, sizeof what, "(X) %s (0x%lx)", X[i].name, rv);
            ok(rv == CKR_OK && ol == X[i].len && memcmp(out, X[i].want, X[i].len) == 0, what);
        }
        char what[160];
        CK_RV r1 = extract(g32, 0, 0, 0, NULL, NULL);
        CK_RV r2 = extract(g32, 256, 4, 0, NULL, NULL);
        CK_MECHANISM none = { CKM_EXTRACT_KEY_FROM_KEY, NULL, 0 };
        CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET, vl = 4;
        CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                             { CKA_TOKEN, &no, 1 }, { CKA_VALUE_LEN, &vl, sizeof vl } };
        CK_OBJECT_HANDLE h = 0;
        CK_RV r3 = C_DeriveKey(s, &none, g32, t, 4, &h);
        CK_RV r4 = extract(aes, 0, 4, 0, NULL, NULL);
        CK_RV r5 = extract(gsens, 0, 32, 0, NULL, NULL);
        snprintf(what, sizeof what,
                 "(R) no length, bit 256, no param, AES base, unsensitive (0x%lx 0x%lx 0x%lx 0x%lx 0x%lx)",
                 r1, r2, r3, r4, r5);
        ok(r1 == CKR_TEMPLATE_INCOMPLETE && r2 == CKR_MECHANISM_PARAM_INVALID
           && r3 == CKR_MECHANISM_PARAM_INVALID && r4 == CKR_KEY_TYPE_INCONSISTENT
           && r5 == CKR_TEMPLATE_INCONSISTENT, what);
        /* (C) A sensitive base is not cut short (#48): four of its 32 bytes
         * would be found by an HMAC under them and 2^32 guesses, one by 256.
         * All 32 bytes, rotated, is not a cut. */
        CK_RV r6 = extract(gsens, 0, 4, 1, NULL, NULL);
        CK_RV r7 = extract(gsens, 8, 32, 1, NULL, NULL);
        snprintf(what, sizeof what,
                 "(C) 4 bytes of a sensitive base refused, 32 rotated made (0x%lx 0x%lx)", r6, r7);
        ok(r6 == CKR_KEY_FUNCTION_NOT_PERMITTED && r7 == CKR_OK, what);
    }

    /* --- CKM_PUB_KEY_FROM_PRIV_KEY ---------------------------------------- */
    ok(listed(CKM_PUB_KEY_FROM_PRIV_KEY), "PUB_KEY_FROM_PRIV_KEY listed");
    static CK_BYTE p256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
    static CK_BYTE ed25519[] = { 0x06,0x03,0x2B,0x65,0x70 };
    CK_ULONG bits = 2048;
    CK_BYTE e65537[3] = { 1, 0, 1 };
    CK_ATTRIBUTE priv_t[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 }, { CKA_DERIVE, &yes, 1 } };
    /* The private keys ask CKA_DERIVE; only the EC one can have it, and the
     * mechanism does not ask for it -- the RSA and Ed25519 cases are the
     * proof. The P-256 public key carries it too, which (Q) does not need. */
    struct { const char *name; CK_ULONG mech, kt; CK_ATTRIBUTE pub[4]; CK_ULONG a1, a2; } K[] = {
        { "P-256", CKM_EC_KEY_PAIR_GEN, CKK_EC,
          { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 }, { CKA_EC_PARAMS, p256, sizeof p256 },
            { CKA_DERIVE, &yes, 1 } },
          CKA_EC_POINT, CKA_EC_PARAMS },
        { "RSA-2048", CKM_RSA_PKCS_KEY_PAIR_GEN, CKK_RSA,
          { { CKA_TOKEN, &no, 1 }, { CKA_MODULUS_BITS, &bits, sizeof bits },
            { CKA_PUBLIC_EXPONENT, e65537, sizeof e65537 }, { CKA_VERIFY, &yes, 1 } },
          CKA_MODULUS, CKA_PUBLIC_EXPONENT },
        { "Ed25519", CKM_EC_EDWARDS_KEY_PAIR_GEN, 0x40UL /* CKK_EC_EDWARDS */,
          { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 }, { CKA_EC_PARAMS, ed25519, sizeof ed25519 },
            { CKA_DERIVE, &no, 1 } },
          CKA_EC_POINT, CKA_EC_PARAMS },
    };
    CK_OBJECT_HANDLE ec_priv = 0, ec_pub = 0, ec_derived = 0;
    for (size_t i = 0; i < 3; i++) {
        char what[128];
        CK_MECHANISM m = { K[i].mech, NULL, 0 };
        CK_OBJECT_HANDLE pub = 0, priv = 0, d = 0;
        CK_RV rv = C_GenerateKeyPair(s, &m, K[i].pub, 4, priv_t, 3, &pub, &priv);
        if (rv == CKR_OK) rv = pub_from(priv, CKO_PUBLIC_KEY, K[i].kt, &d);
        CK_ULONG cls = 0; CK_BYTE local = 1;
        CK_ATTRIBUTE ca[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_LOCAL, &local, 1 } };
        if (rv == CKR_OK) rv = C_GetAttributeValue(s, d, ca, 2);
        snprintf(what, sizeof what, "(P) %s: a public key, not local, the generated one's (0x%lx)",
                 K[i].name, rv);
        ok(rv == CKR_OK && cls == CKO_PUBLIC_KEY && local == 0
           && same_attr(pub, d, K[i].a1) && same_attr(pub, d, K[i].a2), what);
        if (i == 0) { ec_priv = priv; ec_pub = pub; ec_derived = d; }
    }
    {
        char what[128];
        CK_MECHANISM m = { CKM_ECDSA_SHA256, NULL, 0 };
        CK_BYTE msg[] = "the public half of a private key", sig[80];
        CK_ULONG sl = sizeof sig;
        CK_RV rv = C_SignInit(s, &m, ec_priv);
        if (rv == CKR_OK) rv = C_Sign(s, msg, sizeof msg - 1, sig, &sl);
        if (rv == CKR_OK) rv = C_VerifyInit(s, &m, ec_derived);
        if (rv == CKR_OK) rv = C_Verify(s, msg, sizeof msg - 1, sig, sl);
        snprintf(what, sizeof what, "(P) an ECDSA signature verifies under the derived key (0x%lx)", rv);
        ok(rv == CKR_OK, what);
    }
    {
        char what[160];
        CK_ULONG p = 0;
        CK_MECHANISM withp = { CKM_PUB_KEY_FROM_PRIV_KEY, &p, sizeof p };
        CK_ULONG cls = CKO_PUBLIC_KEY, kt = CKK_EC;
        CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                             { CKA_TOKEN, &no, 1 } };
        CK_OBJECT_HANDLE h = 0;
        CK_RV r1 = C_DeriveKey(s, &withp, ec_priv, t, 3, &h);
        CK_RV r2 = pub_from(ec_priv, CKO_SECRET_KEY, CKK_EC, &h);
        CK_RV r3 = pub_from(ec_priv, CKO_PUBLIC_KEY, CKK_RSA, &h);
        CK_RV r4 = pub_from(ec_pub, CKO_PUBLIC_KEY, CKK_EC, &h);
        snprintf(what, sizeof what,
                 "(Q) a parameter, secret class, other type, public base (0x%lx 0x%lx 0x%lx 0x%lx)",
                 r1, r2, r3, r4);
        ok(r1 == CKR_MECHANISM_PARAM_INVALID && r2 == CKR_TEMPLATE_INCONSISTENT
           && r3 == CKR_TEMPLATE_INCONSISTENT && r4 == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
