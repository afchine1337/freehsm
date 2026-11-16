/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_ec_extra_bits.c --- CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS (2.8.0), the
 * private key by FIPS 186-5 A.2.1, extra random bits.
 *
 *   (G) listed in both builds; P-256, P-384 and P-521 pairs are made, their
 *       public CKA_EC_PARAMS is the curve asked, and an ECDSA signature by
 *       each private key verifies under its public key.
 *   (D) sixteen P-256 pairs have sixteen different public points.
 *   (R) where a private key may be made not sensitive (all-mechanisms,
 *       permissive mode), its d read back is in [1, n - 1] for P-256.
 *   (T) no CKA_EC_PARAMS is CKR_TEMPLATE_INCOMPLETE; CKA_KEY_TYPE CKK_RSA
 *       in a template is CKR_TEMPLATE_INCONSISTENT.
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
#define CKR_TEMPLATE_INCOMPLETE        0x0D0UL
#define CKR_TEMPLATE_INCONSISTENT      0x0D1UL
#define CKF_RW                         6UL
#define CKK_RSA                        0x00UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_EXTRACTABLE                0x162UL
#define CKA_EC_PARAMS                  0x180UL
#define CKA_EC_POINT                   0x181UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_ECDSA_SHA256               0x1044UL
#define CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS 0x140BUL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);
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

static int listed(CK_ULONG mech) {
    CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
    CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
    C_GetMechanismList(0, ml, &n);
    int found = 0;
    for (CK_ULONG i = 0; i < n; i++) if (ml[i] == mech) found = 1;
    free(ml);
    return found;
}

static CK_RV gen(CK_BYTE *params, CK_ULONG pl, CK_BYTE sens,
                 CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {
    CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS, NULL, 0 };
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                          { CKA_EC_PARAMS, params, pl } };
    CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 },
                          { CKA_SENSITIVE, &sens, 1 }, { CKA_EXTRACTABLE, &yes, 1 } };
    *pub = *priv = 0;
    /* The sensitivity and extractability only for (R), the one case that
     * reads d back; elsewhere the module's defaults. */
    return C_GenerateKeyPair(s, &m, pt, params ? 3 : 2, kt, sens ? 2 : 4, pub, priv);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_GenerateKeyPair || !C_Verify) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("EC_KEY_PAIR_GEN_W_EXTRA_BITS\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "ecextra", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const char *mode = getenv("FHSM_MODE");
    const int nist = !listed(CKM_RSA_PKCS)
                     || (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips")));

    /* (G) */
    ok(listed(CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS), "(G) listed");
    static CK_BYTE p256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
    static CK_BYTE p384[] = { 0x06,0x05,0x2B,0x81,0x04,0x00,0x22 };
    static CK_BYTE p521[] = { 0x06,0x05,0x2B,0x81,0x04,0x00,0x23 };
    struct { const char *name; CK_BYTE *p; CK_ULONG pl; } C[] = {
        { "P-256", p256, sizeof p256 }, { "P-384", p384, sizeof p384 }, { "P-521", p521, sizeof p521 },
    };
    for (size_t i = 0; i < 3; i++) {
        char what[128];
        CK_OBJECT_HANDLE pub = 0, priv = 0;
        CK_RV rv = gen(C[i].p, C[i].pl, 1, &pub, &priv);
        CK_BYTE ep[16]; CK_ATTRIBUTE a = { CKA_EC_PARAMS, ep, sizeof ep };
        if (rv == CKR_OK) rv = C_GetAttributeValue(s, pub, &a, 1);
        int params_ok = rv == CKR_OK && a.ulValueLen == C[i].pl && memcmp(ep, C[i].p, C[i].pl) == 0;
        CK_MECHANISM m = { CKM_ECDSA_SHA256, NULL, 0 };
        CK_BYTE msg[] = "extra random bits", sig[160];
        CK_ULONG sl = sizeof sig;
        if (rv == CKR_OK) rv = C_SignInit(s, &m, priv);
        if (rv == CKR_OK) rv = C_Sign(s, msg, sizeof msg - 1, sig, &sl);
        if (rv == CKR_OK) rv = C_VerifyInit(s, &m, pub);
        if (rv == CKR_OK) rv = C_Verify(s, msg, sizeof msg - 1, sig, sl);
        snprintf(what, sizeof what, "(G) %s: made, its curve, sign and verify (0x%lx)", C[i].name, rv);
        ok(rv == CKR_OK && params_ok, what);
    }

    /* (D) */
    {
        static CK_BYTE pts[16][80];
        CK_ULONG pls[16];
        int made = 1, distinct = 1;
        for (int i = 0; i < 16 && made; i++) {
            CK_OBJECT_HANDLE pub = 0, priv = 0;
            CK_ATTRIBUTE a = { CKA_EC_POINT, pts[i], sizeof pts[i] };
            made = gen(p256, sizeof p256, 1, &pub, &priv) == CKR_OK
                   && C_GetAttributeValue(s, pub, &a, 1) == CKR_OK;
            pls[i] = a.ulValueLen;
            for (int j = 0; made && j < i; j++)
                if (pls[j] == pls[i] && memcmp(pts[j], pts[i], pls[i]) == 0) distinct = 0;
        }
        ok(made && distinct, "(D) sixteen P-256 pairs, sixteen public points");
    }

    /* (R) */
    if (!nist) {
        char what[128];
        static const CK_BYTE order[32] = {
            0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51 };
        CK_OBJECT_HANDLE pub = 0, priv = 0;
        CK_BYTE d[66]; CK_ATTRIBUTE a = { CKA_VALUE, d, sizeof d };
        CK_RV rv = gen(p256, sizeof p256, 0, &pub, &priv);
        if (rv == CKR_OK) rv = C_GetAttributeValue(s, priv, &a, 1);
        int nonzero = 0;
        for (CK_ULONG i = 0; i < a.ulValueLen && i < sizeof d; i++) if (d[i]) nonzero = 1;
        snprintf(what, sizeof what, "(R) P-256 d read back, in [1, n - 1] (0x%lx, %lu bytes)",
                 rv, a.ulValueLen);
        ok(rv == CKR_OK && a.ulValueLen == 32 && nonzero && memcmp(d, order, 32) < 0, what);
    }

    /* (T) */
    {
        char what[128];
        CK_OBJECT_HANDLE pub = 0, priv = 0;
        CK_RV r1 = gen(NULL, 0, 1, &pub, &priv);
        CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS, NULL, 0 };
        CK_ULONG rsa = CKK_RSA;
        CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_EC_PARAMS, p256, sizeof p256 },
                              { CKA_KEY_TYPE, &rsa, sizeof rsa } };
        CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 } };
        CK_RV r2 = C_GenerateKeyPair(s, &m, pt, 3, kt, 1, &pub, &priv);
        snprintf(what, sizeof what, "(T) no curve, CKK_RSA: INCOMPLETE, INCONSISTENT (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_TEMPLATE_INCOMPLETE && r2 == CKR_TEMPLATE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
