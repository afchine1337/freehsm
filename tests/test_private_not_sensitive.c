/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_private_not_sensitive.c --- a private key asked CKA_SENSITIVE=FALSE.
 *
 * PKCS#11 does not forbid it. 2.7.0 refused it (CKR_TEMPLATE_INCONSISTENT),
 * earlier versions accepted it and made the key sensitive anyway. Since 2.8.0
 * it is honoured outside strict mode, in both build profiles: the key is made
 * not sensitive, and when it is also CKA_EXTRACTABLE=TRUE C_GetAttributeValue
 * gives its private value in the form PKCS#11 v3.2 defines for its type.
 *
 * Permissive mode (this process):
 *   (K) for RSA-2048, P-256, Ed25519, X25519, ML-DSA-44, ML-KEM-512 and
 *       SLH-DSA-SHA2-128f, wherever the build and provider offer them: a pair
 *       generated with the private half CKA_SENSITIVE=FALSE and extractable is
 *       made; CKA_SENSITIVE and CKA_ALWAYS_SENSITIVE read FALSE; the private
 *       value reads back at the length its standard gives; imported again
 *       through C_CreateObject it is accepted, and a signing key imported
 *       that way signs for the original public key -- which proves the value
 *       is the key, not merely bytes of the right length. Keys that do not
 *       sign read back the same value from the imported copy.
 *   (S) the rules around it, on RSA: a private key that does not name
 *       CKA_SENSITIVE is sensitive; one not sensitive but not extractable
 *       withholds its components (CKR_ATTRIBUTE_SENSITIVE); CKA_SENSITIVE set
 *       to TRUE afterwards withholds them and cannot be set back
 *       (CKR_ATTRIBUTE_READ_ONLY); the composite ML-DSA-65 + Ed25519 pair,
 *       which has no standard private value, is refused not sensitive.
 * Strict mode (this program again, FHSM_MODE=strict, same token):
 *   (T) a pair or an import asking CKA_SENSITIVE=FALSE is
 *       CKR_TEMPLATE_INCONSISTENT; a token key made not sensitive and
 *       extractable in permissive mode withholds its value
 *       (CKR_ATTRIBUTE_SENSITIVE).
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                       0x000UL
#define CKR_ATTRIBUTE_READ_ONLY      0x010UL
#define CKR_ATTRIBUTE_SENSITIVE      0x011UL
#define CKR_MECHANISM_INVALID        0x070UL
#define CKR_TEMPLATE_INCONSISTENT    0x0D1UL
#define CKR_CURVE_NOT_SUPPORTED      0x140UL
#define CKF_RW                       6UL

#define CKO_PRIVATE_KEY              3UL
#define CKK_RSA                      0x00UL
#define CKK_EC                       0x03UL
#define CKK_EC_EDWARDS               0x40UL
#define CKK_EC_MONTGOMERY            0x41UL
#define CKK_ML_KEM                   0x49UL
#define CKK_ML_DSA                   0x4AUL
#define CKK_SLH_DSA                  0x4BUL

#define CKA_CLASS                    0x000UL
#define CKA_TOKEN                    0x001UL
#define CKA_LABEL                    0x003UL
#define CKA_VALUE                    0x011UL
#define CKA_KEY_TYPE                 0x100UL
#define CKA_SENSITIVE                0x103UL
#define CKA_DERIVE                   0x10CUL
#define CKA_SIGN                     0x108UL
#define CKA_VERIFY                   0x10AUL
#define CKA_MODULUS                  0x120UL
#define CKA_MODULUS_BITS             0x121UL
#define CKA_PUBLIC_EXPONENT          0x122UL
#define CKA_PRIVATE_EXPONENT         0x123UL
#define CKA_PRIME_1                  0x124UL
#define CKA_PRIME_2                  0x125UL
#define CKA_EXPONENT_1               0x126UL
#define CKA_EXPONENT_2               0x127UL
#define CKA_COEFFICIENT              0x128UL
#define CKA_EXTRACTABLE              0x162UL
#define CKA_ALWAYS_SENSITIVE         0x165UL
#define CKA_EC_PARAMS                0x180UL
#define CKA_PARAMETER_SET            0x61DUL
#define CKA_ENCAPSULATE              0x633UL
#define CKA_DECAPSULATE              0x634UL

#define CKM_RSA_PKCS_KEY_PAIR_GEN    0x0000UL
#define CKM_ML_KEM_KEY_PAIR_GEN      0x000FUL
#define CKM_ML_DSA_KEY_PAIR_GEN      0x001CUL
#define CKM_ML_DSA                   0x001DUL
#define CKM_SLH_DSA_KEY_PAIR_GEN     0x002DUL
#define CKM_SLH_DSA                  0x002EUL
#define CKM_SHA256_RSA_PKCS          0x0040UL
#define CKM_EC_KEY_PAIR_GEN          0x1040UL
#define CKM_ECDSA                    0x1041UL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN  0x1055UL
#define CKM_EC_MONTGOMERY_KEY_PAIR_GEN 0x1056UL
#define CKM_EDDSA                    0x1057UL
#define CKM_COMPOSITE_MLDSA65_ED25519 0x80004202UL

/* Test PINs, for a token this program makes in a throwaway directory. */
#define SO_PIN    "sopin1234"
#define USER_PIN  "userpin1234"
#define TOKEN_KEY "nonsens-ec"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-74s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;
static const CK_BYTE P256[]    = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
static const CK_BYTE ED25519[] = { 0x06,0x03,0x2B,0x65,0x70 };
static const CK_BYTE X25519[]  = { 0x06,0x03,0x2B,0x65,0x6E };
/* 32 bytes: ECDSA signs the hash it is given. */
static CK_BYTE msg[32] = "a private key that may be read.";

/* A buffer large enough for any value read here: ML-DSA-44's private key is
 * 2560 bytes, its signature 2420, SLH-DSA-SHA2-128f's 17088. */
static CK_BYTE big[20000];

/* Read one attribute into `buf` (`cap` bytes); length in *len. */
static CK_RV get(CK_OBJECT_HANDLE h, CK_ULONG type, CK_BYTE *buf, CK_ULONG cap, CK_ULONG *len) {
    CK_ATTRIBUTE a = { type, buf, cap };
    CK_RV rv = C_GetAttributeValue(s, h, &a, 1);
    *len = a.ulValueLen;
    return rv;
}

static int get_bool(CK_OBJECT_HANDLE h, CK_ULONG type) {
    CK_BYTE v = 2; CK_ULONG l = 0;
    if (get(h, type, &v, 1, &l) != CKR_OK || l != 1) return -1;
    return v;
}

static int sign_verify(CK_ULONG mech, CK_OBJECT_HANDLE prv, CK_OBJECT_HANDLE pub) {
    CK_MECHANISM m = { mech, NULL, 0 };
    CK_ULONG sl = sizeof big;
    if (C_SignInit(s, &m, prv) != CKR_OK || C_Sign(s, msg, sizeof msg, big, &sl) != CKR_OK)
        return 0;
    return C_VerifyInit(s, &m, pub) == CKR_OK && C_Verify(s, msg, sizeof msg, big, sl) == CKR_OK;
}

/* One key type of (K). `param` is the public template's defining attribute:
 * CKA_EC_PARAMS, CKA_PARAMETER_SET or CKA_MODULUS_BITS. */
typedef struct {
    const char *name;
    CK_ULONG gen, ckk, sign;           /* sign == 0: the key does not sign */
    CK_ULONG pub_use, priv_use;
    CK_ATTRIBUTE param;
    CK_ULONG value_len;                /* CKA_VALUE length; 0 for RSA */
} key_case;

static CK_RV gen_pair(const key_case *k, int sensitive, int extractable, CK_BYTE token,
                      CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv) {
    CK_MECHANISM m = { k->gen, NULL, 0 };
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { k->pub_use, &yes, 1 }, k->param };
    CK_BYTE tok = token;
    CK_ATTRIBUTE vt[5] = { { CKA_TOKEN, &tok, 1 }, { k->priv_use, &yes, 1 } };
    CK_ULONG n = 2;
    if (sensitive >= 0)   { vt[n].type = CKA_SENSITIVE;   vt[n].pValue = sensitive ? &yes : &no;   vt[n++].ulValueLen = 1; }
    if (extractable >= 0) { vt[n].type = CKA_EXTRACTABLE; vt[n].pValue = extractable ? &yes : &no; vt[n++].ulValueLen = 1; }
    if (token) { vt[n].type = CKA_LABEL; vt[n].pValue = (void *)TOKEN_KEY; vt[n++].ulValueLen = strlen(TOKEN_KEY); }
    *pub = *prv = 0;
    return C_GenerateKeyPair(s, &m, pt, 3, vt, n, pub, prv);
}

/* Import `val` as a private key of k's type, not sensitive and extractable. */
static CK_RV import_value(const key_case *k, const CK_BYTE *val, CK_ULONG len, CK_OBJECT_HANDLE *h) {
    CK_ULONG cls = CKO_PRIVATE_KEY, kt = k->ckk;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { k->priv_use, &yes, 1 },
                         { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 },
                         { CKA_VALUE, (void *)val, len }, k->param };
    return C_CreateObject(s, t, 8, h);
}

/* RSA: rebuild the private key from its components and the public key. */
static CK_RV import_rsa(CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE prv, CK_OBJECT_HANDLE *h) {
    static const CK_ULONG from_pub[2] = { CKA_MODULUS, CKA_PUBLIC_EXPONENT };
    static const CK_ULONG from_prv[6] = { CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2,
                                          CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT };
    static CK_BYTE part[8][512];
    CK_ULONG cls = CKO_PRIVATE_KEY, kt = CKK_RSA;
    CK_ATTRIBUTE t[12] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                           { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    CK_ULONG n = 4, l;
    for (int i = 0; i < 8; i++) {
        CK_ULONG ty = i < 2 ? from_pub[i] : from_prv[i - 2];
        if (get(i < 2 ? pub : prv, ty, part[i], sizeof part[i], &l) != CKR_OK) return 0xFFFFUL;
        t[n].type = ty; t[n].pValue = part[i]; t[n++].ulValueLen = l;
    }
    return C_CreateObject(s, t, n, h);
}

static void check_case(const key_case *k) {
    char what[128];
    CK_OBJECT_HANDLE pub, prv, imp = 0;
    CK_ULONG l = 0;
    CK_RV rv = gen_pair(k, 0, 1, 0, &pub, &prv);
    if (rv == CKR_MECHANISM_INVALID || rv == CKR_CURVE_NOT_SUPPORTED) {
        printf("  %-74s skipped\n", k->name);
        return;
    }
    snprintf(what, sizeof what, "(K) %s: made not sensitive, extractable (0x%lx)", k->name, rv);
    ok(rv == CKR_OK, what);
    if (rv != CKR_OK) return;
    snprintf(what, sizeof what, "(K) %s: CKA_SENSITIVE and CKA_ALWAYS_SENSITIVE read FALSE", k->name);
    ok(get_bool(prv, CKA_SENSITIVE) == 0 && get_bool(prv, CKA_ALWAYS_SENSITIVE) == 0, what);

    if (k->ckk == CKK_RSA) {
        static const CK_ULONG comp[6] = { CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2,
                                          CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT };
        int all = 1;
        for (int i = 0; i < 6; i++) {
            rv = get(prv, comp[i], big, sizeof big, &l);
            all &= rv == CKR_OK && l > 0 && l <= (i == 0 ? 256u : 128u);
        }
        snprintf(what, sizeof what, "(K) %s: its six components are given", k->name);
        ok(all, what);
        rv = get(prv, CKA_VALUE, big, sizeof big, &l);
        snprintf(what, sizeof what, "(K) %s: no CKA_VALUE, TYPE_INVALID (0x%lx)", k->name, rv);
        ok(rv == 0x12UL, what);
        rv = import_rsa(pub, prv, &imp);
    } else {
        rv = get(prv, CKA_VALUE, big, sizeof big, &l);
        snprintf(what, sizeof what, "(K) %s: CKA_VALUE given, %lu bytes, want %lu (0x%lx)",
                 k->name, l, k->value_len, rv);
        ok(rv == CKR_OK && l == k->value_len, what);
        if (rv != CKR_OK) return;
        static CK_BYTE first[5000];
        CK_ULONG fl = l;
        memcpy(first, big, l);
        rv = import_value(k, first, fl, &imp);
        if (rv == CKR_OK && !k->sign) {
            CK_RV r2 = get(imp, CKA_VALUE, big, sizeof big, &l);
            snprintf(what, sizeof what, "(K) %s: the imported copy reads back the same value", k->name);
            ok(r2 == CKR_OK && l == fl && memcmp(big, first, fl) == 0, what);
        }
    }
    snprintf(what, sizeof what, "(K) %s: the value imports again (0x%lx)", k->name, rv);
    ok(rv == CKR_OK, what);
    if (rv == CKR_OK && k->sign) {
        snprintf(what, sizeof what, "(K) %s: the imported key signs for the original public key", k->name);
        ok(sign_verify(k->sign, imp, pub), what);
    }
}

static int open_user(int init) {
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "nonsens", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 0; }
    if (init && C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 0; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 0; }
    if (init) {
        if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 0; }
        if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 0; }
        (void)C_Logout(s);
    }
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 0; }
    return 1;
}

static const key_case RSA_CASE = {
    "RSA-2048", CKM_RSA_PKCS_KEY_PAIR_GEN, CKK_RSA, CKM_SHA256_RSA_PKCS, CKA_VERIFY, CKA_SIGN,
    { CKA_MODULUS_BITS, NULL, sizeof(CK_ULONG) }, 0 };
static const key_case EC_CASE = {
    "P-256", CKM_EC_KEY_PAIR_GEN, CKK_EC, CKM_ECDSA, CKA_VERIFY, CKA_SIGN,
    { CKA_EC_PARAMS, (void *)P256, sizeof P256 }, 32 };

static int permissive(void) {
    static CK_ULONG bits = 2048, pset1 = 1, pset3 = 3;
    key_case cases[7] = {
        RSA_CASE, EC_CASE,
        { "Ed25519", CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK_EC_EDWARDS, CKM_EDDSA, CKA_VERIFY, CKA_SIGN,
          { CKA_EC_PARAMS, (void *)ED25519, sizeof ED25519 }, 32 },
        { "X25519", CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKK_EC_MONTGOMERY, 0, CKA_DERIVE, CKA_DERIVE,
          { CKA_EC_PARAMS, (void *)X25519, sizeof X25519 }, 32 },
        { "ML-DSA-44", CKM_ML_DSA_KEY_PAIR_GEN, CKK_ML_DSA, CKM_ML_DSA, CKA_VERIFY, CKA_SIGN,
          { CKA_PARAMETER_SET, &pset1, sizeof pset1 }, 2560 },
        { "ML-KEM-512", CKM_ML_KEM_KEY_PAIR_GEN, CKK_ML_KEM, 0, CKA_ENCAPSULATE, CKA_DECAPSULATE,
          { CKA_PARAMETER_SET, &pset1, sizeof pset1 }, 1632 },
        { "SLH-DSA-SHA2-128f", CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKM_SLH_DSA, CKA_VERIFY, CKA_SIGN,
          { CKA_PARAMETER_SET, &pset3, sizeof pset3 }, 64 },
    };
    cases[0].param.pValue = &bits;

    if (!open_user(1)) return 2;
    printf("Permissive mode\n");
    for (int i = 0; i < 7; i++) check_case(&cases[i]);

    /* (S) */
    CK_OBJECT_HANDLE pub, prv;
    CK_ULONG l;
    CK_RV rv;
    char what[128];
    ok(gen_pair(&cases[0], -1, -1, 0, &pub, &prv) == CKR_OK
       && get_bool(prv, CKA_SENSITIVE) == 1
       && get(prv, CKA_PRIVATE_EXPONENT, big, sizeof big, &l) == CKR_ATTRIBUTE_SENSITIVE,
       "(S) a private key not naming CKA_SENSITIVE is sensitive");
    ok(gen_pair(&cases[0], 0, 0, 0, &pub, &prv) == CKR_OK
       && get(prv, CKA_PRIVATE_EXPONENT, big, sizeof big, &l) == CKR_ATTRIBUTE_SENSITIVE,
       "(S) not sensitive but not extractable: components withheld");
    if (gen_pair(&cases[0], 0, 1, 0, &pub, &prv) == CKR_OK) {
        CK_ATTRIBUTE st = { CKA_SENSITIVE, &yes, 1 }, sf = { CKA_SENSITIVE, &no, 1 };
        ok(C_SetAttributeValue(s, prv, &st, 1) == CKR_OK
           && get(prv, CKA_PRIVATE_EXPONENT, big, sizeof big, &l) == CKR_ATTRIBUTE_SENSITIVE,
           "(S) made sensitive afterwards: components withheld");
        rv = C_SetAttributeValue(s, prv, &sf, 1);
        snprintf(what, sizeof what, "(S) and not made not sensitive again: READ_ONLY (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_READ_ONLY, what);
    } else ok(0, "(S) RSA pair for the one-way rule");
    {
        CK_MECHANISM m = { CKM_COMPOSITE_MLDSA65_ED25519, NULL, 0 };
        CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 } };
        CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 },
                              { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 } };
        rv = C_GenerateKeyPair(s, &m, pt, 2, vt, 4, &pub, &prv);
        snprintf(what, sizeof what, "(S) composite pair not sensitive: INCONSISTENT, or not offered (0x%lx)", rv);
        ok(rv == CKR_TEMPLATE_INCONSISTENT || rv == CKR_MECHANISM_INVALID, what);
    }

    /* A token key for (T): P-256, not sensitive, extractable. */
    rv = gen_pair(&cases[1], 0, 1, 1, &pub, &prv);
    snprintf(what, sizeof what, "token P-256 key, not sensitive, for strict mode (0x%lx)", rv);
    ok(rv == CKR_OK, what);
    C_Finalize(NULL);
    return 0;
}

static int strict(void) {
    if (!open_user(0)) return 2;
    printf("\nStrict mode (FHSM_MODE=strict)\n");
    CK_OBJECT_HANDLE pub, prv, h;
    CK_ULONG l, n = 0;
    CK_RV rv;
    char what[128];
    static CK_ULONG bits = 2048;
    key_case rsa = RSA_CASE;
    rsa.param.pValue = &bits;

    rv = gen_pair(&rsa, 0, 1, 0, &pub, &prv);
    snprintf(what, sizeof what, "(T) RSA pair, private not sensitive: INCONSISTENT (0x%lx)", rv);
    ok(rv == CKR_TEMPLATE_INCONSISTENT && prv == 0, what);
    rv = gen_pair(&EC_CASE, 0, 1, 0, &pub, &prv);
    snprintf(what, sizeof what, "(T) P-256 pair, private not sensitive: INCONSISTENT (0x%lx)", rv);
    ok(rv == CKR_TEMPLATE_INCONSISTENT && prv == 0, what);
    {
        CK_BYTE d[32];
        memset(d, 0x11, sizeof d);
        rv = import_value(&EC_CASE, d, sizeof d, &h);
        snprintf(what, sizeof what, "(T) P-256 import not sensitive: INCONSISTENT (0x%lx)", rv);
        ok(rv == CKR_TEMPLATE_INCONSISTENT, what);
    }
    ok(gen_pair(&rsa, -1, 1, 0, &pub, &prv) == CKR_OK
       && get(prv, CKA_PRIVATE_EXPONENT, big, sizeof big, &l) == CKR_ATTRIBUTE_SENSITIVE,
       "(T) a sensitive pair is made as before, its components withheld");

    CK_ULONG cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE ft[] = { { CKA_CLASS, &cls, sizeof cls },
                          { CKA_LABEL, (void *)TOKEN_KEY, strlen(TOKEN_KEY) } };
    h = 0;
    if (C_FindObjectsInit(s, ft, 2) == CKR_OK) {
        (void)C_FindObjects(s, &h, 1, &n);
        (void)C_FindObjectsFinal(s);
    }
    ok(n == 1 && get_bool(h, CKA_SENSITIVE) == 0,
       "(T) the token key made in permissive mode is found, not sensitive");
    rv = get(h, CKA_VALUE, big, sizeof big, &l);
    snprintf(what, sizeof what, "(T) its CKA_VALUE is withheld: SENSITIVE (0x%lx)", rv);
    ok(n == 1 && rv == CKR_ATTRIBUTE_SENSITIVE && l == (CK_ULONG)-1, what);
    C_Finalize(NULL);
    return 0;
}

int main(int argc, char **argv) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKeyPair);
    SYM(C_CreateObject); SYM(C_GetAttributeValue); SYM(C_SetAttributeValue);
    SYM(C_FindObjectsInit); SYM(C_FindObjects); SYM(C_FindObjectsFinal);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_GenerateKeyPair || !C_GetAttributeValue || !C_FindObjectsFinal || !C_Verify) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    if (argc > 1 && strcmp(argv[1], "strict") == 0) {
        int r = strict();
        return r ? r : (fails ? 1 : 0);
    }

    printf("A private key asked CKA_SENSITIVE=FALSE\n\n");
    int r = permissive();
    if (r) return r;

    /* Strict mode is read once per process, so it is this program again,
     * with FHSM_MODE=strict and the same token directory. */
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        setenv("FHSM_MODE", "strict", 1);
        char *const av[] = { argv[0], (char *)"strict", NULL };
        execv("/proc/self/exe", av);
        _exit(3);
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("  %-74s FAIL\n", "strict-mode run");
        fails++;
    }

    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
