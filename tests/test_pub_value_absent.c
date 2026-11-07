/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_pub_value_absent.c --- an RSA, EC, Edwards or Montgomery public key
 * has no CKA_VALUE.
 *
 * PKCS#11 v3.2 gives those public keys CKA_MODULUS and CKA_PUBLIC_EXPONENT,
 * or CKA_EC_PARAMS and CKA_EC_POINT, and no CKA_VALUE. C_GetAttributeValue
 * returned the SubjectPublicKeyInfo the module stores, a form of its own that
 * a caller could take for a standard one. It now answers
 * CKR_ATTRIBUTE_TYPE_INVALID with the length set to CK_UNAVAILABLE_INFORMATION,
 * and the standard attributes still read. Found by pkcs11-check 0.3.0.
 *
 * The cases, one per key type (a type the profile does not generate is
 * reported skipped):
 *   - CKA_VALUE alone: CKR_ATTRIBUTE_TYPE_INVALID, length -1;
 *   - CKA_VALUE with the key's standard attribute: the same return code, and
 *     the standard attribute's length is still filled in;
 *   - control: an ML-DSA-65 public key's CKA_VALUE still reads, raw, 1952
 *     bytes, as v3.2 defines it.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                         0UL
#define CKR_ATTRIBUTE_TYPE_INVALID     0x12UL
#define CKR_MECHANISM_INVALID          0x70UL
#define CKF_RW                         6UL
#define CK_UNAVAILABLE                 ((CK_ULONG)-1)
#define CKA_TOKEN                      0x1UL
#define CKA_VALUE                      0x11UL
#define CKA_DERIVE                     0x10CUL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_MODULUS                    0x120UL
#define CKA_MODULUS_BITS               0x121UL
#define CKA_PUBLIC_EXPONENT            0x122UL
#define CKA_EC_PARAMS                  0x180UL
#define CKA_EC_POINT                   0x181UL
#define CKA_PARAMETER_SET              0x61DUL
#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x0UL
#define CKM_ML_DSA_KEY_PAIR_GEN        0x1CUL
#define CKM_EC_KEY_PAIR_GEN            0x1040UL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN    0x1055UL
#define CKM_EC_MONTGOMERY_KEY_PAIR_GEN 0x1056UL
#define CKP_ML_DSA_65                  2UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);

static CK_BYTE g_yes = 1, g_no = 0;

/* One classical key type: generates the pair, then asks the public half. */
static void classical(CK_SESSION_HANDLE s, const char *name, CK_ULONG mech,
                      CK_ATTRIBUTE *pub_t, CK_ULONG np, CK_ULONG priv_use,
                      CK_ULONG std_attr)
{
    CK_MECHANISM m = { mech, NULL, 0 };
    CK_ATTRIBUTE priv_t[] = { { CKA_TOKEN, &g_no, 1 }, { priv_use, &g_yes, 1 } };
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    char what[96];
    CK_RV rv = C_GenerateKeyPair(s, &m, pub_t, np, priv_t, 2, &pub, &priv);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("  %-66s skipped\n", name);
        return;
    }
    snprintf(what, sizeof what, "%s: the key pair is generated", name);
    ok(rv == CKR_OK, what);
    if (rv != CKR_OK) return;

    CK_ATTRIBUTE a = { CKA_VALUE, NULL, 0 };
    rv = C_GetAttributeValue(s, pub, &a, 1);
    snprintf(what, sizeof what, "    CKA_VALUE: CKR_ATTRIBUTE_TYPE_INVALID, length -1");
    ok(rv == CKR_ATTRIBUTE_TYPE_INVALID && a.ulValueLen == CK_UNAVAILABLE, what);

    CK_ATTRIBUTE two[] = { { CKA_VALUE, NULL, 0 }, { std_attr, NULL, 0 } };
    rv = C_GetAttributeValue(s, pub, two, 2);
    ok(rv == CKR_ATTRIBUTE_TYPE_INVALID && two[0].ulValueLen == CK_UNAVAILABLE
       && two[1].ulValueLen != CK_UNAVAILABLE && two[1].ulValueLen > 0,
       "    with the standard attribute: that one's length is still given");

    CK_ATTRIBUTE one = { std_attr, NULL, 0 };
    ok(C_GetAttributeValue(s, pub, &one, 1) == CKR_OK
       && one.ulValueLen != CK_UNAVAILABLE && one.ulValueLen > 0,
       "    the standard attribute alone reads CKR_OK");
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKeyPair);
    SYM(C_GetAttributeValue);
    if (!C_GenerateKeyPair || !C_GetAttributeValue || !C_Logout) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("CKA_VALUE on classical public keys\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"pubvalue",8);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    {
        CK_ULONG bits = 2048;
        CK_BYTE e[] = { 1, 0, 1 };
        CK_ATTRIBUTE t[] = { { CKA_TOKEN, &g_no, 1 }, { CKA_VERIFY, &g_yes, 1 },
                             { CKA_MODULUS_BITS, &bits, sizeof bits },
                             { CKA_PUBLIC_EXPONENT, e, sizeof e } };
        classical(s, "RSA-2048", CKM_RSA_PKCS_KEY_PAIR_GEN, t, 4, CKA_SIGN, CKA_MODULUS);
    }
    {
        static CK_BYTE p256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
        CK_ATTRIBUTE t[] = { { CKA_TOKEN, &g_no, 1 }, { CKA_VERIFY, &g_yes, 1 },
                             { CKA_EC_PARAMS, p256, sizeof p256 } };
        classical(s, "EC P-256", CKM_EC_KEY_PAIR_GEN, t, 3, CKA_SIGN, CKA_EC_POINT);
    }
    {
        static CK_BYTE ed[] = { 0x06,0x03,0x2B,0x65,0x70 };
        CK_ATTRIBUTE t[] = { { CKA_TOKEN, &g_no, 1 }, { CKA_VERIFY, &g_yes, 1 },
                             { CKA_EC_PARAMS, ed, sizeof ed } };
        classical(s, "Ed25519", CKM_EC_EDWARDS_KEY_PAIR_GEN, t, 3, CKA_SIGN, CKA_EC_POINT);
    }
    {
        static CK_BYTE x[] = { 0x06,0x03,0x2B,0x65,0x6E };
        CK_ATTRIBUTE t[] = { { CKA_TOKEN, &g_no, 1 }, { CKA_DERIVE, &g_yes, 1 },
                             { CKA_EC_PARAMS, x, sizeof x } };
        classical(s, "X25519", CKM_EC_MONTGOMERY_KEY_PAIR_GEN, t, 3, CKA_DERIVE, CKA_EC_POINT);
    }

    /* The control: a PQC public key's CKA_VALUE is defined, and raw. */
    {
        CK_ULONG ps = CKP_ML_DSA_65;
        CK_MECHANISM m = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
        CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &g_no, 1 }, { CKA_VERIFY, &g_yes, 1 },
                              { CKA_PARAMETER_SET, &ps, sizeof ps } };
        CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &g_no, 1 }, { CKA_SIGN, &g_yes, 1 } };
        CK_OBJECT_HANDLE pub = 0, priv = 0;
        CK_RV rv = C_GenerateKeyPair(s, &m, pt, 3, kt, 2, &pub, &priv);
        CK_ATTRIBUTE a = { CKA_VALUE, NULL, 0 };
        ok(rv == CKR_OK && C_GetAttributeValue(s, pub, &a, 1) == CKR_OK
           && a.ulValueLen == 1952,
           "control: ML-DSA-65 public CKA_VALUE reads, raw, 1952 bytes");
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
