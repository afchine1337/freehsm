/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_key_sizes.c --- the curves and RSA sizes generated are the ones
 * C_GetMechanismInfo states.
 *
 * 2.8.0 widened both:
 *   - EC curves from 192 bits in the all-mechanisms build in permissive mode
 *     (P-192, P-224 and their neighbours), 256 bits elsewhere as before;
 *   - RSA from the minimum (1024 or 2048) to 8192 bits in steps of 512,
 *     where 2048, 3072 and 4096 alone were taken.
 * The test reads the stated bounds and checks against them, so it means the
 * same in every build and mode:
 *   (E) CKM_EC_KEY_PAIR_GEN states a minimum of 192, 224 or 256 (224 where
 *       the provider builds P-224 and not P-192, as the FIPS provider does);
 *       P-192 and P-224 generate and sign when they reach the minimum, and
 *       are CKR_CURVE_NOT_SUPPORTED when they do not;
 *   (R) CKM_RSA_PKCS_KEY_PAIR_GEN states a maximum of 8192; a size between
 *       the old ones (2560) generates; 4608, above the old 4096, generates
 *       and signs (its 576-byte signature did not fit the old 512-byte
 *       bound); a size that is not a multiple of 512, one past the maximum
 *       and one under the minimum are CKR_KEY_SIZE_RANGE.
 * 8192 itself is not generated here: it takes long enough to slow the suite,
 * and 4608 already exercises the larger signature.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize; CK_FLAGS flags; } CK_MECHANISM_INFO;

#define CKR_OK                      0x000UL
#define CKR_KEY_SIZE_RANGE          0x062UL
#define CKR_CURVE_NOT_SUPPORTED     0x140UL
#define CKF_RW                      6UL
#define CKA_TOKEN                   0x001UL
#define CKA_SIGN                    0x108UL
#define CKA_VERIFY                  0x10AUL
#define CKA_MODULUS_BITS            0x121UL
#define CKA_EC_PARAMS               0x180UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN   0x0000UL
#define CKM_SHA256_RSA_PKCS_PSS     0x0043UL
#define CKM_SHA256                  0x0250UL
#define CKG_MGF1_SHA256             0x0002UL
#define CKM_EC_KEY_PAIR_GEN         0x1040UL
#define CKM_ECDSA                   0x1041UL

typedef struct { CK_ULONG hashAlg, mgf, sLen; } CK_RSA_PKCS_PSS_PARAMS;

/* Test PINs, for a token this program makes in a throwaway directory. */
#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_ULONG, CK_MECHANISM_INFO*);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
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
static CK_BYTE msg[] = { 'k','e','y',' ','s','i','z','e','s' };

/* An EC pair on the curve whose DER OID is `oid`. */
static CK_RV ec_pair(const CK_BYTE *oid, CK_ULONG oid_len, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv) {
    CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                          { CKA_EC_PARAMS, (void *)oid, oid_len } };
    CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    *pub = *prv = 0;
    return C_GenerateKeyPair(s, &m, pt, 3, vt, 2, pub, prv);
}

/* An RSA pair of `bits`. */
static CK_RV rsa_pair(CK_ULONG bits, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv) {
    CK_MECHANISM m = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                          { CKA_MODULUS_BITS, &bits, sizeof bits } };
    CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    *pub = *prv = 0;
    return C_GenerateKeyPair(s, &m, pt, 3, vt, 2, pub, prv);
}

/* Sign msg with `prv` and verify with `pub`; *sig_len is the length signed. */
static int sign_verify(CK_MECHANISM *m, CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE prv, CK_ULONG *sig_len) {
    CK_BYTE sig[1100];
    CK_ULONG sl = sizeof sig;
    *sig_len = 0;
    if (C_SignInit(s, m, prv) != CKR_OK || C_Sign(s, msg, sizeof msg, sig, &sl) != CKR_OK)
        return 0;
    *sig_len = sl;
    return C_VerifyInit(s, m, pub) == CKR_OK && C_Verify(s, msg, sizeof msg, sig, sl) == CKR_OK;
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismInfo);
    SYM(C_GenerateKeyPair); SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_GetMechanismInfo || !C_GenerateKeyPair || !C_Verify) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("Key sizes generated are the ones stated\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"keysizes",8);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_OBJECT_HANDLE pub, prv;
    CK_ULONG sl;
    CK_RV rv;
    char what[128];

    /* (E) */
    CK_MECHANISM_INFO ei = { 0, 0, 0 };
    if (C_GetMechanismInfo(0, CKM_EC_KEY_PAIR_GEN, &ei) != CKR_OK) { fprintf(stderr, "EC info\n"); return 2; }
    printf("(E) CKM_EC_KEY_PAIR_GEN states %lu to %lu bits\n", ei.ulMinKeySize, ei.ulMaxKeySize);
    ok(ei.ulMinKeySize == 192 || ei.ulMinKeySize == 224 || ei.ulMinKeySize == 256,
       "the minimum is 192, 224 or 256");
    {
        static const struct { const char *name; CK_BYTE oid[12]; CK_ULONG len, bits; } C[] = {
            { "P-192", { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x01 }, 10, 192 },
            { "P-224", { 0x06,0x05,0x2B,0x81,0x04,0x00,0x21 }, 7, 224 },
        };
        CK_MECHANISM ecdsa = { CKM_ECDSA, NULL, 0 };
        for (int i = 0; i < 2; i++) {
            rv = ec_pair(C[i].oid, C[i].len, &pub, &prv);
            if (C[i].bits >= ei.ulMinKeySize) {
                snprintf(what, sizeof what, "%s generates (0x%lx)", C[i].name, rv);
                ok(rv == CKR_OK && pub && prv, what);
                snprintf(what, sizeof what, "%s signs and verifies", C[i].name);
                ok(rv == CKR_OK && sign_verify(&ecdsa, pub, prv, &sl), what);
            } else {
                snprintf(what, sizeof what, "%s: CKR_CURVE_NOT_SUPPORTED (0x%lx)", C[i].name, rv);
                ok(rv == CKR_CURVE_NOT_SUPPORTED && pub == 0 && prv == 0, what);
            }
        }
    }

    /* (R) */
    CK_MECHANISM_INFO ri = { 0, 0, 0 };
    if (C_GetMechanismInfo(0, CKM_RSA_PKCS_KEY_PAIR_GEN, &ri) != CKR_OK) { fprintf(stderr, "RSA info\n"); return 2; }
    printf("\n(R) CKM_RSA_PKCS_KEY_PAIR_GEN states %lu to %lu bits\n", ri.ulMinKeySize, ri.ulMaxKeySize);
    ok(ri.ulMaxKeySize == 8192, "the maximum is 8192");
    ok(ri.ulMinKeySize == 1024 || ri.ulMinKeySize == 2048, "the minimum is 1024 or 2048");
    {
        CK_RSA_PKCS_PSS_PARAMS pp = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
        CK_MECHANISM pss = { CKM_SHA256_RSA_PKCS_PSS, &pp, sizeof pp };
        rv = rsa_pair(2560, &pub, &prv);
        snprintf(what, sizeof what, "2560 bits generates (0x%lx)", rv);
        ok(rv == CKR_OK && pub && prv, what);
        rv = rsa_pair(4608, &pub, &prv);
        snprintf(what, sizeof what, "4608 bits generates (0x%lx)", rv);
        ok(rv == CKR_OK && pub && prv, what);
        ok(rv == CKR_OK && sign_verify(&pss, pub, prv, &sl) && sl == 576,
           "and signs in 576 bytes, past the old 512-byte bound");
        ok(rsa_pair(2100, &pub, &prv) == CKR_KEY_SIZE_RANGE && pub == 0,
           "2100 bits, not a multiple of 512: CKR_KEY_SIZE_RANGE");
        ok(rsa_pair(8704, &pub, &prv) == CKR_KEY_SIZE_RANGE,
           "8704 bits, past the maximum: CKR_KEY_SIZE_RANGE");
        ok(rsa_pair(ri.ulMinKeySize - 512, &pub, &prv) == CKR_KEY_SIZE_RANGE,
           "512 bits under the minimum: CKR_KEY_SIZE_RANGE");
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
