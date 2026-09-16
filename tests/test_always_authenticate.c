/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_always_authenticate.c --- CKA_ALWAYS_AUTHENTICATE, PKCS#11 v3.2 5.6.
 *
 * The module stored the attribute and reported it through
 * C_GetAttributeValue, and gated nothing on it: C_Sign succeeded on a key
 * marked TRUE with no C_Login(CKU_CONTEXT_SPECIFIC) anywhere. An application
 * that set the attribute, then read it back to confirm, was told it had a
 * protection it did not have -- worse than not offering the attribute at all,
 * because a false reassurance is acted upon and a missing feature is not.
 *
 * C_Login(CKU_CONTEXT_SPECIFIC) meanwhile returned CKR_FUNCTION_NOT_SUPPORTED
 * whenever an operation was active, on the reasoning that accepting a
 * re-authentication would claim a control nothing enforced. That reasoning was
 * sound and the conclusion was half the size of the problem: it made the
 * module honest about the call it did not support and left it silent about the
 * control it was not applying.
 *
 * What is checked here is the whole loop, both directions: that the gate
 * refuses, that a correct PIN opens it, that a wrong PIN does not, that the
 * authorisation dies with the operation rather than with the call, and that a
 * key without the attribute is unaffected.
 *
 * The wrong-PIN case runs last on purpose: it increments the PIN failure
 * counter and arms the throttle, which would otherwise reach the cases after
 * it and make them fail for a reason that has nothing to do with what they
 * test.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                          0UL
#define CKR_PIN_INCORRECT               0xA0UL
#define CKR_OPERATION_NOT_INITIALIZED   0x91UL
#define CKR_USER_NOT_LOGGED_IN          0x101UL

#define CKF_RW                          6UL
#define CKU_SO                          0UL
#define CKU_USER                        1UL
#define CKU_CONTEXT_SPECIFIC            2UL

#define CKA_ALWAYS_AUTHENTICATE         0x202UL
#define CKA_MODULUS_BITS                0x121UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN       0UL
#define CKM_SHA256_RSA_PKCS             0x40UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"
#define BAD_PIN  "not-the-pin"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,
                                   CK_ATTRIBUTE*,CK_ULONG,CK_ATTRIBUTE*,CK_ULONG,
                                   CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);

/* One signature attempt on hKey, reporting only the return value. */
static CK_RV try_sign(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k) {
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL, 0 };
    CK_BYTE sig[1024]; CK_ULONG sl = sizeof sig;
    CK_RV rv = C_SignInit(s, &m, k);
    if (rv != CKR_OK) return rv;
    return C_Sign(s, (CK_BYTE*)"abc", 3, sig, &sl);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue);
    SYM(C_SignInit); SYM(C_Sign);
    if (!C_GenerateKeyPair || !C_SignInit || !C_Sign) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("CKA_ALWAYS_AUTHENTICATE enforcement (PKCS#11 v3.2 5.6)\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"alwaysauth",10);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,CKU_SO,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"C_Login SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,CKU_USER,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_Login USER\n"); return 2; }

    CK_ULONG mb = 2048;
    CK_BYTE b_true = 1;
    CK_ATTRIBUTE pub[]  = { { CKA_MODULUS_BITS, &mb, sizeof mb } };
    CK_ATTRIBUTE priv[] = { { CKA_ALWAYS_AUTHENTICATE, &b_true, 1 } };
    CK_MECHANISM gen = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };

    CK_OBJECT_HANDLE hpub = 0, hguarded = 0, hplain = 0, hp2 = 0;
    CK_RV g = C_GenerateKeyPair(s, &gen, pub, 1, priv, 1, &hpub, &hguarded);
    if (g != CKR_OK) { fprintf(stderr, "RSA keygen rv=0x%lx\n", (unsigned long)g); return 2; }
    /* A second pair with no such attribute : the control must be per key, not
     * a mode the module falls into once any guarded key exists. */
    if (C_GenerateKeyPair(s, &gen, pub, 1, NULL, 0, &hp2, &hplain) != CKR_OK) {
        fprintf(stderr, "second RSA keygen\n"); return 2;
    }

    /* (1) What the module says about the key. This part always worked, and is
     *     exactly what made the gap worth closing rather than documenting. */
    {
        CK_BYTE v = 0xFF;
        CK_ATTRIBUTE q[] = { { CKA_ALWAYS_AUTHENTICATE, &v, 1 } };
        ok(C_GetAttributeValue(s, hguarded, q, 1) == CKR_OK && v == 1,
           "guarded key reads back CKA_ALWAYS_AUTHENTICATE = TRUE");
        v = 0xFF;
        CK_ATTRIBUTE q2[] = { { CKA_ALWAYS_AUTHENTICATE, &v, 1 } };
        ok(C_GetAttributeValue(s, hplain, q2, 1) == CKR_OK && v == 0,
           "ordinary key reads back FALSE");
    }

    /* (2) The gap itself : this returned CKR_OK. */
    ok(try_sign(s, hguarded) == CKR_USER_NOT_LOGGED_IN,
       "C_Sign without re-authentication -> CKR_USER_NOT_LOGGED_IN");

    /* (3) And the error terminated the operation, per the general rule for
     *     C_Sign, so the re-authentication has nothing left to attach to. */
    ok(C_Login(s, CKU_CONTEXT_SPECIFIC, (CK_BYTE*)USER_PIN, strlen(USER_PIN))
         == CKR_OPERATION_NOT_INITIALIZED,
       "refused C_Sign terminated the operation");

    /* (4) The prescribed sequence : Init, re-authenticate, Sign. */
    {
        CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL, 0 };
        CK_BYTE sig[1024]; CK_ULONG sl = sizeof sig;
        ok(C_SignInit(s, &m, hguarded) == CKR_OK,
           "C_SignInit on a guarded key succeeds (the gate is not at Init)");
        ok(C_Login(s, CKU_CONTEXT_SPECIFIC, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) == CKR_OK,
           "C_Login(CKU_CONTEXT_SPECIFIC) with the correct PIN accepted");
        ok(C_Sign(s, (CK_BYTE*)"abc", 3, sig, &sl) == CKR_OK && sl == 256,
           "C_Sign then produces a 2048-bit signature");
    }

    /* (5) One re-authentication, one operation. The authorisation is scoped to
     *     the operation it was granted for and does not carry into the next --
     *     which is the whole content of "always" in the attribute's name. */
    ok(try_sign(s, hguarded) == CKR_USER_NOT_LOGGED_IN,
       "the next operation is unauthorised again");

    /* (6) No collateral : a key without the attribute signs as before. */
    ok(try_sign(s, hplain) == CKR_OK,
       "a key without the attribute signs with no re-authentication");

    /* (7) The call remains meaningless with nothing in progress. */
    ok(C_Login(s, CKU_CONTEXT_SPECIFIC, (CK_BYTE*)USER_PIN, strlen(USER_PIN))
         == CKR_OPERATION_NOT_INITIALIZED,
       "C_Login(CKU_CONTEXT_SPECIFIC) with no operation -> not initialized");

    /* (8) Last, because it arms the throttle : the re-authentication actually
     *     verifies the PIN. It is routed through fhsm_token_verify_pin rather
     *     than the login path, which short-circuits on
     *     CKR_USER_ALREADY_LOGGED_IN before reading the PIN at all -- and
     *     would therefore have accepted this one. */
    {
        CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL, 0 };
        CK_BYTE sig[1024]; CK_ULONG sl = sizeof sig;
        ok(C_SignInit(s, &m, hguarded) == CKR_OK, "C_SignInit for the wrong-PIN case");
        ok(C_Login(s, CKU_CONTEXT_SPECIFIC, (CK_BYTE*)BAD_PIN, strlen(BAD_PIN))
             == CKR_PIN_INCORRECT,
           "a wrong PIN is refused, not accepted because the user is logged in");
        ok(C_Sign(s, (CK_BYTE*)"abc", 3, sig, &sl) == CKR_USER_NOT_LOGGED_IN,
           "and the operation stays unauthorised after it");
    }

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
