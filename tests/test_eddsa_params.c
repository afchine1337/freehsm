/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_eddsa_params.c --- on an Ed25519 key, CK_EDDSA_PARAMS selects
 * Ed25519ctx / Ed25519ph, which this module does not implement.
 *
 * PKCS#11 v3.2 makes the presence of the parameter block the switch: none is
 * pure Ed25519, a block is Ed25519ctx (Ed25519ph with phFlag), whose signature
 * carries RFC 8032's dom2 prefix. The module refused a non-empty context and
 * phFlag, but took a block with phFlag clear and no context and signed pure
 * Ed25519 -- a signature from the other variant than the one asked for.
 * pkcs11-check 0.2.3, TestEdDSAParametrizedModes::test_edwards25519_ctx_*.
 *
 * What is asserted:
 *   (1) Ed25519, no parameters: C_SignInit / C_VerifyInit accept, and the
 *       signature verifies
 *   (2) Ed25519, empty CK_EDDSA_PARAMS: both Inits refuse with
 *       CKR_MECHANISM_PARAM_INVALID
 *   (3) Ed448, empty CK_EDDSA_PARAMS: accepted -- that is pure Ed448 -- and
 *       the signature verifies (skipped where Ed448 is not built)
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_BYTE phFlag; CK_ULONG ulContextDataLen; CK_BYTE *pContextData; } CK_EDDSA_PARAMS;

#define CKR_OK                        0UL
#define CKR_MECHANISM_PARAM_INVALID   0x71UL
#define CKF_RW                        6UL
#define CKA_TOKEN                     0x1UL
#define CKA_SIGN                      0x108UL
#define CKA_VERIFY                    0x10AUL
#define CKA_EC_PARAMS                 0x180UL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN   0x1055UL
#define CKM_EDDSA                     0x1057UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);

static int keypair(CK_SESSION_HANDLE s, const CK_BYTE *oid, CK_ULONG oid_len,
                   CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {
    CK_BYTE f = 0, t = 1;
    CK_ATTRIBUTE pt[] = {
        { CKA_TOKEN,     &f,          1 },
        { CKA_EC_PARAMS, (void*)oid,  oid_len },
        { CKA_VERIFY,    &t,          1 },
    };
    CK_ATTRIBUTE kt[] = {
        { CKA_TOKEN, &f, 1 },
        { CKA_SIGN,  &t, 1 },
    };
    CK_MECHANISM m = { CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL, 0 };
    return C_GenerateKeyPair(s, &m, pt, 3, kt, 2, pub, priv) == CKR_OK;
}

/* Sign and verify "abc" under mechanism m; 1 when both succeed. */
static int roundtrip(CK_SESSION_HANDLE s, CK_MECHANISM *m,
                     CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv) {
    CK_BYTE sig[256]; CK_ULONG sl = sizeof sig;
    if (C_SignInit(s, m, priv) != CKR_OK) return 0;
    if (C_Sign(s, (CK_BYTE*)"abc", 3, sig, &sl) != CKR_OK) return 0;
    if (C_VerifyInit(s, m, pub) != CKR_OK) return 0;
    return C_Verify(s, (CK_BYTE*)"abc", 3, sig, sl) == CKR_OK;
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
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKeyPair);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_GenerateKeyPair || !C_SignInit || !C_VerifyInit || !C_Logout) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("CKM_EDDSA: a parameter block on Ed25519 asks for Ed25519ctx/ph\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "eddsaparams")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    static const CK_BYTE OID_ED25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
    static const CK_BYTE OID_ED448[]   = { 0x06, 0x03, 0x2B, 0x65, 0x71 };
    CK_EDDSA_PARAMS empty = { 0, 0, NULL };
    CK_MECHANISM bare   = { CKM_EDDSA, NULL, 0 };
    CK_MECHANISM withp  = { CKM_EDDSA, &empty, sizeof empty };
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    char what[96];

    printf("Ed25519\n");
    if (!keypair(s, OID_ED25519, sizeof OID_ED25519, &pub, &priv)) {
        printf("  key generation unavailable in this build, skipped\n");
    } else {
        ok(roundtrip(s, &bare, pub, priv), "(1) no parameters: sign and verify");
        CK_RV rv = C_SignInit(s, &withp, priv);
        snprintf(what, sizeof what, "(2) empty CK_EDDSA_PARAMS: C_SignInit refused (rv=0x%lx)", rv);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, what);
        rv = C_VerifyInit(s, &withp, pub);
        snprintf(what, sizeof what, "(2) empty CK_EDDSA_PARAMS: C_VerifyInit refused (rv=0x%lx)", rv);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, what);
        /* The refusal left no operation behind: plain Ed25519 still works. */
        ok(roundtrip(s, &bare, pub, priv), "(1) no parameters after the refusals");
    }

    printf("Ed448\n");
    if (!keypair(s, OID_ED448, sizeof OID_ED448, &pub, &priv)) {
        printf("  key generation unavailable in this build, skipped\n");
    } else {
        ok(roundtrip(s, &withp, pub, priv), "(3) empty CK_EDDSA_PARAMS is pure Ed448: sign and verify");
    }

    C_Finalize(NULL);
    printf("\n%s (%d failure%s)\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
