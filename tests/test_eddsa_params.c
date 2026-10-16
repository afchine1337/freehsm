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
 *
 * And the two EdDSA key profiles, which CKA_EC_PARAMS tells apart: the
 * RFC 8410 OID (id-Ed25519, id-Ed448) or the RFC 8032 curveName
 * PrintableString ("edwards25519", "edwards448"). On an RFC 8032 edwards448
 * key the parameter block is required; the module accepted NULL there.
 * pkcs11-check 0.2.3,
 * TestEdDSAParameters::test_eddsa_edwards448_{sign,verify}_missing_required_param.
 *   (4) id-Ed448 key, no parameters: sign and verify, as before
 *   (5) edwards448 key, no parameters: both Inits refuse with
 *       CKR_MECHANISM_PARAM_INVALID; with the empty block, sign and verify
 *   (6) CKA_EC_PARAMS reads back in the form it was given, on both halves
 *   (7) edwards25519 key, no parameters: pure Ed25519, sign and verify
 *   (8) a token edwards448 key keeps (5) and (6) across C_Finalize /
 *       C_Initialize -- the profile is in the store, not only in memory
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

static int roundtrip(CK_SESSION_HANDLE s, CK_MECHANISM *m,
                     CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);

static int keypair_tok(CK_SESSION_HANDLE s, const CK_BYTE *oid, CK_ULONG oid_len,
                       CK_BYTE token,
                       CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {
    CK_BYTE t = 1;
    CK_ATTRIBUTE pt[] = {
        { CKA_TOKEN,     &token,      1 },
        { CKA_EC_PARAMS, (void*)oid,  oid_len },
        { CKA_VERIFY,    &t,          1 },
    };
    CK_ATTRIBUTE kt[] = {
        { CKA_TOKEN, &token, 1 },
        { CKA_SIGN,  &t, 1 },
    };
    CK_MECHANISM m = { CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL, 0 };
    return C_GenerateKeyPair(s, &m, pt, 3, kt, 2, pub, priv) == CKR_OK;
}

static int keypair(CK_SESSION_HANDLE s, const CK_BYTE *oid, CK_ULONG oid_len,
                   CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {
    return keypair_tok(s, oid, oid_len, 0, pub, priv);
}

/* 1 when the object's CKA_EC_PARAMS is exactly `want`. */
static int ec_params_is(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o,
                        const CK_BYTE *want, CK_ULONG want_len) {
    CK_BYTE buf[64];
    CK_ATTRIBUTE a = { CKA_EC_PARAMS, buf, sizeof buf };
    if (C_GetAttributeValue(s, o, &a, 1) != CKR_OK) return 0;
    return a.ulValueLen == want_len && memcmp(buf, want, want_len) == 0;
}

/* (5): NULL refused on both Inits, the empty block accepted. */
static void curve_name_448(CK_SESSION_HANDLE s, CK_MECHANISM *bare, CK_MECHANISM *withp,
                           CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv,
                           const char *tag) {
    char what[112];
    CK_RV rv = C_SignInit(s, bare, priv);
    snprintf(what, sizeof what, "%s no parameters: C_SignInit refused (rv=0x%lx)", tag, rv);
    ok(rv == CKR_MECHANISM_PARAM_INVALID, what);
    rv = C_VerifyInit(s, bare, pub);
    snprintf(what, sizeof what, "%s no parameters: C_VerifyInit refused (rv=0x%lx)", tag, rv);
    ok(rv == CKR_MECHANISM_PARAM_INVALID, what);
    snprintf(what, sizeof what, "%s empty CK_EDDSA_PARAMS: sign and verify", tag);
    ok(roundtrip(s, withp, pub, priv), what);
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
    SYM(C_GetAttributeValue);
    if (!C_GenerateKeyPair || !C_SignInit || !C_VerifyInit || !C_Logout
        || !C_GetAttributeValue) {
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
        ok(roundtrip(s, &bare, pub, priv), "(4) id-Ed448, no parameters: sign and verify");
        ok(ec_params_is(s, pub, OID_ED448, sizeof OID_ED448), "(6) id-Ed448: CKA_EC_PARAMS is the OID");
    }

    /* PrintableString, tag 0x13. */
    static const CK_BYTE NAME_ED448[]   = { 0x13, 0x0A, 'e','d','w','a','r','d','s','4','4','8' };
    static const CK_BYTE NAME_ED25519[] = { 0x13, 0x0C, 'e','d','w','a','r','d','s','2','5','5','1','9' };

    printf("edwards448 (RFC 8032 curveName)\n");
    if (!keypair(s, NAME_ED448, sizeof NAME_ED448, &pub, &priv)) {
        printf("  key generation unavailable in this build, skipped\n");
    } else {
        curve_name_448(s, &bare, &withp, pub, priv, "(5)");
        ok(ec_params_is(s, pub,  NAME_ED448, sizeof NAME_ED448), "(6) public: CKA_EC_PARAMS is the curveName");
        ok(ec_params_is(s, priv, NAME_ED448, sizeof NAME_ED448), "(6) private: CKA_EC_PARAMS is the curveName");
    }

    printf("edwards25519 (RFC 8032 curveName)\n");
    if (!keypair(s, NAME_ED25519, sizeof NAME_ED25519, &pub, &priv)) {
        printf("  key generation unavailable in this build, skipped\n");
    } else {
        ok(roundtrip(s, &bare, pub, priv), "(7) no parameters: pure Ed25519, sign and verify");
        ok(ec_params_is(s, pub, NAME_ED25519, sizeof NAME_ED25519), "(6) CKA_EC_PARAMS is the curveName");
    }

    printf("edwards448, token object, after C_Finalize / C_Initialize\n");
    if (!keypair_tok(s, NAME_ED448, sizeof NAME_ED448, 1, &pub, &priv)) {
        printf("  key generation unavailable in this build, skipped\n");
    } else {
        C_Finalize(NULL);
        s = 0;
        if (C_Initialize(NULL) != CKR_OK
            || C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK
            || C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) {
            fprintf(stderr, "re-open after C_Finalize\n"); return 2;
        }
        curve_name_448(s, &bare, &withp, pub, priv, "(8)");
        ok(ec_params_is(s, pub, NAME_ED448, sizeof NAME_ED448), "(8) CKA_EC_PARAMS is still the curveName");
    }

    C_Finalize(NULL);
    printf("\n%s (%d failure%s)\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
