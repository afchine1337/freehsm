/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_usage_defaults.c --- a key has the usages of its type, and derives
 * only when asked.
 *
 * The usages of a new private key came from its class: decrypt, sign, unwrap
 * and derive, whatever the type, unless the template named one FALSE. A
 * P-256 key asked for CKA_SIGN only reported CKA_DERIVE=TRUE and could be
 * used for ECDH; an X25519 key reported CKA_SIGN=TRUE. C_GenerateKeyPair
 * cleared CKA_DERIVE for some types, C_UnwrapKey cleared nothing (#34,
 * reported by Alexandre Laroche).
 *
 * The cases, each on the generated key and, where the profile wraps private
 * keys, on its unwrapped copy:
 *   (1) Ed25519 asked CKA_SIGN: signs, nothing else;
 *   (2) P-256 asked CKA_SIGN: signs, does not derive, and C_DeriveKey is
 *       CKR_KEY_FUNCTION_NOT_PERMITTED;
 *   (3) P-256 asked nothing: signs, does not derive (CKA_DERIVE defaults to
 *       CK_FALSE); asked CKA_DERIVE=TRUE: derives, and C_DeriveKey works;
 *   (4) X25519 asked CKA_DERIVE: derives, does not sign; asked nothing:
 *       neither;
 *   (5) RSA asked nothing: decrypts, signs, unwraps, does not derive; its
 *       public half encrypts, verifies and wraps;
 *   (6) a usage the type does not have, asked TRUE, is accepted and reads
 *       back FALSE (what pkcs11-tool sends without a --usage-* option);
 *   (7) a usage asked FALSE is FALSE;
 *   (8) a secret key is unchanged: six usages, and CKA_DERIVE when asked.
 * A key type the profile does not offer is skipped, and said so.
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
typedef struct { CK_ULONG kdf, ulSharedDataLen; CK_BYTE *pSharedData;
                 CK_ULONG ulPublicDataLen; CK_BYTE *pPublicData; } CK_ECDH1_DERIVE_PARAMS;

#define CKR_OK                          0x000UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED  0x068UL
#define CKR_MECHANISM_INVALID           0x070UL
#define CKF_RW                          6UL
#define CKU_SO                          0UL
#define CKU_USER                        1UL
#define CKO_PRIVATE_KEY                 3UL
#define CKO_SECRET_KEY                  4UL
#define CKK_RSA                         0x00UL
#define CKK_EC                          0x03UL
#define CKK_GENERIC_SECRET              0x10UL
#define CKK_AES                         0x1FUL
#define CKK_EC_EDWARDS                  0x40UL
#define CKK_EC_MONTGOMERY               0x41UL
#define CKA_CLASS                       0x000UL
#define CKA_TOKEN                       0x001UL
#define CKA_KEY_TYPE                    0x100UL
#define CKA_SENSITIVE                   0x103UL
#define CKA_ENCRYPT                     0x104UL
#define CKA_DECRYPT                     0x105UL
#define CKA_WRAP                        0x106UL
#define CKA_UNWRAP                      0x107UL
#define CKA_SIGN                        0x108UL
#define CKA_VERIFY                      0x10AUL
#define CKA_DERIVE                      0x10CUL
#define CKA_MODULUS_BITS                0x121UL
#define CKA_PUBLIC_EXPONENT             0x122UL
#define CKA_VALUE_LEN                   0x161UL
#define CKA_EXTRACTABLE                 0x162UL
#define CKA_EC_PARAMS                   0x180UL
#define CKA_EC_POINT                    0x181UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN       0x0000UL
#define CKM_EC_KEY_PAIR_GEN             0x1040UL
#define CKM_ECDH1_DERIVE                0x1050UL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN     0x1055UL
#define CKM_EC_MONTGOMERY_KEY_PAIR_GEN  0x1056UL
#define CKM_AES_KEY_GEN                 0x1080UL
#define CKM_AES_CBC_PAD                 0x1085UL
#define CKD_NULL                        1UL

/* Test PINs, for a token this program makes in a throwaway directory. */
#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
static CK_RV (*C_WrapKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE,
                          CK_BYTE*, CK_ULONG*);
static CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_BYTE*, CK_ULONG,
                            CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_OBJECT_HANDLE kek;
static CK_BYTE yes = 1, no = 0;
static CK_BYTE p256[]    = { 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 };
static CK_BYTE ed25519[] = { 0x06,0x03,0x2b,0x65,0x70 };
static CK_BYTE x25519[]  = { 0x06,0x03,0x2b,0x65,0x6e };

/* A usage attribute of an object: 0, 1, or 9 if it cannot be read. */
static int rd(CK_OBJECT_HANDLE h, CK_ULONG type) {
    CK_BYTE v = 9; CK_ATTRIBUTE a = { type, &v, 1 };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? v : 9;
}

/* The seven usages of an object as a string of 0 and 1, in the order
 * encrypt, decrypt, sign, verify, wrap, unwrap, derive. */
static const char *usages(CK_OBJECT_HANDLE h) {
    static char b[4][8]; static int i;
    static const CK_ULONG t[7] = { CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY,
                                   CKA_WRAP, CKA_UNWRAP, CKA_DERIVE };
    char *o = b[i++ & 3];
    for (int k = 0; k < 7; k++) o[k] = (char)('0' + rd(h, t[k]));
    o[7] = 0;
    return o;
}
static int is(CK_OBJECT_HANDLE h, const char *want) { return strcmp(usages(h), want) == 0; }

/* An EC, Edwards or Montgomery key pair. The private template is sensitive
 * and extractable, plus up to two usage attributes (0 for none). */
static CK_RV gen_ec(CK_ULONG mech, CK_BYTE *params, CK_ULONG plen,
                    CK_ULONG u1, CK_BYTE *v1, CK_ULONG u2, CK_BYTE *v2,
                    CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv) {
    CK_MECHANISM g = { mech, NULL, 0 };
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_EC_PARAMS, params, plen } };
    CK_ATTRIBUTE vt[5] = { { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &yes, 1 },
                           { CKA_EXTRACTABLE, &yes, 1 } };
    CK_ULONG n = 3;
    if (u1) { vt[n].type = u1; vt[n].pValue = v1; vt[n].ulValueLen = 1; n++; }
    if (u2) { vt[n].type = u2; vt[n].pValue = v2; vt[n].ulValueLen = 1; n++; }
    return C_GenerateKeyPair(s, &g, pt, 2, vt, n, pub, prv);
}

/* Wraps prv under the session AES key and unwraps it as a private key of
 * type kt, with up to two usage attributes. Returns 0 and prints why when
 * the profile does not do it. */
static int rewrap(CK_OBJECT_HANDLE prv, CK_ULONG kt, CK_ULONG u1, CK_BYTE *v1,
                  CK_ULONG u2, CK_BYTE *v2, CK_OBJECT_HANDLE *copy) {
    static CK_BYTE w[8192]; CK_ULONG wl = sizeof w;
    CK_BYTE iv[16] = { 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC_PAD, iv, sizeof iv };
    CK_ULONG cls = CKO_PRIVATE_KEY;
    CK_RV rv = C_WrapKey(s, &cbc, kek, prv, w, &wl);
    if (rv != CKR_OK) { printf("  (unwrapped copy skipped: C_WrapKey 0x%lx)\n", rv); return 0; }
    CK_ATTRIBUTE ut[7] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                           { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &yes, 1 },
                           { CKA_EXTRACTABLE, &yes, 1 } };
    CK_ULONG n = 5;
    if (u1) { ut[n].type = u1; ut[n].pValue = v1; ut[n].ulValueLen = 1; n++; }
    if (u2) { ut[n].type = u2; ut[n].pValue = v2; ut[n].ulValueLen = 1; n++; }
    rv = C_UnwrapKey(s, &cbc, kek, w, wl, ut, n, copy);
    if (rv != CKR_OK) { printf("  (unwrapped copy skipped: C_UnwrapKey 0x%lx)\n", rv); return 0; }
    return 1;
}

/* ECDH of prv with the public half pub of the same pair. */
static CK_RV ecdh(CK_OBJECT_HANDLE prv, CK_OBJECT_HANDLE pub) {
    CK_BYTE pt[80]; CK_ATTRIBUTE a = { CKA_EC_POINT, pt, sizeof pt };
    if (C_GetAttributeValue(s, pub, &a, 1) != CKR_OK || a.ulValueLen != 67) return 0xFFFFUL;
    CK_ECDH1_DERIVE_PARAMS p = { CKD_NULL, 0, NULL, 65, pt + 2 };   /* past the OCTET STRING header */
    CK_MECHANISM m = { CKM_ECDH1_DERIVE, &p, sizeof p };
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET, vl = 32;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 } };
    CK_OBJECT_HANDLE h;
    return C_DeriveKey(s, &m, prv, t, 4, &h);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetAttributeValue);
    SYM(C_GenerateKey); SYM(C_GenerateKeyPair); SYM(C_WrapKey); SYM(C_UnwrapKey); SYM(C_DeriveKey);
    if (!C_GenerateKeyPair || !C_UnwrapKey || !C_WrapKey || !C_DeriveKey || !C_GetAttributeValue) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("Key usages by type (encrypt decrypt sign verify wrap unwrap derive)\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"usages",6);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,CKU_SO,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,CKU_USER,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_ULONG csec = CKO_SECRET_KEY, kaes = CKK_AES, vl = 32;
    CK_MECHANISM ag = { CKM_AES_KEY_GEN, NULL, 0 };
    { CK_ATTRIBUTE t[] = { { CKA_CLASS, &csec, sizeof csec }, { CKA_KEY_TYPE, &kaes, sizeof kaes },
                           { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 },
                           { CKA_WRAP, &yes, 1 }, { CKA_UNWRAP, &yes, 1 } };
      if (C_GenerateKey(s, &ag, t, 6, &kek)) { fprintf(stderr,"wrapping key\n"); return 2; } }

    CK_OBJECT_HANDLE pub, prv, copy;
    CK_RV rv;

    /* (1) Ed25519 asked CKA_SIGN. */
    rv = gen_ec(CKM_EC_EDWARDS_KEY_PAIR_GEN, ed25519, sizeof ed25519, CKA_SIGN, &yes, 0, NULL, &pub, &prv);
    if (rv == CKR_MECHANISM_INVALID) printf("  (Ed25519 skipped: not in this profile)\n");
    else {
        ok(rv == CKR_OK && is(prv, "0010000"), "(1) Ed25519 asked CKA_SIGN: signs, nothing else");
        ok(is(pub, "0001000"), "(1) its public half verifies, nothing else");
        if (rewrap(prv, CKK_EC_EDWARDS, CKA_SIGN, &yes, 0, NULL, &copy))
            ok(is(copy, "0010000"), "(1) the unwrapped copy: the same");
        /* (6) CKA_DERIVE=TRUE on an Edwards key, as pkcs11-tool sends it. */
        rv = gen_ec(CKM_EC_EDWARDS_KEY_PAIR_GEN, ed25519, sizeof ed25519, CKA_SIGN, &yes,
                    CKA_DERIVE, &yes, &pub, &prv);
        ok(rv == CKR_OK && is(prv, "0010000"), "(6) Ed25519 asked CKA_DERIVE=TRUE: accepted, reads FALSE");
    }

    /* (2) P-256 asked CKA_SIGN. */
    rv = gen_ec(CKM_EC_KEY_PAIR_GEN, p256, sizeof p256, CKA_SIGN, &yes, 0, NULL, &pub, &prv);
    if (rv != CKR_OK) { fprintf(stderr, "P-256 key pair: 0x%lx\n", rv); return 2; }
    ok(is(prv, "0010000"), "(2) P-256 asked CKA_SIGN: signs, does not derive");
    ok(is(pub, "0001000"), "(2) its public half verifies, nothing else");
    ok(ecdh(prv, pub) == CKR_KEY_FUNCTION_NOT_PERMITTED,
       "(2) C_DeriveKey with it: CKR_KEY_FUNCTION_NOT_PERMITTED");
    if (rewrap(prv, CKK_EC, CKA_SIGN, &yes, 0, NULL, &copy)) {
        ok(is(copy, "0010000"), "(2) the unwrapped copy: the same");
        ok(ecdh(copy, pub) == CKR_KEY_FUNCTION_NOT_PERMITTED,
           "(2) C_DeriveKey with the copy: CKR_KEY_FUNCTION_NOT_PERMITTED");
    }
    /* (6) CKA_DECRYPT=TRUE on the unwrapped EC key, as pkcs11-tool sends it. */
    if (rewrap(prv, CKK_EC, CKA_DECRYPT, &yes, 0, NULL, &copy))
        ok(is(copy, "0010000"), "(6) P-256 unwrapped asking CKA_DECRYPT=TRUE: accepted, reads FALSE");

    /* (3) P-256 asked nothing, then asked CKA_DERIVE. */
    rv = gen_ec(CKM_EC_KEY_PAIR_GEN, p256, sizeof p256, 0, NULL, 0, NULL, &pub, &prv);
    ok(rv == CKR_OK && is(prv, "0010000"), "(3) P-256 asked nothing: signs, does not derive");
    rv = gen_ec(CKM_EC_KEY_PAIR_GEN, p256, sizeof p256, CKA_DERIVE, &yes, 0, NULL, &pub, &prv);
    ok(rv == CKR_OK && is(prv, "0010001"), "(3) P-256 asked CKA_DERIVE=TRUE: signs and derives");
    ok(ecdh(prv, pub) == CKR_OK, "(3) C_DeriveKey with it works");
    if (rewrap(prv, CKK_EC, CKA_DERIVE, &yes, 0, NULL, &copy)) {
        ok(is(copy, "0010001"), "(3) the unwrapped copy: the same");
        ok(ecdh(copy, pub) == CKR_OK, "(3) C_DeriveKey with the copy works");
    }
    /* (7) A usage asked FALSE. */
    rv = gen_ec(CKM_EC_KEY_PAIR_GEN, p256, sizeof p256, CKA_SIGN, &no, CKA_DERIVE, &yes, &pub, &prv);
    ok(rv == CKR_OK && is(prv, "0000001"), "(7) P-256 asked CKA_SIGN=FALSE, CKA_DERIVE=TRUE: derives only");

    /* (4) X25519. */
    rv = gen_ec(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, x25519, sizeof x25519, CKA_DERIVE, &yes, 0, NULL, &pub, &prv);
    if (rv == CKR_MECHANISM_INVALID) printf("  (X25519 skipped: not in this profile)\n");
    else {
        ok(rv == CKR_OK && is(prv, "0000001"), "(4) X25519 asked CKA_DERIVE: derives, does not sign");
        if (rewrap(prv, CKK_EC_MONTGOMERY, CKA_DERIVE, &yes, 0, NULL, &copy))
            ok(is(copy, "0000001"), "(4) the unwrapped copy: the same");
        rv = gen_ec(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, x25519, sizeof x25519, 0, NULL, 0, NULL, &pub, &prv);
        ok(rv == CKR_OK && is(prv, "0000000"), "(4) X25519 asked nothing: no usage");
        /* (6) CKA_SIGN=TRUE on a Montgomery key, as pkcs11-tool sends it. */
        rv = gen_ec(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, x25519, sizeof x25519, CKA_SIGN, &yes,
                    CKA_DERIVE, &yes, &pub, &prv);
        ok(rv == CKR_OK && is(prv, "0000001"), "(6) X25519 asked CKA_SIGN=TRUE: accepted, reads FALSE");
    }

    /* (5) RSA asked nothing. */
    { CK_MECHANISM g = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
      CK_ULONG bits = 2048; CK_BYTE e[] = { 1, 0, 1 };
      CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_MODULUS_BITS, &bits, sizeof bits },
                            { CKA_PUBLIC_EXPONENT, e, sizeof e } };
      CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &yes, 1 }, { CKA_DERIVE, &yes, 1 } };
      rv = C_GenerateKeyPair(s, &g, pt, 3, vt, 2, &pub, &prv);
      ok(rv == CKR_OK && is(prv, "0110010"), "(5) RSA asked nothing: decrypts, signs, unwraps, does not derive");
      ok(is(pub, "1001100"), "(5) its public half encrypts, verifies and wraps");
      rv = C_GenerateKeyPair(s, &g, pt, 3, vt, 3, &pub, &prv);
      ok(rv == CKR_OK && is(prv, "0110010"), "(6) RSA asked CKA_DERIVE=TRUE: accepted, reads FALSE"); }

    /* (8) Secret keys are unchanged. */
    { CK_OBJECT_HANDLE h;
      CK_ATTRIBUTE t[] = { { CKA_CLASS, &csec, sizeof csec }, { CKA_KEY_TYPE, &kaes, sizeof kaes },
                           { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 },
                           { CKA_DERIVE, &yes, 1 } };
      rv = C_GenerateKey(s, &ag, t, 4, &h);
      ok(rv == CKR_OK && is(h, "1111110"), "(8) AES asked nothing: six usages, does not derive");
      rv = C_GenerateKey(s, &ag, t, 5, &h);
      ok(rv == CKR_OK && is(h, "1111111"), "(8) AES asked CKA_DERIVE=TRUE: derives too"); }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
