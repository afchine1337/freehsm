/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_rsa_pss_raw.c --- bare CKM_RSA_PKCS_PSS signs the digest hashAlg names.
 *
 * Bare CKM_RSA_PKCS_PSS takes a digest the caller computed, and
 * CK_RSA_PKCS_PSS_PARAMS.hashAlg says which. The module dropped hashAlg and
 * left OpenSSL its default, SHA-1: a 20-byte digest signed, a SHA-256 one
 * failed with CKR_FUNCTION_FAILED. OpenSC's test-pkcs11-tool-sign-verify.sh,
 * RSA-PKCS-PSS with --hash-algorithm=SHA256, found it.
 *
 * What is asserted, on an RSA-2048 key:
 *   (1) bare PSS signs SHA-256(M) with hashAlg = CKM_SHA256
 *   (2) the signature verifies under bare PSS, and under
 *       CKM_SHA256_RSA_PKCS_PSS over M -- the module hashing M itself; the
 *       two paths agree, so the digest was taken as SHA-256
 *   (3) a changed digest does not verify
 *   (4) SHA-1, 20 bytes, still signs and verifies
 *   (5) a hashAlg that is not a digest is refused at C_SignInit with
 *       CKR_MECHANISM_PARAM_INVALID
 *   (6) CKM_SHA224_RSA_PKCS_PSS signs, and the signature verifies under
 *       bare PSS over SHA-224(M); (7) the same for CKM_SHA1_RSA_PKCS_PSS
 *       where the build has it. Neither existed: OpenSC's sign-and-verify
 *       test got CKR_MECHANISM_INVALID for both
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG hashAlg, mgf, sLen; } CK_RSA_PKCS_PSS_PARAMS;

#define CKR_OK                       0UL
#define CKR_MECHANISM_PARAM_INVALID  0x71UL
#define CKR_SIGNATURE_INVALID        0xC0UL
#define CKF_RW                       6UL
#define CKA_TOKEN                    0x001UL
#define CKA_SIGN                     0x108UL
#define CKA_VERIFY                   0x10AUL
#define CKA_MODULUS_BITS             0x121UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN    0x000UL
#define CKM_RSA_PKCS_PSS             0x00DUL
#define CKM_SHA256_RSA_PKCS_PSS      0x043UL
#define CKM_SHA224_RSA_PKCS_PSS      0x047UL
#define CKM_SHA1_RSA_PKCS_PSS        0x00EUL
#define CKM_SHA_1                    0x220UL
#define CKM_SHA224                   0x255UL
#define CKM_SHA256                   0x250UL
#define CKG_MGF1_SHA1                0x1UL
#define CKG_MGF1_SHA256              0x2UL
#define CKG_MGF1_SHA224              0x5UL

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

static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_DigestInit)(CK_SESSION_HANDLE,CK_MECHANISM*);
static CK_RV (*C_Digest)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);

static CK_RV sign(CK_SESSION_HANDLE s, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                  CK_BYTE *in, CK_ULONG il, CK_BYTE *sig, CK_ULONG *sl) {
    CK_RV rv = C_SignInit(s, m, k);
    return rv == CKR_OK ? C_Sign(s, in, il, sig, sl) : rv;
}
static CK_RV verify(CK_SESSION_HANDLE s, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                    CK_BYTE *in, CK_ULONG il, CK_BYTE *sig, CK_ULONG sl) {
    CK_RV rv = C_VerifyInit(s, m, k);
    return rv == CKR_OK ? C_Verify(s, in, il, sig, sl) : rv;
}
static CK_RV digest(CK_SESSION_HANDLE s, CK_ULONG mech, CK_BYTE *in, CK_ULONG il,
                    CK_BYTE *out, CK_ULONG *ol) {
    CK_MECHANISM m = { mech, NULL, 0 };
    CK_RV rv = C_DigestInit(s, &m);
    return rv == CKR_OK ? C_Digest(s, in, il, out, ol) : rv;
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
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                               CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKeyPair);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    SYM(C_DigestInit); SYM(C_Digest);

    printf("Bare CKM_RSA_PKCS_PSS and hashAlg\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "pss")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    C_OpenSession(0, CKF_RW, NULL, NULL, &s);
    C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN));
    C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN));
    C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) {
        fprintf(stderr, "C_Login\n"); return 2;
    }

    CK_BYTE no = 0, yes = 1; CK_ULONG bits = 2048;
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                          { CKA_MODULUS_BITS, &bits, sizeof bits } };
    CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    CK_MECHANISM gen = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    if (C_GenerateKeyPair(s, &gen, pt, 3, kt, 2, &pub, &priv) != CKR_OK) {
        fprintf(stderr, "RSA key generation\n"); return 2;
    }

    CK_BYTE msg[] = "bare PSS signs the digest hashAlg names";
    CK_ULONG ml = sizeof msg - 1;
    CK_BYTE d256[32], d1[20], sig[256];
    CK_ULONG dl = sizeof d256, sl = sizeof sig;
    if (digest(s, CKM_SHA256, msg, ml, d256, &dl) != CKR_OK || dl != 32) {
        fprintf(stderr, "SHA-256 digest\n"); return 2;
    }

    CK_RSA_PKCS_PSS_PARAMS p256 = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
    CK_MECHANISM bare256 = { CKM_RSA_PKCS_PSS, &p256, sizeof p256 };
    CK_MECHANISM hashed256 = { CKM_SHA256_RSA_PKCS_PSS, &p256, sizeof p256 };
    CK_RV rv = sign(s, &bare256, priv, d256, 32, sig, &sl);
    char what[96];
    snprintf(what, sizeof what, "(1) SHA-256 digest signs (rv 0x%lx)", rv);
    ok(rv == CKR_OK && sl == 256, what);
    ok(verify(s, &bare256, pub, d256, 32, sig, sl) == CKR_OK,
       "(2) verifies under bare PSS");
    ok(verify(s, &hashed256, pub, msg, ml, sig, sl) == CKR_OK,
       "(2) verifies under CKM_SHA256_RSA_PKCS_PSS over the message");
    d256[0] ^= 0x01;
    ok(verify(s, &bare256, pub, d256, 32, sig, sl) == CKR_SIGNATURE_INVALID,
       "(3) a changed digest does not verify");

    CK_ULONG dl1 = sizeof d1; sl = sizeof sig;
    CK_RSA_PKCS_PSS_PARAMS p1 = { CKM_SHA_1, CKG_MGF1_SHA1, 20 };
    CK_MECHANISM bare1 = { CKM_RSA_PKCS_PSS, &p1, sizeof p1 };
    /* SHA-1 is refused where the build or the mode does not run it. */
    if (digest(s, CKM_SHA_1, msg, ml, d1, &dl1) != CKR_OK)
        printf("  (4) SHA-1 not available in this build or mode, skipped\n");
    else
        ok(sign(s, &bare1, priv, d1, 20, sig, &sl) == CKR_OK
           && verify(s, &bare1, pub, d1, 20, sig, sl) == CKR_OK,
           "(4) SHA-1 digest signs and verifies");

    /* (6) CKM_SHA224_RSA_PKCS_PSS, and (7) CKM_SHA1_RSA_PKCS_PSS where the
     * build has SHA-1: signed over M by the module, verified under bare PSS
     * over the caller's digest -- the same cross-check as (2). */
    {
        CK_BYTE d224[28]; CK_ULONG l224 = sizeof d224; sl = sizeof sig;
        CK_RSA_PKCS_PSS_PARAMS p224 = { CKM_SHA224, CKG_MGF1_SHA224, 28 };
        CK_MECHANISM h224 = { CKM_SHA224_RSA_PKCS_PSS, &p224, sizeof p224 };
        CK_MECHANISM b224 = { CKM_RSA_PKCS_PSS, &p224, sizeof p224 };
        rv = sign(s, &h224, priv, msg, ml, sig, &sl);
        snprintf(what, sizeof what, "(6) CKM_SHA224_RSA_PKCS_PSS signs (rv 0x%lx)", rv);
        ok(rv == CKR_OK, what);
        ok(rv == CKR_OK && digest(s, CKM_SHA224, msg, ml, d224, &l224) == CKR_OK
           && verify(s, &b224, pub, d224, 28, sig, sl) == CKR_OK,
           "(6) and verifies under bare PSS over SHA-224(M)");
    }
    {
        CK_ULONG l1 = sizeof d1; sl = sizeof sig;
        CK_MECHANISM h1 = { CKM_SHA1_RSA_PKCS_PSS, &p1, sizeof p1 };
        rv = sign(s, &h1, priv, msg, ml, sig, &sl);
        if (rv == 0x70UL /* CKR_MECHANISM_INVALID */)
            printf("  (7) CKM_SHA1_RSA_PKCS_PSS not in this build, skipped\n");
        else {
            snprintf(what, sizeof what, "(7) CKM_SHA1_RSA_PKCS_PSS signs (rv 0x%lx)", rv);
            ok(rv == CKR_OK, what);
            ok(rv == CKR_OK && digest(s, CKM_SHA_1, msg, ml, d1, &l1) == CKR_OK
               && verify(s, &bare1, pub, d1, 20, sig, sl) == CKR_OK,
               "(7) and verifies under bare PSS over SHA-1(M)");
        }
    }

    CK_RSA_PKCS_PSS_PARAMS pbad = { 0x12345UL, CKG_MGF1_SHA256, 32 };
    CK_MECHANISM barebad = { CKM_RSA_PKCS_PSS, &pbad, sizeof pbad };
    rv = C_SignInit(s, &barebad, priv);
    snprintf(what, sizeof what, "(5) unknown hashAlg refused at C_SignInit (rv 0x%lx)", rv);
    ok(rv == CKR_MECHANISM_PARAM_INVALID, what);

    C_Finalize(NULL);
    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
