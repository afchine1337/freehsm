/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_sig_sha3_family.c --- ECDSA with SHA-1, SHA-224 and SHA-3, and
 * RSASSA-PSS with SHA-3 (2.8.0).
 *
 *   (E) each CKM_ECDSA_SHA224 / CKM_ECDSA_SHA3_* signature, single-part and
 *       multipart, is a raw r||s of 64 bytes on P-256 that verifies under the
 *       same mechanism, and under bare CKM_ECDSA over the digest C_Digest
 *       computes: so the mechanism hashes with the digest it names and no
 *       other. A changed message is CKR_SIGNATURE_INVALID; an RSA key is
 *       CKR_KEY_TYPE_INCONSISTENT.
 *   (P) each CKM_SHA3_*_RSA_PKCS_PSS signature, single-part and multipart,
 *       verifies under the same mechanism and under bare CKM_RSA_PKCS_PSS
 *       with hashAlg the SHA-3 digest, over C_Digest's digest. A hashAlg
 *       naming another digest is CKR_MECHANISM_PARAM_INVALID, a missing
 *       parameter too.
 *   (S) CKM_ECDSA_SHA1 signs and verifies in the all-mechanisms build, as
 *       (E); the nist-approved-only build does not list it and C_SignInit
 *       refuses it with CKR_MECHANISM_INVALID.
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
typedef struct { CK_ULONG hashAlg, mgf, sLen; } CK_RSA_PKCS_PSS_PARAMS;

#define CKR_OK                       0x000UL
#define CKR_KEY_TYPE_INCONSISTENT    0x063UL
#define CKR_MECHANISM_INVALID        0x070UL
#define CKR_MECHANISM_PARAM_INVALID  0x071UL
#define CKR_SIGNATURE_INVALID        0x0C0UL
#define CKF_RW                       6UL
#define CKA_TOKEN                    0x001UL
#define CKA_SIGN                     0x108UL
#define CKA_VERIFY                   0x10AUL
#define CKA_MODULUS_BITS             0x121UL
#define CKA_EC_PARAMS                0x180UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN    0x000UL
#define CKM_RSA_PKCS                 0x001UL
#define CKM_RSA_PKCS_PSS             0x00DUL
#define CKM_SHA256                   0x250UL
#define CKM_EC_KEY_PAIR_GEN          0x1040UL
#define CKM_ECDSA                    0x1041UL
#define CKM_ECDSA_SHA1               0x1042UL

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
static CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM*);
static CK_RV (*C_Digest)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE msg[] = "the mechanism hashes with the digest it names";
#define MSGLEN ((CK_ULONG)(sizeof msg - 1))

static CK_RV sign1(CK_MECHANISM *m, CK_OBJECT_HANDLE k, CK_BYTE *in, CK_ULONG il,
                   CK_BYTE *sig, CK_ULONG *sl) {
    CK_RV rv = C_SignInit(s, m, k);
    return rv != CKR_OK ? rv : C_Sign(s, in, il, sig, sl);
}

static CK_RV sign_multi(CK_MECHANISM *m, CK_OBJECT_HANDLE k, CK_BYTE *sig, CK_ULONG *sl) {
    CK_RV rv = C_SignInit(s, m, k);
    if (rv == CKR_OK) rv = C_SignUpdate(s, msg, 10);
    if (rv == CKR_OK) rv = C_SignUpdate(s, msg + 10, MSGLEN - 10);
    return rv != CKR_OK ? rv : C_SignFinal(s, sig, sl);
}

static CK_RV verify1(CK_MECHANISM *m, CK_OBJECT_HANDLE k, CK_BYTE *in, CK_ULONG il,
                     CK_BYTE *sig, CK_ULONG sl) {
    CK_RV rv = C_VerifyInit(s, m, k);
    return rv != CKR_OK ? rv : C_Verify(s, in, il, sig, sl);
}

static CK_ULONG digest(CK_ULONG dmech, CK_BYTE *out) {
    CK_MECHANISM m = { dmech, NULL, 0 };
    CK_ULONG l = 64;
    if (C_DigestInit(s, &m) != CKR_OK || C_Digest(s, msg, MSGLEN, out, &l) != CKR_OK) return 0;
    return l;
}

static int listed(CK_ULONG mech) {
    CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
    CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
    C_GetMechanismList(0, ml, &n);
    int found = 0;
    for (CK_ULONG i = 0; i < n; i++) if (ml[i] == mech) found = 1;
    free(ml);
    return found;
}

/* (E) and (S): one ECDSA mechanism against the P-256 pair. */
static void ecdsa_case(const char *name, CK_ULONG mech, CK_ULONG dmech,
                       CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE rsa) {
    char what[128];
    CK_MECHANISM m = { mech, NULL, 0 }, raw = { CKM_ECDSA, NULL, 0 };
    CK_BYTE sig[128], sig2[128], d[64];
    CK_ULONG sl = sizeof sig, sl2 = sizeof sig2;
    CK_RV rv = sign1(&m, priv, msg, MSGLEN, sig, &sl);
    snprintf(what, sizeof what, "(E) %s: signs, 64-byte r||s (0x%lx, %lu)", name, rv, sl);
    ok(rv == CKR_OK && sl == 64, what);
    snprintf(what, sizeof what, "(E) %s: verifies under itself", name);
    ok(verify1(&m, pub, msg, MSGLEN, sig, sl) == CKR_OK, what);
    CK_ULONG dl = digest(dmech, d);
    snprintf(what, sizeof what, "(E) %s: verifies under CKM_ECDSA over its digest (%lu bytes)", name, dl);
    ok(dl > 0 && verify1(&raw, pub, d, dl, sig, sl) == CKR_OK, what);
    rv = sign_multi(&m, priv, sig2, &sl2);
    snprintf(what, sizeof what, "(E) %s: multipart signs, verifies single-part (0x%lx)", name, rv);
    ok(rv == CKR_OK && sl2 == 64 && verify1(&m, pub, msg, MSGLEN, sig2, sl2) == CKR_OK, what);
    rv = verify1(&m, pub, msg, MSGLEN - 1, sig, sl);
    snprintf(what, sizeof what, "(E) %s: a changed message: SIGNATURE_INVALID (0x%lx)", name, rv);
    ok(rv == CKR_SIGNATURE_INVALID, what);
    rv = C_SignInit(s, &m, rsa);
    snprintf(what, sizeof what, "(E) %s: an RSA key: KEY_TYPE_INCONSISTENT (0x%lx)", name, rv);
    ok(rv == CKR_KEY_TYPE_INCONSISTENT, what);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_GenerateKeyPair); SYM(C_DigestInit); SYM(C_Digest);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_Verify || !C_SignFinal) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("ECDSA with SHA-1, SHA-224 and SHA-3; RSASSA-PSS with SHA-3\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "sigsha3", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const int nist = !listed(CKM_RSA_PKCS);
    char what[128];
    CK_RV rv;

    CK_BYTE no = 0, yes = 1;
    static const CK_BYTE P256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    CK_ATTRIBUTE ept[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                           { CKA_EC_PARAMS, (void*)P256, sizeof P256 } };
    CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    CK_MECHANISM egen = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE epub = 0, epriv = 0;
    if (C_GenerateKeyPair(s, &egen, ept, 3, kt, 2, &epub, &epriv) != CKR_OK) {
        fprintf(stderr, "EC key generation\n"); return 2;
    }
    CK_ULONG bits = 2048;
    CK_ATTRIBUTE rpt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                           { CKA_MODULUS_BITS, &bits, sizeof bits } };
    CK_MECHANISM rgen = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE rpub = 0, rpriv = 0;
    if (C_GenerateKeyPair(s, &rgen, rpt, 3, kt, 2, &rpub, &rpriv) != CKR_OK) {
        fprintf(stderr, "RSA key generation\n"); return 2;
    }

    /* (E) */
    static const struct { const char *name; CK_ULONG mech, dmech; } E[] = {
        { "ECDSA_SHA224",   0x1043, 0x255 }, { "ECDSA_SHA3_224", 0x1047, 0x2B5 },
        { "ECDSA_SHA3_256", 0x1048, 0x2B0 }, { "ECDSA_SHA3_384", 0x1049, 0x2C0 },
        { "ECDSA_SHA3_512", 0x104A, 0x2D0 },
    };
    for (size_t i = 0; i < sizeof E / sizeof E[0]; i++) {
        snprintf(what, sizeof what, "(E) %s listed", E[i].name);
        ok(listed(E[i].mech), what);
        ecdsa_case(E[i].name, E[i].mech, E[i].dmech, epub, epriv, rpriv);
    }

    /* (P) */
    static const struct { const char *name; CK_ULONG mech, dmech, mgf, dlen; } P[] = {
        { "SHA3_224_RSA_PKCS_PSS", 0x67, 0x2B5, 6, 28 }, { "SHA3_256_RSA_PKCS_PSS", 0x63, 0x2B0, 7, 32 },
        { "SHA3_384_RSA_PKCS_PSS", 0x64, 0x2C0, 8, 48 }, { "SHA3_512_RSA_PKCS_PSS", 0x65, 0x2D0, 9, 64 },
    };
    for (size_t i = 0; i < sizeof P / sizeof P[0]; i++) {
        CK_RSA_PKCS_PSS_PARAMS pp = { P[i].dmech, P[i].mgf, P[i].dlen };
        CK_MECHANISM m = { P[i].mech, &pp, sizeof pp }, bare = { CKM_RSA_PKCS_PSS, &pp, sizeof pp };
        CK_BYTE sig[256], sig2[256], d[64];
        CK_ULONG sl = sizeof sig, sl2 = sizeof sig2;
        snprintf(what, sizeof what, "(P) %s listed", P[i].name);
        ok(listed(P[i].mech), what);
        rv = sign1(&m, rpriv, msg, MSGLEN, sig, &sl);
        snprintf(what, sizeof what, "(P) %s: signs, 256 bytes (0x%lx, %lu)", P[i].name, rv, sl);
        ok(rv == CKR_OK && sl == 256, what);
        snprintf(what, sizeof what, "(P) %s: verifies under itself", P[i].name);
        ok(verify1(&m, rpub, msg, MSGLEN, sig, sl) == CKR_OK, what);
        CK_ULONG dl = digest(P[i].dmech, d);
        snprintf(what, sizeof what, "(P) %s: verifies under bare PSS over its digest", P[i].name);
        ok(dl == P[i].dlen && verify1(&bare, rpub, d, dl, sig, sl) == CKR_OK, what);
        rv = sign_multi(&m, rpriv, sig2, &sl2);
        snprintf(what, sizeof what, "(P) %s: multipart signs, verifies single-part (0x%lx)", P[i].name, rv);
        ok(rv == CKR_OK && verify1(&m, rpub, msg, MSGLEN, sig2, sl2) == CKR_OK, what);
        rv = verify1(&m, rpub, msg, MSGLEN - 1, sig, sl);
        snprintf(what, sizeof what, "(P) %s: a changed message: SIGNATURE_INVALID (0x%lx)", P[i].name, rv);
        ok(rv == CKR_SIGNATURE_INVALID, what);
        CK_RSA_PKCS_PSS_PARAMS bad = { CKM_SHA256, P[i].mgf, P[i].dlen };
        CK_MECHANISM mb = { P[i].mech, &bad, sizeof bad }, mn = { P[i].mech, NULL, 0 };
        CK_RV rb = C_SignInit(s, &mb, rpriv), rn = C_SignInit(s, &mn, rpriv);
        snprintf(what, sizeof what, "(P) %s: hashAlg SHA-256, no parameter: PARAM_INVALID", P[i].name);
        ok(rb == CKR_MECHANISM_PARAM_INVALID && rn == CKR_MECHANISM_PARAM_INVALID, what);
    }

    /* (S) */
    if (nist) {
        CK_MECHANISM m = { CKM_ECDSA_SHA1, NULL, 0 };
        rv = C_SignInit(s, &m, epriv);
        snprintf(what, sizeof what, "(S) ECDSA_SHA1: not listed, MECHANISM_INVALID (0x%lx)", rv);
        ok(!listed(CKM_ECDSA_SHA1) && rv == CKR_MECHANISM_INVALID, what);
    } else {
        ok(listed(CKM_ECDSA_SHA1), "(S) ECDSA_SHA1 listed");
        ecdsa_case("ECDSA_SHA1", CKM_ECDSA_SHA1, 0x220, epub, epriv, rpriv);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
