/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_dsa.c --- DSA (2.8.0): CKM_DSA_KEY_PAIR_GEN on given domain
 * parameters, and the signatures CKM_DSA, CKM_DSA_SHA1 to CKM_DSA_SHA512 and
 * CKM_DSA_SHA3_224 to CKM_DSA_SHA3_512.
 *
 * The parameters are a fixed (2048, 256) set, made with OpenSSL's
 * "genpkey -genparam -algorithm DSA".
 *   (G) the key pair: CKA_PRIME, CKA_SUBPRIME and CKA_BASE read back as
 *       given, on both halves; CKA_VALUE of the public key, y, of p's length
 *       at most.
 *   (S) the signatures are r || s, 64 bytes. A signature by
 *       CKM_DSA_SHA256 verifies under bare CKM_DSA over SHA-256 of the
 *       message, computed with C_Digest, and one by CKM_DSA over that digest
 *       verifies under CKM_DSA_SHA256: the hashed and the raw paths sign the
 *       same thing. SHA-3, and a signature made in parts. A changed byte
 *       and a short signature are refused.
 *   (F) refusals: no CKA_BASE, sizes that are not one of FIPS 186-4's pairs,
 *       a generator of the wrong order, an ECDSA mechanism on a DSA key.
 *   (N) refused where NIST's rules apply, and not offered where only the
 *       FIPS provider serves DSA.
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
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_SIGNATURE_INVALID          0x0C0UL
#define CKR_SIGNATURE_LEN_RANGE        0x0C1UL
#define CKR_TEMPLATE_INCOMPLETE        0x0D0UL
#define CKR_DOMAIN_PARAMS_INVALID      0x130UL
#define CKF_RW                         6UL
#define CKK_DSA                        0x01UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_PRIME                      0x130UL
#define CKA_SUBPRIME                   0x131UL
#define CKA_BASE                       0x132UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_DSA_KEY_PAIR_GEN           0x0010UL
#define CKM_DSA                        0x0011UL
#define CKM_DSA_SHA256                 0x0014UL
#define CKM_DSA_SHA384                 0x0015UL
#define CKM_DSA_SHA3_256               0x0019UL
#define CKM_SHA256                     0x0250UL
#define CKM_ECDSA_SHA256               0x1044UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

/* (2048, 256) domain parameters. */
static const CK_BYTE dsa_p[256] = {
    0xc7, 0xb1, 0x8f, 0x97, 0x7d, 0x60, 0x24, 0x99, 0xf0, 0x6e, 0x42, 0x82,
    0x07, 0x8e, 0xf3, 0x07, 0x16, 0x84, 0x1b, 0x7c, 0x29, 0xd4, 0xbe, 0xf3,
    0x27, 0x4d, 0x84, 0x8a, 0x38, 0x06, 0xfd, 0x04, 0x4c, 0x99, 0x12, 0xfc,
    0x0d, 0xf0, 0xc3, 0x98, 0x30, 0x96, 0x30, 0xcb, 0xe2, 0x39, 0x02, 0x13,
    0x24, 0x60, 0xd2, 0x22, 0xdd, 0xfe, 0x82, 0x07, 0xf7, 0xc1, 0x63, 0x12,
    0x3a, 0xbb, 0xb9, 0x10, 0xf9, 0x70, 0xc2, 0x05, 0x4b, 0x53, 0x7d, 0xc8,
    0xaa, 0x7f, 0x5c, 0x44, 0xe5, 0x12, 0x54, 0x76, 0x35, 0x02, 0xc9, 0x69,
    0x43, 0xcf, 0x89, 0xde, 0xe2, 0x6b, 0xe1, 0x58, 0x4a, 0x97, 0x93, 0x57,
    0x94, 0xb6, 0xd5, 0x27, 0x05, 0x66, 0xc9, 0x50, 0x50, 0xb6, 0x00, 0x58,
    0x84, 0xf5, 0x5f, 0x1c, 0xcd, 0xaa, 0xda, 0xee, 0x9e, 0x3f, 0x50, 0xf5,
    0xd6, 0x8b, 0x0c, 0x69, 0xa1, 0xb3, 0x09, 0x55, 0x20, 0x16, 0xae, 0x11,
    0x23, 0xbe, 0x1a, 0xc7, 0x56, 0x83, 0x2e, 0x9b, 0x1f, 0xc8, 0xa0, 0x70,
    0xc0, 0x9a, 0x89, 0xb5, 0x84, 0x89, 0xfe, 0xd2, 0x66, 0xa7, 0x98, 0x44,
    0x56, 0xe4, 0x53, 0xcb, 0x3b, 0x84, 0x73, 0x6c, 0x5a, 0x9f, 0x3a, 0x64,
    0xbf, 0x46, 0x48, 0x2a, 0x6d, 0xdd, 0x49, 0xef, 0xf1, 0x96, 0xd1, 0x0f,
    0x14, 0xc3, 0xa5, 0x80, 0xcc, 0x7e, 0x8b, 0x72, 0x09, 0xc0, 0xca, 0xda,
    0x15, 0xf8, 0xe5, 0xec, 0x84, 0xcd, 0x28, 0xa4, 0xab, 0x38, 0xd8, 0x57,
    0xc7, 0x0b, 0xf9, 0x5a, 0x83, 0xe4, 0x2e, 0x48, 0xd7, 0x24, 0x08, 0x63,
    0xf4, 0xec, 0xe1, 0x12, 0xc7, 0x95, 0x70, 0xe4, 0x69, 0x17, 0x71, 0x0e,
    0xc2, 0xb1, 0xda, 0xae, 0xf3, 0x27, 0xda, 0xca, 0xa0, 0xa9, 0x78, 0xee,
    0x82, 0x54, 0x3f, 0x7a, 0x80, 0x1b, 0x7b, 0xaa, 0x91, 0x8d, 0x03, 0x1f,
    0xd0, 0x2f, 0x87, 0x6d,
};
static const CK_BYTE dsa_q[32] = {
    0xe5, 0x1a, 0xa7, 0x3b, 0xda, 0x39, 0x84, 0x87, 0x2c, 0x21, 0x98, 0xfe,
    0x59, 0x22, 0xa0, 0xed, 0xff, 0x66, 0x31, 0x25, 0x03, 0x4c, 0x4f, 0xa1,
    0x2c, 0x94, 0x79, 0xd9, 0xc7, 0xe6, 0x97, 0xa3,
};
static const CK_BYTE dsa_g[256] = {
    0x35, 0x2f, 0xf1, 0x2a, 0xe4, 0xfa, 0xe6, 0x36, 0x6b, 0x80, 0xd3, 0x50,
    0x62, 0x3a, 0xe5, 0xcb, 0x8b, 0x1e, 0xee, 0x62, 0x93, 0xed, 0x51, 0xc3,
    0xa7, 0xbd, 0x0d, 0x68, 0x26, 0x56, 0x1a, 0xde, 0xa9, 0xe5, 0xfc, 0x96,
    0x62, 0x2e, 0x71, 0x9a, 0x10, 0x10, 0x7e, 0x0b, 0x13, 0x54, 0xc2, 0xc1,
    0xe0, 0xe1, 0xcc, 0xa5, 0x9e, 0x83, 0x83, 0xe8, 0x96, 0x57, 0xec, 0x49,
    0x37, 0xff, 0x59, 0xe8, 0x91, 0xc8, 0x7f, 0xf6, 0x38, 0x5c, 0xf8, 0xed,
    0x22, 0x3c, 0xc7, 0x56, 0xbb, 0x6c, 0x3b, 0x93, 0xb2, 0xdd, 0x76, 0xdc,
    0x96, 0xb8, 0x64, 0xd2, 0x15, 0x60, 0xdd, 0xb4, 0xf3, 0x4b, 0x83, 0xc4,
    0x8c, 0x51, 0xd2, 0xf2, 0x7f, 0x42, 0x7d, 0x7f, 0x45, 0xae, 0x4c, 0x35,
    0xf9, 0x79, 0x70, 0x05, 0xb3, 0x85, 0xc3, 0x4d, 0x49, 0x1e, 0x43, 0x1d,
    0xe3, 0x64, 0x0d, 0xd4, 0xdb, 0x82, 0x8d, 0xe0, 0x8a, 0xe1, 0x35, 0x38,
    0xce, 0x8f, 0xdb, 0xed, 0x20, 0x51, 0x44, 0x61, 0x1c, 0xc3, 0xcf, 0x84,
    0x2f, 0xb9, 0x3c, 0x84, 0xb6, 0xb7, 0xe6, 0x0d, 0x5f, 0xa4, 0x3b, 0xb1,
    0x54, 0x5f, 0x97, 0xdb, 0xe2, 0x90, 0x8f, 0x9b, 0x8b, 0x38, 0xce, 0xd6,
    0xf0, 0x3b, 0xa7, 0x8d, 0x78, 0x9c, 0x70, 0x80, 0x9a, 0xbc, 0x9e, 0x58,
    0x1c, 0x84, 0xb0, 0x51, 0x3f, 0x93, 0xdb, 0xa5, 0xb8, 0xd1, 0xf0, 0x60,
    0x94, 0x2d, 0x32, 0xd0, 0xf0, 0xa0, 0xc2, 0x6f, 0x42, 0xd8, 0xcc, 0x24,
    0x55, 0xe2, 0x98, 0x33, 0x21, 0x02, 0x1a, 0x68, 0x36, 0x4e, 0xe5, 0x01,
    0x42, 0x8b, 0xfa, 0x84, 0x5e, 0x29, 0x94, 0x2e, 0x90, 0x4a, 0xee, 0x4e,
    0xc8, 0x36, 0x36, 0xbd, 0xbc, 0x79, 0x34, 0x35, 0x7d, 0x89, 0x03, 0xdf,
    0xe9, 0x55, 0x28, 0x7d, 0x21, 0xe8, 0x39, 0xa2, 0xc5, 0x2d, 0x33, 0xde,
    0xff, 0x14, 0xab, 0x3e,
};

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
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM*);
static CK_RV (*C_Digest)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);

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

/* A key pair on (p, q, g); n of the three attributes given. */
static CK_RV gen(const CK_BYTE *p, CK_ULONG pl, const CK_BYTE *q, CK_ULONG ql,
                 const CK_BYTE *g, CK_ULONG gl, CK_ULONG n,
                 CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv) {
    CK_MECHANISM m = { CKM_DSA_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                          { CKA_PRIME, (void*)p, pl }, { CKA_SUBPRIME, (void*)q, ql },
                          { CKA_BASE, (void*)g, gl } };
    CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    return C_GenerateKeyPair(s, &m, pt, 2 + n, vt, 2, pub, prv);
}

static int attr_is(CK_OBJECT_HANDLE h, CK_ULONG type, const CK_BYTE *want, CK_ULONG wl) {
    CK_BYTE buf[512];
    CK_ATTRIBUTE a = { type, buf, sizeof buf };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK && a.ulValueLen == wl
           && !memcmp(buf, want, wl);
}

static CK_RV sign(CK_ULONG mech, CK_OBJECT_HANDLE k, const CK_BYTE *d, CK_ULONG dl,
                  CK_BYTE *sig, CK_ULONG *sl) {
    CK_MECHANISM m = { mech, NULL, 0 };
    CK_RV rv = C_SignInit(s, &m, k);
    return rv != CKR_OK ? rv : C_Sign(s, (CK_BYTE*)d, dl, sig, sl);
}

static CK_RV verify(CK_ULONG mech, CK_OBJECT_HANDLE k, const CK_BYTE *d, CK_ULONG dl,
                    const CK_BYTE *sig, CK_ULONG sl) {
    CK_MECHANISM m = { mech, NULL, 0 };
    CK_RV rv = C_VerifyInit(s, &m, k);
    return rv != CKR_OK ? rv : C_Verify(s, (CK_BYTE*)d, dl, (CK_BYTE*)sig, sl);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_Verify); SYM(C_DigestInit); SYM(C_Digest);
    if (!C_GenerateKeyPair || !C_Sign || !C_Digest) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("DSA\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "dsa", 3);
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
    char what[160];
    CK_OBJECT_HANDLE pub = 0, prv = 0;
    CK_RV rv = gen(dsa_p, sizeof dsa_p, dsa_q, sizeof dsa_q, dsa_g, sizeof dsa_g, 3, &pub, &prv);

    /* --- (N) where DSA is not offered ------------------------------------ */
    if (nist || !listed(CKM_DSA_KEY_PAIR_GEN)) {
        snprintf(what, sizeof what, "(N) %s: CKM_DSA_KEY_PAIR_GEN refused (0x%lx)",
                 nist ? "NIST's rules" : "DSA from the FIPS provider only", rv);
        ok(rv == CKR_MECHANISM_INVALID && !listed(CKM_DSA_SHA256), what);
        C_Finalize(NULL);
        printf("\n%s\n", fails ? "FAILURES" : "all good");
        return fails ? 1 : 0;
    }

    /* --- (G) the key pair ------------------------------------------------ */
    snprintf(what, sizeof what, "(G) CKM_DSA_KEY_PAIR_GEN, (2048, 256): 0x%lx", rv);
    ok(rv == CKR_OK, what);
    if (rv != CKR_OK) { C_Finalize(NULL); printf("\nFAILURES\n"); return 1; }
    ok(attr_is(pub, CKA_PRIME, dsa_p, sizeof dsa_p) && attr_is(prv, CKA_PRIME, dsa_p, sizeof dsa_p)
       && attr_is(pub, CKA_SUBPRIME, dsa_q, sizeof dsa_q) && attr_is(prv, CKA_SUBPRIME, dsa_q, sizeof dsa_q)
       && attr_is(pub, CKA_BASE, dsa_g, sizeof dsa_g) && attr_is(prv, CKA_BASE, dsa_g, sizeof dsa_g),
       "(G) CKA_PRIME, CKA_SUBPRIME, CKA_BASE as given, on both halves");
    {
        CK_ULONG kt = 0; CK_BYTE y[512];
        CK_ATTRIBUTE a[] = { { CKA_KEY_TYPE, &kt, sizeof kt }, { CKA_VALUE, y, sizeof y } };
        CK_RV ar = C_GetAttributeValue(s, pub, a, 2);
        snprintf(what, sizeof what, "(G) CKK_DSA, CKA_VALUE y of %lu bytes: 0x%lx", a[1].ulValueLen, ar);
        ok(ar == CKR_OK && kt == CKK_DSA && a[1].ulValueLen > 200 && a[1].ulValueLen <= 256, what);
    }

    /* --- (S) the signatures ---------------------------------------------- */
    CK_BYTE msg[100], dig[32], sig[128], sig2[128];
    for (int i = 0; i < 100; i++) msg[i] = (CK_BYTE)(i * 7 + 1);
    CK_ULONG dl = sizeof dig, sl = sizeof sig, sl2 = sizeof sig2;
    CK_MECHANISM dm = { CKM_SHA256, NULL, 0 };
    int have_dig = C_DigestInit(s, &dm) == CKR_OK && C_Digest(s, msg, 100, dig, &dl) == CKR_OK && dl == 32;
    rv = sign(CKM_DSA_SHA256, prv, msg, 100, sig, &sl);
    snprintf(what, sizeof what, "(S) CKM_DSA_SHA256: 0x%lx, %lu bytes", rv, sl);
    ok(rv == CKR_OK && sl == 64 && listed(CKM_DSA_SHA256), what);
    CK_RV v1 = verify(CKM_DSA_SHA256, pub, msg, 100, sig, sl);
    CK_RV v2 = have_dig ? verify(CKM_DSA, pub, dig, 32, sig, sl) : 0xFFFF;
    snprintf(what, sizeof what, "(S) verified by CKM_DSA_SHA256 and by CKM_DSA over SHA-256 (0x%lx 0x%lx)", v1, v2);
    ok(v1 == CKR_OK && v2 == CKR_OK, what);
    rv = have_dig ? sign(CKM_DSA, prv, dig, 32, sig2, &sl2) : 0xFFFF;
    CK_RV v3 = rv == CKR_OK ? verify(CKM_DSA_SHA256, pub, msg, 100, sig2, sl2) : rv;
    snprintf(what, sizeof what, "(S) CKM_DSA over the digest verified by CKM_DSA_SHA256 (0x%lx 0x%lx)", rv, v3);
    ok(rv == CKR_OK && sl2 == 64 && v3 == CKR_OK, what);

    sl = sizeof sig;
    rv = sign(CKM_DSA_SHA3_256, prv, msg, 100, sig, &sl);
    v1 = rv == CKR_OK ? verify(CKM_DSA_SHA3_256, pub, msg, 100, sig, sl) : rv;
    snprintf(what, sizeof what, "(S) CKM_DSA_SHA3_256 signed and verified (0x%lx)", v1);
    ok(rv == CKR_OK && v1 == CKR_OK, what);

    {
        CK_MECHANISM m = { CKM_DSA_SHA384, NULL, 0 };
        sl = sizeof sig;
        rv = C_SignInit(s, &m, prv);
        if (rv == CKR_OK) rv = C_SignUpdate(s, msg, 40);
        if (rv == CKR_OK) rv = C_SignUpdate(s, msg + 40, 60);
        if (rv == CKR_OK) rv = C_SignFinal(s, sig, &sl);
        v1 = rv == CKR_OK ? verify(CKM_DSA_SHA384, pub, msg, 100, sig, sl) : rv;
        snprintf(what, sizeof what, "(S) CKM_DSA_SHA384 in parts, verified at once (0x%lx 0x%lx)", rv, v1);
        ok(rv == CKR_OK && sl == 64 && v1 == CKR_OK, what);
    }

    sl = sizeof sig;
    rv = sign(CKM_DSA_SHA256, prv, msg, 100, sig, &sl);
    sig[10] ^= 0x01;
    v1 = verify(CKM_DSA_SHA256, pub, msg, 100, sig, sl);
    sig[10] ^= 0x01;
    v2 = verify(CKM_DSA_SHA256, pub, msg, 100, sig, 63);
    snprintf(what, sizeof what, "(S) a changed byte and 63 bytes refused (0x%lx 0x%lx)", v1, v2);
    ok(v1 == CKR_SIGNATURE_INVALID && (v2 == CKR_SIGNATURE_INVALID || v2 == CKR_SIGNATURE_LEN_RANGE), what);

    /* --- (F) refusals ---------------------------------------------------- */
    {
        CK_OBJECT_HANDLE a = 0, b = 0;
        CK_RV r1 = gen(dsa_p, sizeof dsa_p, dsa_q, sizeof dsa_q, dsa_g, sizeof dsa_g, 2, &a, &b);
        CK_RV r2 = gen(dsa_p, sizeof dsa_p, dsa_q, 20, dsa_g, sizeof dsa_g, 3, &a, &b);
        CK_BYTE two = 2;
        CK_RV r3 = gen(dsa_p, sizeof dsa_p, dsa_q, sizeof dsa_q, &two, 1, 3, &a, &b);
        sl = sizeof sig;
        CK_RV r4 = sign(CKM_ECDSA_SHA256, prv, msg, 100, sig, &sl);
        snprintf(what, sizeof what, "(F) no base, (2048, 160), g = 2, ECDSA (0x%lx 0x%lx 0x%lx 0x%lx)",
                 r1, r2, r3, r4);
        ok(r1 == CKR_TEMPLATE_INCOMPLETE && r2 == CKR_DOMAIN_PARAMS_INVALID
           && r3 == CKR_DOMAIN_PARAMS_INVALID && r4 == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
