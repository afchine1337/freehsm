/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_rsa_x931.c --- RSA X9.31 (2.8.0): CKM_RSA_X9_31_KEY_PAIR_GEN,
 * CKM_RSA_X9_31 and CKM_SHA1_RSA_X9_31.
 *
 *   (G) a 2048-bit key pair, CKA_KEY_GEN_MECHANISM the X9.31 generator;
 *       1024 bits, under the 2048 where the generation makes strong primes,
 *       is CKR_KEY_SIZE_RANGE, and no CKA_MODULUS_BITS is
 *       CKR_TEMPLATE_INCOMPLETE.
 *   (S) CKM_SHA1_RSA_X9_31 signs in k bytes, and the signature opened with
 *       the public key through CKM_RSA_X_509 -- n minus it when its last
 *       nibble is not 0xC, as X9.31 signs min(s, n - s) -- is the X9.31
 *       block 0x6B 0xBB... 0xBA SHA-1(M) 0x33 0xCC. CKM_RSA_X9_31 over
 *       SHA-1(M) || 0x33, the digest by C_Digest, gives the same signature,
 *       and each verifies under the other mechanism. In parts, the same
 *       signature again. SHA-256 || 0x34 under CKM_RSA_X9_31.
 *   (F) a changed signature, other data: CKR_SIGNATURE_INVALID; k - 2 bytes
 *       of input sign and verify (header 0x6A, no padding), k - 3 bytes too
 *       (0x6B 0xBA, which OpenSSL's X9.31 check refuses), k - 1 bytes are
 *       CKR_DATA_LEN_RANGE.
 *   (N) refused where NIST's rules apply; the signatures not offered where
 *       only the FIPS provider serves RSA.
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
#define CKR_DATA_LEN_RANGE             0x021UL
#define CKR_KEY_SIZE_RANGE             0x062UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_SIGNATURE_INVALID          0x0C0UL
#define CKR_TEMPLATE_INCOMPLETE        0x0D0UL
#define CKF_RW                         6UL
#define CKA_TOKEN                      0x001UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_MODULUS                    0x120UL
#define CKA_MODULUS_BITS               0x121UL
#define CKA_PUBLIC_EXPONENT            0x122UL
#define CKA_KEY_GEN_MECHANISM          0x166UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_RSA_X_509                  0x0003UL
#define CKM_RSA_X9_31_KEY_PAIR_GEN     0x000AUL
#define CKM_RSA_X9_31                  0x000BUL
#define CKM_SHA1_RSA_X9_31             0x000CUL
#define CKM_SHA_1                      0x0220UL
#define CKM_SHA256                     0x0250UL

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
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
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

/* An X9.31 key pair of `bits` (0: no CKA_MODULUS_BITS), e = 65537. */
static CK_RV gen(CK_ULONG bits, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv) {
    CK_MECHANISM m = { CKM_RSA_X9_31_KEY_PAIR_GEN, NULL, 0 };
    CK_BYTE e[] = { 0x01, 0x00, 0x01 };
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                          { CKA_ENCRYPT, &yes, 1 }, { CKA_PUBLIC_EXPONENT, e, sizeof e },
                          { CKA_MODULUS_BITS, &bits, sizeof bits } };
    CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    return C_GenerateKeyPair(s, &m, pt, bits ? 5 : 4, vt, 2, pub, prv);
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

static int digest(CK_ULONG mech, const CK_BYTE *d, CK_ULONG dl, CK_BYTE *out, CK_ULONG want) {
    CK_MECHANISM m = { mech, NULL, 0 };
    CK_ULONG ol = want;
    return C_DigestInit(s, &m) == CKR_OK && C_Digest(s, (CK_BYTE*)d, dl, out, &ol) == CKR_OK
           && ol == want;
}

/* The X9.31 block behind sig: sig^e mod n through CKM_RSA_X_509, then
 * n - that when its last nibble is not 0xC. 1 when it could be computed. */
static int open_block(CK_OBJECT_HANDLE pub, const CK_BYTE *n, CK_ULONG k,
                      const CK_BYTE *sig, CK_BYTE *block) {
    CK_MECHANISM m = { CKM_RSA_X_509, NULL, 0 };
    CK_ULONG bl = k;
    if (C_EncryptInit(s, &m, pub) != CKR_OK
        || C_Encrypt(s, (CK_BYTE*)sig, k, block, &bl) != CKR_OK || bl != k)
        return 0;
    if ((block[k - 1] & 0x0F) != 0x0C) {
        int borrow = 0;
        for (CK_ULONG i = k; i-- > 0; ) {
            int d = (int)n[i] - (int)block[i] - borrow;
            borrow = d < 0;
            block[i] = (CK_BYTE)(d + (borrow ? 256 : 0));
        }
    }
    return 1;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_Verify); SYM(C_EncryptInit); SYM(C_Encrypt);
    SYM(C_DigestInit); SYM(C_Digest);
    if (!C_GenerateKeyPair || !C_Sign || !C_Encrypt) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("RSA X9.31\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "x931", 4);
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

    /* --- (N) where NIST's rules apply ------------------------------------ */
    if (nist) {
        CK_RV rv = gen(2048, &pub, &prv);
        snprintf(what, sizeof what, "(N) NIST's rules: the X9.31 generator refused (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_INVALID && !listed(CKM_RSA_X9_31_KEY_PAIR_GEN)
           && !listed(CKM_RSA_X9_31) && !listed(CKM_SHA1_RSA_X9_31), what);
        C_Finalize(NULL);
        printf("\n%s\n", fails ? "FAILURES" : "all good");
        return fails ? 1 : 0;
    }

    /* --- (G) the key pair ------------------------------------------------ */
    CK_RV rv = gen(1024, &pub, &prv);
    snprintf(what, sizeof what, "(G) 1024 bits: CKR_KEY_SIZE_RANGE (0x%lx)", rv);
    ok(rv == CKR_KEY_SIZE_RANGE, what);
    rv = gen(0, &pub, &prv);
    snprintf(what, sizeof what, "(G) no CKA_MODULUS_BITS: CKR_TEMPLATE_INCOMPLETE (0x%lx)", rv);
    ok(rv == CKR_TEMPLATE_INCOMPLETE, what);
    rv = gen(2048, &pub, &prv);
    snprintf(what, sizeof what, "(G) CKM_RSA_X9_31_KEY_PAIR_GEN, 2048 bits (0x%lx)", rv);
    ok(rv == CKR_OK && listed(CKM_RSA_X9_31_KEY_PAIR_GEN), what);
    if (rv != CKR_OK) { C_Finalize(NULL); printf("\nFAILURES\n"); return 1; }
    CK_BYTE n[512];
    CK_ULONG kgm = 0;
    CK_ATTRIBUTE na[] = { { CKA_MODULUS, n, sizeof n }, { CKA_KEY_GEN_MECHANISM, &kgm, sizeof kgm } };
    rv = C_GetAttributeValue(s, pub, na, 2);
    const CK_ULONG k = na[0].ulValueLen;
    snprintf(what, sizeof what, "(G) a modulus of %lu bytes, CKA_KEY_GEN_MECHANISM 0x%lx (0x%lx)", k, kgm, rv);
    ok(rv == CKR_OK && k == 256 && kgm == CKM_RSA_X9_31_KEY_PAIR_GEN, what);

    if (!listed(CKM_RSA_X9_31)) {
        rv = sign(CKM_SHA1_RSA_X9_31, prv, (const CK_BYTE*)"x", 1, n, &(CK_ULONG){ sizeof n });
        snprintf(what, sizeof what, "(N) RSA from the FIPS provider only: no X9.31 signature (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_INVALID && !listed(CKM_SHA1_RSA_X9_31), what);
        C_Finalize(NULL);
        printf("\n%s\n", fails ? "FAILURES" : "all good");
        return fails ? 1 : 0;
    }

    /* --- (S) the signatures ---------------------------------------------- */
    CK_BYTE msg[100], h1[21], h2[33], sig[512], sig2[512], sig3[512], blk[512];
    for (int i = 0; i < 100; i++) msg[i] = (CK_BYTE)(i * 7 + 1);
    CK_ULONG sl = sizeof sig, sl2 = sizeof sig2, sl3 = sizeof sig3;
    rv = sign(CKM_SHA1_RSA_X9_31, prv, msg, 100, sig, &sl);
    snprintf(what, sizeof what, "(S) CKM_SHA1_RSA_X9_31: 0x%lx, %lu bytes", rv, sl);
    ok(rv == CKR_OK && sl == k, what);
    int have_h1 = digest(CKM_SHA_1, msg, 100, h1, 20);
    h1[20] = 0x33;
    int good = rv == CKR_OK && have_h1 && open_block(pub, n, k, sig, blk)
               && blk[0] == 0x6B && blk[k - 1] == 0xCC && blk[k - 2] == 0x33
               && !memcmp(blk + k - 22, h1, 20) && blk[k - 23] == 0xBA;
    for (CK_ULONG i = 1; good && i < k - 23; i++) good = blk[i] == 0xBB;
    ok(good, "(S) opened: 0x6B 0xBB... 0xBA SHA-1(M) 0x33 0xCC");

    rv = have_h1 ? sign(CKM_RSA_X9_31, prv, h1, 21, sig2, &sl2) : 0xFFFF;
    snprintf(what, sizeof what, "(S) CKM_RSA_X9_31 over SHA-1(M) || 0x33: the same signature (0x%lx)", rv);
    ok(rv == CKR_OK && sl2 == sl && !memcmp(sig, sig2, sl), what);
    CK_RV v1 = verify(CKM_SHA1_RSA_X9_31, pub, msg, 100, sig2, sl2);
    CK_RV v2 = have_h1 ? verify(CKM_RSA_X9_31, pub, h1, 21, sig, sl) : 0xFFFF;
    snprintf(what, sizeof what, "(S) each verifies under the other mechanism (0x%lx 0x%lx)", v1, v2);
    ok(v1 == CKR_OK && v2 == CKR_OK, what);

    {
        CK_MECHANISM m = { CKM_SHA1_RSA_X9_31, NULL, 0 };
        CK_RV r1 = C_SignInit(s, &m, prv);
        CK_RV r2 = r1 == CKR_OK ? C_SignUpdate(s, msg, 40) : r1;
        CK_RV r3 = r2 == CKR_OK ? C_SignUpdate(s, msg + 40, 60) : r2;
        CK_RV r4 = r3 == CKR_OK ? C_SignFinal(s, sig3, &sl3) : r3;
        snprintf(what, sizeof what, "(S) in parts, the same signature (0x%lx)", r4);
        ok(r4 == CKR_OK && sl3 == sl && !memcmp(sig3, sig, sl), what);
    }

    if (digest(CKM_SHA256, msg, 100, h2, 32)) {
        h2[32] = 0x34;
        sl2 = sizeof sig2;
        rv = sign(CKM_RSA_X9_31, prv, h2, 33, sig2, &sl2);
        CK_RV v3 = rv == CKR_OK ? verify(CKM_RSA_X9_31, pub, h2, 33, sig2, sl2) : rv;
        good = rv == CKR_OK && open_block(pub, n, k, sig2, blk) && blk[k - 2] == 0x34
               && !memcmp(blk + k - 34, h2, 32) && blk[k - 35] == 0xBA;
        snprintf(what, sizeof what, "(S) SHA-256 || 0x34: signed, opened, verified (0x%lx 0x%lx)", rv, v3);
        ok(good && v3 == CKR_OK, what);
    }

    /* --- (F) refusals ---------------------------------------------------- */
    {
        CK_BYTE bad[512];
        memcpy(bad, sig, sl);
        bad[sl / 2] ^= 0x01;
        CK_RV f1 = verify(CKM_SHA1_RSA_X9_31, pub, msg, 100, bad, sl);
        CK_RV f2 = verify(CKM_SHA1_RSA_X9_31, pub, msg, 99, sig, sl);
        snprintf(what, sizeof what, "(F) a changed signature, other data: SIGNATURE_INVALID (0x%lx 0x%lx)", f1, f2);
        ok(f1 == CKR_SIGNATURE_INVALID && f2 == CKR_SIGNATURE_INVALID, what);

        CK_BYTE in[512];
        for (CK_ULONG i = 0; i < k; i++) in[i] = (CK_BYTE)(i + 3);
        in[0] = 0x11;
        sl2 = sizeof sig2;
        CK_RV f3 = sign(CKM_RSA_X9_31, prv, in, k - 2, sig2, &sl2);
        CK_RV f4 = f3 == CKR_OK ? verify(CKM_RSA_X9_31, pub, in, k - 2, sig2, sl2) : f3;
        good = f3 == CKR_OK && open_block(pub, n, k, sig2, blk) && blk[0] == 0x6A
               && !memcmp(blk + 1, in, k - 2) && blk[k - 1] == 0xCC;
        snprintf(what, sizeof what, "(F) k - 2 bytes: header 0x6A, verified (0x%lx 0x%lx)", f3, f4);
        ok(good && f4 == CKR_OK, what);
        sl2 = sizeof sig2;
        CK_RV f6 = sign(CKM_RSA_X9_31, prv, in, k - 3, sig2, &sl2);
        CK_RV f7 = f6 == CKR_OK ? verify(CKM_RSA_X9_31, pub, in, k - 3, sig2, sl2) : f6;
        good = f6 == CKR_OK && open_block(pub, n, k, sig2, blk) && blk[0] == 0x6B
               && blk[1] == 0xBA && !memcmp(blk + 2, in, k - 3) && blk[k - 1] == 0xCC;
        snprintf(what, sizeof what, "(F) k - 3 bytes: 0x6B 0xBA, no 0xBB, verified (0x%lx 0x%lx)", f6, f7);
        ok(good && f7 == CKR_OK, what);
        sl2 = sizeof sig2;
        CK_RV f5 = sign(CKM_RSA_X9_31, prv, in, k - 1, sig2, &sl2);
        snprintf(what, sizeof what, "(F) k - 1 bytes: CKR_DATA_LEN_RANGE (0x%lx)", f5);
        ok(f5 == CKR_DATA_LEN_RANGE, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
