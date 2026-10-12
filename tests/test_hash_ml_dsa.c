/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_hash_ml_dsa.c --- HashML-DSA (PKCS#11 v3.2 §6.67.6-6.67.7) against
 * NIST's known answers.
 *
 * The module builds M' = 0x01 || len(ctx) || ctx || OID(PH) || PH(M) itself
 * and signs it with ML-DSA.Sign_internal, because OpenSSL 3.5 has no
 * HashML-DSA (docs/hash-ml-dsa-plan.md). A wrong M' still verifies against
 * the module's own verify, so a round trip proves nothing about it: this
 * test signs deterministically and compares with NIST's signature byte for
 * byte.
 *
 * tests/vectors/hash_ml_dsa_kat.txt, from scripts/extract_hash_mldsa_kat.py:
 *
 *   G <set> <hash> <ctx> <msg> <sk> <sig>       deterministic sigGen
 *   V <set> <hash> <ctx> <msg> <pk> <sig> <1|0> sigVer, 1 = accepted
 *
 * What is asserted:
 *   (1) each G vector: the hash-specific mechanism's signature is NIST's;
 *       SHA-512/224 and SHA-512/256, which have none, go through the
 *       generic CKM_HASH_ML_DSA with PH(M) from C_Digest
 *   (2) each G vector whose hash has a digest mechanism: the generic
 *       mechanism, given C_Digest's PH(M), gives the same signature -- the
 *       table's digest column and the mechanism column agree
 *   (3) each G vector with a hash-specific mechanism, streamed: three
 *       C_SignUpdate parts (one empty), a C_SignFinal into 16 bytes that
 *       answers CKR_BUFFER_TOO_SMALL with the length, and the retry, which
 *       gives NIST's signature
 *   (4) each V vector: C_Verify says CKR_OK or CKR_SIGNATURE_INVALID as
 *       NIST does, and so does C_VerifyUpdate / C_VerifyFinal where the
 *       hash has its own mechanism
 *   (5) refusals: the generic mechanism without its parameter block, with a
 *       hash it cannot name, a context of 256 bytes, an unknown hedge
 *       variant; PH(M) of the wrong length (CKR_DATA_LEN_RANGE at C_Sign,
 *       CKR_SIGNATURE_INVALID at C_Verify, v3.2 Table 283); C_SignUpdate,
 *       C_SignFinal and C_VerifyUpdate on the generic mechanism, which is
 *       single-part, refused with CKR_FUNCTION_NOT_SUPPORTED
 *   (6) a context over 255 bytes, for CKM_ML_DSA and HashML-DSA alike:
 *       C_SignInit refuses it with CKR_MECHANISM_PARAM_INVALID (FIPS 204
 *       Algorithms 2 and 4), C_Verify and C_VerifyFinal answer
 *       CKR_SIGNATURE_INVALID (Algorithms 3 and 5). It was
 *       CKR_FUNCTION_FAILED at 256 bytes, and beyond that the context was
 *       dropped and the empty one used. A NULL context with a length is
 *       refused; 255 bytes signs.
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
/* CK_SIGN_ADDITIONAL_CONTEXT and CK_HASH_SIGN_ADDITIONAL_CONTEXT. */
typedef struct { CK_ULONG hedgeVariant; CK_BYTE *pContext; CK_ULONG ulContextLen; } CK_SIGN_CTX;
typedef struct { CK_ULONG hedgeVariant; CK_BYTE *pContext; CK_ULONG ulContextLen;
                 CK_ULONG hash; } CK_HASH_SIGN_CTX;

#define CKR_OK                     0UL
#define CKR_DATA_LEN_RANGE         0x21UL
#define CKR_FUNCTION_NOT_SUPPORTED 0x54UL
#define CKR_BUFFER_TOO_SMALL       0x150UL
#define CKR_MECHANISM_PARAM_INVALID 0x71UL
#define CKR_SIGNATURE_INVALID      0xC0UL
#define CKF_RW                     6UL
#define CKA_CLASS                  0x000UL
#define CKA_TOKEN                  0x001UL
#define CKA_VALUE                  0x011UL
#define CKA_KEY_TYPE               0x100UL
#define CKA_SIGN                   0x108UL
#define CKA_VERIFY                 0x10AUL
#define CKA_PARAMETER_SET          0x61DUL
#define CKO_PUBLIC_KEY             2UL
#define CKO_PRIVATE_KEY            3UL
#define CKK_ML_DSA                 0x4AUL
#define CKM_HASH_ML_DSA            0x1FUL
#define CKM_MD5                    0x210UL
#define CKH_DETERMINISTIC_REQUIRED 2UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"
#define KAT_FILE "tests/vectors/hash_ml_dsa_kat.txt"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

/* The hash names of the vector file: the hash-specific mechanism (0 if
 * none) and the digest mechanism naming it in the generic block (0 if none). */
static const struct { const char *name; CK_ULONG mech, digest; } HASHES[] = {
    { "SHA2-224",     0x23UL, 0x255UL }, { "SHA2-256",     0x24UL, 0x250UL },
    { "SHA2-384",     0x25UL, 0x260UL }, { "SHA2-512",     0x26UL, 0x270UL },
    { "SHA2-512/224", 0,      0x048UL }, { "SHA2-512/256", 0,      0x04CUL },
    { "SHA3-224",     0x27UL, 0x2B5UL }, { "SHA3-256",     0x28UL, 0x2B0UL },
    { "SHA3-384",     0x29UL, 0x2C0UL }, { "SHA3-512",     0x2AUL, 0x2D0UL },
    { "SHAKE-128",    0x2BUL, 0 },       { "SHAKE-256",    0x2CUL, 0 },
};
#define NHASH (sizeof HASHES / sizeof HASHES[0])

static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE);
static CK_RV (*C_DigestInit)(CK_SESSION_HANDLE,CK_MECHANISM*);
static CK_RV (*C_Digest)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);

/* Hex to a fresh buffer; "-" is empty. NULL on a malformed field. */
static CK_BYTE *unhex(const char *h, CK_ULONG *len) {
    if (!strcmp(h, "-")) { *len = 0; return calloc(1, 1); }
    size_t n = strlen(h);
    if (n % 2) return NULL;
    CK_BYTE *b = malloc(n / 2 + 1);
    if (!b) return NULL;
    for (size_t i = 0; i < n / 2; ++i) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) { free(b); return NULL; }
        b[i] = (CK_BYTE)v;
    }
    *len = (CK_ULONG)(n / 2);
    return b;
}

static int hash_index(const char *name) {
    for (size_t i = 0; i < NHASH; ++i)
        if (!strcmp(HASHES[i].name, name)) return (int)i;
    return -1;
}

/* CKA_PARAMETER_SET is required on import (v3.2 Tables 280-281, footnote
 * 1): CKP_ML_DSA_44/65/87 = 1/2/3, from the vector's set name. */
static CK_OBJECT_HANDLE import_key(CK_SESSION_HANDLE s, CK_ULONG cls, const char *set,
                                   CK_BYTE *v, CK_ULONG vlen) {
    CK_ULONG kt = CKK_ML_DSA;
    CK_ULONG ps = !strcmp(set, "ML-DSA-44") ? 1 : !strcmp(set, "ML-DSA-65") ? 2
                : !strcmp(set, "ML-DSA-87") ? 3 : 0;
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE t[] = {
        { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
        { CKA_TOKEN, &no, 1 },
        { cls == CKO_PRIVATE_KEY ? CKA_SIGN : CKA_VERIFY, &yes, 1 },
        { CKA_VALUE, v, vlen },
        { CKA_PARAMETER_SET, &ps, sizeof ps },
    };
    CK_OBJECT_HANDLE h = 0;
    CK_RV rv = C_CreateObject(s, t, sizeof t / sizeof t[0], &h);
    if (rv != CKR_OK) { printf("    C_CreateObject: 0x%lx\n", rv); return 0; }
    return h;
}

/* PH(M) through the module's own C_Digest. */
static CK_RV digest(CK_SESSION_HANDLE s, CK_ULONG ckm, CK_BYTE *m, CK_ULONG ml,
                    CK_BYTE *out, CK_ULONG *out_len) {
    CK_MECHANISM dm = { ckm, NULL, 0 };
    CK_RV rv = C_DigestInit(s, &dm);
    return rv != CKR_OK ? rv : C_Digest(s, m, ml, out, out_len);
}

/* The mechanism for a hash-specific sign or verify, or the generic one with
 * PH(M) computed into ph. *data and *dlen are what goes to C_Sign / C_Verify. */
typedef struct {
    CK_MECHANISM     m;
    CK_SIGN_CTX      sc;
    CK_HASH_SIGN_CTX hc;
    CK_BYTE          ph[64];
} mech_t;

static CK_RV setup(CK_SESSION_HANDLE s, mech_t *x, int hi, int generic,
                   CK_BYTE *ctx, CK_ULONG ctxl, CK_BYTE **data, CK_ULONG *dlen) {
    if (!generic) {
        x->sc = (CK_SIGN_CTX){ CKH_DETERMINISTIC_REQUIRED, ctx, ctxl };
        x->m = (CK_MECHANISM){ HASHES[hi].mech, &x->sc, sizeof x->sc };
        return CKR_OK;
    }
    CK_ULONG pl = sizeof x->ph;
    CK_RV rv = digest(s, HASHES[hi].digest, *data, *dlen, x->ph, &pl);
    if (rv != CKR_OK) return rv;
    x->hc = (CK_HASH_SIGN_CTX){ CKH_DETERMINISTIC_REQUIRED, ctx, ctxl, HASHES[hi].digest };
    x->m = (CK_MECHANISM){ CKM_HASH_ML_DSA, &x->hc, sizeof x->hc };
    *data = x->ph; *dlen = pl;
    return CKR_OK;
}

static CK_RV sign_one(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k, int hi, int generic,
                      CK_BYTE *ctx, CK_ULONG ctxl, CK_BYTE *msg, CK_ULONG ml,
                      CK_BYTE *sig, CK_ULONG *sl) {
    mech_t x;
    CK_BYTE *d = msg; CK_ULONG dl = ml;
    CK_RV rv = setup(s, &x, hi, generic, ctx, ctxl, &d, &dl);
    if (rv == CKR_OK) rv = C_SignInit(s, &x.m, k);
    if (rv == CKR_OK) rv = C_Sign(s, d, dl, sig, sl);
    return rv;
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
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN);
    SYM(C_CreateObject); SYM(C_DestroyObject); SYM(C_DigestInit); SYM(C_Digest);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_Verify); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    if (!C_CreateObject || !C_SignInit || !C_Sign || !C_SignUpdate || !C_SignFinal
        || !C_VerifyInit || !C_Verify || !C_VerifyUpdate || !C_VerifyFinal
        || !C_Digest || !C_DestroyObject) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    FILE *f = fopen(KAT_FILE, "r");
    if (!f) { fprintf(stderr, "%s: cannot open (run from the tree's root)\n", KAT_FILE); return 2; }

    printf("HashML-DSA against NIST's known answers\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "hashmldsa")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    char *line = NULL; size_t cap = 0;
    char what[128];
    int gens = 0, vers = 0;
    CK_OBJECT_HANDLE any_sk = 0, any_pk = 0;
    CK_BYTE sig[8192];

    while (getline(&line, &cap, f) > 0) {
        if (line[0] != 'G' && line[0] != 'V') continue;
        char *fld[8] = { 0 };
        int nf = 0;
        for (char *tok = strtok(line, " \r\n"); tok && nf < 8; tok = strtok(NULL, " \r\n"))
            fld[nf++] = tok;
        const int gen = (line[0] == 'G');
        if (nf != (gen ? 7 : 8)) { ok(0, "a vector line with the expected fields"); continue; }
        int hi = hash_index(fld[2]);
        if (hi < 0) { snprintf(what, sizeof what, "known hash %s", fld[2]); ok(0, what); continue; }
        CK_ULONG ctxl, ml, kl, el;
        CK_BYTE *ctx = unhex(fld[3], &ctxl), *msg = unhex(fld[4], &ml),
                *key = unhex(fld[5], &kl), *exp = unhex(fld[6], &el);
        if (!ctx || !msg || !key || !exp) {
            ok(0, "vector fields are hex");
            free(ctx); free(msg); free(key); free(exp);
            continue;
        }
        const int specific = HASHES[hi].mech != 0;

        if (gen) {
            gens++;
            CK_OBJECT_HANDLE k = import_key(s, CKO_PRIVATE_KEY, fld[1], key, kl);
            if (!any_sk && k && !strcmp(fld[1], "ML-DSA-44")) any_sk = k;
            /* (1) */
            CK_ULONG sl = sizeof sig;
            CK_RV rv = k ? sign_one(s, k, hi, !specific, ctx, ctxl, msg, ml, sig, &sl) : 0x6UL;
            snprintf(what, sizeof what, "(1) %s %s%s: NIST's signature (rv 0x%lx)",
                     fld[1], fld[2], specific ? "" : " via generic", rv);
            ok(rv == CKR_OK && sl == el && !memcmp(sig, exp, el), what);
            /* (2) */
            if (k && specific && HASHES[hi].digest) {
                sl = sizeof sig;
                rv = sign_one(s, k, hi, 1, ctx, ctxl, msg, ml, sig, &sl);
                snprintf(what, sizeof what, "(2) %s %s via generic: the same (rv 0x%lx)",
                         fld[1], fld[2], rv);
                ok(rv == CKR_OK && sl == el && !memcmp(sig, exp, el), what);
            }
            /* (3) */
            if (k && specific) {
                mech_t x;
                CK_BYTE *d = msg; CK_ULONG dl = ml;
                (void)setup(s, &x, hi, 0, ctx, ctxl, &d, &dl);
                CK_ULONG half = ml / 2, small = 16;
                CK_RV r3 = C_SignInit(s, &x.m, k);
                if (r3 == CKR_OK) r3 = C_SignUpdate(s, msg, half);
                if (r3 == CKR_OK) r3 = C_SignUpdate(s, msg + half, 0);
                if (r3 == CKR_OK) r3 = C_SignUpdate(s, msg + half, ml - half);
                CK_RV r_small = r3 == CKR_OK ? C_SignFinal(s, sig, &small) : r3;
                sl = sizeof sig;
                CK_RV r_full = r_small == CKR_BUFFER_TOO_SMALL ? C_SignFinal(s, sig, &sl) : r_small;
                snprintf(what, sizeof what, "(3) %s %s streamed, retried: the same (rv 0x%lx/0x%lx)",
                         fld[1], fld[2], r_small, r_full);
                ok(r_small == CKR_BUFFER_TOO_SMALL && small == el && r_full == CKR_OK
                   && sl == el && !memcmp(sig, exp, el), what);
            }
            if (k && k != any_sk) (void)C_DestroyObject(s, k);
        } else {
            vers++;
            const int accepted = !strcmp(fld[7], "1");
            CK_OBJECT_HANDLE k = import_key(s, CKO_PUBLIC_KEY, fld[1], key, kl);
            mech_t x;
            CK_BYTE *d = msg; CK_ULONG dl = ml;
            CK_RV rv = k ? setup(s, &x, hi, !specific, ctx, ctxl, &d, &dl) : 0x6UL;
            if (rv == CKR_OK) rv = C_VerifyInit(s, &x.m, k);
            if (rv == CKR_OK) rv = C_Verify(s, d, dl, exp, el);
            snprintf(what, sizeof what, "(4) %s %s%s: %s as NIST says (rv 0x%lx)",
                     fld[1], fld[2], specific ? "" : " via generic",
                     accepted ? "accepted" : "rejected", rv);
            ok(rv == (accepted ? CKR_OK : CKR_SIGNATURE_INVALID), what);
            if (k && specific) {
                d = msg; dl = ml;
                (void)setup(s, &x, hi, 0, ctx, ctxl, &d, &dl);
                CK_ULONG half = ml / 2;
                rv = C_VerifyInit(s, &x.m, k);
                if (rv == CKR_OK) rv = C_VerifyUpdate(s, msg, half);
                if (rv == CKR_OK) rv = C_VerifyUpdate(s, msg + half, ml - half);
                if (rv == CKR_OK) rv = C_VerifyFinal(s, exp, el);
                snprintf(what, sizeof what, "(4) %s %s streamed: %s (rv 0x%lx)",
                         fld[1], fld[2], accepted ? "accepted" : "rejected", rv);
                ok(rv == (accepted ? CKR_OK : CKR_SIGNATURE_INVALID), what);
            }
            if (!any_pk && k) any_pk = k;
            else if (k) (void)C_DestroyObject(s, k);
        }
        free(ctx); free(msg); free(key); free(exp);
    }
    free(line);
    fclose(f);
    ok(gens == 14 && vers == 12, "the vector file had 14 generations and 12 verifications");

    printf("\nrefusals\n");
    if (!any_sk) {
        ok(0, "an ML-DSA-44 private key to test refusals with");
    } else {
        CK_BYTE ctx256[256];
        memset(ctx256, 'c', sizeof ctx256);
        CK_MECHANISM m = { CKM_HASH_ML_DSA, NULL, 0 };
        ok(C_SignInit(s, &m, any_sk) == CKR_MECHANISM_PARAM_INVALID,
           "(5) generic without CK_HASH_SIGN_ADDITIONAL_CONTEXT");
        CK_HASH_SIGN_CTX hc = { 0, NULL, 0, CKM_MD5 };
        m = (CK_MECHANISM){ CKM_HASH_ML_DSA, &hc, sizeof hc };
        ok(C_SignInit(s, &m, any_sk) == CKR_MECHANISM_PARAM_INVALID,
           "(5) generic naming a hash it has no OID for (MD5)");
        hc = (CK_HASH_SIGN_CTX){ 0, ctx256, 256, 0x250UL };
        ok(C_SignInit(s, &m, any_sk) == CKR_MECHANISM_PARAM_INVALID,
           "(5) generic with a 256-byte context");
        CK_SIGN_CTX sc = { 3, NULL, 0 };
        m = (CK_MECHANISM){ 0x24UL, &sc, sizeof sc };
        ok(C_SignInit(s, &m, any_sk) == CKR_MECHANISM_PARAM_INVALID,
           "(5) SHA256 mechanism with hedge variant 3");
        sc = (CK_SIGN_CTX){ 0, ctx256, 256 };
        ok(C_SignInit(s, &m, any_sk) == CKR_MECHANISM_PARAM_INVALID,
           "(5) SHA256 mechanism with a 256-byte context");
        hc = (CK_HASH_SIGN_CTX){ 0, NULL, 0, 0x250UL };
        m = (CK_MECHANISM){ CKM_HASH_ML_DSA, &hc, sizeof hc };
        CK_BYTE ph[33] = { 0 };
        CK_ULONG sl = sizeof sig;
        CK_RV rv = C_SignInit(s, &m, any_sk);
        ok(rv == CKR_OK, "(5) generic SHA-256 accepted at C_SignInit");
        if (rv == CKR_OK)
            ok(C_Sign(s, ph, 33, sig, &sl) == CKR_DATA_LEN_RANGE,
               "(5) generic SHA-256 given 33 bytes: CKR_DATA_LEN_RANGE");
        rv = C_SignInit(s, &m, any_sk);
        ok(rv == CKR_OK && C_SignUpdate(s, ph, 32) == CKR_FUNCTION_NOT_SUPPORTED,
           "(5) generic: C_SignUpdate refused, single-part");
        rv = C_SignInit(s, &m, any_sk);
        sl = sizeof sig;
        ok(rv == CKR_OK && C_SignFinal(s, sig, &sl) == CKR_FUNCTION_NOT_SUPPORTED,
           "(5) generic: C_SignFinal refused, single-part");
        ok(C_SignInit(s, &m, any_sk) == CKR_OK,
           "(5) generic: each refusal ended its operation");
        sl = sizeof sig;
        (void)C_Sign(s, ph, 32, sig, &sl);
        if (any_pk) {
            CK_BYTE fake[2420] = { 0 };
            rv = C_VerifyInit(s, &m, any_pk);
            ok(rv == CKR_OK && C_Verify(s, ph, 33, fake, sizeof fake) == CKR_SIGNATURE_INVALID,
               "(5) generic SHA-256 verify of 33 bytes: CKR_SIGNATURE_INVALID");
            rv = C_VerifyInit(s, &m, any_pk);
            ok(rv == CKR_OK && C_VerifyUpdate(s, ph, 32) == CKR_FUNCTION_NOT_SUPPORTED,
               "(5) generic: C_VerifyUpdate refused, single-part");
        } else {
            ok(0, "an ML-DSA-44 public key to test verify refusals with");
        }
    }

    printf("\na context over 255 bytes\n");
    if (any_sk && any_pk) {
        CK_BYTE big[300], fake[2420] = { 0 }, sig2[8192];
        memset(big, 'c', sizeof big);
        CK_BYTE msg3[] = "abc";
        CK_ULONG sl = sizeof sig2;
        const CK_ULONG CKM_ML_DSA = 0x1DUL, CKM_HASH_ML_DSA_SHA256 = 0x24UL;
        CK_SIGN_CTX sc = { 0, big, 256 };
        CK_MECHANISM m = { CKM_ML_DSA, &sc, sizeof sc };

        ok(C_SignInit(s, &m, any_sk) == CKR_MECHANISM_PARAM_INVALID,
           "(6) CKM_ML_DSA C_SignInit, 256-byte context: refused");
        sc.ulContextLen = 300;
        ok(C_SignInit(s, &m, any_sk) == CKR_MECHANISM_PARAM_INVALID,
           "(6) CKM_ML_DSA C_SignInit, 300-byte context: refused");
        sc = (CK_SIGN_CTX){ 0, NULL, 5 };
        ok(C_SignInit(s, &m, any_sk) == CKR_MECHANISM_PARAM_INVALID,
           "(6) CKM_ML_DSA C_SignInit, NULL context of length 5: refused");

        sc = (CK_SIGN_CTX){ 0, big, 256 };
        CK_RV rv = C_VerifyInit(s, &m, any_pk);
        ok(rv == CKR_OK && C_Verify(s, msg3, 3, fake, sizeof fake) == CKR_SIGNATURE_INVALID,
           "(6) CKM_ML_DSA verify, 256-byte context: CKR_SIGNATURE_INVALID");
        sc.ulContextLen = 300;
        rv = C_VerifyInit(s, &m, any_pk);
        ok(rv == CKR_OK && C_Verify(s, msg3, 3, fake, sizeof fake) == CKR_SIGNATURE_INVALID,
           "(6) CKM_ML_DSA verify, 300-byte context: CKR_SIGNATURE_INVALID");
        sc.ulContextLen = 256;
        rv = C_VerifyInit(s, &m, any_pk);
        if (rv == CKR_OK) rv = C_VerifyUpdate(s, msg3, 3);
        if (rv == CKR_OK) rv = C_VerifyFinal(s, fake, sizeof fake);
        ok(rv == CKR_SIGNATURE_INVALID,
           "(6) CKM_ML_DSA multipart verify, 256-byte context: CKR_SIGNATURE_INVALID");
        m.mechanism = CKM_HASH_ML_DSA_SHA256;
        rv = C_VerifyInit(s, &m, any_pk);
        ok(rv == CKR_OK && C_Verify(s, msg3, 3, fake, sizeof fake) == CKR_SIGNATURE_INVALID,
           "(6) HASH_ML_DSA_SHA256 verify, 256-byte context: CKR_SIGNATURE_INVALID");

        /* The control: 255 bytes is a context like any other. */
        sc = (CK_SIGN_CTX){ 0, big, 255 };
        m = (CK_MECHANISM){ CKM_ML_DSA, &sc, sizeof sc };
        rv = C_SignInit(s, &m, any_sk);
        if (rv == CKR_OK) rv = C_Sign(s, msg3, 3, sig2, &sl);
        ok(rv == CKR_OK && sl == 2420, "(6) CKM_ML_DSA, 255-byte context: signed");
    } else {
        ok(0, "an ML-DSA-44 key pair to test context bounds with");
    }

    (void)C_Finalize(NULL);
    printf("\n%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
