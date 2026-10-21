/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_slh_dsa_kat.c --- SLH-DSA (FIPS 205, PKCS#11 v3.2 CKM_SLH_DSA)
 * against NIST's known answers.
 *
 * Wycheproof has no SLH-DSA vectors, and test_slh_dsa_sets.c only shows the
 * module agrees with itself: it signs and verifies its own signatures. This
 * test takes keys and signatures from NIST's ACVP-Server
 * (SLH-DSA-sigGen-FIPS205 and SLH-DSA-sigVer-FIPS205), as far as PKCS#11
 * reaches them: the external interface, pure, deterministic generation.
 *
 * tests/vectors/slh_dsa_kat.txt, from scripts/extract_slh_dsa_kat.py:
 *
 *   G <set> <ctx> <msg> <sk> <pk> <sig>          deterministic sigGen
 *   V <set> <ctx> <msg> <pk> <sig> <1|0> <kind>  sigVer, 1 = accepted
 *
 * What is asserted:
 *   (1) each G vector: NIST's private key imports with CKA_PARAMETER_SET,
 *       and C_Sign with CKH_DETERMINISTIC_REQUIRED and the vector's context
 *       gives NIST's signature byte for byte -- all twelve parameter sets,
 *       and an empty context for SHA2-128s and SHAKE-128s
 *   (2) each G vector: NIST's public key imports, C_Verify accepts NIST's
 *       signature, and rejects it with one bit changed
 *   (3) each V vector: C_Verify answers as NIST does -- CKR_OK for a valid
 *       signature, CKR_SIGNATURE_INVALID for a modified message, R, SIGFORS
 *       or SIGHT, and for a signature one byte short or long either
 *       CKR_SIGNATURE_LEN_RANGE or CKR_SIGNATURE_INVALID
 *   (4) the file held 14 generations and 14 verifications
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
/* CK_SIGN_ADDITIONAL_CONTEXT */
typedef struct { CK_ULONG hedgeVariant; CK_BYTE *pContext; CK_ULONG ulContextLen; } CK_SIGN_CTX;

#define CKR_OK                     0UL
#define CKR_SIGNATURE_INVALID      0xC0UL
#define CKR_SIGNATURE_LEN_RANGE    0xC1UL
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
#define CKK_SLH_DSA                0x4BUL
#define CKM_SLH_DSA                0x2EUL
#define CKH_DETERMINISTIC_REQUIRED 2UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"
#define KAT_FILE "tests/vectors/slh_dsa_kat.txt"
#define SIG_MAX  65536

/* PKCS#11 v3.2 CKP_SLH_DSA_*, 1 to 12, as in test_slh_dsa_sets.c. */
static const char *SETS[] = {
    "SHA2-128s", "SHAKE-128s", "SHA2-128f", "SHAKE-128f",
    "SHA2-192s", "SHAKE-192s", "SHA2-192f", "SHAKE-192f",
    "SHA2-256s", "SHAKE-256s", "SHA2-256f", "SHAKE-256f",
};
#define NSETS (sizeof SETS / sizeof SETS[0])

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-70s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);

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

static CK_ULONG set_index(const char *name) {
    for (size_t i = 0; i < NSETS; ++i)
        if (!strcmp(SETS[i], name)) return (CK_ULONG)(i + 1);
    return 0;
}

/* CKA_PARAMETER_SET is required on import (v3.2 Table 13, footnote 1), and
 * for SLH-DSA nothing else could tell the set: a 64-byte private key is
 * SHA2-128s, SHAKE-128s, SHA2-128f or SHAKE-128f. */
static CK_OBJECT_HANDLE import_key(CK_SESSION_HANDLE s, CK_ULONG cls, CK_ULONG ps,
                                   CK_BYTE *v, CK_ULONG vlen, CK_RV *rv_out) {
    CK_ULONG kt = CKK_SLH_DSA;
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE t[] = {
        { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
        { CKA_TOKEN, &no, 1 },
        { cls == CKO_PRIVATE_KEY ? CKA_SIGN : CKA_VERIFY, &yes, 1 },
        { CKA_VALUE, v, vlen },
        { CKA_PARAMETER_SET, &ps, sizeof ps },
    };
    CK_OBJECT_HANDLE h = 0;
    *rv_out = C_CreateObject(s, t, sizeof t / sizeof t[0], &h);
    return *rv_out == CKR_OK ? h : 0;
}

static CK_RV verify(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k, CK_BYTE *ctx, CK_ULONG ctxl,
                    CK_BYTE *msg, CK_ULONG ml, CK_BYTE *sig, CK_ULONG sl) {
    CK_SIGN_CTX sc = { 0, ctx, ctxl };
    CK_MECHANISM m = { CKM_SLH_DSA, &sc, sizeof sc };
    CK_RV rv = C_VerifyInit(s, &m, k);
    return rv != CKR_OK ? rv : C_Verify(s, msg, ml, sig, sl);
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
    SYM(C_CreateObject); SYM(C_DestroyObject);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_CreateObject || !C_DestroyObject || !C_SignInit || !C_Sign
        || !C_VerifyInit || !C_Verify) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    FILE *f = fopen(KAT_FILE, "r");
    if (!f) { fprintf(stderr, "%s: cannot open (run from the tree's root)\n", KAT_FILE); return 2; }

    printf("SLH-DSA against NIST's known answers\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "slhdsakat")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    CK_BYTE *sig = malloc(SIG_MAX);
    if (!sig) return 2;
    char *line = NULL; size_t cap = 0;
    char what[160];
    int gens = 0, vers = 0;

    while (getline(&line, &cap, f) > 0) {
        if (line[0] != 'G' && line[0] != 'V') continue;
        char *fld[8] = { 0 };
        int nf = 0;
        for (char *tok = strtok(line, " \r\n"); tok && nf < 8; tok = strtok(NULL, " \r\n"))
            fld[nf++] = tok;
        const int gen = (line[0] == 'G');
        if (nf != (gen ? 7 : 8)) { ok(0, "a vector line with the expected fields"); continue; }
        CK_ULONG ps = set_index(fld[1]);
        if (!ps) { snprintf(what, sizeof what, "known parameter set %s", fld[1]); ok(0, what); continue; }

        CK_ULONG ctxl, ml, al, bl, cl = 0;
        CK_BYTE *ctx = unhex(fld[2], &ctxl), *msg = unhex(fld[3], &ml),
                *a = unhex(fld[4], &al), *b = unhex(fld[5], &bl),
                *c = gen ? unhex(fld[6], &cl) : calloc(1, 1);
        if (!ctx || !msg || !a || !b || !c) {
            ok(0, "vector fields are hex");
            free(ctx); free(msg); free(a); free(b); free(c);
            continue;
        }
        const char *ctx_note = ctxl ? "" : ", empty context";

        if (gen) {
            /* a = sk, b = pk, c = NIST's signature */
            gens++;
            CK_RV rv;
            CK_OBJECT_HANDLE sk = import_key(s, CKO_PRIVATE_KEY, ps, a, al, &rv);
            snprintf(what, sizeof what, "(1) %s: private key imports (rv 0x%lx)", fld[1], rv);
            ok(sk != 0, what);
            if (sk) {
                CK_SIGN_CTX sc = { CKH_DETERMINISTIC_REQUIRED, ctx, ctxl };
                CK_MECHANISM m = { CKM_SLH_DSA, &sc, sizeof sc };
                CK_ULONG sl = SIG_MAX;
                rv = C_SignInit(s, &m, sk);
                if (rv == CKR_OK) rv = C_Sign(s, msg, ml, sig, &sl);
                snprintf(what, sizeof what, "(1) %s%s: NIST's signature (rv 0x%lx)",
                         fld[1], ctx_note, rv);
                ok(rv == CKR_OK && sl == cl && !memcmp(sig, c, cl), what);
                (void)C_DestroyObject(s, sk);
            }

            CK_OBJECT_HANDLE pk = import_key(s, CKO_PUBLIC_KEY, ps, b, bl, &rv);
            snprintf(what, sizeof what, "(2) %s: public key imports (rv 0x%lx)", fld[1], rv);
            ok(pk != 0, what);
            if (pk) {
                rv = verify(s, pk, ctx, ctxl, msg, ml, c, cl);
                snprintf(what, sizeof what, "(2) %s%s: NIST's signature verifies (rv 0x%lx)",
                         fld[1], ctx_note, rv);
                ok(rv == CKR_OK, what);
                c[cl / 2] ^= 0x01;
                rv = verify(s, pk, ctx, ctxl, msg, ml, c, cl);
                snprintf(what, sizeof what, "(2) %s%s: one bit changed, rejected (rv 0x%lx)",
                         fld[1], ctx_note, rv);
                ok(rv == CKR_SIGNATURE_INVALID, what);
                (void)C_DestroyObject(s, pk);
            }
        } else {
            /* a = pk, b = the signature under test */
            vers++;
            const int accepted = !strcmp(fld[6], "1");
            const int length_case = !strcmp(fld[7], "too-small") || !strcmp(fld[7], "too-large");
            CK_RV rv;
            CK_OBJECT_HANDLE pk = import_key(s, CKO_PUBLIC_KEY, ps, a, al, &rv);
            if (pk) rv = verify(s, pk, ctx, ctxl, msg, ml, b, bl);
            snprintf(what, sizeof what, "(3) %s %s: %s as NIST says (rv 0x%lx)",
                     fld[1], fld[7], accepted ? "accepted" : "rejected", rv);
            ok(pk && (accepted ? rv == CKR_OK
                      : length_case ? (rv == CKR_SIGNATURE_LEN_RANGE || rv == CKR_SIGNATURE_INVALID)
                      : rv == CKR_SIGNATURE_INVALID), what);
            if (pk) (void)C_DestroyObject(s, pk);
        }
        free(ctx); free(msg); free(a); free(b); free(c);
    }
    free(line);
    fclose(f);
    ok(gens == 14 && vers == 14, "(4) the vector file had 14 generations and 14 verifications");

    free(sig);
    (void)C_Finalize(NULL);
    printf("\n%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
