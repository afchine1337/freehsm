/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_pqc_pub_import.c --- importing an ML-KEM or ML-DSA public key.
 *
 * PKCS#11 v3.2 defines CKA_VALUE of a PQC public key as the raw key, with
 * CKA_PARAMETER_SET naming the set. This module stores SubjectPublicKeyInfo,
 * because that is what every reader in it expects. Until 2026-09-18 nothing
 * converted between the two, and the two families failed differently:
 *
 *   ML-KEM public  -- refused, CKR_TEMPLATE_INCONSISTENT. Honest.
 *   ML-DSA public  -- accepted on the verbatim path, stored as sent, and
 *                     unusable at first use. Accepted-then-broken.
 *
 * The second is the worse of the two, which is why both were fixed in one
 * change: they are one rule and one code path.
 *
 * Every case here ends by *using* the imported key -- encapsulating with it,
 * or verifying a signature the token made. An import that returns CKR_OK and
 * yields a key nothing can use is the defect, so a test that stops at the
 * return code would have passed against the broken module.
 *
 * The keys come from the token itself: generate a pair, read CKA_VALUE, and
 * import that back as a fresh object. No external vectors, and it closes the
 * loop through both boundaries at once -- if either conversion is wrong, the
 * round trip says so.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS, CK_USER_TYPE;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                        0UL
#define CKR_TEMPLATE_INCONSISTENT     0xD1UL
#define CKR_ATTRIBUTE_VALUE_INVALID   0x13UL

#define CKF_RW                        6UL
#define CKU_SO                        0UL
#define CKU_USER                      1UL

#define CKA_CLASS                     0UL
#define CKA_LABEL                     0x03UL
#define CKA_VALUE                     0x11UL
#define CKA_KEY_TYPE                  0x100UL
#define CKA_VERIFY                    0x10AUL
#define CKA_EXTRACTABLE               0x162UL
#define CKA_PARAMETER_SET             0x61DUL

#define CKO_PUBLIC_KEY                2UL
#define CKK_ML_KEM                    0x49UL
#define CKK_ML_DSA                    0x4AUL

#define CKM_ML_KEM_KEY_PAIR_GEN       0x0FUL
#define CKM_ML_KEM                    0x17UL
#define CKM_ML_DSA_KEY_PAIR_GEN       0x1CUL
#define CKM_ML_DSA                    0x1DUL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                   CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_EncapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_BYTE*,CK_ULONG*,CK_OBJECT_HANDLE*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);

/* Read CKA_VALUE of a public key. After this change it is the raw key. */
static CK_ULONG read_pub(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                          CK_BYTE *out, CK_ULONG cap) {
    CK_ATTRIBUTE q[] = { { CKA_VALUE, out, cap } };
    if (C_GetAttributeValue(s, h, q, 1) != CKR_OK) return 0;
    return q[0].ulValueLen;
}

static CK_OBJECT_HANDLE import_pub(CK_SESSION_HANDLE s, CK_ULONG ckk,
                                    const CK_BYTE *val, CK_ULONG len,
                                    const char *pset, CK_RV *rv_out) {
    CK_BYTE yes = 1;
    CK_ULONG cls = CKO_PUBLIC_KEY, kt = ckk;
    CK_ATTRIBUTE t[5];
    CK_ULONG n = 0;
    t[n].type = CKA_CLASS;       t[n].pValue = &cls; t[n].ulValueLen = sizeof cls; n++;
    t[n].type = CKA_KEY_TYPE;    t[n].pValue = &kt;  t[n].ulValueLen = sizeof kt;  n++;
    t[n].type = CKA_VALUE;       t[n].pValue = (void*)val; t[n].ulValueLen = len;  n++;
    t[n].type = CKA_EXTRACTABLE; t[n].pValue = &yes; t[n].ulValueLen = 1;          n++;
    if (pset) {
        t[n].type = CKA_PARAMETER_SET; t[n].pValue = (void*)pset;
        t[n].ulValueLen = (CK_ULONG)strlen(pset); n++;
    }
    CK_OBJECT_HANDLE h = 0;
    CK_RV rv = C_CreateObject(s, t, n, &h);
    if (rv_out) *rv_out = rv;
    return (rv == CKR_OK) ? h : 0;
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_GetAttributeValue);
    SYM(C_GenerateKeyPair); SYM(C_EncapsulateKey);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_CreateObject || !C_EncapsulateKey) { fprintf(stderr,"missing symbols\n"); return 2; }

    printf("PQC public-key import: raw in, raw out, and the key still works\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"pqcimport",9);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,CKU_SO,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,CKU_USER,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_BYTE yes = 1;
    char kl[] = "src";
    CK_ATTRIBUTE pub_t[] = { { CKA_LABEL, kl, sizeof kl - 1 },
                             { CKA_EXTRACTABLE, &yes, 1 } };
    CK_ATTRIBUTE priv_t[] = { { CKA_LABEL, kl, sizeof kl - 1 } };
    static CK_BYTE raw[4096];
    CK_RV rv;

    /* ---- ML-KEM ------------------------------------------------------- */
    {
        CK_MECHANISM gen = { CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE hp = 0, hk = 0;
        rv = C_GenerateKeyPair(s, &gen, pub_t, 2, priv_t, 1, &hp, &hk);
        ok(rv == CKR_OK, "ML-KEM key pair generated on the token");
        if (rv == CKR_OK) {
            CK_ULONG n = read_pub(s, hp, raw, sizeof raw);
            /* Default parameter set is ML-KEM-768 : 1184 raw bytes, measured
             * with tests/probe_pqc_pub_lengths. A readback still handing back
             * the 1206-byte SPKI would show here. */
            ok(n == 1184, "CKA_VALUE reads back as the 1184-byte raw key");

            CK_RV irv = 0;
            CK_OBJECT_HANDLE imp = import_pub(s, CKK_ML_KEM, raw, n, NULL, &irv);
            ok(irv == CKR_OK && imp != 0, "the raw key imports without CKA_PARAMETER_SET");

            if (imp) {
                CK_ULONG m = read_pub(s, imp, raw + 2048, 2048);
                ok(m == n && memcmp(raw, raw + 2048, n) == 0,
                   "and reads back byte-identical to what went in");

                /* The part a return code cannot tell you. */
                CK_MECHANISM kem = { CKM_ML_KEM, NULL, 0 };
                CK_ATTRIBUTE ss_t[] = { { CKA_EXTRACTABLE, &yes, 1 } };
                CK_BYTE ct[4096]; CK_ULONG ctl = sizeof ct;
                CK_OBJECT_HANDLE ss = 0;
                ok(C_EncapsulateKey(s, &kem, imp, ss_t, 1, ct, &ctl, &ss) == CKR_OK
                   && ctl == 1088 && ss != 0,
                   "the imported key encapsulates -- 1088-byte ciphertext");
            }

            /* The parameter set, when stated, must agree with the key. */
            CK_RV grv = 0;
            (void)import_pub(s, CKK_ML_KEM, raw, n, "ML-KEM-768", &grv);
            ok(grv == CKR_OK, "a CKA_PARAMETER_SET that agrees is accepted");
            (void)import_pub(s, CKK_ML_KEM, raw, n, "ML-KEM-1024", &grv);
            ok(grv == CKR_TEMPLATE_INCONSISTENT,
               "one that contradicts the key is refused, not ignored");
        }
    }

    /* ---- ML-DSA : the one that used to be accepted and broken ---------- */
    {
        CK_MECHANISM gen = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE hp = 0, hk = 0;
        rv = C_GenerateKeyPair(s, &gen, pub_t, 2, priv_t, 1, &hp, &hk);
        ok(rv == CKR_OK, "ML-DSA key pair generated on the token");
        if (rv == CKR_OK) {
            CK_ULONG n = read_pub(s, hp, raw, sizeof raw);
            ok(n == 1952, "CKA_VALUE reads back as the 1952-byte raw key (ML-DSA-65)");

            CK_RV irv = 0;
            CK_OBJECT_HANDLE imp = import_pub(s, CKK_ML_DSA, raw, n, NULL, &irv);
            ok(irv == CKR_OK && imp != 0, "the raw key imports");

            /* Sign with the token's own private key, verify with the imported
             * public one. Before this change the import returned CKR_OK and
             * this verify is where it fell over. */
            if (imp) {
                CK_MECHANISM sm = { CKM_ML_DSA, NULL, 0 };
                CK_BYTE sig[8192]; CK_ULONG sl = sizeof sig;
                CK_BYTE msg[] = "round trip";
                if (C_SignInit(s, &sm, hk) == CKR_OK
                    && C_Sign(s, msg, sizeof msg - 1, sig, &sl) == CKR_OK) {
                    ok(C_VerifyInit(s, &sm, imp) == CKR_OK
                       && C_Verify(s, msg, sizeof msg - 1, sig, sl) == CKR_OK,
                       "the imported key verifies a signature the token made");
                } else {
                    ok(0, "could not sign with the generated private key");
                }
            }
        }
    }

    /* ---- The refusals -------------------------------------------------- */
    {
        CK_RV brv = 0;
        (void)import_pub(s, CKK_ML_KEM, raw, 100, NULL, &brv);
        ok(brv != CKR_OK, "a value of no recognised length is refused");
        (void)import_pub(s, CKK_ML_KEM, raw, 1952, NULL, &brv);
        ok(brv != CKR_OK,
           "an ML-DSA-65 length declared CKK_ML_KEM is refused, not crossed over");
    }

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
