/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_kem_attrs.c --- the key C_EncapsulateKey and C_DecapsulateKey create.
 *
 * PKCS#11 v3.2 §5.18.8 and §5.18.9 give the new key, in the same words for
 * both functions:
 *   CKA_ALWAYS_SENSITIVE  FALSE
 *   CKA_NEVER_EXTRACTABLE FALSE
 *   CKA_EXTRACTABLE       from the template, TRUE when it does not say
 *   CKA_LOCAL             FALSE
 * and say that a call which "cannot support the precise template supplied to
 * it" fails without creating a key object.
 *
 * Before this test the module answered TRUE for the first two on a key created
 * sensitive and not extractable, defaulted CKA_EXTRACTABLE to FALSE, dropped
 * the usage flags and the dates of the template, created a token object from a
 * read-only session, and wrote *phKey before steps that could still destroy
 * the object.
 *
 *   (1) the defaults, both functions;
 *   (2) the history, on a key created sensitive and not extractable;
 *   (3) CKA_ENCRYPT=FALSE is stored, and C_EncryptInit refuses;
 *   (4) CKA_START_DATE is stored;
 *   (5) CKA_CLASS other than CKO_SECRET_KEY: CKR_TEMPLATE_INCONSISTENT, and
 *       *phKey is left as it was;
 *   (6) key type and length: AES-128 by CKA_VALUE_LEN, AES with 20 bytes and
 *       DES3 with 32 refused;
 *   (7) CKA_TOKEN=TRUE in a read-only session: CKR_SESSION_READ_ONLY;
 *   (8) the two shared secrets are still equal.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                          0UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED  0x68UL
#define CKR_SESSION_READ_ONLY           0xB5UL
#define CKR_TEMPLATE_INCONSISTENT       0xD1UL
#define CKF_SERIAL                      4UL
#define CKF_RW                          6UL
#define CKA_CLASS                       0UL
#define CKA_TOKEN                       1UL
#define CKA_VALUE                       0x11UL
#define CKA_KEY_TYPE                    0x100UL
#define CKA_SENSITIVE                   0x103UL
#define CKA_ENCRYPT                     0x104UL
#define CKA_START_DATE                  0x110UL
#define CKA_VALUE_LEN                   0x161UL
#define CKA_EXTRACTABLE                 0x162UL
#define CKA_LOCAL                       0x163UL
#define CKA_NEVER_EXTRACTABLE           0x164UL
#define CKA_ALWAYS_SENSITIVE            0x165UL
#define CKO_DATA                        0UL
#define CKO_SECRET_KEY                  4UL
#define CKK_DES3                        0x15UL
#define CKK_AES                         0x1FUL
#define CKM_ML_KEM_KEY_PAIR_GEN         0x0FUL
#define CKM_ML_KEM                      0x17UL
#define CKM_AES_ECB                     0x1081UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                   CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_EncapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_BYTE*,CK_ULONG*,CK_OBJECT_HANDLE*);
static CK_RV (*C_DecapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_BYTE*,CK_ULONG,CK_OBJECT_HANDLE*);

static CK_SESSION_HANDLE s;
static CK_OBJECT_HANDLE pub, priv;
static CK_MECHANISM kem = { CKM_ML_KEM, NULL, 0 };
static CK_BYTE ct[2048];
static CK_ULONG ctl;

/* 0 or 1, or -1 when the attribute cannot be read. */
static int bool_of(CK_OBJECT_HANDLE h, CK_ULONG attr) {
    CK_BYTE v = 0xFF;
    CK_ATTRIBUTE q[] = { { attr, &v, 1 } };
    if (C_GetAttributeValue(s, h, q, 1) != CKR_OK || q[0].ulValueLen != 1) return -1;
    return v ? 1 : 0;
}

/* Encapsulate with t, which also leaves a fresh ciphertext in ct. */
static CK_RV encap(CK_ATTRIBUTE *t, CK_ULONG n, CK_OBJECT_HANDLE *h) {
    ctl = sizeof ct;
    return C_EncapsulateKey(s, &kem, pub, t, n, ct, &ctl, h);
}

/* Decapsulate the last ciphertext with t. */
static CK_RV decap(CK_ATTRIBUTE *t, CK_ULONG n, CK_OBJECT_HANDLE *h) {
    return C_DecapsulateKey(s, &kem, priv, t, n, ct, ctl, h);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKeyPair);
    SYM(C_GetAttributeValue); SYM(C_EncryptInit);
    SYM(C_EncapsulateKey); SYM(C_DecapsulateKey);
    if (!C_EncapsulateKey || !C_DecapsulateKey || !C_Logout) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("Keys created by C_EncapsulateKey / C_DecapsulateKey (PKCS#11 v3.2 §5.18.8, §5.18.9)\n\n");

    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "kemattrs", 8);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    CK_BYTE yes = 1, no = 0;
    CK_ULONG cls_secret = CKO_SECRET_KEY, cls_data = CKO_DATA;
    CK_ULONG aes = CKK_AES, des3 = CKK_DES3, len16 = 16, len20 = 20;
    {
        CK_MECHANISM gen = { CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0 };
        CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 } };
        CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 } };
        if (C_GenerateKeyPair(s, &gen, pt, 1, kt, 1, &pub, &priv) != CKR_OK) {
            fprintf(stderr, "ML-KEM key pair\n"); return 2;
        }
    }

    /* (1) Nothing stated. */
    {
        CK_OBJECT_HANDLE e = 0, d = 0;
        ok(encap(NULL, 0, &e) == CKR_OK && decap(NULL, 0, &d) == CKR_OK,
           "(1) both functions with an empty template");
        ok(bool_of(e, CKA_EXTRACTABLE) == 1 && bool_of(d, CKA_EXTRACTABLE) == 1,
           "(1) CKA_EXTRACTABLE defaults to TRUE");
        ok(bool_of(e, CKA_SENSITIVE) == 0 && bool_of(d, CKA_SENSITIVE) == 0,
           "(1) CKA_SENSITIVE defaults to FALSE");
        ok(bool_of(e, CKA_ALWAYS_SENSITIVE) == 0 && bool_of(d, CKA_ALWAYS_SENSITIVE) == 0,
           "(1) CKA_ALWAYS_SENSITIVE is FALSE");
        ok(bool_of(e, CKA_NEVER_EXTRACTABLE) == 0 && bool_of(d, CKA_NEVER_EXTRACTABLE) == 0,
           "(1) CKA_NEVER_EXTRACTABLE is FALSE");
        ok(bool_of(e, CKA_LOCAL) == 0 && bool_of(d, CKA_LOCAL) == 0,
           "(1) CKA_LOCAL is FALSE");
    }

    /* (2) The case the history is for: a key that has been sensitive and not
     *     extractable since it was created here, but whose bytes exist outside
     *     the token -- in the other party's hands, or derived from what the
     *     caller passed in. */
    {
        CK_ATTRIBUTE t[] = { { CKA_SENSITIVE, &yes, 1 }, { CKA_EXTRACTABLE, &no, 1 } };
        CK_OBJECT_HANDLE e = 0, d = 0;
        ok(encap(t, 2, &e) == CKR_OK && decap(t, 2, &d) == CKR_OK,
           "(2) both functions, sensitive and not extractable");
        ok(bool_of(e, CKA_SENSITIVE) == 1 && bool_of(d, CKA_EXTRACTABLE) == 0,
           "(2) the template is applied");
        ok(bool_of(e, CKA_ALWAYS_SENSITIVE) == 0 && bool_of(d, CKA_ALWAYS_SENSITIVE) == 0,
           "(2) CKA_ALWAYS_SENSITIVE is still FALSE");
        ok(bool_of(e, CKA_NEVER_EXTRACTABLE) == 0 && bool_of(d, CKA_NEVER_EXTRACTABLE) == 0,
           "(2) CKA_NEVER_EXTRACTABLE is still FALSE");
    }

    /* (3) A usage flag. It was dropped, so the key encrypted whatever the
     *     template said. */
    {
        CK_ATTRIBUTE t[] = { { CKA_KEY_TYPE, &aes, sizeof aes }, { CKA_ENCRYPT, &no, 1 } };
        CK_OBJECT_HANDLE e = 0, d = 0;
        ok(encap(t, 2, &e) == CKR_OK && decap(t, 2, &d) == CKR_OK,
           "(3) both functions, AES with CKA_ENCRYPT=FALSE");
        ok(bool_of(e, CKA_ENCRYPT) == 0 && bool_of(d, CKA_ENCRYPT) == 0,
           "(3) CKA_ENCRYPT reads back FALSE");
        CK_MECHANISM ecb = { CKM_AES_ECB, NULL, 0 };
        ok(C_EncryptInit(s, &ecb, e) == CKR_KEY_FUNCTION_NOT_PERMITTED
           && C_EncryptInit(s, &ecb, d) == CKR_KEY_FUNCTION_NOT_PERMITTED,
           "(3) C_EncryptInit refuses with CKR_KEY_FUNCTION_NOT_PERMITTED");
    }

    /* (4) A date. */
    {
        CK_BYTE date[8] = { '2','0','2','6','1','1','0','7' };
        CK_ATTRIBUTE t[] = { { CKA_START_DATE, date, sizeof date } };
        CK_OBJECT_HANDLE e = 0, d = 0;
        ok(encap(t, 1, &e) == CKR_OK && decap(t, 1, &d) == CKR_OK,
           "(4) both functions with CKA_START_DATE");
        CK_BYTE r1[8] = { 0 }, r2[8] = { 0 };
        CK_ATTRIBUTE q1[] = { { CKA_START_DATE, r1, sizeof r1 } };
        CK_ATTRIBUTE q2[] = { { CKA_START_DATE, r2, sizeof r2 } };
        ok(C_GetAttributeValue(s, e, q1, 1) == CKR_OK && q1[0].ulValueLen == 8
           && memcmp(r1, date, 8) == 0
           && C_GetAttributeValue(s, d, q2, 1) == CKR_OK && q2[0].ulValueLen == 8
           && memcmp(r2, date, 8) == 0,
           "(4) and reads it back");
    }

    /* (5) The functions create a secret key and nothing else. */
    {
        CK_ATTRIBUTE ok_t[]  = { { CKA_CLASS, &cls_secret, sizeof cls_secret } };
        CK_ATTRIBUTE bad_t[] = { { CKA_CLASS, &cls_data, sizeof cls_data } };
        CK_OBJECT_HANDLE e = 0, d = 0;
        ok(encap(ok_t, 1, &e) == CKR_OK && decap(ok_t, 1, &d) == CKR_OK,
           "(5) CKA_CLASS = CKO_SECRET_KEY is accepted");
        e = d = 0xDEAD;
        ok(encap(bad_t, 1, &e) == CKR_TEMPLATE_INCONSISTENT,
           "(5) C_EncapsulateKey, CKO_DATA: CKR_TEMPLATE_INCONSISTENT");
        ok(decap(bad_t, 1, &d) == CKR_TEMPLATE_INCONSISTENT,
           "(5) C_DecapsulateKey, CKO_DATA: CKR_TEMPLATE_INCONSISTENT");
        ok(e == 0xDEAD && d == 0xDEAD, "(5) *phKey is not written on failure");
    }

    /* (6) The key type and the length agree, or the call fails. */
    {
        CK_ATTRIBUTE a16[] = { { CKA_KEY_TYPE, &aes, sizeof aes },
                               { CKA_VALUE_LEN, &len16, sizeof len16 } };
        CK_ATTRIBUTE a20[] = { { CKA_KEY_TYPE, &aes, sizeof aes },
                               { CKA_VALUE_LEN, &len20, sizeof len20 } };
        CK_ATTRIBUTE d32[] = { { CKA_KEY_TYPE, &des3, sizeof des3 } };
        CK_OBJECT_HANDLE e = 0, d = 0;
        ok(encap(a16, 2, &e) == CKR_OK && decap(a16, 2, &d) == CKR_OK,
           "(6) AES with CKA_VALUE_LEN = 16 is accepted");
        CK_ULONG l1 = 0, l2 = 0;
        CK_ATTRIBUTE q1[] = { { CKA_VALUE_LEN, &l1, sizeof l1 } };
        CK_ATTRIBUTE q2[] = { { CKA_VALUE_LEN, &l2, sizeof l2 } };
        ok(C_GetAttributeValue(s, e, q1, 1) == CKR_OK && l1 == 16
           && C_GetAttributeValue(s, d, q2, 1) == CKR_OK && l2 == 16,
           "(6) and is a 16-byte key");
        ok(encap(a20, 2, &e) == CKR_TEMPLATE_INCONSISTENT
           && decap(a20, 2, &d) == CKR_TEMPLATE_INCONSISTENT,
           "(6) AES with 20 bytes: CKR_TEMPLATE_INCONSISTENT");
        ok(encap(d32, 1, &e) == CKR_TEMPLATE_INCONSISTENT
           && decap(d32, 1, &d) == CKR_TEMPLATE_INCONSISTENT,
           "(6) DES3 with the 32-byte secret: CKR_TEMPLATE_INCONSISTENT");
    }

    /* (7) A token object from a read-only session. The login is the token's,
     *     so the second session is logged in too. */
    {
        CK_SESSION_HANDLE ro = 0;
        if (C_OpenSession(0, CKF_SERIAL, NULL, NULL, &ro) != CKR_OK) {
            ok(0, "(7) read-only session");
        } else {
            CK_ATTRIBUTE t[] = { { CKA_TOKEN, &yes, 1 } };
            CK_OBJECT_HANDLE e = 0, d = 0;
            ctl = sizeof ct;
            CK_RV re = C_EncapsulateKey(ro, &kem, pub, t, 1, ct, &ctl, &e);
            (void)encap(NULL, 0, &e);   /* a valid ciphertext, from the RW session */
            CK_RV rd = C_DecapsulateKey(ro, &kem, priv, t, 1, ct, ctl, &d);
            ok(re == CKR_SESSION_READ_ONLY && rd == CKR_SESSION_READ_ONLY,
               "(7) CKA_TOKEN=TRUE, read-only session: CKR_SESSION_READ_ONLY");
        }
    }

    /* (8) What the functions are for. */
    {
        CK_OBJECT_HANDLE e = 0, d = 0;
        CK_BYTE v1[64], v2[64];
        CK_ATTRIBUTE q1[] = { { CKA_VALUE, v1, sizeof v1 } };
        CK_ATTRIBUTE q2[] = { { CKA_VALUE, v2, sizeof v2 } };
        ok(encap(NULL, 0, &e) == CKR_OK && decap(NULL, 0, &d) == CKR_OK
           && C_GetAttributeValue(s, e, q1, 1) == CKR_OK
           && C_GetAttributeValue(s, d, q2, 1) == CKR_OK
           && q1[0].ulValueLen == 32 && q2[0].ulValueLen == 32
           && memcmp(v1, v2, 32) == 0,
           "(8) the two shared secrets are equal");
    }

    C_Finalize(NULL);
    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
