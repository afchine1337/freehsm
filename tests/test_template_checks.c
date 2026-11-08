/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_template_checks.c --- templates that were accepted and not honoured.
 *
 * Reported by AlexLaroche (#33, C5, C7, C8, C9, C11). Each answered CKR_OK
 * for a template the module had not followed:
 *   C5  C_GenerateKeyPair(RSA) without CKA_MODULUS_BITS made 2048 bits;
 *       §6.1.2 requires it: CKR_TEMPLATE_INCOMPLETE.
 *   C7  C_GenerateKey(CKM_AES_KEY_GEN) with CKA_KEY_TYPE=CKK_GENERIC_SECRET
 *       made an AES key: CKR_TEMPLATE_INCONSISTENT.
 *   C8  CKA_ALWAYS_SENSITIVE in a C_GenerateKey template was dropped; it
 *       and CKA_LOCAL, CKA_NEVER_EXTRACTABLE, CKA_KEY_GEN_MECHANISM are the
 *       token's to set: CKR_ATTRIBUTE_READ_ONLY (§4.11).
 *   C9  CKA_UNIQUE_ID in a private key template was dropped: the token
 *       assigns it, CKR_ATTRIBUTE_READ_ONLY, and nothing is made (§4.4.1).
 *   C11 C_FindObjects matched the class, label and id only. A CKA_TOKEN of
 *       four zero bytes, or any other attribute, matched every object.
 *
 * What is asserted:
 *   (1) C5: RSA without CKA_MODULUS_BITS is CKR_TEMPLATE_INCOMPLETE
 *   (2) C7: CKM_AES_KEY_GEN with CKK_GENERIC_SECRET, or with
 *       CKA_CLASS=CKO_PUBLIC_KEY, is CKR_TEMPLATE_INCONSISTENT; with CKK_AES
 *       it generates
 *   (3) C8: CKA_ALWAYS_SENSITIVE or CKA_LOCAL in C_GenerateKey, CKA_LOCAL in
 *       C_CreateObject: CKR_ATTRIBUTE_READ_ONLY
 *   (4) C9: CKA_UNIQUE_ID in the private template of an EC pair:
 *       CKR_ATTRIBUTE_READ_ONLY, and no key is added
 *   (5) C11: CKA_TOKEN of four zero bytes finds nothing; CKA_TOKEN=FALSE
 *       finds the session object, CKA_TOKEN=TRUE does not; CKA_KEY_TYPE=AES
 *       finds the AES key and not the generic secret; a 4-byte CKA_CLASS
 *       finds nothing
 *   (6) C6: CKA_PUBLIC_EXPONENT 65539 makes a key with 65539, where F4 was
 *       made; e = 3, outside FIPS 186-5's 2^16 < e < 2^256, is
 *       CKR_ATTRIBUTE_VALUE_INVALID
 *   (7) C10: a data object with CKA_OBJECT_ID is CKR_ATTRIBUTE_TYPE_INVALID,
 *       not accepted and dropped: the store has no field for it
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                       0UL
#define CKR_ATTRIBUTE_READ_ONLY      0x10UL
#define CKR_ATTRIBUTE_TYPE_INVALID   0x12UL
#define CKR_ATTRIBUTE_VALUE_INVALID  0x13UL
#define CKA_OBJECT_ID                0x012UL
#define CKA_MODULUS_BITS             0x121UL
#define CKR_TEMPLATE_INCOMPLETE      0xD0UL
#define CKR_TEMPLATE_INCONSISTENT    0xD1UL
#define CKF_RW                       6UL
#define CKA_CLASS                    0x000UL
#define CKA_TOKEN                    0x001UL
#define CKA_LABEL                    0x003UL
#define CKA_UNIQUE_ID                0x004UL
#define CKA_VALUE                    0x011UL
#define CKA_KEY_TYPE                 0x100UL
#define CKA_SIGN                     0x108UL
#define CKA_VERIFY                   0x10AUL
#define CKA_PUBLIC_EXPONENT          0x122UL
#define CKA_VALUE_LEN                0x161UL
#define CKA_LOCAL                    0x163UL
#define CKA_ALWAYS_SENSITIVE         0x165UL
#define CKA_EC_PARAMS                0x180UL
#define CKO_DATA                     0UL
#define CKO_PUBLIC_KEY               2UL
#define CKO_PRIVATE_KEY              3UL
#define CKK_GENERIC_SECRET           0x10UL
#define CKK_AES                      0x1FUL
#define CKM_RSA_PKCS_KEY_PAIR_GEN    0x000UL
#define CKM_GENERIC_SECRET_KEY_GEN   0x350UL
#define CKM_EC_KEY_PAIR_GEN          0x1040UL
#define CKM_AES_KEY_GEN              0x1080UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-68s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
static CK_SESSION_HANDLE s;

/* How many objects match; the first in *first. */
static CK_ULONG count(CK_ATTRIBUTE *t, CK_ULONG n, CK_OBJECT_HANDLE *first) {
    CK_OBJECT_HANDLE h[64]; CK_ULONG got = 0;
    if (C_FindObjectsInit(s, t, n) != CKR_OK) return (CK_ULONG)-1;
    (void)C_FindObjects(s, h, 64, &got);
    (void)C_FindObjectsFinal(s);
    if (first) *first = got ? h[0] : 0;
    return got;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                               CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(lib, #n); \
                   if (!n) { fprintf(stderr, "missing %s\n", #n); return 2; }
    SYM(C_Initialize) SYM(C_Finalize) SYM(C_InitToken) SYM(C_OpenSession) SYM(C_Login)
    SYM(C_Logout) SYM(C_InitPIN) SYM(C_GenerateKey) SYM(C_GenerateKeyPair)
    SYM(C_CreateObject) SYM(C_FindObjectsInit) SYM(C_FindObjects) SYM(C_FindObjectsFinal)
    SYM(C_GetAttributeValue)

    printf("Templates the module did not honour\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "tmplchk", 7);
    if (C_Initialize(NULL) || C_InitToken(0, (CK_BYTE *)SO_PIN, strlen(SO_PIN), label)
        || C_OpenSession(0, CKF_RW, NULL, NULL, &s)
        || C_Login(s, 0, (CK_BYTE *)SO_PIN, strlen(SO_PIN))
        || C_InitPIN(s, (CK_BYTE *)USER_PIN, strlen(USER_PIN))
        || C_Logout(s)
        || C_Login(s, 1, (CK_BYTE *)USER_PIN, strlen(USER_PIN))) {
        fprintf(stderr, "token setup failed\n"); return 2;
    }

    CK_BYTE yes = 1, no = 0;
    CK_RV rv;
    char what[96];
    CK_OBJECT_HANDLE h = 0, h2 = 0;

    /* (1) C5 */
    {
        static CK_BYTE f4[] = { 1, 0, 1 };
        CK_ATTRIBUTE pt[] = { { CKA_VERIFY, &yes, 1 }, { CKA_PUBLIC_EXPONENT, f4, 3 } };
        CK_ATTRIBUTE vt[] = { { CKA_SIGN, &yes, 1 } };
        CK_MECHANISM m = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
        rv = C_GenerateKeyPair(s, &m, pt, 2, vt, 1, &h, &h2);
        snprintf(what, sizeof what, "(1) RSA without CKA_MODULUS_BITS: TEMPLATE_INCOMPLETE (0x%lx)", rv);
        ok(rv == CKR_TEMPLATE_INCOMPLETE, what);
    }

    /* (2) C7 */
    CK_ULONG len16 = 16, gen = CKK_GENERIC_SECRET, aes = CKK_AES, pubc = CKO_PUBLIC_KEY;
    CK_MECHANISM ag = { CKM_AES_KEY_GEN, NULL, 0 };
    {
        CK_ATTRIBUTE t1[] = { { CKA_VALUE_LEN, &len16, sizeof len16 }, { CKA_KEY_TYPE, &gen, sizeof gen } };
        rv = C_GenerateKey(s, &ag, t1, 2, &h);
        snprintf(what, sizeof what, "(2) AES_KEY_GEN, CKK_GENERIC_SECRET: TEMPLATE_INCONSISTENT (0x%lx)", rv);
        ok(rv == CKR_TEMPLATE_INCONSISTENT, what);
        CK_ATTRIBUTE t2[] = { { CKA_VALUE_LEN, &len16, sizeof len16 }, { CKA_CLASS, &pubc, sizeof pubc } };
        rv = C_GenerateKey(s, &ag, t2, 2, &h);
        snprintf(what, sizeof what, "(2) AES_KEY_GEN, CKO_PUBLIC_KEY: TEMPLATE_INCONSISTENT (0x%lx)", rv);
        ok(rv == CKR_TEMPLATE_INCONSISTENT, what);
        CK_ATTRIBUTE t3[] = { { CKA_VALUE_LEN, &len16, sizeof len16 }, { CKA_KEY_TYPE, &aes, sizeof aes } };
        ok(C_GenerateKey(s, &ag, t3, 2, &h) == CKR_OK, "(2) AES_KEY_GEN, CKK_AES: generates");
    }

    /* (3) C8 */
    {
        CK_ATTRIBUTE t1[] = { { CKA_VALUE_LEN, &len16, sizeof len16 }, { CKA_ALWAYS_SENSITIVE, &yes, 1 } };
        rv = C_GenerateKey(s, &ag, t1, 2, &h);
        snprintf(what, sizeof what, "(3) C_GenerateKey, CKA_ALWAYS_SENSITIVE: READ_ONLY (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_READ_ONLY, what);
        CK_ATTRIBUTE t2[] = { { CKA_VALUE_LEN, &len16, sizeof len16 }, { CKA_LOCAL, &yes, 1 } };
        rv = C_GenerateKey(s, &ag, t2, 2, &h);
        snprintf(what, sizeof what, "(3) C_GenerateKey, CKA_LOCAL: READ_ONLY (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_READ_ONLY, what);
        CK_ULONG dc = CKO_DATA;
        CK_ATTRIBUTE t3[] = { { CKA_CLASS, &dc, sizeof dc }, { CKA_VALUE, (void *)"x", 1 },
                              { CKA_LOCAL, &no, 1 } };
        rv = C_CreateObject(s, t3, 3, &h);
        snprintf(what, sizeof what, "(3) C_CreateObject, CKA_LOCAL: READ_ONLY (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_READ_ONLY, what);
    }

    /* (4) C9 */
    {
        CK_ULONG prc = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE pc = { CKA_CLASS, &prc, sizeof prc };
        CK_ULONG before = count(&pc, 1, NULL);
        static CK_BYTE p256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
        CK_ATTRIBUTE pt[] = { { CKA_EC_PARAMS, p256, sizeof p256 }, { CKA_VERIFY, &yes, 1 } };
        CK_ATTRIBUTE vt[] = { { CKA_SIGN, &yes, 1 }, { CKA_UNIQUE_ID, (void *)"mine", 4 } };
        CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
        rv = C_GenerateKeyPair(s, &m, pt, 2, vt, 2, &h, &h2);
        snprintf(what, sizeof what, "(4) CKA_UNIQUE_ID in the private template: READ_ONLY (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_READ_ONLY, what);
        ok(count(&pc, 1, NULL) == before, "(4) and no private key is added");
    }

    /* (5) C11 */
    {
        CK_ULONG dc = CKO_DATA;
        CK_ATTRIBUTE dt[] = { { CKA_CLASS, &dc, sizeof dc }, { CKA_TOKEN, &no, 1 },
                              { CKA_LABEL, (void *)"sess-obj", 8 }, { CKA_VALUE, (void *)"v", 1 } };
        if (C_CreateObject(s, dt, 4, &h) != CKR_OK) { fprintf(stderr, "session object\n"); return 2; }
        CK_ULONG zero4 = 0;   /* four (or eight) zero bytes, not a CK_BBOOL */
        CK_ATTRIBUTE f1[] = { { CKA_TOKEN, &zero4, 4 } };
        ok(count(f1, 1, NULL) == 0, "(5) a 4-byte CKA_TOKEN of zeros finds nothing");
        CK_ATTRIBUTE f2[] = { { CKA_TOKEN, &no, 1 }, { CKA_LABEL, (void *)"sess-obj", 8 } };
        CK_OBJECT_HANDLE got = 0;
        ok(count(f2, 2, &got) == 1 && got == h, "(5) CKA_TOKEN=FALSE finds the session object");
        CK_ATTRIBUTE f3[] = { { CKA_TOKEN, &yes, 1 }, { CKA_LABEL, (void *)"sess-obj", 8 } };
        ok(count(f3, 2, NULL) == 0, "(5) CKA_TOKEN=TRUE does not");

        CK_ULONG l32 = 32;
        CK_MECHANISM gg = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };
        CK_ATTRIBUTE gt[] = { { CKA_VALUE_LEN, &l32, sizeof l32 }, { CKA_LABEL, (void *)"kt-test", 7 } };
        CK_ATTRIBUTE at[] = { { CKA_VALUE_LEN, &len16, sizeof len16 }, { CKA_LABEL, (void *)"kt-test", 7 } };
        CK_OBJECT_HANDLE gk = 0, ak = 0;
        if (C_GenerateKey(s, &gg, gt, 2, &gk) != CKR_OK || C_GenerateKey(s, &ag, at, 2, &ak) != CKR_OK) {
            fprintf(stderr, "keys for (5)\n"); return 2;
        }
        CK_ATTRIBUTE f4[] = { { CKA_LABEL, (void *)"kt-test", 7 }, { CKA_KEY_TYPE, &aes, sizeof aes } };
        ok(count(f4, 2, &got) == 1 && got == ak, "(5) CKA_KEY_TYPE=AES finds the AES key, not the generic one");
        unsigned int dc4 = 0;
        CK_ATTRIBUTE f5[] = { { CKA_CLASS, &dc4, 4 } };
        ok(count(f5, 1, NULL) == 0, "(5) a 4-byte CKA_CLASS finds nothing");
    }

    /* (6) C6 */
    {
        CK_ULONG bits = 2048;
        CK_MECHANISM m = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
        CK_ATTRIBUTE vt[] = { { CKA_SIGN, &yes, 1 } };
        static CK_BYTE e65539[] = { 0x01, 0x00, 0x03 }, e3[] = { 0x03 };
        CK_ATTRIBUTE pt[] = { { CKA_MODULUS_BITS, &bits, sizeof bits }, { CKA_VERIFY, &yes, 1 },
                              { CKA_PUBLIC_EXPONENT, e65539, sizeof e65539 } };
        CK_BYTE eb[8]; CK_ATTRIBUTE ea = { CKA_PUBLIC_EXPONENT, eb, sizeof eb };
        rv = C_GenerateKeyPair(s, &m, pt, 3, vt, 1, &h, &h2);
        ok(rv == CKR_OK && C_GetAttributeValue(s, h, &ea, 1) == CKR_OK
           && ea.ulValueLen == 3 && memcmp(eb, e65539, 3) == 0,
           "(6) RSA, CKA_PUBLIC_EXPONENT 65539: the key has 65539");
        pt[2].pValue = e3; pt[2].ulValueLen = 1;
        rv = C_GenerateKeyPair(s, &m, pt, 3, vt, 1, &h, &h2);
        snprintf(what, sizeof what, "(6) RSA, e = 3: ATTRIBUTE_VALUE_INVALID (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_VALUE_INVALID, what);
    }

    /* (7) C10 */
    {
        CK_ULONG dc = CKO_DATA;
        static CK_BYTE oid[] = { 0x06, 0x03, 0x2A, 0x03, 0x04 };
        CK_ATTRIBUTE dt[] = { { CKA_CLASS, &dc, sizeof dc }, { CKA_VALUE, (void *)"v", 1 },
                              { CKA_OBJECT_ID, oid, sizeof oid } };
        rv = C_CreateObject(s, dt, 3, &h);
        snprintf(what, sizeof what, "(7) data object with CKA_OBJECT_ID: TYPE_INVALID (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_TYPE_INVALID, what);
    }

    C_Finalize(NULL);
    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
