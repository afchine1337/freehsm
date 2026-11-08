/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_ecdh_key_len.c --- CKM_ECDH1_DERIVE with CKD_NULL: the key's length,
 * and no shared data.
 *
 * PKCS#11 v3.2 §6.3.16: the mechanism "truncates the result according to the
 * CKA_KEY_TYPE attribute of the template and, if it has one and the key type
 * supports it, the CKA_VALUE_LEN attribute of the template. (The truncation
 * removes bytes from the leading end of the secret value.)" And with
 * CKD_NULL, "pSharedData must be NULL and ulSharedDataLen must be zero".
 * The module stored all of Z whatever the template asked, and ignored
 * shared data. Reported by AlexLaroche (#33, C15, C16, C17).
 *
 * What is asserted, between two P-256 keys made by the module (Z is 32
 * bytes), and one P-384 pair (48):
 *   (1) generic secret, no CKA_VALUE_LEN: all of Z
 *   (2) generic secret, CKA_VALUE_LEN 16: Z's last 16 bytes
 *   (3) CKA_VALUE_LEN 33, and 0: CKR_ATTRIBUTE_VALUE_INVALID
 *   (4) AES, CKA_VALUE_LEN 13: CKR_ATTRIBUTE_VALUE_INVALID; 16: Z's last 16
 *       bytes; none: all 32
 *   (5) AES without CKA_VALUE_LEN on P-384, a 48-byte Z:
 *       CKR_TEMPLATE_INCOMPLETE; with 32: Z's last 32 bytes
 *   (6) CKD_NULL with 6 bytes of shared data: CKR_MECHANISM_PARAM_INVALID
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG kdf; CK_ULONG ulSharedDataLen; void *pSharedData;
                 CK_ULONG ulPublicDataLen; void *pPublicData; } CK_ECDH1_DERIVE_PARAMS;

#define CKR_OK                       0UL
#define CKR_ATTRIBUTE_VALUE_INVALID  0x13UL
#define CKR_MECHANISM_PARAM_INVALID  0x71UL
#define CKR_TEMPLATE_INCOMPLETE      0xD0UL
#define CKF_RW              6UL
#define CKA_CLASS           0x000UL
#define CKA_VALUE           0x011UL
#define CKA_KEY_TYPE        0x100UL
#define CKA_SENSITIVE       0x103UL
#define CKA_DERIVE          0x10CUL
#define CKA_VALUE_LEN       0x161UL
#define CKA_EXTRACTABLE     0x162UL
#define CKA_EC_PARAMS       0x180UL
#define CKA_EC_POINT        0x181UL
#define CKO_SECRET_KEY      4UL
#define CKK_GENERIC_SECRET  0x10UL
#define CKK_AES             0x1FUL
#define CKM_EC_KEY_PAIR_GEN 0x1040UL
#define CKM_ECDH1_DERIVE    0x1050UL
#define CKD_NULL            1UL

#define SO_PIN   "So-Pin-ecdhl"
#define USER_PIN "Us-Pin-ecdhl"

static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,
                            CK_ULONG,CK_OBJECT_HANDLE*);

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;

/* A key pair on the curve `oid`; the public point into pt / *pl. */
static CK_OBJECT_HANDLE pair(const CK_BYTE *oid, CK_ULONG oid_len, CK_BYTE *pt, CK_ULONG *pl) {
    CK_BYTE t = 1;
    CK_ATTRIBUTE pub_t[] = { { CKA_EC_PARAMS, (void *)oid, oid_len }, { CKA_DERIVE, &t, 1 } };
    CK_ATTRIBUTE prv_t[] = { { CKA_DERIVE, &t, 1 } };
    CK_MECHANISM kg = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE pub = 0, prv = 0;
    if (C_GenerateKeyPair(s, &kg, pub_t, 2, prv_t, 1, &pub, &prv) != CKR_OK) return 0;
    CK_ATTRIBUTE q = { CKA_EC_POINT, pt, *pl };
    if (C_GetAttributeValue(s, pub, &q, 1) != CKR_OK) return 0;
    *pl = q.ulValueLen;
    return prv;
}

/* Derive from `base` and the peer point; key type `kt`, CKA_VALUE_LEN `vl`
 * unless it is (CK_ULONG)-1, shared data when `sd` is set. The value read
 * back into out / *ol. */
static CK_RV derive(CK_OBJECT_HANDLE base, CK_BYTE *pt, CK_ULONG pl, CK_ULONG kt,
                    CK_ULONG vl, int sd, CK_BYTE *out, CK_ULONG *ol) {
    static CK_BYTE shared[6] = { 1, 2, 3, 4, 5, 6 };
    CK_ECDH1_DERIVE_PARAMS p = { CKD_NULL, sd ? 6 : 0, sd ? shared : NULL, pl, pt };
    CK_MECHANISM m = { CKM_ECDH1_DERIVE, &p, sizeof p };
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_BYTE f = 0, t = 1;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
        { CKA_SENSITIVE, &f, 1 }, { CKA_EXTRACTABLE, &t, 1 },
        { CKA_VALUE_LEN, &vl, sizeof vl },
    };
    CK_OBJECT_HANDLE k = 0;
    CK_RV rv = C_DeriveKey(s, &m, base, tmpl, vl == (CK_ULONG)-1 ? 4 : 5, &k);
    if (rv != CKR_OK) return rv;
    CK_ATTRIBUTE v = { CKA_VALUE, out, *ol };
    rv = C_GetAttributeValue(s, k, &v, 1);
    *ol = v.ulValueLen;
    return rv;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(lib, #n); \
                   if (!n) { fprintf(stderr, "missing %s\n", #n); return 2; }
    SYM(C_Initialize) SYM(C_InitToken) SYM(C_OpenSession) SYM(C_Login)
    SYM(C_Logout) SYM(C_InitPIN) SYM(C_GenerateKeyPair) SYM(C_GetAttributeValue)
    SYM(C_DeriveKey)

    printf("CKM_ECDH1_DERIVE, CKD_NULL: key length and shared data\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "ecdhlen", 7);
    if (C_Initialize(NULL) || C_InitToken(0, (CK_BYTE *)SO_PIN, strlen(SO_PIN), label)
        || C_OpenSession(0, CKF_RW, NULL, NULL, &s)
        || C_Login(s, 0, (CK_BYTE *)SO_PIN, strlen(SO_PIN))
        || C_InitPIN(s, (CK_BYTE *)USER_PIN, strlen(USER_PIN))
        || C_Logout(s)
        || C_Login(s, 1, (CK_BYTE *)USER_PIN, strlen(USER_PIN))) {
        fprintf(stderr, "token setup failed\n"); return 2;
    }

    static const CK_BYTE p256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
    static const CK_BYTE p384[] = { 0x06,0x05,0x2B,0x81,0x04,0x00,0x22 };
    CK_BYTE pa[160], pb[160];
    CK_ULONG la = sizeof pa, lb = sizeof pb;
    CK_OBJECT_HANDLE a = pair(p256, sizeof p256, pa, &la);
    CK_OBJECT_HANDLE b = pair(p256, sizeof p256, pb, &lb);
    if (!a || !b) { fprintf(stderr, "P-256 key pairs\n"); return 2; }
    (void)la;

    const CK_ULONG NONE = (CK_ULONG)-1;
    CK_BYTE z[66], v[66];
    CK_ULONG zl = sizeof z, vl;
    CK_RV rv;
    char what[96];

    /* (1) */
    ok(derive(a, pb, lb, CKK_GENERIC_SECRET, NONE, 0, z, &zl) == CKR_OK && zl == 32,
       "(1) generic secret, no CKA_VALUE_LEN: the 32 bytes of Z");

    /* (2) */
    vl = sizeof v;
    ok(derive(a, pb, lb, CKK_GENERIC_SECRET, 16, 0, v, &vl) == CKR_OK
       && vl == 16 && memcmp(v, z + 16, 16) == 0,
       "(2) CKA_VALUE_LEN 16: Z's last 16 bytes");

    /* (3) */
    vl = sizeof v; rv = derive(a, pb, lb, CKK_GENERIC_SECRET, 33, 0, v, &vl);
    snprintf(what, sizeof what, "(3) CKA_VALUE_LEN 33: CKR_ATTRIBUTE_VALUE_INVALID (0x%lx)", rv);
    ok(rv == CKR_ATTRIBUTE_VALUE_INVALID, what);
    vl = sizeof v; rv = derive(a, pb, lb, CKK_GENERIC_SECRET, 0, 0, v, &vl);
    snprintf(what, sizeof what, "(3) CKA_VALUE_LEN 0: CKR_ATTRIBUTE_VALUE_INVALID (0x%lx)", rv);
    ok(rv == CKR_ATTRIBUTE_VALUE_INVALID, what);

    /* (4) */
    vl = sizeof v; rv = derive(a, pb, lb, CKK_AES, 13, 0, v, &vl);
    snprintf(what, sizeof what, "(4) AES, CKA_VALUE_LEN 13: CKR_ATTRIBUTE_VALUE_INVALID (0x%lx)", rv);
    ok(rv == CKR_ATTRIBUTE_VALUE_INVALID, what);
    vl = sizeof v;
    ok(derive(a, pb, lb, CKK_AES, 16, 0, v, &vl) == CKR_OK
       && vl == 16 && memcmp(v, z + 16, 16) == 0,
       "(4) AES, CKA_VALUE_LEN 16: Z's last 16 bytes");
    vl = sizeof v;
    ok(derive(a, pb, lb, CKK_AES, NONE, 0, v, &vl) == CKR_OK
       && vl == 32 && memcmp(v, z, 32) == 0,
       "(4) AES, no CKA_VALUE_LEN: all 32 bytes");

    /* (5) */
    {
        CK_BYTE qa[160], qb[160];
        CK_ULONG ma = sizeof qa, mb = sizeof qb;
        CK_OBJECT_HANDLE c = pair(p384, sizeof p384, qa, &ma);
        CK_OBJECT_HANDLE d = pair(p384, sizeof p384, qb, &mb);
        if (!c || !d) { fprintf(stderr, "P-384 key pairs\n"); return 2; }
        CK_BYTE z3[66]; CK_ULONG z3l = sizeof z3;
        int full = derive(c, qb, mb, CKK_GENERIC_SECRET, NONE, 0, z3, &z3l) == CKR_OK
                && z3l == 48;
        vl = sizeof v; rv = derive(c, qb, mb, CKK_AES, NONE, 0, v, &vl);
        snprintf(what, sizeof what, "(5) P-384, AES, no CKA_VALUE_LEN: CKR_TEMPLATE_INCOMPLETE (0x%lx)", rv);
        ok(full && rv == CKR_TEMPLATE_INCOMPLETE, what);
        vl = sizeof v;
        ok(full && derive(c, qb, mb, CKK_AES, 32, 0, v, &vl) == CKR_OK
           && vl == 32 && memcmp(v, z3 + 16, 32) == 0,
           "(5) P-384, AES, CKA_VALUE_LEN 32: Z's last 32 bytes");
    }

    /* (6) */
    vl = sizeof v; rv = derive(a, pb, lb, CKK_GENERIC_SECRET, NONE, 1, v, &vl);
    snprintf(what, sizeof what, "(6) CKD_NULL with shared data: CKR_MECHANISM_PARAM_INVALID (0x%lx)", rv);
    ok(rv == CKR_MECHANISM_PARAM_INVALID, what);

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
