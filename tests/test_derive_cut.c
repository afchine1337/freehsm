/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_derive_cut.c --- a protected key is not cut short by a derivation
 * that copies its bytes (#48).
 *
 * A key holding the first n bytes of a sensitive key, all but the last
 * known, answers an HMAC that a caller matches against 256 guesses; n + 1
 * gives the next byte. The derived key kept the base's protection, which
 * kept its value from being read, not from being used: a logged-in user
 * recovered a 32-byte generic secret in 32 derivations, and an AES-256 key
 * in 33 through a concatenation onto a known base.
 *
 *   (X) CKM_XOR_BASE_AND_DATA: data shorter than a sensitive base, or than
 *       an unextractable one, is CKR_KEY_FUNCTION_NOT_PERMITTED; as long or
 *       longer is taken; from a base in the clear, shorter is taken. Where
 *       NIST's rules apply the mechanism is refused (it is not approved).
 *   (C) the report's AES-256 victim, concatenated onto a known 16-byte
 *       base: the 48-byte result is made, and cutting it to 17 bytes is
 *       refused.
 *   (E) CKM_EXTRACT_KEY_FROM_KEY: 4 of the 32 bytes of a sensitive base are
 *       refused, of a base in the clear taken (permissive mode only).
 *   (I) CKM_IKE1_EXTENDED_DERIVE without g^xy: SKEYID_e cut to 16 bytes is
 *       refused from a sensitive SKEYID_e, taken in the clear and at its
 *       full length (permissive mode only).
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
typedef struct { CK_BYTE *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;
typedef struct { CK_ULONG prfMechanism; CK_BYTE bHasKeygxy; CK_OBJECT_HANDLE hKeygxy;
                 CK_BYTE *pExtraData; CK_ULONG ulExtraDataLen; } CK_IKE1_EXTENDED_DERIVE_PARAMS;

#define CKR_OK                         0x000UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED 0x068UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_AES                        0x1FUL
#define CKK_SHA256_HMAC                0x2BUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_SIGN                       0x108UL
#define CKA_DERIVE                     0x10CUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKM_SHA256_HMAC                0x0251UL
#define CKM_CONCATENATE_BASE_AND_KEY   0x0360UL
#define CKM_XOR_BASE_AND_DATA          0x0364UL
#define CKM_EXTRACT_KEY_FROM_KEY       0x0365UL
#define CKM_IKE1_EXTENDED_DERIVE       0x4031UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);

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

/* A secret key of type kt and vl bytes, CKA_DERIVE and CKA_SIGN, with the
 * given CKA_SENSITIVE and CKA_EXTRACTABLE. */
static CK_OBJECT_HANDLE key(CK_ULONG kt, CK_BYTE fill, CK_ULONG vl, CK_BYTE sens, CK_BYTE extr) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_BYTE v[48];
    for (CK_ULONG i = 0; i < vl; i++) v[i] = (CK_BYTE)(fill + 7 * i);
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &sens, 1 },
                         { CKA_EXTRACTABLE, &extr, 1 }, { CKA_DERIVE, &yes, 1 },
                         { CKA_SIGN, &yes, 1 }, { CKA_VALUE, v, vl } };
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, 8, &h) == CKR_OK ? h : 0;
}

/* A derived generic secret, as the report asks it: CKA_SIGN, nothing said
 * about its protection, which it takes from the base. */
static CK_ULONG cls_s = CKO_SECRET_KEY, gen = CKK_GENERIC_SECRET;

static CK_RV xor_cut(CK_OBJECT_HANDLE base, CK_ULONG dl, CK_OBJECT_HANDLE *h) {
    CK_BYTE zeros[64] = { 0 };
    CK_KEY_DERIVATION_STRING_DATA p = { zeros, dl };
    CK_MECHANISM m = { CKM_XOR_BASE_AND_DATA, &p, sizeof p };
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls_s, sizeof cls_s }, { CKA_KEY_TYPE, &gen, sizeof gen },
                         { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    *h = 0;
    return C_DeriveKey(s, &m, base, t, 4, h);
}

static CK_ULONG value_len(CK_OBJECT_HANDLE h) {
    CK_ULONG v = 0;
    CK_ATTRIBUTE a = { CKA_VALUE_LEN, &v, sizeof v };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? v : 0;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_GetAttributeValue); SYM(C_DeriveKey);
    if (!C_DeriveKey || !C_CreateObject) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("A protected key is not cut short by a derivation (#48)\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "derivecut", 9);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const char *mode = getenv("FHSM_MODE");
    const int strict = mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips"));
    const int permissive = !strict && listed(CKM_EXTRACT_KEY_FROM_KEY);
    const int xor_ok = !strict && listed(CKM_XOR_BASE_AND_DATA);
    char what[160];
    CK_OBJECT_HANDLE h = 0;
    CK_RV rv;

    CK_OBJECT_HANDLE sens = key(CKK_GENERIC_SECRET, 0x11, 32, 1, 0),
                     unext = key(CKK_GENERIC_SECRET, 0x22, 32, 0, 0),
                     clear = key(CKK_GENERIC_SECRET, 0x33, 32, 0, 1);
    if (!sens || !unext || !clear) { fprintf(stderr, "keys\n"); return 2; }

    /* --- (X) CKM_XOR_BASE_AND_DATA --------------------------------------- */
    if (!xor_ok) {
        rv = xor_cut(clear, 32, &h);
        snprintf(what, sizeof what, "(X) XOR_BASE_AND_DATA not approved: refused (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_INVALID, what);
    } else {
        rv = xor_cut(sens, 1, &h);
        snprintf(what, sizeof what, "(X) one byte of a sensitive base: refused (0x%lx)", rv);
        ok(rv == CKR_KEY_FUNCTION_NOT_PERMITTED && h == 0, what);
        rv = xor_cut(sens, 31, &h);
        snprintf(what, sizeof what, "(X) 31 bytes of it: refused (0x%lx)", rv);
        ok(rv == CKR_KEY_FUNCTION_NOT_PERMITTED, what);
        rv = xor_cut(unext, 16, &h);
        snprintf(what, sizeof what, "(X) 16 bytes of an unextractable base: refused (0x%lx)", rv);
        ok(rv == CKR_KEY_FUNCTION_NOT_PERMITTED, what);
        rv = xor_cut(sens, 32, &h);
        snprintf(what, sizeof what, "(X) 32 bytes of the sensitive base: made (0x%lx)", rv);
        ok(rv == CKR_OK && value_len(h) == 32, what);
        rv = xor_cut(sens, 40, &h);
        snprintf(what, sizeof what, "(X) 40 bytes, longer than the base: made (0x%lx)", rv);
        ok(rv == CKR_OK && value_len(h) == 40, what);
        rv = xor_cut(clear, 1, &h);
        snprintf(what, sizeof what, "(X) one byte of a base in the clear: made (0x%lx)", rv);
        ok(rv == CKR_OK && value_len(h) == 1, what);

        /* --- (C) the report's victim, through the concatenation ---------- */
        CK_OBJECT_HANDLE victim = key(CKK_AES, 0x80, 32, 1, 0);
        CK_OBJECT_HANDLE known = key(CKK_GENERIC_SECRET, 0x01, 16, 0, 1);
        if (!victim || !known) { fprintf(stderr, "victim\n"); return 2; }
        CK_MECHANISM cm = { CKM_CONCATENATE_BASE_AND_KEY, &victim, sizeof victim };
        CK_ATTRIBUTE ct[] = { { CKA_CLASS, &cls_s, sizeof cls_s }, { CKA_KEY_TYPE, &gen, sizeof gen },
                              { CKA_TOKEN, &no, 1 }, { CKA_DERIVE, &yes, 1 } };
        CK_OBJECT_HANDLE cat = 0;
        rv = C_DeriveKey(s, &cm, known, ct, 4, &cat);
        snprintf(what, sizeof what, "(C) known 16 bytes || AES-256 victim: 48 bytes (0x%lx)", rv);
        ok(rv == CKR_OK && value_len(cat) == 48, what);
        rv = xor_cut(cat, 17, &h);
        snprintf(what, sizeof what, "(C) cut to 17 bytes, one unknown: refused (0x%lx)", rv);
        ok(rv == CKR_KEY_FUNCTION_NOT_PERMITTED, what);
    }

    /* --- (E) CKM_EXTRACT_KEY_FROM_KEY ------------------------------------ */
    if (permissive) {
        CK_ULONG bit = 0, l4 = 4;
        CK_MECHANISM m = { CKM_EXTRACT_KEY_FROM_KEY, &bit, sizeof bit };
        CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls_s, sizeof cls_s }, { CKA_KEY_TYPE, &gen, sizeof gen },
                             { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 },
                             { CKA_VALUE_LEN, &l4, sizeof l4 } };
        rv = C_DeriveKey(s, &m, sens, t, 5, &h);
        snprintf(what, sizeof what, "(E) 4 bytes of a sensitive base: refused (0x%lx)", rv);
        ok(rv == CKR_KEY_FUNCTION_NOT_PERMITTED, what);
        rv = C_DeriveKey(s, &m, clear, t, 5, &h);
        snprintf(what, sizeof what, "(E) 4 bytes of a base in the clear: made (0x%lx)", rv);
        ok(rv == CKR_OK && value_len(h) == 4, what);
    } else printf("  (E) CKM_EXTRACT_KEY_FROM_KEY: not in this build or mode\n");

    /* --- (I) CKM_IKE1_EXTENDED_DERIVE, SKEYID_e cut ----------------------- */
    if (permissive && listed(CKM_IKE1_EXTENDED_DERIVE)) {
        CK_OBJECT_HANDLE ske = key(CKK_SHA256_HMAC, 0x44, 32, 1, 0),
                         skc = key(CKK_SHA256_HMAC, 0x55, 32, 0, 1);
        if (!ske || !skc) { fprintf(stderr, "SKEYID_e\n"); return 2; }
        CK_IKE1_EXTENDED_DERIVE_PARAMS p = { CKM_SHA256_HMAC, 0, 0, NULL, 0 };
        CK_MECHANISM m = { CKM_IKE1_EXTENDED_DERIVE, &p, sizeof p };
        CK_ULONG l16 = 16, l32 = 32;
        CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls_s, sizeof cls_s }, { CKA_KEY_TYPE, &gen, sizeof gen },
                             { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 },
                             { CKA_VALUE_LEN, &l16, sizeof l16 } };
        rv = C_DeriveKey(s, &m, ske, t, 5, &h);
        snprintf(what, sizeof what, "(I) 16 bytes of a sensitive SKEYID_e: refused (0x%lx)", rv);
        ok(rv == CKR_KEY_FUNCTION_NOT_PERMITTED, what);
        rv = C_DeriveKey(s, &m, skc, t, 5, &h);
        snprintf(what, sizeof what, "(I) 16 bytes of one in the clear: made (0x%lx)", rv);
        ok(rv == CKR_OK && value_len(h) == 16, what);
        t[4].pValue = &l32;
        rv = C_DeriveKey(s, &m, ske, t, 5, &h);
        snprintf(what, sizeof what, "(I) all 32 bytes of the sensitive one: made (0x%lx)", rv);
        ok(rv == CKR_OK && value_len(h) == 32, what);
    } else printf("  (I) CKM_IKE1_EXTENDED_DERIVE: not in this build or mode\n");

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
