/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_hmac_general.c --- the *_HMAC_GENERAL mechanisms (2.8.0).
 *
 * Each is its HMAC, truncated to the length CK_MAC_GENERAL_PARAMS gives. For
 * the eleven hashes, with one generic secret key:
 *   (I) C_GetMechanismInfo states sign and verify;
 *   (S) a 10-byte MAC is the first 10 bytes of the full HMAC, and one at the
 *       full length is the full HMAC;
 *   (M) the same MAC, signed in three parts;
 *   (V) it verifies, single-part and in parts; one byte shorter, or with a
 *       byte changed, it does not;
 *   (P) no parameter, a length of 0 and one past the hash's output are
 *       CKR_MECHANISM_PARAM_INVALID; 3 bytes is taken where NIST's rules do
 *       not apply and refused where they do (SP 800-107 rev. 1 §5.3.3).
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
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize; CK_FLAGS flags; } CK_MECHANISM_INFO;

#define CKR_OK                       0x000UL
#define CKR_MECHANISM_PARAM_INVALID  0x071UL
#define CKR_SIGNATURE_INVALID        0x0C0UL
#define CKF_RW                       6UL
#define CKF_SIGN                     0x0800UL
#define CKF_VERIFY                   0x2000UL
#define CKA_TOKEN                    0x001UL
#define CKA_SIGN                     0x108UL
#define CKA_VERIFY                   0x10AUL
#define CKA_VALUE_LEN                0x161UL
#define CKM_RSA_PKCS                 0x001UL
#define CKM_GENERIC_SECRET_KEY_GEN   0x350UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);
static CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_ULONG, CK_MECHANISM_INFO*);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-70s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_OBJECT_HANDLE key;
static CK_BYTE msg[] = "The *_HMAC_GENERAL mechanisms truncate the HMAC.";
#define MSG_LEN (sizeof msg - 1)

/* Sign msg; general: mech with a length parameter of `len`. */
static CK_RV sign(CK_ULONG mech, const CK_ULONG *len, CK_BYTE *out, CK_ULONG *ol) {
    CK_ULONG l = len ? *len : 0;
    CK_MECHANISM m = { mech, len ? &l : NULL, len ? sizeof l : 0 };
    CK_RV rv = C_SignInit(s, &m, key);
    if (rv != CKR_OK) return rv;
    *ol = 64;
    return C_Sign(s, msg, MSG_LEN, out, ol);
}

static CK_RV sign_parts(CK_ULONG mech, CK_ULONG len, CK_BYTE *out, CK_ULONG *ol) {
    CK_MECHANISM m = { mech, &len, sizeof len };
    CK_RV rv = C_SignInit(s, &m, key);
    if (rv != CKR_OK) return rv;
    if ((rv = C_SignUpdate(s, msg, 7)) != CKR_OK) return rv;
    if ((rv = C_SignUpdate(s, msg + 7, 20)) != CKR_OK) return rv;
    if ((rv = C_SignUpdate(s, msg + 27, MSG_LEN - 27)) != CKR_OK) return rv;
    *ol = 64;
    return C_SignFinal(s, out, ol);
}

static CK_RV verify(CK_ULONG mech, CK_ULONG len, CK_BYTE *sig, CK_ULONG sl, int parts) {
    CK_MECHANISM m = { mech, &len, sizeof len };
    CK_RV rv = C_VerifyInit(s, &m, key);
    if (rv != CKR_OK) return rv;
    if (!parts) return C_Verify(s, msg, MSG_LEN, sig, sl);
    if ((rv = C_VerifyUpdate(s, msg, 30)) != CKR_OK) return rv;
    if ((rv = C_VerifyUpdate(s, msg + 30, MSG_LEN - 30)) != CKR_OK) return rv;
    return C_VerifyFinal(s, sig, sl);
}

static CK_RV init_only(CK_ULONG mech, void *param, CK_ULONG plen) {
    CK_MECHANISM m = { mech, param, plen };
    CK_RV rv = C_SignInit(s, &m, key);
    if (rv == CKR_OK) {   /* finish it, so the next Init is not OPERATION_ACTIVE */
        CK_BYTE out[64]; CK_ULONG ol = sizeof out;
        (void)C_Sign(s, msg, MSG_LEN, out, &ol);
    }
    return rv;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_GetMechanismInfo); SYM(C_GenerateKey); SYM(C_SignInit); SYM(C_Sign);
    SYM(C_SignUpdate); SYM(C_SignFinal); SYM(C_VerifyInit); SYM(C_Verify);
    SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    if (!C_GenerateKey || !C_VerifyFinal) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("The *_HMAC_GENERAL mechanisms\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "hmacgen", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    /* Where NIST's rules apply: the nist-approved-only build (no CKM_RSA_PKCS
     * in the list) or strict mode. */
    int nist = 0;
    {
        CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
        CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
        C_GetMechanismList(0, ml, &n);
        nist = 1;
        for (CK_ULONG i = 0; i < n; i++) if (ml[i] == CKM_RSA_PKCS) nist = 0;
        free(ml);
        const char *mode = getenv("FHSM_MODE");
        if (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips"))) nist = 1;
    }

    CK_BYTE yes = 1, no = 0;
    CK_ULONG klen = 32;
    CK_MECHANISM kg = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };
    CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 },
                          { CKA_VERIFY, &yes, 1 }, { CKA_VALUE_LEN, &klen, sizeof klen } };
    if (C_GenerateKey(s, &kg, kt, 4, &key) != CKR_OK) { fprintf(stderr, "key\n"); return 2; }

    static const struct { const char *name; CK_ULONG hmac, general, full; } H[] = {
        { "SHA-1",       0x221, 0x222, 20 }, { "SHA-224",     0x256, 0x257, 28 },
        { "SHA-256",     0x251, 0x252, 32 }, { "SHA-384",     0x261, 0x262, 48 },
        { "SHA-512",     0x271, 0x272, 64 }, { "SHA-512/224", 0x049, 0x04A, 28 },
        { "SHA-512/256", 0x04D, 0x04E, 32 }, { "SHA3-224",    0x2B6, 0x2B7, 28 },
        { "SHA3-256",    0x2B1, 0x2B2, 32 }, { "SHA3-384",    0x2C1, 0x2C2, 48 },
        { "SHA3-512",    0x2D1, 0x2D2, 64 },
    };
    char what[128];
    for (size_t i = 0; i < sizeof H / sizeof H[0]; i++) {
        CK_MECHANISM_INFO mi = { 0, 0, 0 };
        CK_RV rv = C_GetMechanismInfo(0, H[i].general, &mi);
        snprintf(what, sizeof what, "(I) %s: stated, sign and verify (0x%lx)", H[i].name, rv);
        ok(rv == CKR_OK && (mi.flags & CKF_SIGN) && (mi.flags & CKF_VERIFY), what);
        if (rv != CKR_OK) continue;

        CK_BYTE full[64], cut[64], whole[64], parts[64];
        CK_ULONG fl = 0, cl = 0, wl = 0, pl = 0, ten = 10, all = H[i].full;
        int got_full = sign(H[i].hmac, NULL, full, &fl) == CKR_OK && fl == H[i].full;
        rv = sign(H[i].general, &ten, cut, &cl);
        snprintf(what, sizeof what, "(S) %s: 10 bytes, the HMAC's first 10 (0x%lx)", H[i].name, rv);
        ok(got_full && rv == CKR_OK && cl == 10 && memcmp(cut, full, 10) == 0, what);
        rv = sign(H[i].general, &all, whole, &wl);
        snprintf(what, sizeof what, "(S) %s: %lu bytes, the whole HMAC", H[i].name, all);
        ok(got_full && rv == CKR_OK && wl == all && memcmp(whole, full, all) == 0, what);
        rv = sign_parts(H[i].general, 10, parts, &pl);
        snprintf(what, sizeof what, "(M) %s: in three parts, the same 10 bytes (0x%lx)", H[i].name, rv);
        ok(rv == CKR_OK && pl == 10 && memcmp(parts, cut, 10) == 0, what);

        snprintf(what, sizeof what, "(V) %s: verifies, single-part and in parts", H[i].name);
        ok(verify(H[i].general, 10, cut, 10, 0) == CKR_OK
           && verify(H[i].general, 10, cut, 10, 1) == CKR_OK, what);
        CK_BYTE bad[64]; memcpy(bad, cut, 10); bad[3] = (CK_BYTE)(bad[3] ^ 1u);
        snprintf(what, sizeof what, "(V) %s: 9 bytes, or one changed, do not", H[i].name);
        ok(verify(H[i].general, 10, cut, 9, 0) == CKR_SIGNATURE_INVALID
           && verify(H[i].general, 10, bad, 10, 0) == CKR_SIGNATURE_INVALID
           && verify(H[i].general, 10, bad, 10, 1) == CKR_SIGNATURE_INVALID, what);

        CK_ULONG zero = 0, over = H[i].full + 1, three = 3;
        snprintf(what, sizeof what, "(P) %s: no parameter, 0, %lu: PARAM_INVALID", H[i].name, over);
        ok(init_only(H[i].general, NULL, 0) == CKR_MECHANISM_PARAM_INVALID
           && init_only(H[i].general, &zero, sizeof zero) == CKR_MECHANISM_PARAM_INVALID
           && init_only(H[i].general, &over, sizeof over) == CKR_MECHANISM_PARAM_INVALID, what);
        rv = init_only(H[i].general, &three, sizeof three);
        snprintf(what, sizeof what, "(P) %s: 3 bytes %s (0x%lx)", H[i].name,
                 nist ? "refused, NIST's rules" : "taken", rv);
        ok(nist ? rv == CKR_MECHANISM_PARAM_INVALID : rv == CKR_OK, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
