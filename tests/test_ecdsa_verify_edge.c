/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_ecdsa_verify_edge.c --- an ECDSA signature whose verification
 * reaches the point at infinity is CKR_SIGNATURE_INVALID, not
 * CKR_FUNCTION_FAILED.
 *
 * OpenSSL returns -1, not 0, when the verification arithmetic of (r, s)
 * fails, and the module passed that on as CKR_FUNCTION_FAILED -- a module
 * error, for a signature that is simply wrong. pkcs11-check scored 80
 * Wycheproof vectors per profile as non-clean rejections
 * (PKCS11_CHECK_FINDINGS, 2026-10-21).
 *
 * Vectors from tests/wycheproof/vectors/ecdsa_secp256r1_sha256_test.json,
 * signatures converted from DER to the r || s PKCS#11 uses:
 *   tc1    valid, "pseudorandom signature" (the control)
 *   tc392  invalid, "point at infinity during verify"
 *   tc431  invalid, "comparison with point at infinity"
 *
 * What is asserted, with CKM_ECDSA_SHA256 one-shot and multipart:
 *   (1) tc1 verifies: CKR_OK
 *   (2) tc392 and tc431: CKR_SIGNATURE_INVALID
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

#define CKR_OK                0UL
#define CKR_SIGNATURE_INVALID 0xC0UL
#define CKF_RW                6UL
#define CKA_CLASS             0x000UL
#define CKA_TOKEN             0x001UL
#define CKA_KEY_TYPE          0x100UL
#define CKA_VERIFY            0x10AUL
#define CKA_EC_PARAMS         0x180UL
#define CKA_EC_POINT          0x181UL
#define CKO_PUBLIC_KEY        2UL
#define CKK_EC                3UL
#define CKM_ECDSA_SHA256      0x1044UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static const struct { const char *name; const char *pk, *msg, *sig; CK_RV want; } VEC[] = {
    { "tc1 valid",
      "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5"
      "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
      "",
      "b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a"
      "0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2",
      CKR_OK },
    { "tc392 point at infinity during verify",
      "b533d4695dd5b8c5e07757e55e6e516f7e2c88fa0239e23f60e8ec07dd70f287"
      "1b134ee58cc583278456863f33c3a85d881f7d4a39850143e29d4eaf009afe47",
      "313233343030",
      "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8"
      "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
      CKR_SIGNATURE_INVALID },
    { "tc431 comparison with point at infinity",
      "dd86d3b5f4a13e8511083b78002081c53ff467f11ebd98a51a633db76665d250"
      "45d5c8200c89f2fa10d849349226d21d8dfaed6ff8d5cb3e1b7e17474ebc18f7",
      "313233343030",
      "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70"
      "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9",
      CKR_SIGNATURE_INVALID },
};
#define NVEC (sizeof VEC / sizeof VEC[0])
static const CK_BYTE P256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };

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

static size_t unhex(const char *h, CK_BYTE *out) {
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; ++i) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (CK_BYTE)v; }
    return n;
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
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject);
    SYM(C_VerifyInit); SYM(C_Verify); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    if (!C_CreateObject || !C_VerifyInit || !C_Verify || !C_VerifyUpdate || !C_VerifyFinal) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("ECDSA verification reaching the point at infinity\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "ecdsaedge")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    char what[128];
    for (size_t i = 0; i < NVEC; ++i) {
        /* CKA_EC_POINT: DER OCTET STRING around 04 || X || Y. */
        CK_BYTE point[67] = { 0x04, 0x41, 0x04 };
        unhex(VEC[i].pk, point + 3);
        CK_BYTE msg[16], sig[64];
        size_t ml = unhex(VEC[i].msg, msg), sl = unhex(VEC[i].sig, sig);

        CK_ULONG cls = CKO_PUBLIC_KEY, kt = CKK_EC;
        CK_BYTE yes = 1, no = 0;
        CK_ATTRIBUTE t[] = {
            { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
            { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
            { CKA_EC_PARAMS, (void*)P256, sizeof P256 }, { CKA_EC_POINT, point, sizeof point },
        };
        CK_OBJECT_HANDLE k = 0;
        CK_RV rv = C_CreateObject(s, t, sizeof t / sizeof t[0], &k);
        snprintf(what, sizeof what, "%s: public key imports (rv 0x%lx)", VEC[i].name, rv);
        ok(rv == CKR_OK, what);
        if (rv != CKR_OK) continue;

        const int n = VEC[i].want == CKR_OK ? 1 : 2;
        const char *code = n == 1 ? "CKR_OK" : "CKR_SIGNATURE_INVALID";
        CK_MECHANISM m = { CKM_ECDSA_SHA256, NULL, 0 };
        rv = C_VerifyInit(s, &m, k);
        if (rv == CKR_OK) rv = C_Verify(s, msg, ml, sig, sl);
        snprintf(what, sizeof what, "(%d) %s: %s (rv 0x%lx)", n, VEC[i].name, code, rv);
        ok(rv == VEC[i].want, what);

        rv = C_VerifyInit(s, &m, k);
        if (rv == CKR_OK) rv = C_VerifyUpdate(s, msg, ml);
        if (rv == CKR_OK) rv = C_VerifyFinal(s, sig, sl);
        snprintf(what, sizeof what, "(%d) %s, multipart: %s (rv 0x%lx)", n, VEC[i].name, code, rv);
        ok(rv == VEC[i].want, what);
    }

    (void)C_Finalize(NULL);
    printf("\n%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
