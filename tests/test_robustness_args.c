/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_robustness_args.c --- Regression test for the TSFI robustness
 * guards against caller-supplied NULL pointers and integer-overflow
 * counts (#125, pkcs11-check security/test_api_boundary,
 * test_arithmetic_overflow, test_ffi_null_pointer).
 *
 *  Before the fix, several entry points iterated a caller template
 *  (find_attr / C_FindObjectsInit loops) or passed a data pointer to
 *  EVP without guarding NULL+non-zero-length or an absurd count. The
 *  harness's raw probes therefore crashed the module with SIGSEGV /
 *  SIGBUS (subprocess-isolated, so reported as failed rather than
 *  crashed). Each probe below must now return CKR_ARGUMENTS_BAD instead
 *  of crashing. Runs IN-PROCESS via dlopen : if any guard regresses the
 *  process faults and this test fails (non-zero exit).
 *
 *  Requires a loadable OpenSSL provider and, for an unsigned dev build,
 *  FHSM_INTEGRITY_ALLOW_UNSIGNED=1.
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKF_SERIAL_SESSION 4UL
#define CKF_RW_SESSION     2UL
#define CKU_SO   0UL
#define CKU_USER 1UL
#define CKM_AES_KEY_GEN 0x1080UL
#define CKM_SHA256      0x250UL
#define CKR_ARGUMENTS_BAD 7UL

static int fails = 0;
#define WANT_BAD(label, expr) do {                                        \
    CK_RV _rv = (expr);                                                   \
    if (_rv != CKR_ARGUMENTS_BAD) {                                       \
        fprintf(stderr, "FAIL: %s -> 0x%lx (want CKR_ARGUMENTS_BAD)\n",   \
                label, (unsigned long)_rv); fails++;                      \
    } else {                                                              \
        printf("  %-40s -> CKR_ARGUMENTS_BAD : OK\n", label);             \
    }                                                                     \
} while (0)

/* PKCS#11 v3.2 C.6.4.1 : pLabel is a fixed 32-byte field, blank-padded and
 * NOT NUL-terminated. Passing a short string literal made C_InitToken read
 * past it -- harmless in practice, which is why it survived until the suite
 * was first run under ASan (#125). */
static CK_BYTE *fhsm_pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

int main(void) {
    void *h = dlopen("./libfreehsm-fips.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_DigestInit)(CK_SESSION_HANDLE,CK_MECHANISM*);
    CK_RV (*C_Digest)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    *(void**)&C_Initialize     = dlsym(h,"C_Initialize");
    *(void**)&C_InitToken      = dlsym(h,"C_InitToken");
    *(void**)&C_OpenSession    = dlsym(h,"C_OpenSession");
    *(void**)&C_Login          = dlsym(h,"C_Login");
    *(void**)&C_InitPIN        = dlsym(h,"C_InitPIN");
    *(void**)&C_FindObjectsInit= dlsym(h,"C_FindObjectsInit");
    *(void**)&C_GenerateKey    = dlsym(h,"C_GenerateKey");
    *(void**)&C_DigestInit     = dlsym(h,"C_DigestInit");
    *(void**)&C_Digest         = dlsym(h,"C_Digest");
    *(void**)&C_SignInit       = dlsym(h,"C_SignInit");
    *(void**)&C_DigestUpdate   = dlsym(h,"C_DigestUpdate");

    C_Initialize(NULL);
    CK_BYTE so[] = "00000000", user[] = "user0000";
    C_InitToken(0, so, 8, fhsm_pad_label((CK_BYTE[32]){0}, "robust"));
    CK_SESSION_HANDLE s = 0;
    C_OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &s);
    C_Login(s, CKU_SO, so, 8);
    C_InitPIN(s, user, 8);
    (void)C_Login(s, CKU_USER, user, 8);

    /* --- template guards : NULL template + non-zero count, absurd count --- */
    WANT_BAD("C_FindObjectsInit(NULL, 5)", C_FindObjectsInit(s, NULL, 5));
    {
        CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL, 0 }; CK_OBJECT_HANDLE k = 0;
        WANT_BAD("C_GenerateKey(NULL template, 5)", C_GenerateKey(s, &m, NULL, 5, &k));
        CK_ATTRIBUTE one = { 0, NULL, 0 };
        WANT_BAD("C_GenerateKey(count=ULONG_MAX)", C_GenerateKey(s, &m, &one, ~0UL, &k));
    }

    /* --- data guards : NULL data + non-zero length --- */
    {
        CK_MECHANISM m = { CKM_SHA256, NULL, 0 };
        CK_BYTE out[64]; CK_ULONG ol = sizeof(out);
        if (C_DigestInit(s, &m) == 0)
            WANT_BAD("C_Digest(NULL, 32)", C_Digest(s, NULL, 32, out, &ol));
        if (C_DigestInit(s, &m) == 0)
            WANT_BAD("C_DigestUpdate(NULL, 32)", C_DigestUpdate(s, NULL, 32));
    }

    if (fails) { fprintf(stderr, "test_robustness_args : %d FAIL\n", fails); return 1; }
    printf("test_robustness_args : PASS\n");
    return 0;
}
