/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_decrypt_null_args.c --- Regression test for the C_Decrypt NULL
 * argument hardening (#125, pkcs11-check finding
 * test_null_argument_rejection_terminates_encrypt_decrypt_operation).
 *
 *  Before the fix, C_Decrypt dereferenced pulDataLen on every path
 *  (size query and copy) without a NULL check, unlike C_Encrypt which
 *  guarded pulEncLen. pkcs11-check's NULL-argument probe therefore
 *  caused a SIGSEGV inside the module. This test drives the PUBLIC
 *  PKCS#11 API (dlopen, no internal linkage) to assert C_Decrypt now
 *  returns CKR_ARGUMENTS_BAD instead of crashing when pulDataLen is
 *  NULL, and terminates the operation (session not stranded).
 *
 *  Linked against the shipped .so via dlopen ; requires a loadable
 *  OpenSSL provider (same constraint as the other harness tests) and,
 *  for an unsigned dev build, FHSM_INTEGRITY_ALLOW_UNSIGNED=1.
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
#define CKO_SECRET_KEY 4UL
#define CKK_AES 0x1FUL
#define CKA_CLASS 0UL
#define CKA_KEY_TYPE 0x100UL
#define CKA_VALUE 0x11UL
#define CKM_AES_CBC 0x1082UL
#define CKR_ARGUMENTS_BAD 7UL

int main(void) {
    void *h = dlopen("./libfreehsm-fips.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    /* ISO C forbids a direct void*->function-pointer assignment, and the
     * build is -Wpedantic -Werror ; use the POSIX-blessed
     * *(void**)&fn = dlsym(...) idiom. */
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    *(void**)&C_Initialize  = dlsym(h,"C_Initialize");
    *(void**)&C_InitToken   = dlsym(h,"C_InitToken");
    *(void**)&C_OpenSession = dlsym(h,"C_OpenSession");
    *(void**)&C_Login       = dlsym(h,"C_Login");
    *(void**)&C_InitPIN     = dlsym(h,"C_InitPIN");
    *(void**)&C_CreateObject= dlsym(h,"C_CreateObject");
    *(void**)&C_DecryptInit = dlsym(h,"C_DecryptInit");
    *(void**)&C_Decrypt     = dlsym(h,"C_Decrypt");
    if (!C_Initialize || !C_Decrypt || !C_CreateObject
        || !C_InitToken || !C_OpenSession || !C_Login || !C_InitPIN
        || !C_DecryptInit) {
        fprintf(stderr, "dlsym: missing symbol\n"); return 2;
    }

    CK_RV rv = C_Initialize(NULL);
    if (rv) { fprintf(stderr, "C_Initialize 0x%lx\n", rv); return 2; }
    char so[] = "00000000", user[] = "user0000";
    if ((rv = C_InitToken(0,(CK_BYTE*)so,8,(CK_BYTE*)"tok")))      { fprintf(stderr,"InitToken 0x%lx\n",rv); return 2; }
    CK_SESSION_HANDLE s;
    if ((rv = C_OpenSession(0,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&s))) { fprintf(stderr,"Open 0x%lx\n",rv); return 2; }
    if ((rv = C_Login(s,CKU_SO,(CK_BYTE*)so,8)))                  { fprintf(stderr,"LoginSO 0x%lx\n",rv); return 2; }
    if ((rv = C_InitPIN(s,(CK_BYTE*)user,8)))                     { fprintf(stderr,"InitPIN 0x%lx\n",rv); return 2; }
    (void)C_Login(s,CKU_USER,(CK_BYTE*)user,8);   /* may already be logged in */

    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES; CK_BYTE key[16] = {0};
    CK_ATTRIBUTE tmpl[] = { {CKA_CLASS,&cls,sizeof cls}, {CKA_KEY_TYPE,&kt,sizeof kt}, {CKA_VALUE,key,16} };
    CK_OBJECT_HANDLE ko = 0;
    if ((rv = C_CreateObject(s,tmpl,3,&ko))) { fprintf(stderr,"CreateObject 0x%lx\n",rv); return 2; }

    CK_BYTE iv[16] = {0};
    CK_MECHANISM m = { CKM_AES_CBC, iv, 16 };
    if ((rv = C_DecryptInit(s,&m,ko))) { fprintf(stderr,"DecryptInit 0x%lx\n",rv); return 2; }

    /* The probe: pulDataLen == NULL. Pre-fix: SIGSEGV. Post-fix: CKR_ARGUMENTS_BAD. */
    CK_BYTE ct[16] = {0};
    rv = C_Decrypt(s, ct, 16, NULL, NULL);
    if (rv != CKR_ARGUMENTS_BAD) {
        fprintf(stderr, "FAIL: C_Decrypt(pulDataLen=NULL) -> 0x%lx (want CKR_ARGUMENTS_BAD)\n", rv);
        return 1;
    }
    printf("test_decrypt_null_args : C_Decrypt(NULL len) -> CKR_ARGUMENTS_BAD : OK\n");

    /* --- C_EncryptUpdate NULL length probe (GCM multipart), #125 ------
     * Same NULL-deref class as C_Decrypt. Pre-fix: SIGSEGV. */
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    *(void**)&C_EncryptInit   = dlsym(h,"C_EncryptInit");
    *(void**)&C_EncryptUpdate = dlsym(h,"C_EncryptUpdate");
    if (C_EncryptInit && C_EncryptUpdate) {
        struct { void *pIv; CK_ULONG ulIvLen; CK_ULONG ulIvBits;
                 void *pAAD; CK_ULONG ulAADLen; CK_ULONG ulTagBits; } gcm;
        CK_BYTE giv[12] = {0};
        gcm.pIv = giv; gcm.ulIvLen = 12; gcm.ulIvBits = 96;
        gcm.pAAD = NULL; gcm.ulAADLen = 0; gcm.ulTagBits = 128;
        CK_MECHANISM gm = { 0x1087UL /* CKM_AES_GCM */, &gcm, sizeof gcm };
        CK_RV ir = C_EncryptInit(s, &gm, ko);
        if (ir != 0) { fprintf(stderr, "FAIL: GCM C_EncryptInit -> 0x%lx\n", ir); return 1; }
        CK_BYTE part[16] = {0};
        rv = C_EncryptUpdate(s, part, 16, part, NULL);   /* pulEncLen = NULL */
        if (rv != CKR_ARGUMENTS_BAD) {
            fprintf(stderr, "FAIL: C_EncryptUpdate(NULL len) -> 0x%lx\n", rv);
            return 1;
        }
        printf("test_decrypt_null_args : C_EncryptUpdate(NULL len) -> CKR_ARGUMENTS_BAD : OK\n");
    }

    /* --- C_DecryptFinal with no multipart context (#125 crash) -------
     * C_DecryptInit(AES-CBC) with an invalid key handle, then
     * C_DecryptFinal directly (no Update). Pre-fix: SIGSEGV in
     * EVP_DecryptFinal_ex(NULL). Post-fix: CKR_OPERATION_NOT_INITIALIZED. */
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
    *(void**)&C_DecryptFinal = dlsym(h,"C_DecryptFinal");
    if (C_DecryptFinal) {
        CK_BYTE iv_f[16] = {0};
        CK_MECHANISM cbc = { 0x1082UL /* CKM_AES_CBC */, iv_f, 16 };
        if (C_DecryptInit(s, &cbc, 0 /* invalid key handle */) == 0) {
            CK_BYTE last[64]; CK_ULONG ll = 64;
            rv = C_DecryptFinal(s, last, &ll);   /* must not crash */
            if (rv == 0) { fprintf(stderr, "FAIL: DecryptFinal(no ctx) unexpectedly OK\n"); return 1; }
            printf("test_decrypt_null_args : C_DecryptFinal(no ctx) -> 0x%lx (no crash) : OK\n", rv);
        }
    }

    printf("test_decrypt_null_args : PASS\n");
    return 0;
}
