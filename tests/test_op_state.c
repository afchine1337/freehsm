/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_op_state.c --- Regression test for per-session operation-state
 * hygiene (#125, pkcs11-check TestOperationActive / ckr *Init errors and
 * TestBufferTooSmall::test_sign_buffer_too_small).
 *
 *  (1) Session handles are drawn from a reusable pool. A session closed
 *      with an active crypto operation must NOT leak that state into the
 *      next session handed out by C_OpenSession, otherwise the next
 *      C_*Init wrongly returns CKR_OPERATION_ACTIVE. C_OpenSession /
 *      C_CloseSession now reset the per-session operation slots.
 *  (2) C_Sign with an undersized signature buffer must return
 *      CKR_BUFFER_TOO_SMALL (with the required length) and keep the
 *      operation active for retry -- not CKR_FUNCTION_FAILED.
 *
 *  Drives the PUBLIC API via dlopen. Requires a loadable OpenSSL
 *  provider and, for an unsigned dev build, FHSM_INTEGRITY_ALLOW_UNSIGNED=1.
 * ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                0UL
#define CKR_BUFFER_TOO_SMALL  0x150UL
#define CKF_RW  6UL   /* SERIAL|RW */
#define CKM_AES_KEY_GEN       0x1080UL
#define CKM_AES_CBC           0x1082UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0UL
#define CKM_SHA256_RSA_PKCS   0x40UL
#define CKA_CLASS 0UL
#define CKA_KEY_TYPE 0x100UL
#define CKA_VALUE_LEN 0x161UL
#define CKA_MODULUS_BITS 0x121UL
#define CKO_SECRET_KEY 4UL
#define CKK_AES 0x1FUL

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fails++; } \
                              else printf("  %s : OK\n", msg); } while (0)

int main(void) {
    void *h = dlopen("./libfreehsm-fips.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_InitToken); SYM(C_OpenSession); SYM(C_CloseSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_GenerateKey); SYM(C_GenerateKeyPair);
    SYM(C_EncryptInit); SYM(C_SignInit); SYM(C_Sign);

    C_Initialize(NULL);
    CK_BYTE so[] = "00000000", up[] = "user0000";
    C_InitToken(0, so, 8, (CK_BYTE*)"opstate");
    CK_SESSION_HANDLE s = 0;
    C_OpenSession(0, CKF_RW, NULL, NULL, &s);
    C_Login(s, 0, so, 8); C_InitPIN(s, up, 8); (void)C_Login(s, 1, up, 8);

    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES, vl = 32;
    /* CKA_TOKEN=TRUE : the key must survive the C_CloseSession below so
     * the reopened-session probe can reuse its handle (session objects
     * are now destroyed on close, #125). */
    CK_BYTE bt = 1;
    CK_ATTRIBUTE at[] = { {CKA_CLASS,&cls,8}, {CKA_KEY_TYPE,&kt,8}, {CKA_VALUE_LEN,&vl,8}, {1,&bt,1} };
    CK_OBJECT_HANDLE ak = 0;
    CK_MECHANISM aesgen = { CKM_AES_KEY_GEN, NULL, 0 };
    C_GenerateKey(s, &aesgen, at, 4, &ak);

    /* (1) leave an operation active, close, reopen : must not bleed */
    CK_BYTE iv[16] = {0};
    CK_MECHANISM cbc = { CKM_AES_CBC, iv, 16 };
    C_EncryptInit(s, &cbc, ak);            /* active = 1, not terminated */
    C_CloseSession(s);
    CK_SESSION_HANDLE s2 = 0;
    C_OpenSession(0, CKF_RW, NULL, NULL, &s2);
    (void)C_Login(s2, 1, up, 8);
    CK_RV r1 = C_EncryptInit(s2, &cbc, ak);
    CHECK(r1 == CKR_OK, "reopened session : no stale CKR_OPERATION_ACTIVE");

    /* (2) C_Sign undersized buffer -> CKR_BUFFER_TOO_SMALL, op preserved */
    CK_ULONG mb = 2048;
    CK_ATTRIBUTE pub[] = { {CKA_MODULUS_BITS,&mb,8} };
    CK_OBJECT_HANDLE hpub = 0, hpriv = 0;
    CK_MECHANISM rsagen = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_RV g = C_GenerateKeyPair(s2, &rsagen, pub, 1, NULL, 0, &hpub, &hpriv);
    if (g != CKR_OK) {
        printf("  (RSA keygen rv=0x%lx : skipping buffer-too-small case)\n", (unsigned long)g);
    } else {
        CK_MECHANISM sigm = { CKM_SHA256_RSA_PKCS, NULL, 0 };
        CK_BYTE sig[512]; CK_ULONG sl = 4;      /* deliberately too small */
        C_SignInit(s2, &sigm, hpriv);
        CK_RV r2 = C_Sign(s2, (CK_BYTE*)"abc", 3, sig, &sl);
        CHECK(r2 == CKR_BUFFER_TOO_SMALL, "C_Sign(small buf) -> CKR_BUFFER_TOO_SMALL");
        CK_ULONG sl2 = sizeof(sig);
        CK_RV r3 = C_Sign(s2, (CK_BYTE*)"abc", 3, sig, &sl2);   /* retry same op */
        CHECK(r3 == CKR_OK, "C_Sign retry with adequate buffer : op preserved");
    }

    /* Use-after-destroy : C_*Init on a destroyed key handle must fail
     * with CKR_KEY_HANDLE_INVALID, not succeed (#125). */
    { CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE);
      CK_RV (*C_SignInit2)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
      CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
      *(void**)&C_DestroyObject   = dlsym(h,"C_DestroyObject");
      *(void**)&C_SignInit2       = dlsym(h,"C_SignInit");
      *(void**)&C_GetAttributeValue = dlsym(h,"C_GetAttributeValue");
      CK_ULONG cls2=4, kt2=0x10, vl2=32; CK_BYTE lbl[]="lbl";
      CK_ATTRIBUTE gt[] = { {0,&cls2,8}, {0x100,&kt2,8}, {0x161,&vl2,8}, {0x03,lbl,3} };
      CK_OBJECT_HANDLE gk=0; CK_MECHANISM gg={0x350,NULL,0};
      C_GenerateKey(s2, &gg, gt, 4, &gk);
      /* buffer-too-small on a readable attribute */
      CK_BYTE tiny[1]; CK_ATTRIBUTE q={0x03,tiny,1};
      CK_RV rb = C_GetAttributeValue(s2, gk, &q, 1);
      if (rb != 0x150UL) { fprintf(stderr,"FAIL: GetAttr small buf 0x%lx (want 0x150)\n",(unsigned long)rb); fails++; }
      else printf("  C_GetAttributeValue undersized -> CKR_BUFFER_TOO_SMALL : OK\n");
      C_DestroyObject(s2, gk);
      CK_MECHANISM hm={0x251,NULL,0};
      CK_RV rd = C_SignInit2(s2, &hm, gk);
      if (rd != 0x60UL) { fprintf(stderr,"FAIL: SignInit destroyed key 0x%lx (want 0x60)\n",(unsigned long)rd); fails++; }
      else printf("  C_SignInit on destroyed key -> CKR_KEY_HANDLE_INVALID : OK\n"); }

    if (fails) { fprintf(stderr, "test_op_state : %d FAIL\n", fails); return 1; }
    printf("test_op_state : PASS\n");
    return 0;
}
