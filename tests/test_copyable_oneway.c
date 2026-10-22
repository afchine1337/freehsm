/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_copyable_oneway.c --- CKA_COPYABLE goes from CK_TRUE to CK_FALSE
 * through C_SetAttributeValue, and not back (PKCS#11 v3.0 §4.4).
 *
 * Both directions were CKR_ATTRIBUTE_READ_ONLY, a stated limitation that
 * pkcs11-check's TestCopyableOneWay scored as not operational.
 *
 * What is asserted, on a session AES key:
 *   (1) it is created copyable, and C_CopyObject copies it
 *   (2) setting CKA_COPYABLE to CK_TRUE again is accepted (no change)
 *   (3) setting it to CK_FALSE is accepted, and reads back CK_FALSE
 *   (4) C_CopyObject now answers CKR_ACTION_PROHIBITED
 *   (5) setting it back to CK_TRUE answers CKR_ATTRIBUTE_READ_ONLY, and it
 *       still reads CK_FALSE
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                  0UL
#define CKR_ATTRIBUTE_READ_ONLY 0x10UL
#define CKR_ACTION_PROHIBITED   0x1BUL
#define CKF_RW                  6UL
#define CKA_TOKEN               0x001UL
#define CKA_ENCRYPT             0x104UL
#define CKA_VALUE_LEN           0x161UL
#define CKA_COPYABLE            0x171UL
#define CKM_AES_KEY_GEN         0x1080UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

static CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_CopyObject)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);

static CK_RV set_copyable(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k, CK_BYTE v) {
    CK_ATTRIBUTE a = { CKA_COPYABLE, &v, 1 };
    return C_SetAttributeValue(s, k, &a, 1);
}

static int copyable(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k) {
    CK_BYTE v = 0xFF;
    CK_ATTRIBUTE a = { CKA_COPYABLE, &v, 1 };
    if (C_GetAttributeValue(s, k, &a, 1) != CKR_OK) return -1;
    return v;
}

static CK_RV copy(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k) {
    CK_BYTE no = 0;
    CK_ATTRIBUTE t = { CKA_TOKEN, &no, 1 };
    CK_OBJECT_HANDLE c = 0;
    return C_CopyObject(s, k, &t, 1, &c);
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
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKey);
    SYM(C_SetAttributeValue); SYM(C_GetAttributeValue); SYM(C_CopyObject);
    if (!C_GenerateKey || !C_SetAttributeValue || !C_GetAttributeValue || !C_CopyObject) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("CKA_COPYABLE: CK_TRUE to CK_FALSE, and not back\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "copyable")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    CK_BYTE yes = 1, no = 0;
    CK_ULONG len = 32;
    CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 },
                          { CKA_VALUE_LEN, &len, sizeof len } };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE k = 0;
    if (C_GenerateKey(s, &m, kt, 3, &k) != CKR_OK) { fprintf(stderr, "C_GenerateKey\n"); return 2; }

    char what[96];
    CK_RV rv;
    ok(copyable(s, k) == 1, "(1) a new key reads CKA_COPYABLE = CK_TRUE");
    rv = copy(s, k);
    snprintf(what, sizeof what, "(1) C_CopyObject copies it (rv 0x%lx)", rv);
    ok(rv == CKR_OK, what);

    rv = set_copyable(s, k, 1);
    snprintf(what, sizeof what, "(2) CK_TRUE to CK_TRUE: accepted (rv 0x%lx)", rv);
    ok(rv == CKR_OK, what);

    rv = set_copyable(s, k, 0);
    snprintf(what, sizeof what, "(3) CK_TRUE to CK_FALSE: accepted (rv 0x%lx)", rv);
    ok(rv == CKR_OK, what);
    ok(copyable(s, k) == 0, "(3) it reads back CK_FALSE");

    rv = copy(s, k);
    snprintf(what, sizeof what, "(4) C_CopyObject: CKR_ACTION_PROHIBITED (rv 0x%lx)", rv);
    ok(rv == CKR_ACTION_PROHIBITED, what);

    rv = set_copyable(s, k, 1);
    snprintf(what, sizeof what, "(5) CK_FALSE to CK_TRUE: CKR_ATTRIBUTE_READ_ONLY (rv 0x%lx)", rv);
    ok(rv == CKR_ATTRIBUTE_READ_ONLY, what);
    ok(copyable(s, k) == 0, "(5) it still reads CK_FALSE");

    (void)C_Finalize(NULL);
    printf("\n%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
