/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_generic_secret_len.c --- CKM_GENERIC_SECRET_KEY_GEN makes the lengths
 * C_GetMechanismInfo advertises for it.
 *
 * Key generation applied the AES rule (16, 24 or 32 bytes) to generic
 * secrets, so a 64-byte HMAC key -- inside the advertised range -- was
 * CKR_KEY_SIZE_RANGE (pkcs11-check TestGenericSecretKeyGen, 512 bits).
 *
 * What is asserted:
 *   (1) every length from the advertised minimum to the maximum generates,
 *       and CKA_VALUE_LEN reads back as asked
 *   (2) one below the minimum and one above the maximum: CKR_KEY_SIZE_RANGE
 *   (3) the AES rule is unchanged: a 20-byte AES key is CKR_KEY_SIZE_RANGE
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize, flags; } CK_MECHANISM_INFO;

#define CKR_OK                     0UL
#define CKR_KEY_SIZE_RANGE         0x62UL
#define CKF_RW                     6UL
#define CKA_TOKEN                  0x001UL
#define CKA_SIGN                   0x108UL
#define CKA_ENCRYPT                0x104UL
#define CKA_VALUE_LEN              0x161UL
#define CKM_GENERIC_SECRET_KEY_GEN 0x350UL
#define CKM_AES_KEY_GEN            0x1080UL

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

static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE);

static CK_RV gen(CK_SESSION_HANDLE s, CK_ULONG mech, CK_ULONG attr, CK_ULONG len,
                 CK_OBJECT_HANDLE *k) {
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE t[] = { { CKA_TOKEN, &no, 1 }, { attr, &yes, 1 },
                         { CKA_VALUE_LEN, &len, sizeof len } };
    CK_MECHANISM m = { mech, NULL, 0 };
    return C_GenerateKey(s, &m, t, 3, k);
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
    CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID,CK_ULONG,CK_MECHANISM_INFO*);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismInfo);
    SYM(C_GenerateKey); SYM(C_GetAttributeValue); SYM(C_DestroyObject);
    if (!C_GenerateKey || !C_GetAttributeValue || !C_DestroyObject || !C_GetMechanismInfo) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("CKM_GENERIC_SECRET_KEY_GEN: the advertised lengths\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "genericlen")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    CK_MECHANISM_INFO info;
    if (C_GetMechanismInfo(0, CKM_GENERIC_SECRET_KEY_GEN, &info) != CKR_OK) {
        fprintf(stderr, "C_GetMechanismInfo\n"); return 2;
    }
    printf("  advertised: %lu to %lu bytes\n", info.ulMinKeySize, info.ulMaxKeySize);

    char what[96];
    int bad = 0;
    for (CK_ULONG n = info.ulMinKeySize; n <= info.ulMaxKeySize; ++n) {
        CK_OBJECT_HANDLE k = 0;
        CK_RV rv = gen(s, CKM_GENERIC_SECRET_KEY_GEN, CKA_SIGN, n, &k);
        CK_ULONG got = 0;
        CK_ATTRIBUTE a = { CKA_VALUE_LEN, &got, sizeof got };
        if (rv != CKR_OK || C_GetAttributeValue(s, k, &a, 1) != CKR_OK || got != n) {
            if (!bad) printf("    first failure at %lu bytes (rv 0x%lx)\n", n, rv);
            bad++;
        }
        if (rv == CKR_OK) (void)C_DestroyObject(s, k);
    }
    snprintf(what, sizeof what, "(1) every advertised length generates, %lu..%lu (%d failed)",
             info.ulMinKeySize, info.ulMaxKeySize, bad);
    ok(bad == 0, what);

    CK_OBJECT_HANDLE k = 0;
    if (info.ulMinKeySize > 0)
        ok(gen(s, CKM_GENERIC_SECRET_KEY_GEN, CKA_SIGN, info.ulMinKeySize - 1, &k)
               == CKR_KEY_SIZE_RANGE, "(2) one byte under the minimum: CKR_KEY_SIZE_RANGE");
    ok(gen(s, CKM_GENERIC_SECRET_KEY_GEN, CKA_SIGN, info.ulMaxKeySize + 1, &k)
           == CKR_KEY_SIZE_RANGE, "(2) one byte over the maximum: CKR_KEY_SIZE_RANGE");
    ok(gen(s, CKM_AES_KEY_GEN, CKA_ENCRYPT, 20, &k) == CKR_KEY_SIZE_RANGE,
       "(3) a 20-byte AES key: CKR_KEY_SIZE_RANGE");

    (void)C_Finalize(NULL);
    printf("\n%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
