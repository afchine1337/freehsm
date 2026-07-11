/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_attributes.c --- Regression test for C_GetAttributeValue coverage
 * of the standard PKCS#11 boolean policy / usage attributes and date
 * attributes (#125, pkcs11-check test_attribute_defaults / test_key_flags
 * / test_access_control : previously returned CK_UNAVAILABLE_INFORMATION,
 * which the harness reads as a missing key -> KeyError).
 * ========================================================================= */
#include <stdio.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG l; } CK_MECHANISM;

static void *H;
static CK_RV (*GA)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static int fails = 0;

static void want_bool(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k, CK_ULONG a,
                      int expect, const char *name) {
    CK_BYTE b = 0xAA; CK_ATTRIBUTE t = { a, &b, 1 };
    CK_RV r = GA(s, k, &t, 1);
    if (r != 0 || t.ulValueLen != 1 || b != expect) {
        fprintf(stderr, "FAIL: %s rv=0x%lx len=%ld val=%d (want %d)\n",
                name, (unsigned long)r, (long)t.ulValueLen, (t.ulValueLen==1)?b:-1, expect);
        fails++;
    } else printf("  %-22s = %d : OK\n", name, expect);
}

int main(void) {
    H = dlopen("./libfreehsm-fips.so", RTLD_NOW);
    if (!H) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*I)(void*); CK_RV (*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*L)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG); CK_RV (*IP)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*GK)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    #define S(n,nm) *(void**)&n = dlsym(H, nm)
    S(I,"C_Initialize"); S(IT,"C_InitToken"); S(OS,"C_OpenSession"); S(L,"C_Login");
    S(IP,"C_InitPIN"); S(GK,"C_GenerateKey"); S(GA,"C_GetAttributeValue");

    I(NULL); CK_BYTE so[]="00000000", up[]="user0000";
    IT(0, so, 8, (CK_BYTE*)"attr"); CK_SESSION_HANDLE s = 0; OS(0, 6, NULL, NULL, &s);
    L(s, 0, so, 8); IP(s, up, 8); (void)L(s, 1, up, 8);

    CK_ULONG cls = 4, kt = 0x1F, vl = 32;
    CK_ATTRIBUTE at[] = { {0,&cls,8}, {0x100,&kt,8}, {0x161,&vl,8} };
    CK_OBJECT_HANDLE k = 0;
    CK_MECHANISM gen = { 0x1080, 0, 0 };
    if (GK(s, &gen, at, 3, &k) != 0) { fprintf(stderr, "FAIL keygen\n"); return 1; }

    /* Secret key : usage + policy booleans must be present with sane values. */
    want_bool(s, k, 0x001, 1, "CKA_TOKEN");
    want_bool(s, k, 0x002, 1, "CKA_PRIVATE");
    want_bool(s, k, 0x104, 1, "CKA_ENCRYPT");
    want_bool(s, k, 0x105, 1, "CKA_DECRYPT");
    want_bool(s, k, 0x108, 1, "CKA_SIGN");
    want_bool(s, k, 0x10A, 1, "CKA_VERIFY");
    want_bool(s, k, 0x163, 1, "CKA_LOCAL");
    want_bool(s, k, 0x165, 1, "CKA_ALWAYS_SENSITIVE");
    want_bool(s, k, 0x164, 1, "CKA_NEVER_EXTRACTABLE");
    want_bool(s, k, 0x170, 1, "CKA_MODIFIABLE");
    want_bool(s, k, 0x171, 1, "CKA_COPYABLE");
    want_bool(s, k, 0x172, 1, "CKA_DESTROYABLE");
    want_bool(s, k, 0x202, 0, "CKA_ALWAYS_AUTHENTICATE");
    want_bool(s, k, 0x210, 0, "CKA_WRAP_WITH_TRUSTED");

    /* Date attribute : present, empty (length 0). */
    { CK_ATTRIBUTE d = { 0x110, NULL, 0 };
      CK_RV r = GA(s, k, &d, 1);
      if (r != 0 || d.ulValueLen != 0) { fprintf(stderr, "FAIL: CKA_START_DATE rv=0x%lx len=%ld\n", (unsigned long)r, (long)d.ulValueLen); fails++; }
      else printf("  %-22s = empty : OK\n", "CKA_START_DATE"); }

    /* Per-object usage flag override : a key created with CKA_ENCRYPT=FALSE
     * must report CKA_ENCRYPT=0 (#125 usage-flag storage). */
    { CK_BYTE F = 0;
      CK_ATTRIBUTE r[] = { {0,&cls,8}, {0x100,&kt,8}, {0x161,&vl,8}, {0x104,&F,1} };
      CK_OBJECT_HANDLE k2 = 0; CK_MECHANISM g2 = { 0x1080, NULL, 0 };
      GK(s, &g2, r, 4, &k2);
      CK_BYTE b = 9; CK_ATTRIBUTE q = { 0x104, &b, 1 };
      GA(s, k2, &q, 1);
      if (b != 0) { fprintf(stderr, "FAIL: CKA_ENCRYPT=FALSE override not honored (got %d)\n", b); fails++; }
      else printf("  %-22s = 0 (override) : OK\n", "CKA_ENCRYPT restricted"); }

    if (fails) { fprintf(stderr, "test_attributes : %d FAIL\n", fails); return 1; }
    printf("test_attributes : PASS\n");
    return 0;
}
