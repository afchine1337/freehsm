/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_session_objects.c --- Regression test for PKCS#11 CKA_TOKEN
 * semantics (#125): session objects (CKA_TOKEN=FALSE) are destroyed when
 * their session closes and are not persisted; token objects persist; and
 * creating a token object on a read-only session is CKR_SESSION_READ_ONLY.
 * ========================================================================= */
#include <stdio.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG l; } CK_MECHANISM;

#define CKR_SESSION_READ_ONLY 0xB5UL
static void *H;
static CK_RV (*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*CSf)(CK_SESSION_HANDLE);
static CK_RV (*L)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*GK)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*FI)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*FO)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV (*FF)(CK_SESSION_HANDLE);
static CK_RV (*CO)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_BYTE up[] = "user0000";
static int fails = 0;

static int count(CK_SESSION_HANDLE s) {
    CK_OBJECT_HANDLE h[128]; CK_ULONG n = 0;
    FI(s, NULL, 0); FO(s, h, 128, &n); FF(s); return (int)n;
}
static void mkaes(CK_SESSION_HANDLE s, int token) {
    CK_ULONG cls = 4, kt = 0x1F, vl = 32; CK_BYTE T = 1;
    CK_ATTRIBUTE a[] = { {0,&cls,8}, {0x100,&kt,8}, {0x161,&vl,8}, {0x01,&T,1} };
    CK_OBJECT_HANDLE k; GK(s, &(CK_MECHANISM){0x1080,0,0}, a, token ? 4 : 3, &k);
}

int main(void) {
    H = dlopen("./libfreehsm-fips.so", RTLD_NOW);
    if (!H) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*I)(void*); CK_RV (*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*); CK_RV (*IP)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define S(n,nm) *(void**)&n = dlsym(H, nm)
    S(I,"C_Initialize"); S(IT,"C_InitToken"); S(OS,"C_OpenSession"); S(CSf,"C_CloseSession");
    S(L,"C_Login"); S(IP,"C_InitPIN"); S(GK,"C_GenerateKey"); S(FI,"C_FindObjectsInit");
    S(FO,"C_FindObjects"); S(FF,"C_FindObjectsFinal"); S(CO,"C_CreateObject");

    I(NULL); CK_BYTE so[] = "00000000";
    IT(0, so, 8, (CK_BYTE*)"sess"); CK_SESSION_HANDLE s1; OS(0,6,NULL,NULL,&s1);
    L(s1,0,so,8); IP(s1,up,8); (void)L(s1,1,up,8);

    mkaes(s1, 0);   /* session object (CKA_TOKEN=FALSE default) */
    mkaes(s1, 1);   /* token object (CKA_TOKEN=TRUE) */
    int c1 = count(s1);
    if (c1 != 2) { fprintf(stderr, "FAIL: s1 count %d (want 2)\n", c1); fails++; }
    else printf("  s1 sees session+token objects (2) : OK\n");
    CSf(s1);

    CK_SESSION_HANDLE s2; OS(0,6,NULL,NULL,&s2); (void)L(s2,1,up,8);
    int c2 = count(s2);
    if (c2 != 1) { fprintf(stderr, "FAIL: s2 count %d (want 1 : token persists, session destroyed)\n", c2); fails++; }
    else printf("  reopened session : only token object survives (1) : OK\n");

    CK_SESSION_HANDLE ro; OS(0,4,NULL,NULL,&ro); (void)L(ro,1,up,8);  /* RO */
    CK_ULONG cls=4, kt=0x1F, vl=32; CK_BYTE T=1;
    CK_ATTRIBUTE a[] = { {0,&cls,8}, {0x100,&kt,8}, {0x161,&vl,8}, {0x01,&T,1} };
    CK_OBJECT_HANDLE k; CK_RV r = CO(ro, a, 4, &k);
    if (r != CKR_SESSION_READ_ONLY) { fprintf(stderr, "FAIL: RO token create 0x%lx (want 0xb5)\n", (unsigned long)r); fails++; }
    else printf("  token object on RO session -> CKR_SESSION_READ_ONLY : OK\n");

    /* Access control : a private object (secret/private key) must be
     * hidden from a session that is not logged in as USER (#125). */
    { CK_RV (*C_Logout)(CK_SESSION_HANDLE); *(void**)&C_Logout = dlsym(H,"C_Logout");
      CK_SESSION_HANDLE s3; OS(0,6,NULL,NULL,&s3); (void)L(s3,1,up,8);
      mkaes(s3, 1);                          /* token private key */
      int seen_in = count(s3);
      C_Logout(s3);
      int seen_out = count(s3);
      if (seen_in < 1) { fprintf(stderr,"FAIL: logged-in sees %d (want >=1)\n",seen_in); fails++; }
      else if (seen_out != 0) { fprintf(stderr,"FAIL: post-logout sees %d private (want 0)\n",seen_out); fails++; }
      else printf("  private object hidden after logout : OK\n"); }

    if (fails) { fprintf(stderr, "test_session_objects : %d FAIL\n", fails); return 1; }
    printf("test_session_objects : PASS\n");
    return 0;
}
