/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_login_conflicts.c --- the rules of PKCS#11 v3.2 §5.6 that keep the SO
 * and the USER apart, keep the SO out of read-only sessions, and tie the login
 * to the sessions that carry it.
 *
 *   0. C_OpenSession without CKF_SERIAL_SESSION  -> CKR_SESSION_PARALLEL_NOT_SUPPORTED
 *   1. C_Login(SO) while USER holds the token  -> CKR_USER_ANOTHER_ALREADY_LOGGED_IN
 *      and C_Login(USER) while SO holds it     -> the same
 *   2. C_Login(SO) with a read-only session open -> CKR_SESSION_READ_ONLY_EXISTS
 *   3. C_OpenSession(read-only) while SO is in   -> CKR_SESSION_READ_WRITE_SO_EXISTS
 *   4. closing the last session logs the token out (C_CloseSession, §5.6.2)
 *
 * None was enforced. The first was the dangerous one: with the right PIN an SO
 * login took over a token a USER held, and the USER's sessions carried on under
 * the SO role. Thirty-two tests in this directory logged in as SO, then as
 * USER with no C_Logout between, and passed only because of it. The fourth
 * rule surfaced once the first was enforced: two tests closed their SO
 * session and logged in as USER on a new one, and the token was still SO.
 *
 * Each refusal is also checked for what it must NOT do: the refused login
 * leaves the holder in place, and a wrong PIN offered to a refused login
 * costs no attempt -- the refusal comes before the PIN is looked at.
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG slotID, state, flags, ulDeviceError; } CK_SESSION_INFO;

#define CKR_OK                              0x000UL
#define CKR_SESSION_READ_ONLY_EXISTS        0x0B7UL
#define CKR_SESSION_READ_WRITE_SO_EXISTS    0x0B8UL
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED  0x0B4UL
#define CKR_USER_ALREADY_LOGGED_IN          0x100UL
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN  0x104UL
#define CKU_SO    0UL
#define CKU_USER  1UL
#define CKF_RW_SESSION      0x2UL
#define CKF_SERIAL_SESSION  0x4UL
#define CKS_RW_SO_FUNCTIONS    4UL
#define CKS_RW_USER_FUNCTIONS  3UL

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE,CK_SESSION_INFO*);

static CK_ULONG state_of(CK_SESSION_HANDLE s) {
    CK_SESSION_INFO i; memset(&i, 0, sizeof i);
    return C_GetSessionInfo(s, &i) == CKR_OK ? i.state : (CK_ULONG)-1;
}

static CK_BYTE *pad32(CK_BYTE b[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(b, ' ', 32); memcpy(b, s, n); return b;
}

int main(void) {
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define S(n) *(void**)&n = dlsym(h,#n); \
                 if (!n) { fprintf(stderr,"missing %s\n",#n); return 2; }
    S(C_Initialize) S(C_InitToken) S(C_OpenSession) S(C_CloseSession)
    S(C_Login) S(C_Logout) S(C_InitPIN) S(C_GetSessionInfo)

    printf("test_login_conflicts\n");

    CK_BYTE so[] = "00000000", up[] = "user0000", bad[] = "wrong000", lbl[32];
    const CK_FLAGS RW = CKF_SERIAL_SESSION | CKF_RW_SESSION, RO = CKF_SERIAL_SESSION;
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0, so, 8, pad32(lbl, "logins")) != CKR_OK) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE a, b, r;
    printf("\n== CKF_SERIAL_SESSION ==\n");
    ok(C_OpenSession(0, CKF_RW_SESSION, NULL, NULL, &r) == CKR_SESSION_PARALLEL_NOT_SUPPORTED,
       "a session without CKF_SERIAL_SESSION is refused with CKR_SESSION_PARALLEL_NOT_SUPPORTED");
    ok(C_OpenSession(0, 0, NULL, NULL, &r) == CKR_SESSION_PARALLEL_NOT_SUPPORTED,
       "and so is one with no flags at all");

    if (C_OpenSession(0, RW, NULL, NULL, &a) != CKR_OK) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_OpenSession(0, RW, NULL, NULL, &b) != CKR_OK) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(a, CKU_SO, so, 8) != CKR_OK) { fprintf(stderr,"C_Login SO\n"); return 2; }
    if (C_InitPIN(a, up, 8) != CKR_OK) { fprintf(stderr,"C_InitPIN\n"); return 2; }

    printf("\n== SO holds the token ==\n");
    ok(C_Login(b, CKU_USER, up, 8) == CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
       "C_Login(USER) is refused with CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
    ok(state_of(a) == CKS_RW_SO_FUNCTIONS,
       "and the SO still holds it");
    ok(C_OpenSession(0, RO, NULL, NULL, &r) == CKR_SESSION_READ_WRITE_SO_EXISTS,
       "a read-only session is refused with CKR_SESSION_READ_WRITE_SO_EXISTS");
    ok(C_OpenSession(0, RW, NULL, NULL, &r) == CKR_OK && C_CloseSession(r) == CKR_OK,
       "a read-write one is not");
    ok(C_Login(b, CKU_SO, so, 8) == CKR_USER_ALREADY_LOGGED_IN,
       "C_Login(SO) again is CKR_USER_ALREADY_LOGGED_IN, unchanged");
    C_Logout(a);

    printf("\n== USER holds the token ==\n");
    if (C_Login(a, CKU_USER, up, 8) != CKR_OK) { fprintf(stderr,"C_Login USER\n"); return 2; }
    ok(C_Login(b, CKU_SO, so, 8) == CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
       "C_Login(SO) with the right PIN is refused with CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
    ok(state_of(a) == CKS_RW_USER_FUNCTIONS,
       "and the USER still holds the token");
    /* Login state is per token: C_GetSessionInfo on a sibling session that
     * never called C_Login must say so. It read a per-session copy. */
    ok(state_of(b) == CKS_RW_USER_FUNCTIONS,
       "a sibling session reports the USER state too");
    /* Before the fix a wrong PIN here counted against the SO. Five of them
     * (FHSM_PIN_MAX_FAILED) would lock the SO out of a token it was never
     * allowed to log into. */
    for (int i = 0; i < 12; ++i) (void)C_Login(b, CKU_SO, bad, 8);
    C_Logout(b);   /* from the sibling: a peer session may log the token out */
    ok(state_of(a) == 2UL /* CKS_RW_PUBLIC_SESSION */,
       "and after it logs out, the session that logged in reports public");
    ok(C_Login(b, CKU_SO, so, 8) == CKR_OK,
       "twelve wrong SO PINs offered meanwhile cost no attempt: the SO still logs in");
    C_Logout(b);

    printf("\n== a read-only session is open ==\n");
    if (C_OpenSession(0, RO, NULL, NULL, &r) != CKR_OK) { fprintf(stderr,"C_OpenSession RO\n"); return 2; }
    ok(C_Login(a, CKU_SO, so, 8) == CKR_SESSION_READ_ONLY_EXISTS,
       "C_Login(SO) is refused with CKR_SESSION_READ_ONLY_EXISTS");
    ok(C_Login(a, CKU_USER, up, 8) == CKR_OK,
       "C_Login(USER) is not --- the rule is the SO's");
    C_Logout(a);
    C_CloseSession(r);
    ok(C_Login(a, CKU_SO, so, 8) == CKR_OK,
       "once it is closed, C_Login(SO) succeeds");

    printf("\n== the last session closes ==\n");
    C_CloseSession(b);
    ok(C_CloseSession(a) == CKR_OK, "closing the last session succeeds");
    ok(C_OpenSession(0, RO, NULL, NULL, &r) == CKR_OK,
       "and logs the SO out: a read-only session opens afterwards");
    ok(state_of(r) == 0UL /* CKS_RO_PUBLIC_SESSION */,
       "in the public state");
    ok(C_Login(r, CKU_USER, up, 8) == CKR_OK,
       "and C_Login(USER) on it is a real login, not CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
    C_CloseSession(r);

    if (fails) { fprintf(stderr, "\ntest_login_conflicts : %d FAIL\n", fails); return 1; }
    printf("\ntest_login_conflicts : PASS\n");
    return 0;
}
