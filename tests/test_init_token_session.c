/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_init_token_session.c --- C_InitToken with a session open.
 *
 * PKCS#11 v3.2 answers CKR_SESSION_EXISTS when C_InitToken is called while a
 * session is open with the token; the module re-initialized it under the
 * session's feet. Checked here: refused with a session open on the slot,
 * read-only or read/write; accepted again once it is closed; and a session on
 * another slot does not stand in the way.
 * ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_FLAGS;

#define CKF_RW_SESSION      0x2UL
#define CKF_SERIAL_SESSION  0x4UL
#define CKR_SESSION_EXISTS  0xB6UL

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

int main(void) {
    void *H = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!H) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*I)(void*); CK_RV (*F)(void*);
    CK_RV (*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*CS)(CK_SESSION_HANDLE);
    #define S(n,nm) *(void**)&n = dlsym(H, nm)
    S(I,"C_Initialize"); S(F,"C_Finalize"); S(IT,"C_InitToken");
    S(OS,"C_OpenSession"); S(CS,"C_CloseSession");

    printf("C_InitToken with a session open\n\n");

    CK_BYTE so[] = "00000000", lbl[32];
    if (I(NULL) != 0) { fprintf(stderr, "C_Initialize\n"); return 2; }
    ok(IT(0, so, 8, pad_label(lbl, "first")) == 0, "no session: the token is initialized");

    CK_SESSION_HANDLE s = 0;
    OS(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &s);
    ok(IT(0, so, 8, pad_label(lbl, "second")) == CKR_SESSION_EXISTS,
       "a read/write session open: CKR_SESSION_EXISTS");
    CS(s);

    OS(0, CKF_SERIAL_SESSION, NULL, NULL, &s);
    ok(IT(0, so, 8, pad_label(lbl, "second")) == CKR_SESSION_EXISTS,
       "a read-only session open: CKR_SESSION_EXISTS");
    CS(s);

    ok(IT(0, so, 8, pad_label(lbl, "second")) == 0,
       "the session closed: the token is re-initialized");

    /* Slot 1, if the build has one: its session does not concern slot 0. Its
     * token is initialized first; C_OpenSession refuses a slot without one. */
    CK_SESSION_HANDLE s1 = 0;
    if (IT(1, so, 8, pad_label(lbl, "other")) == 0
        && OS(1, CKF_SERIAL_SESSION, NULL, NULL, &s1) == 0) {
        ok(IT(0, so, 8, pad_label(lbl, "third")) == 0,
           "a session on another slot does not stand in the way");
        CS(s1);
    }
    F(NULL);

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
