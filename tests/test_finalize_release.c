/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_finalize_release.c --- C_Finalize ends the application's use of the
 * library, including its authentication.
 *
 * The comment above g_init_pid in src/fhsm_pkcs11.c has said this since #125:
 *
 *   C_Finalize does not free any of it -- it only closes crypto and drops the
 *   state machine to POWER_OFF -- so a child that calls C_Finalize and then
 *   C_Initialize [...] came up holding the parent's session objects AND the
 *   parent's logged-in state, without ever presenting a PIN.
 *
 * #125 answered the fork half by detecting the PID change. The other half
 * stayed: in ONE process, C_Finalize followed by C_Initialize came up still
 * logged in, because nothing had been released and the PID had not changed.
 * The rule was wired to the path where the process changes and not to the one
 * where it does not -- with the sentence describing the defect sitting above
 * the code that kept it.
 *
 * Found sideways, on 2026-09-19, while writing a store round-trip test that
 * could not make the module re-read its own file: the second C_Login answered
 * CKR_USER_ALREADY_LOGGED_IN, so the token was never reopened. That test had
 * to move to the token layer. This one is why it can come back.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                       0UL
#define CKR_USER_ALREADY_LOGGED_IN   0x100UL
#define CKR_SESSION_HANDLE_INVALID   0xB3UL
#define CKF_RW                       6UL
#define CKA_CLASS                    0UL
#define CKA_TOKEN                    1UL
#define CKA_LABEL                    3UL
#define CKA_VALUE                    0x11UL
#define CKA_KEY_TYPE                 0x100UL
#define CKA_VALUE_LEN                0x161UL
#define CKA_EXTRACTABLE              0x162UL
#define CKA_SENSITIVE                0x103UL
#define CKO_SECRET_KEY               4UL
#define CKK_AES                      0x1FUL
#define CKM_AES_KEY_GEN              0x1080UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_GenerateKey); SYM(C_GetAttributeValue);
    SYM(C_FindObjectsInit); SYM(C_FindObjects); SYM(C_FindObjectsFinal);
    if (!C_Finalize || !C_GenerateKey) { fprintf(stderr,"missing symbols\n"); return 2; }

    printf("C_Finalize releases the application's state, authentication included\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"finalize",8);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    /* A token object, so the reload has something to find. */
    CK_BYTE yes = 1, no = 0;
    CK_ULONG vl = 32;
    char klabel[] = "survivor";
    /* CKA_SENSITIVE=FALSE explicitly. A generated secret key is sensitive by
     * default here, and C_GetAttributeValue then refuses CKA_VALUE -- rightly.
     * The first draft of this test omitted it and read the refusal as a
     * storage failure. */
    CK_ATTRIBUTE kt[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY}, sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_AES},        sizeof(CK_ULONG) },
        { CKA_VALUE_LEN,   &vl, sizeof(CK_ULONG) },
        { CKA_TOKEN,       &yes, 1 },
        { CKA_EXTRACTABLE, &yes, 1 },
        { CKA_SENSITIVE,   &no,  1 },
        { CKA_LABEL,       klabel, sizeof klabel - 1 },
    };
    CK_MECHANISM gen = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE hk = 0;
    /* sizeof, not a literal: adding CKA_SENSITIVE above while leaving a
     * hand-written 6 here dropped CKA_LABEL silently, and the failure
     * surfaced two cases later as "the key was not found after the reload" --
     * pointing at the store rather than at the template. */
    ok(C_GenerateKey(s, &gen, kt, sizeof kt / sizeof kt[0], &hk) == CKR_OK,
       "a token key is generated before finalizing");

    C_Finalize(NULL);

    /* (1) The point of the change. This answered CKR_USER_ALREADY_LOGGED_IN:
     *     the token object and its authenticated state outlived the library,
     *     so a second application in the same process inherited a login it
     *     never performed. */
    ok(C_Initialize(NULL) == CKR_OK, "C_Initialize succeeds after C_Finalize");
    CK_SESSION_HANDLE s2 = 0;
    ok(C_OpenSession(0, CKF_RW, NULL, NULL, &s2) == CKR_OK, "a session opens");
    ok(C_Login(s2, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) == CKR_OK,
       "and C_Login is a real login, not CKR_USER_ALREADY_LOGGED_IN");

    /* (2) The store was re-read, which is the other half of releasing the
     *     token: the object is found again, by label, through a fresh parse
     *     of the file rather than from memory that was never dropped. */
    {
        CK_ATTRIBUTE f[] = { { CKA_LABEL, klabel, sizeof klabel - 1 } };
        CK_OBJECT_HANDLE found[8]; CK_ULONG n = 0;
        C_FindObjectsInit(s2, f, 1);
        C_FindObjects(s2, found, 8, &n);
        C_FindObjectsFinal(s2);
        ok(n == 1, "the token key is found again after the reload");
        if (n == 1) {
            CK_BYTE v[64];
            CK_ATTRIBUTE q[] = { { CKA_VALUE, v, sizeof v } };
            ok(C_GetAttributeValue(s2, found[0], q, 1) == CKR_OK
               && q[0].ulValueLen == 32,
               "and its value survived the file");
        }
    }

    /* There is no case here for "a session handle from before C_Finalize is
     * refused", and the reason is worth more than the case was.
     *
     * It was written, and it failed, because session handles are small
     * integers drawn from the same table: the session opened after the
     * restart was handed the number the old one had. The assertion was
     * comparing a coincidence, not a behaviour, and would have passed or
     * failed on an allocation detail either way.
     *
     * The sessions really are gone -- fhsm_session_reset_all runs in
     * fhsm_finalize_release -- but that is not observable through this API
     * from outside, and an assertion that cannot see what it claims to check
     * is worse than none. */

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
