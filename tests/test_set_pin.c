/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_set_pin.c --- C_SetPIN changes a PIN, in the three session states
 * PKCS#11 v3.2 §5.4.7 gives it.
 *
 * "C_SetPIN modifies the PIN of the user that is currently logged in, or the
 * CKU_USER PIN if the session is not logged in", from an R/W public, R/W user
 * or R/W SO session. The module refused a session that was not logged in
 * with CKR_USER_NOT_LOGGED_IN, and verified the old PIN of a logged-in one
 * through the login path, which answers CKR_USER_ALREADY_LOGGED_IN before it
 * looks at a PIN. No PIN could be changed in any state (#36, reported by
 * Alexandre Laroche).
 *
 * The cases:
 *   (1) before C_InitPIN there is no user PIN to change:
 *       CKR_USER_PIN_NOT_INITIALIZED;
 *   (2) R/W user session: the PIN changes, the session stays logged in, the
 *       old PIN no longer logs in and the new one does;
 *   (3) a wrong old PIN is CKR_PIN_INCORRECT and changes nothing;
 *   (4) R/W public session: the user's PIN changes, nobody is logged in
 *       afterwards, and the private token object made in (2) is still read
 *       with the new PIN -- the store key is wrapped again, not replaced;
 *   (5) R/W SO session: the SO PIN changes and the user's does not;
 *   (6) a read-only session is CKR_SESSION_READ_ONLY;
 *   (7) in a new process image (C_Finalize, C_Initialize) both new PINs log
 *       in and the object is still there: the change reached the token file.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_SLOT_ID slotID; CK_ULONG state; CK_FLAGS flags;
                 CK_ULONG ulDeviceError; } CK_SESSION_INFO;

#define CKR_OK                        0x000UL
#define CKR_PIN_INCORRECT             0x0A0UL
#define CKR_SESSION_READ_ONLY         0x0B5UL
#define CKR_USER_PIN_NOT_INITIALIZED  0x102UL
#define CKF_RW                        6UL   /* CKF_SERIAL_SESSION | CKF_RW_SESSION */
#define CKF_RO                        4UL
#define CKS_RW_PUBLIC_SESSION         2UL
#define CKS_RW_USER_FUNCTIONS         3UL
#define CKS_RW_SO_FUNCTIONS           4UL
#define CKU_SO                        0UL
#define CKU_USER                      1UL
#define CKO_DATA                      0UL
#define CKA_CLASS                     0x000UL
#define CKA_TOKEN                     0x001UL
#define CKA_PRIVATE                   0x002UL
#define CKA_LABEL                     0x003UL
#define CKA_VALUE                     0x011UL

/* Test PINs, for a token this program makes in a throwaway directory. */
#define SO_PIN    "sopin1234"
#define SO_PIN2   "sopin5678"
#define USER_PIN  "userpin1234"
#define USER_PIN2 "userpin5678"
#define USER_PIN3 "userpin9012"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
static CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE, CK_SESSION_INFO*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SetPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV login(CK_SESSION_HANDLE s, CK_ULONG who, const char *pin) {
    return C_Login(s, who, (CK_BYTE*)pin, strlen(pin));
}
static CK_RV setpin(CK_SESSION_HANDLE s, const char *old, const char *new_) {
    return C_SetPIN(s, (CK_BYTE*)old, strlen(old), (CK_BYTE*)new_, strlen(new_));
}
static CK_ULONG state(CK_SESSION_HANDLE s) {
    CK_SESSION_INFO i; memset(&i, 0xff, sizeof i);
    return C_GetSessionInfo(s, &i) == CKR_OK ? i.state : (CK_ULONG)-1;
}

static const char SECRET[] = "kept across the PIN change";

/* 1 when the private token data object is found and holds SECRET. */
static int secret_read(CK_SESSION_HANDLE s) {
    CK_ULONG cls = CKO_DATA;
    CK_ATTRIBUTE f[] = { { CKA_CLASS, &cls, sizeof cls },
                         { CKA_LABEL, (void*)"set-pin", 7 } };
    CK_OBJECT_HANDLE h = 0; CK_ULONG n = 0;
    if (C_FindObjectsInit(s, f, 2) != CKR_OK) return 0;
    (void)C_FindObjects(s, &h, 1, &n);
    (void)C_FindObjectsFinal(s);
    if (n != 1) return 0;
    char buf[64] = {0};
    CK_ATTRIBUTE v = { CKA_VALUE, buf, sizeof buf };
    if (C_GetAttributeValue(s, h, &v, 1) != CKR_OK) return 0;
    return v.ulValueLen == sizeof SECRET - 1 && !memcmp(buf, SECRET, sizeof SECRET - 1);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_CloseSession); SYM(C_GetSessionInfo); SYM(C_Login); SYM(C_Logout);
    SYM(C_InitPIN); SYM(C_SetPIN); SYM(C_CreateObject); SYM(C_GetAttributeValue);
    SYM(C_FindObjectsInit); SYM(C_FindObjects); SYM(C_FindObjectsFinal);
    if (!C_SetPIN || !C_GetSessionInfo || !C_FindObjectsFinal || !C_CloseSession) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("C_SetPIN in its three session states\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"setpin",6);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }

    /* (1) No user PIN yet. */
    ok(setpin(s, USER_PIN, USER_PIN2) == CKR_USER_PIN_NOT_INITIALIZED,
       "(1) before C_InitPIN: CKR_USER_PIN_NOT_INITIALIZED");

    if (login(s, CKU_SO, SO_PIN)) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (login(s, CKU_USER, USER_PIN)) { fprintf(stderr,"USER\n"); return 2; }

    CK_ULONG cls = CKO_DATA; CK_BYTE yes = 1;
    CK_ATTRIBUTE dt[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_TOKEN, &yes, 1 },
                          { CKA_PRIVATE, &yes, 1 }, { CKA_LABEL, (void*)"set-pin", 7 },
                          { CKA_VALUE, (void*)SECRET, sizeof SECRET - 1 } };
    CK_OBJECT_HANDLE obj = 0;
    if (C_CreateObject(s, dt, 5, &obj)) { fprintf(stderr,"C_CreateObject\n"); return 2; }

    /* (2) R/W user session. */
    ok(setpin(s, USER_PIN, USER_PIN2) == CKR_OK, "(2) user session: C_SetPIN is CKR_OK");
    ok(state(s) == CKS_RW_USER_FUNCTIONS, "(2) the session is still the user's");
    ok(secret_read(s), "(2) the private object is still read");
    (void)C_Logout(s);
    ok(login(s, CKU_USER, USER_PIN) == CKR_PIN_INCORRECT, "(2) the old PIN no longer logs in");
    ok(login(s, CKU_USER, USER_PIN2) == CKR_OK, "(2) the new PIN logs in");

    /* (3) A wrong old PIN. */
    ok(setpin(s, USER_PIN, USER_PIN3) == CKR_PIN_INCORRECT,
       "(3) a wrong old PIN is CKR_PIN_INCORRECT");
    ok(state(s) == CKS_RW_USER_FUNCTIONS, "(3) the session is still the user's");
    (void)C_Logout(s);
    ok(login(s, CKU_USER, USER_PIN2) == CKR_OK, "(3) the PIN did not change");
    (void)C_Logout(s);

    /* (4) R/W public session: the user's PIN. */
    ok(state(s) == CKS_RW_PUBLIC_SESSION, "(4) nobody is logged in");
    ok(setpin(s, USER_PIN2, USER_PIN3) == CKR_OK, "(4) public session: C_SetPIN is CKR_OK");
    ok(state(s) == CKS_RW_PUBLIC_SESSION, "(4) nobody is logged in afterwards");
    ok(!secret_read(s), "(4) the private object is not read without a login");
    ok(login(s, CKU_USER, USER_PIN3) == CKR_OK, "(4) the new PIN logs in");
    ok(secret_read(s), "(4) the private object is read with the new PIN");
    (void)C_Logout(s);

    /* (5) R/W SO session: the SO PIN, and only it. */
    if (login(s, CKU_SO, SO_PIN)) { fprintf(stderr,"SO (5)\n"); return 2; }
    ok(setpin(s, SO_PIN, SO_PIN2) == CKR_OK, "(5) SO session: C_SetPIN is CKR_OK");
    ok(state(s) == CKS_RW_SO_FUNCTIONS, "(5) the session is still the SO's");
    (void)C_Logout(s);
    ok(login(s, CKU_SO, SO_PIN) == CKR_PIN_INCORRECT, "(5) the old SO PIN no longer logs in");
    ok(login(s, CKU_SO, SO_PIN2) == CKR_OK, "(5) the new SO PIN logs in");
    (void)C_Logout(s);
    ok(login(s, CKU_USER, USER_PIN3) == CKR_OK, "(5) the user's PIN did not change");
    (void)C_Logout(s);

    /* (6) A read-only session. The SO cannot log in while one is open, so it
     * is closed again here. */
    CK_SESSION_HANDLE ro = 0;
    if (C_OpenSession(0,CKF_RO,NULL,NULL,&ro)) { fprintf(stderr,"C_OpenSession ro\n"); return 2; }
    ok(setpin(ro, USER_PIN3, USER_PIN) == CKR_SESSION_READ_ONLY,
       "(6) read-only session: CKR_SESSION_READ_ONLY");
    (void)C_CloseSession(ro);
    ok(login(s, CKU_USER, USER_PIN3) == CKR_OK, "(6) the PIN did not change");
    (void)C_Logout(s);

    /* (7) A new process image. */
    C_Finalize(NULL);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize (7)\n"); return 2; }
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession (7)\n"); return 2; }
    ok(login(s, CKU_USER, USER_PIN3) == CKR_OK, "(7) new image: the user's new PIN logs in");
    ok(secret_read(s), "(7) new image: the private object is read");
    (void)C_Logout(s);
    ok(login(s, CKU_SO, SO_PIN2) == CKR_OK, "(7) new image: the SO's new PIN logs in");
    (void)C_Logout(s);

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
