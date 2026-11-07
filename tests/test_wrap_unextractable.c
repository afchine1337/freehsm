/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_wrap_unextractable.c --- C_WrapKey refuses every key whose
 * CKA_EXTRACTABLE is FALSE, sensitive or not.
 *
 * §5.18.5: "The CKA_EXTRACTABLE attribute of the key to be wrapped MUST also
 * be CK_TRUE." C_WrapKey refused only a key that was sensitive *and*
 * unextractable. A key created with CKA_EXTRACTABLE=FALSE and
 * CKA_SENSITIVE=FALSE -- CKA_SENSITIVE defaults to FALSE, so a template that
 * names only CKA_EXTRACTABLE=FALSE gives exactly that key -- was wrapped on
 * request, although C_GetAttributeValue withheld its value for the same flag.
 * Found by pkcs11-check 0.3.0, which reached it from five directions: a key
 * created so, one cleared by C_SetAttributeValue, a C_CopyObject copy, and
 * keys derived by the byte KDFs and by HKDF.
 *
 * The cases:
 *   (1) control: SENSITIVE=FALSE, EXTRACTABLE=TRUE wraps. If wrapping is
 *       broken for another reason, the refusals below would pass for the
 *       wrong one, and this case says so.
 *   (2) SENSITIVE=FALSE, EXTRACTABLE=FALSE is refused CKR_KEY_UNEXTRACTABLE,
 *       on the size query as well as on the real call.
 *   (3) the template names only CKA_EXTRACTABLE=FALSE: refused.
 *   (4) SENSITIVE=TRUE, EXTRACTABLE=FALSE: refused, as before.
 *   (5) EXTRACTABLE cleared by C_SetAttributeValue: refused afterwards.
 *   (6) a C_CopyObject copy made with CKA_EXTRACTABLE=FALSE: refused, while
 *       its extractable source still wraps.
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
#define CKR_KEY_UNEXTRACTABLE        0x6AUL
#define CKF_RW                       6UL
#define CKA_CLASS                    0UL
#define CKA_TOKEN                    1UL
#define CKA_LABEL                    3UL
#define CKA_VALUE                    0x11UL
#define CKA_KEY_TYPE                 0x100UL
#define CKA_SENSITIVE                0x103UL
#define CKA_WRAP                     0x106UL
#define CKA_EXTRACTABLE              0x162UL
#define CKO_SECRET_KEY               4UL
#define CKK_AES                      0x1FUL
#define CKM_AES_KEY_WRAP             0x2109UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

/* Which of CKA_SENSITIVE / CKA_EXTRACTABLE the template names. */
#define OMIT (-1)

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_CopyObject)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,
                             CK_OBJECT_HANDLE*);
static CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_WrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                          CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG*);

static CK_ULONG g_klass = CKO_SECRET_KEY, g_aes = CKK_AES;
static CK_BYTE  g_yes = 1, g_no = 0;
static const CK_BYTE g_val[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };

/* An AES session key. `sens` and `extr` are 1, 0 or OMIT. */
static CK_RV make_key(CK_SESSION_HANDLE s, const char *label, int sens, int extr,
                      int wrap, CK_OBJECT_HANDLE *out)
{
    CK_ATTRIBUTE t[10];
    CK_ULONG c = 0;
    t[c].type = CKA_CLASS;    t[c].pValue = &g_klass; t[c].ulValueLen = sizeof g_klass; c++;
    t[c].type = CKA_KEY_TYPE; t[c].pValue = &g_aes;   t[c].ulValueLen = sizeof g_aes; c++;
    t[c].type = CKA_VALUE;    t[c].pValue = (void*)g_val; t[c].ulValueLen = sizeof g_val; c++;
    t[c].type = CKA_TOKEN;    t[c].pValue = &g_no;  t[c].ulValueLen = 1; c++;
    t[c].type = CKA_LABEL;    t[c].pValue = (void*)label;
                              t[c].ulValueLen = (CK_ULONG)strlen(label); c++;
    if (sens != OMIT) { t[c].type = CKA_SENSITIVE; t[c].pValue = sens ? &g_yes : &g_no;
                        t[c].ulValueLen = 1; c++; }
    if (extr != OMIT) { t[c].type = CKA_EXTRACTABLE; t[c].pValue = extr ? &g_yes : &g_no;
                        t[c].ulValueLen = 1; c++; }
    if (wrap) { t[c].type = CKA_WRAP; t[c].pValue = &g_yes; t[c].ulValueLen = 1; c++; }
    *out = 0;
    return C_CreateObject(s, t, c, out);
}

static CK_RV wrap(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE wrapper, CK_OBJECT_HANDLE k,
                  int size_query)
{
    CK_MECHANISM m = { CKM_AES_KEY_WRAP, NULL, 0 };
    CK_BYTE out[64];
    CK_ULONG ol = sizeof out;
    return C_WrapKey(s, &m, wrapper, k, size_query ? NULL : out, &ol);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject);
    SYM(C_CopyObject); SYM(C_SetAttributeValue); SYM(C_WrapKey);
    if (!C_WrapKey || !C_CopyObject || !C_SetAttributeValue || !C_Logout) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("C_WrapKey and CKA_EXTRACTABLE=FALSE\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"wrapunx",7);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_OBJECT_HANDLE wrapper = 0, open_k = 0, plain_unx = 0, only_unx = 0,
                     sens_unx = 0, cleared = 0, copy = 0;
    if (make_key(s, "wrapper", 0, 1, 1, &wrapper) != CKR_OK) {
        fprintf(stderr, "wrapping key\n"); return 2;
    }

    /* (1) The control. */
    ok(make_key(s, "open", 0, 1, 0, &open_k) == CKR_OK
       && wrap(s, wrapper, open_k, 0) == CKR_OK,
       "(1) SENSITIVE=FALSE, EXTRACTABLE=TRUE wraps (control)");

    /* (2) The case that was let through. */
    ok(make_key(s, "plain-unx", 0, 0, 0, &plain_unx) == CKR_OK,
       "(2) SENSITIVE=FALSE, EXTRACTABLE=FALSE is created");
    ok(wrap(s, wrapper, plain_unx, 0) == CKR_KEY_UNEXTRACTABLE,
       "    and C_WrapKey refuses it with CKR_KEY_UNEXTRACTABLE");
    ok(wrap(s, wrapper, plain_unx, 1) == CKR_KEY_UNEXTRACTABLE,
       "    including on the size query");

    /* (3) The usual way to ask for it: name only CKA_EXTRACTABLE. */
    ok(make_key(s, "only-unx", OMIT, 0, 0, &only_unx) == CKR_OK
       && wrap(s, wrapper, only_unx, 0) == CKR_KEY_UNEXTRACTABLE,
       "(3) a template naming only EXTRACTABLE=FALSE: refused");

    /* (4) What was already refused stays refused. */
    ok(make_key(s, "sens-unx", 1, 0, 0, &sens_unx) == CKR_OK
       && wrap(s, wrapper, sens_unx, 0) == CKR_KEY_UNEXTRACTABLE,
       "(4) SENSITIVE=TRUE, EXTRACTABLE=FALSE: refused");

    /* (5) Cleared after creation. */
    {
        CK_ATTRIBUTE clr = { CKA_EXTRACTABLE, &g_no, 1 };
        ok(make_key(s, "cleared", 0, 1, 0, &cleared) == CKR_OK
           && wrap(s, wrapper, cleared, 0) == CKR_OK
           && C_SetAttributeValue(s, cleared, &clr, 1) == CKR_OK
           && wrap(s, wrapper, cleared, 0) == CKR_KEY_UNEXTRACTABLE,
           "(5) wraps, EXTRACTABLE cleared by C_SetAttributeValue, then refused");
    }

    /* (6) A copy made unextractable. */
    {
        CK_ATTRIBUTE ct = { CKA_EXTRACTABLE, &g_no, 1 };
        ok(C_CopyObject(s, open_k, &ct, 1, &copy) == CKR_OK
           && wrap(s, wrapper, copy, 0) == CKR_KEY_UNEXTRACTABLE,
           "(6) a copy made with EXTRACTABLE=FALSE: refused");
        ok(wrap(s, wrapper, open_k, 0) == CKR_OK,
           "    while its extractable source still wraps");
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
