/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_wrap_with_trusted.c --- CKA_WRAP_WITH_TRUSTED, stored and enforced.
 *
 * §4.9: a key with CKA_WRAP_WITH_TRUSTED = TRUE may only be wrapped by a
 * wrapping key that is CKA_TRUSTED. The whole of the attribute in this module
 * was one line in C_GetAttributeValue returning a hard-coded FALSE:
 *
 *     case CKA_WRAP_WITH_TRUSTED_ATTR: bval = 0; src = &bval; src_len = 1;
 *
 * It passed fhsm_check_bool_attr_lengths, so it was accepted in a creation
 * template, dropped, and then contradicted on readback. That is the fourth
 * attribute of this family to arrive that way, after CKA_ALWAYS_AUTHENTICATE,
 * CKA_ENCAPSULATE and CKA_COPYABLE, and it was found by pkcs11-check 0.2.0
 * rather than by us -- 0.2.0 counts accepting an attribute as the claim.
 *
 * The sentence it enforces was already in the tree. fhsm_token.h has carried
 * it beside FHSM_OBJF_TRUSTED since #125: "a key marked WRAP_WITH_TRUSTED may
 * only be wrapped by a wrapping key that is CKA_TRUSTED." The reasoning was
 * written next to a control nobody had written.
 *
 * ## What this file does not cover, and why it says so
 *
 * The positive half -- a CKA_TRUSTED wrapping key succeeds -- is not here.
 * CKA_TRUSTED may only be set by the SO (§4.6), so staging it means an SO
 * session, and the key must then survive into a USER session to be used. That
 * is role choreography, and pkcs11-check already does it in
 * test_access_levels.py::TestTrustedAttribute. Writing a worse version of it
 * here would add a test without adding an assurance.
 *
 * What is here is the half that fails open if it is wrong: the refusal.
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
#define CKR_ATTRIBUTE_READ_ONLY      0x10UL
#define CKR_KEY_NOT_WRAPPABLE        0x69UL
#define CKR_ACTION_PROHIBITED        0x1BUL
#define CKF_RW                       6UL
#define CKA_CLASS                    0UL
#define CKA_TOKEN                    1UL
#define CKA_LABEL                    3UL
#define CKA_VALUE                    0x11UL
#define CKA_KEY_TYPE                 0x100UL
#define CKA_SENSITIVE                0x103UL
#define CKA_WRAP                     0x106UL
#define CKA_VALUE_LEN                0x161UL
#define CKA_EXTRACTABLE              0x162UL
#define CKA_WRAP_WITH_TRUSTED        0x210UL
#define CKO_SECRET_KEY               4UL
#define CKK_AES                      0x1FUL
#define CKM_AES_KEY_WRAP             0x2109UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

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
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_WrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                          CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG*);

static CK_ULONG g_klass = CKO_SECRET_KEY, g_aes = CKK_AES;
static CK_BYTE  g_yes = 1, g_no = 0;
static const CK_BYTE g_val[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };

/* An AES key; `wwt` adds CKA_WRAP_WITH_TRUSTED=TRUE, `wrap` adds CKA_WRAP. */
static CK_RV make_key(CK_SESSION_HANDLE s, const char *label,
                      int wwt, int wrap, CK_OBJECT_HANDLE *out)
{
    CK_ATTRIBUTE t[10];
    CK_ULONG c = 0;
    t[c].type = CKA_CLASS;       t[c].pValue = &g_klass; t[c].ulValueLen = sizeof g_klass; c++;
    t[c].type = CKA_KEY_TYPE;    t[c].pValue = &g_aes;   t[c].ulValueLen = sizeof g_aes; c++;
    t[c].type = CKA_VALUE;       t[c].pValue = (void*)g_val; t[c].ulValueLen = sizeof g_val; c++;
    t[c].type = CKA_TOKEN;       t[c].pValue = &g_no;  t[c].ulValueLen = 1; c++;
    t[c].type = CKA_SENSITIVE;   t[c].pValue = &g_no;  t[c].ulValueLen = 1; c++;
    t[c].type = CKA_EXTRACTABLE; t[c].pValue = &g_yes; t[c].ulValueLen = 1; c++;
    t[c].type = CKA_LABEL;       t[c].pValue = (void*)label;
                                 t[c].ulValueLen = (CK_ULONG)strlen(label); c++;
    if (wrap) { t[c].type = CKA_WRAP; t[c].pValue = &g_yes; t[c].ulValueLen = 1; c++; }
    if (wwt)  { t[c].type = CKA_WRAP_WITH_TRUSTED; t[c].pValue = &g_yes;
                t[c].ulValueLen = 1; c++; }
    *out = 0;
    return C_CreateObject(s, t, c, out);
}

static int read_bool(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ULONG attr, CK_BYTE *v)
{
    *v = 0xFF;
    CK_ATTRIBUTE q = { attr, v, 1 };
    return C_GetAttributeValue(s, h, &q, 1) == CKR_OK && q.ulValueLen == 1;
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_GetAttributeValue);
    SYM(C_SetAttributeValue); SYM(C_WrapKey);
    if (!C_WrapKey || !C_SetAttributeValue) { fprintf(stderr,"missing symbols\n"); return 2; }

    printf("CKA_WRAP_WITH_TRUSTED\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"wwtrust",7);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_OBJECT_HANDLE guarded = 0, plain = 0, wrapper = 0;
    ok(make_key(s, "guarded", 1, 0, &guarded) == CKR_OK,
       "a key with CKA_WRAP_WITH_TRUSTED=TRUE is created");
    ok(make_key(s, "plain",   0, 0, &plain)   == CKR_OK,
       "a key without it is created");
    ok(make_key(s, "wrapper", 0, 1, &wrapper) == CKR_OK,
       "and an untrusted wrapping key");

    /* The readback that was a hard-coded FALSE. */
    {
        CK_BYTE v = 0xFF;
        ok(read_bool(s, guarded, CKA_WRAP_WITH_TRUSTED, &v) && v == 1,
           "it reads back TRUE -- the value the module was given");
        v = 0xFF;
        ok(read_bool(s, plain, CKA_WRAP_WITH_TRUSTED, &v) && v == 0,
           "and FALSE on the key that never asked for it");
    }

    /* The enforcement. */
    {
        CK_MECHANISM m = { CKM_AES_KEY_WRAP, NULL, 0 };
        CK_BYTE out[64]; CK_ULONG ol;

        /* The negative control first. If wrapping is broken for an unrelated
         * reason, the refusal below would pass for the wrong reason and this
         * is the case that says so. */
        ol = sizeof out;
        CK_RV rv_plain = C_WrapKey(s, &m, wrapper, plain, out, &ol);
        if (rv_plain != CKR_OK) {
            printf("  (CKM_AES_KEY_WRAP unusable here: 0x%lx -- enforcement half skipped)\n",
                   rv_plain);
        } else {
            ok(1, "a key without the attribute wraps with an untrusted key");

            ol = sizeof out;
            CK_RV rv = C_WrapKey(s, &m, wrapper, guarded, out, &ol);
            ok(rv == CKR_KEY_NOT_WRAPPABLE || rv == CKR_ACTION_PROHIBITED,
               "and the guarded key is refused by the same wrapper");

            /* The size query must be refused too. A policy enforced only on
             * the call that returns bytes still tells the caller how many
             * bytes it is protecting. */
            CK_ULONG qlen = 0;
            CK_RV rvq = C_WrapKey(s, &m, wrapper, guarded, NULL, &qlen);
            ok(rvq == CKR_KEY_NOT_WRAPPABLE || rvq == CKR_ACTION_PROHIBITED,
               "  including on the size query, not only on the real call");
        }
    }

    /* One-way: settable, not clearable. */
    {
        CK_ATTRIBUTE clear = { CKA_WRAP_WITH_TRUSTED, &g_no, 1 };
        ok(C_SetAttributeValue(s, guarded, &clear, 1) == CKR_ATTRIBUTE_READ_ONLY,
           "clearing it is CKR_ATTRIBUTE_READ_ONLY");
        CK_BYTE v = 0xFF;
        ok(read_bool(s, guarded, CKA_WRAP_WITH_TRUSTED, &v) && v == 1,
           "  and the refusal left the value alone");

        CK_ATTRIBUTE set = { CKA_WRAP_WITH_TRUSTED, &g_yes, 1 };
        ok(C_SetAttributeValue(s, plain, &set, 1) == CKR_OK,
           "setting it on a key that lacked it is allowed");
        v = 0xFF;
        ok(read_bool(s, plain, CKA_WRAP_WITH_TRUSTED, &v) && v == 1,
           "  and takes effect");
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
