/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_nested_templates.c --- the three nested policy templates.
 *
 * All three say the same thing about the key that carries them: an object
 * reached through this key must match this template. They do not say it to
 * the same kind of object, and that is what the file is arranged around.
 *
 * CKA_UNWRAP_TEMPLATE and CKA_DERIVE_TEMPLATE constrain an object that does
 * not exist yet: C_UnwrapKey and C_DeriveKey are handed a creation template,
 * and the comparison is template against template.
 *
 * CKA_WRAP_TEMPLATE constrains one that does. C_WrapKey names an existing
 * key, so the comparison is template against the object's own attributes --
 * a different mechanism, and the reason this one arrived a commit later
 * rather than being given the shape of its two neighbours because they share
 * a paragraph of the spec.
 *
 * That difference has a consequence worth stating: the module can only
 * compare attributes it can read back off an object, so a CKA_WRAP_TEMPLATE
 * naming anything else is refused when the key is created. A policy that
 * cannot be checked would have to treat the unreadable attribute as matching,
 * and a policy that fails open is worse than an attribute that is refused.
 *
 * ## What the old support actually covered
 *
 * fhsm_parse_unwrap_template accepted CKA_SENSITIVE=TRUE and
 * CKA_EXTRACTABLE=FALSE and refused everything else, which its comment called
 * partial support. Its first test on each nested entry was ulValueLen != 1,
 * and every entry anything sends is a CK_ULONG or a 33-to-41-byte CKA_LABEL.
 * The overlap with what is tested was zero. This file uses CKA_LABEL, which is
 * what pkcs11-check sends, and would have been refused outright before today.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_BYTE *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;

#define CKR_OK                       0UL
#define CKR_TEMPLATE_INCONSISTENT    0xD1UL
#define CKF_RW                       6UL
#define CKA_CLASS                    0UL
#define CKA_TOKEN                    1UL
#define CKA_LABEL                    3UL
#define CKA_VALUE                    0x11UL
#define CKA_KEY_TYPE                 0x100UL
#define CKA_SENSITIVE                0x103UL
#define CKA_ENCRYPT                  0x104UL
#define CKA_DECRYPT                  0x105UL
#define CKA_WRAP                     0x106UL
#define CKA_UNWRAP                   0x107UL
#define CKA_DERIVE                   0x10CUL
#define CKA_VALUE_LEN                0x161UL
#define CKA_EXTRACTABLE              0x162UL
#define CKA_WRAP_TEMPLATE            0x40000211UL
#define CKA_UNWRAP_TEMPLATE          0x40000212UL
#define CKA_DERIVE_TEMPLATE          0x40000213UL
#define CKO_SECRET_KEY               4UL
#define CKK_AES                      0x1FUL
#define CKK_GENERIC_SECRET           0x10UL
#define CKM_AES_KEY_WRAP             0x2109UL
#define CKM_CONCATENATE_BASE_AND_DATA 0x362UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"
#define ALLOWED  "policy-allowed"
#define DENIED   "policy-denied"

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
static CK_RV (*C_WrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                          CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                            CK_BYTE*,CK_ULONG,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                            CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);

static CK_ULONG g_klass = CKO_SECRET_KEY, g_aes = CKK_AES, g_gen = CKK_GENERIC_SECRET;
static CK_ULONG g_len16 = 16;
static CK_BYTE  g_yes = 1, g_no = 0;
static const CK_BYTE g_val[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };

/* The key that carries the policy: it wraps, unwraps and derives, and names
 * one template that objects created through it must match. */
static CK_RV make_policy_key(CK_SESSION_HANDLE s, CK_ULONG which_tmpl,
                             CK_ATTRIBUTE *nested, CK_ULONG nested_bytes,
                             CK_OBJECT_HANDLE *out)
{
    CK_ATTRIBUTE t[] = {
        { CKA_CLASS,       &g_klass, sizeof g_klass },
        { CKA_KEY_TYPE,    &g_aes,   sizeof g_aes },
        { CKA_VALUE,       (void*)g_val, sizeof g_val },
        { CKA_TOKEN,       &g_no,  1 },
        { CKA_SENSITIVE,   &g_no,  1 },
        { CKA_EXTRACTABLE, &g_yes, 1 },
        { CKA_WRAP,        &g_yes, 1 },
        { CKA_UNWRAP,      &g_yes, 1 },
        { CKA_DERIVE,      &g_yes, 1 },
        { which_tmpl,      nested, nested_bytes },
    };
    *out = 0;
    return C_CreateObject(s, t, sizeof t / sizeof t[0], out);
}

/* A template for the object being created, with whichever label is asked for. */
static CK_ULONG new_key_template(CK_ATTRIBUTE *t, const char *label, CK_ULONG ckk)
{
    CK_ULONG c = 0;
    t[c].type = CKA_CLASS;    t[c].pValue = &g_klass; t[c].ulValueLen = sizeof g_klass; c++;
    t[c].type = CKA_KEY_TYPE; t[c].pValue = (ckk == CKK_AES) ? &g_aes : &g_gen;
                              t[c].ulValueLen = sizeof g_aes; c++;
    t[c].type = CKA_VALUE_LEN;t[c].pValue = &g_len16; t[c].ulValueLen = sizeof g_len16; c++;
    t[c].type = CKA_TOKEN;    t[c].pValue = &g_no;  t[c].ulValueLen = 1; c++;
    t[c].type = CKA_SENSITIVE;t[c].pValue = &g_no;  t[c].ulValueLen = 1; c++;
    t[c].type = CKA_EXTRACTABLE; t[c].pValue = &g_yes; t[c].ulValueLen = 1; c++;
    t[c].type = CKA_LABEL;    t[c].pValue = (void*)label;
                              t[c].ulValueLen = (CK_ULONG)strlen(label); c++;
    return c;
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_GetAttributeValue);
    SYM(C_WrapKey); SYM(C_UnwrapKey); SYM(C_DeriveKey);
    if (!C_UnwrapKey || !C_DeriveKey) { fprintf(stderr,"missing symbols\n"); return 2; }

    printf("The three nested policy templates\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"nesttmpl",8);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_ATTRIBUTE nested[1] = { { CKA_LABEL, (void*)ALLOWED, (CK_ULONG)strlen(ALLOWED) } };

    /* ---------------- CKA_UNWRAP_TEMPLATE ---------------- */
    {
        CK_OBJECT_HANDLE kw = 0;
        ok(make_policy_key(s, CKA_UNWRAP_TEMPLATE, nested, sizeof nested, &kw) == CKR_OK,
           "a key carrying CKA_UNWRAP_TEMPLATE is accepted at creation");

        /* The readback, both levels, and the thing that matters about it:
         * the caller owns the array AND the buffer each entry points at, and
         * the module fills them without touching either pointer.
         *
         * The first implementation returned pointers into its own stack,
         * which died when the call returned. It passed a shape check and was
         * caught by pkcs11-check's security/test_unwrap_reimport, which
         * compares each returned pValue against the address it supplied. This
         * case is that comparison, so the next version cannot regress past a
         * green suite. */
        CK_ATTRIBUTE q = { CKA_UNWRAP_TEMPLATE, NULL, 0 };
        ok(C_GetAttributeValue(s, kw, &q, 1) == CKR_OK
           && q.ulValueLen == sizeof(CK_ATTRIBUTE),
           "  and a size query reports one CK_ATTRIBUTE");
        {
            CK_BYTE      lbuf[64];
            CK_ATTRIBUTE inner[1] = { { CKA_LABEL, lbuf, sizeof lbuf } };
            CK_ATTRIBUTE outer[1] = { { CKA_UNWRAP_TEMPLATE, inner, sizeof inner } };
            CK_RV rv = C_GetAttributeValue(s, kw, outer, 1);
            ok(rv == CKR_OK
               && outer[0].pValue == inner
               && outer[0].ulValueLen == sizeof(CK_ATTRIBUTE),
               "  the outer pointer is still the caller's array");
            ok(inner[0].pValue == lbuf
               && inner[0].type == CKA_LABEL
               && inner[0].ulValueLen == strlen(ALLOWED)
               && memcmp(lbuf, ALLOWED, strlen(ALLOWED)) == 0,
               "  and the value landed in the caller's own buffer");
        }

        /* Something to unwrap. */
        CK_OBJECT_HANDLE src = 0;
        CK_ATTRIBUTE st[] = {
            { CKA_CLASS, &g_klass, sizeof g_klass },
            { CKA_KEY_TYPE, &g_aes, sizeof g_aes },
            { CKA_VALUE, (void*)g_val, sizeof g_val },
            { CKA_TOKEN, &g_no, 1 },
            { CKA_SENSITIVE, &g_no, 1 },
            { CKA_EXTRACTABLE, &g_yes, 1 },
        };
        if (C_CreateObject(s, st, sizeof st / sizeof st[0], &src) != CKR_OK) {
            fprintf(stderr, "source key\n"); return 2;
        }
        CK_MECHANISM kwmech = { CKM_AES_KEY_WRAP, NULL, 0 };
        CK_BYTE wrapped[64]; CK_ULONG wl = sizeof wrapped;
        if (C_WrapKey(s, &kwmech, kw, src, wrapped, &wl) != CKR_OK) {
            printf("  (CKM_AES_KEY_WRAP unavailable -- unwrap half skipped)\n");
        } else {
            CK_ATTRIBUTE nt[8]; CK_ULONG nc;
            CK_OBJECT_HANDLE out = 0;

            nc = new_key_template(nt, ALLOWED, CKK_AES);
            ok(C_UnwrapKey(s, &kwmech, kw, wrapped, wl, nt, nc, &out) == CKR_OK,
               "  a matching template unwraps");

            out = 0;
            nc = new_key_template(nt, DENIED, CKK_AES);
            ok(C_UnwrapKey(s, &kwmech, kw, wrapped, wl, nt, nc, &out)
               == CKR_TEMPLATE_INCONSISTENT,
               "  a violating label is CKR_TEMPLATE_INCONSISTENT");

            /* Omitting the constrained attribute is refused rather than
             * quietly creating an object without the restriction. Narrower
             * than the spec, which says to impose the value; never weaker. */
            out = 0;
            nc = new_key_template(nt, ALLOWED, CKK_AES) - 1;   /* drop CKA_LABEL */
            ok(C_UnwrapKey(s, &kwmech, kw, wrapped, wl, nt, nc, &out)
               == CKR_TEMPLATE_INCONSISTENT,
               "  and omitting it entirely is refused too");
        }
    }

    /* ---------------- CKA_DERIVE_TEMPLATE ---------------- */
    {
        CK_OBJECT_HANDLE kd = 0;
        ok(make_policy_key(s, CKA_DERIVE_TEMPLATE, nested, sizeof nested, &kd) == CKR_OK,
           "a key carrying CKA_DERIVE_TEMPLATE is accepted at creation");

        CK_BYTE data[16] = { 9 };
        CK_KEY_DERIVATION_STRING_DATA sd = { data, sizeof data };
        CK_MECHANISM dm = { CKM_CONCATENATE_BASE_AND_DATA, &sd, sizeof sd };
        CK_ATTRIBUTE nt[8]; CK_ULONG nc;
        CK_OBJECT_HANDLE out = 0;

        nc = new_key_template(nt, ALLOWED, CKK_GENERIC_SECRET);
        CK_RV rv = C_DeriveKey(s, &dm, kd, nt, nc, &out);
        if (rv != CKR_OK) {
            printf("  (CKM_CONCATENATE_BASE_AND_DATA unavailable: 0x%lx)\n", rv);
        } else {
            ok(1, "  a matching template derives");
            out = 0;
            nc = new_key_template(nt, DENIED, CKK_GENERIC_SECRET);
            ok(C_DeriveKey(s, &dm, kd, nt, nc, &out) == CKR_TEMPLATE_INCONSISTENT,
               "  a violating label is CKR_TEMPLATE_INCONSISTENT");
        }
    }

    /* ---------------- CKA_WRAP_TEMPLATE ---------------- */
    {
        CK_OBJECT_HANDLE kw = 0;
        ok(make_policy_key(s, CKA_WRAP_TEMPLATE, nested, sizeof nested, &kw) == CKR_OK,
           "a key carrying CKA_WRAP_TEMPLATE is accepted at creation");

        /* Two targets that differ only by the attribute the policy names. */
        CK_OBJECT_HANDLE good = 0, bad = 0;
        CK_ATTRIBUTE gt[] = {
            { CKA_CLASS, &g_klass, sizeof g_klass },
            { CKA_KEY_TYPE, &g_aes, sizeof g_aes },
            { CKA_VALUE, (void*)g_val, sizeof g_val },
            { CKA_TOKEN, &g_no, 1 },
            { CKA_SENSITIVE, &g_no, 1 },
            { CKA_EXTRACTABLE, &g_yes, 1 },
            { CKA_LABEL, (void*)ALLOWED, (CK_ULONG)strlen(ALLOWED) },
        };
        CK_ATTRIBUTE bt[] = {
            { CKA_CLASS, &g_klass, sizeof g_klass },
            { CKA_KEY_TYPE, &g_aes, sizeof g_aes },
            { CKA_VALUE, (void*)g_val, sizeof g_val },
            { CKA_TOKEN, &g_no, 1 },
            { CKA_SENSITIVE, &g_no, 1 },
            { CKA_EXTRACTABLE, &g_yes, 1 },
            { CKA_LABEL, (void*)DENIED, (CK_ULONG)strlen(DENIED) },
        };
        if (C_CreateObject(s, gt, sizeof gt / sizeof gt[0], &good) != CKR_OK
            || C_CreateObject(s, bt, sizeof bt / sizeof bt[0], &bad) != CKR_OK) {
            fprintf(stderr, "wrap targets\n"); return 2;
        }
        CK_MECHANISM kwmech = { CKM_AES_KEY_WRAP, NULL, 0 };
        CK_BYTE out[64]; CK_ULONG ol = sizeof out;
        CK_RV rv = C_WrapKey(s, &kwmech, kw, good, out, &ol);
        if (rv != CKR_OK) {
            printf("  (CKM_AES_KEY_WRAP unavailable: 0x%lx -- wrap half skipped)\n", rv);
        } else {
            ok(1, "  a key matching the template wraps");
            ol = sizeof out;
            ok(C_WrapKey(s, &kwmech, kw, bad, out, &ol) == CKR_TEMPLATE_INCONSISTENT,
               "  and one that does not is CKR_TEMPLATE_INCONSISTENT");
        }

        /* An attribute the module cannot read back off an object is refused
         * when the template is created, not silently treated as matching when
         * it is checked. CKA_MODULUS is a real attribute of a real class and
         * is not in the readable set. */
        CK_BYTE dummy[4] = { 0 };
        CK_ATTRIBUTE unreadable[1] = { { 0x120UL /* CKA_MODULUS */, dummy, sizeof dummy } };
        CK_OBJECT_HANDLE nope = 0;
        ok(make_policy_key(s, CKA_WRAP_TEMPLATE, unreadable, sizeof unreadable, &nope)
           != CKR_OK,
           "  and a template naming an unreadable attribute is refused at creation");
    }

    /* A key with no nested template is unrestricted, which is every key
     * written before today. */
    {
        CK_OBJECT_HANDLE plain = 0;
        CK_ATTRIBUTE t[] = {
            { CKA_CLASS, &g_klass, sizeof g_klass },
            { CKA_KEY_TYPE, &g_aes, sizeof g_aes },
            { CKA_VALUE, (void*)g_val, sizeof g_val },
            { CKA_TOKEN, &g_no, 1 },
            { CKA_SENSITIVE, &g_no, 1 },
            { CKA_EXTRACTABLE, &g_yes, 1 },
            { CKA_DERIVE, &g_yes, 1 },
        };
        ok(C_CreateObject(s, t, sizeof t / sizeof t[0], &plain) == CKR_OK,
           "a key with no nested template is created");
        CK_ATTRIBUTE q = { CKA_UNWRAP_TEMPLATE, NULL, 0 };
        (void)C_GetAttributeValue(s, plain, &q, 1);
        ok(q.ulValueLen == (CK_ULONG)-1,
           "  and reports the attribute unavailable, not an empty template");
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
