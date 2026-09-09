/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_derive_concat.c --- the four PKCS#11 v3.2 §6.20 combiners produce the
 * bytes the specification says, not merely a non-error.
 *
 * C_DeriveKey named CKM_ECDH1_DERIVE and its cofactor variant and refused
 * everything else, while fhsm_mechanism_table[] advertised these four with a
 * working handler each in src/dispatch/fhsm_dispatch_concat.c that no code
 * path called.
 *
 * tests/test_advertised_operational would go green on any answer other than
 * CKR_MECHANISM_INVALID, so on its own it cannot tell an implementation from
 * a stub that returns CKR_OK. This checks the derived key byte for byte:
 *
 *     base = 01 02 03 04 05 06 07 08      data = AA BB CC DD
 *     key2 = 11 22 33 44
 *
 *     CONCATENATE_BASE_AND_DATA   base || data   (12 bytes)
 *     CONCATENATE_DATA_AND_BASE   data || base   (12)
 *     CONCATENATE_BASE_AND_KEY    base || key2   (12)
 *     XOR_BASE_AND_DATA           base ^ data    ( 4 -- the data length
 *                                                  sets the output length)
 *
 * Case 5 is the parameter validation: a NULL pData with a non-zero ulLen,
 * and a 2^63 ulLen, both of which the sign and cipher paths already refuse
 * and which this one had no opportunity to refuse until now.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { void *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;

#define CKR_OK                        0UL
#define CKR_MECHANISM_PARAM_INVALID   0x71UL
#define CKF_RW                        6UL
#define CKA_CLASS                     0UL
#define CKA_VALUE                     0x11UL
#define CKA_KEY_TYPE                  0x100UL
#define CKA_DERIVE                    0x10CUL
#define CKA_EXTRACTABLE               0x162UL
#define CKA_SENSITIVE                 0x103UL
#define CKO_SECRET_KEY                4UL
#define CKK_GENERIC_SECRET            0x10UL

#define CKM_CONCATENATE_BASE_AND_KEY  0x360UL
#define CKM_CONCATENATE_BASE_AND_DATA 0x362UL
#define CKM_CONCATENATE_DATA_AND_BASE 0x363UL
#define CKM_XOR_BASE_AND_DATA         0x364UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-58s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);

static CK_OBJECT_HANDLE make_secret(CK_SESSION_HANDLE s,
                                     const CK_BYTE *v, CK_ULONG n) {
    CK_BYTE t_true = 1;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_VALUE,       (void*)v,                        n },
        { CKA_DERIVE,      &t_true, 1 },
        { CKA_EXTRACTABLE, &t_true, 1 },
    };
    CK_OBJECT_HANDLE h = 0;
    if (C_CreateObject(s, tmpl, 5, &h) != CKR_OK) return 0;
    return h;
}

/* Read back the derived key and compare. The template asks for an
 * extractable, non-sensitive result so that CKA_VALUE can be read; a
 * derived key that could not be inspected would make this test vacuous. */
static void check_derived(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                           const CK_BYTE *want, CK_ULONG wantlen,
                           const char *what) {
    CK_BYTE got[64];
    CK_ATTRIBUTE q[] = { { CKA_VALUE, got, sizeof got } };
    CK_RV rv = C_GetAttributeValue(s, h, q, 1);
    ok(rv == CKR_OK && q[0].ulValueLen == wantlen
       && memcmp(got, want, wantlen) == 0, what);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_DeriveKey);
    SYM(C_GetAttributeValue);
    if (!C_DeriveKey || !C_CreateObject || !C_GetAttributeValue) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("PKCS#11 v3.2 6.20 combiners through C_DeriveKey\n\n");

    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "concat", 6);
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label) != CKR_OK) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s) != CKR_OK) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN)) != CKR_OK) { fprintf(stderr,"C_Login SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN)) != CKR_OK) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN)) != CKR_OK) { fprintf(stderr,"C_Login USER\n"); return 2; }

    const CK_BYTE base[8]  = { 1,2,3,4,5,6,7,8 };
    const CK_BYTE data[4]  = { 0xAA,0xBB,0xCC,0xDD };
    const CK_BYTE key2v[4] = { 0x11,0x22,0x33,0x44 };

    CK_OBJECT_HANDLE hbase = make_secret(s, base, 8);
    CK_OBJECT_HANDLE hkey2 = make_secret(s, key2v, 4);
    if (!hbase || !hkey2) { fprintf(stderr, "C_CreateObject\n"); return 2; }

    CK_BYTE t_true = 1, t_false = 0;
    CK_ATTRIBUTE out_tmpl[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_EXTRACTABLE, &t_true,  1 },
        { CKA_SENSITIVE,   &t_false, 1 },
    };
    CK_KEY_DERIVATION_STRING_DATA sd = { (void*)data, 4 };
    CK_OBJECT_HANDLE out = 0;
    CK_RV rv;

    /* (1) base || data */
    {
        CK_MECHANISM m = { CKM_CONCATENATE_BASE_AND_DATA, &sd, sizeof sd };
        rv = C_DeriveKey(s, &m, hbase, out_tmpl, 4, &out);
        ok(rv == CKR_OK, "CONCATENATE_BASE_AND_DATA accepted");
        if (rv == CKR_OK) {
            CK_BYTE want[12]; memcpy(want, base, 8); memcpy(want+8, data, 4);
            check_derived(s, out, want, 12, "CONCATENATE_BASE_AND_DATA = base || data");
        }
    }
    /* (2) data || base */
    {
        CK_MECHANISM m = { CKM_CONCATENATE_DATA_AND_BASE, &sd, sizeof sd };
        rv = C_DeriveKey(s, &m, hbase, out_tmpl, 4, &out);
        ok(rv == CKR_OK, "CONCATENATE_DATA_AND_BASE accepted");
        if (rv == CKR_OK) {
            CK_BYTE want[12]; memcpy(want, data, 4); memcpy(want+4, base, 8);
            check_derived(s, out, want, 12, "CONCATENATE_DATA_AND_BASE = data || base");
        }
    }
    /* (3) base || key2 -- the one whose parameter is a handle, not a string */
    {
        CK_OBJECT_HANDLE p = hkey2;
        CK_MECHANISM m = { CKM_CONCATENATE_BASE_AND_KEY, &p, sizeof p };
        rv = C_DeriveKey(s, &m, hbase, out_tmpl, 4, &out);
        ok(rv == CKR_OK, "CONCATENATE_BASE_AND_KEY accepted");
        if (rv == CKR_OK) {
            CK_BYTE want[12]; memcpy(want, base, 8); memcpy(want+8, key2v, 4);
            check_derived(s, out, want, 12, "CONCATENATE_BASE_AND_KEY = base || key2");
        }
    }
    /* (4) base XOR data, output length taken from the data */
    {
        CK_MECHANISM m = { CKM_XOR_BASE_AND_DATA, &sd, sizeof sd };
        rv = C_DeriveKey(s, &m, hbase, out_tmpl, 4, &out);
        ok(rv == CKR_OK, "XOR_BASE_AND_DATA accepted");
        if (rv == CKR_OK) {
            CK_BYTE want[4];
            for (int i = 0; i < 4; ++i) want[i] = base[i] ^ data[i];
            check_derived(s, out, want, 4, "XOR_BASE_AND_DATA = base ^ data, 4 bytes");
        }
    }
    /* (5) the two parameter guards */
    {
        CK_KEY_DERIVATION_STRING_DATA bad = { NULL, 4 };
        CK_MECHANISM m = { CKM_CONCATENATE_BASE_AND_DATA, &bad, sizeof bad };
        rv = C_DeriveKey(s, &m, hbase, out_tmpl, 4, &out);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "NULL pData with ulLen>0 refused");

        bad.pData = (void*)data; bad.ulLen = 0x7FFFFFFFFFFFFFFFUL;
        rv = C_DeriveKey(s, &m, hbase, out_tmpl, 4, &out);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "un-honorable 2^63 ulLen refused");

        m.pParameter = NULL; m.ulParameterLen = 0;
        rv = C_DeriveKey(s, &m, hbase, out_tmpl, 4, &out);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "missing parameter block refused");
    }

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
