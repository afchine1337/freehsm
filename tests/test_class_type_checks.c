/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_class_type_checks.c --- a class and a key type that disagree are
 * refused on every creation path, and two refusals carry their own reason.
 *
 * Three neighbours of #33 C3 and C7, found by Alexandre Laroche when he
 * retested v2.7.0:
 *   (G) C_GenerateKeyPair with a CKA_CLASS or CKA_KEY_TYPE other than the
 *       mechanism's, in either template: CKR_TEMPLATE_INCONSISTENT and no
 *       key, not CKR_OK;
 *   (C) C_CreateObject of a CKO_SECRET_KEY of type CKK_EC, or of a
 *       CKO_PRIVATE_KEY of type CKK_AES: CKR_TEMPLATE_INCONSISTENT, not
 *       CKR_OK;
 *   (P) C_CreateObject of a CKK_EC private key without CKA_EC_PARAMS:
 *       CKR_TEMPLATE_INCOMPLETE, not CKR_TEMPLATE_INCONSISTENT;
 *   (V) C_CopyObject with a new CKA_VALUE: CKR_ATTRIBUTE_READ_ONLY, not
 *       CKR_TEMPLATE_INCONSISTENT.
 * What was accepted before still is.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                         0x000UL
#define CKR_ATTRIBUTE_READ_ONLY        0x010UL
#define CKR_ATTRIBUTE_VALUE_INVALID    0x013UL
#define CKR_TEMPLATE_INCOMPLETE        0x0D0UL
#define CKR_TEMPLATE_INCONSISTENT      0x0D1UL
#define CKF_RW                         6UL
#define CKU_SO                         0UL
#define CKU_USER                       1UL
#define CKO_PUBLIC_KEY                 2UL
#define CKO_PRIVATE_KEY                3UL
#define CKO_SECRET_KEY                 4UL
#define CKK_RSA                        0x00UL
#define CKK_EC                         0x03UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_LABEL                      0x003UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EC_PARAMS                  0x180UL
#define CKM_EC_KEY_PAIR_GEN            0x1040UL
#define CKM_AES_KEY_GEN                0x1080UL

/* Test PINs, for a token this program makes in a throwaway directory. */
#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_CopyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG,
                             CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;
static CK_BYTE p256[] = { 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 };

/* CKM_EC_KEY_PAIR_GEN on P-256 with one more attribute in the public
 * template (which = 0) or the private one (which = 1), or none (xtra NULL). */
static CK_RV ec_pair(int which, CK_ATTRIBUTE *xtra, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv) {
    CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pt[4] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                           { CKA_EC_PARAMS, p256, sizeof p256 } };
    CK_ATTRIBUTE vt[3] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    CK_ULONG np = 3, nv = 2;
    if (xtra) { if (which == 0) pt[np++] = *xtra; else vt[nv++] = *xtra; }
    *pub = *prv = 0;
    return C_GenerateKeyPair(s, &m, pt, np, vt, nv, pub, prv);
}

/* C_CreateObject of a 32-byte value under the class and key type given,
 * with CKA_EC_PARAMS when asked. */
static CK_RV import(CK_ULONG cls, CK_ULONG kt, int with_params, CK_OBJECT_HANDLE *h) {
    static CK_BYTE v[32];
    memset(v, 0x11, sizeof v);
    CK_ATTRIBUTE t[5] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                          { CKA_TOKEN, &no, 1 }, { CKA_VALUE, v, sizeof v } };
    CK_ULONG n = 4;
    if (with_params) { CK_ATTRIBUTE e = { CKA_EC_PARAMS, p256, sizeof p256 }; t[n++] = e; }
    *h = 0;
    return C_CreateObject(s, t, n, h);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_CopyObject);
    SYM(C_GenerateKey); SYM(C_GenerateKeyPair);
    if (!C_CreateObject || !C_CopyObject || !C_GenerateKey || !C_GenerateKeyPair) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("Class and key type checked on every creation path\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"clstype",7);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,CKU_SO,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,CKU_USER,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_ULONG pubc = CKO_PUBLIC_KEY, prvc = CKO_PRIVATE_KEY, secc = CKO_SECRET_KEY;
    CK_ULONG rsa = CKK_RSA, ec = CKK_EC;
    CK_OBJECT_HANDLE pub, prv, h;
    CK_RV rv;

    printf("(G) C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN)\n");
    { CK_ATTRIBUTE x = { CKA_KEY_TYPE, &rsa, sizeof rsa };
      rv = ec_pair(1, &x, &pub, &prv);
      ok(rv == CKR_TEMPLATE_INCONSISTENT && pub == 0 && prv == 0,
         "CKK_RSA in the private template: CKR_TEMPLATE_INCONSISTENT, no key");
      rv = ec_pair(0, &x, &pub, &prv);
      ok(rv == CKR_TEMPLATE_INCONSISTENT && pub == 0 && prv == 0,
         "CKK_RSA in the public template: the same"); }
    { CK_ATTRIBUTE x = { CKA_CLASS, &prvc, sizeof prvc };
      rv = ec_pair(0, &x, &pub, &prv);
      ok(rv == CKR_TEMPLATE_INCONSISTENT && pub == 0 && prv == 0,
         "CKO_PRIVATE_KEY in the public template: CKR_TEMPLATE_INCONSISTENT, no key"); }
    { CK_ATTRIBUTE x = { CKA_CLASS, &pubc, sizeof pubc };
      rv = ec_pair(1, &x, &pub, &prv);
      ok(rv == CKR_TEMPLATE_INCONSISTENT && pub == 0 && prv == 0,
         "CKO_PUBLIC_KEY in the private template: the same"); }
    { CK_ATTRIBUTE x = { CKA_CLASS, &secc, sizeof secc };
      rv = ec_pair(1, &x, &pub, &prv);
      ok(rv == CKR_TEMPLATE_INCONSISTENT, "CKO_SECRET_KEY in the private template: the same"); }
    { CK_BYTE one = 3; CK_ATTRIBUTE x = { CKA_KEY_TYPE, &one, 1 };
      rv = ec_pair(1, &x, &pub, &prv);
      ok(rv == CKR_ATTRIBUTE_VALUE_INVALID, "a one-byte CKA_KEY_TYPE: CKR_ATTRIBUTE_VALUE_INVALID"); }
    ok(ec_pair(0, NULL, &pub, &prv) == CKR_OK && pub && prv, "neither named: CKR_OK");
    { CK_ATTRIBUTE x = { CKA_KEY_TYPE, &ec, sizeof ec };
      ok(ec_pair(1, &x, &pub, &prv) == CKR_OK, "CKK_EC in the private template: CKR_OK");
      ok(ec_pair(0, &x, &pub, &prv) == CKR_OK, "CKK_EC in the public template: CKR_OK"); }
    { CK_ATTRIBUTE x = { CKA_CLASS, &pubc, sizeof pubc }, y = { CKA_CLASS, &prvc, sizeof prvc };
      ok(ec_pair(0, &x, &pub, &prv) == CKR_OK, "CKO_PUBLIC_KEY in the public template: CKR_OK");
      ok(ec_pair(1, &y, &pub, &prv) == CKR_OK, "CKO_PRIVATE_KEY in the private template: CKR_OK"); }

    printf("\n(C) C_CreateObject, class against key type\n");
    rv = import(CKO_SECRET_KEY, CKK_EC, 0, &h);
    ok(rv == CKR_TEMPLATE_INCONSISTENT && h == 0,
       "CKO_SECRET_KEY of type CKK_EC: CKR_TEMPLATE_INCONSISTENT, no object");
    rv = import(CKO_SECRET_KEY, CKK_RSA, 0, &h);
    ok(rv == CKR_TEMPLATE_INCONSISTENT && h == 0, "CKO_SECRET_KEY of type CKK_RSA: the same");
    rv = import(CKO_PRIVATE_KEY, CKK_AES, 0, &h);
    ok(rv == CKR_TEMPLATE_INCONSISTENT && h == 0,
       "CKO_PRIVATE_KEY of type CKK_AES: CKR_TEMPLATE_INCONSISTENT, no object");
    ok(import(CKO_SECRET_KEY, CKK_AES, 0, &h) == CKR_OK && h, "CKO_SECRET_KEY of type CKK_AES: CKR_OK");
    ok(import(CKO_PRIVATE_KEY, CKK_EC, 1, &h) == CKR_OK && h,
       "CKO_PRIVATE_KEY of type CKK_EC, with CKA_EC_PARAMS: CKR_OK");

    printf("\n(P) C_CreateObject, EC private key without CKA_EC_PARAMS\n");
    rv = import(CKO_PRIVATE_KEY, CKK_EC, 0, &h);
    ok(rv == CKR_TEMPLATE_INCOMPLETE && h == 0, "CKR_TEMPLATE_INCOMPLETE, no object");

    printf("\n(V) C_CopyObject with a new value\n");
    { CK_OBJECT_HANDLE aes = 0, cp = 0;
      CK_ULONG vl = 32;
      CK_ATTRIBUTE t[] = { { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 },
                           { CKA_ENCRYPT, &yes, 1 } };
      CK_MECHANISM g = { CKM_AES_KEY_GEN, NULL, 0 };
      if (C_GenerateKey(s, &g, t, 3, &aes)) { fprintf(stderr, "AES key\n"); return 2; }
      CK_BYTE nv[32]; memset(nv, 0x22, sizeof nv);
      CK_ATTRIBUTE v = { CKA_VALUE, nv, sizeof nv };
      rv = C_CopyObject(s, aes, &v, 1, &cp);
      ok(rv == CKR_ATTRIBUTE_READ_ONLY && cp == 0, "CKA_VALUE: CKR_ATTRIBUTE_READ_ONLY, no copy");
      CK_ULONG kt = CKK_AES; CK_ATTRIBUTE k = { CKA_KEY_TYPE, &kt, sizeof kt };
      cp = 0; rv = C_CopyObject(s, aes, &k, 1, &cp);
      ok(rv == CKR_TEMPLATE_INCONSISTENT && cp == 0, "CKA_KEY_TYPE: CKR_TEMPLATE_INCONSISTENT, as before");
      CK_BYTE lbl[4] = { 'c', 'o', 'p', 'y' };
      CK_ATTRIBUTE l = { CKA_LABEL, lbl, sizeof lbl };
      cp = 0; rv = C_CopyObject(s, aes, &l, 1, &cp);
      ok(rv == CKR_OK && cp != 0, "CKA_LABEL: CKR_OK"); }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
