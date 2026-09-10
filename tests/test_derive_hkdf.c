/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_derive_hkdf.c --- CKM_HKDF_DERIVE through C_DeriveKey.
 *
 * CKM_HKDF_DERIVE and CKM_HKDF_DATA were advertised with a handler in
 * src/dispatch/fhsm_dispatch_kdf.c that no code path called. 660 vectors in
 * the conformance report read "HKDF derive failed for valid vector ...
 * CKR_MECHANISM_INVALID".
 *
 * What is under test is the plumbing, not RFC 5869: parsing CK_HKDF_PARAMS,
 * choosing the mode from bExtract/bExpand, resolving prfHashMechanism through
 * the same table C_DigestInit uses, and the three salt types. The primitive
 * is OpenSSL's on both sides.
 *
 * So each case computes its own reference with EVP_KDF here and compares.
 * That keeps the expected values out of the author's memory -- but it would
 * also pass if the same mistake were made twice, so case 1 additionally
 * checks the RFC 5869 test case 1 output, written out. If that one alone
 * fails, the transcription is wrong; if both fail, the module is.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

typedef struct {
    CK_BYTE          bExtract;
    CK_BYTE          bExpand;
    CK_ULONG         prfHashMechanism;
    CK_ULONG         ulSaltType;
    void            *pSalt;
    CK_ULONG         ulSaltLen;
    CK_OBJECT_HANDLE hSaltKey;
    void            *pInfo;
    CK_ULONG         ulInfoLen;
} CK_HKDF_PARAMS;

#define CKR_OK                        0UL
#define CKR_TEMPLATE_INCOMPLETE       0xD0UL
#define CKR_MECHANISM_PARAM_INVALID   0x71UL
#define CKF_RW                        6UL
#define CKA_CLASS                     0UL
#define CKA_VALUE                     0x11UL
#define CKA_KEY_TYPE                  0x100UL
#define CKA_DERIVE                    0x10CUL
#define CKA_VALUE_LEN                 0x161UL
#define CKA_EXTRACTABLE               0x162UL
#define CKA_SENSITIVE                 0x103UL
#define CKO_SECRET_KEY                4UL
#define CKK_GENERIC_SECRET            0x10UL

#define CKO_DATA         0UL
#define CKM_HKDF_DERIVE  0x402AUL
#define CKM_HKDF_DATA    0x402BUL
#define CKM_SHA256       0x250UL
#define CKM_SHA384       0x260UL
#define CKF_HKDF_SALT_NULL 1UL
#define CKF_HKDF_SALT_DATA 2UL
#define CKF_HKDF_SALT_KEY  4UL

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

/* The reference. Same primitive, driven directly. */
static int hkdf_ref(int mode, const char *digest,
                     const unsigned char *ikm, size_t ikm_len,
                     const unsigned char *salt, size_t salt_len,
                     const unsigned char *info, size_t info_len,
                     unsigned char *out, size_t out_len) {
    EVP_KDF *k = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!k) return 0;
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(k);
    EVP_KDF_free(k);
    if (!c) return 0;
    OSSL_PARAM p[6]; int n = 0;
    p[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)digest, 0);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm, ikm_len);
    if (salt_len) p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt, salt_len);
    if (info_len) p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info, info_len);
    p[n] = OSSL_PARAM_construct_end();
    int r = EVP_KDF_derive(c, out, out_len, p);
    EVP_KDF_CTX_free(c);
    return r == 1;
}

static CK_OBJECT_HANDLE make_secret(CK_SESSION_HANDLE s, const CK_BYTE *v, CK_ULONG n) {
    CK_BYTE t = 1;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_VALUE,       (void*)v, n },
        { CKA_DERIVE,      &t, 1 },
        { CKA_EXTRACTABLE, &t, 1 },
    };
    CK_OBJECT_HANDLE h = 0;
    if (C_CreateObject(s, tmpl, 5, &h) != CKR_OK) return 0;
    return h;
}

static int read_value(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                       CK_BYTE *out, CK_ULONG *outlen) {
    CK_ATTRIBUTE q[] = { { CKA_VALUE, out, *outlen } };
    if (C_GetAttributeValue(s, h, q, 1) != CKR_OK) return 0;
    *outlen = q[0].ulValueLen;
    return 1;
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_DeriveKey);
    SYM(C_GetAttributeValue);
    if (!C_DeriveKey || !C_CreateObject) { fprintf(stderr,"missing symbols\n"); return 2; }

    printf("HKDF (RFC 5869) through C_DeriveKey\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"hkdf",4);
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"C_Login SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_Login USER\n"); return 2; }

    /* RFC 5869 test case 1 inputs. */
    CK_BYTE ikm[22];  memset(ikm, 0x0b, sizeof ikm);
    CK_BYTE salt[13]; for (int i = 0; i < 13; ++i) salt[i] = (CK_BYTE)i;
    CK_BYTE info[10]; for (int i = 0; i < 10; ++i) info[i] = (CK_BYTE)(0xf0 + i);

    CK_OBJECT_HANDLE hikm = make_secret(s, ikm, sizeof ikm);
    CK_OBJECT_HANDLE hsalt = make_secret(s, salt, sizeof salt);
    if (!hikm || !hsalt) { fprintf(stderr,"C_CreateObject\n"); return 2; }

    CK_BYTE t_true = 1, t_false = 0;
    CK_ULONG len42 = 42;
    CK_ATTRIBUTE out42[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_VALUE_LEN,   &len42, sizeof(CK_ULONG) },
        { CKA_EXTRACTABLE, &t_true,  1 },
        { CKA_SENSITIVE,   &t_false, 1 },
    };
    CK_ATTRIBUTE out_novlen[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_EXTRACTABLE, &t_true,  1 },
        { CKA_SENSITIVE,   &t_false, 1 },
    };
    CK_OBJECT_HANDLE out = 0;
    CK_BYTE got[128], want[128];
    CK_ULONG gotlen;
    CK_RV rv;

    /* (1) extract+expand, SHA-256, data salt -- RFC 5869 test case 1. */
    {
        CK_HKDF_PARAMS p = { 1, 1, CKM_SHA256, CKF_HKDF_SALT_DATA,
                             salt, sizeof salt, 0, info, sizeof info };
        CK_MECHANISM m = { CKM_HKDF_DERIVE, &p, sizeof p };
        rv = C_DeriveKey(s, &m, hikm, out42, 5, &out);
        ok(rv == CKR_OK, "extract+expand SHA-256 accepted");
        if (rv == CKR_OK) {
            gotlen = sizeof got;
            ok(read_value(s, out, got, &gotlen) && gotlen == 42, "42 bytes derived");
            hkdf_ref(EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND, "SHA2-256",
                     ikm, sizeof ikm, salt, sizeof salt, info, sizeof info, want, 42);
            ok(memcmp(got, want, 42) == 0, "matches the OpenSSL reference");
            /* RFC 5869 A.1 OKM, written out. */
            static const CK_BYTE rfc[42] = {
                0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,
                0xd0,0x36,0x2f,0x2a,0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
                0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,0x34,0x00,0x72,0x08,
                0xd5,0xb8,0x87,0x18,0x58,0x65 };
            ok(memcmp(got, rfc, 42) == 0, "matches RFC 5869 A.1 OKM");
        }
    }
    /* (2) extract-only : the PRK, hash-length, CKA_VALUE_LEN not consulted. */
    {
        CK_HKDF_PARAMS p = { 1, 0, CKM_SHA256, CKF_HKDF_SALT_DATA,
                             salt, sizeof salt, 0, NULL, 0 };
        CK_MECHANISM m = { CKM_HKDF_DERIVE, &p, sizeof p };
        rv = C_DeriveKey(s, &m, hikm, out_novlen, 4, &out);
        ok(rv == CKR_OK, "extract-only accepted without CKA_VALUE_LEN");
        if (rv == CKR_OK) {
            gotlen = sizeof got;
            ok(read_value(s, out, got, &gotlen) && gotlen == 32, "PRK is 32 bytes");
            hkdf_ref(EVP_KDF_HKDF_MODE_EXTRACT_ONLY, "SHA2-256",
                     ikm, sizeof ikm, salt, sizeof salt, NULL, 0, want, 32);
            ok(memcmp(got, want, 32) == 0, "PRK matches the reference");
        }
    }
    /* (3) expand-only. */
    {
        CK_HKDF_PARAMS p = { 0, 1, CKM_SHA256, CKF_HKDF_SALT_NULL,
                             NULL, 0, 0, info, sizeof info };
        CK_MECHANISM m = { CKM_HKDF_DERIVE, &p, sizeof p };
        rv = C_DeriveKey(s, &m, hikm, out42, 5, &out);
        ok(rv == CKR_OK, "expand-only accepted");
        if (rv == CKR_OK) {
            gotlen = sizeof got;
            read_value(s, out, got, &gotlen);
            hkdf_ref(EVP_KDF_HKDF_MODE_EXPAND_ONLY, "SHA2-256",
                     ikm, sizeof ikm, NULL, 0, info, sizeof info, want, 42);
            ok(gotlen == 42 && memcmp(got, want, 42) == 0, "expand-only matches");
        }
    }
    /* (4) salt from a key object, not from bytes. */
    {
        CK_HKDF_PARAMS p = { 1, 1, CKM_SHA256, CKF_HKDF_SALT_KEY,
                             NULL, 0, hsalt, info, sizeof info };
        CK_MECHANISM m = { CKM_HKDF_DERIVE, &p, sizeof p };
        rv = C_DeriveKey(s, &m, hikm, out42, 5, &out);
        ok(rv == CKR_OK, "CKF_HKDF_SALT_KEY accepted");
        if (rv == CKR_OK) {
            gotlen = sizeof got;
            read_value(s, out, got, &gotlen);
            hkdf_ref(EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND, "SHA2-256",
                     ikm, sizeof ikm, salt, sizeof salt, info, sizeof info, want, 42);
            ok(gotlen == 42 && memcmp(got, want, 42) == 0,
               "salt-from-key equals the same salt as bytes");
        }
    }
    /* (5) a different PRF hash, so a hard-coded SHA-256 would show. */
    {
        CK_HKDF_PARAMS p = { 1, 1, CKM_SHA384, CKF_HKDF_SALT_DATA,
                             salt, sizeof salt, 0, info, sizeof info };
        CK_MECHANISM m = { CKM_HKDF_DERIVE, &p, sizeof p };
        rv = C_DeriveKey(s, &m, hikm, out42, 5, &out);
        ok(rv == CKR_OK, "prfHashMechanism = CKM_SHA384 accepted");
        if (rv == CKR_OK) {
            gotlen = sizeof got;
            read_value(s, out, got, &gotlen);
            hkdf_ref(EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND, "SHA2-384",
                     ikm, sizeof ikm, salt, sizeof salt, info, sizeof info, want, 42);
            ok(gotlen == 42 && memcmp(got, want, 42) == 0, "SHA-384 output differs and matches");
        }
    }
    /* (6) CKM_HKDF_DATA derives a data object, not a key. Same bytes, other
     *     class -- and no CKR_ would have shown the difference, which is why
     *     it is asserted rather than assumed. */
    {
        CK_HKDF_PARAMS p = { 1, 1, CKM_SHA256, CKF_HKDF_SALT_DATA,
                             salt, sizeof salt, 0, info, sizeof info };
        CK_MECHANISM m = { CKM_HKDF_DATA, &p, sizeof p };
        CK_ATTRIBUTE data_tmpl[] = {
            { CKA_VALUE_LEN,   &len42, sizeof(CK_ULONG) },
            { CKA_EXTRACTABLE, &t_true,  1 },
            { CKA_SENSITIVE,   &t_false, 1 },
        };
        rv = C_DeriveKey(s, &m, hikm, data_tmpl, 3, &out);
        ok(rv == CKR_OK, "CKM_HKDF_DATA accepted");
        if (rv == CKR_OK) {
            CK_ULONG cls = 0xFFFF;
            CK_ATTRIBUTE q[] = { { CKA_CLASS, &cls, sizeof cls } };
            ok(C_GetAttributeValue(s, out, q, 1) == CKR_OK && cls == CKO_DATA,
               "CKM_HKDF_DATA yields CKO_DATA, not a secret key");
            gotlen = sizeof got;
            read_value(s, out, got, &gotlen);
            hkdf_ref(EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND, "SHA2-256",
                     ikm, sizeof ikm, salt, sizeof salt, info, sizeof info, want, 42);
            ok(gotlen == 42 && memcmp(got, want, 42) == 0,
               "CKM_HKDF_DATA bytes equal CKM_HKDF_DERIVE's");
        }
    }
    /* (7) the refusals. */
    {
        CK_MECHANISM m = { CKM_HKDF_DERIVE, NULL, 0 };
        CK_HKDF_PARAMS p;

        rv = C_DeriveKey(s, &m, hikm, out42, 5, &out);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "missing parameter block refused");

        p = (CK_HKDF_PARAMS){ 0, 0, CKM_SHA256, CKF_HKDF_SALT_NULL, NULL,0,0, NULL,0 };
        m.pParameter = &p; m.ulParameterLen = sizeof p;
        rv = C_DeriveKey(s, &m, hikm, out42, 5, &out);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "neither extract nor expand refused");

        p = (CK_HKDF_PARAMS){ 1, 1, CKM_SHA256, 99UL, NULL,0,0, NULL,0 };
        rv = C_DeriveKey(s, &m, hikm, out42, 5, &out);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "unknown ulSaltType refused, not ignored");

        p = (CK_HKDF_PARAMS){ 1, 1, CKM_SHA256, CKF_HKDF_SALT_DATA, NULL, 8, 0, NULL, 0 };
        rv = C_DeriveKey(s, &m, hikm, out42, 5, &out);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "NULL pSalt with ulSaltLen>0 refused");

        p = (CK_HKDF_PARAMS){ 1, 1, CKM_SHA256, CKF_HKDF_SALT_DATA,
                              salt, 0x7FFFFFFFFFFFFFFFUL, 0, NULL, 0 };
        rv = C_DeriveKey(s, &m, hikm, out42, 5, &out);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "un-honorable 2^63 ulSaltLen refused");

        p = (CK_HKDF_PARAMS){ 1, 1, 0x9999UL, CKF_HKDF_SALT_NULL, NULL,0,0, NULL,0 };
        rv = C_DeriveKey(s, &m, hikm, out42, 5, &out);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "unknown prfHashMechanism refused");

        p = (CK_HKDF_PARAMS){ 1, 1, CKM_SHA256, CKF_HKDF_SALT_NULL, NULL,0,0, NULL,0 };
        rv = C_DeriveKey(s, &m, hikm, out_novlen, 4, &out);
        ok(rv == CKR_TEMPLATE_INCOMPLETE, "expand without CKA_VALUE_LEN refused");
    }

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
