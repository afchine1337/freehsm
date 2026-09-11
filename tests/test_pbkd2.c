/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_pbkd2.c --- CKM_PKCS5_PBKD2 through C_GenerateKey.
 *
 * Three defects met in this one mechanism. It was advertised under "derive",
 * so C_GetMechanismInfo reported CKF_DERIVE and sent callers to C_DeriveKey,
 * where PKCS#11 v3.2 6.28 says it does not belong. It was not implemented
 * anywhere. And fhsm_pbkdf2() refused fewer than 200,000 iterations, which
 * no real PKCS#12 file uses -- so even once wired, every file anyone
 * actually holds would have been refused.
 *
 * 1,647 vectors reported the middle one as "advertised PBES2 key derivation
 * is not operational". The first and the third would have been found only by
 * someone trying to open a file.
 *
 * References are computed here with EVP_KDF rather than written from memory,
 * as in test_derive_hkdf. Case 1 also carries the RFC 6070 output written
 * out, so that a mistake made twice would still show.
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
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize; CK_FLAGS flags; } CK_MECHANISM_INFO;

typedef struct {
    CK_ULONG  saltSource;
    void     *pSaltSourceData;
    CK_ULONG  ulSaltSourceDataLen;
    CK_ULONG  iterations;
    CK_ULONG  prf;
    void     *pPrfData;
    CK_ULONG  ulPrfDataLen;
    void     *pPassword;
    CK_ULONG  ulPasswordLen;
} CK_PKCS5_PBKD2_PARAMS2;

#define CKR_OK                      0UL
#define CKR_TEMPLATE_INCOMPLETE     0xD0UL
#define CKR_MECHANISM_PARAM_INVALID 0x71UL
#define CKF_RW                      6UL
#define CKF_GENERATE                0x00008000UL
#define CKF_DERIVE                  0x00080000UL
#define CKA_CLASS                   0UL
#define CKA_VALUE                   0x11UL
#define CKA_KEY_TYPE                0x100UL
#define CKA_VALUE_LEN               0x161UL
#define CKA_EXTRACTABLE             0x162UL
#define CKA_SENSITIVE               0x103UL
#define CKO_SECRET_KEY              4UL
#define CKK_GENERIC_SECRET          0x10UL
#define CKM_PKCS5_PBKD2             0x3B0UL
#define CKZ_SALT_SPECIFIED          1UL
#define PRF_SHA1                    1UL
#define PRF_SHA256                  4UL

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
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID,CK_ULONG,CK_MECHANISM_INFO*);

static int pbkdf2_ref(const char *digest, const char *pw, const char *salt,
                       unsigned iter, unsigned char *out, size_t out_len) {
    EVP_KDF *k = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (!k) return 0;
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(k);
    EVP_KDF_free(k);
    if (!c) return 0;
    OSSL_PARAM p[5]; int n = 0;
    p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)digest, 0);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void*)pw, strlen(pw));
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt, strlen(salt));
    p[n++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter);
    p[n] = OSSL_PARAM_construct_end();
    int r = EVP_KDF_derive(c, out, out_len, p);
    EVP_KDF_CTX_free(c);
    return r == 1;
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_GenerateKey); SYM(C_GetAttributeValue);
    SYM(C_GetMechanismInfo);
    if (!C_GenerateKey || !C_GetMechanismInfo) { fprintf(stderr,"missing symbols\n"); return 2; }

    printf("CKM_PKCS5_PBKD2 through C_GenerateKey\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"pbkd2",5);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"C_Login SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_Login USER\n"); return 2; }

    /* (0) The operation the module claims. This said CKF_DERIVE. */
    {
        CK_MECHANISM_INFO mi; memset(&mi, 0, sizeof mi);
        CK_RV rv = C_GetMechanismInfo(0, CKM_PKCS5_PBKD2, &mi);
        ok(rv == CKR_OK && (mi.flags & CKF_GENERATE), "advertised with CKF_GENERATE");
        ok(rv == CKR_OK && !(mi.flags & CKF_DERIVE), "no longer advertised with CKF_DERIVE");
    }

    /* Two configurations, two truths.
     *
     * Run with FHSM_INTEGRITY_ALLOW_UNSIGNED set, the module serves EVP from
     * the default provider and PBKDF2 accepts the parameters the caller
     * chooses. Run without it -- inside the evaluated configuration -- the
     * FIPS provider applies SP 800-132 itself and refuses a salt under 128
     * bits, whatever OSSL_KDF_PARAM_PKCS5 says.
     *
     * That is a real limit of the module in a FIPS deployment and it is
     * stated here rather than worked around: a PKCS#12 file with an 8-byte
     * salt, which is most of them, will not open under fips-strict with the
     * provider loaded. The interop build is the answer for those.
     *
     * So the known-answer cases, which use RFC 6070's 4-byte salt, run only
     * where they can. Everything else uses a 16-byte salt and runs in both. */
    const int bypass = (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED") != NULL);
    char pw[] = "password", salt[] = "salt";
    char salt16[] = "0123456789abcdef";   /* 16 bytes: SP 800-132 clean */
    CK_BYTE t_true = 1, t_false = 0;
    CK_ULONG vl20 = 20, vl32 = 32;
    CK_ATTRIBUTE tmpl20[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_VALUE_LEN,   &vl20, sizeof(CK_ULONG) },
        { CKA_EXTRACTABLE, &t_true,  1 },
        { CKA_SENSITIVE,   &t_false, 1 },
    };
    CK_ATTRIBUTE tmpl32[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_VALUE_LEN,   &vl32, sizeof(CK_ULONG) },
        { CKA_EXTRACTABLE, &t_true,  1 },
        { CKA_SENSITIVE,   &t_false, 1 },
    };
    CK_ATTRIBUTE tmpl_novl[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_EXTRACTABLE, &t_true,  1 },
    };
    CK_OBJECT_HANDLE key = 0;
    CK_BYTE got[64], want[64];
    CK_RV rv;

    /* (1) RFC 6070 test case 3: PBKDF2-HMAC-SHA1, 4096 iterations, 20 bytes.
     *     The RFC's first two cases use 1 and 2 iterations, which SP 800-132
     *     puts below the floor; this is the smallest of its cases the module
     *     will accept, and the one a PKCS#12 file resembles. */
    if (!bypass) {
        printf("  %-58s %s\n",
               "RFC 6070 (4-byte salt): FIPS provider refuses, as it should", "skip");
    } else {
        CK_PKCS5_PBKD2_PARAMS2 p = { CKZ_SALT_SPECIFIED, salt, 4, 4096,
                                     PRF_SHA1, NULL, 0, pw, 8 };
        CK_MECHANISM m = { CKM_PKCS5_PBKD2, &p, sizeof p };
        rv = C_GenerateKey(s, &m, tmpl20, 5, &key);
        ok(rv == CKR_OK, "HMAC-SHA1, 4096 iterations accepted");
        if (rv == CKR_OK) {
            CK_ATTRIBUTE q[] = { { CKA_VALUE, got, sizeof got } };
            ok(C_GetAttributeValue(s, key, q, 1) == CKR_OK && q[0].ulValueLen == 20,
               "20 bytes derived");
            pbkdf2_ref("SHA1", pw, salt, 4096, want, 20);
            ok(memcmp(got, want, 20) == 0, "matches the OpenSSL reference");
            static const CK_BYTE rfc[20] = {
                0x4b,0x00,0x79,0x01,0xb7,0x65,0x48,0x9a,0xbe,0xad,
                0x49,0xd9,0x26,0xf7,0x21,0xd0,0x65,0xa4,0x29,0xc1 };
            ok(memcmp(got, rfc, 20) == 0, "matches RFC 6070 test case 3");
        }
    }
    /* (2) A second PRF, so a hard-coded SHA-1 would show. */
    {
        CK_PKCS5_PBKD2_PARAMS2 p = { CKZ_SALT_SPECIFIED, salt16, 16, 2048,
                                     PRF_SHA256, NULL, 0, pw, 8 };
        CK_MECHANISM m = { CKM_PKCS5_PBKD2, &p, sizeof p };
        rv = C_GenerateKey(s, &m, tmpl32, 5, &key);
        ok(rv == CKR_OK, "HMAC-SHA256, 2048 iterations accepted");
        if (rv == CKR_OK) {
            CK_ATTRIBUTE q[] = { { CKA_VALUE, got, sizeof got } };
            C_GetAttributeValue(s, key, q, 1);
            pbkdf2_ref("SHA256", pw, salt16, 2048, want, 32);
            ok(q[0].ulValueLen == 32 && memcmp(got, want, 32) == 0,
               "SHA-256 output differs and matches");
        }
    }
    /* (2b) The template decides the key type, not the mechanism. PBES2
     *      derives an AES key; a derived key typed CKK_GENERIC_SECRET is
     *      refused by the mechanism<->key-type gate at first use, which is
     *      how this was reported -- as PBES2 decryption not working, several
     *      layers from the cause. */
    {
        CK_ULONG vl16 = 16;
        CK_ATTRIBUTE aes_t[] = {
            { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},   sizeof(CK_ULONG) },
            { CKA_KEY_TYPE,    &(CK_ULONG){0x1FUL /* CKK_AES */}, sizeof(CK_ULONG) },
            { CKA_VALUE_LEN,   &vl16, sizeof(CK_ULONG) },
            { CKA_EXTRACTABLE, &t_true,  1 },
            { CKA_SENSITIVE,   &t_false, 1 },
        };
        CK_PKCS5_PBKD2_PARAMS2 p = { CKZ_SALT_SPECIFIED, salt16, 16, 2048,
                                     PRF_SHA256, NULL, 0, pw, 8 };
        CK_MECHANISM m = { CKM_PKCS5_PBKD2, &p, sizeof p };
        rv = C_GenerateKey(s, &m, aes_t, 5, &key);
        ok(rv == CKR_OK, "CKA_KEY_TYPE = CKK_AES accepted");
        if (rv == CKR_OK) {
            CK_ULONG kt = 0;
            CK_ATTRIBUTE q[] = { { CKA_KEY_TYPE, &kt, sizeof kt } };
            ok(C_GetAttributeValue(s, key, q, 1) == CKR_OK && kt == 0x1FUL,
               "derived key reads back as CKK_AES, not generic secret");
        }
    }
    /* (3) The floor, and the refusals. */
    {
        CK_PKCS5_PBKD2_PARAMS2 p = { CKZ_SALT_SPECIFIED, salt16, 16, 999,
                                     PRF_SHA256, NULL, 0, pw, 8 };
        CK_MECHANISM m = { CKM_PKCS5_PBKD2, &p, sizeof p };
        rv = C_GenerateKey(s, &m, tmpl20, 5, &key);
        ok(rv != CKR_OK, "999 iterations refused (SP 800-132 minimum is 1000)");

        p.iterations = 1000;
        rv = C_GenerateKey(s, &m, tmpl20, 5, &key);
        ok(rv == CKR_OK, "1000 iterations accepted");

        p.iterations = 4096; p.saltSource = 99;
        rv = C_GenerateKey(s, &m, tmpl20, 5, &key);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "unknown saltSource refused, not ignored");

        p.saltSource = CKZ_SALT_SPECIFIED; p.prf = 2; /* GOSTR3411 */
        rv = C_GenerateKey(s, &m, tmpl20, 5, &key);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "unimplemented PRF refused");

        p.prf = PRF_SHA256; p.pPassword = NULL; p.ulPasswordLen = 8;
        rv = C_GenerateKey(s, &m, tmpl20, 5, &key);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "NULL password with length>0 refused");

        p.pPassword = pw; p.ulPasswordLen = 0x7FFFFFFFFFFFFFFFUL;
        rv = C_GenerateKey(s, &m, tmpl20, 5, &key);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "un-honorable 2^63 password length refused");

        p.ulPasswordLen = 8;
        m.pParameter = NULL; m.ulParameterLen = 0;
        rv = C_GenerateKey(s, &m, tmpl20, 5, &key);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, "missing parameter block refused");

        m.pParameter = &p; m.ulParameterLen = sizeof p;
        rv = C_GenerateKey(s, &m, tmpl_novl, 3, &key);
        ok(rv == CKR_TEMPLATE_INCOMPLETE, "missing CKA_VALUE_LEN refused");
    }

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
