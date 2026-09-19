/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_gmac_params.c --- CKM_AES_GMAC takes CK_GCM_PARAMS.
 *
 * PKCS#11 v3.2 §6.13.6, verbatim:
 *
 *   GMAC is a special case of GCM that authenticates only the Additional
 *   Authenticated Data (AAD) part of the GCM mechanism parameters. [...] When
 *   GMAC is used with C_Sign or C_Verify, pData points to the AAD. [...] the
 *   tag's length is determined by the CK_GCM_PARAMS field ulTagBits. The IV
 *   length is determined by the CK_GCM_PARAMS field ulIvLen.
 *
 * The module parsed CK_GCM_PARAMS for CKM_AES_GCM only. A caller sending the
 * canonical block for GMAC had its 48 bytes read as a raw IV -- the first
 * eight of which are a pointer -- and got a tag computed under an IV made of
 * an address. Thirty ACVP known-answer vectors, CRITICAL, on 2026-09-18.
 *
 * It had been invisible because pkcs11-check picks the parameter form from
 * the interface version it negotiates, and until this module published a v3.2
 * interface the day before, it had been sending a bare IV. Publishing the
 * interface is what made the defect measurable.
 *
 * The tag length was the second half: 16 bytes were returned whatever
 * ulTagBits asked for.
 *
 * Expected values are computed here with EVP_MAC rather than written out, so
 * a mistake made in the module and repeated in the test would still show.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

/* CK_GCM_PARAMS, OASIS order: pIv, ulIvLen, ulIvBits, pAAD, ulAADLen,
 * ulTagBits. Six words on LP64. */
typedef struct {
    void     *pIv;      CK_ULONG ulIvLen;  CK_ULONG ulIvBits;
    void     *pAAD;     CK_ULONG ulAADLen; CK_ULONG ulTagBits;
} CK_GCM_PARAMS;

#define CKR_OK                 0UL
#define CKR_SIGNATURE_INVALID  0xC0UL
#define CKF_RW                 6UL
#define CKA_CLASS              0UL
#define CKA_VALUE              0x11UL
#define CKA_KEY_TYPE           0x100UL
#define CKA_SIGN               0x108UL
#define CKA_VERIFY             0x10AUL
#define CKA_EXTRACTABLE        0x162UL
#define CKO_SECRET_KEY         4UL
#define CKK_AES                0x1FUL
#define CKM_AES_GMAC           0x108EUL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);

/* The reference: OpenSSL's own GMAC, driven directly. */
static int gmac_ref(const unsigned char *key, size_t key_len,
                     const unsigned char *iv, size_t iv_len,
                     const unsigned char *aad, size_t aad_len,
                     unsigned char out[16]) {
    EVP_MAC *m = EVP_MAC_fetch(NULL, "GMAC", NULL);
    if (!m) return 0;
    EVP_MAC_CTX *c = EVP_MAC_CTX_new(m);
    EVP_MAC_free(m);
    if (!c) return 0;
    char cipher[16];
    snprintf(cipher, sizeof cipher, "AES-%zu-GCM", key_len * 8);
    OSSL_PARAM p[3] = {
        OSSL_PARAM_construct_utf8_string("cipher", cipher, 0),
        OSSL_PARAM_construct_octet_string("iv", (void*)iv, iv_len),
        OSSL_PARAM_construct_end()
    };
    size_t n = 16;
    int r = EVP_MAC_init(c, key, key_len, p) == 1
            && EVP_MAC_update(c, aad, aad_len) == 1
            && EVP_MAC_final(c, out, &n, 16) == 1 && n == 16;
    EVP_MAC_CTX_free(c);
    return r;
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_CreateObject);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_Sign || !C_CreateObject) { fprintf(stderr,"missing symbols\n"); return 2; }

    printf("CKM_AES_GMAC takes CK_GCM_PARAMS (PKCS#11 v3.2 §6.13.6)\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"gmacparams",10);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_BYTE key[16]; for (int i = 0; i < 16; ++i) key[i] = (CK_BYTE)(i + 1);
    CK_BYTE iv12[12]; for (int i = 0; i < 12; ++i) iv12[i] = (CK_BYTE)(0xA0 + i);
    CK_BYTE iv16[16]; for (int i = 0; i < 16; ++i) iv16[i] = (CK_BYTE)(0x50 + i);
    CK_BYTE aad[29] = "the message is the AAD here!";
    const CK_ULONG aad_len = 28;

    CK_BYTE yes = 1;
    CK_ATTRIBUTE kt[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY}, sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_AES},        sizeof(CK_ULONG) },
        { CKA_VALUE,       key, sizeof key },
        { CKA_SIGN,        &yes, 1 },
        { CKA_VERIFY,      &yes, 1 },
        { CKA_EXTRACTABLE, &yes, 1 },
    };
    CK_OBJECT_HANDLE hk = 0;
    if (C_CreateObject(s, kt, 6, &hk) != CKR_OK) { fprintf(stderr,"key import\n"); return 2; }

    CK_BYTE want[16], got[16];
    if (!gmac_ref(key, sizeof key, iv12, sizeof iv12, aad, aad_len, want)) {
        fprintf(stderr, "no GMAC from this provider\n"); return 2;
    }

    /* (1) The canonical block, full-length tag. This is what the module read
     *     as a raw IV -- 48 struct bytes beginning with a pointer. */
    {
        CK_GCM_PARAMS p = { iv12, sizeof iv12, 8 * sizeof iv12, NULL, 0, 128 };
        CK_MECHANISM m = { CKM_AES_GMAC, &p, sizeof p };
        CK_ULONG n = sizeof got;
        ok(C_SignInit(s, &m, hk) == CKR_OK
           && C_Sign(s, aad, aad_len, got, &n) == CKR_OK && n == 16,
           "CK_GCM_PARAMS accepted, 16-byte tag");
        ok(memcmp(got, want, 16) == 0,
           "and the tag matches the OpenSSL reference");
    }

    /* (2) ulTagBits is honoured, and the short tag is the prefix of the long
     *     one (SP 800-38D §5.2.1.2). 16 bytes were returned regardless. */
    {
        CK_GCM_PARAMS p = { iv12, sizeof iv12, 8 * sizeof iv12, NULL, 0, 32 };
        CK_MECHANISM m = { CKM_AES_GMAC, &p, sizeof p };
        CK_ULONG n = sizeof got;
        memset(got, 0, sizeof got);
        ok(C_SignInit(s, &m, hk) == CKR_OK
           && C_Sign(s, aad, aad_len, got, &n) == CKR_OK && n == 4,
           "ulTagBits=32 yields a 4-byte tag");
        ok(memcmp(got, want, 4) == 0, "which is the leftmost 4 bytes of the full tag");

        /* The size query must agree, or a caller sizing its buffer from it
         * gets a length the operation will not produce. */
        /* The size query, which leaves the operation active: PKCS#11 expects
         * the caller to come back with a real buffer, and this test must do
         * the same or strand the session. Getting that wrong here is what
         * made the next two cases fail with CKR_OPERATION_ACTIVE and look
         * briefly like a regression in the module. */
        CK_ULONG q = 0;
        CK_BYTE again[16];
        CK_ULONG qn = sizeof again;
        ok(C_SignInit(s, &m, hk) == CKR_OK
           && C_Sign(s, aad, aad_len, NULL, &q) == CKR_OK && q == 4,
           "and the size query says 4, not 16");
        ok(C_Sign(s, aad, aad_len, again, &qn) == CKR_OK && qn == 4
           && memcmp(again, want, 4) == 0,
           "the operation survives the query and then produces the tag");

        /* C_Verify must compare on the same length, or the module refuses a
         * tag it has just produced. */
        ok(C_VerifyInit(s, &m, hk) == CKR_OK
           && C_Verify(s, aad, aad_len, got, 4) == CKR_OK,
           "C_Verify accepts the 4-byte tag it would itself make");
        ok(C_VerifyInit(s, &m, hk) == CKR_OK
           && C_Verify(s, aad, aad_len, got, 16) == CKR_SIGNATURE_INVALID,
           "and refuses the same bytes claimed to be 16 long");
    }

    /* (3) The raw-IV interop form, kept: pkcs11-tool and friends send it. */
    {
        CK_MECHANISM m = { CKM_AES_GMAC, iv12, sizeof iv12 };
        CK_ULONG n = sizeof got;
        ok(C_SignInit(s, &m, hk) == CKR_OK
           && C_Sign(s, aad, aad_len, got, &n) == CKR_OK
           && n == 16 && memcmp(got, want, 16) == 0,
           "a bare 12-byte IV still works and gives the same tag");
    }

    /* (4) A 16-byte parameter is a 16-byte IV.
     *
     *     It used to be probed for a CK_AES_GMAC_PARAMS = { ulIvLen; pIv },
     *     a structure that exists in neither the OASIS header nor
     *     pkcs11-check. When the first eight bytes happened to look like a
     *     length, a genuine 16-byte IV was read as a pointer. */
    {
        CK_BYTE want16[16];
        if (!gmac_ref(key, sizeof key, iv16, sizeof iv16, aad, aad_len, want16)) {
            ok(0, "reference for the 16-byte IV");
        } else {
            CK_MECHANISM m = { CKM_AES_GMAC, iv16, sizeof iv16 };
            CK_ULONG n = sizeof got;
            ok(C_SignInit(s, &m, hk) == CKR_OK
               && C_Sign(s, aad, aad_len, got, &n) == CKR_OK
               && n == 16 && memcmp(got, want16, 16) == 0,
               "a 16-byte IV is an IV, not a phantom parameter struct");
        }
    }

    /* (5) Still refused: no parameter at all. The module used to answer
     *     CKR_OK here, having quietly become CMAC. */
    {
        CK_MECHANISM m = { CKM_AES_GMAC, NULL, 0 };
        ok(C_SignInit(s, &m, hk) != CKR_OK
           || C_Sign(s, aad, aad_len, got, &(CK_ULONG){sizeof got}) != CKR_OK,
           "a missing parameter block is still refused");
    }

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
