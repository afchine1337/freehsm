/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_len_and_param_rv.c --- a wrong length and a wrong ECDH parameter are
 * refused for what they are.
 *
 * Five answers of #37 (reported by Alexandre Laroche), each a refusal that
 * carried the wrong reason, or an acceptance:
 *   (B1) C_Encrypt, AES-ECB or AES-CBC without padding, of a partial block:
 *        CKR_DATA_LEN_RANGE, not CKR_FUNCTION_FAILED;
 *   (B2) C_Decrypt, AES-ECB, AES-CBC or AES-CBC-PAD, of a partial block, and
 *        AES-CBC-PAD of nothing: CKR_ENCRYPTED_DATA_LEN_RANGE, not
 *        CKR_ENCRYPTED_DATA_INVALID;
 *   (K2) C_CreateObject of a CKK_AES key of 13 bytes:
 *        CKR_ATTRIBUTE_VALUE_INVALID, not CKR_OK;
 *   (E1) CKM_ECDH1_DERIVE with a peer value that is not a point of the curve
 *        in any accepted form: CKR_MECHANISM_PARAM_INVALID, not
 *        CKR_ATTRIBUTE_VALUE_INVALID, and no key;
 *   (E2) CKM_ECDH1_DERIVE with a KDF other than CKD_NULL, or without a
 *        parameter: CKR_MECHANISM_PARAM_INVALID, not CKR_ARGUMENTS_BAD.
 * Each refusal ends the operation, and what was accepted before still is.
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
typedef struct { CK_ULONG kdf, ulSharedDataLen; CK_BYTE *pSharedData;
                 CK_ULONG ulPublicDataLen; CK_BYTE *pPublicData; } CK_ECDH1_DERIVE_PARAMS;

#define CKR_OK                         0x000UL
#define CKR_ATTRIBUTE_VALUE_INVALID    0x013UL
#define CKR_DATA_LEN_RANGE             0x021UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE   0x041UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKR_OPERATION_NOT_INITIALIZED  0x091UL
#define CKF_RW                         6UL
#define CKU_SO                         0UL
#define CKU_USER                       1UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_DECRYPT                    0x105UL
#define CKA_DERIVE                     0x10CUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EC_PARAMS                  0x180UL
#define CKA_EC_POINT                   0x181UL
#define CKM_EC_KEY_PAIR_GEN            0x1040UL
#define CKM_ECDH1_DERIVE               0x1050UL
#define CKM_AES_KEY_GEN                0x1080UL
#define CKM_AES_ECB                    0x1081UL
#define CKM_AES_CBC                    0x1082UL
#define CKM_AES_CBC_PAD                0x1085UL
#define CKD_NULL                       1UL
#define CKD_SHA256_KDF                 6UL

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
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_OBJECT_HANDLE aes;
static CK_BYTE yes = 1, no = 0;
static CK_BYTE iv[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
static CK_BYTE data[64], buf[96], buf2[96];

static CK_MECHANISM mech(CK_ULONG m) {
    CK_MECHANISM x = { m, m == CKM_AES_ECB ? NULL : iv, m == CKM_AES_ECB ? 0 : sizeof iv };
    return x;
}
/* C_Encrypt of n bytes of data into buf; *ol is the length it gives. */
static CK_RV enc(CK_ULONG m, CK_ULONG n, CK_ULONG *ol) {
    CK_MECHANISM x = mech(m);
    CK_RV rv = C_EncryptInit(s, &x, aes);
    if (rv != CKR_OK) return 0xE000UL | rv;
    *ol = sizeof buf;
    return C_Encrypt(s, data, n, buf, ol);
}
/* C_Decrypt of n bytes of buf into buf2. */
static CK_RV dec(CK_ULONG m, CK_ULONG n, CK_ULONG *ol) {
    CK_MECHANISM x = mech(m);
    CK_RV rv = C_DecryptInit(s, &x, aes);
    if (rv != CKR_OK) return 0xE000UL | rv;
    *ol = sizeof buf2;
    return C_Decrypt(s, buf, n, buf2, ol);
}

/* A secret key of type kt holding n bytes. */
static CK_RV import(CK_ULONG kt, CK_ULONG n, CK_OBJECT_HANDLE *h) {
    static CK_BYTE v[32] = "0123456789abcdef0123456789abcdef";
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_VALUE, v, n }, { CKA_ENCRYPT, &yes, 1 } };
    return C_CreateObject(s, t, 5, h);
}

static CK_OBJECT_HANDLE ecprv;
/* CKM_ECDH1_DERIVE with the given parameter block; *made is the handle. */
static CK_RV derive(void *param, CK_ULONG plen, CK_OBJECT_HANDLE *made) {
    CK_MECHANISM m = { CKM_ECDH1_DERIVE, param, plen };
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET, vl = 32;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 } };
    *made = 0;
    return C_DeriveKey(s, &m, ecprv, t, 4, made);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_GetAttributeValue);
    SYM(C_GenerateKey); SYM(C_GenerateKeyPair); SYM(C_EncryptInit); SYM(C_Encrypt);
    SYM(C_DecryptInit); SYM(C_Decrypt); SYM(C_DeriveKey);
    if (!C_CreateObject || !C_Decrypt || !C_Encrypt || !C_DeriveKey || !C_GenerateKeyPair) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("Lengths and ECDH parameters refused for what they are\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"lenparam",8);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,CKU_SO,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,CKU_USER,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    { CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES, vl = 32;
      CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                           { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 },
                           { CKA_ENCRYPT, &yes, 1 }, { CKA_DECRYPT, &yes, 1 } };
      CK_MECHANISM g = { CKM_AES_KEY_GEN, NULL, 0 };
      if (C_GenerateKey(s, &g, t, 6, &aes)) { fprintf(stderr,"AES key\n"); return 2; } }
    for (int i = 0; i < 64; i++) data[i] = (CK_BYTE)(i * 3 + 1);

    CK_ULONG l = 0; CK_RV rv;

    /* (B1) */
    rv = enc(CKM_AES_ECB, 15, &l);
    ok(rv == CKR_DATA_LEN_RANGE, "(B1) C_Encrypt AES-ECB, 15 bytes: CKR_DATA_LEN_RANGE");
    l = sizeof buf;
    ok(C_Encrypt(s, data, 16, buf, &l) == CKR_OPERATION_NOT_INITIALIZED, "(B1) and the operation is over");
    ok(enc(CKM_AES_CBC, 31, &l) == CKR_DATA_LEN_RANGE, "(B1) C_Encrypt AES-CBC, 31 bytes: CKR_DATA_LEN_RANGE");
    ok(enc(CKM_AES_ECB, 0, &l) == CKR_OK && l == 0, "(B1) AES-ECB, 0 bytes: accepted, nothing out");
    ok(enc(CKM_AES_CBC_PAD, 15, &l) == CKR_OK && l == 16, "(B1) AES-CBC-PAD, 15 bytes: 16 bytes, as before");
    ok(enc(CKM_AES_ECB, 32, &l) == CKR_OK && l == 32, "(B1) AES-ECB, 32 bytes: 32 bytes, as before");

    /* (B2) buf holds 32 bytes of AES-ECB ciphertext. */
    ok(dec(CKM_AES_ECB, 15, &l) == CKR_ENCRYPTED_DATA_LEN_RANGE,
       "(B2) C_Decrypt AES-ECB, 15 bytes: CKR_ENCRYPTED_DATA_LEN_RANGE");
    l = sizeof buf2;
    ok(C_Decrypt(s, buf, 16, buf2, &l) == CKR_OPERATION_NOT_INITIALIZED, "(B2) and the operation is over");
    ok(dec(CKM_AES_ECB, 32, &l) == CKR_OK && l == 32 && !memcmp(buf2, data, 32),
       "(B2) AES-ECB, 32 bytes: decrypts, as before");
    ok(dec(CKM_AES_CBC, 31, &l) == CKR_ENCRYPTED_DATA_LEN_RANGE,
       "(B2) C_Decrypt AES-CBC, 31 bytes: CKR_ENCRYPTED_DATA_LEN_RANGE");
    ok(dec(CKM_AES_CBC_PAD, 17, &l) == CKR_ENCRYPTED_DATA_LEN_RANGE,
       "(B2) C_Decrypt AES-CBC-PAD, 17 bytes: CKR_ENCRYPTED_DATA_LEN_RANGE");
    ok(dec(CKM_AES_CBC_PAD, 0, &l) == CKR_ENCRYPTED_DATA_LEN_RANGE,
       "(B2) C_Decrypt AES-CBC-PAD, 0 bytes: CKR_ENCRYPTED_DATA_LEN_RANGE");
    ok(enc(CKM_AES_CBC_PAD, 40, &l) == CKR_OK && l == 48, "(B2) AES-CBC-PAD, 40 bytes encrypt to 48");
    ok(dec(CKM_AES_CBC_PAD, 48, &l) == CKR_OK && l == 40 && !memcmp(buf2, data, 40),
       "(B2) and decrypt back, as before");

    /* (K2) */
    { CK_OBJECT_HANDLE h = 0;
      ok(import(CKK_AES, 13, &h) == CKR_ATTRIBUTE_VALUE_INVALID,
         "(K2) C_CreateObject CKK_AES, 13 bytes: CKR_ATTRIBUTE_VALUE_INVALID");
      ok(import(CKK_AES, 16, &h) == CKR_OK, "(K2) CKK_AES, 16 bytes: accepted");
      ok(import(CKK_AES, 24, &h) == CKR_OK, "(K2) CKK_AES, 24 bytes: accepted");
      ok(import(CKK_AES, 32, &h) == CKR_OK, "(K2) CKK_AES, 32 bytes: accepted");
      ok(import(CKK_GENERIC_SECRET, 13, &h) == CKR_OK, "(K2) CKK_GENERIC_SECRET, 13 bytes: accepted, as before"); }

    /* (E1), (E2) A P-256 key pair that derives. */
    { static CK_BYTE p256[] = { 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 };
      CK_MECHANISM g = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
      CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_EC_PARAMS, p256, sizeof p256 } };
      CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &yes, 1 }, { CKA_DERIVE, &yes, 1 } };
      CK_OBJECT_HANDLE pub, made;
      if (C_GenerateKeyPair(s, &g, pt, 2, vt, 3, &pub, &ecprv)) { fprintf(stderr,"P-256 key pair\n"); return 2; }
      CK_BYTE point[80]; CK_ATTRIBUTE a = { CKA_EC_POINT, point, sizeof point };
      if (C_GetAttributeValue(s, pub, &a, 1) || a.ulValueLen != 67) { fprintf(stderr,"CKA_EC_POINT\n"); return 2; }

      CK_ECDH1_DERIVE_PARAMS good = { CKD_NULL, 0, NULL, 65, point + 2 };
      ok(derive(&good, sizeof good, &made) == CKR_OK && made != 0, "(E1) the pair's own point: a key, as before");
      CK_ECDH1_DERIVE_PARAMS wrapped = { CKD_NULL, 0, NULL, 67, point };
      ok(derive(&wrapped, sizeof wrapped, &made) == CKR_OK, "(E1) the same in its OCTET STRING: a key, as before");

      static CK_BYTE big[1024];
      memset(big, 0x5a, sizeof big);
      CK_ECDH1_DERIVE_PARAMS p1 = { CKD_NULL, 0, NULL, sizeof big, big };
      rv = derive(&p1, sizeof p1, &made);
      ok(rv == CKR_MECHANISM_PARAM_INVALID && made == 0,
         "(E1) a 1 KiB peer value: CKR_MECHANISM_PARAM_INVALID, no key");

      CK_BYTE shortp[42]; memcpy(shortp, point, 42);      /* says 65 bytes, holds 40 */
      CK_ECDH1_DERIVE_PARAMS p2 = { CKD_NULL, 0, NULL, sizeof shortp, shortp };
      rv = derive(&p2, sizeof p2, &made);
      ok(rv == CKR_MECHANISM_PARAM_INVALID && made == 0,
         "(E1) an OCTET STRING promising 65 bytes, holding 40: the same");

      CK_BYTE off[65]; memcpy(off, point + 2, 65); off[64] ^= 1;   /* no longer on the curve */
      CK_ECDH1_DERIVE_PARAMS p3 = { CKD_NULL, 0, NULL, sizeof off, off };
      rv = derive(&p3, sizeof p3, &made);
      ok(rv == CKR_MECHANISM_PARAM_INVALID && made == 0, "(E1) a point off the curve: the same");

      static CK_BYTE shared[19] = "shared information";
      CK_ECDH1_DERIVE_PARAMS p4 = { CKD_SHA256_KDF, sizeof shared, shared, 65, point + 2 };
      rv = derive(&p4, sizeof p4, &made);
      ok(rv == CKR_MECHANISM_PARAM_INVALID && made == 0,
         "(E2) CKD_SHA256_KDF with shared data: CKR_MECHANISM_PARAM_INVALID, no key");
      ok(derive(NULL, 0, &made) == CKR_MECHANISM_PARAM_INVALID, "(E2) no parameter: the same");
      CK_ECDH1_DERIVE_PARAMS p5 = { CKD_NULL, 0, NULL, 0, NULL };
      ok(derive(&p5, sizeof p5, &made) == CKR_MECHANISM_PARAM_INVALID, "(E2) no peer value: the same"); }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
