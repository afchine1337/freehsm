/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_single_part_after_update.c --- a single-part call does not finish an
 * operation that has taken a part.
 *
 * PKCS#11 v3.2 says of C_Digest, C_Sign, C_Verify, C_Encrypt and C_Decrypt
 * that each "cannot be used to terminate a multi-part operation" and must
 * follow its Init with no Update in between. C_Digest after C_DigestUpdate
 * answered CKR_OK and the digest of its own argument alone: the part already
 * given was dropped (#37 M1, reported by Alexandre Laroche).
 *
 * For each of the five:
 *   (a) Init, Update, then the single-part call: CKR_OPERATION_ACTIVE;
 *   (b) that error ended the operation: the Final is
 *       CKR_OPERATION_NOT_INITIALIZED;
 *   (c) a new Init is accepted and the single-part call gives the right
 *       answer, so the refusal left nothing behind;
 *   (d) Init, Update, Final still works.
 * And for C_Digest: the size query is refused as well, and C_DigestKey
 * counts as a part.
 *
 * Case (d) found a second defect, older than the rule: an operation that
 * ended on an error after an Update kept its MAC or cipher context, and the
 * next operation in the session carried on in it -- the previous key, IV and
 * parts. So also:
 *   (e) Init with one key, Update, an Update that fails; then Init with
 *       another key, Update, Final gives what that second key gives alone.
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
#define CKR_OPERATION_ACTIVE           0x090UL
#define CKR_OPERATION_NOT_INITIALIZED  0x091UL
#define CKF_RW                         6UL
#define CKU_SO                         0UL
#define CKU_USER                       1UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_DECRYPT                    0x105UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKM_SHA256                     0x250UL
#define CKM_SHA256_HMAC                0x251UL
#define CKM_GENERIC_SECRET_KEY_GEN     0x350UL
#define CKM_AES_KEY_GEN                0x1080UL
#define CKM_AES_CBC_PAD                0x1085UL

/* Test PINs, for a token this program makes in a throwaway directory. */
#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM*);
static CK_RV (*C_Digest)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_DigestKey)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-70s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE abc[] = "abc", def[] = "def", abcdef[] = "abcdef";

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKey);
    SYM(C_DigestInit); SYM(C_Digest); SYM(C_DigestUpdate); SYM(C_DigestKey); SYM(C_DigestFinal);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_Verify); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    SYM(C_EncryptInit); SYM(C_Encrypt); SYM(C_EncryptUpdate); SYM(C_EncryptFinal);
    SYM(C_DecryptInit); SYM(C_Decrypt); SYM(C_DecryptUpdate); SYM(C_DecryptFinal);
    if (!C_DigestKey || !C_VerifyFinal || !C_DecryptFinal || !C_EncryptFinal || !C_SignFinal) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("A single-part call after an Update\n\n");

    CK_SESSION_HANDLE s;
    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"onepart",7);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,CKU_SO,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,CKU_USER,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_ULONG cls = CKO_SECRET_KEY, kaes = CKK_AES, kgen = CKK_GENERIC_SECRET, vl = 32;
    CK_BYTE yes = 1, no = 0;
    CK_OBJECT_HANDLE aes, aes2, mac, mac2, plain;
    { CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kaes, sizeof kaes },
                           { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 },
                           { CKA_ENCRYPT, &yes, 1 }, { CKA_DECRYPT, &yes, 1 } };
      CK_MECHANISM g = { CKM_AES_KEY_GEN, NULL, 0 };
      if (C_GenerateKey(s, &g, t, 6, &aes) || C_GenerateKey(s, &g, t, 6, &aes2)) { fprintf(stderr,"AES key\n"); return 2; } }
    { CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kgen, sizeof kgen },
                           { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 },
                           { CKA_SIGN, &yes, 1 }, { CKA_VERIFY, &yes, 1 } };
      CK_MECHANISM g = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };
      if (C_GenerateKey(s, &g, t, 6, &mac) || C_GenerateKey(s, &g, t, 6, &mac2)) { fprintf(stderr,"HMAC key\n"); return 2; } }
    /* A key C_DigestKey accepts: not sensitive. */
    { CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kgen, sizeof kgen },
                           { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 },
                           { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 } };
      CK_MECHANISM g = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };
      if (C_GenerateKey(s, &g, t, 6, &plain)) { fprintf(stderr,"plain key\n"); return 2; } }

    /* ---- C_Digest ---------------------------------------------------- */
    { CK_MECHANISM m = { CKM_SHA256, NULL, 0 };
      CK_BYTE ref_def[32], ref_all[32], d[32]; CK_ULONG l = 32, fl = 32;
      if (C_DigestInit(s, &m) || C_Digest(s, def, 3, ref_def, &l) || l != 32) { fprintf(stderr,"C_Digest\n"); return 2; }
      l = 32;
      if (C_DigestInit(s, &m) || C_Digest(s, abcdef, 6, ref_all, &l)) { fprintf(stderr,"C_Digest\n"); return 2; }

      memset(d, 0, sizeof d); l = 32;
      CK_RV r0 = C_DigestInit(s, &m);
      CK_RV r1 = C_DigestUpdate(s, abc, 3);
      CK_RV r2 = C_Digest(s, def, 3, d, &l);
      CK_RV r3 = C_DigestFinal(s, d, &fl);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OPERATION_ACTIVE,
         "C_Digest after C_DigestUpdate: CKR_OPERATION_ACTIVE");
      ok(memcmp(d, ref_def, 32) != 0, "C_Digest: and no digest of the last argument alone");
      ok(r3 == CKR_OPERATION_NOT_INITIALIZED, "C_Digest: the operation is over");

      l = 0;
      r0 = C_DigestInit(s, &m); r1 = C_DigestUpdate(s, abc, 3);
      r2 = C_Digest(s, def, 3, NULL, &l);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OPERATION_ACTIVE,
         "C_Digest: the size query after an Update is refused too");

      l = 32;
      r0 = C_DigestInit(s, &m); r1 = C_DigestKey(s, plain);
      r2 = C_Digest(s, def, 3, d, &l);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OPERATION_ACTIVE,
         "C_Digest after C_DigestKey: CKR_OPERATION_ACTIVE");

      l = 32;
      r0 = C_DigestInit(s, &m); r2 = C_Digest(s, def, 3, d, &l);
      ok(r0 == CKR_OK && r2 == CKR_OK && l == 32 && !memcmp(d, ref_def, 32),
         "C_Digest: a new C_DigestInit, then C_Digest, is right");

      l = 32;
      r0 = C_DigestInit(s, &m); r1 = C_DigestUpdate(s, abc, 3);
      r2 = C_DigestUpdate(s, def, 3); r3 = C_DigestFinal(s, d, &l);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OK && r3 == CKR_OK && !memcmp(d, ref_all, 32),
         "C_Digest: Init, Update, Update, Final still gives SHA-256(abcdef)"); }

    /* ---- C_Sign and C_Verify (HMAC-SHA-256) --------------------------- */
    { CK_MECHANISM m = { CKM_SHA256_HMAC, NULL, 0 };
      CK_BYTE ref_def[32], ref_all[32], g[32]; CK_ULONG l = 32, fl = 32;
      if (C_SignInit(s, &m, mac) || C_Sign(s, def, 3, ref_def, &l) || l != 32) { fprintf(stderr,"C_Sign\n"); return 2; }
      l = 32;
      if (C_SignInit(s, &m, mac) || C_Sign(s, abcdef, 6, ref_all, &l)) { fprintf(stderr,"C_Sign\n"); return 2; }

      memset(g, 0, sizeof g); l = 32;
      CK_RV r0 = C_SignInit(s, &m, mac);
      CK_RV r1 = C_SignUpdate(s, abc, 3);
      CK_RV r2 = C_Sign(s, def, 3, g, &l);
      CK_RV r3 = C_SignFinal(s, g, &fl);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OPERATION_ACTIVE,
         "C_Sign after C_SignUpdate: CKR_OPERATION_ACTIVE");
      ok(r3 == CKR_OPERATION_NOT_INITIALIZED, "C_Sign: the operation is over");
      l = 32;
      r0 = C_SignInit(s, &m, mac); r2 = C_Sign(s, def, 3, g, &l);
      ok(r0 == CKR_OK && r2 == CKR_OK && !memcmp(g, ref_def, 32),
         "C_Sign: a new C_SignInit, then C_Sign, is right");
      l = 32;
      r0 = C_SignInit(s, &m, mac); r1 = C_SignUpdate(s, abc, 3);
      r2 = C_SignUpdate(s, def, 3); r3 = C_SignFinal(s, g, &l);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OK && r3 == CKR_OK && !memcmp(g, ref_all, 32),
         "C_Sign: Init, Update, Update, Final still gives the MAC of abcdef");

      /* (e) mac2 is another key; the failed operation was under mac. */
      { CK_BYTE ref2[32], g2[32]; CK_ULONG l2 = 32;
        if (C_SignInit(s, &m, mac2) || C_Sign(s, def, 3, ref2, &l2)) { fprintf(stderr,"C_Sign\n"); return 2; }
        r0 = C_SignInit(s, &m, mac); r1 = C_SignUpdate(s, abc, 3);
        r2 = C_SignUpdate(s, NULL, 5);
        l2 = 32;
        CK_RV r4 = C_SignInit(s, &m, mac2), r5 = C_SignUpdate(s, def, 3), r6 = C_SignFinal(s, g2, &l2);
        ok(r0 == CKR_OK && r1 == CKR_OK && r2 != CKR_OK, "C_SignUpdate with a NULL part fails");
        ok(r4 == CKR_OK && r5 == CKR_OK && r6 == CKR_OK && !memcmp(g2, ref2, 32),
           "(e) the next C_SignInit starts afresh, under its own key"); }

      /* The refused C_Verify is given a MAC that is right for its own
       * argument: before the rule it could have answered CKR_OK. */
      r0 = C_VerifyInit(s, &m, mac);
      r1 = C_VerifyUpdate(s, abc, 3);
      r2 = C_Verify(s, def, 3, ref_def, 32);
      r3 = C_VerifyFinal(s, ref_all, 32);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OPERATION_ACTIVE,
         "C_Verify after C_VerifyUpdate: CKR_OPERATION_ACTIVE");
      ok(r3 == CKR_OPERATION_NOT_INITIALIZED, "C_Verify: the operation is over");
      r0 = C_VerifyInit(s, &m, mac); r2 = C_Verify(s, def, 3, ref_def, 32);
      ok(r0 == CKR_OK && r2 == CKR_OK, "C_Verify: a new C_VerifyInit, then C_Verify, is right");
      r0 = C_VerifyInit(s, &m, mac); r1 = C_VerifyUpdate(s, abc, 3);
      r2 = C_VerifyUpdate(s, def, 3); r3 = C_VerifyFinal(s, ref_all, 32);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OK && r3 == CKR_OK,
         "C_Verify: Init, Update, Update, Final still verifies"); }

    /* ---- C_Encrypt and C_Decrypt (AES-CBC-PAD) ------------------------ */
    { CK_BYTE iv[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
      CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof iv };
      CK_BYTE pt[40], ct[64], out[64], tmp[64];
      CK_ULONG cl = sizeof ct, l, a, b;
      for (int i = 0; i < 40; i++) pt[i] = (CK_BYTE)(i * 5 + 1);
      if (C_EncryptInit(s, &m, aes) || C_Encrypt(s, pt, 40, ct, &cl) || cl != 48) { fprintf(stderr,"C_Encrypt\n"); return 2; }

      l = sizeof tmp; a = sizeof tmp; b = sizeof tmp;
      CK_RV r0 = C_EncryptInit(s, &m, aes);
      CK_RV r1 = C_EncryptUpdate(s, pt, 20, tmp, &a);
      CK_RV r2 = C_Encrypt(s, pt + 20, 20, tmp, &l);
      CK_RV r3 = C_EncryptFinal(s, tmp, &b);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OPERATION_ACTIVE,
         "C_Encrypt after C_EncryptUpdate: CKR_OPERATION_ACTIVE");
      ok(r3 == CKR_OPERATION_NOT_INITIALIZED, "C_Encrypt: the operation is over");
      l = sizeof tmp;
      r0 = C_EncryptInit(s, &m, aes); r2 = C_Encrypt(s, pt, 40, tmp, &l);
      ok(r0 == CKR_OK && r2 == CKR_OK && l == 48 && !memcmp(tmp, ct, 48),
         "C_Encrypt: a new C_EncryptInit, then C_Encrypt, is right");
      a = sizeof tmp;
      r0 = C_EncryptInit(s, &m, aes); r1 = C_EncryptUpdate(s, pt, 20, tmp, &a);
      b = sizeof tmp - a; r2 = C_EncryptUpdate(s, pt + 20, 20, tmp + a, &b);
      l = sizeof tmp - a - b; r3 = C_EncryptFinal(s, tmp + a + b, &l);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OK && r3 == CKR_OK && a + b + l == 48
         && !memcmp(tmp, ct, 48), "C_Encrypt: Init, Update, Update, Final still encrypts");

      /* (e) aes2 is another key; the failed operations were under aes. */
      { CK_BYTE ref2[64]; CK_ULONG rl = sizeof ref2;
        if (C_EncryptInit(s, &m, aes2) || C_Encrypt(s, pt, 40, ref2, &rl) || rl != 48) { fprintf(stderr,"C_Encrypt\n"); return 2; }
        a = sizeof tmp;
        r0 = C_EncryptInit(s, &m, aes); r1 = C_EncryptUpdate(s, pt, 20, tmp, &a);
        r2 = C_EncryptUpdate(s, pt, 20, tmp, NULL);
        a = sizeof tmp;
        CK_RV r4 = C_EncryptInit(s, &m, aes2), r5 = C_EncryptUpdate(s, pt, 40, tmp, &a);
        l = sizeof tmp - a;
        CK_RV r6 = C_EncryptFinal(s, tmp + a, &l);
        ok(r0 == CKR_OK && r1 == CKR_OK && r2 != CKR_OK, "C_EncryptUpdate with a NULL length fails");
        ok(r4 == CKR_OK && r5 == CKR_OK && r6 == CKR_OK && a + l == 48 && !memcmp(tmp, ref2, 48),
           "(e) the next C_EncryptInit starts afresh, under its own key and IV");
        a = sizeof out;
        r0 = C_DecryptInit(s, &m, aes); r1 = C_DecryptUpdate(s, ct, 20, out, &a);
        r2 = C_DecryptUpdate(s, ct, 20, out, NULL);
        a = sizeof out;
        r4 = C_DecryptInit(s, &m, aes2); r5 = C_DecryptUpdate(s, ref2, 48, out, &a);
        l = sizeof out - a;
        r6 = C_DecryptFinal(s, out + a, &l);
        ok(r0 == CKR_OK && r1 == CKR_OK && r2 != CKR_OK, "C_DecryptUpdate with a NULL length fails");
        ok(r4 == CKR_OK && r5 == CKR_OK && r6 == CKR_OK && a + l == 40 && !memcmp(out, pt, 40),
           "(e) the next C_DecryptInit starts afresh, under its own key and IV"); }

      l = sizeof out; a = sizeof out; b = sizeof out;
      r0 = C_DecryptInit(s, &m, aes);
      r1 = C_DecryptUpdate(s, ct, 16, out, &a);
      r2 = C_Decrypt(s, ct + 16, 32, out, &l);
      r3 = C_DecryptFinal(s, out, &b);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OPERATION_ACTIVE,
         "C_Decrypt after C_DecryptUpdate: CKR_OPERATION_ACTIVE");
      ok(r3 == CKR_OPERATION_NOT_INITIALIZED, "C_Decrypt: the operation is over");
      l = sizeof out;
      r0 = C_DecryptInit(s, &m, aes); r2 = C_Decrypt(s, ct, 48, out, &l);
      ok(r0 == CKR_OK && r2 == CKR_OK && l == 40 && !memcmp(out, pt, 40),
         "C_Decrypt: a new C_DecryptInit, then C_Decrypt, is right");
      a = sizeof out;
      r0 = C_DecryptInit(s, &m, aes); r1 = C_DecryptUpdate(s, ct, 20, out, &a);
      b = sizeof out - a; r2 = C_DecryptUpdate(s, ct + 20, 28, out + a, &b);
      l = sizeof out - a - b; r3 = C_DecryptFinal(s, out + a + b, &l);
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OK && r3 == CKR_OK && a + b + l == 40
         && !memcmp(out, pt, 40), "C_Decrypt: Init, Update, Update, Final still decrypts"); }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
