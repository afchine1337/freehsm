/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_gcm_multipart_decrypt.c --- AES-GCM decrypts in parts.
 *
 * PKCS#11 v3.2 §6.13.5: on decryption the tag is the last ulTagBits / 8 bytes
 * of the input. C_DecryptUpdate handed every byte to the cipher, the tag
 * included, and C_DecryptFinal verified against a tag that had never been
 * set. Every ciphertext was CKR_ENCRYPTED_DATA_INVALID, however it was split,
 * while C_Decrypt accepted the same bytes (#35, reported by Alexandre
 * Laroche).
 *
 * The cases:
 *   (1) one C_DecryptUpdate with everything, then C_DecryptFinal;
 *   (2) parts of 1, 15, 16, 17 and 4097 bytes, on 40 and on 5000 bytes;
 *   (3) a split inside the tag, and the tag given one byte at a time;
 *   (4) additional data and a 96-bit tag;
 *   (5) the parts never give out more than the plaintext, nor the tag;
 *   (6) a changed tag, a changed ciphertext byte and changed additional data
 *       are CKR_ENCRYPTED_DATA_INVALID at C_DecryptFinal;
 *   (7) fewer bytes than a tag in all: CKR_ENCRYPTED_DATA_LEN_RANGE;
 *   (8) the size query answers what the part will give, a buffer too small
 *       is CKR_BUFFER_TOO_SMALL and the same part can be given again;
 *   (9) in place: pPart is pEncryptedPart;
 *  (10) what C_EncryptUpdate and C_EncryptFinal made is decrypted in parts.
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
typedef struct { CK_BYTE *pIv; CK_ULONG ulIvLen, ulIvBits; CK_BYTE *pAAD;
                 CK_ULONG ulAADLen, ulTagBits; } CK_GCM_PARAMS;

#define CKR_OK                        0x000UL
#define CKR_ENCRYPTED_DATA_INVALID    0x040UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE  0x041UL
#define CKR_BUFFER_TOO_SMALL          0x150UL
#define CKF_RW                        6UL
#define CKU_SO                        0UL
#define CKU_USER                      1UL
#define CKO_SECRET_KEY                4UL
#define CKK_AES                       0x1FUL
#define CKA_CLASS                     0x000UL
#define CKA_TOKEN                     0x001UL
#define CKA_KEY_TYPE                  0x100UL
#define CKA_ENCRYPT                   0x104UL
#define CKA_DECRYPT                   0x105UL
#define CKA_VALUE_LEN                 0x161UL
#define CKM_AES_KEY_GEN               0x1080UL
#define CKM_AES_GCM                   0x1087UL

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
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

#define BIG 5000
static CK_SESSION_HANDLE s;
static CK_OBJECT_HANDLE key;
static CK_BYTE iv[12];
static CK_BYTE aad[] = "additional data";
static CK_BYTE pt[BIG], ct[BIG + 16], out[BIG + 64];

/* A fresh IV for each encryption. */
static CK_GCM_PARAMS params(int with_aad, CK_ULONG tag_bits) {
    CK_GCM_PARAMS p = { iv, sizeof iv, sizeof iv * 8,
                        with_aad ? aad : NULL, with_aad ? sizeof aad - 1 : 0, tag_bits };
    return p;
}
static void next_iv(void) { for (int i = 11; i >= 0 && ++iv[i] == 0; i--) { } }

/* Single-part encryption of pt[0..n) into ct; returns the ciphertext length. */
static CK_ULONG enc(CK_GCM_PARAMS *p, CK_ULONG n) {
    CK_MECHANISM m = { CKM_AES_GCM, p, sizeof *p };
    CK_ULONG cl = sizeof ct;
    next_iv();
    if (C_EncryptInit(s, &m, key) != CKR_OK) return 0;
    if (C_Encrypt(s, pt, n, ct, &cl) != CKR_OK) return 0;
    return cl;
}

/* Decrypts c[0..cl) in parts of `chunk` bytes into out. Returns the rv of the
 * first call that fails, or of C_DecryptFinal; *got is what the parts and the
 * final gave, *from_final what the final alone gave. */
static CK_RV dec_parts(CK_GCM_PARAMS *p, CK_BYTE *c, CK_ULONG cl, CK_ULONG chunk,
                       CK_ULONG *got, CK_ULONG *from_final) {
    CK_MECHANISM m = { CKM_AES_GCM, p, sizeof *p };
    CK_RV rv = C_DecryptInit(s, &m, key);
    *got = 0; if (from_final) *from_final = 0;
    if (rv != CKR_OK) return rv;
    for (CK_ULONG off = 0; off < cl; off += chunk) {
        CK_ULONG n = cl - off < chunk ? cl - off : chunk;
        CK_ULONG ol = sizeof out - *got;
        rv = C_DecryptUpdate(s, c + off, n, out + *got, &ol);
        if (rv != CKR_OK) return rv;
        *got += ol;
    }
    CK_ULONG fl = sizeof out - *got;
    rv = C_DecryptFinal(s, out + *got, &fl);
    if (rv == CKR_OK) { *got += fl; if (from_final) *from_final = fl; }
    return rv;
}

/* 1 when c[0..cl) decrypts in parts of `chunk` to pt[0..n). */
static int roundtrip(CK_GCM_PARAMS *p, CK_ULONG cl, CK_ULONG n, CK_ULONG chunk) {
    CK_ULONG got = 0;
    memset(out, 0xEE, sizeof out);
    return dec_parts(p, ct, cl, chunk, &got, NULL) == CKR_OK
        && got == n && !memcmp(out, pt, n);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKey);
    SYM(C_EncryptInit); SYM(C_Encrypt); SYM(C_EncryptUpdate); SYM(C_EncryptFinal);
    SYM(C_DecryptInit); SYM(C_Decrypt); SYM(C_DecryptUpdate); SYM(C_DecryptFinal);
    if (!C_DecryptFinal || !C_DecryptUpdate || !C_EncryptFinal || !C_Decrypt) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("AES-GCM decryption in parts\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"gcmparts",8);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,CKU_SO,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,CKU_USER,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES, vl = 32; CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 },
                         { CKA_ENCRYPT, &yes, 1 }, { CKA_DECRYPT, &yes, 1 } };
    CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };
    if (C_GenerateKey(s, &kg, t, 6, &key)) { fprintf(stderr,"C_GenerateKey\n"); return 2; }
    for (int i = 0; i < BIG; i++) pt[i] = (CK_BYTE)(i * 7 + 3);

    CK_GCM_PARAMS p = params(0, 128);
    CK_ULONG cl = enc(&p, 40);
    if (cl != 56) { fprintf(stderr,"C_Encrypt: %lu bytes\n", cl); return 2; }

    /* (1) Everything in one part. */
    ok(roundtrip(&p, cl, 40, cl), "(1) one part with everything, then the final");

    /* (2) Parts of several sizes. */
    ok(roundtrip(&p, cl, 40, 1),  "(2) 40 bytes in parts of 1");
    ok(roundtrip(&p, cl, 40, 15), "(2) 40 bytes in parts of 15");
    ok(roundtrip(&p, cl, 40, 16), "(2) 40 bytes in parts of 16");
    ok(roundtrip(&p, cl, 40, 17), "(2) 40 bytes in parts of 17");

    /* (3) A split inside the tag: 51 = 40 + 11, so the second part is the
     * last 5 bytes of the tag. Parts of 1 gave the tag byte by byte above. */
    ok(roundtrip(&p, cl, 40, 51), "(3) a split inside the tag");

    /* (5) The parts give the plaintext and no more; the final gives nothing. */
    { CK_ULONG got = 0, fin = 99;
      CK_RV rv = dec_parts(&p, ct, cl, 7, &got, &fin);
      ok(rv == CKR_OK && got == 40 && fin == 0,
         "(5) 40 bytes out for 56 in, none of them from the final"); }

    /* (6) Changed tag, changed ciphertext. */
    { CK_ULONG got = 0;
      ct[cl - 1] ^= 1;
      ok(dec_parts(&p, ct, cl, 13, &got, NULL) == CKR_ENCRYPTED_DATA_INVALID,
         "(6) a changed tag: CKR_ENCRYPTED_DATA_INVALID at the final");
      ct[cl - 1] ^= 1; ct[3] ^= 1;
      ok(dec_parts(&p, ct, cl, 13, &got, NULL) == CKR_ENCRYPTED_DATA_INVALID,
         "(6) a changed ciphertext byte: CKR_ENCRYPTED_DATA_INVALID");
      ct[3] ^= 1;
      ok(roundtrip(&p, cl, 40, 13), "(6) and the unchanged bytes still decrypt"); }

    /* (7) Fewer bytes than a tag. */
    { CK_ULONG got = 0;
      ok(dec_parts(&p, ct, 10, 4, &got, NULL) == CKR_ENCRYPTED_DATA_LEN_RANGE && got == 0,
         "(7) 10 bytes in all: CKR_ENCRYPTED_DATA_LEN_RANGE, nothing out");
      ok(dec_parts(&p, ct, 0, 4, &got, NULL) == CKR_ENCRYPTED_DATA_LEN_RANGE,
         "(7) no bytes at all: CKR_ENCRYPTED_DATA_LEN_RANGE"); }

    /* (8) Size query, and a buffer too small. */
    { CK_MECHANISM m = { CKM_AES_GCM, &p, sizeof p };
      CK_ULONG n = 99, small = 5, full = sizeof out, fl = sizeof out;
      CK_RV r0 = C_DecryptInit(s, &m, key);
      CK_RV r1 = C_DecryptUpdate(s, ct, 30, NULL, &n);          /* 30 - 16 held back */
      CK_RV r2 = C_DecryptUpdate(s, ct, 30, out, &small);
      CK_RV r3 = C_DecryptUpdate(s, ct, 30, out, &full);
      CK_ULONG rest = sizeof out - full;
      CK_RV r4 = C_DecryptUpdate(s, ct + 30, cl - 30, out + full, &rest);
      CK_RV r5 = C_DecryptFinal(s, out + full + rest, &fl);
      ok(r0 == CKR_OK && r1 == CKR_OK && n == 14, "(8) the size query answers 14 for 30 bytes");
      ok(r2 == CKR_BUFFER_TOO_SMALL && small == 14, "(8) 5 bytes of room: CKR_BUFFER_TOO_SMALL, 14");
      ok(r3 == CKR_OK && full == 14 && r4 == CKR_OK && rest == 26 && r5 == CKR_OK
         && !memcmp(out, pt, 40), "(8) the same part again, then the rest, decrypts"); }

    /* (9) In place. */
    { CK_MECHANISM m = { CKM_AES_GCM, &p, sizeof p };
      static CK_BYTE buf[56]; memcpy(buf, ct, 56);
      CK_ULONG a = 20, b = 36, fl = 0; CK_BYTE none[1];
      CK_RV r0 = C_DecryptInit(s, &m, key);
      CK_RV r1 = C_DecryptUpdate(s, buf, 20, buf, &a);
      CK_RV r2 = C_DecryptUpdate(s, buf + 20, 36, buf + a, &b);
      CK_RV r3 = C_DecryptFinal(s, none, &fl);
      ok(r0 == CKR_OK && r1 == CKR_OK && a == 4 && r2 == CKR_OK && b == 36 && r3 == CKR_OK
         && !memcmp(buf, pt, 40), "(9) in place, pPart being pEncryptedPart"); }

    /* (2) again, on 5000 bytes. */
    cl = enc(&p, BIG);
    if (cl != BIG + 16) { fprintf(stderr,"C_Encrypt: %lu bytes\n", cl); return 2; }
    ok(roundtrip(&p, cl, BIG, 4097), "(2) 5000 bytes in parts of 4097");
    ok(roundtrip(&p, cl, BIG, 17),   "(2) 5000 bytes in parts of 17");

    /* (4) Additional data and a 96-bit tag. */
    { CK_GCM_PARAMS q = params(1, 96);
      CK_ULONG got = 0;
      cl = enc(&q, 100);
      ok(cl == 112, "(4) 96-bit tag: 100 bytes encrypt to 112");
      ok(roundtrip(&q, cl, 100, 9), "(4) with additional data, in parts of 9");
      ok(roundtrip(&q, cl, 100, 101), "(4) and with a split inside the 12-byte tag");
      CK_GCM_PARAMS bad = q; static CK_BYTE other[] = "additional dat4"; bad.pAAD = other;
      ok(dec_parts(&bad, ct, cl, 9, &got, NULL) == CKR_ENCRYPTED_DATA_INVALID,
         "(6) changed additional data: CKR_ENCRYPTED_DATA_INVALID"); }

    /* (10) Encrypted in parts, decrypted in parts; and by C_Decrypt. */
    { CK_GCM_PARAMS q = params(1, 128);
      CK_MECHANISM m = { CKM_AES_GCM, &q, sizeof q };
      CK_ULONG a = sizeof ct, b, c;
      next_iv();
      CK_RV r0 = C_EncryptInit(s, &m, key);
      CK_RV r1 = C_EncryptUpdate(s, pt, 33, ct, &a);
      b = sizeof ct - a;
      CK_RV r2 = C_EncryptUpdate(s, pt + 33, 67, ct + a, &b);
      c = sizeof ct - a - b;
      CK_RV r3 = C_EncryptFinal(s, ct + a + b, &c);
      cl = a + b + c;
      ok(r0 == CKR_OK && r1 == CKR_OK && r2 == CKR_OK && r3 == CKR_OK && cl == 116,
         "(10) 100 bytes encrypted in two parts: 116 bytes");
      ok(roundtrip(&q, cl, 100, 31), "(10) decrypted in parts of 31");
      CK_ULONG ol = sizeof out;
      ok(C_DecryptInit(s, &m, key) == CKR_OK && C_Decrypt(s, ct, cl, out, &ol) == CKR_OK
         && ol == 100 && !memcmp(out, pt, 100), "(10) and by C_Decrypt"); }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
