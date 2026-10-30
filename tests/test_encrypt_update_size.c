/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_encrypt_update_size.c --- C_EncryptUpdate on a block cipher asks for
 * the length it will write, not for the part plus a block.
 *
 * Encryption holds back only an incomplete block, even with padding, so a
 * part produces every whole block of what was held back plus the part. The
 * module asked for ulPartLen + 16 whatever was held back, and refused the
 * exact length with CKR_BUFFER_TOO_SMALL. pkcs11-tool encrypts in 1024-byte
 * parts into a 1024-byte buffer: an aligned part fills it exactly, and OpenSC's
 * test-pkcs11-tool-sym-crypt-test.sh (AES-CBC-PAD, 24393 bytes) failed.
 *
 * What is asserted, AES-128-CBC-PAD:
 *   (1) parts of 1024 bytes into a 1024-byte buffer are accepted, and
 *       Update + Final equal the one-shot C_Encrypt of the same input
 *   (2) the size query answers the exact length: 7 bytes held back plus a
 *       1024-byte part is 1024, not 1040; 7 + 9 is 16; 7 alone is 0
 *   (3) one byte less than that length is still refused with
 *       CKR_BUFFER_TOO_SMALL, reporting the length, and the guard bytes
 *       after it are untouched
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                0x00000000UL
#define CKR_BUFFER_TOO_SMALL  0x00000150UL
#define CKM_AES_KEY_GEN       0x00001080UL
#define CKM_AES_CBC_PAD       0x00001085UL
#define CKA_VALUE_LEN         0x00000161UL
#define CKA_ENCRYPT           0x00000104UL

#define TOTAL 24393   /* 8131 x 3, as in OpenSC's test */

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad32(CK_BYTE b[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(b, ' ', 32); memcpy(b, s, n); return b;
}

static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);

/* The size query's answer for `n` bytes, or (CK_ULONG)-1 on an error. */
static CK_ULONG query(CK_SESSION_HANDLE s, CK_BYTE *in, CK_ULONG n) {
    CK_ULONG l = 0;
    return C_EncryptUpdate(s, in, n, NULL, &l) == CKR_OK ? l : (CK_ULONG)-1;
}

int main(void) {
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
    #define S(n) *(void**)&n = dlsym(h,#n); \
                 if (!n) { fprintf(stderr,"missing %s\n",#n); return 2; }
    S(C_Initialize) S(C_InitToken) S(C_OpenSession) S(C_Login) S(C_Logout) S(C_InitPIN)
    S(C_GenerateKey) S(C_EncryptInit) S(C_Encrypt) S(C_EncryptUpdate) S(C_EncryptFinal)

    printf("C_EncryptUpdate output length, AES-CBC-PAD\n\n");

    CK_BYTE so[] = "00000000", up[] = "user0000", lbl[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr,"C_Initialize\n"); return 2; }
    C_InitToken(0, so, 8, pad32(lbl, "encupdsize"));
    CK_SESSION_HANDLE s;
    if (C_OpenSession(0, 6, NULL, NULL, &s) != CKR_OK) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    C_Login(s, 0, so, 8); C_InitPIN(s, up, 8); C_Logout(s);
    if (C_Login(s, 1, up, 8) != CKR_OK) { fprintf(stderr,"C_Login\n"); return 2; }

    CK_ULONG klen = 16; CK_BYTE yes = 1;
    CK_ATTRIBUTE kt[] = { { CKA_VALUE_LEN, &klen, sizeof klen }, { CKA_ENCRYPT, &yes, 1 } };
    CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = 0;
    if (C_GenerateKey(s, &kg, kt, 2, &key) != CKR_OK) { fprintf(stderr,"C_GenerateKey\n"); return 2; }

    CK_BYTE iv[16] = { 0 };
    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof iv };
    CK_BYTE *pt = malloc(TOTAL), *one = malloc(TOTAL + 16), *multi = malloc(TOTAL + 16);
    if (!pt || !one || !multi) return 2;
    for (size_t i = 0; i < TOTAL; ++i) pt[i] = (CK_BYTE)(i * 131 + 7);

    /* (1) pkcs11-tool's loop: 1024 in, 1024 out. */
    CK_ULONG one_len = TOTAL + 16;
    if (C_EncryptInit(s, &m, key) != CKR_OK || C_Encrypt(s, pt, TOTAL, one, &one_len) != CKR_OK) {
        fprintf(stderr, "one-shot C_Encrypt\n"); return 2;
    }
    size_t off = 0, done = 0; int upd_ok = 1;
    if (C_EncryptInit(s, &m, key) != CKR_OK) { fprintf(stderr,"C_EncryptInit\n"); return 2; }
    while (off < TOTAL && upd_ok) {
        CK_ULONG n = TOTAL - off > 1024 ? 1024 : (CK_ULONG)(TOTAL - off);
        CK_BYTE out[1024]; CK_ULONG ol = sizeof out;
        upd_ok = C_EncryptUpdate(s, pt + off, n, out, &ol) == CKR_OK;
        if (upd_ok) { memcpy(multi + done, out, ol); done += ol; off += n; }
    }
    CK_BYTE fin[1024]; CK_ULONG fl = sizeof fin;
    int fin_ok = upd_ok && C_EncryptFinal(s, fin, &fl) == CKR_OK;
    if (fin_ok) { memcpy(multi + done, fin, fl); done += fl; }
    ok(upd_ok, "(1) 1024-byte parts into a 1024-byte buffer are accepted");
    ok(fin_ok && done == one_len && memcmp(multi, one, one_len) == 0,
       "(1) Update + Final equal the one-shot C_Encrypt");

    /* (2) the size query, with 7 bytes held back. */
    CK_BYTE out[2048]; CK_ULONG ol;
    if (C_EncryptInit(s, &m, key) != CKR_OK) { fprintf(stderr,"C_EncryptInit\n"); return 2; }
    CK_ULONG q0 = query(s, pt, 7);
    ol = sizeof out;
    int seven = C_EncryptUpdate(s, pt, 7, out, &ol) == CKR_OK && ol == 0;
    CK_ULONG q1 = query(s, pt + 7, 1024), q2 = query(s, pt + 7, 9);
    char what[96];
    snprintf(what, sizeof what, "(2) 7 bytes alone: 0 (asked %lu, wrote %lu)", q0, ol);
    ok(q0 == 0 && seven, what);
    snprintf(what, sizeof what, "(2) 7 held + 1024: 1024 (asked %lu)", q1);
    ok(q1 == 1024, what);
    snprintf(what, sizeof what, "(2) 7 held + 9: 16 (asked %lu)", q2);
    ok(q2 == 16, what);

    /* (3) one byte short of 1024: refused, length reported, guard intact. */
    struct { CK_BYTE data[1023]; CK_BYTE guard[32]; } probe;
    memset(probe.guard, 0x8D, sizeof probe.guard);
    ol = sizeof probe.data;
    CK_RV rv = C_EncryptUpdate(s, pt + 7, 1024, probe.data, &ol);
    int guard = 1;
    for (size_t i = 0; i < sizeof probe.guard; ++i) guard &= probe.guard[i] == 0x8D;
    snprintf(what, sizeof what, "(3) 1023 for 1024: CKR_BUFFER_TOO_SMALL, %lu reported", ol);
    ok(rv == CKR_BUFFER_TOO_SMALL && ol == 1024, what);
    ok(guard, "(3) the bytes after the buffer are untouched");

    free(pt); free(one); free(multi);
    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
