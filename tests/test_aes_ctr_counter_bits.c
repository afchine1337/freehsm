/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_aes_ctr_counter_bits.c --- AES-CTR stops at the end of its counter.
 *
 * CK_AES_CTR_PARAMS.ulCounterBits says how many low bits of the counter block
 * count. PKCS#11 v3.2 §6.11.3: data that would overflow them is
 * CKR_DATA_LEN_RANGE -- "if ulCounterBits = 2 and the counter bits start as 1
 * then only 3 blocks of data can be processed". The module checked the range
 * 1..128 and then dropped the value: OpenSSL increments all 128 bits, so the
 * counter carried into the nonce and the call answered CKR_OK.
 * Reported by AlexLaroche (#33, C13).
 *
 * What is asserted, AES-128-CTR:
 *   (1) ulCounterBits 2, counter 1: 48 bytes (3 blocks) are encrypted, 47
 *       too; 49 and 64 are CKR_DATA_LEN_RANGE
 *   (2) within the room the ciphertext is the 128-bit counter's: the limit
 *       refuses, it does not change the keystream
 *   (3) multipart: 32 then 16 are accepted, one more byte is refused; a size
 *       query does not count
 *   (4) C_Decrypt and C_DecryptUpdate follow the same limit
 *   (5) ulCounterBits 8 with the counter at 0xFF: one block, then refused;
 *       ulCounterBits 64 with the low 64 bits all ones: the same
 *   (6) a bare 16-byte counter block (all 128 bits) and ulCounterBits 128:
 *       4096 bytes go through
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG ulCounterBits; CK_BYTE cb[16]; } CK_AES_CTR_PARAMS;

#define CKR_OK                0x00000000UL
#define CKR_DATA_LEN_RANGE    0x00000021UL
#define CKM_AES_KEY_GEN       0x00001080UL
#define CKM_AES_CTR           0x00001086UL
#define CKA_VALUE_LEN         0x00000161UL
#define CKA_ENCRYPT           0x00000104UL
#define CKA_DECRYPT           0x00000105UL

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad32(CK_BYTE b[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(b, ' ', 32); memcpy(b, s, n); return b;
}

static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Decrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);

static CK_SESSION_HANDLE s;
static CK_OBJECT_HANDLE key;
static CK_BYTE pt[4096], ct[4096 + 16];

/* A counter block: nonce bytes 0xA0.., with `cnt` in the last 8 bytes. */
static void params(CK_AES_CTR_PARAMS *p, CK_ULONG bits, unsigned long long cnt) {
    p->ulCounterBits = bits;
    for (int i = 0; i < 8; i++) p->cb[i] = (CK_BYTE)(0xA0 + i);
    for (int i = 0; i < 8; i++) p->cb[15 - i] = (CK_BYTE)(cnt >> (8 * i));
}

/* C_Encrypt of `n` bytes under `p` (or a bare block when p->ulCounterBits is
 * 0); the answer, the output in ct. */
static CK_RV enc(CK_AES_CTR_PARAMS *p, CK_ULONG n) {
    CK_MECHANISM m = { CKM_AES_CTR, p, sizeof *p };
    if (p->ulCounterBits == 0) { m.pParameter = p->cb; m.ulParameterLen = 16; }
    if (C_EncryptInit(s, &m, key) != CKR_OK) return (CK_RV)-1;
    CK_ULONG l = sizeof ct;
    return C_Encrypt(s, pt, n, ct, &l);
}

static CK_RV dec(CK_AES_CTR_PARAMS *p, CK_ULONG n) {
    CK_MECHANISM m = { CKM_AES_CTR, p, sizeof *p };
    if (C_DecryptInit(s, &m, key) != CKR_OK) return (CK_RV)-1;
    CK_BYTE out[4096]; CK_ULONG l = sizeof out;
    return C_Decrypt(s, ct, n, out, &l);
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
    #define S(n) *(void**)&n = dlsym(h,#n); \
                 if (!n) { fprintf(stderr,"missing %s\n",#n); return 2; }
    S(C_Initialize) S(C_InitToken) S(C_OpenSession) S(C_Login) S(C_Logout) S(C_InitPIN)
    S(C_GenerateKey) S(C_EncryptInit) S(C_Encrypt) S(C_EncryptUpdate)
    S(C_DecryptInit) S(C_Decrypt) S(C_DecryptUpdate)

    printf("AES-CTR and ulCounterBits\n\n");

    CK_BYTE so[] = "00000000", up[] = "user0000", lbl[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr,"C_Initialize\n"); return 2; }
    C_InitToken(0, so, 8, pad32(lbl, "ctrbits"));
    if (C_OpenSession(0, 6, NULL, NULL, &s) != CKR_OK) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    C_Login(s, 0, so, 8); C_InitPIN(s, up, 8); C_Logout(s);
    if (C_Login(s, 1, up, 8) != CKR_OK) { fprintf(stderr,"C_Login\n"); return 2; }

    CK_ULONG klen = 16; CK_BYTE yes = 1;
    CK_ATTRIBUTE kt[] = { { CKA_VALUE_LEN, &klen, sizeof klen }, { CKA_ENCRYPT, &yes, 1 },
                          { CKA_DECRYPT, &yes, 1 } };
    CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };
    if (C_GenerateKey(s, &kg, kt, 3, &key) != CKR_OK) { fprintf(stderr,"C_GenerateKey\n"); return 2; }
    for (size_t i = 0; i < sizeof pt; ++i) pt[i] = (CK_BYTE)(i * 131 + 7);

    CK_AES_CTR_PARAMS p;
    char what[96];
    CK_RV rv;

    /* (1) 2 bits from 1: three blocks. */
    params(&p, 2, 1);
    ok(enc(&p, 48) == CKR_OK, "(1) 2 bits from 1: 48 bytes (3 blocks) are encrypted");
    CK_BYTE narrow[48]; memcpy(narrow, ct, 48);
    ok(enc(&p, 47) == CKR_OK, "(1) 47 bytes too");
    rv = enc(&p, 49);
    snprintf(what, sizeof what, "(1) 49 bytes: CKR_DATA_LEN_RANGE (got 0x%lx)", rv);
    ok(rv == CKR_DATA_LEN_RANGE, what);
    rv = enc(&p, 64);
    snprintf(what, sizeof what, "(1) 64 bytes, 4 blocks: CKR_DATA_LEN_RANGE (got 0x%lx)", rv);
    ok(rv == CKR_DATA_LEN_RANGE, what);

    /* (2) the same counter block under 128 bits gives the same 48 bytes. */
    params(&p, 128, 1);
    ok(enc(&p, 48) == CKR_OK && memcmp(ct, narrow, 48) == 0,
       "(2) within the room, the keystream is the 128-bit counter's");

    /* (3) multipart. */
    params(&p, 2, 1);
    {
        CK_MECHANISM m = { CKM_AES_CTR, &p, sizeof p };
        CK_BYTE out[64]; CK_ULONG l;
        int a = C_EncryptInit(s, &m, key) == CKR_OK;
        l = 0; int q = a && C_EncryptUpdate(s, pt, 64, NULL, &l) == CKR_OK;
        l = sizeof out; a = a && C_EncryptUpdate(s, pt, 32, out, &l) == CKR_OK;
        l = sizeof out; a = a && C_EncryptUpdate(s, pt + 32, 16, out, &l) == CKR_OK;
        ok(q && a, "(3) a 64-byte size query, then 32 + 16 bytes are accepted");
        l = sizeof out; rv = C_EncryptUpdate(s, pt + 48, 1, out, &l);
        snprintf(what, sizeof what, "(3) one byte more: CKR_DATA_LEN_RANGE (got 0x%lx)", rv);
        ok(rv == CKR_DATA_LEN_RANGE, what);
    }

    /* (4) decryption. */
    params(&p, 2, 1);
    ok(dec(&p, 48) == CKR_OK, "(4) C_Decrypt of 48 bytes is accepted");
    rv = dec(&p, 64);
    snprintf(what, sizeof what, "(4) C_Decrypt of 64: CKR_DATA_LEN_RANGE (got 0x%lx)", rv);
    ok(rv == CKR_DATA_LEN_RANGE, what);
    {
        CK_MECHANISM m = { CKM_AES_CTR, &p, sizeof p };
        CK_BYTE out[64]; CK_ULONG l = sizeof out;
        int a = C_DecryptInit(s, &m, key) == CKR_OK
             && C_DecryptUpdate(s, ct, 40, out, &l) == CKR_OK;
        l = sizeof out; rv = C_DecryptUpdate(s, ct, 9, out, &l);
        ok(a && rv == CKR_DATA_LEN_RANGE, "(4) C_DecryptUpdate: 40, then 9 more, refused");
    }

    /* (5) a counter at its last value. */
    params(&p, 8, 0xFF);
    ok(enc(&p, 16) == CKR_OK && enc(&p, 17) == CKR_DATA_LEN_RANGE,
       "(5) 8 bits at 0xFF: 16 bytes, not 17");
    params(&p, 64, 0xFFFFFFFFFFFFFFFFULL);
    ok(enc(&p, 16) == CKR_OK && enc(&p, 17) == CKR_DATA_LEN_RANGE,
       "(5) 64 bits all ones: 16 bytes, not 17");

    /* (6) the full width. */
    params(&p, 0, 1);
    ok(enc(&p, 4096) == CKR_OK, "(6) a bare 16-byte counter block: 4096 bytes");
    params(&p, 128, 0xFFFFFFFFFFFFFFFFULL);
    ok(enc(&p, 4096) == CKR_OK, "(6) 128 bits: 4096 bytes, across the low 64 bits");

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
