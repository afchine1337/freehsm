/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_cbc_pad_update_size.c --- C_DecryptUpdate reports a length the caller
 * can retry with, and does not consume the input when it refuses.
 *
 * The undersized-buffer guard was right and the number it used was not.
 * ulEncLen + one block is C_EncryptUpdate's bound, where it is real: a block
 * cipher fed 64 bytes with 12 already buffered emits 64 + 16. Decryption
 * cannot do that -- each ciphertext block yields one plaintext block and
 * padding only removes bytes -- but the encrypt bound had been copied to the
 * decrypt side.
 *
 * The cost was a refusal, not an overrun. pkcs11-check decrypts 64 bytes of
 * AES-CBC-PAD into a one-byte buffer and is told to retry with 80, which is
 * larger than the ciphertext; its check requires the reported size to be
 * usable, so it never retried and the module looked unable to recover.
 *
 * Four things are checked:
 *   1. the guard bytes past the declared length are untouched
 *   2. the reported length is usable --- greater than what was offered and
 *      no greater than the ciphertext
 *   3. the retry with that length succeeds, and C_DecryptFinal after it
 *      returns the original plaintext: the refusal must not have consumed
 *      the ciphertext, or those bytes would be decrypted twice
 *   4. a caller who offers a generous buffer is not made to pay for any of
 *      this, and still gets its plaintext in one call
 * ========================================================================= */
#include <stdio.h>
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
#define CKA_DECRYPT           0x00000105UL

#define GUARD_BYTE 0x8D
#define GUARD_SIZE 32

static int fails = 0;
static void ok(int cond, const char *what) {
    if (cond) printf("  [PASS] %s\n", what);
    else { printf("  [FAIL] %s\n", what); fails++; }
}

static CK_BYTE *pad32(CK_BYTE b[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(b, ' ', 32); memcpy(b, s, n); return b;
}

int main(void) {
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
    #define S(n) *(void**)&n = dlsym(h,#n); \
                 if (!n) { fprintf(stderr,"missing %s\n",#n); return 2; }
    S(C_Initialize) S(C_InitToken) S(C_OpenSession) S(C_Login) S(C_InitPIN)
    S(C_GenerateKey) S(C_EncryptInit) S(C_Encrypt)
    S(C_DecryptInit) S(C_DecryptUpdate) S(C_DecryptFinal)

    printf("test_cbc_pad_update_size\n");

    CK_BYTE so[] = "00000000", up[] = "user0000", lbl[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr,"C_Initialize\n"); return 2; }
    C_InitToken(0, so, 8, pad32(lbl, "cbcpadsize"));
    CK_SESSION_HANDLE s;
    if (C_OpenSession(0, 6, NULL, NULL, &s) != CKR_OK) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    C_Login(s, 0, so, 8); C_InitPIN(s, up, 8); (void)C_Login(s, 1, up, 8);

    CK_ULONG klen = 16; CK_BYTE yes = 1;
    CK_ATTRIBUTE kt[] = { { CKA_VALUE_LEN, &klen, sizeof klen },
                          { CKA_ENCRYPT, &yes, 1 },
                          { CKA_DECRYPT, &yes, 1 } };
    CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = 0;
    if (C_GenerateKey(s, &kg, kt, 3, &key) != CKR_OK) { fprintf(stderr,"C_GenerateKey\n"); return 2; }

    /* 48 bytes of plaintext: three blocks, so CBC-PAD adds a fourth and the
     * ciphertext is 64. The padding block is what a padded decrypt holds
     * back, which is what makes the produced length differ from both the
     * input length and the encrypt-side bound. */
    CK_BYTE iv[16]; for (int i = 0; i < 16; ++i) iv[i] = (CK_BYTE)i;
    CK_BYTE pt[48]; memset(pt, 'B', sizeof pt);
    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof iv };

    CK_BYTE ct[96]; CK_ULONG ct_len = sizeof ct;
    if (C_EncryptInit(s, &m, key) != CKR_OK) { fprintf(stderr,"C_EncryptInit\n"); return 2; }
    if (C_Encrypt(s, pt, sizeof pt, ct, &ct_len) != CKR_OK) { fprintf(stderr,"C_Encrypt\n"); return 2; }
    ok(ct_len == 64, "48 bytes of plaintext encrypt to 64 with CBC padding");

    /* --- the refusal, and what it reports ---------------------------- */
    struct { CK_BYTE data[1]; CK_BYTE guard[GUARD_SIZE]; } probe;
    memset(probe.data, 0, sizeof probe.data);
    memset(probe.guard, GUARD_BYTE, sizeof probe.guard);

    if (C_DecryptInit(s, &m, key) != CKR_OK) { fprintf(stderr,"C_DecryptInit\n"); return 2; }
    CK_ULONG one = 1;
    CK_RV rv = C_DecryptUpdate(s, ct, ct_len, probe.data, &one);
    ok(rv == CKR_BUFFER_TOO_SMALL, "a one-byte buffer is refused");

    int intact = 1;
    for (int i = 0; i < GUARD_SIZE; ++i) if (probe.guard[i] != GUARD_BYTE) intact = 0;
    ok(intact, "and nothing was written past the declared length");

    if (one <= 1 || one > ct_len)
        printf("         (reported %lu, ciphertext is %lu)\n",
               (unsigned long)one, (unsigned long)ct_len);
    ok(one > 1 && one <= ct_len,
       "the reported length is usable: more than offered, no more than the ciphertext");

    /* --- the retry, which proves the refusal consumed nothing --------- */
    CK_BYTE part[96]; CK_ULONG part_len = one;
    rv = C_DecryptUpdate(s, ct, ct_len, part, &part_len);
    ok(rv == CKR_OK, "the retry with the reported length succeeds");

    CK_BYTE last[96]; CK_ULONG last_len = sizeof last;
    rv = C_DecryptFinal(s, last, &last_len);
    ok(rv == CKR_OK, "C_DecryptFinal completes");

    CK_BYTE got[192];
    memcpy(got, part, part_len);
    memcpy(got + part_len, last, last_len);
    ok(part_len + last_len == sizeof pt && memcmp(got, pt, sizeof pt) == 0,
       "and the plaintext comes back whole --- the refusal consumed nothing");

    /* --- the ordinary caller, unaffected ----------------------------- */
    if (C_DecryptInit(s, &m, key) != CKR_OK) { fprintf(stderr,"C_DecryptInit (roomy)\n"); return 2; }
    CK_BYTE roomy[192]; CK_ULONG roomy_len = sizeof roomy;
    rv = C_DecryptUpdate(s, ct, ct_len, roomy, &roomy_len);
    ok(rv == CKR_OK, "a generous buffer is accepted without a size dance");
    CK_ULONG roomy_last = sizeof last;
    rv = C_DecryptFinal(s, last, &roomy_last);
    memcpy(got, roomy, roomy_len);
    memcpy(got + roomy_len, last, roomy_last);
    ok(rv == CKR_OK && roomy_len + roomy_last == sizeof pt
       && memcmp(got, pt, sizeof pt) == 0,
       "and returns the same plaintext");

    /* --- C_DecryptFinal, which had no size check at all -------------- */

    /* 31 bytes of plaintext: the padded block is 15 bytes of padding, so
     * Final has 15 bytes left to emit after an Update that took 16. That is
     * the largest a padded Final can produce, and it was being written into
     * whatever the caller declared.
     *
     * This call was unreachable from the harness until the C_DecryptUpdate
     * bound above was fixed: the probe's Update offered 31 bytes for 32 of
     * ciphertext, the old bound demanded 48, and the probe gave up at setup.
     * One defect shadowing another. */
    {
        CK_BYTE pt31[31]; memset(pt31, 'A', sizeof pt31);
        CK_BYTE ct31[64]; CK_ULONG ct31_len = sizeof ct31;
        if (C_EncryptInit(s, &m, key) != CKR_OK) { fprintf(stderr,"C_EncryptInit (31)\n"); return 2; }
        if (C_Encrypt(s, pt31, sizeof pt31, ct31, &ct31_len) != CKR_OK) {
            fprintf(stderr,"C_Encrypt (31)\n"); return 2;
        }
        ok(ct31_len == 32, "31 bytes of plaintext encrypt to 32");

        if (C_DecryptInit(s, &m, key) != CKR_OK) { fprintf(stderr,"C_DecryptInit (31)\n"); return 2; }
        CK_BYTE u[31]; CK_ULONG u_len = sizeof u;
        ok(C_DecryptUpdate(s, ct31, ct31_len, u, &u_len) == CKR_OK,
           "C_DecryptUpdate accepts a buffer the size of the plaintext");

        struct { CK_BYTE data[1]; CK_BYTE guard[GUARD_SIZE]; } fp;
        memset(fp.data, 0, sizeof fp.data);
        memset(fp.guard, GUARD_BYTE, sizeof fp.guard);
        CK_ULONG f_one = 1;
        CK_RV frv = C_DecryptFinal(s, fp.data, &f_one);
        ok(frv == CKR_BUFFER_TOO_SMALL, "C_DecryptFinal refuses a one-byte buffer");

        int fintact = 1;
        for (int i = 0; i < GUARD_SIZE; ++i) if (fp.guard[i] != GUARD_BYTE) fintact = 0;
        ok(fintact, "and writes nothing past the declared length");

        CK_BYTE fr[64]; CK_ULONG fr_len = sizeof fr;
        ok(C_DecryptFinal(s, fr, &fr_len) == CKR_OK,
           "the retry succeeds --- the held-back block survived the refusal");

        CK_BYTE all[64];
        memcpy(all, u, u_len);
        memcpy(all + u_len, fr, fr_len);
        ok(u_len + fr_len == sizeof pt31 && memcmp(all, pt31, sizeof pt31) == 0,
           "and the 31 bytes come back");
    }

    /* --- the size query may over-report, but not under-report -------- */
    if (C_DecryptInit(s, &m, key) != CKR_OK) { fprintf(stderr,"C_DecryptInit (query)\n"); return 2; }
    CK_ULONG q = 0;
    rv = C_DecryptUpdate(s, ct, ct_len, NULL, &q);
    ok(rv == CKR_OK && q >= one,
       "the size query answers at least what the refusal reported");

    if (fails) { fprintf(stderr, "\ntest_cbc_pad_update_size : %d FAIL\n", fails); return 1; }
    printf("test_cbc_pad_update_size : PASS\n");
    return 0;
}
