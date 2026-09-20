/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_oaep_decrypt_size.c --- C_Decrypt measures the caller's buffer
 * against the recovered plaintext, not against the key size.
 *
 * EVP_PKEY_decrypt with a NULL output buffer reports RSA_size(key), because
 * the real length is only known once OAEP padding has been removed. Both RSA
 * branches of C_Decrypt compared *pulDataLen against that maximum, so a
 * buffer that would have held the result was refused: 2048-bit key,
 * OAEP-SHA256, 29 bytes of plaintext, a 37-byte buffer told
 * CKR_BUFFER_TOO_SMALL with a required size of 256.
 *
 * PKCS#11 v3.2 §5.2 lets the size *query* over-report. It does not let the
 * call that carries a buffer refuse one that fits. pkcs11-check's
 * test_oaep_decrypt_correctness passes len(plaintext) + 8 and does not retry.
 *
 * Three things are checked, and the second is the regression:
 *   1. the NULL-buffer query answers at least the real length
 *   2. a buffer the size of the plaintext is accepted, and round-trips
 *   3. a buffer one byte short is refused AND reports the real length,
 *      so the retry allocates what is needed rather than the key size
 * ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG l; } CK_MECHANISM;

/* CK_RSA_PKCS_OAEP_PARAMS, PKCS#11 v3.2 §6.1.10. */
typedef struct {
    CK_ULONG hashAlg;
    CK_ULONG mgf;
    CK_ULONG source;
    void    *pSourceData;
    CK_ULONG ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

#define CKR_OK                  0x00000000UL
#define CKR_BUFFER_TOO_SMALL    0x00000150UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000UL
#define CKM_RSA_PKCS_OAEP       0x00000009UL
#define CKM_SHA256              0x00000250UL
#define CKG_MGF1_SHA256         0x00000002UL
#define CKA_MODULUS_BITS        0x00000121UL
#define CKA_ENCRYPT             0x00000104UL
#define CKA_DECRYPT             0x00000105UL

static int fails = 0;
static void ok(int cond, const char *what) {
    if (cond) printf("  [PASS] %s\n", what);
    else { printf("  [FAIL] %s\n", what); fails++; }
}

static CK_BYTE *pad32(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

int main(void) {
    void *H = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!H) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                               CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);

    #define S(n) *(void**)&n = dlsym(H, #n); if (!n) { fprintf(stderr, "missing %s\n", #n); return 2; }
    S(C_Initialize) S(C_InitToken) S(C_OpenSession) S(C_Login) S(C_InitPIN)
    S(C_GenerateKeyPair) S(C_EncryptInit) S(C_Encrypt) S(C_DecryptInit) S(C_Decrypt)

    printf("test_oaep_decrypt_size\n");

    CK_BYTE so[] = "00000000", up[] = "user0000", lbl[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    C_InitToken(0, so, 8, pad32(lbl, "oaepsize"));
    CK_SESSION_HANDLE s;
    if (C_OpenSession(0, 6, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    C_Login(s, 0, so, 8); C_InitPIN(s, up, 8); (void)C_Login(s, 1, up, 8);

    CK_ULONG bits = 2048; CK_BYTE yes = 1;
    CK_ATTRIBUTE pub_t[] = { { CKA_MODULUS_BITS, &bits, sizeof bits },
                             { CKA_ENCRYPT, &yes, 1 } };
    CK_ATTRIBUTE prv_t[] = { { CKA_DECRYPT, &yes, 1 } };
    CK_MECHANISM kg = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE pub = 0, prv = 0;
    CK_RV rv = C_GenerateKeyPair(s, &kg, pub_t, 2, prv_t, 1, &pub, &prv);
    if (rv != CKR_OK) { fprintf(stderr, "C_GenerateKeyPair: 0x%lx\n", rv); return 2; }

    CK_RSA_PKCS_OAEP_PARAMS op = { CKM_SHA256, CKG_MGF1_SHA256, 0, NULL, 0 };
    CK_MECHANISM oaep = { CKM_RSA_PKCS_OAEP, &op, sizeof op };

    /* The same 29-byte plaintext the harness uses, so the numbers in the
     * commentary above are the numbers this test exercises. */
    CK_BYTE pt[] = "OAEP parameter-fidelity probe";
    const CK_ULONG pt_len = (CK_ULONG)(sizeof pt - 1);

    CK_BYTE ct[512]; CK_ULONG ct_len = sizeof ct;
    if (C_EncryptInit(s, &oaep, pub) != CKR_OK) { fprintf(stderr, "C_EncryptInit\n"); return 2; }
    rv = C_Encrypt(s, pt, pt_len, ct, &ct_len);
    if (rv != CKR_OK) { fprintf(stderr, "C_Encrypt: 0x%lx\n", rv); return 2; }
    ok(ct_len == 256, "the ciphertext is one 2048-bit block");

    /* 1. Size query. Allowed to over-report; must not under-report. */
    CK_ULONG q = 0;
    if (C_DecryptInit(s, &oaep, prv) != CKR_OK) { fprintf(stderr, "C_DecryptInit\n"); return 2; }
    rv = C_Decrypt(s, ct, ct_len, NULL, &q);
    ok(rv == CKR_OK && q >= pt_len, "the NULL-buffer query answers at least the plaintext length");

    /* 2. The regression. A buffer the size of the plaintext must be accepted:
     *    it holds the result, whatever the key size is. */
    CK_BYTE out[512]; CK_ULONG out_len = pt_len;
    rv = C_Decrypt(s, ct, ct_len, out, &out_len);
    ok(rv == CKR_OK, "a buffer the size of the plaintext is accepted");
    ok(out_len == pt_len && memcmp(out, pt, pt_len) == 0, "and the plaintext round-trips");

    /* 3. A buffer one byte short is refused, and reports the length that
     *    would have worked -- not RSA_size, which would make the caller
     *    allocate 256 bytes for 29. The operation stays active, so the
     *    retry needs no second C_DecryptInit. */
    if (C_DecryptInit(s, &oaep, prv) != CKR_OK) { fprintf(stderr, "C_DecryptInit (short)\n"); return 2; }
    CK_ULONG short_len = pt_len - 1;
    rv = C_Decrypt(s, ct, ct_len, out, &short_len);
    ok(rv == CKR_BUFFER_TOO_SMALL, "a buffer one byte short is refused");
    ok(short_len == pt_len, "and the required size is the plaintext length, not the key size");

    CK_ULONG retry_len = short_len;
    rv = C_Decrypt(s, ct, ct_len, out, &retry_len);
    ok(rv == CKR_OK && retry_len == pt_len && memcmp(out, pt, pt_len) == 0,
       "the retry with the reported size succeeds");

    if (fails) { fprintf(stderr, "test_oaep_decrypt_size : %d FAIL\n", fails); return 1; }
    printf("test_oaep_decrypt_size : PASS\n");
    return 0;
}
