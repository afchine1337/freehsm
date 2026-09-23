/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_sign_multipart.c --- C_SignUpdate / C_SignFinal for the asymmetric
 * mechanisms.
 *
 * C_SignInit accepts every signature mechanism, because C_Sign needs it to.
 * C_SignUpdate and C_SignFinal implemented HMAC and the composite mechanism
 * only, so CKM_SHA256_RSA_PKCS was accepted at Init and refused at Final
 * with CKR_MECHANISM_INVALID: advertised, not operational. pkcs11-check
 * test_sign_final_buffer_too_small_then_correct never reached the buffer
 * question it was asking.
 *
 * The parts are now accumulated and signed at Final by the same
 * sign_asymmetric() the one-shot path uses. Four things have to hold, and
 * the third is the one that nearly went wrong:
 *
 *   1. the multipart signature verifies against the concatenated message
 *   2. the size query answers without signing, and the operation survives it
 *   3. a buffer sized to the EXACT signature length is accepted --- for
 *      ECDSA the module produces a DER ECDSA-Sig-Value and converts it to
 *      the raw r||s PKCS#11 mandates, and DER is the longer of the two, so
 *      signing into a caller buffer sized for r||s would write past its end.
 *      P-256 is 64 bytes raw against roughly 72 DER: the overflow is eight
 *      bytes and no smaller buffer is legal, so this is the only size that
 *      catches it.
 *   4. a too-small buffer is refused with the real length and the retry
 *      succeeds --- which requires the accumulated message to survive the
 *      refusal, since the caller will not send it again
 *
 * Plus the ceiling: buffering trades away the property multipart exists for,
 * so the module says by how much rather than growing until the allocator
 * refuses.
 * ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG l; } CK_MECHANISM;

#define CKR_OK                    0x00000000UL
#define CKR_BUFFER_TOO_SMALL      0x00000150UL
/* 0x21. 0x20 is CKR_DATA_INVALID, which is what this said first --- so the
 * ceiling check failed against a module that was answering correctly. */
#define CKR_DATA_LEN_RANGE        0x00000021UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000UL
#define CKM_SHA256_RSA_PKCS       0x00000040UL
#define CKM_ECDSA_KEY_PAIR_GEN    0x00001040UL
#define CKM_ECDSA_SHA256          0x00001044UL
#define CKA_MODULUS_BITS          0x00000121UL
#define CKA_EC_PARAMS             0x00000180UL
#define CKA_SIGN                  0x00000108UL
#define CKA_VERIFY                0x0000010AUL

/* The 16 MiB ceiling in src/fhsm_pkcs11.c. Restated rather than shared: this
 * file dlopen()s the module and must not include its headers, so that a
 * change to the limit shows up here as a failure rather than being agreed to
 * in silence. */
#define MULTIPART_MAX  (16u * 1024u * 1024u)

static int fails = 0;
static void ok(int cond, const char *what) {
    if (cond) printf("  [PASS] %s\n", what);
    else { printf("  [FAIL] %s\n", what); fails++; }
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);

static CK_BYTE *pad32(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

/* The message, in three parts, and the same bytes concatenated. */
static const char *PART[3] = { "multipart ", "signature ", "message" };
static CK_BYTE WHOLE[] = "multipart signature message";
#define WHOLE_LEN ((CK_ULONG)(sizeof WHOLE - 1))

static int feed(CK_SESSION_HANDLE s) {
    for (int i = 0; i < 3; ++i)
        if (C_SignUpdate(s, (CK_BYTE *)PART[i], (CK_ULONG)strlen(PART[i])) != CKR_OK)
            return 0;
    return 1;
}

/* One mechanism family, end to end. */
static void family(const char *label, CK_SESSION_HANDLE s,
                   CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE prv, CK_ULONG mech) {
    printf("\n== %s ==\n", label);
    CK_MECHANISM m = { mech, NULL, 0 };

    /* 2. Size query: no signature produced, operation survives it. */
    CK_ULONG need = 0;
    ok(C_SignInit(s, &m, prv) == CKR_OK, "C_SignInit");
    if (!feed(s)) { ok(0, "C_SignUpdate x3"); return; }
    ok(C_SignFinal(s, NULL, &need) == CKR_OK && need > 0,
       "the size query answers without signing");

    /* 3. A buffer of EXACTLY that size is accepted. For ECDSA this is the
     *    only buffer length that can catch a module signing DER into a
     *    caller buffer sized for raw r||s. */
    CK_BYTE *sig = malloc(need);
    if (!sig) { ok(0, "malloc"); return; }
    CK_ULONG sig_len = need;
    CK_RV rv = C_SignFinal(s, sig, &sig_len);
    ok(rv == CKR_OK, "a buffer of exactly the reported size is accepted");
    ok(sig_len == need, "and the signature is the length that was reported");

    /* 1. It verifies against the concatenation. Not a comparison with a
     *    one-shot signature: ECDSA is randomised, so equal bytes are not the
     *    property --- validity is. */
    ok(C_VerifyInit(s, &m, pub) == CKR_OK, "C_VerifyInit");
    ok(C_Verify(s, WHOLE, WHOLE_LEN, sig, sig_len) == CKR_OK,
       "the multipart signature verifies over the concatenated message");

    /* And it is a signature over THOSE bytes, not over something else that
     * happens to verify. One flipped message byte must break it. */
    CK_BYTE tampered[sizeof WHOLE];
    memcpy(tampered, WHOLE, sizeof WHOLE);
    tampered[0] ^= 1;
    ok(C_VerifyInit(s, &m, pub) == CKR_OK, "C_VerifyInit (tampered)");
    ok(C_Verify(s, tampered, WHOLE_LEN, sig, sig_len) != CKR_OK,
       "a flipped message byte breaks it");

    /* 4. Too small, then the retry. The module must report the real length
     *    and keep the accumulated message: the caller will not resend it. */
    ok(C_SignInit(s, &m, prv) == CKR_OK, "C_SignInit (retry case)");
    if (!feed(s)) { ok(0, "C_SignUpdate x3 (retry case)"); free(sig); return; }
    CK_BYTE small[16];
    CK_ULONG small_len = sizeof small;
    rv = C_SignFinal(s, small, &small_len);
    ok(rv == CKR_BUFFER_TOO_SMALL, "a 16-byte buffer is refused");
    ok(small_len == need, "and the required length is the real one");

    CK_ULONG retry_len = small_len;
    CK_BYTE *sig2 = malloc(retry_len);
    if (!sig2) { ok(0, "malloc (retry)"); free(sig); return; }
    rv = C_SignFinal(s, sig2, &retry_len);
    ok(rv == CKR_OK, "the retry succeeds --- the message survived the refusal");
    ok(C_VerifyInit(s, &m, pub) == CKR_OK, "C_VerifyInit (retry)");
    ok(C_Verify(s, WHOLE, WHOLE_LEN, sig2, retry_len) == CKR_OK,
       "and signs the same message, not an empty one");

    free(sig); free(sig2);
}

int main(void) {
    void *H = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!H) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define S(n) *(void**)&n = dlsym(H, #n); \
                 if (!n) { fprintf(stderr, "missing %s\n", #n); return 2; }
    S(C_Initialize) S(C_InitToken) S(C_OpenSession) S(C_Login) S(C_InitPIN)
    S(C_GenerateKeyPair) S(C_SignInit) S(C_SignUpdate) S(C_SignFinal)
    S(C_VerifyInit) S(C_Verify)

    printf("test_sign_multipart\n");

    CK_BYTE so[] = "00000000", up[] = "user0000", lbl[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    C_InitToken(0, so, 8, pad32(lbl, "signmulti"));
    CK_SESSION_HANDLE s;
    if (C_OpenSession(0, 6, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    C_Login(s, 0, so, 8); C_InitPIN(s, up, 8); (void)C_Login(s, 1, up, 8);

    CK_BYTE yes = 1;

    /* RSA-2048. The family pkcs11-check exercises. */
    {
        CK_ULONG bits = 2048;
        CK_ATTRIBUTE pt[] = { { CKA_MODULUS_BITS, &bits, sizeof bits },
                              { CKA_VERIFY, &yes, 1 } };
        CK_ATTRIBUTE st[] = { { CKA_SIGN, &yes, 1 } };
        CK_MECHANISM kg = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE pub = 0, prv = 0;
        if (C_GenerateKeyPair(s, &kg, pt, 2, st, 1, &pub, &prv) != CKR_OK) {
            fprintf(stderr, "C_GenerateKeyPair (RSA)\n"); return 2;
        }
        family("RSA-2048 + SHA-256", s, pub, prv, CKM_SHA256_RSA_PKCS);

        /* The ceiling. Seventeen 1 MiB parts against a 16 MiB limit: the
         * refusal must come from the running total, not from any single
         * part, so no part here is itself oversized. */
        printf("\n== the buffered-multipart ceiling ==\n");
        CK_BYTE *chunk = calloc(1, 1024 * 1024);
        if (!chunk) { ok(0, "calloc"); return 1; }
        ok(C_SignInit(s, &(CK_MECHANISM){ CKM_SHA256_RSA_PKCS, NULL, 0 }, prv) == CKR_OK,
           "C_SignInit (ceiling)");
        CK_RV last = CKR_OK;
        unsigned fed = 0;
        for (unsigned i = 0; i < (MULTIPART_MAX / (1024 * 1024)) + 1; ++i) {
            last = C_SignUpdate(s, chunk, 1024 * 1024);
            if (last != CKR_OK) break;
            fed++;
        }
        free(chunk);
        if (last != CKR_DATA_LEN_RANGE)
            printf("         (got 0x%lx after %u MiB, wanted 0x%lx)\n",
                   (unsigned long)last, fed, (unsigned long)CKR_DATA_LEN_RANGE);
        ok(last == CKR_DATA_LEN_RANGE, "past the ceiling, CKR_DATA_LEN_RANGE");
        ok(fed == MULTIPART_MAX / (1024 * 1024),
           "and everything up to the ceiling was accepted");
    }

    /* ECDSA P-256. The family where the signature is converted from DER to
     * raw r||s in place, so an exact-size caller buffer is the one that
     * would have been overflowed. */
    {
        /* prime256v1, as an ASN.1 OBJECT IDENTIFIER --- what CKA_EC_PARAMS
         * carries (PKCS#11 v3.2 §6.3.3). */
        CK_BYTE p256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
        CK_ATTRIBUTE pt[] = { { CKA_EC_PARAMS, p256, sizeof p256 },
                              { CKA_VERIFY, &yes, 1 } };
        CK_ATTRIBUTE st[] = { { CKA_SIGN, &yes, 1 } };
        CK_MECHANISM kg = { CKM_ECDSA_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE pub = 0, prv = 0;
        CK_RV g = C_GenerateKeyPair(s, &kg, pt, 2, st, 1, &pub, &prv);
        if (g != CKR_OK) {
            printf("\n  [FAIL] C_GenerateKeyPair (EC P-256) -> 0x%lx\n", (unsigned long)g);
            fails++;
        } else {
            family("ECDSA P-256 + SHA-256", s, pub, prv, CKM_ECDSA_SHA256);
        }
    }

    if (fails) { fprintf(stderr, "\ntest_sign_multipart : %d FAIL\n", fails); return 1; }
    printf("\ntest_sign_multipart : PASS\n");
    return 0;
}
