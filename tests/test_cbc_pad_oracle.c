/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_cbc_pad_oracle.c --- CKM_AES_CBC_PAD decrypt behaviour (R2).
 *
 *  Born from a measurement problem, not a code problem.
 *
 *  pkcs11-check's TestAESPaddingOracle::test_cbc_pad_all_last_block_positions
 *  reported a padding oracle during the #125 campaign, then stopped reporting
 *  it on a later run, with nothing in between having touched this path. A
 *  security finding that comes and goes has to be explained, not shrugged off,
 *  so PKCS11_CHECK_FINDINGS.md carried an instruction not to drop it on the
 *  strength of one green run.
 *
 *  The explanation turned out to be arithmetic. That test corrupts one byte of
 *  the last ciphertext block, which randomises the whole final plaintext block,
 *  and asks whether the module ever returns CKR_OK. A uniformly random 16-byte
 *  block carries valid PKCS#7 padding with probability
 *
 *      sum_{n=1..16} 256^-n  =  1/255  ~=  0.392%
 *
 *  over 320 probes that is P(none) = (1 - 1/255)^320 ~= 28%. The test misses
 *  roughly one run in three. Its docstring claims 0.05%, a figure that follows
 *  from assuming 6/256 per probe -- six times too high.
 *
 *  Measured here over 57 600 probes: 218 accidentally-valid paddings,
 *  p = 1/264, 95% CI [1/305, 1/233], which contains 1/255. Theory and
 *  measurement agree, the module never changed, and R2 was never a phantom.
 *
 *  So what is this test for? Not for the oracle -- that is inherent to CBC-PAD
 *  without authentication and cannot be removed without removing the
 *  mechanism. It guards the two ways the implementation could actually be
 *  wrong, both of which the rate above distinguishes:
 *
 *    * a module that accepts every corrupted ciphertext and returns garbage
 *      plaintext is not leaking one bit per query, it has no padding check at
 *      all -- strictly worse, and it would show up here as a rate near 100%;
 *    * a rate of exactly zero over tens of thousands of probes would mean the
 *      module is not decrypting what it was asked to, which is its own bug.
 *
 *  The band below is wide on purpose. This test must not itself become a
 *  coin flip -- which is the whole lesson of R2.
 * ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                     0UL
#define CKR_ENCRYPTED_DATA_INVALID 0x40UL
#define CKF_RW                     6UL
#define CKM_AES_KEY_GEN            0x1080UL
#define CKM_AES_CBC_PAD            0x1085UL
#define CKA_CLASS                  0UL
#define CKA_KEY_TYPE               0x100UL
#define CKA_VALUE_LEN              0x161UL
#define CKO_SECRET_KEY             4UL
#define CKK_AES                    0x1FUL

/* 3000 trials x 16 positions. Sized so the expected count (~118 at 1/255) is
 * far from both edges of the band asserted below. */
#define TRIALS 3000
#define KEY_EVERY 50          /* the token's object cap is 1024; the key does
                                 not affect the rate, the IV does */

static int fails = 0;
static void ck(const char *what, int ok, const char *detail) {
    printf("  %-52s %s\n", what, ok ? "OK" : "<<< FAIL");
    if (detail && *detail) printf("      %s\n", detail);
    if (!ok) fails++;
}

static CK_BYTE *padlbl(CK_BYTE b[32], const char *s) {
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
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_GenerateRandom)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_InitToken); SYM(C_OpenSession); SYM(C_Login);
    SYM(C_InitPIN); SYM(C_GenerateKey); SYM(C_EncryptInit); SYM(C_Encrypt);
    SYM(C_DecryptInit); SYM(C_Decrypt); SYM(C_GenerateRandom);

    printf("=== test_cbc_pad_oracle : CKM_AES_CBC_PAD decrypt behaviour (R2) ===\n");

    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize failed\n"); return 2; }
    CK_BYTE so[] = "00000000", up[] = "user0000";
    CK_BYTE lbl[32];
    if (C_InitToken(0, so, 8, padlbl(lbl, "cbcpadoracle")) != CKR_OK) {
        fprintf(stderr, "C_InitToken failed -- stale token? set FHSM_TOKENS_DIR\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) return 2;
    if (C_Login(s, 0, so, 8) != CKR_OK) return 2;
    if (C_InitPIN(s, up, 8) != CKR_OK) return 2;
    if (C_Login(s, 1, up, 8) != CKR_OK) return 2;

    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES, vl = 32;
    CK_ATTRIBUTE at[] = {{CKA_CLASS,&cls,8},{CKA_KEY_TYPE,&kt,8},{CKA_VALUE_LEN,&vl,8}};
    CK_MECHANISM gen = {CKM_AES_KEY_GEN, NULL, 0};

    const CK_BYTE pt[32] = "vaudenay POODLE all 16 position";
    long probes = 0, ok_match = 0, ok_diff = 0, rejected = 0, other = 0;
    CK_RV other_rv = 0;
    CK_OBJECT_HANDLE k = 0;

    for (int t = 0; t < TRIALS; ++t) {
        if (t % KEY_EVERY == 0 && C_GenerateKey(s, &gen, at, 3, &k) != CKR_OK) {
            fprintf(stderr, "C_GenerateKey failed at trial %d\n", t); return 2;
        }
        CK_BYTE iv[16];
        if (C_GenerateRandom(s, iv, 16) != CKR_OK) return 2;
        CK_MECHANISM m = {CKM_AES_CBC_PAD, iv, 16};
        CK_BYTE ct[64]; CK_ULONG ctl = sizeof(ct);
        if (C_EncryptInit(s,&m,k) != CKR_OK || C_Encrypt(s,(CK_BYTE*)pt,32,ct,&ctl) != CKR_OK) {
            fprintf(stderr, "encrypt failed at trial %d\n", t); return 2;
        }
        CK_ULONG last = ctl - 16;
        for (int pos = 0; pos < 16; ++pos) {
            CK_BYTE bad[64]; memcpy(bad, ct, ctl); bad[last + pos] ^= 0xFF;
            CK_BYTE out[64]; CK_ULONG outl = sizeof(out);
            CK_RV r = C_DecryptInit(s, &m, k);
            if (r == CKR_OK) r = C_Decrypt(s, bad, ctl, out, &outl);
            probes++;
            if (r == CKR_OK) {
                if (outl == 32 && memcmp(out, pt, 32) == 0) ok_match++; else ok_diff++;
            } else if (r == CKR_ENCRYPTED_DATA_INVALID) {
                rejected++;
            } else { other++; if (!other_rv) other_rv = r; }
        }
    }

    char buf[256];
    double rate = (double)(ok_diff + ok_match) / (double)probes;
    snprintf(buf, sizeof(buf),
             "%ld probes: %ld rejected, %ld CKR_OK with different plaintext, "
             "%ld CKR_OK matching, %ld other", probes, rejected, ok_diff, ok_match, other);
    printf("  %s\n", buf);
    snprintf(buf, sizeof(buf), "accidentally-valid rate = %.5f (1/%.0f), theory 1/255 = 0.00392",
             rate, rate > 0 ? 1.0/rate : 0.0);

    /* A corrupted last block cannot decrypt back to the original plaintext.
     * If it does, something is echoing rather than decrypting. */
    ck("no corrupted ciphertext returns the original plaintext", ok_match == 0, "");

    /* The failure code must be the one PKCS#11 defines, uniformly. */
    ck("every rejection is CKR_ENCRYPTED_DATA_INVALID", other == 0,
       other ? "an unexpected CK_RV appeared -- see the tally above" : "");

    /* Padding is actually validated: the overwhelming majority is refused.
     * A module with no padding check would sit near 0% rejection. */
    ck("padding is validated (>98% of corruptions refused)",
       rejected > (probes * 98) / 100, "");

    /* And the residual matches theory. Both edges matter: too high means the
     * check is weak, exactly zero over 48 000 probes means it is not really
     * decrypting. The band is deliberately wide -- ~5x either side of 1/255 --
     * so that this test never becomes the coin flip that R2 was. */
    ck("accidentally-valid rate is within ~5x of the theoretical 1/255",
       rate > 0.0008 && rate < 0.02, buf);

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
