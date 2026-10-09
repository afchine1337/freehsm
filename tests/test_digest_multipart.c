/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_digest_multipart.c --- multipart digest for every digest C_DigestInit
 * accepts, and what an error in C_DigestUpdate leaves behind.
 *
 * C_DigestUpdate fetched its EVP digest through a private table that knew
 * SHA-256, SHA-384 and SHA-512. C_DigestInit accepts eleven, so for the other
 * eight the first Update answered CKR_MECHANISM_INVALID -- and, being an error
 * path that did not end the operation, left the digest active: the caller's
 * next C_DigestInit got CKR_OPERATION_ACTIVE. pkcs11-check 0.2.3 showed it as
 * eight TestMultipartDigest xfails that alternated with the refused digests,
 * which looked like session cross-talk in the harness.
 *
 * A third defect sat behind the second: an Update error after a successful
 * Update cleared op->active but kept the EVP context, so the next operation's
 * Update hashed into the previous one's state, under its algorithm.
 *
 * What is asserted:
 *   (1) for each digest the module accepts at C_DigestInit: Init, three
 *       Updates and Final give the same bytes as one-shot C_Digest
 *   (2) an Update error ends the operation: C_DigestFinal then answers
 *       CKR_OPERATION_NOT_INITIALIZED, and a new C_DigestInit is accepted
 *   (3) the new operation does not inherit the old one's state: after
 *       SHA-256 "abc" + a failed Update, SHA3-256 "xyz" multipart equals
 *       one-shot SHA3-256 "xyz"
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                        0UL
#define CKR_ARGUMENTS_BAD             0x07UL
#define CKR_MECHANISM_INVALID         0x70UL
#define CKR_OPERATION_NOT_INITIALIZED 0x91UL
#define CKF_SERIAL_SESSION            4UL
#define CKM_SHA256                    0x250UL
#define CKM_SHA3_256                  0x2B0UL

#define SO_PIN "sopin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

static const struct { CK_ULONG ckm; const char *name; } DIGESTS[] = {
    { 0x255UL, "SHA224" },     { 0x250UL, "SHA256" },
    { 0x260UL, "SHA384" },     { 0x270UL, "SHA512" },
    { 0x048UL, "SHA512_224" }, { 0x04CUL, "SHA512_256" },
    { 0x2B5UL, "SHA3_224" },   { 0x2B0UL, "SHA3_256" },
    { 0x2C0UL, "SHA3_384" },   { 0x2D0UL, "SHA3_512" },
    { 0x220UL, "SHA_1" },      { 0x210UL, "MD5" },
};
#define NDIG (sizeof DIGESTS / sizeof DIGESTS[0])

static CK_RV (*C_DigestInit)(CK_SESSION_HANDLE,CK_MECHANISM*);
static CK_RV (*C_Digest)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);

static CK_RV oneshot(CK_SESSION_HANDLE s, CK_ULONG ckm, const char *msg,
                     CK_BYTE *out, CK_ULONG *out_len) {
    CK_MECHANISM m = { ckm, NULL, 0 };
    CK_RV rv = C_DigestInit(s, &m);
    if (rv != CKR_OK) return rv;
    return C_Digest(s, (CK_BYTE*)msg, strlen(msg), out, out_len);
}

int main(void)
{
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_DigestInit); SYM(C_Digest); SYM(C_DigestUpdate); SYM(C_DigestFinal);
    if (!C_DigestInit || !C_Digest || !C_DigestUpdate || !C_DigestFinal) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("multipart digest: every accepted digest, and Update errors\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "digestmp")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &s) != CKR_OK) {
        fprintf(stderr, "C_OpenSession\n"); return 2;
    }

    const char *msg = "multipart digest test input data, ninety-six bytes long, give or take a few";
    size_t mlen = strlen(msg), third = mlen / 3;
    char what[96];
    int accepted = 0;

    for (size_t i = 0; i < NDIG; ++i) {
        CK_BYTE one[64], multi[64];
        CK_ULONG one_len = sizeof one, multi_len = sizeof multi;
        CK_RV rv = oneshot(s, DIGESTS[i].ckm, msg, one, &one_len);
        if (rv == CKR_MECHANISM_INVALID) {
            printf("  %-62s skipped\n", DIGESTS[i].name);
            continue;
        }
        accepted++;
        CK_MECHANISM m = { DIGESTS[i].ckm, NULL, 0 };
        CK_RV r1 = C_DigestInit(s, &m);
        CK_RV r2 = C_DigestUpdate(s, (CK_BYTE*)msg, third);
        CK_RV r3 = C_DigestUpdate(s, (CK_BYTE*)msg + third, third);
        CK_RV r4 = C_DigestUpdate(s, (CK_BYTE*)msg + 2 * third, mlen - 2 * third);
        CK_RV r5 = C_DigestFinal(s, multi, &multi_len);
        snprintf(what, sizeof what, "(1) %s: multipart == one-shot (rv %lx/%lx/%lx/%lx/%lx)",
                 DIGESTS[i].name, r1, r2, r3, r4, r5);
        ok(rv == CKR_OK && r1 == CKR_OK && r2 == CKR_OK && r3 == CKR_OK && r4 == CKR_OK
           && r5 == CKR_OK && multi_len == one_len && memcmp(one, multi, one_len) == 0, what);
        if (r5 != CKR_OK) {
            /* Leave the session clean for the next digest whatever happened. */
            CK_BYTE junk[64]; CK_ULONG jl = sizeof junk;
            (void)C_DigestFinal(s, junk, &jl);
        }
    }
    ok(accepted >= 10, "the ten approved SHA-2 and SHA-3 digests were all accepted");

    printf("\nan Update error ends the operation and its state\n");
    CK_MECHANISM m256 = { CKM_SHA256, NULL, 0 }, m3 = { CKM_SHA3_256, NULL, 0 };
    ok(C_DigestInit(s, &m256) == CKR_OK, "C_DigestInit SHA-256");
    ok(C_DigestUpdate(s, (CK_BYTE*)"abc", 3) == CKR_OK, "C_DigestUpdate \"abc\"");
    ok(C_DigestUpdate(s, NULL, 5) == CKR_ARGUMENTS_BAD, "C_DigestUpdate(NULL, 5) -> CKR_ARGUMENTS_BAD");
    {
        CK_BYTE d[64]; CK_ULONG dl = sizeof d;
        ok(C_DigestFinal(s, d, &dl) == CKR_OPERATION_NOT_INITIALIZED,
           "(2) C_DigestFinal afterwards finds no operation");
    }
    ok(C_DigestInit(s, &m3) == CKR_OK, "(2) a new C_DigestInit is accepted");
    {
        CK_BYTE multi[64], one[64]; CK_ULONG ml = sizeof multi, ol = sizeof one;
        CK_RV ru = C_DigestUpdate(s, (CK_BYTE*)"xyz", 3);
        CK_RV rf = C_DigestFinal(s, multi, &ml);
        CK_RV ro = oneshot(s, CKM_SHA3_256, "xyz", one, &ol);
        ok(ru == CKR_OK && rf == CKR_OK && ro == CKR_OK && ml == ol && memcmp(multi, one, ol) == 0,
           "(3) SHA3-256 \"xyz\" carries nothing of the failed SHA-256");
    }

    C_Finalize(NULL);
    printf("\n%s (%d failure%s)\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
