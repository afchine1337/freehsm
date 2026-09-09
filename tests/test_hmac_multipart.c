/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_hmac_multipart.c --- multipart verify must accept every HMAC the
 * module advertises, not only SHA-256.
 *
 * #125 generalised multipart HMAC: C_SignUpdate had hard-coded the digest
 * name "SHA256", so SHA-384, SHA-512 and the SHA-3 family produced a MAC that
 * did not match the one-shot path. The comment it left in place says so.
 *
 * C_VerifyUpdate and C_VerifyFinal, twenty lines below, kept the hard-coding:
 * "if (op->mechanism != CKM_SHA256_HMAC) return CKR_MECHANISM_INVALID", a
 * mac[32] and a literal FHSM_HASH_SHA256 in the empty-input branch. So the
 * module would sign a multipart HMAC-SHA-512 and then refuse to verify what
 * it had just produced. The fix had been applied to one of two neighbours,
 * which is the shape this project keeps finding.
 *
 * The harness does not catch it: pkcs11-check exercises multipart with
 * SHA-256, the one value the gate allowed through.
 *
 * What each mechanism is asserted on:
 *   (1) multipart sign == one-shot sign      -- the digest is really selected
 *   (2) multipart verify accepts that MAC    -- the defect fixed here
 *   (3) a flipped byte is refused            -- so (2) is not a blanket accept
 *   (4) a truncated MAC is refused           -- length is compared, not just
 *                                               the prefix
 *   (5) Final without Update == HMAC of ""   -- the empty-input branch, which
 *                                               had its own literal SHA-256
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                      0UL
#define CKR_SIGNATURE_INVALID       0xC0UL
#define CKR_SIGNATURE_LEN_RANGE     0xC1UL
#define CKF_RW                      6UL
#define CKA_CLASS                   0UL
#define CKA_KEY_TYPE                0x100UL
#define CKA_VALUE_LEN               0x161UL
#define CKA_SIGN                    0x108UL
#define CKA_VERIFY                  0x10AUL
#define CKO_SECRET_KEY              4UL
#define CKK_GENERIC_SECRET          0x10UL
#define CKM_GENERIC_SECRET_KEY_GEN  0x350UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-58s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

/* Every HMAC the module advertises for which a multipart path exists. The
 * two truncated SHA-512 variants are here because their MAC length (28, 32)
 * differs from their block digest, which a length check taken from the wrong
 * place would get wrong without failing on the others. */
static const struct { CK_ULONG ckm; const char *name; CK_ULONG maclen; } MECHS[] = {
    { 0x00000221UL, "SHA_1_HMAC",      20 },
    { 0x00000256UL, "SHA224_HMAC",     28 },
    { 0x00000251UL, "SHA256_HMAC",     32 },
    { 0x00000261UL, "SHA384_HMAC",     48 },
    { 0x00000271UL, "SHA512_HMAC",     64 },
    { 0x00000049UL, "SHA512_224_HMAC", 28 },
    { 0x0000004DUL, "SHA512_256_HMAC", 32 },
    { 0x000002B6UL, "SHA3_224_HMAC",   28 },
    { 0x000002B1UL, "SHA3_256_HMAC",   32 },
    { 0x000002C1UL, "SHA3_384_HMAC",   48 },
    { 0x000002D1UL, "SHA3_512_HMAC",   64 },
};
#define NMECH (sizeof MECHS / sizeof MECHS[0])

int main(void)
{
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_SignFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_GenerateKey);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    if (!C_VerifyUpdate || !C_VerifyFinal || !C_SignUpdate || !C_SignFinal) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("multipart HMAC: verify accepts what sign produces\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "hmacmp")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    /* CKA_SIGN / CKA_VERIFY are CK_BBOOL, one byte -- tests/test_unwrap_len.c
     * records what passing sizeof(CK_ULONG) costs. */
    CK_ULONG len32 = 32;
    CK_BYTE  t_true = 1;
    CK_ATTRIBUTE key_tmpl[] = {
        { CKA_CLASS,     &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,  &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_VALUE_LEN, &len32,                          sizeof(CK_ULONG) },
        { CKA_SIGN,      &t_true,                         1 },
        { CKA_VERIFY,    &t_true,                         1 },
    };
    CK_MECHANISM keygen = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = 0;
    if (C_GenerateKey(s, &keygen, key_tmpl, 5, &key) != CKR_OK) {
        fprintf(stderr, "C_GenerateKey (HMAC key)\n"); return 2;
    }

    CK_BYTE part1[] = "the quick brown fox ";
    CK_BYTE part2[] = "jumps over the lazy dog";
    CK_BYTE whole[64];
    CK_ULONG p1 = sizeof part1 - 1, p2 = sizeof part2 - 1;
    memcpy(whole, part1, p1); memcpy(whole + p1, part2, p2);
    CK_ULONG wlen = p1 + p2;

    for (size_t i = 0; i < NMECH; ++i) {
        CK_MECHANISM m = { MECHS[i].ckm, NULL, 0 };
        CK_BYTE mp[64], one[64], empty[64];
        CK_ULONG mplen = sizeof mp, onelen = sizeof one, emptylen = sizeof empty;
        CK_RV rv;
        char what[96];

        /* (1) multipart sign, then the same input in one shot. */
        if (C_SignInit(s, &m, key) != CKR_OK) {
            snprintf(what, sizeof what, "%s: C_SignInit", MECHS[i].name);
            ok(0, what); continue;
        }
        C_SignUpdate(s, part1, p1);
        C_SignUpdate(s, part2, p2);
        rv = C_SignFinal(s, mp, &mplen);
        snprintf(what, sizeof what, "%s: multipart sign, %lu bytes",
                 MECHS[i].name, MECHS[i].maclen);
        ok(rv == CKR_OK && mplen == MECHS[i].maclen, what);
        if (rv != CKR_OK) continue;

        if (C_SignInit(s, &m, key) != CKR_OK) continue;
        rv = C_Sign(s, whole, wlen, one, &onelen);
        snprintf(what, sizeof what, "%s: multipart == one-shot", MECHS[i].name);
        ok(rv == CKR_OK && onelen == mplen && memcmp(mp, one, mplen) == 0, what);

        /* (2) the defect: multipart verify of that MAC. */
        rv = C_VerifyInit(s, &m, key);
        if (rv == CKR_OK) {
            C_VerifyUpdate(s, part1, p1);
            C_VerifyUpdate(s, part2, p2);
            rv = C_VerifyFinal(s, mp, mplen);
        }
        snprintf(what, sizeof what, "%s: multipart verify accepts it", MECHS[i].name);
        ok(rv == CKR_OK, what);

        /* (3) and refuses a MAC that is wrong by one bit. */
        mp[0] ^= 0x01;
        rv = C_VerifyInit(s, &m, key);
        if (rv == CKR_OK) {
            C_VerifyUpdate(s, part1, p1);
            C_VerifyUpdate(s, part2, p2);
            rv = C_VerifyFinal(s, mp, mplen);
        }
        snprintf(what, sizeof what, "%s: flipped bit refused", MECHS[i].name);
        ok(rv == CKR_SIGNATURE_INVALID, what);
        mp[0] ^= 0x01;

        /* (4) and refuses a correct prefix presented short. */
        rv = C_VerifyInit(s, &m, key);
        if (rv == CKR_OK) {
            C_VerifyUpdate(s, part1, p1);
            C_VerifyUpdate(s, part2, p2);
            rv = C_VerifyFinal(s, mp, mplen - 1);
        }
        snprintf(what, sizeof what, "%s: truncated MAC refused", MECHS[i].name);
        ok(rv == CKR_SIGNATURE_INVALID || rv == CKR_SIGNATURE_LEN_RANGE, what);

        /* (5) Final with no Update is the HMAC of the empty string -- the
         *     branch that carried its own literal SHA-256. */
        if (C_SignInit(s, &m, key) != CKR_OK) continue;
        rv = C_Sign(s, (CK_BYTE*)"", 0, empty, &emptylen);
        if (rv == CKR_OK) {
            rv = C_VerifyInit(s, &m, key);
            if (rv == CKR_OK) rv = C_VerifyFinal(s, empty, emptylen);
        }
        snprintf(what, sizeof what, "%s: Final without Update == HMAC(\"\")",
                 MECHS[i].name);
        ok(rv == CKR_OK && emptylen == MECHS[i].maclen, what);
    }

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
