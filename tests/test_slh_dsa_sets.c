/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_slh_dsa_sets.c --- every SLH-DSA parameter set, generated, signed and
 * verified through the module.
 *
 * The pair-wise consistency check after C_GenerateKeyPair signed into a
 * 16384-byte array, and eight of the twelve SLH-DSA sets sign larger. Their
 * key generation answered CKR_FUNCTION_FAILED and latched the module into
 * ERROR, so one request for an SLH-DSA-128f key made the token unusable for
 * the rest of the process. Nothing here had generated anything but the
 * default set; OpenSC pkcs11-tool asked for SHA2-128F and found it.
 *
 * What is asserted, for each CKP_SLH_DSA_* in PKCS#11 v3.2 order:
 *   (1) C_GenerateKeyPair succeeds with CKA_PARAMETER_SET
 *   (2) C_Sign gives a signature of FIPS 205's length for the set
 *   (3) C_Verify accepts it, and rejects it with one bit changed
 * and, after all twelve, (4) the module still generates a key, which it
 * would not in ERROR.
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

#define CKR_OK                   0UL
#define CKR_SIGNATURE_INVALID    0xC0UL
#define CKF_RW                   6UL
#define CKA_TOKEN                0x001UL
#define CKA_SIGN                 0x108UL
#define CKA_VERIFY               0x10AUL
#define CKA_PARAMETER_SET        0x61DUL
#define CKM_SLH_DSA_KEY_PAIR_GEN 0x2DUL
#define CKM_SLH_DSA              0x2EUL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

/* PKCS#11 v3.2 CKP_SLH_DSA_*, 1 to 12, and FIPS 205 Table 2's signature
   length for each. */
static const struct { const char *name; CK_ULONG sig_len; } SETS[] = {
    { "SHA2-128s",  7856 }, { "SHAKE-128s",  7856 },
    { "SHA2-128f", 17088 }, { "SHAKE-128f", 17088 },
    { "SHA2-192s", 16224 }, { "SHAKE-192s", 16224 },
    { "SHA2-192f", 35664 }, { "SHAKE-192f", 35664 },
    { "SHA2-256s", 29792 }, { "SHAKE-256s", 29792 },
    { "SHA2-256f", 49856 }, { "SHAKE-256f", 49856 },
};
#define NSETS (sizeof SETS / sizeof SETS[0])

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

static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);

static CK_RV keygen(CK_SESSION_HANDLE s, CK_ULONG set, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
{
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                          { CKA_PARAMETER_SET, &set, sizeof set } };
    CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
    CK_MECHANISM m = { CKM_SLH_DSA_KEY_PAIR_GEN, NULL, 0 };
    return C_GenerateKeyPair(s, &m, pt, 3, kt, 2, pub, priv);
}

int main(void)
{
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKeyPair);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_GenerateKeyPair || !C_SignInit || !C_Sign || !C_VerifyInit || !C_Verify) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("SLH-DSA: every parameter set, generated, signed and verified\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "slhdsa")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    CK_BYTE msg[] = "SLH-DSA through the module";
    CK_BYTE *sig = malloc(65536);
    if (!sig) return 2;
    char what[96];

    for (size_t i = 0; i < NSETS; i++) {
        CK_OBJECT_HANDLE pub = 0, priv = 0;
        CK_RV rv = keygen(s, (CK_ULONG)(i + 1), &pub, &priv);
        snprintf(what, sizeof what, "(1) %s: C_GenerateKeyPair (rv 0x%lx)", SETS[i].name, rv);
        ok(rv == CKR_OK, what);
        if (rv != CKR_OK) continue;

        CK_MECHANISM m = { CKM_SLH_DSA, NULL, 0 };
        CK_ULONG sl = 65536;
        rv = C_SignInit(s, &m, priv);
        if (rv == CKR_OK) rv = C_Sign(s, msg, sizeof msg - 1, sig, &sl);
        snprintf(what, sizeof what, "(2) %s: signature of %lu bytes (rv 0x%lx)",
                 SETS[i].name, SETS[i].sig_len, rv);
        ok(rv == CKR_OK && sl == SETS[i].sig_len, what);
        if (rv != CKR_OK) continue;

        rv = C_VerifyInit(s, &m, pub);
        if (rv == CKR_OK) rv = C_Verify(s, msg, sizeof msg - 1, sig, sl);
        snprintf(what, sizeof what, "(3) %s: verifies", SETS[i].name);
        ok(rv == CKR_OK, what);
        sig[sl / 2] ^= 0x01;
        rv = C_VerifyInit(s, &m, pub);
        if (rv == CKR_OK) rv = C_Verify(s, msg, sizeof msg - 1, sig, sl);
        snprintf(what, sizeof what, "(3) %s: one bit changed, rejected", SETS[i].name);
        ok(rv == CKR_SIGNATURE_INVALID, what);
    }

    CK_OBJECT_HANDLE pub = 0, priv = 0;
    ok(keygen(s, 1, &pub, &priv) == CKR_OK,
       "(4) after all twelve the module still generates (not in ERROR)");

    free(sig);
    (void)C_Finalize(NULL);
    printf("\n%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
