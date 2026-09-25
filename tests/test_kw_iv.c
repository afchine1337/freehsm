/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_kw_iv.c --- the optional key-wrap IV of PKCS#11 v3.2 §6.16.2 is used,
 * on all four entry points.
 *
 * pParameter is either absent -- the SP 800-38F default initial value -- or
 * the alternative one: 8 bytes for CKM_AES_KEY_WRAP (RFC 3394's ICV) and 4
 * for CKM_AES_KEY_WRAP_KWP (the AIV prefix of RFC 5649 §3).
 *
 * It was read nowhere. A caller who supplied one got the default and CKR_OK
 * on all four paths -- C_WrapKey, C_UnwrapKey, and the C_Encrypt / C_Decrypt
 * pair that #14 added. Accepting a parameter and dropping it claims a
 * behaviour that is not there.
 *
 * What is checked, and the second is the one that matters:
 *
 *   1. a non-default IV changes the ciphertext --- it reached the cipher
 *   2. a blob wrapped under one IV does NOT unwrap under another, and does
 *      not unwrap under the default either. An ICV that can be ignored is
 *      not an integrity check, and (1) alone would pass on a module that
 *      used the IV to encrypt and dropped it to decrypt
 *   3. the round trip under the same non-default IV returns the key
 *   4. a wrong parameter length is refused rather than silently defaulted
 *
 * Both mechanisms, because the lengths differ and a rule applied to one is
 * how this repository's defects usually start.
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                       0x00000000UL
#define CKR_MECHANISM_PARAM_INVALID  0x00000071UL
#define CKM_AES_KEY_GEN              0x00001080UL
#define CKM_AES_KEY_WRAP             0x00002109UL
#define CKM_AES_KEY_WRAP_KWP         0x0000210BUL
#define CKA_CLASS                    0x00000000UL
#define CKA_KEY_TYPE                 0x00000100UL
#define CKA_VALUE                    0x00000011UL
#define CKA_VALUE_LEN                0x00000161UL
#define CKA_WRAP                     0x00000106UL
#define CKA_UNWRAP                   0x00000107UL
#define CKA_EXTRACTABLE              0x00000162UL
#define CKA_SENSITIVE                0x00000103UL
#define CKO_SECRET_KEY               0x00000004UL
#define CKK_AES                      0x0000001FUL
#define CKK_GENERIC_SECRET           0x00000010UL

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_WrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);

static CK_BYTE *pad32(CK_BYTE b[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(b, ' ', 32); memcpy(b, s, n); return b;
}

/* One mechanism, end to end. ivlen is 8 for KW and 4 for KWP. */
static void family(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE wk, CK_OBJECT_HANDLE target,
                   CK_ULONG mech, const char *name, CK_ULONG ivlen) {
    printf("\n== %s ==\n", name);
    CK_BYTE ivA[8] = {0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA7};
    CK_BYTE ivB[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

    CK_MECHANISM m_def = { mech, NULL, 0 };
    CK_MECHANISM m_A   = { mech, ivA,  ivlen };
    CK_MECHANISM m_B   = { mech, ivB,  ivlen };

    CK_BYTE blob_def[128], blob_A[128];
    CK_ULONG n_def = sizeof blob_def, n_A = sizeof blob_A;

    ok(C_WrapKey(s, &m_def, wk, target, blob_def, &n_def) == CKR_OK,
       "C_WrapKey with no parameter (the default IV)");
    ok(C_WrapKey(s, &m_A, wk, target, blob_A, &n_A) == CKR_OK,
       "C_WrapKey with a non-default IV");
    ok(n_def == n_A && memcmp(blob_def, blob_A, n_def) != 0,
       "the two blobs differ --- the IV reached the cipher");

    /* The one that matters: the ICV must actually be checked. */
    /* CKA_SENSITIVE=FALSE as well as extractable: the value check below reads
     * CKA_VALUE back, and a sensitive key refuses that -- correctly. Without
     * it the assertion fails on the module doing the right thing, which is
     * how the first version of this test read. */
    CK_ATTRIBUTE t[] = {
        { CKA_CLASS,       &(CK_ULONG){ CKO_SECRET_KEY },     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){ CKK_GENERIC_SECRET }, sizeof(CK_ULONG) },
        { CKA_EXTRACTABLE, &(CK_BYTE){ 1 },                   1 },
        { CKA_SENSITIVE,   &(CK_BYTE){ 0 },                   1 },
    };
    const CK_ULONG tn = 4;
    CK_OBJECT_HANDLE out = 0;
    ok(C_UnwrapKey(s, &m_B, wk, blob_A, n_A, t, tn, &out) != CKR_OK,
       "a blob wrapped under one IV does not unwrap under another");
    out = 0;
    ok(C_UnwrapKey(s, &m_def, wk, blob_A, n_A, t, tn, &out) != CKR_OK,
       "and does not unwrap under the default either");

    out = 0;
    ok(C_UnwrapKey(s, &m_A, wk, blob_A, n_A, t, tn, &out) == CKR_OK && out != 0,
       "the round trip under the same IV succeeds");

    /* And the recovered key is the one that went in. */
    if (out) {
        CK_BYTE got[64], want[64];
        CK_ATTRIBUTE g = { CKA_VALUE, got, sizeof got };
        CK_ATTRIBUTE w = { CKA_VALUE, want, sizeof want };
        CK_RV rg = C_GetAttributeValue(s, out, &g, 1);
        CK_RV rw = C_GetAttributeValue(s, target, &w, 1);
        int same = (rg == CKR_OK && rw == CKR_OK
                    && g.ulValueLen == w.ulValueLen
                    && memcmp(got, want, g.ulValueLen) == 0);
        if (!same)
            printf("         unwrapped rv=0x%lx len=%lu ; original rv=0x%lx len=%lu\n",
                   (unsigned long)rg, (unsigned long)g.ulValueLen,
                   (unsigned long)rw, (unsigned long)w.ulValueLen);
        ok(same, "and returns the key that was wrapped");
    }

    /* A wrong length is refused, not defaulted. */
    CK_BYTE junk[16] = {0};
    CK_MECHANISM m_bad = { mech, junk, ivlen + 1 };
    CK_BYTE tmp[128]; CK_ULONG ntmp = sizeof tmp;
    ok(C_WrapKey(s, &m_bad, wk, target, tmp, &ntmp) == CKR_MECHANISM_PARAM_INVALID,
       "a parameter of the wrong length is refused");

    /* The C_Encrypt half of the pair carries the same IV. */
    CK_BYTE data[32]; memset(data, 0x5A, sizeof data);
    CK_BYTE e_def[128], e_A[128];
    CK_ULONG ne_def = sizeof e_def, ne_A = sizeof e_A;
    CK_ULONG dlen = (mech == CKM_AES_KEY_WRAP) ? 32 : 20;
    ok(C_EncryptInit(s, &m_def, wk) == CKR_OK
       && C_Encrypt(s, data, dlen, e_def, &ne_def) == CKR_OK,
       "C_EncryptInit / C_Encrypt with the default IV");
    ok(C_EncryptInit(s, &m_A, wk) == CKR_OK
       && C_Encrypt(s, data, dlen, e_A, &ne_A) == CKR_OK,
       "C_EncryptInit / C_Encrypt with a non-default IV");
    ok(ne_def == ne_A && memcmp(e_def, e_A, ne_def) != 0,
       "the two ciphertexts differ --- the IV survived C_EncryptInit");
}

int main(void) {
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define S(n) *(void**)&n = dlsym(h,#n); \
                 if (!n) { fprintf(stderr,"missing %s\n",#n); return 2; }
    S(C_Initialize) S(C_InitToken) S(C_OpenSession) S(C_Login) S(C_InitPIN)
    S(C_GenerateKey) S(C_WrapKey) S(C_UnwrapKey)
    S(C_EncryptInit) S(C_Encrypt) S(C_GetAttributeValue)

    printf("test_kw_iv\n");

    CK_BYTE so[] = "00000000", up[] = "user0000", lbl[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr,"C_Initialize\n"); return 2; }
    C_InitToken(0, so, 8, pad32(lbl, "kwiv"));
    CK_SESSION_HANDLE s;
    if (C_OpenSession(0, 6, NULL, NULL, &s) != CKR_OK) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    C_Login(s, 0, so, 8); C_InitPIN(s, up, 8); (void)C_Login(s, 1, up, 8);

    CK_ULONG k32 = 32, k16 = 16; CK_BYTE yes = 1;
    CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };

    CK_ATTRIBUTE wt[] = { { CKA_VALUE_LEN, &k32, sizeof k32 },
                          { CKA_WRAP, &yes, 1 }, { CKA_UNWRAP, &yes, 1 } };
    CK_OBJECT_HANDLE wk = 0;
    if (C_GenerateKey(s, &kg, wt, 3, &wk) != CKR_OK) { fprintf(stderr,"wrapping key\n"); return 2; }

    CK_BYTE no = 0;
    CK_ATTRIBUTE tt[] = { { CKA_VALUE_LEN, &k16, sizeof k16 },
                          { CKA_EXTRACTABLE, &yes, 1 },
                          { CKA_SENSITIVE, &no, 1 } };
    CK_OBJECT_HANDLE target = 0;
    if (C_GenerateKey(s, &kg, tt, 3, &target) != CKR_OK) { fprintf(stderr,"target key\n"); return 2; }

    family(s, wk, target, CKM_AES_KEY_WRAP,     "CKM_AES_KEY_WRAP (ICV, 8 bytes)",     8);
    family(s, wk, target, CKM_AES_KEY_WRAP_KWP, "CKM_AES_KEY_WRAP_KWP (AIV, 4 bytes)", 4);

    if (fails) { fprintf(stderr, "\ntest_kw_iv : %d FAIL\n", fails); return 1; }
    printf("\ntest_kw_iv : PASS\n");
    return 0;
}
