/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_pqc_params.c --- CKA_PARAMETER_SET reads back, and a decapsulation
 * ciphertext of the wrong size is refused as such.
 *
 * Both found by running OpenSC pkcs11-tool's --encapsulate / --decapsulate
 * against the module. pkcs11-tool reads CKA_PARAMETER_SET to name a PQC key;
 * the module accepted it at generation and answered
 * CKR_ATTRIBUTE_TYPE_INVALID afterwards, so `--read-object` gave up on every
 * ML-KEM public key. A truncated ciphertext reached OpenSSL and came back
 * CKR_FUNCTION_FAILED.
 *
 * What is asserted:
 *   (1) ML-KEM-512/768/1024, ML-DSA-44/65/87 and SLH-DSA-SHA2-128f: both
 *       halves read back the CKA_PARAMETER_SET selector they were made with
 *   (2) an EC key has no CKA_PARAMETER_SET: CKR_OK, ulValueLen = -1
 *   (3) ML-KEM-512/768/1024: a ciphertext one byte short or one byte long is
 *       refused with CKR_ENCRYPTED_DATA_LEN_RANGE, and the right one still
 *       decapsulates
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                        0UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE  0x41UL
#define CKF_RW                        6UL
#define CKA_TOKEN                     0x1UL
#define CKA_SIGN                      0x108UL
#define CKA_VERIFY                    0x10AUL
#define CKA_EC_PARAMS                 0x180UL
#define CKA_PARAMETER_SET             0x61DUL
#define CKA_ENCAPSULATE               0x633UL
#define CKA_DECAPSULATE               0x634UL
#define CKM_EC_KEY_PAIR_GEN           0x1040UL
#define CKM_ML_KEM_KEY_PAIR_GEN       0x0FUL
#define CKM_ML_KEM                    0x17UL
#define CKM_ML_DSA_KEY_PAIR_GEN       0x1CUL
#define CKM_SLH_DSA_KEY_PAIR_GEN      0x2DUL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

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
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_EncapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                                 CK_ATTRIBUTE*,CK_ULONG,CK_BYTE*,CK_ULONG*,CK_OBJECT_HANDLE*);
static CK_RV (*C_DecapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                                 CK_ATTRIBUTE*,CK_ULONG,CK_BYTE*,CK_ULONG,CK_OBJECT_HANDLE*);

/* Generate with CKA_PARAMETER_SET = sel; `use` is the usage attribute pair. */
static CK_RV keygen(CK_SESSION_HANDLE s, CK_ULONG mech, CK_ULONG sel,
                    CK_ULONG pub_use, CK_ULONG priv_use,
                    CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
{
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { pub_use, &yes, 1 },
                          { CKA_PARAMETER_SET, &sel, sizeof sel } };
    CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { priv_use, &yes, 1 } };
    CK_MECHANISM m = { mech, NULL, 0 };
    return C_GenerateKeyPair(s, &m, pt, 3, kt, 2, pub, priv);
}

/* The CKA_PARAMETER_SET an object reports; -2 if the call failed, -1 absent. */
static long pset_of(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o)
{
    CK_ULONG v = 0;
    CK_ATTRIBUTE a = { CKA_PARAMETER_SET, &v, sizeof v };
    if (C_GetAttributeValue(s, o, &a, 1) != CKR_OK) return -2;
    if (a.ulValueLen == (CK_ULONG)-1) return -1;
    if (a.ulValueLen != sizeof v) return -2;
    return (long)v;
}

int main(void)
{
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_InitToken); SYM(C_OpenSession); SYM(C_Login);
    SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue);
    SYM(C_EncapsulateKey); SYM(C_DecapsulateKey);
    if (!C_GenerateKeyPair || !C_GetAttributeValue || !C_EncapsulateKey
        || !C_DecapsulateKey || !C_Logout) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "pqcparams")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    static const struct {
        const char *name; CK_ULONG mech, sel, pub_use, priv_use;
    } keys[] = {
        { "ML-KEM-512",        CKM_ML_KEM_KEY_PAIR_GEN,  1, CKA_ENCAPSULATE, CKA_DECAPSULATE },
        { "ML-KEM-768",        CKM_ML_KEM_KEY_PAIR_GEN,  2, CKA_ENCAPSULATE, CKA_DECAPSULATE },
        { "ML-KEM-1024",       CKM_ML_KEM_KEY_PAIR_GEN,  3, CKA_ENCAPSULATE, CKA_DECAPSULATE },
        { "ML-DSA-44",         CKM_ML_DSA_KEY_PAIR_GEN,  1, CKA_VERIFY,      CKA_SIGN },
        { "ML-DSA-65",         CKM_ML_DSA_KEY_PAIR_GEN,  2, CKA_VERIFY,      CKA_SIGN },
        { "ML-DSA-87",         CKM_ML_DSA_KEY_PAIR_GEN,  3, CKA_VERIFY,      CKA_SIGN },
        { "SLH-DSA-SHA2-128f", CKM_SLH_DSA_KEY_PAIR_GEN, 3, CKA_VERIFY,      CKA_SIGN },
    };
    CK_OBJECT_HANDLE kem_pub[3] = {0}, kem_priv[3] = {0};
    char what[96];

    printf("CKA_PARAMETER_SET reads back\n");
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; ++i) {
        CK_OBJECT_HANDLE pub = 0, priv = 0;
        CK_RV rv = keygen(s, keys[i].mech, keys[i].sel, keys[i].pub_use, keys[i].priv_use,
                          &pub, &priv);
        snprintf(what, sizeof what, "(1) %s: generated (rv=0x%lx)", keys[i].name, rv);
        ok(rv == CKR_OK, what);
        if (rv != CKR_OK) continue;
        long p = pset_of(s, pub), q = pset_of(s, priv);
        snprintf(what, sizeof what, "(1) %s: public %ld, private %ld, want %lu",
                 keys[i].name, p, q, keys[i].sel);
        ok(p == (long)keys[i].sel && q == (long)keys[i].sel, what);
        if (keys[i].mech == CKM_ML_KEM_KEY_PAIR_GEN) {
            kem_pub[keys[i].sel - 1] = pub; kem_priv[keys[i].sel - 1] = priv;
        }
    }

    {
        static const CK_BYTE P256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
        CK_BYTE yes = 1, no = 0;
        CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                              { CKA_EC_PARAMS, (void*)P256, sizeof P256 } };
        CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
        CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE pub = 0, priv = 0;
        if (C_GenerateKeyPair(s, &m, pt, 3, kt, 2, &pub, &priv) == CKR_OK)
            ok(pset_of(s, pub) == -1 && pset_of(s, priv) == -1,
               "(2) P-256: no CKA_PARAMETER_SET on either half");
        else
            printf("  P-256 key generation unavailable, (2) skipped\n");
    }

    printf("C_DecapsulateKey: ciphertext length\n");
    static const char *kem_names[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
    static const CK_ULONG kem_ct[] = { 768, 1088, 1568 };
    for (int i = 0; i < 3; ++i) {
        if (!kem_pub[i]) continue;
        CK_MECHANISM m = { CKM_ML_KEM, NULL, 0 };
        CK_BYTE ct[1569];
        CK_ULONG ct_len = sizeof ct;
        CK_OBJECT_HANDLE ss = 0;
        CK_RV rv = C_EncapsulateKey(s, &m, kem_pub[i], NULL, 0, ct, &ct_len, &ss);
        snprintf(what, sizeof what, "(3) %s: encapsulated, %lu bytes (rv=0x%lx)",
                 kem_names[i], ct_len, rv);
        ok(rv == CKR_OK && ct_len == kem_ct[i], what);
        if (rv != CKR_OK) continue;
        ct[ct_len] = 0;
        rv = C_DecapsulateKey(s, &m, kem_priv[i], NULL, 0, ct, ct_len - 1, &ss);
        snprintf(what, sizeof what, "(3) %s: one byte short refused (rv=0x%lx)", kem_names[i], rv);
        ok(rv == CKR_ENCRYPTED_DATA_LEN_RANGE, what);
        rv = C_DecapsulateKey(s, &m, kem_priv[i], NULL, 0, ct, ct_len + 1, &ss);
        snprintf(what, sizeof what, "(3) %s: one byte long refused (rv=0x%lx)", kem_names[i], rv);
        ok(rv == CKR_ENCRYPTED_DATA_LEN_RANGE, what);
        rv = C_DecapsulateKey(s, &m, kem_priv[i], NULL, 0, ct, ct_len, &ss);
        snprintf(what, sizeof what, "(3) %s: the right length decapsulates (rv=0x%lx)", kem_names[i], rv);
        ok(rv == CKR_OK, what);
    }

    printf("\n%s\n", fails ? "FAILED" : "all passed");
    return fails ? 1 : 0;
}
