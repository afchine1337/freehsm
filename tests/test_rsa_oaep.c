/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_rsa_oaep.c --- RSA-OAEP through the module, checked against OpenSSL.
 *
 * test_oaep_decrypt_size.c checks one rule, the output length; the file
 * encryption tests use one parameter set. OAEP has more than that to get
 * right -- the hash, the MGF's hash, which may differ from it, and the label --
 * and a module that mixed any two up would still decrypt what it had itself
 * encrypted. So here OpenSSL encrypts, with the public key read back from the
 * token, and the module must decrypt it.
 *
 * What is asserted, for RSA 2048, 3072 and 4096 generated on the token:
 *   (1) for SHA-224, SHA-256, SHA-384 and SHA-512 as hash and MGF1 hash,
 *       with an empty label and with one: OpenSSL's ciphertext decrypts in
 *       the module to the plaintext
 *   (2) SHA-256 with MGF1-SHA-1, the two hashes differing
 *   (3) SHA-1: decrypts, or is refused by the profile -- said which
 *   (4) the module's own ciphertext decrypts back
 *   (5) a wrong label is refused, and so is a ciphertext with one bit changed
 *   (6) the longest message, k - 2hLen - 2 bytes, is accepted; one byte more
 *       is CKR_DATA_LEN_RANGE -- it was CKR_FUNCTION_FAILED
 *   (7) a hash the module does not take for OAEP (MD5) is refused at Init
 *       with CKR_MECHANISM_PARAM_INVALID
 * (1) runs SHA3-256 and SHA3-512 as well, and SHA-224, which the module
 * refused with CKR_MECHANISM_INVALID until this test found it.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rsa.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG hashAlg; CK_ULONG mgf; CK_ULONG source;
                 void *pSourceData; CK_ULONG ulSourceDataLen; } CK_RSA_PKCS_OAEP_PARAMS;

#define CKR_OK                      0UL
#define CKR_DATA_LEN_RANGE          0x21UL
#define CKR_MECHANISM_PARAM_INVALID 0x71UL
#define CKF_RW                      6UL
#define CKA_TOKEN                   0x001UL
#define CKA_ENCRYPT                 0x104UL
#define CKA_DECRYPT                 0x105UL
#define CKA_MODULUS                 0x120UL
#define CKA_MODULUS_BITS            0x121UL
#define CKA_PUBLIC_EXPONENT         0x122UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN   0x0000UL
#define CKM_RSA_PKCS_OAEP           0x0009UL
#define CKZ_DATA_SPECIFIED          1UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

/* The hash, its MGF1 code and its OpenSSL name and length. */
static const struct { const char *name; CK_ULONG ckm, mgf; size_t len; } H[] = {
    { "SHA1",   0x220, 1, 20 },
    { "SHA224", 0x255, 5, 28 },
    { "SHA256", 0x250, 2, 32 },
    { "SHA384", 0x260, 3, 48 },
    { "SHA512", 0x270, 4, 64 },
    { "SHA3-256", 0x2B0, 7, 32 },
    { "SHA3-512", 0x2D0, 9, 64 },
};

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
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
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Decrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);

static CK_SESSION_HANDLE s;

/* The token's public key as an OpenSSL key, from CKA_MODULUS and
   CKA_PUBLIC_EXPONENT -- the standard attributes, not the module's storage. */
static EVP_PKEY *public_key(CK_OBJECT_HANDLE pub)
{
    CK_BYTE n[512], e[8];
    CK_ATTRIBUTE a[] = { { CKA_MODULUS, n, sizeof n }, { CKA_PUBLIC_EXPONENT, e, sizeof e } };
    if (C_GetAttributeValue(s, pub, a, 2) != CKR_OK) return NULL;
    /* OSSL_PARAM BNs are native-endian; the attributes are big-endian. */
    BIGNUM *bn = BN_bin2bn(n, (int)a[0].ulValueLen, NULL);
    BIGNUM *be = BN_bin2bn(e, (int)a[1].ulValueLen, NULL);
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM *p = NULL;
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (bn && be && b && c
        && OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_RSA_N, bn)
        && OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_RSA_E, be)
        && (p = OSSL_PARAM_BLD_to_param(b)) != NULL
        && EVP_PKEY_fromdata_init(c) == 1)
        (void)EVP_PKEY_fromdata(c, &k, EVP_PKEY_PUBLIC_KEY, p);
    OSSL_PARAM_free(p); OSSL_PARAM_BLD_free(b); EVP_PKEY_CTX_free(c);
    BN_free(bn); BN_free(be);
    return k;
}

static int ossl_encrypt(EVP_PKEY *k, const char *md, const char *mgf, const CK_BYTE *label,
                        size_t label_len, const CK_BYTE *in, size_t in_len,
                        CK_BYTE *out, size_t *out_len)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    int r = c && EVP_PKEY_encrypt_init(c) == 1
            && EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) == 1
            && EVP_PKEY_CTX_set_rsa_oaep_md_name(c, md, NULL) == 1
            && EVP_PKEY_CTX_set_rsa_mgf1_md_name(c, mgf, NULL) == 1;
    if (r && label_len) {
        /* The context takes ownership of the label. */
        unsigned char *l = OPENSSL_memdup(label, label_len);
        r = l && EVP_PKEY_CTX_set0_rsa_oaep_label(c, l, (int)label_len) == 1;
        if (!r) OPENSSL_free(l);
    }
    r = r && EVP_PKEY_encrypt(c, out, out_len, in, in_len) == 1;
    EVP_PKEY_CTX_free(c);
    return r;
}

static CK_RV module_op(int enc, CK_OBJECT_HANDLE k, CK_RSA_PKCS_OAEP_PARAMS *p,
                       const CK_BYTE *in, CK_ULONG in_len, CK_BYTE *out, CK_ULONG *out_len)
{
    CK_MECHANISM m = { CKM_RSA_PKCS_OAEP, p, sizeof *p };
    CK_RV rv = enc ? C_EncryptInit(s, &m, k) : C_DecryptInit(s, &m, k);
    if (rv != CKR_OK) return rv;
    return enc ? C_Encrypt(s, (CK_BYTE *)in, in_len, out, out_len)
               : C_Decrypt(s, (CK_BYTE *)in, in_len, out, out_len);
}

static void one_size(CK_ULONG bits)
{
    CK_ULONG e_len = 3;
    CK_BYTE e[] = { 1, 0, 1 }, yes = 1, no = 0;
    CK_ATTRIBUTE pt_[] = { { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 },
                           { CKA_MODULUS_BITS, &bits, sizeof bits },
                           { CKA_PUBLIC_EXPONENT, e, e_len } };
    CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_DECRYPT, &yes, 1 } };
    CK_MECHANISM gen = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    char what[112];
    CK_RV rv = C_GenerateKeyPair(s, &gen, pt_, 4, kt, 2, &pub, &priv);
    snprintf(what, sizeof what, "RSA-%lu key pair generated (rv 0x%lx)", bits, rv);
    ok(rv == CKR_OK, what);
    if (rv != CKR_OK) return;
    EVP_PKEY *k = public_key(pub);
    snprintf(what, sizeof what, "RSA-%lu public key read back from the token", bits);
    ok(k != NULL, what);
    if (!k) return;

    const size_t mod = bits / 8;
    CK_BYTE msg[] = "RSA-OAEP through the token", label[] = "a label";
    CK_BYTE ct[512], pt[512];
    size_t ct_len;
    CK_ULONG pt_len;

    /* (1), (2), (3): OpenSSL encrypts, the module decrypts. */
    struct { int h, mgf, with_label; const char *tag; } cases[] = {
        { 1, 1, 0, "(1)" }, { 2, 2, 0, "(1)" }, { 3, 3, 0, "(1)" }, { 4, 4, 0, "(1)" },
        { 1, 1, 1, "(1)" }, { 2, 2, 1, "(1)" }, { 3, 3, 1, "(1)" }, { 4, 4, 1, "(1)" },
        { 5, 5, 0, "(1)" }, { 6, 6, 1, "(1)" },
        { 2, 0, 1, "(2)" }, { 0, 0, 0, "(3)" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int h = cases[i].h, g = cases[i].mgf;
        CK_RSA_PKCS_OAEP_PARAMS p = { H[h].ckm, H[g].mgf, CKZ_DATA_SPECIFIED,
                                      cases[i].with_label ? label : NULL,
                                      cases[i].with_label ? sizeof label - 1 : 0 };
        ct_len = sizeof ct;
        int r = ossl_encrypt(k, H[h].name, H[g].name, label,
                             cases[i].with_label ? sizeof label - 1 : 0,
                             msg, sizeof msg - 1, ct, &ct_len);
        pt_len = sizeof pt;
        rv = r ? module_op(0, priv, &p, ct, ct_len, pt, &pt_len) : 0x6;
        int good = rv == CKR_OK && pt_len == sizeof msg - 1 && !memcmp(pt, msg, pt_len);
        snprintf(what, sizeof what, "%s RSA-%lu %s, MGF1-%s, %s: decrypts (rv 0x%lx)",
                 cases[i].tag, bits, H[h].name, H[g].name,
                 cases[i].with_label ? "label" : "no label", rv);
        if (h == 0 && rv != CKR_OK && r) {
            /* SHA-1: a profile may withhold it. Said, not failed. */
            printf("  %-66s %s\n", what, "refused by this profile");
            continue;
        }
        ok(r && good, what);
    }

    /* (4) The module's own ciphertext. */
    CK_RSA_PKCS_OAEP_PARAMS p256 = { H[2].ckm, H[2].mgf, CKZ_DATA_SPECIFIED, label, sizeof label - 1 };
    CK_ULONG mct_len = sizeof ct;
    rv = module_op(1, pub, &p256, msg, sizeof msg - 1, ct, &mct_len);
    pt_len = sizeof pt;
    if (rv == CKR_OK) rv = module_op(0, priv, &p256, ct, mct_len, pt, &pt_len);
    snprintf(what, sizeof what, "(4) RSA-%lu module encrypts, module decrypts (rv 0x%lx)", bits, rv);
    ok(rv == CKR_OK && mct_len == mod && pt_len == sizeof msg - 1 && !memcmp(pt, msg, pt_len), what);

    /* (5) A wrong label, and a changed bit. */
    CK_BYTE other[] = "another label";
    CK_RSA_PKCS_OAEP_PARAMS wrong = { H[2].ckm, H[2].mgf, CKZ_DATA_SPECIFIED, other, sizeof other - 1 };
    pt_len = sizeof pt;
    rv = module_op(0, priv, &wrong, ct, mct_len, pt, &pt_len);
    snprintf(what, sizeof what, "(5) RSA-%lu wrong label: refused (rv 0x%lx)", bits, rv);
    ok(rv != CKR_OK, what);
    ct[mct_len / 2] ^= 0x01;
    pt_len = sizeof pt;
    rv = module_op(0, priv, &p256, ct, mct_len, pt, &pt_len);
    snprintf(what, sizeof what, "(5) RSA-%lu one bit changed: refused (rv 0x%lx)", bits, rv);
    ok(rv != CKR_OK, what);

    /* (6) Length bounds, SHA-256: k - 2*32 - 2. */
    CK_BYTE longest[512];
    memset(longest, 0x5A, sizeof longest);
    size_t max = mod - 2 * H[2].len - 2;
    mct_len = sizeof ct;
    rv = module_op(1, pub, &p256, longest, max, ct, &mct_len);
    snprintf(what, sizeof what, "(6) RSA-%lu %zu-byte message, the longest: accepted (rv 0x%lx)",
             bits, max, rv);
    ok(rv == CKR_OK, what);
    mct_len = sizeof ct;
    rv = module_op(1, pub, &p256, longest, max + 1, ct, &mct_len);
    snprintf(what, sizeof what, "(6) RSA-%lu one byte longer: CKR_DATA_LEN_RANGE (rv 0x%lx)", bits, rv);
    ok(rv == CKR_DATA_LEN_RANGE, what);

    /* (7) An unknown hash is a parameter defect, said at Init. */
    CK_RSA_PKCS_OAEP_PARAMS md5 = { 0x210, 1, CKZ_DATA_SPECIFIED, NULL, 0 };
    CK_MECHANISM mm = { CKM_RSA_PKCS_OAEP, &md5, sizeof md5 };
    rv = C_DecryptInit(s, &mm, priv);
    snprintf(what, sizeof what, "(7) RSA-%lu OAEP with MD5: CKR_MECHANISM_PARAM_INVALID (rv 0x%lx)",
             bits, rv);
    ok(rv == CKR_MECHANISM_PARAM_INVALID, what);

    EVP_PKEY_free(k);
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
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKeyPair);
    SYM(C_GetAttributeValue); SYM(C_EncryptInit); SYM(C_Encrypt);
    SYM(C_DecryptInit); SYM(C_Decrypt);
    if (!C_GenerateKeyPair || !C_Encrypt || !C_Decrypt) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("RSA-OAEP: OpenSSL encrypts, the module decrypts\n\n");

    CK_BYTE lbl[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(lbl, "rsaoaep")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    static const CK_ULONG bits[] = { 2048, 3072, 4096 };
    for (size_t i = 0; i < 3; i++) { one_size(bits[i]); printf("\n"); }

    (void)C_Finalize(NULL);
    printf("%s: %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
