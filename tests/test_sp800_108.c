/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_sp800_108.c --- CKM_SP800_108_COUNTER_KDF, _FEEDBACK_KDF and
 * _DOUBLE_PIPELINE_KDF (PKCS#11 v3.1 §6.42), issue #28.
 *
 * The module builds its own loop over EVP_MAC, because the caller orders the
 * fields of the PRF input. So the expected values do not come from that loop:
 * OpenSSL's KBKDF answers for the layouts it has, and the others are written
 * out here as the literal bytes the PRF must receive.
 *
 * What is asserted:
 *   (1) counter mode, AES-CMAC and HMAC-SHA-256, equal to OpenSSL's KBKDF
 *   (2) feedback mode with an IV and a counter, equal to OpenSSL's KBKDF, and
 *       with an IV shorter than the PRF's output, which it refuses, on literal
 *       bytes
 *   (3) the SCP03 layout, the counter inside the input, literal bytes
 *   (4) a little-endian counter and length, literal bytes
 *   (5) double pipeline, literal bytes, A(0) leaving out the iteration
 *       variable and the counter
 *   (6) §6.42.6's example: 48 and 16 bytes under HMAC-SHA-256 take three
 *       segments; the DKM length is 512 bits or 768 by its method, and the
 *       second key is the third segment
 *   (7) refusals: a missing or repeated iteration variable, a counter field in
 *       counter mode, a width that is not whole bytes, a counter or a length
 *       too narrow for the output, an AES-CMAC PRF on a key that is not AES,
 *       no CKA_VALUE_LEN
 *   (8) a bad additional template: its phKey says CK_INVALID_HANDLE and no key
 *       is created
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_PRF_DATA_PARAM;
typedef struct { CK_BYTE bLittleEndian; CK_ULONG ulWidthInBits; } CK_SP800_108_COUNTER_FORMAT;
typedef struct { CK_ULONG dkmLengthMethod; CK_BYTE bLittleEndian; CK_ULONG ulWidthInBits; } CK_SP800_108_DKM_LENGTH_FORMAT;
typedef struct { CK_ATTRIBUTE *pTemplate; CK_ULONG ulAttributeCount; CK_OBJECT_HANDLE *phKey; } CK_DERIVED_KEY;
typedef struct { CK_ULONG prfType, ulNumberOfDataParams; CK_PRF_DATA_PARAM *pDataParams;
                 CK_ULONG ulAdditionalDerivedKeys; CK_DERIVED_KEY *pAdditionalDerivedKeys; } CK_SP800_108_KDF_PARAMS;
typedef struct { CK_ULONG prfType, ulNumberOfDataParams; CK_PRF_DATA_PARAM *pDataParams;
                 CK_ULONG ulIVLen; CK_BYTE *pIV;
                 CK_ULONG ulAdditionalDerivedKeys; CK_DERIVED_KEY *pAdditionalDerivedKeys; } CK_SP800_108_FEEDBACK_KDF_PARAMS;

#define CKR_OK                       0UL
#define CKR_KEY_TYPE_INCONSISTENT    0x63UL
#define CKR_MECHANISM_PARAM_INVALID  0x71UL
#define CKR_TEMPLATE_INCOMPLETE      0xD0UL
#define CKF_RW                       6UL
#define CKA_CLASS                    0x000UL
#define CKA_TOKEN                    0x001UL
#define CKA_VALUE                    0x011UL
#define CKA_KEY_TYPE                 0x100UL
#define CKA_SENSITIVE                0x103UL
#define CKA_DERIVE                   0x10CUL
#define CKA_VALUE_LEN                0x161UL
#define CKA_EXTRACTABLE              0x162UL
#define CKO_SECRET_KEY               4UL
#define CKK_GENERIC_SECRET           0x10UL
#define CKK_AES                      0x1FUL
#define CKM_SHA256_HMAC              0x251UL
#define CKM_AES_CMAC                 0x108AUL
#define CKM_COUNTER                  0x3ACUL
#define CKM_FEEDBACK                 0x3ADUL
#define CKM_DOUBLE_PIPELINE          0x3AEUL
#define ITER                         1UL
#define COUNTER                      2UL
#define DKM                          3UL
#define BYTES                        4UL
#define SUM_OF_KEYS                  1UL
#define SUM_OF_SEGMENTS              2UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;
static CK_ULONG cls = CKO_SECRET_KEY, generic = CKK_GENERIC_SECRET, aes = CKK_AES;

static CK_OBJECT_HANDLE base_key(CK_ULONG *type, CK_BYTE *v, CK_ULONG n) {
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, type, sizeof *type },
                         { CKA_TOKEN, &no, 1 }, { CKA_VALUE, v, n }, { CKA_DERIVE, &yes, 1 } };
    CK_OBJECT_HANDLE h = 0;
    if (C_CreateObject(s, t, 5, &h) != CKR_OK) { fprintf(stderr, "C_CreateObject\n"); return 0; }
    return h;
}

/* Derive `len` bytes and read them back. */
static CK_RV derive(CK_MECHANISM *m, CK_OBJECT_HANDLE base, CK_ULONG len,
                    CK_OBJECT_HANDLE *h, CK_BYTE *out) {
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &generic, sizeof generic },
                         { CKA_TOKEN, &no, 1 }, { CKA_VALUE_LEN, &len, sizeof len },
                         { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 } };
    CK_RV rv = C_DeriveKey(s, m, base, t, 6, h);
    if (rv != CKR_OK || !out) return rv;
    CK_ATTRIBUTE a = { CKA_VALUE, out, len };
    return C_GetAttributeValue(s, *h, &a, 1);
}

static CK_ULONG secret_count(void) {
    CK_ATTRIBUTE f = { CKA_CLASS, &cls, sizeof cls };
    CK_OBJECT_HANDLE found[64]; CK_ULONG n = 0;
    C_FindObjectsInit(s, &f, 1);
    C_FindObjects(s, found, 64, &n);
    C_FindObjectsFinal(s);
    return n;
}

/* OpenSSL's KBKDF: [i]32 || label || 0x00 || context || [L]32, after K(i-1) in
 * feedback mode. */
static int ossl_kbkdf(const char *mode, const char *mac, const char *sub_key,
                      const char *sub, const CK_BYTE *key, size_t kl,
                      CK_BYTE *label, size_t ll, CK_BYTE *ctx_, size_t cl,
                      CK_BYTE *iv, size_t ivl, CK_BYTE *out, size_t ol) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    EVP_KDF_CTX *c = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    OSSL_PARAM p[8]; int n = 0;
    p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, (char*)mode, 0);
    p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, (char*)mac, 0);
    p[n++] = OSSL_PARAM_construct_utf8_string(sub_key, (char*)sub, 0);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)key, kl);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, label, ll);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, ctx_, cl);
    if (ivl) p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, iv, ivl);
    p[n] = OSSL_PARAM_construct_end();
    int r = c && EVP_KDF_derive(c, out, ol, p) == 1;
    EVP_KDF_CTX_free(c);
    EVP_KDF_free(kdf);
    return r;
}

/* The PRF on literal bytes. */
static void prf(const char *mac, const char *sub_key, const char *sub,
                const CK_BYTE *key, size_t kl, const CK_BYTE *in, size_t il,
                CK_BYTE *out, size_t ol) {
    EVP_MAC *m = EVP_MAC_fetch(NULL, mac, NULL);
    EVP_MAC_CTX *c = EVP_MAC_CTX_new(m);
    OSSL_PARAM p[2] = { OSSL_PARAM_construct_utf8_string(sub_key, (char*)sub, 0),
                        OSSL_PARAM_construct_end() };
    size_t l = 0;
    EVP_MAC_init(c, key, kl, p); EVP_MAC_update(c, in, il); EVP_MAC_final(c, out, &l, ol);
    EVP_MAC_CTX_free(c); EVP_MAC_free(m);
}
#define HMAC(k, kl, in, il, out) prf("HMAC", "digest", "SHA256", k, kl, in, il, out, 32)
#define CMAC(k, kl, in, il, out) prf("CMAC", "cipher", "AES-128-CBC", k, kl, in, il, out, 16)

int main(void)
{
    void *hl = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!hl) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*C_Initialize)(void*); CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(hl,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_DeriveKey);
    SYM(C_GetAttributeValue); SYM(C_FindObjectsInit); SYM(C_FindObjects); SYM(C_FindObjectsFinal);

    printf("SP 800-108 key derivation\n\n");

    CK_BYTE tl[32];
    memset(tl, ' ', 32); memcpy(tl, "kbkdf", 5);
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), tl) != CKR_OK) { fprintf(stderr, "C_InitToken\n"); return 2; }
    C_OpenSession(0, CKF_RW, NULL, NULL, &s);
    C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN));
    C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN));
    C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login\n"); return 2; }

    CK_BYTE kaes[16], khmac[32], label[] = { 0xde, 0xad, 0xbe, 0xef },
            ctx_[] = { 0xfe, 0xed, 0xbe, 0xef }, sep[] = { 0x00 }, iv[32];
    for (int i = 0; i < 16; ++i) kaes[i] = (CK_BYTE)(0x10 + i);
    for (int i = 0; i < 32; ++i) { khmac[i] = (CK_BYTE)(0x40 + i); iv[i] = (CK_BYTE)(0x80 + i); }
    CK_OBJECT_HANDLE baes = base_key(&aes, kaes, 16), bgen = base_key(&generic, khmac, 32), h = 0;
    if (!baes || !bgen) return 2;

    CK_SP800_108_COUNTER_FORMAT c32 = { 0, 32 }, c16 = { 0, 16 }, c8 = { 0, 8 },
                                c16le = { 1, 16 }, c12 = { 0, 12 };
    CK_SP800_108_DKM_LENGTH_FORMAT d32 = { SUM_OF_KEYS, 0, 32 }, d16 = { SUM_OF_KEYS, 0, 16 },
                                   d16le = { SUM_OF_KEYS, 1, 16 }, d8 = { SUM_OF_KEYS, 0, 8 },
                                   dseg = { SUM_OF_SEGMENTS, 0, 16 };
    CK_BYTE got[128], want[128], lit[128], a[32];
    CK_RV rv;

    /* (1) */
    CK_PRF_DATA_PARAM std[] = { { ITER, &c32, sizeof c32 }, { BYTES, label, 4 }, { BYTES, sep, 1 },
                                { BYTES, ctx_, 4 }, { DKM, &d32, sizeof d32 } };
    CK_SP800_108_KDF_PARAMS kp = { CKM_AES_CMAC, 5, std, 0, NULL };
    CK_MECHANISM m = { CKM_COUNTER, &kp, sizeof kp };
    rv = derive(&m, baes, 40, &h, got);
    ok(rv == CKR_OK && ossl_kbkdf("counter", "CMAC", "cipher", "AES-128-CBC", kaes, 16, label, 4,
                                  ctx_, 4, NULL, 0, want, 40) && !memcmp(got, want, 40),
       "(1) counter, AES-CMAC, 40 bytes: equal to OpenSSL's KBKDF");
    kp.prfType = CKM_SHA256_HMAC;
    rv = derive(&m, bgen, 40, &h, got);
    ok(rv == CKR_OK && ossl_kbkdf("counter", "HMAC", "digest", "SHA256", khmac, 32, label, 4,
                                  ctx_, 4, NULL, 0, want, 40) && !memcmp(got, want, 40),
       "(1) counter, HMAC-SHA-256, 40 bytes: equal to OpenSSL's KBKDF");

    /* (2) */
    CK_PRF_DATA_PARAM fb[] = { { ITER, NULL, 0 }, { COUNTER, &c32, sizeof c32 }, { BYTES, label, 4 },
                               { BYTES, sep, 1 }, { BYTES, ctx_, 4 }, { DKM, &d32, sizeof d32 } };
    CK_SP800_108_FEEDBACK_KDF_PARAMS fp = { CKM_SHA256_HMAC, 6, fb, 32, iv, 0, NULL };
    CK_MECHANISM mf = { CKM_FEEDBACK, &fp, sizeof fp };
    rv = derive(&mf, bgen, 40, &h, got);
    /* OpenSSL takes only an IV of the PRF's output length. */
    ok(rv == CKR_OK && ossl_kbkdf("feedback", "HMAC", "digest", "SHA256", khmac, 32, label, 4,
                                  ctx_, 4, iv, 32, want, 40) && !memcmp(got, want, 40),
       "(2) feedback, HMAC-SHA-256, IV: equal to OpenSSL's KBKDF");
    /* PKCS#11 sets no such length: K(1) = PRF(IV || [1]16 || Label), then
     * K(2) = PRF(K(1) || [2]16 || Label). */
    CK_PRF_DATA_PARAM fb2[] = { { ITER, NULL, 0 }, { COUNTER, &c16, sizeof c16 }, { BYTES, label, 4 } };
    fp.pDataParams = fb2; fp.ulNumberOfDataParams = 3; fp.ulIVLen = 7;
    rv = derive(&mf, bgen, 40, &h, got);
    memcpy(lit, iv, 7); lit[7] = 0; lit[8] = 1; memcpy(lit + 9, label, 4);
    HMAC(khmac, 32, lit, 13, want);
    memcpy(lit, want, 32); lit[32] = 0; lit[33] = 2; memcpy(lit + 34, label, 4);
    HMAC(khmac, 32, lit, 38, want + 32);
    ok(rv == CKR_OK && !memcmp(got, want, 40), "(2) feedback, a 7-byte IV, on its literal bytes");

    /* (3) Label || 0x00 || [L]16 || [i]16 || Context, 32 bytes of AES-CMAC. */
    CK_PRF_DATA_PARAM scp[] = { { BYTES, label, 4 }, { BYTES, sep, 1 }, { DKM, &d16, sizeof d16 },
                                { ITER, &c16, sizeof c16 }, { BYTES, ctx_, 4 } };
    CK_SP800_108_KDF_PARAMS sp = { CKM_AES_CMAC, 5, scp, 0, NULL };
    CK_MECHANISM ms = { CKM_COUNTER, &sp, sizeof sp };
    rv = derive(&ms, baes, 32, &h, got);
    CK_BYTE in3[] = { 0xde,0xad,0xbe,0xef, 0x00, 0x01,0x00, 0x00,0x01, 0xfe,0xed,0xbe,0xef };
    CMAC(kaes, 16, in3, sizeof in3, want);
    in3[8] = 0x02;
    CMAC(kaes, 16, in3, sizeof in3, want + 16);
    ok(rv == CKR_OK && !memcmp(got, want, 32), "(3) the SCP03 layout, on its literal bytes");

    /* (4) */
    CK_PRF_DATA_PARAM lep[] = { { ITER, &c16le, sizeof c16le }, { BYTES, label, 4 },
                                { DKM, &d16le, sizeof d16le } };
    CK_SP800_108_KDF_PARAMS lp = { CKM_SHA256_HMAC, 3, lep, 0, NULL };
    CK_MECHANISM ml = { CKM_COUNTER, &lp, sizeof lp };
    rv = derive(&ml, bgen, 32, &h, got);
    CK_BYTE in4[] = { 0x01,0x00, 0xde,0xad,0xbe,0xef, 0x00,0x01 };
    HMAC(khmac, 32, in4, sizeof in4, want);
    ok(rv == CKR_OK && !memcmp(got, want, 32), "(4) a little-endian counter and length");

    /* (5) A(0) = Label || [L]16, K(i) = PRF(A(i) || [i]16 || Label || [L]16). */
    CK_PRF_DATA_PARAM dp[] = { { ITER, NULL, 0 }, { COUNTER, &c16, sizeof c16 }, { BYTES, label, 4 },
                               { DKM, &d16, sizeof d16 } };
    CK_SP800_108_KDF_PARAMS pp = { CKM_SHA256_HMAC, 4, dp, 0, NULL };
    CK_MECHANISM mp = { CKM_DOUBLE_PIPELINE, &pp, sizeof pp };
    rv = derive(&mp, bgen, 40, &h, got);
    CK_BYTE a0[] = { 0xde,0xad,0xbe,0xef, 0x01,0x40 };
    HMAC(khmac, 32, a0, sizeof a0, a);                  /* A(1) */
    memcpy(lit, a, 32); lit[32] = 0; lit[33] = 1; memcpy(lit + 34, a0, 6);
    HMAC(khmac, 32, lit, 40, want);
    HMAC(khmac, 32, a, 32, a);                          /* A(2) */
    memcpy(lit, a, 32); lit[33] = 2;
    HMAC(khmac, 32, lit, 40, want + 32);
    ok(rv == CKR_OK && !memcmp(got, want, 40), "(5) double pipeline, on its literal bytes");

    /* (6) */
    for (int k = 0; k < 2; ++k) {
        CK_PRF_DATA_PARAM ex[] = { { ITER, &c16, sizeof c16 }, { DKM, k ? &dseg : &d16, sizeof d16 } };
        CK_ULONG len2 = 16;
        CK_OBJECT_HANDLE h2 = 0;
        CK_ATTRIBUTE t2[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &aes, sizeof aes },
                              { CKA_TOKEN, &no, 1 }, { CKA_VALUE_LEN, &len2, sizeof len2 },
                              { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 } };
        CK_DERIVED_KEY dk = { t2, 6, &h2 };
        CK_SP800_108_KDF_PARAMS ep = { CKM_SHA256_HMAC, 2, ex, 1, &dk };
        CK_MECHANISM me = { CKM_COUNTER, &ep, sizeof ep };
        CK_BYTE v2[16]; CK_ATTRIBUTE a2 = { CKA_VALUE, v2, 16 };
        rv = derive(&me, bgen, 48, &h, got);
        rv = rv == CKR_OK ? C_GetAttributeValue(s, h2, &a2, 1) : rv;
        CK_BYTE in6[] = { 0x00,0x01, (CK_BYTE)(k ? 0x03 : 0x02), 0x00 };
        HMAC(khmac, 32, in6, 4, want);
        in6[1] = 2; HMAC(khmac, 32, in6, 4, want + 32);
        in6[1] = 3; HMAC(khmac, 32, in6, 4, want + 64);
        ok(rv == CKR_OK && !memcmp(got, want, 48) && !memcmp(v2, want + 64, 16),
           k ? "(6) 48+16, sum of segments, 768 bits: the second key is segment 3"
             : "(6) 48+16, sum of keys, 512 bits: the second key is segment 3");
    }

    /* (7) */
    CK_PRF_DATA_PARAM noit[] = { { BYTES, label, 4 } };
    CK_PRF_DATA_PARAM twoit[] = { { ITER, &c16, sizeof c16 }, { ITER, &c16, sizeof c16 } };
    CK_PRF_DATA_PARAM cnt[] = { { ITER, &c16, sizeof c16 }, { COUNTER, &c16, sizeof c16 } };
    CK_PRF_DATA_PARAM bad12[] = { { ITER, &c12, sizeof c12 } };
    CK_PRF_DATA_PARAM narrow[] = { { ITER, &c8, sizeof c8 } };
    CK_PRF_DATA_PARAM thin[] = { { ITER, &c16, sizeof c16 }, { DKM, &d8, sizeof d8 } };
    CK_PRF_DATA_PARAM good[] = { { ITER, &c16, sizeof c16 } };
    CK_SP800_108_KDF_PARAMS bp = { CKM_SHA256_HMAC, 1, noit, 0, NULL };
    CK_MECHANISM mb = { CKM_COUNTER, &bp, sizeof bp };
    ok(derive(&mb, bgen, 32, &h, NULL) == CKR_MECHANISM_PARAM_INVALID, "(7) no iteration variable");
    bp.pDataParams = twoit; bp.ulNumberOfDataParams = 2;
    ok(derive(&mb, bgen, 32, &h, NULL) == CKR_MECHANISM_PARAM_INVALID, "(7) two iteration variables");
    bp.pDataParams = cnt;
    ok(derive(&mb, bgen, 32, &h, NULL) == CKR_MECHANISM_PARAM_INVALID, "(7) a counter field in counter mode");
    bp.pDataParams = bad12; bp.ulNumberOfDataParams = 1;
    ok(derive(&mb, bgen, 32, &h, NULL) == CKR_MECHANISM_PARAM_INVALID, "(7) a 12-bit counter");
    bp.pDataParams = narrow;
    ok(derive(&mb, bgen, 32 * 256, &h, NULL) == CKR_MECHANISM_PARAM_INVALID,
       "(7) 256 segments on an 8-bit counter");
    ok(derive(&mb, bgen, 32 * 255, &h, NULL) == CKR_OK, "(7) 255 segments on it are fine");
    bp.pDataParams = thin; bp.ulNumberOfDataParams = 2;
    ok(derive(&mb, bgen, 32, &h, NULL) == CKR_MECHANISM_PARAM_INVALID,
       "(7) 256 bits in an 8-bit length");
    bp.pDataParams = good; bp.ulNumberOfDataParams = 1; bp.prfType = CKM_AES_CMAC;
    ok(derive(&mb, bgen, 32, &h, NULL) == CKR_KEY_TYPE_INCONSISTENT, "(7) AES-CMAC on a generic key");
    bp.prfType = CKM_SHA256_HMAC;
    { CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_TOKEN, &no, 1 } };
      ok(C_DeriveKey(s, &mb, bgen, t, 2, &h) == CKR_TEMPLATE_INCOMPLETE, "(7) no CKA_VALUE_LEN"); }

    /* (8) */
    {
        CK_ULONG before = secret_count(), len2 = 7;
        CK_OBJECT_HANDLE h2 = 0x1234;
        CK_ATTRIBUTE t2[] = { { CKA_KEY_TYPE, &aes, sizeof aes }, { CKA_VALUE_LEN, &len2, sizeof len2 } };
        CK_DERIVED_KEY dk = { t2, 2, &h2 };
        bp.ulAdditionalDerivedKeys = 1; bp.pAdditionalDerivedKeys = &dk;
        rv = derive(&mb, bgen, 32, &h, NULL);
        ok(rv != CKR_OK && h2 == 0, "(8) a 7-byte AES key: its phKey is CK_INVALID_HANDLE");
        ok(secret_count() == before, "(8) and no key was created");
    }

    C_Finalize(NULL);
    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
