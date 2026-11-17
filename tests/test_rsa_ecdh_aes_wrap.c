/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_rsa_ecdh_aes_wrap.c --- CKM_RSA_AES_KEY_WRAP and
 * CKM_ECDH_AES_KEY_WRAP (2.8.0).
 *
 * Each wrapping is opened by other paths of the module than the one that
 * made it, so the format is checked and not only the round trip:
 *   (R) RSA-AES, RSA-2048 and AES-256: the blob is 256 bytes of RSA-OAEP
 *       then KWP. C_Decrypt with CKM_RSA_PKCS_OAEP on the first part gives
 *       the 32-byte K; C_Decrypt with CKM_AES_KEY_WRAP_KWP under K on the
 *       rest gives the wrapped key's value. C_UnwrapKey makes the key back.
 *   (E) ECDH-AES, P-256, CKD_NULL and AES-256: the blob is the ephemeral
 *       uncompressed point (65 bytes) then KWP. CKM_ECDH1_DERIVE of the EC
 *       private key with that point gives Z, which is K; KWP under K gives
 *       the value. With CKD_SHA256_KDF and shared data, K is
 *       SHA-256(Z || 00000001 || shared data), by C_Digest. C_UnwrapKey
 *       makes the key back in both cases.
 *   (F) refusals: a key length of 100 bits, an EC key for RSA-AES, CKD_NULL
 *       with shared data, a changed byte (CKR_WRAPPED_KEY_INVALID) and a
 *       short blob (CKR_WRAPPED_KEY_LEN_RANGE).
 *   (N) RSA-AES in both builds; ECDH-AES refused where NIST's rules apply.
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
typedef struct { CK_ULONG hashAlg, mgf, source; void *pSourceData; CK_ULONG ulSourceDataLen; } CK_OAEP;
typedef struct { CK_ULONG ulAESKeyBits; CK_OAEP *pOAEPParams; } CK_RSA_AES;
typedef struct { CK_ULONG ulAESKeyBits, kdf, ulSharedDataLen; CK_BYTE *pSharedData; } CK_ECDH_AES;
typedef struct { CK_ULONG kdf, ulSharedDataLen; CK_BYTE *pSharedData;
                 CK_ULONG ulPublicDataLen; CK_BYTE *pPublicData; } CK_ECDH1;

#define CKR_OK                         0x000UL
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKR_WRAPPED_KEY_INVALID        0x110UL
#define CKR_WRAPPED_KEY_LEN_RANGE      0x112UL
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT 0x115UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_DECRYPT                    0x105UL
#define CKA_WRAP                       0x106UL
#define CKA_UNWRAP                     0x107UL
#define CKA_DERIVE                     0x10CUL
#define CKA_MODULUS_BITS               0x121UL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKA_EC_PARAMS                  0x180UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x0000UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_RSA_PKCS_OAEP              0x0009UL
#define CKM_SHA256                     0x0250UL
#define CKM_EC_KEY_PAIR_GEN            0x1040UL
#define CKM_ECDH1_DERIVE               0x1050UL
#define CKM_ECDH_AES_KEY_WRAP          0x1053UL
#define CKM_RSA_AES_KEY_WRAP           0x1054UL
#define CKM_AES_KEY_WRAP_KWP           0x210BUL
#define CKG_MGF1_SHA256                0x0002UL
#define CKZ_DATA_SPECIFIED             0x0001UL
#define CKD_NULL                       0x0001UL
#define CKD_SHA256_KDF                 0x0006UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_WrapKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE,
                          CK_BYTE*, CK_ULONG*);
static CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_BYTE*, CK_ULONG,
                            CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM*);
static CK_RV (*C_Digest)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;

static int listed(CK_ULONG mech) {
    CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
    CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
    C_GetMechanismList(0, ml, &n);
    int found = 0;
    for (CK_ULONG i = 0; i < n; i++) if (ml[i] == mech) found = 1;
    free(ml);
    return found;
}

static CK_OBJECT_HANDLE secret(CK_ULONG kt, const CK_BYTE *v, CK_ULONG vl) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 },
                         { CKA_DECRYPT, &yes, 1 }, { CKA_VALUE, (void*)v, vl } };
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, 7, &h) == CKR_OK ? h : 0;
}

static CK_ULONG value_of(CK_OBJECT_HANDLE h, CK_BYTE *buf, CK_ULONG cap) {
    CK_ATTRIBUTE a = { CKA_VALUE, buf, cap };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? a.ulValueLen : 0;
}

/* Decrypt `in` with mechanism m under key k. */
static CK_RV dec(CK_MECHANISM *m, CK_OBJECT_HANDLE k, CK_BYTE *in, CK_ULONG il,
                 CK_BYTE *out, CK_ULONG *ol) {
    CK_RV rv = C_DecryptInit(s, m, k);
    return rv == CKR_OK ? C_Decrypt(s, in, il, out, ol) : rv;
}

/* KWP-decrypt `in` under the 32-byte K, through an AES key object. */
static CK_RV kwp_open(const CK_BYTE *k, CK_BYTE *in, CK_ULONG il, CK_BYTE *out, CK_ULONG *ol) {
    CK_OBJECT_HANDLE kh = secret(CKK_AES, k, 32);
    CK_MECHANISM m = { CKM_AES_KEY_WRAP_KWP, NULL, 0 };
    return kh ? dec(&m, kh, in, il, out, ol) : CKR_KEY_TYPE_INCONSISTENT;
}

static CK_RV unwrap_aes(CK_MECHANISM *m, CK_OBJECT_HANDLE uk, CK_BYTE *blob, CK_ULONG bl,
                        CK_BYTE *val, CK_ULONG *vl) {
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 } };
    CK_OBJECT_HANDLE h = 0;
    CK_RV rv = C_UnwrapKey(s, m, uk, blob, bl, t, 5, &h);
    if (rv == CKR_OK && val) *vl = value_of(h, val, *vl);
    return rv;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue);
    SYM(C_WrapKey); SYM(C_UnwrapKey); SYM(C_DeriveKey);
    SYM(C_DecryptInit); SYM(C_Decrypt); SYM(C_DigestInit); SYM(C_Digest);
    if (!C_WrapKey || !C_UnwrapKey || !C_Digest) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("RSA-AES and ECDH-AES key wrap\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "aeswrap", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const char *mode = getenv("FHSM_MODE");
    const int nist = !listed(CKM_RSA_PKCS)
                     || (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips")));

    /* The key to wrap: AES-256, extractable. */
    CK_BYTE target[32];
    for (int i = 0; i < 32; i++) target[i] = (CK_BYTE)(0x5A ^ (i * 3));
    CK_OBJECT_HANDLE tk = secret(CKK_AES, target, 32);
    if (!tk) { fprintf(stderr, "target key\n"); return 2; }

    /* --- (R) RSA-AES ------------------------------------------------------ */
    ok(listed(CKM_RSA_AES_KEY_WRAP), "(R) CKM_RSA_AES_KEY_WRAP listed");
    CK_OBJECT_HANDLE rpub = 0, rpriv = 0;
    {
        CK_ULONG bits = 2048;
        CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_MODULUS_BITS, &bits, sizeof bits },
                              { CKA_WRAP, &yes, 1 }, { CKA_ENCRYPT, &yes, 1 } };
        CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_UNWRAP, &yes, 1 }, { CKA_DECRYPT, &yes, 1 } };
        CK_MECHANISM gm = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
        if (C_GenerateKeyPair(s, &gm, pt, 4, kt, 3, &rpub, &rpriv) != CKR_OK) {
            fprintf(stderr, "RSA key pair\n"); return 2;
        }
    }
    CK_OAEP oaep = { CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, NULL, 0 };
    CK_RSA_AES rp = { 256, &oaep };
    CK_MECHANISM rm = { CKM_RSA_AES_KEY_WRAP, &rp, sizeof rp };
    {
        char what[160];
        CK_BYTE blob[512]; CK_ULONG bl = 0;
        CK_RV rv = C_WrapKey(s, &rm, rpub, tk, NULL, &bl);
        CK_ULONG sized = bl;
        if (rv == CKR_OK) { bl = sizeof blob; rv = C_WrapKey(s, &rm, rpub, tk, blob, &bl); }
        snprintf(what, sizeof what, "(R) wrapped: 256 + 40 bytes, the size query exact (0x%lx, %lu)", rv, bl);
        ok(rv == CKR_OK && bl == 296 && sized == 296, what);
        CK_MECHANISM om = { CKM_RSA_PKCS_OAEP, &oaep, sizeof oaep };
        CK_BYTE k[256], val[64]; CK_ULONG kl = sizeof k, vl = sizeof val;
        CK_RV r1 = dec(&om, rpriv, blob, 256, k, &kl);
        CK_RV r2 = (r1 == CKR_OK && kl == 32) ? kwp_open(k, blob + 256, 40, val, &vl) : r1;
        snprintf(what, sizeof what, "(R) opened apart: OAEP gives K, KWP under K the value (0x%lx 0x%lx)", r1, r2);
        ok(r2 == CKR_OK && kl == 32 && vl == 32 && memcmp(val, target, 32) == 0, what);
        vl = sizeof val;
        CK_RV r3 = unwrap_aes(&rm, rpriv, blob, bl, val, &vl);
        snprintf(what, sizeof what, "(R) C_UnwrapKey makes the key back (0x%lx)", r3);
        ok(r3 == CKR_OK && vl == 32 && memcmp(val, target, 32) == 0, what);
        /* (F) */
        blob[bl - 1] ^= 1;
        CK_RV r4 = unwrap_aes(&rm, rpriv, blob, bl, NULL, NULL);
        CK_RV r5 = unwrap_aes(&rm, rpriv, blob, 250, NULL, NULL);
        CK_RSA_AES bad = { 100, &oaep };
        CK_MECHANISM bm = { CKM_RSA_AES_KEY_WRAP, &bad, sizeof bad };
        CK_ULONG l = sizeof blob;
        CK_RV r6 = C_WrapKey(s, &bm, rpub, tk, blob, &l);
        snprintf(what, sizeof what, "(F) RSA-AES: changed byte, short blob, 100 bits (0x%lx 0x%lx 0x%lx)",
                 r4, r5, r6);
        ok(r4 == CKR_WRAPPED_KEY_INVALID && r5 == CKR_WRAPPED_KEY_LEN_RANGE
           && r6 == CKR_MECHANISM_PARAM_INVALID, what);
    }

    /* --- (E) ECDH-AES ----------------------------------------------------- */
    static CK_BYTE p256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
    CK_OBJECT_HANDLE epub = 0, epriv = 0;
    {
        CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_EC_PARAMS, p256, sizeof p256 },
                              { CKA_WRAP, &yes, 1 } };
        CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_UNWRAP, &yes, 1 }, { CKA_DERIVE, &yes, 1 } };
        CK_MECHANISM gm = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
        if (C_GenerateKeyPair(s, &gm, pt, 3, kt, 3, &epub, &epriv) != CKR_OK) {
            fprintf(stderr, "EC key pair\n"); return 2;
        }
    }
    CK_ECDH_AES np = { 256, CKD_NULL, 0, NULL };
    CK_MECHANISM em = { CKM_ECDH_AES_KEY_WRAP, &np, sizeof np };
    if (nist) {
        char what[128];
        CK_BYTE blob[256]; CK_ULONG bl = sizeof blob;
        CK_RV rv = C_WrapKey(s, &em, epub, tk, blob, &bl);
        snprintf(what, sizeof what, "(N) ECDH-AES where NIST's rules apply: MECHANISM_INVALID (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_INVALID, what);
    } else {
        ok(listed(CKM_ECDH_AES_KEY_WRAP), "(E) CKM_ECDH_AES_KEY_WRAP listed");
        static CK_BYTE info[] = "FreeHSM ECDH-AES shared info";
        CK_ECDH_AES kp = { 256, CKD_SHA256_KDF, sizeof info - 1, info };
        CK_MECHANISM km = { CKM_ECDH_AES_KEY_WRAP, &kp, sizeof kp };
        for (int withkdf = 0; withkdf < 2; withkdf++) {
            char what[160];
            CK_MECHANISM *m = withkdf ? &km : &em;
            CK_BYTE blob[256]; CK_ULONG bl = sizeof blob;
            CK_RV rv = C_WrapKey(s, m, epub, tk, blob, &bl);
            snprintf(what, sizeof what, "(E) %s: point (65) + 40 bytes, 04 first (0x%lx, %lu)",
                     withkdf ? "CKD_SHA256_KDF" : "CKD_NULL", rv, bl);
            ok(rv == CKR_OK && bl == 105 && blob[0] == 0x04, what);
            /* Z from the EC private key and the point in front. */
            CK_ECDH1 dp = { CKD_NULL, 0, NULL, 65, blob };
            CK_MECHANISM dm = { CKM_ECDH1_DERIVE, &dp, sizeof dp };
            CK_ULONG cls = CKO_SECRET_KEY, gkt = CKK_GENERIC_SECRET, zl32 = 32;
            CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &gkt, sizeof gkt },
                                 { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 },
                                 { CKA_EXTRACTABLE, &yes, 1 }, { CKA_VALUE_LEN, &zl32, sizeof zl32 } };
            CK_OBJECT_HANDLE zh = 0;
            CK_BYTE z[64], k[32], val[64];
            CK_RV r1 = C_DeriveKey(s, &dm, epriv, t, 6, &zh);
            CK_ULONG zl = r1 == CKR_OK ? value_of(zh, z, sizeof z) : 0;
            if (withkdf) {
                CK_BYTE in[32 + 4 + sizeof info];
                memcpy(in, z, 32);
                in[32] = 0; in[33] = 0; in[34] = 0; in[35] = 1;
                memcpy(in + 36, info, sizeof info - 1);
                CK_MECHANISM sm = { CKM_SHA256, NULL, 0 };
                CK_ULONG kl = sizeof k;
                if (r1 == CKR_OK) r1 = C_DigestInit(s, &sm);
                if (r1 == CKR_OK) r1 = C_Digest(s, in, 36 + sizeof info - 1, k, &kl);
            } else {
                memcpy(k, z, 32);
            }
            CK_ULONG vl = sizeof val;
            CK_RV r2 = (r1 == CKR_OK && zl == 32) ? kwp_open(k, blob + 65, 40, val, &vl) : r1;
            snprintf(what, sizeof what, "(E) %s opened apart: ECDH1_DERIVE gives Z, K, KWP the value (0x%lx 0x%lx)",
                     withkdf ? "CKD_SHA256_KDF" : "CKD_NULL", r1, r2);
            ok(r2 == CKR_OK && vl == 32 && memcmp(val, target, 32) == 0, what);
            vl = sizeof val;
            CK_RV r3 = unwrap_aes(m, epriv, blob, bl, val, &vl);
            snprintf(what, sizeof what, "(E) %s: C_UnwrapKey makes the key back (0x%lx)",
                     withkdf ? "CKD_SHA256_KDF" : "CKD_NULL", r3);
            ok(r3 == CKR_OK && vl == 32 && memcmp(val, target, 32) == 0, what);
        }
        /* (F) */
        char what[160];
        CK_BYTE blob[256]; CK_ULONG bl = sizeof blob;
        CK_ECDH_AES bad = { 256, CKD_NULL, 4, (CK_BYTE*)"abcd" };
        CK_MECHANISM bm = { CKM_ECDH_AES_KEY_WRAP, &bad, sizeof bad };
        CK_RV r1 = C_WrapKey(s, &bm, epub, tk, blob, &bl);
        bl = sizeof blob;
        CK_RV r2 = C_WrapKey(s, &em, rpub, tk, blob, &bl);
        bl = sizeof blob;
        CK_RV r3 = C_WrapKey(s, &rm, epub, tk, blob, &bl);
        bl = sizeof blob;
        CK_RV r4 = C_WrapKey(s, &em, epub, tk, blob, &bl);
        if (r4 == CKR_OK) { blob[bl - 1] ^= 1; r4 = unwrap_aes(&em, epriv, blob, bl, NULL, NULL); }
        snprintf(what, sizeof what,
                 "(F) ECDH-AES: CKD_NULL with data, RSA key, EC for RSA-AES, changed (0x%lx 0x%lx 0x%lx 0x%lx)",
                 r1, r2, r3, r4);
        ok(r1 == CKR_MECHANISM_PARAM_INVALID && r2 == CKR_WRAPPING_KEY_TYPE_INCONSISTENT
           && r3 == CKR_WRAPPING_KEY_TYPE_INCONSISTENT && r4 == CKR_WRAPPED_KEY_INVALID, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
