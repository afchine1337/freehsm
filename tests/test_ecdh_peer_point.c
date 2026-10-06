/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_ecdh_peer_point.c --- a bare peer point that looks like a DER wrapper.
 *
 *  CKM_ECDH1_DERIVE takes the peer's public point bare (0x04 || X || Y) or
 *  wrapped in a DER OCTET STRING (0x04 len || point). The module told them
 *  apart by the first two bytes: 0x04, then a length matching what followed.
 *  A bare P-256 point is 65 bytes and also begins with 0x04, and its second
 *  byte is X's first -- so when X began with 0x3F (63), 63 + 2 = 65 and the
 *  bare point was taken for a wrapper, cut by two bytes, and refused as
 *  CKR_ATTRIBUTE_VALUE_INVALID. One peer key in 256.
 *
 *  pkcs11-check met it by chance: TestEcdhDeriveTemplateEnforcement passed
 *  on 2026-09-29 and failed on 2026-10-06, the module unchanged on that path.
 *  This makes such a key on purpose, for P-256 (X[0] = 0x3F) and P-384
 *  (97 bytes, X[0] = 0x5F), and requires the derive to succeed with the bare
 *  point and with the wrapped one, and both to agree with OpenSSL.
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG kdf; CK_ULONG ulSharedDataLen; void *pSharedData;
                 CK_ULONG ulPublicDataLen; void *pPublicData; } CK_ECDH1_DERIVE_PARAMS;

#define CKR_OK              0UL
#define CKF_RW              6UL
#define CKA_CLASS           0x000UL
#define CKA_KEY_TYPE        0x100UL
#define CKA_VALUE           0x011UL
#define CKA_VALUE_LEN       0x161UL
#define CKA_SENSITIVE       0x103UL
#define CKA_EXTRACTABLE     0x162UL
#define CKA_DERIVE          0x10CUL
#define CKA_EC_PARAMS       0x180UL
#define CKA_EC_POINT        0x181UL
#define CKO_SECRET_KEY      4UL
#define CKK_GENERIC_SECRET  0x10UL
#define CKM_EC_KEY_PAIR_GEN 0x1040UL
#define CKM_ECDH1_DERIVE    0x1050UL
#define CKD_NULL            1UL

#define SO_PIN   "So-Pin-ecdh1"
#define USER_PIN "Us-Pin-ecdh1"

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,
                            CK_ULONG,CK_OBJECT_HANDLE*);

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

/* Derive with `point` as the peer's public data; the secret into `out`. */
static CK_RV derive(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE base, const CK_BYTE *point,
                    CK_ULONG len, CK_ULONG vlen, CK_BYTE *out) {
    CK_ECDH1_DERIVE_PARAMS p = { CKD_NULL, 0, NULL, len, (void *)point };
    CK_MECHANISM m = { CKM_ECDH1_DERIVE, &p, sizeof p };
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET;
    CK_BYTE f = 0, t = 1;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
        { CKA_VALUE_LEN, &vlen, sizeof vlen },
        { CKA_SENSITIVE, &f, 1 }, { CKA_EXTRACTABLE, &t, 1 },
    };
    CK_OBJECT_HANDLE k = 0;
    CK_RV rv = C_DeriveKey(s, &m, base, tmpl, 5, &k);
    if (rv != CKR_OK) return rv;
    CK_ATTRIBUTE v = { CKA_VALUE, out, vlen };
    return C_GetAttributeValue(s, k, &v, 1);
}

static void one_curve(CK_SESSION_HANDLE s, const char *name, const CK_BYTE *oid,
                      CK_ULONG oid_len, const char *group, size_t fb, CK_BYTE trap) {
    printf("\n[%s: a peer point whose X begins with 0x%02X]\n", name, trap);
    CK_BYTE t = 1;
    CK_ATTRIBUTE pub_t[] = { { CKA_EC_PARAMS, (void *)oid, oid_len }, { CKA_DERIVE, &t, 1 } };
    CK_ATTRIBUTE prv_t[] = { { CKA_DERIVE, &t, 1 } };
    CK_MECHANISM kg = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE pub = 0, base = 0;
    if (C_GenerateKeyPair(s, &kg, pub_t, 2, prv_t, 1, &pub, &base) != CKR_OK) {
        ok(0, "the module generates the base key pair"); return;
    }

    /* The base key's public point, for OpenSSL's side of the agreement. */
    CK_BYTE bp[160]; CK_ATTRIBUTE q = { CKA_EC_POINT, bp, sizeof bp };
    if (C_GetAttributeValue(s, pub, &q, 1) != CKR_OK) { ok(0, "CKA_EC_POINT read"); return; }
    const CK_BYTE *bpt = bp; size_t bpl = q.ulValueLen;
    if (bpl == 2 + 1 + 2 * fb) { bpt += 2; bpl -= 2; }

    /* A peer key with the trap byte, made by OpenSSL. */
    EVP_PKEY *peer = NULL;
    unsigned char *enc = NULL; size_t encl = 0;
    for (int tries = 0; tries < 20000; tries++) {
        EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", group);
        unsigned char *e2 = NULL;
        size_t l2 = k ? EVP_PKEY_get1_encoded_public_key(k, &e2) : 0;
        if (l2 == 1 + 2 * fb && e2[1] == trap) { peer = k; enc = e2; encl = l2; break; }
        OPENSSL_free(e2); EVP_PKEY_free(k);
    }
    ok(peer != NULL, "OpenSSL made a peer key with that first byte");
    if (!peer) return;

    CK_BYTE v_bare[66], v_wrap[66], v_ref[66];
    ok(derive(s, base, enc, (CK_ULONG)encl, (CK_ULONG)fb, v_bare) == CKR_OK,
       "the derive accepts the bare point");

    CK_BYTE wrapped[2 + 1 + 2 * 66];
    wrapped[0] = 0x04; wrapped[1] = (CK_BYTE)encl;
    memcpy(wrapped + 2, enc, encl);
    ok(derive(s, base, wrapped, (CK_ULONG)(encl + 2), (CK_ULONG)fb, v_wrap) == CKR_OK
       && memcmp(v_bare, v_wrap, fb) == 0,
       "and the same point in a DER OCTET STRING, to the same secret");

    /* OpenSSL's own agreement, from the peer's private key and the base's
     * public point. */
    EVP_PKEY *bk = EVP_PKEY_new();
    EVP_PKEY_CTX *c = NULL;
    size_t rl = sizeof v_ref;
    int good = bk && EVP_PKEY_copy_parameters(bk, peer) == 1
            && EVP_PKEY_set1_encoded_public_key(bk, bpt, bpl) == 1
            && (c = EVP_PKEY_CTX_new_from_pkey(NULL, peer, NULL)) != NULL
            && EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, bk) == 1
            && EVP_PKEY_derive(c, v_ref, &rl) == 1 && rl == fb
            && memcmp(v_ref, v_bare, fb) == 0;
    ok(good, "and it is the secret OpenSSL computes");
    EVP_PKEY_CTX_free(c); EVP_PKEY_free(bk);
    OPENSSL_free(enc); EVP_PKEY_free(peer);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_InitToken); SYM(C_OpenSession); SYM(C_Login);
    SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue);
    SYM(C_DeriveKey);
    if (!C_DeriveKey || !C_GenerateKeyPair) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("=== test_ecdh_peer_point : bare points that look wrapped ===\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "ecdhpt", 6);
    CK_SESSION_HANDLE s = 0;
    if (C_Initialize(NULL) || C_InitToken(0, (CK_BYTE *)SO_PIN, strlen(SO_PIN), label)
        || C_OpenSession(0, CKF_RW, NULL, NULL, &s)
        || C_Login(s, 0, (CK_BYTE *)SO_PIN, strlen(SO_PIN))
        || C_InitPIN(s, (CK_BYTE *)USER_PIN, strlen(USER_PIN))
        || C_Logout(s)
        || C_Login(s, 1, (CK_BYTE *)USER_PIN, strlen(USER_PIN))) {
        fprintf(stderr, "token setup failed\n"); return 2;
    }

    one_curve(s, "P-256", (const CK_BYTE *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07", 10,
              "P-256", 32, 0x3F);   /* 0x3F + 2 = 65, a bare P-256 point */
    one_curve(s, "P-384", (const CK_BYTE *)"\x06\x05\x2B\x81\x04\x00\x22", 7,
              "P-384", 48, 0x5F);   /* 0x5F + 2 = 97, a bare P-384 point */

    printf("\ntest_ecdh_peer_point : %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
