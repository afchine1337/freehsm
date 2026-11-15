/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_des2_keys.c --- CKM_DES2_KEY_GEN and CKK_DES2 keys under the DES3
 * mechanisms (2.8.0).
 *
 *   (G) CKM_DES2_KEY_GEN makes a 16-byte CKK_DES2 key, CKA_VALUE_LEN 24 is
 *       CKR_TEMPLATE_INCONSISTENT, and C_GetMechanismInfo says 16..16. The
 *       DES2 and DES3 generators set odd parity on every byte.
 *   (E) a DES2 key K1 K2 gives what the DES3 key K1 K2 K1 gives, under
 *       DES3_ECB, DES3_CBC and DES3_CBC_PAD (single-part and in parts),
 *       DES3_CMAC and DES3_MAC (single-part and in parts), and
 *       DES3_ECB_ENCRYPT_DATA -- SP 800-67 keying option 2, which is how
 *       PKCS#11 has the DES3 mechanisms take a double-length key. The DES3
 *       paths were checked against SP 800-67 in test_des3_modes and
 *       test_des3_mac_family.
 *   (K) C_CreateObject of a CKK_DES2 key of 24 bytes, or a CKK_DES3 key of
 *       16, is CKR_ATTRIBUTE_VALUE_INVALID; a DES2 key under AES_ECB is
 *       CKR_KEY_TYPE_INCONSISTENT.
 *   (N) the nist-approved-only build does not list CKM_DES2_KEY_GEN, and
 *       refuses it.
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
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize; CK_FLAGS flags; } CK_MECHANISM_INFO;
typedef struct { CK_BYTE *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;

#define CKR_OK                         0x000UL
#define CKR_ATTRIBUTE_VALUE_INVALID    0x013UL
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_TEMPLATE_INCONSISTENT      0x0D1UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_DES2                       0x14UL
#define CKK_DES3                       0x15UL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_DECRYPT                    0x105UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_DERIVE                     0x10CUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKM_DES2_KEY_GEN               0x130UL
#define CKM_DES3_KEY_GEN               0x131UL
#define CKM_DES3_ECB                   0x132UL
#define CKM_DES3_CBC                   0x133UL
#define CKM_DES3_MAC                   0x134UL
#define CKM_DES3_CBC_PAD               0x136UL
#define CKM_DES3_CMAC                  0x138UL
#define CKM_AES_ECB                    0x1081UL
#define CKM_DES3_ECB_ENCRYPT_DATA      0x1102UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);
static CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_ULONG, CK_MECHANISM_INFO*);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                              CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;

static CK_RV import(const CK_BYTE *v, CK_ULONG vl, CK_ULONG kt, CK_OBJECT_HANDLE *h) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 },
                         { CKA_DECRYPT, &yes, 1 }, { CKA_SIGN, &yes, 1 },
                         { CKA_VERIFY, &yes, 1 }, { CKA_DERIVE, &yes, 1 },
                         { CKA_VALUE, (void*)v, vl } };
    *h = 0;
    return C_CreateObject(s, t, 9, h);
}

static int listed(CK_ULONG mech) {
    CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
    CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
    C_GetMechanismList(0, ml, &n);
    int found = 0;
    for (CK_ULONG i = 0; i < n; i++) if (ml[i] == mech) found = 1;
    free(ml);
    return found;
}

static CK_RV generate(CK_ULONG mech, CK_ULONG vl, CK_OBJECT_HANDLE *h) {
    CK_MECHANISM m = { mech, NULL, 0 };
    CK_ATTRIBUTE t[] = { { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 },
                         { CKA_EXTRACTABLE, &yes, 1 }, { CKA_VALUE_LEN, &vl, sizeof vl } };
    *h = 0;
    return C_GenerateKey(s, &m, t, vl ? 4 : 3, h);
}

static int odd_parity(const CK_BYTE *v, CK_ULONG n) {
    for (CK_ULONG i = 0; i < n; i++) {
        int ones = 0;
        for (CK_BYTE b = v[i]; b; b &= (CK_BYTE)(b - 1)) ones++;
        if (!(ones & 1)) return 0;
    }
    return 1;
}

/* Encrypt, single-part or in parts of 5 bytes and the rest. */
static CK_RV enc(int parts, CK_MECHANISM *m, CK_OBJECT_HANDLE k, const CK_BYTE *in, CK_ULONG il,
                 CK_BYTE *out, CK_ULONG *ol) {
    CK_RV rv = C_EncryptInit(s, m, k);
    if (rv != CKR_OK) return rv;
    if (!parts) return C_Encrypt(s, (CK_BYTE*)in, il, out, ol);
    CK_ULONG done = 0, l = 64;
    rv = C_EncryptUpdate(s, (CK_BYTE*)in, 5, out, &l);
    done += l; l = 64;
    if (rv == CKR_OK) rv = C_EncryptUpdate(s, (CK_BYTE*)in + 5, il - 5, out + done, &l);
    done += l; l = 64;
    if (rv == CKR_OK) rv = C_EncryptFinal(s, out + done, &l);
    *ol = done + l;
    return rv;
}

static CK_RV mac(int parts, CK_MECHANISM *m, CK_OBJECT_HANDLE k, const CK_BYTE *in, CK_ULONG il,
                 CK_BYTE *out, CK_ULONG *ol) {
    CK_RV rv = C_SignInit(s, m, k);
    if (rv != CKR_OK) return rv;
    if (!parts) return C_Sign(s, (CK_BYTE*)in, il, out, ol);
    rv = C_SignUpdate(s, (CK_BYTE*)in, 5);
    if (rv == CKR_OK) rv = C_SignUpdate(s, (CK_BYTE*)in + 5, il - 5);
    if (rv == CKR_OK) rv = C_SignFinal(s, out, ol);
    return rv;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_GetMechanismInfo); SYM(C_CreateObject); SYM(C_GenerateKey);
    SYM(C_GetAttributeValue); SYM(C_DeriveKey);
    SYM(C_EncryptInit); SYM(C_Encrypt); SYM(C_EncryptUpdate); SYM(C_EncryptFinal);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    if (!C_SignFinal || !C_DeriveKey || !C_GenerateKey) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("DES2 keys\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "des2", 4);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    /* (N) */
    if (!listed(CKM_DES3_KEY_GEN)) {
        char what[128];
        CK_OBJECT_HANDLE h = 0;
        CK_RV rv = generate(CKM_DES2_KEY_GEN, 0, &h);
        ok(!listed(CKM_DES2_KEY_GEN), "(N) CKM_DES2_KEY_GEN not listed");
        snprintf(what, sizeof what, "(N) C_GenerateKey: MECHANISM_INVALID (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_INVALID, what);
        C_Finalize(NULL);
        printf("\n%s\n", fails ? "FAILURES" : "all good");
        return fails ? 1 : 0;
    }
    ok(listed(CKM_DES2_KEY_GEN), "CKM_DES2_KEY_GEN listed");
    /* Strict and FIPS mode refuse the 3DES MACs and the derivation; the
     * ciphers and key generation follow the build, as before. */
    const char *mode = getenv("FHSM_MODE");
    const int strict = mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips"));

    /* (G) */
    {
        char what[128];
        CK_OBJECT_HANDLE h2 = 0, h3 = 0, hx = 0;
        CK_RV r2 = generate(CKM_DES2_KEY_GEN, 0, &h2);
        CK_RV r3 = generate(CKM_DES3_KEY_GEN, 24, &h3);
        CK_RV rx = generate(CKM_DES2_KEY_GEN, 24, &hx);
        CK_BYTE v2[32], v3[32];
        CK_ULONG kt = 0;
        CK_ATTRIBUTE a2[] = { { CKA_VALUE, v2, sizeof v2 }, { CKA_KEY_TYPE, &kt, sizeof kt } };
        CK_ATTRIBUTE a3[] = { { CKA_VALUE, v3, sizeof v3 } };
        CK_RV g2 = r2 == CKR_OK ? C_GetAttributeValue(s, h2, a2, 2) : r2;
        CK_RV g3 = r3 == CKR_OK ? C_GetAttributeValue(s, h3, a3, 1) : r3;
        snprintf(what, sizeof what, "(G) DES2: 16 bytes, CKK_DES2, odd parity (0x%lx 0x%lx)", r2, g2);
        ok(g2 == CKR_OK && a2[0].ulValueLen == 16 && kt == CKK_DES2 && odd_parity(v2, 16), what);
        snprintf(what, sizeof what, "(G) DES3: 24 bytes, odd parity (0x%lx 0x%lx)", r3, g3);
        ok(g3 == CKR_OK && a3[0].ulValueLen == 24 && odd_parity(v3, 24), what);
        snprintf(what, sizeof what, "(G) DES2 with CKA_VALUE_LEN 24: TEMPLATE_INCONSISTENT (0x%lx)", rx);
        ok(rx == CKR_TEMPLATE_INCONSISTENT, what);
        CK_MECHANISM_INFO mi; memset(&mi, 0, sizeof mi);
        CK_RV ri = C_GetMechanismInfo(0, CKM_DES2_KEY_GEN, &mi);
        snprintf(what, sizeof what, "(G) mechanism info %lu..%lu (0x%lx)",
                 mi.ulMinKeySize, mi.ulMaxKeySize, ri);
        ok(ri == CKR_OK && mi.ulMinKeySize == 16 && mi.ulMaxKeySize == 16, what);
    }

    /* (E) K1 K2 against K1 K2 K1. */
    CK_BYTE kv[24];
    static const CK_BYTE k1k2[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                                      0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01 };
    memcpy(kv, k1k2, 16); memcpy(kv + 16, k1k2, 8);
    CK_OBJECT_HANDLE d2 = 0, d3 = 0;
    if (import(k1k2, 16, CKK_DES2, &d2) != CKR_OK || import(kv, 24, CKK_DES3, &d3) != CKR_OK) {
        fprintf(stderr, "key import\n"); return 2;
    }
    CK_BYTE msg[29], iv[8] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    for (int i = 0; i < 29; i++) msg[i] = (CK_BYTE)((i * 13 + 1) & 0xFF);
    {
        static const struct { const char *name; CK_ULONG mech; int has_iv; CK_ULONG len; } C[] = {
            { "DES3_ECB",     CKM_DES3_ECB,     0, 24 },
            { "DES3_CBC",     CKM_DES3_CBC,     1, 24 },
            { "DES3_CBC_PAD", CKM_DES3_CBC_PAD, 1, 29 },
        };
        for (size_t i = 0; i < 3; i++)
            for (int parts = 0; parts < 2; parts++) {
                char what[128];
                CK_MECHANISM m = { C[i].mech, C[i].has_iv ? iv : NULL, C[i].has_iv ? 8UL : 0UL };
                CK_BYTE o2[64], o3[64]; CK_ULONG l2 = sizeof o2, l3 = sizeof o3;
                CK_RV r2 = enc(parts, &m, d2, msg, C[i].len, o2, &l2);
                CK_RV r3 = enc(parts, &m, d3, msg, C[i].len, o3, &l3);
                snprintf(what, sizeof what, "(E) %s%s: DES2 = DES3 K1K2K1 (0x%lx 0x%lx)",
                         C[i].name, parts ? " in parts" : "", r2, r3);
                ok(r2 == CKR_OK && r3 == CKR_OK && l2 == l3 && l2 > 0 && memcmp(o2, o3, l2) == 0, what);
            }
    }
    if (!strict) {
        static const struct { const char *name; CK_ULONG mech; } M[] = {
            { "DES3_CMAC", CKM_DES3_CMAC }, { "DES3_MAC", CKM_DES3_MAC },
        };
        for (size_t i = 0; i < 2; i++)
            for (int parts = 0; parts < 2; parts++) {
                char what[128];
                CK_MECHANISM m = { M[i].mech, NULL, 0 };
                CK_BYTE o2[16], o3[16]; CK_ULONG l2 = sizeof o2, l3 = sizeof o3;
                CK_RV r2 = mac(parts, &m, d2, msg, 29, o2, &l2);
                CK_RV r3 = mac(parts, &m, d3, msg, 29, o3, &l3);
                snprintf(what, sizeof what, "(E) %s%s: DES2 = DES3 K1K2K1 (0x%lx 0x%lx)",
                         M[i].name, parts ? " in parts" : "", r2, r3);
                ok(r2 == CKR_OK && r3 == CKR_OK && l2 == l3 && l2 > 0 && memcmp(o2, o3, l2) == 0, what);
            }
    }
    if (!strict) {
        char what[128];
        CK_KEY_DERIVATION_STRING_DATA sd = { msg, 16 };
        CK_MECHANISM m = { CKM_DES3_ECB_ENCRYPT_DATA, &sd, sizeof sd };
        CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET, vl = 16;
        CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                             { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 },
                             { CKA_EXTRACTABLE, &yes, 1 }, { CKA_VALUE_LEN, &vl, sizeof vl } };
        CK_OBJECT_HANDLE x2 = 0, x3 = 0;
        CK_RV r2 = C_DeriveKey(s, &m, d2, t, 6, &x2);
        CK_RV r3 = C_DeriveKey(s, &m, d3, t, 6, &x3);
        CK_BYTE v2[16], v3[16];
        CK_ATTRIBUTE a2 = { CKA_VALUE, v2, sizeof v2 }, a3 = { CKA_VALUE, v3, sizeof v3 };
        if (r2 == CKR_OK) r2 = C_GetAttributeValue(s, x2, &a2, 1);
        if (r3 == CKR_OK) r3 = C_GetAttributeValue(s, x3, &a3, 1);
        snprintf(what, sizeof what, "(E) DES3_ECB_ENCRYPT_DATA: DES2 = DES3 K1K2K1 (0x%lx 0x%lx)", r2, r3);
        ok(r2 == CKR_OK && r3 == CKR_OK && a2.ulValueLen == 16 && memcmp(v2, v3, 16) == 0, what);
    }

    /* (K) */
    {
        char what[128];
        CK_OBJECT_HANDLE h = 0;
        CK_RV r1 = import(kv, 24, CKK_DES2, &h);
        CK_RV r2 = import(k1k2, 16, CKK_DES3, &h);
        snprintf(what, sizeof what, "(K) DES2 of 24, DES3 of 16: ATTRIBUTE_VALUE_INVALID (0x%lx 0x%lx)",
                 r1, r2);
        ok(r1 == CKR_ATTRIBUTE_VALUE_INVALID && r2 == CKR_ATTRIBUTE_VALUE_INVALID, what);
        CK_MECHANISM aes = { CKM_AES_ECB, NULL, 0 };
        CK_RV r3 = C_EncryptInit(s, &aes, d2);
        snprintf(what, sizeof what, "(K) DES2 key under AES_ECB: KEY_TYPE_INCONSISTENT (0x%lx)", r3);
        ok(r3 == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
