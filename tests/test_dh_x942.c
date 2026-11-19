/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_dh_x942.c --- X9.42 Diffie-Hellman (2.8.0): CKM_X9_42_DH_KEY_PAIR_GEN
 * and CKM_X9_42_DH_DERIVE.
 *
 * On ffdhe2048 (RFC 7919) given with q = (p - 1) / 2:
 *   (G) two key pairs; CKA_PRIME, CKA_SUBPRIME and CKA_BASE as given on both
 *       halves, CKA_VALUE y.
 *   (D) CKD_NULL: the two parties' secrets agree, 256 bytes.
 *       CKD_SHA1_KDF_CONCATENATE with other info: they agree, and equal
 *       SHA-1(Z || 00000001 || info) || SHA-1(Z || 00000002 || info) cut to
 *       32 bytes, computed with C_Digest from the CKD_NULL secret.
 *   (F) CKD_NULL with other info, CKD_SHA1_KDF_ASN1, the concatenation KDF
 *       without CKA_VALUE_LEN, a peer y of 1; no CKA_SUBPRIME, a q that is
 *       not ffdhe2048's.
 *   (N) a (2048, 256) DSA-style group, not a named one: made where any group
 *       is allowed, CKR_DOMAIN_PARAMS_INVALID where NIST's rules apply or
 *       only the FIPS provider serves DH.
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
typedef struct { CK_ULONG kdf; CK_ULONG ulOtherInfoLen; CK_BYTE *pOtherInfo;
                 CK_ULONG ulPublicDataLen; CK_BYTE *pPublicData; } CK_X9_42_DH1_DERIVE_PARAMS;

#define CKR_OK                         0x000UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKR_TEMPLATE_INCOMPLETE        0x0D0UL
#define CKR_DOMAIN_PARAMS_INVALID      0x130UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_X9_42_DH                   0x04UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_DERIVE                     0x10CUL
#define CKA_PRIME                      0x130UL
#define CKA_SUBPRIME                   0x131UL
#define CKA_BASE                       0x132UL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_DSA_KEY_PAIR_GEN           0x0010UL
#define CKM_X9_42_DH_KEY_PAIR_GEN      0x0030UL
#define CKM_X9_42_DH_DERIVE            0x0031UL
#define CKM_SHA_1                      0x0220UL
#define CKD_NULL                       0x01UL
#define CKD_SHA1_KDF_ASN1              0x03UL
#define CKD_SHA1_KDF_CONCATENATE       0x04UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

/* RFC 7919 ffdhe2048: g = 2. */
static const CK_BYTE ffdhe2048_p[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xad, 0xf8, 0x54, 0x58,
    0xa2, 0xbb, 0x4a, 0x9a, 0xaf, 0xdc, 0x56, 0x20, 0x27, 0x3d, 0x3c, 0xf1,
    0xd8, 0xb9, 0xc5, 0x83, 0xce, 0x2d, 0x36, 0x95, 0xa9, 0xe1, 0x36, 0x41,
    0x14, 0x64, 0x33, 0xfb, 0xcc, 0x93, 0x9d, 0xce, 0x24, 0x9b, 0x3e, 0xf9,
    0x7d, 0x2f, 0xe3, 0x63, 0x63, 0x0c, 0x75, 0xd8, 0xf6, 0x81, 0xb2, 0x02,
    0xae, 0xc4, 0x61, 0x7a, 0xd3, 0xdf, 0x1e, 0xd5, 0xd5, 0xfd, 0x65, 0x61,
    0x24, 0x33, 0xf5, 0x1f, 0x5f, 0x06, 0x6e, 0xd0, 0x85, 0x63, 0x65, 0x55,
    0x3d, 0xed, 0x1a, 0xf3, 0xb5, 0x57, 0x13, 0x5e, 0x7f, 0x57, 0xc9, 0x35,
    0x98, 0x4f, 0x0c, 0x70, 0xe0, 0xe6, 0x8b, 0x77, 0xe2, 0xa6, 0x89, 0xda,
    0xf3, 0xef, 0xe8, 0x72, 0x1d, 0xf1, 0x58, 0xa1, 0x36, 0xad, 0xe7, 0x35,
    0x30, 0xac, 0xca, 0x4f, 0x48, 0x3a, 0x79, 0x7a, 0xbc, 0x0a, 0xb1, 0x82,
    0xb3, 0x24, 0xfb, 0x61, 0xd1, 0x08, 0xa9, 0x4b, 0xb2, 0xc8, 0xe3, 0xfb,
    0xb9, 0x6a, 0xda, 0xb7, 0x60, 0xd7, 0xf4, 0x68, 0x1d, 0x4f, 0x42, 0xa3,
    0xde, 0x39, 0x4d, 0xf4, 0xae, 0x56, 0xed, 0xe7, 0x63, 0x72, 0xbb, 0x19,
    0x0b, 0x07, 0xa7, 0xc8, 0xee, 0x0a, 0x6d, 0x70, 0x9e, 0x02, 0xfc, 0xe1,
    0xcd, 0xf7, 0xe2, 0xec, 0xc0, 0x34, 0x04, 0xcd, 0x28, 0x34, 0x2f, 0x61,
    0x91, 0x72, 0xfe, 0x9c, 0xe9, 0x85, 0x83, 0xff, 0x8e, 0x4f, 0x12, 0x32,
    0xee, 0xf2, 0x81, 0x83, 0xc3, 0xfe, 0x3b, 0x1b, 0x4c, 0x6f, 0xad, 0x73,
    0x3b, 0xb5, 0xfc, 0xbc, 0x2e, 0xc2, 0x20, 0x05, 0xc5, 0x8e, 0xf1, 0x83,
    0x7d, 0x16, 0x83, 0xb2, 0xc6, 0xf3, 0x4a, 0x26, 0xc1, 0xb2, 0xef, 0xfa,
    0x88, 0x6b, 0x42, 0x38, 0x61, 0x28, 0x5c, 0x97, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
};
/* A (2048, 256) FIPS 186-4 group, from OpenSSL's genpkey -genparam -algorithm DSA. */
static const CK_BYTE dsa_p[256] = {
    0xc7, 0xb1, 0x8f, 0x97, 0x7d, 0x60, 0x24, 0x99, 0xf0, 0x6e, 0x42, 0x82,
    0x07, 0x8e, 0xf3, 0x07, 0x16, 0x84, 0x1b, 0x7c, 0x29, 0xd4, 0xbe, 0xf3,
    0x27, 0x4d, 0x84, 0x8a, 0x38, 0x06, 0xfd, 0x04, 0x4c, 0x99, 0x12, 0xfc,
    0x0d, 0xf0, 0xc3, 0x98, 0x30, 0x96, 0x30, 0xcb, 0xe2, 0x39, 0x02, 0x13,
    0x24, 0x60, 0xd2, 0x22, 0xdd, 0xfe, 0x82, 0x07, 0xf7, 0xc1, 0x63, 0x12,
    0x3a, 0xbb, 0xb9, 0x10, 0xf9, 0x70, 0xc2, 0x05, 0x4b, 0x53, 0x7d, 0xc8,
    0xaa, 0x7f, 0x5c, 0x44, 0xe5, 0x12, 0x54, 0x76, 0x35, 0x02, 0xc9, 0x69,
    0x43, 0xcf, 0x89, 0xde, 0xe2, 0x6b, 0xe1, 0x58, 0x4a, 0x97, 0x93, 0x57,
    0x94, 0xb6, 0xd5, 0x27, 0x05, 0x66, 0xc9, 0x50, 0x50, 0xb6, 0x00, 0x58,
    0x84, 0xf5, 0x5f, 0x1c, 0xcd, 0xaa, 0xda, 0xee, 0x9e, 0x3f, 0x50, 0xf5,
    0xd6, 0x8b, 0x0c, 0x69, 0xa1, 0xb3, 0x09, 0x55, 0x20, 0x16, 0xae, 0x11,
    0x23, 0xbe, 0x1a, 0xc7, 0x56, 0x83, 0x2e, 0x9b, 0x1f, 0xc8, 0xa0, 0x70,
    0xc0, 0x9a, 0x89, 0xb5, 0x84, 0x89, 0xfe, 0xd2, 0x66, 0xa7, 0x98, 0x44,
    0x56, 0xe4, 0x53, 0xcb, 0x3b, 0x84, 0x73, 0x6c, 0x5a, 0x9f, 0x3a, 0x64,
    0xbf, 0x46, 0x48, 0x2a, 0x6d, 0xdd, 0x49, 0xef, 0xf1, 0x96, 0xd1, 0x0f,
    0x14, 0xc3, 0xa5, 0x80, 0xcc, 0x7e, 0x8b, 0x72, 0x09, 0xc0, 0xca, 0xda,
    0x15, 0xf8, 0xe5, 0xec, 0x84, 0xcd, 0x28, 0xa4, 0xab, 0x38, 0xd8, 0x57,
    0xc7, 0x0b, 0xf9, 0x5a, 0x83, 0xe4, 0x2e, 0x48, 0xd7, 0x24, 0x08, 0x63,
    0xf4, 0xec, 0xe1, 0x12, 0xc7, 0x95, 0x70, 0xe4, 0x69, 0x17, 0x71, 0x0e,
    0xc2, 0xb1, 0xda, 0xae, 0xf3, 0x27, 0xda, 0xca, 0xa0, 0xa9, 0x78, 0xee,
    0x82, 0x54, 0x3f, 0x7a, 0x80, 0x1b, 0x7b, 0xaa, 0x91, 0x8d, 0x03, 0x1f,
    0xd0, 0x2f, 0x87, 0x6d,
};
static const CK_BYTE dsa_q[32] = {
    0xe5, 0x1a, 0xa7, 0x3b, 0xda, 0x39, 0x84, 0x87, 0x2c, 0x21, 0x98, 0xfe,
    0x59, 0x22, 0xa0, 0xed, 0xff, 0x66, 0x31, 0x25, 0x03, 0x4c, 0x4f, 0xa1,
    0x2c, 0x94, 0x79, 0xd9, 0xc7, 0xe6, 0x97, 0xa3,
};
static const CK_BYTE dsa_g[256] = {
    0x35, 0x2f, 0xf1, 0x2a, 0xe4, 0xfa, 0xe6, 0x36, 0x6b, 0x80, 0xd3, 0x50,
    0x62, 0x3a, 0xe5, 0xcb, 0x8b, 0x1e, 0xee, 0x62, 0x93, 0xed, 0x51, 0xc3,
    0xa7, 0xbd, 0x0d, 0x68, 0x26, 0x56, 0x1a, 0xde, 0xa9, 0xe5, 0xfc, 0x96,
    0x62, 0x2e, 0x71, 0x9a, 0x10, 0x10, 0x7e, 0x0b, 0x13, 0x54, 0xc2, 0xc1,
    0xe0, 0xe1, 0xcc, 0xa5, 0x9e, 0x83, 0x83, 0xe8, 0x96, 0x57, 0xec, 0x49,
    0x37, 0xff, 0x59, 0xe8, 0x91, 0xc8, 0x7f, 0xf6, 0x38, 0x5c, 0xf8, 0xed,
    0x22, 0x3c, 0xc7, 0x56, 0xbb, 0x6c, 0x3b, 0x93, 0xb2, 0xdd, 0x76, 0xdc,
    0x96, 0xb8, 0x64, 0xd2, 0x15, 0x60, 0xdd, 0xb4, 0xf3, 0x4b, 0x83, 0xc4,
    0x8c, 0x51, 0xd2, 0xf2, 0x7f, 0x42, 0x7d, 0x7f, 0x45, 0xae, 0x4c, 0x35,
    0xf9, 0x79, 0x70, 0x05, 0xb3, 0x85, 0xc3, 0x4d, 0x49, 0x1e, 0x43, 0x1d,
    0xe3, 0x64, 0x0d, 0xd4, 0xdb, 0x82, 0x8d, 0xe0, 0x8a, 0xe1, 0x35, 0x38,
    0xce, 0x8f, 0xdb, 0xed, 0x20, 0x51, 0x44, 0x61, 0x1c, 0xc3, 0xcf, 0x84,
    0x2f, 0xb9, 0x3c, 0x84, 0xb6, 0xb7, 0xe6, 0x0d, 0x5f, 0xa4, 0x3b, 0xb1,
    0x54, 0x5f, 0x97, 0xdb, 0xe2, 0x90, 0x8f, 0x9b, 0x8b, 0x38, 0xce, 0xd6,
    0xf0, 0x3b, 0xa7, 0x8d, 0x78, 0x9c, 0x70, 0x80, 0x9a, 0xbc, 0x9e, 0x58,
    0x1c, 0x84, 0xb0, 0x51, 0x3f, 0x93, 0xdb, 0xa5, 0xb8, 0xd1, 0xf0, 0x60,
    0x94, 0x2d, 0x32, 0xd0, 0xf0, 0xa0, 0xc2, 0x6f, 0x42, 0xd8, 0xcc, 0x24,
    0x55, 0xe2, 0x98, 0x33, 0x21, 0x02, 0x1a, 0x68, 0x36, 0x4e, 0xe5, 0x01,
    0x42, 0x8b, 0xfa, 0x84, 0x5e, 0x29, 0x94, 0x2e, 0x90, 0x4a, 0xee, 0x4e,
    0xc8, 0x36, 0x36, 0xbd, 0xbc, 0x79, 0x34, 0x35, 0x7d, 0x89, 0x03, 0xdf,
    0xe9, 0x55, 0x28, 0x7d, 0x21, 0xe8, 0x39, 0xa2, 0xc5, 0x2d, 0x33, 0xde,
    0xff, 0x14, 0xab, 0x3e,
};

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);
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

/* A key pair on (p, q, g); with_q 0 leaves CKA_SUBPRIME out. */
static CK_RV gen(const CK_BYTE *p, CK_ULONG pl, const CK_BYTE *q, CK_ULONG ql, int with_q,
                 const CK_BYTE *g, CK_ULONG gl, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv) {
    CK_MECHANISM m = { CKM_X9_42_DH_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_PRIME, (void*)p, pl },
                          { CKA_BASE, (void*)g, gl }, { CKA_SUBPRIME, (void*)q, ql } };
    CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_DERIVE, &yes, 1 } };
    return C_GenerateKeyPair(s, &m, pt, with_q ? 4 : 3, vt, 2, pub, prv);
}

static CK_ULONG value_of(CK_OBJECT_HANDLE h, CK_BYTE *buf, CK_ULONG cap) {
    CK_ATTRIBUTE a = { CKA_VALUE, buf, cap };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? a.ulValueLen : 0;
}

static int attr_is(CK_OBJECT_HANDLE h, CK_ULONG type, const CK_BYTE *want, CK_ULONG wl) {
    CK_BYTE buf[512];
    CK_ATTRIBUTE a = { type, buf, sizeof buf };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK && a.ulValueLen == wl
           && !memcmp(buf, want, wl);
}

/* Derive from prv and the peer's y; len 0 asks no CKA_VALUE_LEN. */
static CK_RV derive(CK_OBJECT_HANDLE prv, CK_ULONG kdf, CK_BYTE *info, CK_ULONG il,
                    CK_BYTE *y, CK_ULONG yl, CK_ULONG len, CK_OBJECT_HANDLE *out) {
    CK_X9_42_DH1_DERIVE_PARAMS p = { kdf, il, info, yl, y };
    CK_MECHANISM m = { CKM_X9_42_DH_DERIVE, &p, sizeof p };
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 },
                         { CKA_EXTRACTABLE, &yes, 1 }, { CKA_VALUE_LEN, &len, sizeof len } };
    return C_DeriveKey(s, &m, prv, t, len ? 6 : 5, out);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue); SYM(C_DeriveKey);
    SYM(C_DigestInit); SYM(C_Digest);
    if (!C_GenerateKeyPair || !C_DeriveKey || !C_Digest) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("X9.42 Diffie-Hellman\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "x942", 4);
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
    const int any_group = !nist && listed(CKM_DSA_KEY_PAIR_GEN);
    char what[160];

    /* q = (p - 1) / 2 for a safe prime: p shifted right by one bit. */
    CK_BYTE q[256];
    for (int i = 0; i < 256; i++)
        q[i] = (CK_BYTE)((ffdhe2048_p[i] >> 1) | (i ? (ffdhe2048_p[i - 1] & 1) << 7 : 0));
    const CK_BYTE g2 = 2;

    /* --- (G) the key pairs ----------------------------------------------- */
    CK_OBJECT_HANDLE apub = 0, aprv = 0, bpub = 0, bprv = 0;
    CK_RV ra = gen(ffdhe2048_p, 256, q, 256, 1, &g2, 1, &apub, &aprv);
    CK_RV rb = gen(ffdhe2048_p, 256, q, 256, 1, &g2, 1, &bpub, &bprv);
    snprintf(what, sizeof what, "(G) two key pairs on ffdhe2048 with q (0x%lx 0x%lx)", ra, rb);
    ok(ra == CKR_OK && rb == CKR_OK && listed(CKM_X9_42_DH_KEY_PAIR_GEN)
       && listed(CKM_X9_42_DH_DERIVE), what);
    if (ra != CKR_OK || rb != CKR_OK) { C_Finalize(NULL); printf("\nFAILURES\n"); return 1; }
    ok(attr_is(apub, CKA_PRIME, ffdhe2048_p, 256) && attr_is(aprv, CKA_PRIME, ffdhe2048_p, 256)
       && attr_is(apub, CKA_SUBPRIME, q, 256) && attr_is(aprv, CKA_SUBPRIME, q, 256)
       && attr_is(apub, CKA_BASE, &g2, 1) && attr_is(aprv, CKA_BASE, &g2, 1),
       "(G) CKA_PRIME, CKA_SUBPRIME and CKA_BASE as given, on both halves");
    CK_BYTE ya[300], yb[300];
    CK_ULONG yal = value_of(apub, ya, sizeof ya), ybl = value_of(bpub, yb, sizeof yb);
    CK_ULONG kt = 0;
    CK_ATTRIBUTE ka = { CKA_KEY_TYPE, &kt, sizeof kt };
    CK_RV kr = C_GetAttributeValue(s, aprv, &ka, 1);
    snprintf(what, sizeof what, "(G) CKK_X9_42_DH, y of %lu and %lu bytes (0x%lx)", yal, ybl, kr);
    ok(kr == CKR_OK && kt == CKK_X9_42_DH && yal > 200 && yal <= 256 && ybl > 200 && ybl <= 256, what);

    /* --- (D) the agreement ----------------------------------------------- */
    CK_OBJECT_HANDLE sa = 0, sb = 0;
    CK_BYTE za[300], zb[300], ka32[64], kb32[64], info[32];
    for (int i = 0; i < 32; i++) info[i] = (CK_BYTE)(0xA5 ^ i);
    CK_RV d1 = derive(aprv, CKD_NULL, NULL, 0, yb, ybl, 0, &sa);
    CK_RV d2 = derive(bprv, CKD_NULL, NULL, 0, ya, yal, 0, &sb);
    CK_ULONG zal = d1 == CKR_OK ? value_of(sa, za, sizeof za) : 0;
    CK_ULONG zbl = d2 == CKR_OK ? value_of(sb, zb, sizeof zb) : 0;
    snprintf(what, sizeof what, "(D) CKD_NULL: both parties agree, 256 bytes (0x%lx 0x%lx)", d1, d2);
    ok(zal == 256 && zbl == 256 && !memcmp(za, zb, 256), what);

    d1 = derive(aprv, CKD_SHA1_KDF_CONCATENATE, info, 32, yb, ybl, 32, &sa);
    d2 = derive(bprv, CKD_SHA1_KDF_CONCATENATE, info, 32, ya, yal, 32, &sb);
    CK_ULONG l1 = d1 == CKR_OK ? value_of(sa, ka32, sizeof ka32) : 0;
    CK_ULONG l2 = d2 == CKR_OK ? value_of(sb, kb32, sizeof kb32) : 0;
    snprintf(what, sizeof what, "(D) CKD_SHA1_KDF_CONCATENATE: both agree, 32 bytes (0x%lx 0x%lx)", d1, d2);
    ok(l1 == 32 && l2 == 32 && !memcmp(ka32, kb32, 32), what);
    {
        CK_BYTE in[256 + 4 + 32], want[40];
        CK_MECHANISM dm = { CKM_SHA_1, NULL, 0 };
        /* C_Digest with SHA-1 is refused where NIST's rules apply (SHA-1 is
         * kept there for the KDF, not as a digest service): no independent
         * computation then. */
        if (C_DigestInit(s, &dm) != CKR_OK) {
            printf("  (D) SHA-1 digest not offered: KDF output not recomputed\n");
        } else {
            CK_BYTE scratch[20]; CK_ULONG sl = sizeof scratch;
            (void)C_Digest(s, (CK_BYTE*)"", 0, scratch, &sl);   /* end the probe */
            int good = zal == 256;
            for (int c = 1; good && c <= 2; c++) {
                memcpy(in, za, 256);
                in[256] = 0; in[257] = 0; in[258] = 0; in[259] = (CK_BYTE)c;
                memcpy(in + 260, info, 32);
                CK_ULONG dl = 20;
                good = C_DigestInit(s, &dm) == CKR_OK
                       && C_Digest(s, in, sizeof in, want + 20 * (c - 1), &dl) == CKR_OK && dl == 20;
            }
            ok(good && l1 == 32 && !memcmp(ka32, want, 32),
               "(D) the KDF is SHA-1(Z || counter || other info), by C_Digest");
        }
    }

    /* --- (F) refusals ---------------------------------------------------- */
    {
        CK_OBJECT_HANDLE h = 0;
        CK_BYTE one = 1;
        CK_RV f1 = derive(aprv, CKD_NULL, info, 32, yb, ybl, 0, &h);
        CK_RV f2 = derive(aprv, CKD_SHA1_KDF_ASN1, info, 32, yb, ybl, 32, &h);
        CK_RV f3 = derive(aprv, CKD_SHA1_KDF_CONCATENATE, info, 32, yb, ybl, 0, &h);
        CK_RV f4 = derive(aprv, CKD_NULL, NULL, 0, &one, 1, 0, &h);
        snprintf(what, sizeof what,
                 "(F) NULL with info, ASN1, no length, y = 1 (0x%lx 0x%lx 0x%lx 0x%lx)", f1, f2, f3, f4);
        ok(f1 == CKR_MECHANISM_PARAM_INVALID && f2 == CKR_MECHANISM_PARAM_INVALID
           && f3 == CKR_TEMPLATE_INCOMPLETE && f4 == CKR_MECHANISM_PARAM_INVALID, what);

        CK_OBJECT_HANDLE p1 = 0, p2 = 0;
        CK_BYTE q2[256];
        memcpy(q2, q, 256); q2[255] ^= 2;
        CK_RV k1 = gen(ffdhe2048_p, 256, q, 256, 0, &g2, 1, &p1, &p2);
        CK_RV k2 = gen(ffdhe2048_p, 256, q2, 256, 1, &g2, 1, &p1, &p2);
        snprintf(what, sizeof what, "(F) no CKA_SUBPRIME, a wrong q (0x%lx 0x%lx)", k1, k2);
        ok(k1 == CKR_TEMPLATE_INCOMPLETE && k2 == CKR_DOMAIN_PARAMS_INVALID, what);
    }

    /* --- (N) a group that is not a named one ----------------------------- */
    {
        CK_OBJECT_HANDLE p1 = 0, p2 = 0;
        CK_RV rv = gen(dsa_p, sizeof dsa_p, dsa_q, sizeof dsa_q, 1, dsa_g, sizeof dsa_g, &p1, &p2);
        snprintf(what, sizeof what, "(N) a (2048, 256) group: %s (0x%lx)",
                 any_group ? "made" : "CKR_DOMAIN_PARAMS_INVALID", rv);
        ok(any_group ? rv == CKR_OK : rv == CKR_DOMAIN_PARAMS_INVALID, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
