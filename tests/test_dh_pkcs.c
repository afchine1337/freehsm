/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_dh_pkcs.c --- PKCS #3 Diffie-Hellman (2.8.0): CKM_DH_PKCS_KEY_PAIR_GEN
 * and CKM_DH_PKCS_DERIVE.
 *
 * On ffdhe2048 (RFC 7919), a safe-prime group SP 800-56A rev. 3 approves:
 *   (G) two key pairs; CKA_PRIME and CKA_BASE as given on both halves,
 *       CKA_VALUE y, and CKA_VALUE_BITS within the 256 asked for one of them.
 *   (D) each party derives from its private key and the other's y: the two
 *       secrets agree, at 256 bytes (Z padded to p's length) and cut to 32,
 *       the cut being Z's trailing bytes.
 *   (F) a peer y of 1, of p - 1 and of p refused; a key pair without
 *       CKA_BASE, with an even p, with g = 1 refused.
 *   (N) the same p with g = 5, not a named group: made where any group is
 *       allowed, CKR_DOMAIN_PARAMS_INVALID where NIST's rules apply or only
 *       the FIPS provider serves DH.
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

#define CKR_OK                         0x000UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKR_TEMPLATE_INCOMPLETE        0x0D0UL
#define CKR_DOMAIN_PARAMS_INVALID      0x130UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_DH                         0x02UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_DERIVE                     0x10CUL
#define CKA_PRIME                      0x130UL
#define CKA_BASE                       0x132UL
#define CKA_VALUE_BITS                 0x160UL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_DSA_KEY_PAIR_GEN           0x0010UL
#define CKM_DH_PKCS_KEY_PAIR_GEN       0x0020UL
#define CKM_DH_PKCS_DERIVE             0x0021UL

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

/* A key pair on (p, g); with_base 0 leaves CKA_BASE out; vbits 0 leaves
 * CKA_VALUE_BITS out. */
static CK_RV gen(const CK_BYTE *p, CK_ULONG pl, const CK_BYTE *g, CK_ULONG gl, int with_base,
                 CK_ULONG vbits, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv) {
    CK_MECHANISM m = { CKM_DH_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_PRIME, (void*)p, pl },
                          { CKA_BASE, (void*)g, gl } };
    CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_DERIVE, &yes, 1 },
                          { CKA_VALUE_BITS, &vbits, sizeof vbits } };
    return C_GenerateKeyPair(s, &m, pt, with_base ? 3 : 2, vt, vbits ? 3 : 2, pub, prv);
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

/* Derive from prv with the peer value y; len 0 asks no CKA_VALUE_LEN. */
static CK_RV derive(CK_OBJECT_HANDLE prv, const CK_BYTE *y, CK_ULONG yl, CK_ULONG len,
                    CK_OBJECT_HANDLE *out) {
    CK_MECHANISM m = { CKM_DH_PKCS_DERIVE, (void*)y, yl };
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
    if (!C_GenerateKeyPair || !C_DeriveKey) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("PKCS #3 Diffie-Hellman\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "dh", 2);
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
    /* DSA is offered only where a provider other than the FIPS one serves
     * it; the same provider is the one that takes DH on any group. */
    const int any_group = !nist && listed(CKM_DSA_KEY_PAIR_GEN);
    const CK_BYTE g2 = 2;
    char what[160];

    /* --- (G) the key pairs ----------------------------------------------- */
    CK_OBJECT_HANDLE apub = 0, aprv = 0, bpub = 0, bprv = 0;
    CK_RV ra = gen(ffdhe2048_p, sizeof ffdhe2048_p, &g2, 1, 1, 256, &apub, &aprv);
    CK_RV rb = gen(ffdhe2048_p, sizeof ffdhe2048_p, &g2, 1, 1, 0, &bpub, &bprv);
    snprintf(what, sizeof what, "(G) two key pairs on ffdhe2048 (0x%lx 0x%lx)", ra, rb);
    ok(ra == CKR_OK && rb == CKR_OK && listed(CKM_DH_PKCS_KEY_PAIR_GEN) && listed(CKM_DH_PKCS_DERIVE), what);
    if (ra != CKR_OK || rb != CKR_OK) { C_Finalize(NULL); printf("\nFAILURES\n"); return 1; }
    ok(attr_is(apub, CKA_PRIME, ffdhe2048_p, sizeof ffdhe2048_p)
       && attr_is(aprv, CKA_PRIME, ffdhe2048_p, sizeof ffdhe2048_p)
       && attr_is(apub, CKA_BASE, &g2, 1) && attr_is(aprv, CKA_BASE, &g2, 1),
       "(G) CKA_PRIME and CKA_BASE as given, on both halves");
    CK_BYTE ya[300], yb[300];
    CK_ULONG yal = value_of(apub, ya, sizeof ya), ybl = value_of(bpub, yb, sizeof yb);
    CK_ULONG kt = 0, vb = 0;
    CK_ATTRIBUTE ka[] = { { CKA_KEY_TYPE, &kt, sizeof kt }, { CKA_VALUE_BITS, &vb, sizeof vb } };
    CK_RV kr = C_GetAttributeValue(s, aprv, ka, 2);
    snprintf(what, sizeof what, "(G) CKK_DH, y of %lu and %lu bytes, CKA_VALUE_BITS %lu of 256 (0x%lx)",
             yal, ybl, vb, kr);
    ok(kr == CKR_OK && kt == CKK_DH && yal > 200 && yal <= 256 && ybl > 200 && ybl <= 256
       && vb > 200 && vb <= 256, what);

    /* --- (D) the agreement ----------------------------------------------- */
    CK_OBJECT_HANDLE sa = 0, sb = 0, sa32 = 0, sb32 = 0;
    CK_BYTE za[300], zb[300], za32[64], zb32[64];
    CK_RV d1 = derive(aprv, yb, ybl, 0, &sa), d2 = derive(bprv, ya, yal, 0, &sb);
    CK_ULONG zal = d1 == CKR_OK ? value_of(sa, za, sizeof za) : 0;
    CK_ULONG zbl = d2 == CKR_OK ? value_of(sb, zb, sizeof zb) : 0;
    snprintf(what, sizeof what, "(D) both parties agree, 256 bytes (0x%lx 0x%lx, %lu %lu)", d1, d2, zal, zbl);
    ok(d1 == CKR_OK && d2 == CKR_OK && zal == 256 && zbl == 256 && !memcmp(za, zb, 256), what);
    d1 = derive(aprv, yb, ybl, 32, &sa32); d2 = derive(bprv, ya, yal, 32, &sb32);
    CK_ULONG l1 = d1 == CKR_OK ? value_of(sa32, za32, sizeof za32) : 0;
    CK_ULONG l2 = d2 == CKR_OK ? value_of(sb32, zb32, sizeof zb32) : 0;
    snprintf(what, sizeof what, "(D) cut to 32: equal, Z's trailing 32 bytes (0x%lx 0x%lx)", d1, d2);
    ok(l1 == 32 && l2 == 32 && !memcmp(za32, zb32, 32) && zal == 256 && !memcmp(za32, za + 224, 32), what);

    /* --- (F) refusals ---------------------------------------------------- */
    {
        CK_BYTE one = 1, pm1[256];
        memcpy(pm1, ffdhe2048_p, 256); pm1[255] -= 1;
        CK_OBJECT_HANDLE h = 0;
        CK_RV f1 = derive(aprv, &one, 1, 32, &h);
        CK_RV f2 = derive(aprv, pm1, 256, 32, &h);
        CK_RV f3 = derive(aprv, ffdhe2048_p, 256, 32, &h);
        snprintf(what, sizeof what, "(F) peer y = 1, p - 1, p (0x%lx 0x%lx 0x%lx)", f1, f2, f3);
        ok(f1 == CKR_MECHANISM_PARAM_INVALID && f2 == CKR_MECHANISM_PARAM_INVALID
           && f3 == CKR_MECHANISM_PARAM_INVALID, what);

        CK_OBJECT_HANDLE p1 = 0, p2 = 0;
        CK_BYTE peven[256];
        memcpy(peven, ffdhe2048_p, 256); peven[255] ^= 1;
        CK_RV k1 = gen(ffdhe2048_p, 256, &g2, 1, 0, 0, &p1, &p2);
        CK_RV k2 = gen(peven, 256, &g2, 1, 1, 0, &p1, &p2);
        CK_RV k3 = gen(ffdhe2048_p, 256, &one, 1, 1, 0, &p1, &p2);
        snprintf(what, sizeof what, "(F) no CKA_BASE, an even p, g = 1 (0x%lx 0x%lx 0x%lx)", k1, k2, k3);
        ok(k1 == CKR_TEMPLATE_INCOMPLETE && k2 == CKR_DOMAIN_PARAMS_INVALID
           && k3 == CKR_DOMAIN_PARAMS_INVALID, what);
    }

    /* --- (N) a group that is not a named one ----------------------------- */
    {
        const CK_BYTE g5 = 5;
        CK_OBJECT_HANDLE p1 = 0, p2 = 0;
        CK_RV rv = gen(ffdhe2048_p, sizeof ffdhe2048_p, &g5, 1, 1, 0, &p1, &p2);
        snprintf(what, sizeof what, "(N) ffdhe2048's p with g = 5: %s (0x%lx)",
                 any_group ? "made" : "CKR_DOMAIN_PARAMS_INVALID", rv);
        ok(any_group ? rv == CKR_OK : rv == CKR_DOMAIN_PARAMS_INVALID, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
