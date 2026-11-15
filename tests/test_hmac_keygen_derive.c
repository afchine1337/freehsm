/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_hmac_keygen_derive.c --- the HMAC key generators and the key
 * derivations by digest (2.8.0).
 *
 *   (G) each CKM_SHA*_KEY_GEN makes a key typed CKK_SHA*_HMAC of
 *       CKA_VALUE_LEN bytes, and its HMAC signs with it; 0 and 65 bytes are
 *       CKR_KEY_SIZE_RANGE; another CKA_KEY_TYPE is CKR_TEMPLATE_INCONSISTENT.
 *   (D) each *_KEY_DERIVATION, from a 32-byte generic secret of the bytes 1
 *       to 32: without a length, the key is the whole digest (generic
 *       secret); with CKA_VALUE_LEN 16, its first 16 bytes; SHAKE128 and
 *       SHAKE256 take the length from the template and refuse to go without
 *       one (CKR_TEMPLATE_INCOMPLETE); a length past the digest is
 *       CKR_ATTRIBUTE_VALUE_INVALID; a parameter is
 *       CKR_MECHANISM_PARAM_INVALID; an AES key from SHA-256 is the digest.
 *       The base key may be a generic secret or an HMAC-typed key; an AES
 *       base key is CKR_KEY_TYPE_INCONSISTENT.
 *       The expected values were computed with Python's hashlib, not with
 *       OpenSSL. Where NIST's rules apply (the nist-approved-only build,
 *       strict mode) the derivations are CKR_MECHANISM_INVALID.
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

#define CKR_OK                       0x000UL
#define CKR_ATTRIBUTE_VALUE_INVALID  0x013UL
#define CKR_KEY_SIZE_RANGE           0x062UL
#define CKR_KEY_TYPE_INCONSISTENT    0x063UL
#define CKR_MECHANISM_INVALID        0x070UL
#define CKR_MECHANISM_PARAM_INVALID  0x071UL
#define CKR_TEMPLATE_INCOMPLETE      0x0D0UL
#define CKR_TEMPLATE_INCONSISTENT    0x0D1UL
#define CKF_RW                       6UL
#define CKO_SECRET_KEY               4UL
#define CKK_GENERIC_SECRET           0x10UL
#define CKK_AES                      0x1FUL
#define CKA_CLASS                    0x000UL
#define CKA_TOKEN                    0x001UL
#define CKA_VALUE                    0x011UL
#define CKA_KEY_TYPE                 0x100UL
#define CKA_SENSITIVE                0x103UL
#define CKA_SIGN                     0x108UL
#define CKA_DERIVE                   0x10CUL
#define CKA_VALUE_LEN                0x161UL
#define CKA_EXTRACTABLE              0x162UL
#define CKM_RSA_PKCS                 0x001UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;

static size_t unhex(const char *h, CK_BYTE *out) {
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (CK_BYTE)v;
    }
    return n;
}

static CK_ULONG get_ulong(CK_OBJECT_HANDLE h, CK_ULONG type) {
    CK_ULONG v = 0xFFFFFFFFUL;
    CK_ATTRIBUTE a = { type, &v, sizeof v };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? v : 0xFFFFFFFFUL;
}

/* Derive from `base` with `mech`; tkt the key type asked (0: none), vlen the
 * CKA_VALUE_LEN asked (0: none). The value read back goes to out. */
static CK_RV derive(CK_ULONG mech, CK_OBJECT_HANDLE base, CK_ULONG tkt, CK_ULONG vlen,
                    void *param, CK_ULONG plen, CK_BYTE *out, CK_ULONG *ol) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[7] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_TOKEN, &no, 1 },
                          { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 } };
    CK_ULONG n = 4;
    if (tkt)  { t[n].type = CKA_KEY_TYPE;  t[n].pValue = &tkt;  t[n++].ulValueLen = sizeof tkt; }
    if (vlen) { t[n].type = CKA_VALUE_LEN; t[n].pValue = &vlen; t[n++].ulValueLen = sizeof vlen; }
    CK_MECHANISM m = { mech, param, plen };
    CK_OBJECT_HANDLE h = 0;
    CK_RV rv = C_DeriveKey(s, &m, base, t, n, &h);
    if (rv != CKR_OK) return rv;
    CK_ATTRIBUTE a = { CKA_VALUE, out, 128 };
    rv = C_GetAttributeValue(s, h, &a, 1);
    *ol = a.ulValueLen;
    return rv;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_GenerateKey); SYM(C_CreateObject); SYM(C_DeriveKey);
    SYM(C_GetAttributeValue); SYM(C_SignInit); SYM(C_Sign);
    if (!C_DeriveKey || !C_Sign) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("HMAC key generators and key derivation by digest\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "hmackdf", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    int nist = 1;
    {
        CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
        CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
        C_GetMechanismList(0, ml, &n);
        for (CK_ULONG i = 0; i < n; i++) if (ml[i] == CKM_RSA_PKCS) nist = 0;
        free(ml);
        const char *mode = getenv("FHSM_MODE");
        if (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips"))) nist = 1;
    }
    char what[128];
    CK_RV rv;

    /* (G) */
    static const struct { const char *name; CK_ULONG gen, ckk, hmac; } G[] = {
        { "SHA-1",       0x4003, 0x28, 0x221 }, { "SHA-224",     0x4004, 0x2E, 0x256 },
        { "SHA-256",     0x4005, 0x2B, 0x251 }, { "SHA-384",     0x4006, 0x2C, 0x261 },
        { "SHA-512",     0x4007, 0x2D, 0x271 }, { "SHA-512/224", 0x4008, 0x43, 0x049 },
        { "SHA-512/256", 0x4009, 0x44, 0x04D }, { "SHA3-224",    0x2B8,  0x36, 0x2B6 },
        { "SHA3-256",    0x2B3,  0x37, 0x2B1 }, { "SHA3-384",    0x2C3,  0x38, 0x2C1 },
        { "SHA3-512",    0x2D3,  0x39, 0x2D1 },
    };
    for (size_t i = 0; i < sizeof G / sizeof G[0]; i++) {
        CK_MECHANISM m = { G[i].gen, NULL, 0 };
        CK_ULONG vl = 32, zero = 0, big = 65, other = CKK_GENERIC_SECRET;
        CK_ATTRIBUTE t[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 },
                             { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_KEY_TYPE, &other, sizeof other } };
        CK_OBJECT_HANDLE k = 0;
        rv = C_GenerateKey(s, &m, t, 3, &k);
        snprintf(what, sizeof what, "(G) %s key generated, typed 0x%lx, 32 bytes (0x%lx)",
                 G[i].name, G[i].ckk, rv);
        ok(rv == CKR_OK && get_ulong(k, CKA_KEY_TYPE) == G[i].ckk
           && get_ulong(k, CKA_VALUE_LEN) == 32, what);
        CK_MECHANISM hm = { G[i].hmac, NULL, 0 };
        CK_BYTE mac[64]; CK_ULONG ml = sizeof mac;
        snprintf(what, sizeof what, "(G) %s: its HMAC signs with it", G[i].name);
        ok(rv == CKR_OK && C_SignInit(s, &hm, k) == CKR_OK
           && C_Sign(s, (CK_BYTE*)"m", 1, mac, &ml) == CKR_OK, what);
        t[2].pValue = &zero;
        CK_RV r0 = C_GenerateKey(s, &m, t, 3, &k);
        t[2].pValue = &big;
        CK_RV r65 = C_GenerateKey(s, &m, t, 3, &k);
        t[2].pValue = &vl;
        CK_RV rkt = C_GenerateKey(s, &m, t, 4, &k);
        snprintf(what, sizeof what, "(G) %s: 0 and 65 bytes SIZE_RANGE, CKK_GENERIC_SECRET INCONSISTENT",
                 G[i].name);
        ok(r0 == CKR_KEY_SIZE_RANGE && r65 == CKR_KEY_SIZE_RANGE
           && rkt == CKR_TEMPLATE_INCONSISTENT, what);
    }

    /* (D) */
    CK_BYTE bval[32];
    for (int i = 0; i < 32; i++) bval[i] = (CK_BYTE)(i + 1);
    CK_ULONG cls = CKO_SECRET_KEY, gkt = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE bt[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &gkt, sizeof gkt },
                          { CKA_TOKEN, &no, 1 }, { CKA_DERIVE, &yes, 1 },
                          { CKA_VALUE, bval, sizeof bval } };
    CK_OBJECT_HANDLE base = 0;
    if (C_CreateObject(s, bt, 5, &base) != CKR_OK) { fprintf(stderr, "base key\n"); return 2; }

    static const struct { const char *name; CK_ULONG mech, len; const char *hex; } D[] = {
        { "SHA-1",       0x392, 20, "4c9b68754cc4c6a52c2871b90740059372385833" },
        { "SHA-224",     0x396, 28, "835fed2dbe56c7d6adab737be5e45506b0fa9e5e6ff4e99cbcc814c5" },
        { "SHA-256",     0x393, 32, "ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9" },
        { "SHA-384",     0x394, 48, "79a017feef31127390e00e7bb6cb0e5be29e71fc6e079b2f28004b53068fa336d922a4404d8065339eebd0eefba39b7f" },
        { "SHA-512",     0x395, 64, "77788f1a0cea001a2631dae5d05dbd062008d5b30f50b9e29beb2a7822289004573dfc9b6ffeb1c786a16349e70f9836876a743c31c0a7a2a70727a852eec372" },
        { "SHA-512/224", 0x04B, 28, "5c9a24b3f0d34ec1945f2af0a51d2388c7ac8214302b5820ad8f0bf0" },
        { "SHA-512/256", 0x04F, 32, "86d447c968b3c8ee2c5eb0174c236d7d38b15f14fa4dc3415d5f311739e15b08" },
        { "SHA3-224",    0x398, 28, "7201e5c8a92380577c3d537c9d291e6977d252d20cb9f6d2f17ca595" },
        { "SHA3-256",    0x397, 32, "08d76bb3d477d6f3a5f26cb66c691486547acf9bbac6cfabfba30784c815ae45" },
        { "SHA3-384",    0x399, 48, "8240296acdd8bd0fd8df7dc60e10cb8bdd9c8c5689c4ec68173d997857ee312ff83932e34a6558144179a2973d3e6362" },
        { "SHA3-512",    0x39A, 64, "340e03d7eb46e5568ba4ec3e48c3805d96015ba4108b3118707b9f314b0aa6deb7757d0d158acfc6490f853b251965bee120158a4b0fe7080164e9925beef09c" },
        { "SHAKE128",    0x39B, 0,  "5d52e8465ab88e1779801a3af13071dddbbc5fd194bb6b4e29d2fe452e584ba867e0bbd3324d760c" },
        { "SHAKE256",    0x39C, 0,  "f6a704e0fa1de28f681dd2fb0835391aadd2f114b6521c7bf69fc4f9e5de4ffebf4c82fc872d7c6f" },
    };
    for (size_t i = 0; i < sizeof D / sizeof D[0]; i++) {
        CK_BYTE want[64], got[128];
        size_t wl = unhex(D[i].hex, want);
        CK_ULONG gl = 0;
        if (nist) {
            rv = derive(D[i].mech, base, 0, 16, NULL, 0, got, &gl);
            snprintf(what, sizeof what, "(D) %s: not offered where NIST's rules apply (0x%lx)", D[i].name, rv);
            ok(rv == CKR_MECHANISM_INVALID, what);
            continue;
        }
        if (D[i].len) {
            rv = derive(D[i].mech, base, 0, 0, NULL, 0, got, &gl);
            snprintf(what, sizeof what, "(D) %s: no length, the whole digest (0x%lx, %lu bytes)",
                     D[i].name, rv, gl);
            ok(rv == CKR_OK && gl == D[i].len && gl == wl && memcmp(got, want, wl) == 0, what);
            rv = derive(D[i].mech, base, 0, D[i].len + 1, NULL, 0, got, &gl);
            snprintf(what, sizeof what, "(D) %s: %lu bytes, past the digest: VALUE_INVALID (0x%lx)",
                     D[i].name, D[i].len + 1, rv);
            ok(rv == CKR_ATTRIBUTE_VALUE_INVALID, what);
        } else {
            rv = derive(D[i].mech, base, 0, 0, NULL, 0, got, &gl);
            snprintf(what, sizeof what, "(D) %s: no length: TEMPLATE_INCOMPLETE (0x%lx)", D[i].name, rv);
            ok(rv == CKR_TEMPLATE_INCOMPLETE, what);
            rv = derive(D[i].mech, base, 0, 40, NULL, 0, got, &gl);
            snprintf(what, sizeof what, "(D) %s: 40 bytes, the output's first 40 (0x%lx)", D[i].name, rv);
            ok(rv == CKR_OK && gl == 40 && memcmp(got, want, 40) == 0, what);
        }
        rv = derive(D[i].mech, base, 0, 16, NULL, 0, got, &gl);
        snprintf(what, sizeof what, "(D) %s: 16 bytes, the digest's first 16 (0x%lx)", D[i].name, rv);
        ok(rv == CKR_OK && gl == 16 && memcmp(got, want, 16) == 0, what);
        CK_ULONG junk = 1;
        rv = derive(D[i].mech, base, 0, 16, &junk, sizeof junk, got, &gl);
        snprintf(what, sizeof what, "(D) %s: a parameter: PARAM_INVALID (0x%lx)", D[i].name, rv);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, what);
    }
    if (!nist) {
        CK_BYTE want[32], got[128]; CK_ULONG gl = 0;
        unhex(D[2].hex, want);
        rv = derive(0x393, base, CKK_AES, 0, NULL, 0, got, &gl);
        snprintf(what, sizeof what, "(D) SHA-256 to an AES key: AES-256, the digest (0x%lx)", rv);
        ok(rv == CKR_OK && gl == 32 && memcmp(got, want, 32) == 0, what);

        /* The same bytes as a CKK_SHA256_HMAC key derive the same; as an
         * AES key they are refused. */
        CK_ULONG hkt = 0x2BUL, akt = CKK_AES;
        bt[1].pValue = &hkt;
        CK_OBJECT_HANDLE hbase = 0;
        rv = C_CreateObject(s, bt, 5, &hbase);
        if (rv == CKR_OK) rv = derive(0x393, hbase, 0, 0, NULL, 0, got, &gl);
        snprintf(what, sizeof what, "(D) SHA-256 from a CKK_SHA256_HMAC base: the digest (0x%lx)", rv);
        ok(rv == CKR_OK && gl == 32 && memcmp(got, want, 32) == 0, what);
        bt[1].pValue = &akt;
        CK_OBJECT_HANDLE abase = 0;
        rv = C_CreateObject(s, bt, 5, &abase);
        if (rv == CKR_OK) rv = derive(0x393, abase, 0, 0, NULL, 0, got, &gl);
        snprintf(what, sizeof what, "(D) SHA-256 from an AES base: KEY_TYPE_INCONSISTENT (0x%lx)", rv);
        ok(rv == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
