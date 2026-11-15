/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_chacha20_poly1305.c --- CKM_CHACHA20, CKM_POLY1305 and their key
 * generators, CKK_CHACHA20 and CKK_POLY1305 keys (2.8.0).
 *
 *   (V) ChaCha20: RFC 8439 2.4.2 (32-bit counter at 1, 96-bit nonce, 114
 *       bytes); the 64-bit counter and nonce layout at counter 0, and at
 *       0xFFFFFFFF over 130 bytes, where the counter carries into its high
 *       word; the 32-bit counter at 0xFFFFFFFF for its last block. Through
 *       C_Encrypt, C_Decrypt, and both in parts of 5 bytes and the rest.
 *   (C) the 32-bit counter does not wrap: 65 bytes from 0xFFFFFFFF is
 *       CKR_DATA_LEN_RANGE, single-part and in parts.
 *   (M) Poly1305: RFC 8439 2.5.2, the empty message (the tag is s) and 100
 *       bytes; C_Sign, in parts, C_Verify, in parts; a changed message and
 *       a short tag are CKR_SIGNATURE_INVALID.
 *   (G) both key generators make 32-byte keys of their type; CKA_VALUE_LEN
 *       16 is CKR_TEMPLATE_INCONSISTENT. A generated ChaCha20 key round-trips.
 *   (P) CK_CHACHA20_PARAMS: no parameter, a 32-bit counter with a 64-bit
 *       nonce, no nonce: CKR_MECHANISM_PARAM_INVALID.
 *   (K) a 16-byte CKK_CHACHA20 import is CKR_ATTRIBUTE_VALUE_INVALID; an AES
 *       key under CKM_CHACHA20 and a ChaCha20 key under CKM_POLY1305 are
 *       CKR_KEY_TYPE_INCONSISTENT.
 *   (N) where NIST's rules apply, the mechanisms are refused, and the
 *       nist-approved-only build does not list them.
 * The expected values come from a pure-Python ChaCha20 and Poly1305 that
 * reproduce RFC 8439's block, encryption and Poly1305 vectors; not from
 * OpenSSL.
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
typedef struct { CK_BYTE *pBlockCounter; CK_ULONG blockCounterBits;
                 CK_BYTE *pNonce; CK_ULONG ulNonceBits; } CK_CHACHA20_PARAMS;

#define CKR_OK                         0x000UL
#define CKR_ATTRIBUTE_VALUE_INVALID    0x013UL
#define CKR_DATA_LEN_RANGE             0x021UL
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKR_SIGNATURE_INVALID          0x0C0UL
#define CKR_TEMPLATE_INCONSISTENT      0x0D1UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_AES                        0x1FUL
#define CKK_CHACHA20                   0x33UL
#define CKK_POLY1305                   0x34UL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_DECRYPT                    0x105UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_VALUE_LEN                  0x161UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_CHACHA20_KEY_GEN           0x1225UL
#define CKM_CHACHA20                   0x1226UL
#define CKM_POLY1305_KEY_GEN           0x1227UL
#define CKM_POLY1305                   0x1228UL

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
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                              CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);

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

static CK_RV import(const CK_BYTE *v, CK_ULONG vl, CK_ULONG kt, CK_OBJECT_HANDLE *h) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 },
                         { CKA_DECRYPT, &yes, 1 }, { CKA_SIGN, &yes, 1 },
                         { CKA_VERIFY, &yes, 1 }, { CKA_VALUE, (void*)v, vl } };
    *h = 0;
    return C_CreateObject(s, t, 8, h);
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

static CK_RV one_shot(int enc, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                      const CK_BYTE *in, CK_ULONG il, CK_BYTE *out, CK_ULONG *ol) {
    CK_RV rv = enc ? C_EncryptInit(s, m, k) : C_DecryptInit(s, m, k);
    if (rv != CKR_OK) return rv;
    return enc ? C_Encrypt(s, (CK_BYTE*)in, il, out, ol) : C_Decrypt(s, (CK_BYTE*)in, il, out, ol);
}

static CK_RV in_parts(int enc, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                      const CK_BYTE *in, CK_ULONG il, CK_BYTE *out, CK_ULONG *ol) {
    CK_RV rv = enc ? C_EncryptInit(s, m, k) : C_DecryptInit(s, m, k);
    CK_ULONG cut = il < 5 ? il : 5, done = 0;
    CK_ULONG pieces[2] = { cut, il - cut }, off = 0;
    for (int i = 0; i < 2 && rv == CKR_OK; i++) {
        CK_ULONG l = 256;
        rv = enc ? C_EncryptUpdate(s, (CK_BYTE*)in + off, pieces[i], out + done, &l)
                 : C_DecryptUpdate(s, (CK_BYTE*)in + off, pieces[i], out + done, &l);
        off += pieces[i];
        done += l;
    }
    if (rv == CKR_OK) {
        CK_ULONG l = 256;
        rv = enc ? C_EncryptFinal(s, out + done, &l) : C_DecryptFinal(s, out + done, &l);
        done += l;
    }
    *ol = done;
    return rv;
}

static void vector(const char *name, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                   const CK_BYTE *pt, CK_ULONG pl, const char *cthex) {
    char what[128];
    CK_BYTE ct[256], out[512];
    size_t cl = unhex(cthex, ct);
    CK_ULONG ol = sizeof out;
    CK_RV rv = one_shot(1, m, k, pt, pl, out, &ol);
    snprintf(what, sizeof what, "%s: C_Encrypt, %lu bytes (0x%lx)", name, pl, rv);
    ok(rv == CKR_OK && ol == cl && memcmp(out, ct, cl) == 0, what);
    ol = sizeof out;
    rv = one_shot(0, m, k, ct, (CK_ULONG)cl, out, &ol);
    snprintf(what, sizeof what, "%s: C_Decrypt (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == pl && memcmp(out, pt, pl) == 0, what);
    rv = in_parts(1, m, k, pt, pl, out, &ol);
    snprintf(what, sizeof what, "%s: encrypt in parts (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == cl && memcmp(out, ct, cl) == 0, what);
    rv = in_parts(0, m, k, ct, (CK_ULONG)cl, out, &ol);
    snprintf(what, sizeof what, "%s: decrypt in parts (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == pl && memcmp(out, pt, pl) == 0, what);
}

static CK_RV mac(int parts, int verify, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                 const CK_BYTE *d, CK_ULONG n, CK_BYTE *tag, CK_ULONG *tl) {
    CK_RV rv = verify ? C_VerifyInit(s, m, k) : C_SignInit(s, m, k);
    if (rv != CKR_OK) return rv;
    CK_ULONG cut = n < 5 ? n : 5;
    if (!parts)
        return verify ? C_Verify(s, (CK_BYTE*)d, n, tag, *tl) : C_Sign(s, (CK_BYTE*)d, n, tag, tl);
    rv = verify ? C_VerifyUpdate(s, (CK_BYTE*)d, cut) : C_SignUpdate(s, (CK_BYTE*)d, cut);
    if (rv == CKR_OK)
        rv = verify ? C_VerifyUpdate(s, (CK_BYTE*)d + cut, n - cut)
                    : C_SignUpdate(s, (CK_BYTE*)d + cut, n - cut);
    if (rv == CKR_OK) rv = verify ? C_VerifyFinal(s, tag, *tl) : C_SignFinal(s, tag, tl);
    return rv;
}

static CK_RV generate(CK_ULONG mech, CK_ULONG vl, CK_OBJECT_HANDLE *h) {
    CK_MECHANISM m = { mech, NULL, 0 };
    CK_ATTRIBUTE t[] = { { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 },
                         { CKA_DECRYPT, &yes, 1 }, { CKA_VALUE_LEN, &vl, sizeof vl } };
    *h = 0;
    return C_GenerateKey(s, &m, t, vl ? 4 : 3, h);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_GenerateKey); SYM(C_GetAttributeValue);
    SYM(C_EncryptInit); SYM(C_Encrypt); SYM(C_EncryptUpdate); SYM(C_EncryptFinal);
    SYM(C_DecryptInit); SYM(C_Decrypt); SYM(C_DecryptUpdate); SYM(C_DecryptFinal);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_Verify); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    if (!C_VerifyFinal || !C_GenerateKey) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("ChaCha20 and Poly1305\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "chacha", 6);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const char *mode = getenv("FHSM_MODE");
    const int nist_build = !listed(CKM_RSA_PKCS);
    const int nist = nist_build || (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips")));

    CK_BYTE kv[32], pk[32], pt[130];
    for (int i = 0; i < 32; i++) { kv[i] = (CK_BYTE)i; pk[i] = (CK_BYTE)(0x40 + i); }
    for (int i = 0; i < 130; i++) pt[i] = (CK_BYTE)((i * 7 + 3) & 0xFF);
    CK_OBJECT_HANDLE ak = 0, ck = 0, pkh = 0;
    if (import(kv, 16, CKK_AES, &ak) != CKR_OK || import(kv, 32, CKK_CHACHA20, &ck) != CKR_OK
        || import(pk, 32, CKK_POLY1305, &pkh) != CKR_OK) {
        fprintf(stderr, "key import\n"); return 2;
    }

    /* (N) */
    if (nist) {
        char what[128];
        CK_OBJECT_HANDLE h = 0;
        CK_RV rg = generate(CKM_CHACHA20_KEY_GEN, 0, &h);
        CK_BYTE ctr[4] = { 0 }, nonce[12] = { 0 };
        CK_CHACHA20_PARAMS cp = { ctr, 32, nonce, 96 };
        CK_MECHANISM m = { CKM_CHACHA20, &cp, sizeof cp }, pm = { CKM_POLY1305, NULL, 0 };
        CK_RV re = C_EncryptInit(s, &m, ck), rs = C_SignInit(s, &pm, pkh);
        int any = listed(CKM_CHACHA20) || listed(CKM_POLY1305) || listed(CKM_CHACHA20_KEY_GEN)
                  || listed(CKM_POLY1305_KEY_GEN);
        ok(nist_build ? !any : 1, "(N) none listed in the nist build");
        snprintf(what, sizeof what, "(N) keygen, EncryptInit, SignInit: MECHANISM_INVALID (0x%lx 0x%lx 0x%lx)",
                 rg, re, rs);
        ok(rg == CKR_MECHANISM_INVALID && re == CKR_MECHANISM_INVALID && rs == CKR_MECHANISM_INVALID, what);
        C_Finalize(NULL);
        printf("\n%s\n", fails ? "FAILURES" : "all good");
        return fails ? 1 : 0;
    }
    ok(listed(CKM_CHACHA20) && listed(CKM_POLY1305) && listed(CKM_CHACHA20_KEY_GEN)
       && listed(CKM_POLY1305_KEY_GEN), "all four listed");

    /* (V) */
    {
        static const char ladies[] = "Ladies and Gentlemen of the class of '99: If I could offer "
                                     "you only one tip for the future, sunscreen would be it.";
        CK_BYTE c1[4] = { 1, 0, 0, 0 }, n96[12];
        unhex("000000000000004a00000000", n96);
        CK_CHACHA20_PARAMS cp = { c1, 32, n96, 96 };
        CK_MECHANISM m = { CKM_CHACHA20, &cp, sizeof cp };
        vector("(V) RFC 8439 2.4.2", &m, ck, (const CK_BYTE*)ladies, 114,
               "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab"
               "8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e"
               "52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");
    }
    CK_BYTE n64[8] = { 0, 1, 2, 3, 4, 5, 6, 7 }, n96b[12];
    for (int i = 0; i < 12; i++) n96b[i] = (CK_BYTE)i;
    {
        CK_BYTE c0[8] = { 0 };
        CK_CHACHA20_PARAMS cp = { c0, 64, n64, 64 };
        CK_MECHANISM m = { CKM_CHACHA20, &cp, sizeof cp };
        vector("(V) 64-bit counter at 0", &m, ck, pt, 100,
               "f492b091eeb3cb5db95216ab3355d2190c2d1c2b9994613747b315963f94161dd74ea5838c3d4b55"
               "2b60e074377752255689df31856a2e75d2848cfc8c4691a6fbca5a42f95ad860e5264d076b94fb4a"
               "bae4d46e06d0843ce2891968c1a75c2139f07aa4");
    }
    {
        CK_BYTE cff[8] = { 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 };
        CK_CHACHA20_PARAMS cp = { cff, 64, n64, 64 };
        CK_MECHANISM m = { CKM_CHACHA20, &cp, sizeof cp };
        vector("(V) 64-bit counter across 2^32", &m, ck, pt, 130,
               "a1b2c1530ca1567e4b5182c066bad2644593f1d2190720bc534e1d45c524181603520b56106a50ea"
               "ff1486e811b4e3740ef1d3ed38176ffeb2d42cadc3312ff7ec0063184570e8b13df777827ef5e707"
               "7deb66caa93b99af0a574f754a30412019bc1e322dd2c6200536697a0f10ed27c3ebae934bc64e86"
               "ee15e543153cfa4a484a");
    }
    CK_BYTE cff32[4] = { 0xff, 0xff, 0xff, 0xff };
    CK_CHACHA20_PARAMS last = { cff32, 32, n96b, 96 };
    CK_MECHANISM mlast = { CKM_CHACHA20, &last, sizeof last };
    vector("(V) 32-bit counter, its last block", &mlast, ck, pt, 64,
           "17e4c051d2468962c81bae54ae8ad513e770aed4e3018ae374b6f6f4b279bc85b831b74f83637678"
           "884b781a14ee9422df88d9eebe6d30e24221b113d5fad65e");

    /* (C) */
    {
        char what[128];
        CK_BYTE out[256]; CK_ULONG ol = sizeof out;
        CK_RV r1 = one_shot(1, &mlast, ck, pt, 65, out, &ol);
        ol = sizeof out;
        CK_RV r2 = in_parts(1, &mlast, ck, pt, 65, out, &ol);
        snprintf(what, sizeof what, "(C) 65 bytes from 0xFFFFFFFF: DATA_LEN_RANGE (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_DATA_LEN_RANGE && r2 == CKR_DATA_LEN_RANGE, what);
    }

    /* (M) */
    {
        CK_MECHANISM m = { CKM_POLY1305, NULL, 0 };
        CK_BYTE rk[32];
        unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", rk);
        CK_OBJECT_HANDLE rfc = 0;
        if (import(rk, 32, CKK_POLY1305, &rfc) != CKR_OK) { fprintf(stderr, "Poly1305 key\n"); return 2; }
        static const char cfrg[] = "Cryptographic Forum Research Group";
        static const struct { const char *name; int rfckey; const CK_BYTE *d; CK_ULONG n; const char *tag; } V[] = {
            { "RFC 8439 2.5.2", 1, (const CK_BYTE*)cfrg, 34, "a8061dc1305136c6c22b8baf0c0127a9" },
            { "empty message",  0, NULL, 0,  "505152535455565758595a5b5c5d5e5f" },
            { "100 bytes",      0, NULL, 100, "99e184095a1d4f0f72726b032c9465a3" },
        };
        for (size_t i = 0; i < 3; i++) {
            const CK_BYTE *d = V[i].d ? V[i].d : pt;
            CK_OBJECT_HANDLE k = V[i].rfckey ? rfc : pkh;
            CK_BYTE want[16];
            unhex(V[i].tag, want);
            for (int parts = 0; parts < 2; parts++) {
                char what[128];
                CK_BYTE tag[16]; CK_ULONG tl = sizeof tag;
                CK_RV rv = mac(parts, 0, &m, k, d, V[i].n, tag, &tl);
                snprintf(what, sizeof what, "(M) Poly1305 %s: sign%s (0x%lx)", V[i].name,
                         parts ? " in parts" : "", rv);
                ok(rv == CKR_OK && tl == 16 && memcmp(tag, want, 16) == 0, what);
                tl = 16;
                rv = mac(parts, 1, &m, k, d, V[i].n, want, &tl);
                snprintf(what, sizeof what, "(M) Poly1305 %s: verify%s (0x%lx)", V[i].name,
                         parts ? " in parts" : "", rv);
                ok(rv == CKR_OK, what);
            }
        }
        char what[128];
        CK_BYTE want[16], other[100];
        unhex("99e184095a1d4f0f72726b032c9465a3", want);
        memcpy(other, pt, 100); other[99] ^= 1;
        CK_ULONG tl = 16;
        CK_RV r1 = mac(0, 1, &m, pkh, other, 100, want, &tl);
        tl = 15;
        CK_RV r2 = mac(1, 1, &m, pkh, pt, 100, want, &tl);
        snprintf(what, sizeof what, "(M) changed message, 15-byte tag: SIGNATURE_INVALID (0x%lx 0x%lx)",
                 r1, r2);
        ok(r1 == CKR_SIGNATURE_INVALID && r2 == CKR_SIGNATURE_INVALID, what);
    }

    /* (G) */
    {
        char what[128];
        CK_OBJECT_HANDLE gc = 0, gp = 0, gx = 0;
        CK_RV r1 = generate(CKM_CHACHA20_KEY_GEN, 0, &gc);
        CK_RV r2 = generate(CKM_POLY1305_KEY_GEN, 32, &gp);
        CK_RV r3 = generate(CKM_CHACHA20_KEY_GEN, 16, &gx);
        CK_ULONG kt1 = 0, kt2 = 0, l1 = 0, l2 = 0;
        CK_ATTRIBUTE a1[] = { { CKA_KEY_TYPE, &kt1, sizeof kt1 }, { CKA_VALUE_LEN, &l1, sizeof l1 } };
        CK_ATTRIBUTE a2[] = { { CKA_KEY_TYPE, &kt2, sizeof kt2 }, { CKA_VALUE_LEN, &l2, sizeof l2 } };
        if (r1 == CKR_OK) r1 = C_GetAttributeValue(s, gc, a1, 2);
        if (r2 == CKR_OK) r2 = C_GetAttributeValue(s, gp, a2, 2);
        snprintf(what, sizeof what, "(G) CKK_CHACHA20 and CKK_POLY1305 of 32 bytes (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_OK && r2 == CKR_OK && kt1 == CKK_CHACHA20 && kt2 == CKK_POLY1305
           && l1 == 32 && l2 == 32, what);
        snprintf(what, sizeof what, "(G) CKA_VALUE_LEN 16: TEMPLATE_INCONSISTENT (0x%lx)", r3);
        ok(r3 == CKR_TEMPLATE_INCONSISTENT, what);
        CK_BYTE out[100], back[100]; CK_ULONG ol = sizeof out, bl = sizeof back;
        CK_RV rt = one_shot(1, &mlast, gc, pt, 50, out, &ol);
        if (rt == CKR_OK) rt = one_shot(0, &mlast, gc, out, ol, back, &bl);
        snprintf(what, sizeof what, "(G) a generated ChaCha20 key round-trips (0x%lx)", rt);
        ok(rt == CKR_OK && bl == 50 && memcmp(back, pt, 50) == 0 && memcmp(out, pt, 50) != 0, what);
    }

    /* (P) */
    {
        char what[128];
        CK_BYTE c0[8] = { 0 };
        CK_CHACHA20_PARAMS mixed = { c0, 32, n64, 64 }, nonull = { c0, 32, NULL, 96 };
        CK_MECHANISM m0 = { CKM_CHACHA20, NULL, 0 }, m1 = { CKM_CHACHA20, &mixed, sizeof mixed },
                     m2 = { CKM_CHACHA20, &nonull, sizeof nonull };
        CK_RV r0 = C_EncryptInit(s, &m0, ck), r1 = C_EncryptInit(s, &m1, ck),
              r2 = C_EncryptInit(s, &m2, ck);
        snprintf(what, sizeof what, "(P) none, 32/64, no nonce: PARAM_INVALID (0x%lx 0x%lx 0x%lx)",
                 r0, r1, r2);
        ok(r0 == CKR_MECHANISM_PARAM_INVALID && r1 == CKR_MECHANISM_PARAM_INVALID
           && r2 == CKR_MECHANISM_PARAM_INVALID, what);
    }

    /* (K) */
    {
        char what[128];
        CK_OBJECT_HANDLE h = 0;
        CK_RV r1 = import(kv, 16, CKK_CHACHA20, &h);
        snprintf(what, sizeof what, "(K) 16-byte CKK_CHACHA20: ATTRIBUTE_VALUE_INVALID (0x%lx)", r1);
        ok(r1 == CKR_ATTRIBUTE_VALUE_INVALID, what);
        CK_MECHANISM pm = { CKM_POLY1305, NULL, 0 };
        CK_RV r2 = C_EncryptInit(s, &mlast, ak), r3 = C_SignInit(s, &pm, ck);
        snprintf(what, sizeof what, "(K) AES key, ChaCha20 key for Poly1305: KEY_TYPE_INCONSISTENT (0x%lx 0x%lx)",
                 r2, r3);
        ok(r2 == CKR_KEY_TYPE_INCONSISTENT && r3 == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
