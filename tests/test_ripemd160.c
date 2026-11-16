/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_ripemd160.c --- CKM_RIPEMD160, CKM_RIPEMD160_HMAC,
 * CKM_RIPEMD160_HMAC_GENERAL and CKM_RIPEMD160_RSA_PKCS (2.8.0).
 *
 *   (D) the digest of "", "abc" and "message digest", the reference values
 *       of the RIPEMD-160 authors' page; single-part and in parts.
 *   (H) HMAC-RIPEMD160, RFC 2286 test cases 1 and 2, sign and verify,
 *       single-part and in parts; the GENERAL form at 10 bytes gives the
 *       leading 10; a changed message is CKR_SIGNATURE_INVALID.
 *   (R) an RSA-2048 signature verifies, and opened with the public key
 *       under CKM_RSA_X_509 it is 00 01 FF..FF 00, the RIPEMD-160
 *       DigestInfo, and the digest of the message (EMSA-PKCS1-v1_5).
 *   (N) where NIST's rules apply, or where the provider has no RIPEMD-160,
 *       none of the four is listed or accepted.
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
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_SIGNATURE_INVALID          0x0C0UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_MODULUS_BITS               0x121UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x0000UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_RSA_X_509                  0x0003UL
#define CKM_RIPEMD160_RSA_PKCS         0x0008UL
#define CKM_RIPEMD160                  0x0240UL
#define CKM_RIPEMD160_HMAC             0x0241UL
#define CKM_RIPEMD160_HMAC_GENERAL     0x0242UL

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
static CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM*);
static CK_RV (*C_Digest)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);

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

static int listed(CK_ULONG mech) {
    CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
    CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
    C_GetMechanismList(0, ml, &n);
    int found = 0;
    for (CK_ULONG i = 0; i < n; i++) if (ml[i] == mech) found = 1;
    free(ml);
    return found;
}

static CK_OBJECT_HANDLE hmac_key(const CK_BYTE *v, CK_ULONG vl) {
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 }, { CKA_VERIFY, &yes, 1 },
                         { CKA_VALUE, (void*)v, vl } };
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, 6, &h) == CKR_OK ? h : 0;
}

static CK_RV digest(int parts, const CK_BYTE *d, CK_ULONG n, CK_BYTE *out, CK_ULONG *ol) {
    CK_MECHANISM m = { CKM_RIPEMD160, NULL, 0 };
    CK_RV rv = C_DigestInit(s, &m);
    if (rv != CKR_OK) return rv;
    if (!parts) return C_Digest(s, (CK_BYTE*)d, n, out, ol);
    CK_ULONG cut = n < 2 ? n : 2;
    rv = C_DigestUpdate(s, (CK_BYTE*)d, cut);
    if (rv == CKR_OK) rv = C_DigestUpdate(s, (CK_BYTE*)d + cut, n - cut);
    if (rv == CKR_OK) rv = C_DigestFinal(s, out, ol);
    return rv;
}

static CK_RV mac(int parts, int verify, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                 const CK_BYTE *d, CK_ULONG n, CK_BYTE *tag, CK_ULONG *tl) {
    CK_RV rv = verify ? C_VerifyInit(s, m, k) : C_SignInit(s, m, k);
    if (rv != CKR_OK) return rv;
    CK_ULONG cut = n < 3 ? n : 3;
    if (!parts)
        return verify ? C_Verify(s, (CK_BYTE*)d, n, tag, *tl) : C_Sign(s, (CK_BYTE*)d, n, tag, tl);
    rv = verify ? C_VerifyUpdate(s, (CK_BYTE*)d, cut) : C_SignUpdate(s, (CK_BYTE*)d, cut);
    if (rv == CKR_OK)
        rv = verify ? C_VerifyUpdate(s, (CK_BYTE*)d + cut, n - cut)
                    : C_SignUpdate(s, (CK_BYTE*)d + cut, n - cut);
    if (rv == CKR_OK) rv = verify ? C_VerifyFinal(s, tag, *tl) : C_SignFinal(s, tag, tl);
    return rv;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_GenerateKeyPair);
    SYM(C_DigestInit); SYM(C_Digest); SYM(C_DigestUpdate); SYM(C_DigestFinal);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_Verify); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    SYM(C_EncryptInit); SYM(C_Encrypt);
    if (!C_VerifyFinal || !C_DigestFinal || !C_Encrypt) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("RIPEMD-160\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "ripemd", 6);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const char *mode = getenv("FHSM_MODE");
    const int nist_build = !listed(CKM_RSA_PKCS);
    const int served = listed(CKM_RIPEMD160);
    const int nist = nist_build || !served
                     || (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips")));

    /* (N) */
    if (nist) {
        char what[128];
        CK_BYTE k20[20]; memset(k20, 0x0b, sizeof k20);
        CK_OBJECT_HANDLE k = hmac_key(k20, 20);
        CK_MECHANISM dm = { CKM_RIPEMD160, NULL, 0 }, hm = { CKM_RIPEMD160_HMAC, NULL, 0 };
        CK_RV r1 = C_DigestInit(s, &dm), r2 = C_SignInit(s, &hm, k);
        int any = listed(CKM_RIPEMD160) || listed(CKM_RIPEMD160_HMAC)
                  || listed(CKM_RIPEMD160_HMAC_GENERAL) || listed(CKM_RIPEMD160_RSA_PKCS);
        ok(nist_build ? !any : 1, "(N) none of the four listed in the nist build");
        snprintf(what, sizeof what, "(N) C_DigestInit, C_SignInit: MECHANISM_INVALID (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_MECHANISM_INVALID && r2 == CKR_MECHANISM_INVALID, what);
        C_Finalize(NULL);
        printf("\n%s\n", fails ? "FAILURES" : "all good");
        return fails ? 1 : 0;
    }
    ok(listed(CKM_RIPEMD160_HMAC) && listed(CKM_RIPEMD160_HMAC_GENERAL)
       && listed(CKM_RIPEMD160_RSA_PKCS), "all four listed");

    /* (D) */
    static const struct { const char *in; const char *md; } D[] = {
        { "",               "9c1185a5c5e9fc54612808977ee8f548b2258d31" },
        { "abc",            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
        { "message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36" },
    };
    for (size_t i = 0; i < 3; i++)
        for (int parts = 0; parts < 2; parts++) {
            char what[128];
            CK_BYTE want[20], got[32]; CK_ULONG gl = sizeof got;
            unhex(D[i].md, want);
            CK_RV rv = digest(parts, (const CK_BYTE*)D[i].in, (CK_ULONG)strlen(D[i].in), got, &gl);
            snprintf(what, sizeof what, "(D) RIPEMD-160(\"%s\")%s (0x%lx)", D[i].in,
                     parts ? " in parts" : "", rv);
            ok(rv == CKR_OK && gl == 20 && memcmp(got, want, 20) == 0, what);
        }

    /* (H) */
    {
        CK_BYTE k1[20]; memset(k1, 0x0b, sizeof k1);
        CK_OBJECT_HANDLE h1 = hmac_key(k1, 20), h2 = hmac_key((const CK_BYTE*)"Jefe", 4);
        if (!h1 || !h2) { fprintf(stderr, "HMAC key import\n"); return 2; }
        static const struct { const char *name; int key; const char *d; const char *tag; } H[] = {
            { "RFC 2286 TC1", 1, "Hi There", "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668" },
            { "RFC 2286 TC2", 2, "what do ya want for nothing?", "dda6c0213a485a9e24f4742064a7f033b43c4069" },
        };
        CK_MECHANISM m = { CKM_RIPEMD160_HMAC, NULL, 0 };
        for (size_t i = 0; i < 2; i++) {
            CK_BYTE want[20]; unhex(H[i].tag, want);
            CK_OBJECT_HANDLE k = H[i].key == 1 ? h1 : h2;
            CK_ULONG n = (CK_ULONG)strlen(H[i].d);
            for (int parts = 0; parts < 2; parts++) {
                char what[128];
                CK_BYTE tag[32]; CK_ULONG tl = sizeof tag;
                CK_RV rv = mac(parts, 0, &m, k, (const CK_BYTE*)H[i].d, n, tag, &tl);
                snprintf(what, sizeof what, "(H) %s: sign%s (0x%lx)", H[i].name, parts ? " in parts" : "", rv);
                ok(rv == CKR_OK && tl == 20 && memcmp(tag, want, 20) == 0, what);
                tl = 20;
                rv = mac(parts, 1, &m, k, (const CK_BYTE*)H[i].d, n, want, &tl);
                snprintf(what, sizeof what, "(H) %s: verify%s (0x%lx)", H[i].name, parts ? " in parts" : "", rv);
                ok(rv == CKR_OK, what);
            }
        }
        char what[128];
        CK_ULONG ten = 10;
        CK_MECHANISM g = { CKM_RIPEMD160_HMAC_GENERAL, &ten, sizeof ten };
        CK_BYTE want[20], tag[32]; CK_ULONG tl = sizeof tag;
        unhex(H[1].tag, want);
        CK_RV rv = mac(0, 0, &g, h2, (const CK_BYTE*)H[1].d, (CK_ULONG)strlen(H[1].d), tag, &tl);
        snprintf(what, sizeof what, "(H) GENERAL, 10 bytes: the leading 10 (0x%lx)", rv);
        ok(rv == CKR_OK && tl == 10 && memcmp(tag, want, 10) == 0, what);
        tl = 20;
        rv = mac(0, 1, &m, h1, (const CK_BYTE*)"Hi there", 8, want, &tl);
        snprintf(what, sizeof what, "(H) a changed message: SIGNATURE_INVALID (0x%lx)", rv);
        ok(rv == CKR_SIGNATURE_INVALID, what);
    }

    /* (R) */
    {
        char what[128];
        CK_ULONG bits = 2048;
        CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_MODULUS_BITS, &bits, sizeof bits },
                              { CKA_VERIFY, &yes, 1 }, { CKA_ENCRYPT, &yes, 1 } };
        CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
        CK_MECHANISM gm = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE pub = 0, priv = 0;
        CK_RV rv = C_GenerateKeyPair(s, &gm, pt, 4, kt, 2, &pub, &priv);
        CK_MECHANISM m = { CKM_RIPEMD160_RSA_PKCS, NULL, 0 }, raw = { CKM_RSA_X_509, NULL, 0 };
        CK_BYTE msg[] = "RIPEMD-160 under RSA PKCS#1 v1.5", sig[256], em[256], h[32];
        CK_ULONG sl = sizeof sig, el = sizeof em, hl = sizeof h;
        if (rv == CKR_OK) rv = C_SignInit(s, &m, priv);
        if (rv == CKR_OK) rv = C_Sign(s, msg, sizeof msg - 1, sig, &sl);
        CK_RV rv2 = rv;
        if (rv2 == CKR_OK) rv2 = C_VerifyInit(s, &m, pub);
        if (rv2 == CKR_OK) rv2 = C_Verify(s, msg, sizeof msg - 1, sig, sl);
        snprintf(what, sizeof what, "(R) RSA-2048: sign and verify (0x%lx 0x%lx)", rv, rv2);
        ok(rv == CKR_OK && rv2 == CKR_OK, what);
        CK_RV rv3 = C_EncryptInit(s, &raw, pub);
        if (rv3 == CKR_OK) rv3 = C_Encrypt(s, sig, sl, em, &el);
        CK_RV rv4 = digest(0, msg, sizeof msg - 1, h, &hl);
        static const CK_BYTE di[15] = { 0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x24,0x03,0x02,0x01,
                                        0x05,0x00,0x04,0x14 };
        int enc_ok = rv3 == CKR_OK && rv4 == CKR_OK && el == 256 && em[0] == 0x00 && em[1] == 0x01;
        size_t pad_end = 256 - 20 - 15 - 1;
        for (size_t i = 2; enc_ok && i < pad_end; i++) if (em[i] != 0xFF) enc_ok = 0;
        enc_ok = enc_ok && em[pad_end] == 0x00 && memcmp(em + pad_end + 1, di, 15) == 0
                 && memcmp(em + 256 - 20, h, 20) == 0;
        snprintf(what, sizeof what, "(R) opened: 00 01 FF..FF 00, the RIPEMD-160 DigestInfo, H (0x%lx)", rv3);
        ok(enc_ok, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
