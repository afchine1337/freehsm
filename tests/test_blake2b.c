/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_blake2b.c --- the twenty BLAKE2b mechanisms (2.8.0): CKM_BLAKE2B_n,
 * _HMAC, _HMAC_GENERAL, _KEY_DERIVE and _KEY_GEN for n = 160, 256, 384,
 * 512.
 *
 *   (D) the digest of "" and "abc" at each size, single-part and in parts.
 *       BLAKE2b-n is not a truncation of BLAKE2b-512: the size is a
 *       parameter of the hash, so the four values differ throughout.
 *   (H) HMAC (RFC 2104) at each size, with a 20-byte key and with a
 *       131-byte key, longer than the 128-byte block so that it is hashed
 *       first: sign and verify, single-part and in parts; the GENERAL form
 *       at 10 bytes gives the leading 10; a changed message is
 *       CKR_SIGNATURE_INVALID.
 *   (K) KEY_DERIVE: the derived key's value is the digest of the base key.
 *   (G) KEY_GEN makes a key typed CKK_BLAKE2B_n_HMAC, which the HMAC takes.
 *   (N) where NIST's rules apply, or where the provider does not honour
 *       BLAKE2b's size parameter, none is listed or accepted.
 * The expected values come from CPython's hashlib.blake2b, its own
 * implementation, which gives RFC 7693 Appendix A's BLAKE2b-512("abc"); and
 * its hmac module over it. Not from OpenSSL.
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
#define CKA_SENSITIVE                  0x103UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_DERIVE                     0x10CUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_BLAKE2B_160                0x400CUL

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
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
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

static CK_OBJECT_HANDLE secret(const CK_BYTE *v, CK_ULONG vl) {
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 }, { CKA_VERIFY, &yes, 1 },
                         { CKA_DERIVE, &yes, 1 }, { CKA_VALUE, (void*)v, vl } };
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, 7, &h) == CKR_OK ? h : 0;
}

static CK_RV digest(int parts, CK_ULONG mech, const CK_BYTE *d, CK_ULONG n,
                    CK_BYTE *out, CK_ULONG *ol) {
    CK_MECHANISM m = { mech, NULL, 0 };
    CK_RV rv = C_DigestInit(s, &m);
    if (rv != CKR_OK) return rv;
    if (!parts) return C_Digest(s, (CK_BYTE*)d, n, out, ol);
    CK_ULONG cut = n < 1 ? n : 1;
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

/* The four sizes; each size's mechanisms are base, +1 HMAC, +2 GENERAL,
 * +3 KEY_DERIVE, +4 KEY_GEN. */
static const struct {
    unsigned bits; CK_ULONG base, ckk;
    const char *empty, *abc, *h1, *h2, *kd;
} B[] = {
    { 160, 0x400C, 0x3A,
      "3345524abf6bbe1809449224b5972c41790b6cf2",
      "384264f676f39536840523f284921cdc68b6846b",
      "8e52620843a0942dc68ff03ef437d379a361175e",
      "a975f4dd17d67931e2453d5a8a7253ba27277f0a",
      "b1b133b99f516e6c82ceda892ef5af50fa4b4e71" },
    { 256, 0x4011, 0x3B,
      "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
      "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
      "b6996ecae165cdb17a02becfbf442b5dee41c5075ded9a5763185cd68bd261d0",
      "f712793e6b982dff7007ab22c59d6502436a9bf2c4d48325bcbb554122795f40",
      "cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6" },
    { 384, 0x4016, 0x3C,
      "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100",
      "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4",
      "948364b074f4739bb1be6e7f8c918405f1f06c7a18a125534618269d57e337b67750ba54bd3d6456a59b6b9bb39a7601",
      "64ca6b71d818026afbc7107fbf63eee3f0a0b4a7ce865cdc75cf1ba09b6b3554fb34694eda1c257a09d4d0bb96e164b8",
      "7df0b7be6c29a965d6c3a8056cc72bf36dd8849eb73fc1f23a3aa1902b869e0c8ee99663887ea76893e239c9e45988f7" },
    { 512, 0x401B, 0x3D,
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
      "358a6a184924894fc34bee5680eedf57d84a37bb38832f288e3b27dc63a98cc8c91e76da476b508bc6b2d408a248857452906e4a20b48c6b4b55d2df0fe1dd24",
      "bc2df2a1070af7492e3fc3e29b29b1c8db5de2469c7d7e8db0e5e2cc3831bad6cbde06f8929102204d43004fd0bb0a83a671f816a3f08a4ba32e7d8e2f831479",
      "5c52920a7263e39d57920ca0cb752ac6d79a04fef8a7a216a1ecb7115ce06d89fd7d735bd6f4272555dba22c2d1c96e6352322c62c5630fde0f4777a76c3de2c" },
};

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_GenerateKey); SYM(C_DeriveKey); SYM(C_GetAttributeValue);
    SYM(C_DigestInit); SYM(C_Digest); SYM(C_DigestUpdate); SYM(C_DigestFinal);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_Verify); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);
    if (!C_VerifyFinal || !C_DigestFinal || !C_DeriveKey) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("BLAKE2b\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "blake2b", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const char *mode = getenv("FHSM_MODE");
    const int nist_build = !listed(CKM_RSA_PKCS);
    const int served = listed(CKM_BLAKE2B_160);
    const int nist = nist_build || !served
                     || (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips")));

    CK_BYTE k20[20], k131[131], kd[32];
    memset(k20, 0x0b, sizeof k20);
    for (int i = 0; i < 131; i++) k131[i] = (CK_BYTE)i;
    for (int i = 0; i < 32; i++) kd[i] = (CK_BYTE)i;
    CK_OBJECT_HANDLE h20 = secret(k20, 20), h131 = secret(k131, 131), hkd = secret(kd, 32);
    if (!h20 || !h131 || !hkd) { fprintf(stderr, "key import\n"); return 2; }

    /* (N) */
    if (nist) {
        char what[128];
        int any = 0;
        for (CK_ULONG m = 0x400C; m <= 0x401F; m++) if (listed(m)) any = 1;
        CK_MECHANISM dm = { CKM_BLAKE2B_160, NULL, 0 }, hm = { CKM_BLAKE2B_160 + 1, NULL, 0 };
        CK_RV r1 = C_DigestInit(s, &dm), r2 = C_SignInit(s, &hm, h20);
        ok(nist_build ? !any : 1, "(N) none of the twenty listed in the nist build");
        snprintf(what, sizeof what, "(N) C_DigestInit, C_SignInit: MECHANISM_INVALID (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_MECHANISM_INVALID && r2 == CKR_MECHANISM_INVALID, what);
        C_Finalize(NULL);
        printf("\n%s\n", fails ? "FAILURES" : "all good");
        return fails ? 1 : 0;
    }
    {
        int all = 1;
        for (CK_ULONG m = 0x400C; m <= 0x401F; m++) if (!listed(m)) all = 0;
        ok(all, "all twenty listed");
    }

    for (size_t i = 0; i < 4; i++) {
        const CK_ULONG n = B[i].bits / 8;
        char what[128];
        /* (D) */
        static const char *in[2] = { "", "abc" };
        for (int w = 0; w < 2; w++)
            for (int parts = 0; parts < 2; parts++) {
                CK_BYTE want[64], got[64]; CK_ULONG gl = sizeof got;
                unhex(w ? B[i].abc : B[i].empty, want);
                CK_RV rv = digest(parts, B[i].base, (const CK_BYTE*)in[w], (CK_ULONG)strlen(in[w]), got, &gl);
                snprintf(what, sizeof what, "(D) BLAKE2b-%u(\"%s\")%s (0x%lx)", B[i].bits, in[w],
                         parts ? " in parts" : "", rv);
                ok(rv == CKR_OK && gl == n && memcmp(got, want, n) == 0, what);
            }
        /* (H) */
        CK_MECHANISM hm = { B[i].base + 1, NULL, 0 };
        static const char *msg[2] = { "Hi There", "what do ya want for nothing?" };
        for (int w = 0; w < 2; w++) {
            CK_BYTE want[64]; unhex(w ? B[i].h2 : B[i].h1, want);
            CK_OBJECT_HANDLE k = w ? h131 : h20;
            CK_ULONG ml = (CK_ULONG)strlen(msg[w]);
            for (int parts = 0; parts < 2; parts++) {
                CK_BYTE tag[64]; CK_ULONG tl = sizeof tag;
                CK_RV rv = mac(parts, 0, &hm, k, (const CK_BYTE*)msg[w], ml, tag, &tl);
                snprintf(what, sizeof what, "(H) HMAC-BLAKE2b-%u, %u-byte key: sign%s (0x%lx)", B[i].bits,
                         w ? 131u : 20u, parts ? " in parts" : "", rv);
                ok(rv == CKR_OK && tl == n && memcmp(tag, want, n) == 0, what);
                tl = n;
                rv = mac(parts, 1, &hm, k, (const CK_BYTE*)msg[w], ml, want, &tl);
                snprintf(what, sizeof what, "(H) HMAC-BLAKE2b-%u, %u-byte key: verify%s (0x%lx)", B[i].bits,
                         w ? 131u : 20u, parts ? " in parts" : "", rv);
                ok(rv == CKR_OK, what);
            }
        }
        {
            CK_ULONG ten = 10;
            CK_MECHANISM gm = { B[i].base + 2, &ten, sizeof ten };
            CK_BYTE want[64], tag[64]; CK_ULONG tl = sizeof tag;
            unhex(B[i].h1, want);
            CK_RV rv = mac(1, 0, &gm, h20, (const CK_BYTE*)msg[0], 8, tag, &tl);
            CK_ULONG vl = n;
            CK_RV rv2 = mac(0, 1, &hm, h20, (const CK_BYTE*)"Hi there", 8, want, &vl);
            snprintf(what, sizeof what, "(H) %u: GENERAL 10 bytes in parts; changed message (0x%lx 0x%lx)",
                     B[i].bits, rv, rv2);
            ok(rv == CKR_OK && tl == 10 && memcmp(tag, want, 10) == 0 && rv2 == CKR_SIGNATURE_INVALID, what);
        }
        /* (K) */
        {
            CK_MECHANISM m = { B[i].base + 3, NULL, 0 };
            CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET;
            CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                                 { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 },
                                 { CKA_EXTRACTABLE, &yes, 1 } };
            CK_OBJECT_HANDLE d = 0;
            CK_BYTE want[64], got[64];
            CK_ATTRIBUTE a = { CKA_VALUE, got, sizeof got };
            unhex(B[i].kd, want);
            CK_RV rv = C_DeriveKey(s, &m, hkd, t, 5, &d);
            if (rv == CKR_OK) rv = C_GetAttributeValue(s, d, &a, 1);
            snprintf(what, sizeof what, "(K) BLAKE2B_%u_KEY_DERIVE: the digest of the base (0x%lx)",
                     B[i].bits, rv);
            ok(rv == CKR_OK && a.ulValueLen == n && memcmp(got, want, n) == 0, what);
        }
        /* (G) */
        {
            CK_MECHANISM m = { B[i].base + 4, NULL, 0 };
            CK_ULONG vl = 32;
            CK_ATTRIBUTE t[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 }, { CKA_VERIFY, &yes, 1 },
                                 { CKA_VALUE_LEN, &vl, sizeof vl } };
            CK_OBJECT_HANDLE g = 0;
            CK_RV rv = C_GenerateKey(s, &m, t, 4, &g);
            CK_ULONG kt = 0;
            CK_ATTRIBUTE a = { CKA_KEY_TYPE, &kt, sizeof kt };
            if (rv == CKR_OK) rv = C_GetAttributeValue(s, g, &a, 1);
            CK_BYTE tag[64]; CK_ULONG tl = sizeof tag;
            if (rv == CKR_OK) rv = mac(0, 0, &hm, g, (const CK_BYTE*)"abc", 3, tag, &tl);
            if (rv == CKR_OK) rv = mac(1, 1, &hm, g, (const CK_BYTE*)"abc", 3, tag, &tl);
            snprintf(what, sizeof what, "(G) BLAKE2B_%u_KEY_GEN: typed for its HMAC, which takes it (0x%lx)",
                     B[i].bits, rv);
            ok(rv == CKR_OK && kt == B[i].ckk && tl == n, what);
        }
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
