/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_ike_prf.c --- the IKE key derivations (2.8.0): CKM_IKE_PRF_DERIVE,
 * CKM_IKE1_PRF_DERIVE, CKM_IKE2_PRF_PLUS_DERIVE and
 * CKM_IKE1_EXTENDED_DERIVE, with HMAC-SHA-256 as the prf.
 *
 * Every output is checked against the prf computed here: C_Sign with
 * CKM_SHA256_HMAC under a key holding the prf's key -- another path of the
 * module than the one under test.
 *   (P) CKM_IKE_PRF_DERIVE: SKEYSEED = prf(Ni | Nr, g^ir), the key typed
 *       CKK_SHA256_HMAC; SKEYID = prf(pre-shared key, Ni | Nr); the IKEv2
 *       rekey, prf(SK_d, g^ir (new) | Ni | Nr). Refused: bDataAsKey with
 *       bRekey, a CKA_VALUE_LEN other than the prf's.
 *   (1) CKM_IKE1_PRF_DERIVE: SKEYID_d and SKEYID_a (RFC 2409 5), a value cut
 *       to 16 bytes. Refused: no CKA_KEY_TYPE, a length past the prf's.
 *   (2) CKM_IKE2_PRF_PLUS_DERIVE: prf+ of 100 bytes from data, of 40 from a
 *       key and data (RFC 7296 2.13, 2.17). Refused: no CKA_VALUE_LEN, more
 *       than 255 blocks.
 *   (E) CKM_IKE1_EXTENDED_DERIVE: SKEYID cut, K1 = prf(K, 0x00) expanded,
 *       and from g^xy and extra data (RFC 2409 appendix B, 5.5). Refused
 *       where NIST's rules apply.
 *   (F) a *_HMAC_GENERAL prf, an AES base key, an AES g^ir.
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
typedef struct { CK_ULONG prfMechanism; CK_BYTE bDataAsKey, bRekey; CK_BYTE *pNi; CK_ULONG ulNiLen;
                 CK_BYTE *pNr; CK_ULONG ulNrLen; CK_OBJECT_HANDLE hNewKey; } CK_IKE_PRF_DERIVE_PARAMS;
typedef struct { CK_ULONG prfMechanism; CK_BYTE bHasPrevKey; CK_OBJECT_HANDLE hKeygxy, hPrevKey;
                 CK_BYTE *pCKYi; CK_ULONG ulCKYiLen; CK_BYTE *pCKYr; CK_ULONG ulCKYrLen;
                 CK_BYTE keyNumber; } CK_IKE1_PRF_DERIVE_PARAMS;
typedef struct { CK_ULONG prfMechanism; CK_BYTE bHasKeygxy; CK_OBJECT_HANDLE hKeygxy;
                 CK_BYTE *pExtraData; CK_ULONG ulExtraDataLen; } CK_IKE1_EXTENDED_DERIVE_PARAMS;
typedef struct { CK_ULONG prfMechanism; CK_BYTE bHasSeedKey; CK_OBJECT_HANDLE hSeedKey;
                 CK_BYTE *pSeedData; CK_ULONG ulSeedDataLen; } CK_IKE2_PRF_PLUS_DERIVE_PARAMS;

#define CKR_OK                         0x000UL
#define CKR_ARGUMENTS_BAD              0x007UL
#define CKR_KEY_SIZE_RANGE             0x062UL
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKR_TEMPLATE_INCOMPLETE        0x0D0UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_AES                        0x1FUL
#define CKK_SHA256_HMAC                0x2BUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_SIGN                       0x108UL
#define CKA_DERIVE                     0x10CUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_SHA256_HMAC                0x0251UL
#define CKM_SHA256_HMAC_GENERAL        0x0252UL
#define CKM_IKE2_PRF_PLUS_DERIVE       0x402EUL
#define CKM_IKE_PRF_DERIVE             0x402FUL
#define CKM_IKE1_PRF_DERIVE            0x4030UL
#define CKM_IKE1_EXTENDED_DERIVE       0x4031UL

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
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);

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

/* A secret key of type kt holding v, readable, that derives and signs. */
static CK_OBJECT_HANDLE secret(CK_ULONG kt, const CK_BYTE *v, CK_ULONG vl) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 },
                         { CKA_DERIVE, &yes, 1 }, { CKA_SIGN, &yes, 1 }, { CKA_VALUE, (void*)v, vl } };
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, 8, &h) == CKR_OK ? h : 0;
}

static CK_ULONG value_of(CK_OBJECT_HANDLE h, CK_BYTE *buf, CK_ULONG cap) {
    CK_ATTRIBUTE a = { CKA_VALUE, buf, cap };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? a.ulValueLen : 0;
}

static CK_ULONG ulong_attr(CK_OBJECT_HANDLE h, CK_ULONG type) {
    CK_ULONG v = (CK_ULONG)-1;
    CK_ATTRIBUTE a = { type, &v, sizeof v };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? v : (CK_ULONG)-1;
}

/* prf(k, d), HMAC-SHA-256 by C_Sign under a key holding k. */
static int prf(const CK_BYTE *k, CK_ULONG kl, const CK_BYTE *d, CK_ULONG dl, CK_BYTE out[32]) {
    CK_OBJECT_HANDLE hk = secret(CKK_GENERIC_SECRET, k, kl);
    CK_MECHANISM m = { CKM_SHA256_HMAC, NULL, 0 };
    CK_ULONG ol = 32;
    return hk && C_SignInit(s, &m, hk) == CKR_OK && C_Sign(s, (CK_BYTE*)d, dl, out, &ol) == CKR_OK
           && ol == 32;
}

/* Concatenation into a buffer: cat(buf, &len, p, n). */
static void cat(CK_BYTE *buf, CK_ULONG *len, const CK_BYTE *p, CK_ULONG n) {
    memcpy(buf + *len, p, n); *len += n;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_GetAttributeValue); SYM(C_DeriveKey);
    SYM(C_SignInit); SYM(C_Sign);
    if (!C_DeriveKey || !C_Sign) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("IKE key derivation\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "ike", 3);
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

    CK_BYTE gir[32], psk[24], ni[16], nr[16], ckyi[8], ckyr[8], aesv[16];
    for (int i = 0; i < 32; i++) gir[i] = (CK_BYTE)(0xA0 ^ (i * 11));
    for (int i = 0; i < 24; i++) psk[i] = (CK_BYTE)(0x30 + i);
    for (int i = 0; i < 16; i++) { ni[i] = (CK_BYTE)(i * 3); nr[i] = (CK_BYTE)(0xF0 - i);
                                   aesv[i] = (CK_BYTE)(0x5C + i); }
    for (int i = 0; i < 8; i++)  { ckyi[i] = (CK_BYTE)(0x11 * i); ckyr[i] = (CK_BYTE)(0x80 | i); }
    CK_OBJECT_HANDLE kgir = secret(CKK_GENERIC_SECRET, gir, 32);
    CK_OBJECT_HANDLE kpsk = secret(CKK_GENERIC_SECRET, psk, 24);
    CK_OBJECT_HANDLE kaes = secret(CKK_AES, aesv, 16);
    if (!kgir || !kpsk || !kaes) { fprintf(stderr, "base keys\n"); return 2; }

    CK_ULONG cls = CKO_SECRET_KEY, gen = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE dt[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_TOKEN, &no, 1 },
                          { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 },
                          { CKA_DERIVE, &yes, 1 }, { CKA_KEY_TYPE, &gen, sizeof gen },
                          { CKA_VALUE_LEN, NULL, sizeof(CK_ULONG) } };
    CK_BYTE nn[32], got[128], want[128], in[256], t1[32];
    CK_ULONG il;
    char what[160];
    memcpy(nn, ni, 16); memcpy(nn + 16, nr, 16);

    /* --- (P) CKM_IKE_PRF_DERIVE ------------------------------------------ */
    CK_OBJECT_HANDLE seed = 0, skeyid = 0;
    CK_BYTE seedv[32], skeyidv[32];
    {
        CK_IKE_PRF_DERIVE_PARAMS p = { CKM_SHA256_HMAC, 1, 0, ni, 16, nr, 16, 0 };
        CK_MECHANISM m = { CKM_IKE_PRF_DERIVE, &p, sizeof p };
        CK_RV rv = C_DeriveKey(s, &m, kgir, dt, 5, &seed);
        snprintf(what, sizeof what, "(P) SKEYSEED = prf(Ni | Nr, g^ir): 0x%lx", rv);
        ok(rv == CKR_OK && listed(CKM_IKE_PRF_DERIVE) && value_of(seed, seedv, 32) == 32
           && prf(nn, 32, gir, 32, want) && !memcmp(seedv, want, 32), what);
        ok(ulong_attr(seed, CKA_KEY_TYPE) == CKK_SHA256_HMAC, "(P) typed CKK_SHA256_HMAC, the prf's key type");

        p.bDataAsKey = 0;
        rv = C_DeriveKey(s, &m, kpsk, dt, 5, &skeyid);
        snprintf(what, sizeof what, "(P) SKEYID = prf(pre-shared key, Ni | Nr): 0x%lx", rv);
        ok(rv == CKR_OK && value_of(skeyid, skeyidv, 32) == 32
           && prf(psk, 24, nn, 32, want) && !memcmp(skeyidv, want, 32), what);

        p.bRekey = 1; p.hNewKey = kgir;
        CK_OBJECT_HANDLE h = 0;
        rv = C_DeriveKey(s, &m, seed, dt, 5, &h);
        il = 0; cat(in, &il, gir, 32); cat(in, &il, nn, 32);
        snprintf(what, sizeof what, "(P) rekey: prf(SK_d, g^ir | Ni | Nr): 0x%lx", rv);
        ok(rv == CKR_OK && value_of(h, got, sizeof got) == 32
           && prf(seedv, 32, in, il, want) && !memcmp(got, want, 32), what);

        p.bDataAsKey = 1;
        CK_RV r1 = C_DeriveKey(s, &m, kgir, dt, 5, &h);
        p.bDataAsKey = 0; p.bRekey = 0;
        CK_ULONG l16 = 16;
        dt[6].pValue = &l16;
        CK_RV r2 = C_DeriveKey(s, &m, kpsk, dt, 7, &h);
        snprintf(what, sizeof what, "(P) refused: data as key with rekey, 16 bytes (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_ARGUMENTS_BAD && r2 == CKR_KEY_SIZE_RANGE, what);
    }

    /* --- (1) CKM_IKE1_PRF_DERIVE ----------------------------------------- */
    if (skeyid) {
        CK_IKE1_PRF_DERIVE_PARAMS p = { CKM_SHA256_HMAC, 0, kgir, 0, ckyi, 8, ckyr, 8, 0 };
        CK_MECHANISM m = { CKM_IKE1_PRF_DERIVE, &p, sizeof p };
        CK_OBJECT_HANDLE kd = 0, ka = 0, h = 0;
        CK_BYTE dv[32];
        CK_RV rv = C_DeriveKey(s, &m, skeyid, dt, 6, &kd);
        il = 0; cat(in, &il, gir, 32); cat(in, &il, ckyi, 8); cat(in, &il, ckyr, 8); in[il++] = 0;
        snprintf(what, sizeof what, "(1) SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0): 0x%lx", rv);
        ok(rv == CKR_OK && value_of(kd, dv, 32) == 32
           && prf(skeyidv, 32, in, il, want) && !memcmp(dv, want, 32), what);

        p.bHasPrevKey = 1; p.hPrevKey = kd; p.keyNumber = 1;
        rv = C_DeriveKey(s, &m, skeyid, dt, 6, &ka);
        il = 0; cat(in, &il, dv, 32); cat(in, &il, gir, 32); cat(in, &il, ckyi, 8);
        cat(in, &il, ckyr, 8); in[il++] = 1;
        snprintf(what, sizeof what, "(1) SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKYs | 1): 0x%lx", rv);
        ok(rv == CKR_OK && value_of(ka, got, sizeof got) == 32
           && prf(skeyidv, 32, in, il, want) && !memcmp(got, want, 32), what);

        CK_ULONG l16 = 16;
        dt[6].pValue = &l16;
        rv = C_DeriveKey(s, &m, skeyid, dt, 7, &h);
        ok(rv == CKR_OK && value_of(h, got, sizeof got) == 16 && !memcmp(got, want, 16),
           "(1) CKA_VALUE_LEN 16: the leftmost 16 bytes");
        CK_ULONG l33 = 33;
        dt[6].pValue = &l33;
        CK_RV r1 = C_DeriveKey(s, &m, skeyid, dt, 5, &h);
        CK_RV r2 = C_DeriveKey(s, &m, skeyid, dt, 7, &h);
        snprintf(what, sizeof what, "(1) refused: no CKA_KEY_TYPE, 33 bytes (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_TEMPLATE_INCOMPLETE && r2 == CKR_KEY_SIZE_RANGE, what);
    }

    /* --- (2) CKM_IKE2_PRF_PLUS_DERIVE ------------------------------------ */
    if (seed) {
        CK_BYTE sdata[48];
        memcpy(sdata, nn, 32);
        for (int i = 0; i < 16; i++) sdata[32 + i] = (CK_BYTE)(0x77 ^ i);   /* SPIi | SPIr */
        CK_IKE2_PRF_PLUS_DERIVE_PARAMS p = { CKM_SHA256_HMAC, 0, 0, sdata, 48 };
        CK_MECHANISM m = { CKM_IKE2_PRF_PLUS_DERIVE, &p, sizeof p };
        CK_ULONG l100 = 100;
        dt[6].pValue = &l100;
        CK_OBJECT_HANDLE h = 0;
        CK_RV rv = C_DeriveKey(s, &m, seed, dt, 7, &h);
        int good = rv == CKR_OK && value_of(h, got, sizeof got) == 100;
        CK_ULONG tl = 0;
        for (int i = 1; good && tl < 100; i++) {
            il = 0;
            if (i > 1) cat(in, &il, t1, 32);
            cat(in, &il, sdata, 48); in[il++] = (CK_BYTE)i;
            good = prf(seedv, 32, in, il, t1);
            CK_ULONG n = 100 - tl < 32 ? 100 - tl : 32;
            memcpy(want + tl, t1, n); tl += n;
        }
        snprintf(what, sizeof what, "(2) prf+ of 100 bytes, S = Ni | Nr | SPIi | SPIr: 0x%lx", rv);
        ok(good && !memcmp(got, want, 100) && listed(CKM_IKE2_PRF_PLUS_DERIVE), what);

        p.bHasSeedKey = 1; p.hSeedKey = kgir; p.pSeedData = nn; p.ulSeedDataLen = 32;
        CK_ULONG l40 = 40;
        dt[6].pValue = &l40;
        rv = C_DeriveKey(s, &m, seed, dt, 7, &h);
        CK_BYTE sv[64]; memcpy(sv, gir, 32); memcpy(sv + 32, nn, 32);
        good = rv == CKR_OK && value_of(h, got, sizeof got) == 40;
        il = 0; cat(in, &il, sv, 64); in[il++] = 1;
        good = good && prf(seedv, 32, in, il, t1);
        memcpy(want, t1, 32);
        il = 0; cat(in, &il, t1, 32); cat(in, &il, sv, 64); in[il++] = 2;
        good = good && prf(seedv, 32, in, il, t1);
        memcpy(want + 32, t1, 8);
        snprintf(what, sizeof what, "(2) prf+ of 40 bytes, S = g^ir (new) | Ni | Nr: 0x%lx", rv);
        ok(good && !memcmp(got, want, 40), what);

        CK_RV r1 = C_DeriveKey(s, &m, seed, dt, 6, &h);
        CK_ULONG big = 255 * 32 + 1;
        dt[6].pValue = &big;
        CK_RV r2 = C_DeriveKey(s, &m, seed, dt, 7, &h);
        snprintf(what, sizeof what, "(2) refused: no CKA_VALUE_LEN, 255 blocks and a byte (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_TEMPLATE_INCOMPLETE && r2 == CKR_KEY_SIZE_RANGE, what);
    }

    /* --- (E) CKM_IKE1_EXTENDED_DERIVE ------------------------------------ */
    if (skeyid) {
        CK_IKE1_EXTENDED_DERIVE_PARAMS p = { CKM_SHA256_HMAC, 0, 0, NULL, 0 };
        CK_MECHANISM m = { CKM_IKE1_EXTENDED_DERIVE, &p, sizeof p };
        CK_ULONG l16 = 16;
        dt[6].pValue = &l16;
        CK_OBJECT_HANDLE h = 0;
        CK_RV rv = C_DeriveKey(s, &m, skeyid, dt, 7, &h);
        if (nist) {
            snprintf(what, sizeof what, "(E) CKM_IKE1_EXTENDED_DERIVE refused: 0x%lx", rv);
            ok(rv == CKR_MECHANISM_INVALID, what);
        } else {
            snprintf(what, sizeof what, "(E) 16 bytes, no g^xy: SKEYID cut (0x%lx)", rv);
            ok(rv == CKR_OK && value_of(h, got, sizeof got) == 16 && !memcmp(got, skeyidv, 16), what);

            CK_ULONG l48 = 48;
            dt[6].pValue = &l48;
            rv = C_DeriveKey(s, &m, skeyid, dt, 7, &h);
            CK_BYTE zero = 0;
            int good = rv == CKR_OK && value_of(h, got, sizeof got) == 48
                       && prf(skeyidv, 32, &zero, 1, t1);
            memcpy(want, t1, 32);
            good = good && prf(skeyidv, 32, t1, 32, t1);
            memcpy(want + 32, t1, 16);
            snprintf(what, sizeof what, "(E) 48 bytes: K1 = prf(K, 0x00), K2 = prf(K, K1) (0x%lx)", rv);
            ok(good && !memcmp(got, want, 48), what);

            CK_BYTE extra[12];
            for (int i = 0; i < 12; i++) extra[i] = (CK_BYTE)(0xC0 + i);
            p.bHasKeygxy = 1; p.hKeygxy = kgir; p.pExtraData = extra; p.ulExtraDataLen = 12;
            CK_ULONG l40 = 40;
            dt[6].pValue = &l40;
            rv = C_DeriveKey(s, &m, skeyid, dt, 7, &h);
            CK_BYTE sx[44]; memcpy(sx, gir, 32); memcpy(sx + 32, extra, 12);
            good = rv == CKR_OK && value_of(h, got, sizeof got) == 40 && prf(skeyidv, 32, sx, 44, t1);
            memcpy(want, t1, 32);
            il = 0; cat(in, &il, t1, 32); cat(in, &il, sx, 44);
            good = good && prf(skeyidv, 32, in, il, t1);
            memcpy(want + 32, t1, 8);
            snprintf(what, sizeof what, "(E) 40 bytes from g^xy and extra data (0x%lx)", rv);
            ok(good && !memcmp(got, want, 40), what);
        }
    }

    /* --- (F) refusals ---------------------------------------------------- */
    {
        CK_IKE_PRF_DERIVE_PARAMS p = { CKM_SHA256_HMAC_GENERAL, 0, 0, ni, 16, nr, 16, 0 };
        CK_MECHANISM m = { CKM_IKE_PRF_DERIVE, &p, sizeof p };
        CK_OBJECT_HANDLE h = 0;
        CK_RV r1 = C_DeriveKey(s, &m, kpsk, dt, 5, &h);
        p.prfMechanism = CKM_SHA256_HMAC;
        CK_RV r2 = C_DeriveKey(s, &m, kaes, dt, 5, &h);
        p.bRekey = 1; p.hNewKey = kaes;
        CK_RV r3 = seed ? C_DeriveKey(s, &m, seed, dt, 5, &h) : CKR_OK;
        snprintf(what, sizeof what, "(F) a GENERAL prf, an AES base, an AES g^ir (0x%lx 0x%lx 0x%lx)",
                 r1, r2, r3);
        ok(r1 == CKR_MECHANISM_PARAM_INVALID && r2 == CKR_KEY_TYPE_INCONSISTENT
           && r3 == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
