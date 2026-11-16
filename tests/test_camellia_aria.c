/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_camellia_aria.c --- the Camellia and ARIA mechanisms (2.8.0): ECB,
 * CBC, CBC-PAD, CTR (Camellia), MAC, MAC_GENERAL, KEY_GEN and the two
 * encryption derivations, on CKK_CAMELLIA and CKK_ARIA keys.
 *
 *   (E) ECB against RFC 3713 Appendix A (Camellia) and RFC 5794 Appendix A
 *       (ARIA), 128-, 192- and 256-bit keys, both ways.
 *   (C) CBC over 48 bytes and CBC-PAD over 37, chained by hand from single
 *       ECB blocks; Camellia CTR over 37 bytes, its keystream the ECB of
 *       the counter blocks. Each single-part and in parts, both ways.
 *   (M) the MAC (8 bytes) and MAC_GENERAL (12): the CBC-MAC with a zero
 *       IV over the data padded with zero bytes, chained by hand.
 *   (X) ECB_ENCRYPT_DATA and CBC_ENCRYPT_DATA: the derived value is the
 *       data encrypted, as the cipher gives it.
 *   (G) KEY_GEN makes a key of its type that ECB takes.
 *   (K) an AES key under the Camellia ECB, or a 20-byte CKK_ARIA key, is
 *       refused.
 *   (N) where NIST's rules apply, or the provider has neither cipher, none
 *       is listed or accepted.
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
typedef struct { CK_ULONG ulCounterBits; CK_BYTE cb[16]; } CK_CTR_PARAMS;
typedef struct { CK_BYTE *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;
typedef struct { CK_BYTE iv[16]; CK_BYTE *pData; CK_ULONG length; } CK_CBC_ENCRYPT_DATA_PARAMS;

#define CKR_OK                         0x000UL
#define CKR_ATTRIBUTE_VALUE_INVALID    0x013UL
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_AES                        0x1FUL
#define CKK_CAMELLIA                   0x25UL
#define CKK_ARIA                       0x26UL
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
#define CKM_RSA_PKCS                   0x0001UL
/* Offsets from each family's base: 0x550 Camellia, 0x560 ARIA. */
#define O_KEY_GEN 0
#define O_ECB     1
#define O_CBC     2
#define O_MAC     3
#define O_MAC_GEN 4
#define O_CBC_PAD 5
#define O_ECB_ED  6
#define O_CBC_ED  7
#define O_CTR     8

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

static CK_RV import(const CK_BYTE *v, CK_ULONG vl, CK_ULONG kt, CK_OBJECT_HANDLE *h) {
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 }, { CKA_DECRYPT, &yes, 1 },
                         { CKA_SIGN, &yes, 1 }, { CKA_VERIFY, &yes, 1 }, { CKA_DERIVE, &yes, 1 },
                         { CKA_VALUE, (void*)v, vl } };
    *h = 0;
    return C_CreateObject(s, t, 9, h);
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
        CK_ULONG l = 128;
        rv = enc ? C_EncryptUpdate(s, (CK_BYTE*)in + off, pieces[i], out + done, &l)
                 : C_DecryptUpdate(s, (CK_BYTE*)in + off, pieces[i], out + done, &l);
        off += pieces[i];
        done += l;
    }
    if (rv == CKR_OK) {
        CK_ULONG l = 128;
        rv = enc ? C_EncryptFinal(s, out + done, &l) : C_DecryptFinal(s, out + done, &l);
        done += l;
    }
    *ol = done;
    return rv;
}

static void vector(const char *name, CK_MECHANISM *m, CK_OBJECT_HANDLE k,
                   const CK_BYTE *pt, CK_ULONG pl, const CK_BYTE *ct, CK_ULONG cl) {
    char what[128];
    CK_BYTE out[256];
    CK_ULONG ol = sizeof out;
    CK_RV rv = one_shot(1, m, k, pt, pl, out, &ol);
    snprintf(what, sizeof what, "%s: C_Encrypt, %lu bytes (0x%lx)", name, pl, rv);
    ok(rv == CKR_OK && ol == cl && memcmp(out, ct, cl) == 0, what);
    ol = sizeof out;
    rv = one_shot(0, m, k, ct, cl, out, &ol);
    snprintf(what, sizeof what, "%s: C_Decrypt (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == pl && memcmp(out, pt, pl) == 0, what);
    rv = in_parts(1, m, k, pt, pl, out, &ol);
    snprintf(what, sizeof what, "%s: encrypt in parts (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == cl && memcmp(out, ct, cl) == 0, what);
    rv = in_parts(0, m, k, ct, cl, out, &ol);
    snprintf(what, sizeof what, "%s: decrypt in parts (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == pl && memcmp(out, pt, pl) == 0, what);
}

/* --- the reference, on single ECB blocks of the module's -------------- */
static int ecb_ok;
static void E(CK_ULONG base, CK_OBJECT_HANDLE k, const CK_BYTE in[16], CK_BYTE out[16]) {
    CK_MECHANISM m = { base + O_ECB, NULL, 0 };
    CK_ULONG l = 16;
    if (one_shot(1, &m, k, in, 16, out, &l) != CKR_OK || l != 16) ecb_ok = 0;
}
static void cbc_ref(CK_ULONG base, CK_OBJECT_HANDLE k, const CK_BYTE *iv, const CK_BYTE *p,
                    CK_ULONG n, CK_BYTE *c) {
    const CK_BYTE *prev = iv;
    for (CK_ULONG i = 0; i < n; i += 16) {
        CK_BYTE x[16];
        for (int j = 0; j < 16; j++) x[j] = (CK_BYTE)(p[i + (CK_ULONG)j] ^ prev[j]);
        E(base, k, x, c + i);
        prev = c + i;
    }
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_GenerateKey); SYM(C_DeriveKey); SYM(C_GetAttributeValue);
    SYM(C_EncryptInit); SYM(C_Encrypt); SYM(C_EncryptUpdate); SYM(C_EncryptFinal);
    SYM(C_DecryptInit); SYM(C_Decrypt); SYM(C_DecryptUpdate); SYM(C_DecryptFinal);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    if (!C_SignFinal || !C_DeriveKey || !C_DecryptFinal) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("Camellia and ARIA\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "camaria", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const char *mode = getenv("FHSM_MODE");
    const int nist_build = !listed(CKM_RSA_PKCS);
    const int strict = mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips"));

    static const struct {
        const char *name; CK_ULONG base, ckk; int ctr;
        const char *k[3]; const char *pt; const char *ct[3];
    } F[] = {
        { "Camellia", 0x550, CKK_CAMELLIA, 1,
          { "0123456789abcdeffedcba9876543210",
            "0123456789abcdeffedcba98765432100011223344556677",
            "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff" },
          "0123456789abcdeffedcba9876543210",
          { "67673138549669730857065648eabe43", "b4993401b3e996f84ee5cee7d79b09b9",
            "9acc237dff16d76c20ef7c919e3a7509" } },
        { "ARIA", 0x560, CKK_ARIA, 0,
          { "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" },
          "00112233445566778899aabbccddeeff",
          { "d718fbd6ab644c739da95f3be6451778", "26449c1805dbe7aa25a468ce263a9e79",
            "f92bd7c79fb72e2f2b8f80c1972d24fc" } },
    };

    for (size_t f = 0; f < 2; f++) {
        const CK_ULONG base = F[f].base;
        char what[160];
        CK_BYTE kv[32];
        size_t kl = unhex(F[f].k[0], kv);
        CK_OBJECT_HANDLE k = 0;
        if (import(kv, (CK_ULONG)kl, F[f].ckk, &k) != CKR_OK) { fprintf(stderr, "key import\n"); return 2; }
        const int served = listed(base + O_ECB);

        /* (N) */
        if (nist_build || strict || !served) {
            int any = 0;
            for (CK_ULONG m = base; m <= base + (F[f].ctr ? 8u : 7u); m++) if (listed(m)) any = 1;
            CK_MECHANISM em = { base + O_ECB, NULL, 0 }, mm = { base + O_MAC, NULL, 0 };
            CK_RV r1 = C_EncryptInit(s, &em, k), r2 = C_SignInit(s, &mm, k);
            ok(nist_build ? !any : 1, nist_build ? "(N) none listed in the nist build"
                                                 : "(N) not listed where not served");
            snprintf(what, sizeof what, "(N) %s: EncryptInit, SignInit MECHANISM_INVALID (0x%lx 0x%lx)",
                     F[f].name, r1, r2);
            ok(r1 == CKR_MECHANISM_INVALID && r2 == CKR_MECHANISM_INVALID, what);
            continue;
        }

        /* (E) */
        ecb_ok = 1;
        for (int i = 0; i < 3; i++) {
            CK_BYTE kx[32], pt[16], ct[16];
            size_t kxl = unhex(F[f].k[i], kx);
            unhex(F[f].pt, pt); unhex(F[f].ct[i], ct);
            CK_OBJECT_HANDLE h = 0;
            CK_RV rv = import(kx, (CK_ULONG)kxl, F[f].ckk, &h);
            CK_MECHANISM m = { base + O_ECB, NULL, 0 };
            CK_BYTE out[16], back[16]; CK_ULONG ol = 16, bl = 16;
            if (rv == CKR_OK) rv = one_shot(1, &m, h, pt, 16, out, &ol);
            if (rv == CKR_OK) rv = one_shot(0, &m, h, ct, 16, back, &bl);
            snprintf(what, sizeof what, "(E) %s-%d ECB, the RFC's vector, both ways (0x%lx)",
                     F[f].name, 128 + 64 * i, rv);
            ok(rv == CKR_OK && memcmp(out, ct, 16) == 0 && memcmp(back, pt, 16) == 0, what);
        }

        /* (C) */
        CK_BYTE msg[48], iv[16], ref[64];
        for (int i = 0; i < 48; i++) msg[i] = (CK_BYTE)((i * 5 + 1) & 0xFF);
        for (int i = 0; i < 16; i++) iv[i] = (CK_BYTE)(0xA0 + i);
        CK_MECHANISM cbc = { base + O_CBC, iv, 16 }, pad = { base + O_CBC_PAD, iv, 16 };
        cbc_ref(base, k, iv, msg, 48, ref);
        snprintf(what, sizeof what, "(C) %s CBC", F[f].name);
        vector(what, &cbc, k, msg, 48, ref, 48);
        {
            CK_BYTE padded[48];
            memcpy(padded, msg, 37); memset(padded + 37, 11, 11);
            cbc_ref(base, k, iv, padded, 48, ref);
            snprintf(what, sizeof what, "(C) %s CBC-PAD", F[f].name);
            vector(what, &pad, k, msg, 37, ref, 48);
        }
        if (F[f].ctr) {
            CK_CTR_PARAMS cp = { 128, { 0 } };
            for (int i = 0; i < 16; i++) cp.cb[i] = (CK_BYTE)(0xF0 + i);
            CK_MECHANISM ctr = { base + O_CTR, &cp, sizeof cp };
            CK_BYTE cb[16], ks[48];
            memcpy(cb, cp.cb, 16);
            for (int b = 0; b < 3; b++) {
                E(base, k, cb, ks + 16 * b);
                for (int j = 15; j >= 0 && ++cb[j] == 0; j--) {}
            }
            for (int i = 0; i < 37; i++) ref[i] = (CK_BYTE)(msg[i] ^ ks[i]);
            snprintf(what, sizeof what, "(C) %s CTR", F[f].name);
            vector(what, &ctr, k, msg, 37, ref, 37);
        }

        /* (M) */
        {
            CK_BYTE zp[48] = { 0 }, zero[16] = { 0 }, chain[48];
            memcpy(zp, msg, 37);
            cbc_ref(base, k, zero, zp, 48, chain);
            CK_MECHANISM mm = { base + O_MAC, NULL, 0 };
            CK_ULONG twelve = 12;
            CK_MECHANISM mg = { base + O_MAC_GEN, &twelve, sizeof twelve };
            CK_BYTE tag[16]; CK_ULONG tl = sizeof tag;
            CK_RV r1 = C_SignInit(s, &mm, k);
            if (r1 == CKR_OK) r1 = C_Sign(s, msg, 37, tag, &tl);
            int m1 = r1 == CKR_OK && tl == 8 && memcmp(tag, chain + 32, 8) == 0;
            tl = sizeof tag;
            CK_RV r2 = C_SignInit(s, &mg, k);
            if (r2 == CKR_OK) r2 = C_SignUpdate(s, msg, 5);
            if (r2 == CKR_OK) r2 = C_SignUpdate(s, msg + 5, 32);
            if (r2 == CKR_OK) r2 = C_SignFinal(s, tag, &tl);
            int m2 = r2 == CKR_OK && tl == 12 && memcmp(tag, chain + 32, 12) == 0;
            snprintf(what, sizeof what, "(M) %s MAC 8, MAC_GENERAL 12 in parts (0x%lx 0x%lx)",
                     F[f].name, r1, r2);
            ok(m1 && m2, what);
        }

        /* (X) */
        {
            CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET;
            CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                                 { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 },
                                 { CKA_EXTRACTABLE, &yes, 1 } };
            CK_KEY_DERIVATION_STRING_DATA sd = { msg, 32 };
            CK_CBC_ENCRYPT_DATA_PARAMS cp;
            memcpy(cp.iv, iv, 16); cp.pData = msg; cp.length = 32;
            CK_MECHANISM me = { base + O_ECB_ED, &sd, sizeof sd }, mc = { base + O_CBC_ED, &cp, sizeof cp };
            CK_BYTE we[32], wc[32], ge[32], gc[32];
            E(base, k, msg, we); E(base, k, msg + 16, we + 16);
            cbc_ref(base, k, iv, msg, 32, wc);
            CK_OBJECT_HANDLE de = 0, dc = 0;
            CK_ATTRIBUTE ae = { CKA_VALUE, ge, sizeof ge }, ac = { CKA_VALUE, gc, sizeof gc };
            CK_RV r1 = C_DeriveKey(s, &me, k, t, 5, &de);
            if (r1 == CKR_OK) r1 = C_GetAttributeValue(s, de, &ae, 1);
            CK_RV r2 = C_DeriveKey(s, &mc, k, t, 5, &dc);
            if (r2 == CKR_OK) r2 = C_GetAttributeValue(s, dc, &ac, 1);
            snprintf(what, sizeof what, "(X) %s ECB_ and CBC_ENCRYPT_DATA (0x%lx 0x%lx)", F[f].name, r1, r2);
            ok(r1 == CKR_OK && r2 == CKR_OK && ae.ulValueLen == 32 && ac.ulValueLen == 32
               && memcmp(ge, we, 32) == 0 && memcmp(gc, wc, 32) == 0, what);
        }

        /* (G) */
        {
            CK_MECHANISM m = { base + O_KEY_GEN, NULL, 0 }, em = { base + O_ECB, NULL, 0 };
            CK_ULONG vl = 24;
            CK_ATTRIBUTE t[] = { { CKA_TOKEN, &no, 1 }, { CKA_ENCRYPT, &yes, 1 },
                                 { CKA_DECRYPT, &yes, 1 }, { CKA_VALUE_LEN, &vl, sizeof vl } };
            CK_OBJECT_HANDLE g = 0;
            CK_RV rv = C_GenerateKey(s, &m, t, 4, &g);
            CK_ULONG kt = 0;
            CK_ATTRIBUTE a = { CKA_KEY_TYPE, &kt, sizeof kt };
            if (rv == CKR_OK) rv = C_GetAttributeValue(s, g, &a, 1);
            CK_BYTE out[16], back[16]; CK_ULONG ol = 16, bl = 16;
            if (rv == CKR_OK) rv = one_shot(1, &em, g, msg, 16, out, &ol);
            if (rv == CKR_OK) rv = one_shot(0, &em, g, out, 16, back, &bl);
            snprintf(what, sizeof what, "(G) %s KEY_GEN, 24 bytes: its type, ECB round trip (0x%lx)",
                     F[f].name, rv);
            ok(rv == CKR_OK && kt == F[f].ckk && memcmp(back, msg, 16) == 0, what);
        }
        ok(ecb_ok, "the reference's ECB calls all succeeded");
    }

    /* (K) */
    if (!nist_build && !strict && listed(0x551) && listed(0x561)) {
        char what[128];
        CK_BYTE kv[20] = { 0 };
        CK_OBJECT_HANDLE ak = 0, h = 0;
        (void)import(kv, 16, CKK_AES, &ak);
        CK_MECHANISM m = { 0x551, NULL, 0 };
        CK_RV r1 = C_EncryptInit(s, &m, ak);
        CK_RV r2 = import(kv, 20, CKK_ARIA, &h);
        snprintf(what, sizeof what, "(K) AES key for Camellia; 20-byte ARIA key (0x%lx 0x%lx)", r1, r2);
        ok(r1 == CKR_KEY_TYPE_INCONSISTENT && r2 == CKR_ATTRIBUTE_VALUE_INVALID, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
