/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_aes_xts.c --- CKM_AES_XTS and CKM_AES_XTS_KEY_GEN, CKK_AES_XTS keys
 * (2.8.0).
 *
 *   (V) IEEE 1619 vectors 2 (32 bytes) and 15 (17 bytes, ciphertext
 *       stealing), XTS-AES-128 at 16, 31 and 48 bytes and XTS-AES-256 at 37
 *       and 64 bytes: C_Encrypt gives the ciphertext, C_Decrypt the
 *       plaintext, and the multipart forms, in parts of 5 bytes and the
 *       rest, the same.
 *   (I) C_GetMechanismInfo: 32 to 64 bytes for both mechanisms.
 *   (G) CKM_AES_XTS_KEY_GEN makes 32- and 64-byte keys that encrypt and
 *       decrypt; 16, 24 and 48 bytes are CKR_KEY_SIZE_RANGE; CKA_KEY_TYPE =
 *       CKK_AES in its template is CKR_TEMPLATE_INCONSISTENT.
 *   (K) C_CreateObject of a CKK_AES_XTS key of 48 bytes, or with two equal
 *       halves, is CKR_ATTRIBUTE_VALUE_INVALID.
 *   (L) fewer than 16 bytes: CKR_DATA_LEN_RANGE to encrypt,
 *       CKR_ENCRYPTED_DATA_LEN_RANGE to decrypt, single-part and multipart.
 *   (P) no tweak is CKR_MECHANISM_PARAM_INVALID; a CKK_AES key with
 *       CKM_AES_XTS, and a CKK_AES_XTS key with CKM_AES_CBC, are
 *       CKR_KEY_TYPE_INCONSISTENT.
 * The expected values were computed with a pure-Python XTS over an AES
 * checked against FIPS 197 C.1, which gives IEEE 1619's own for vectors 2
 * and 15; not with OpenSSL. Approved (SP 800-38E): the same results in both
 * builds.
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

#define CKR_OK                         0x000UL
#define CKR_ATTRIBUTE_VALUE_INVALID    0x013UL
#define CKR_DATA_LEN_RANGE             0x021UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE   0x041UL
#define CKR_KEY_SIZE_RANGE             0x062UL
#define CKR_KEY_TYPE_INCONSISTENT      0x063UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKR_TEMPLATE_INCONSISTENT      0x0D1UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_AES                        0x1FUL
#define CKK_AES_XTS                    0x35UL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_DECRYPT                    0x105UL
#define CKA_VALUE_LEN                  0x161UL
#define CKM_AES_CBC                    0x1082UL
#define CKM_AES_XTS                    0x1071UL
#define CKM_AES_XTS_KEY_GEN            0x1072UL

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
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);

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
                         { CKA_DECRYPT, &yes, 1 }, { CKA_VALUE, (void*)v, vl } };
    *h = 0;
    return C_CreateObject(s, t, 6, h);
}

static CK_OBJECT_HANDLE key_of(const CK_BYTE *v, CK_ULONG vl, CK_ULONG kt) {
    CK_OBJECT_HANDLE h = 0;
    return import(v, vl, kt, &h) == CKR_OK ? h : 0;
}

static CK_RV generate(CK_ULONG len, CK_ULONG *kt, CK_OBJECT_HANDLE *h) {
    CK_MECHANISM m = { CKM_AES_XTS_KEY_GEN, NULL, 0 };
    CK_ATTRIBUTE t[] = { { CKA_VALUE_LEN, &len, sizeof len }, { CKA_TOKEN, &no, 1 },
                         { CKA_ENCRYPT, &yes, 1 }, { CKA_DECRYPT, &yes, 1 },
                         { CKA_KEY_TYPE, kt, sizeof *kt } };
    *h = 0;
    return C_GenerateKey(s, &m, t, kt ? 5 : 4, h);
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

/* In parts of 5 bytes and the rest; encrypt (enc = 1) or decrypt. */
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

static void vector(const char *name, CK_OBJECT_HANDLE k, CK_BYTE *tw,
                   const CK_BYTE *pt, size_t pl, const char *cthex) {
    char what[128];
    CK_BYTE ct[128], out[256];
    size_t cl = unhex(cthex, ct);
    CK_MECHANISM m = { CKM_AES_XTS, tw, 16 };
    CK_ULONG ol = sizeof out;
    CK_RV rv = C_EncryptInit(s, &m, k);
    if (rv == CKR_OK) rv = C_Encrypt(s, (CK_BYTE*)pt, (CK_ULONG)pl, out, &ol);
    snprintf(what, sizeof what, "%s: C_Encrypt, %zu bytes (0x%lx)", name, pl, rv);
    ok(rv == CKR_OK && ol == cl && memcmp(out, ct, cl) == 0, what);
    ol = sizeof out;
    rv = C_DecryptInit(s, &m, k);
    if (rv == CKR_OK) rv = C_Decrypt(s, ct, (CK_ULONG)cl, out, &ol);
    snprintf(what, sizeof what, "%s: C_Decrypt (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == pl && memcmp(out, pt, pl) == 0, what);
    rv = in_parts(1, &m, k, pt, (CK_ULONG)pl, out, &ol);
    snprintf(what, sizeof what, "%s: encrypt in parts (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == cl && memcmp(out, ct, cl) == 0, what);
    rv = in_parts(0, &m, k, ct, (CK_ULONG)cl, out, &ol);
    snprintf(what, sizeof what, "%s: decrypt in parts (0x%lx)", name, rv);
    ok(rv == CKR_OK && ol == pl && memcmp(out, pt, pl) == 0, what);
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_GetMechanismInfo); SYM(C_CreateObject); SYM(C_GenerateKey);
    SYM(C_EncryptInit); SYM(C_Encrypt); SYM(C_EncryptUpdate); SYM(C_EncryptFinal);
    SYM(C_DecryptInit); SYM(C_Decrypt); SYM(C_DecryptUpdate); SYM(C_DecryptFinal);
    if (!C_DecryptFinal || !C_EncryptFinal || !C_GenerateKey || !C_GetMechanismInfo) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("AES-XTS\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "aesxts", 6);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    ok(listed(CKM_AES_XTS), "CKM_AES_XTS listed");
    ok(listed(CKM_AES_XTS_KEY_GEN), "CKM_AES_XTS_KEY_GEN listed");

    /* Keys: IEEE 1619 vector 2 (11.. | 22..), vector 15, 00..1f and 40..7f. */
    CK_BYTE kv2[32], kv15[32], k128v[32], k256v[64];
    memset(kv2, 0x11, 16); memset(kv2 + 16, 0x22, 16);
    unhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0", kv15);
    for (int i = 0; i < 32; i++) k128v[i] = (CK_BYTE)i;
    for (int i = 0; i < 64; i++) k256v[i] = (CK_BYTE)(0x40 + i);
    CK_OBJECT_HANDLE k2 = key_of(kv2, 32, CKK_AES_XTS), k15 = key_of(kv15, 32, CKK_AES_XTS),
                     k128 = key_of(k128v, 32, CKK_AES_XTS), k256 = key_of(k256v, 64, CKK_AES_XTS),
                     aes = key_of(k128v, 32, CKK_AES);
    if (!k2 || !k15 || !k128 || !k256 || !aes) { fprintf(stderr, "key import\n"); return 2; }

    /* (V) */
    CK_BYTE tw2[16] = { 0x33, 0x33, 0x33, 0x33, 0x33 };
    CK_BYTE tw[16] = { 0x9a, 0x78, 0x56, 0x34, 0x12 };
    CK_BYTE p44[32], seq[17], pt[64];
    memset(p44, 0x44, sizeof p44);
    for (int i = 0; i < 17; i++) seq[i] = (CK_BYTE)i;
    for (int i = 0; i < 64; i++) pt[i] = (CK_BYTE)((i * 7 + 3) & 0xFF);
    vector("(V) IEEE 1619 vector 2", k2, tw2, p44, 32,
           "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0");
    vector("(V) IEEE 1619 vector 15", k15, tw, seq, 17,
           "6c1625db4671522d3d7599601de7ca09ed");
    vector("(V) XTS-AES-128, 16 bytes", k128, tw, pt, 16,
           "56846a43888ae0db93b956313bb5b10f");
    vector("(V) XTS-AES-128, 31 bytes", k128, tw, pt, 31,
           "b6798de4b8cf2bc9af975880a7e9e8cc56846a43888ae0db93b956313bb5b1");
    vector("(V) XTS-AES-128, 48 bytes", k128, tw, pt, 48,
           "56846a43888ae0db93b956313bb5b10f9dbbc60b04e078b5636a175d405e3ebe"
           "be687bfb4522069f5cfe44ca9592f172");
    vector("(V) XTS-AES-256, 37 bytes", k256, tw, pt, 37,
           "e6fcca463e91fee6fca6d88f69b623d4dacc04007cf5d0d44eed4314e00bc0de"
           "fcca41ef29");
    vector("(V) XTS-AES-256, 64 bytes", k256, tw, pt, 64,
           "e6fcca463e91fee6fca6d88f69b623d4fcca41ef29eaae876a55e7dffbde7a50"
           "d43c31a89c285a4a1c00fa76aaf02b7dfc1f6c2d08dfc54f58a4cd758a89245c");

    /* (I) */
    {
        char what[128];
        CK_MECHANISM_INFO a, g;
        memset(&a, 0, sizeof a); memset(&g, 0, sizeof g);
        CK_RV ra = C_GetMechanismInfo(0, CKM_AES_XTS, &a);
        CK_RV rg = C_GetMechanismInfo(0, CKM_AES_XTS_KEY_GEN, &g);
        snprintf(what, sizeof what, "(I) key sizes %lu..%lu and %lu..%lu bytes",
                 a.ulMinKeySize, a.ulMaxKeySize, g.ulMinKeySize, g.ulMaxKeySize);
        ok(ra == CKR_OK && rg == CKR_OK && a.ulMinKeySize == 32 && a.ulMaxKeySize == 64
           && g.ulMinKeySize == 32 && g.ulMaxKeySize == 64, what);
    }

    /* (G) */
    {
        char what[128];
        static const CK_ULONG good[] = { 32, 64 }, bad[] = { 16, 24, 48 };
        for (size_t i = 0; i < 2; i++) {
            CK_OBJECT_HANDLE h = 0;
            CK_RV rv = generate(good[i], NULL, &h);
            CK_MECHANISM m = { CKM_AES_XTS, tw, 16 };
            CK_BYTE ct[40], back[40];
            CK_ULONG cl = sizeof ct, bl = sizeof back;
            if (rv == CKR_OK) rv = C_EncryptInit(s, &m, h);
            if (rv == CKR_OK) rv = C_Encrypt(s, pt, 40, ct, &cl);
            if (rv == CKR_OK) rv = C_DecryptInit(s, &m, h);
            if (rv == CKR_OK) rv = C_Decrypt(s, ct, cl, back, &bl);
            snprintf(what, sizeof what, "(G) %lu-byte key: generated, round trip (0x%lx)",
                     good[i], rv);
            ok(rv == CKR_OK && cl == 40 && bl == 40 && memcmp(back, pt, 40) == 0
               && memcmp(ct, pt, 40) != 0, what);
        }
        for (size_t i = 0; i < 3; i++) {
            CK_OBJECT_HANDLE h = 0;
            CK_RV rv = generate(bad[i], NULL, &h);
            snprintf(what, sizeof what, "(G) %lu bytes: KEY_SIZE_RANGE (0x%lx)", bad[i], rv);
            ok(rv == CKR_KEY_SIZE_RANGE, what);
        }
        CK_ULONG kt = CKK_AES;
        CK_OBJECT_HANDLE h = 0;
        CK_RV rv = generate(32, &kt, &h);
        snprintf(what, sizeof what, "(G) CKA_KEY_TYPE CKK_AES: TEMPLATE_INCONSISTENT (0x%lx)", rv);
        ok(rv == CKR_TEMPLATE_INCONSISTENT, what);
    }

    /* (K) */
    {
        char what[128];
        CK_OBJECT_HANDLE h = 0;
        CK_RV r48 = import(k256v, 48, CKK_AES_XTS, &h);
        CK_BYTE same[32];
        memset(same, 0x5a, sizeof same);
        CK_RV req = import(same, 32, CKK_AES_XTS, &h);
        snprintf(what, sizeof what,
                 "(K) 48 bytes, equal halves: ATTRIBUTE_VALUE_INVALID (0x%lx 0x%lx)", r48, req);
        ok(r48 == CKR_ATTRIBUTE_VALUE_INVALID && req == CKR_ATTRIBUTE_VALUE_INVALID, what);
    }

    /* (L) */
    {
        char what[128];
        CK_MECHANISM m = { CKM_AES_XTS, tw, 16 };
        CK_BYTE out[64]; CK_ULONG ol = sizeof out;
        CK_RV re = C_EncryptInit(s, &m, k128);
        if (re == CKR_OK) re = C_Encrypt(s, pt, 15, out, &ol);
        ol = sizeof out;
        CK_RV rd = C_DecryptInit(s, &m, k128);
        if (rd == CKR_OK) rd = C_Decrypt(s, pt, 15, out, &ol);
        snprintf(what, sizeof what, "(L) 15 bytes: DATA_LEN_RANGE, ENCRYPTED_DATA_LEN_RANGE (0x%lx 0x%lx)",
                 re, rd);
        ok(re == CKR_DATA_LEN_RANGE && rd == CKR_ENCRYPTED_DATA_LEN_RANGE, what);
        CK_RV pe = in_parts(1, &m, k128, pt, 15, out, &ol);
        CK_RV pd = in_parts(0, &m, k128, pt, 15, out, &ol);
        snprintf(what, sizeof what, "(L) 15 bytes in parts: the same (0x%lx 0x%lx)", pe, pd);
        ok(pe == CKR_DATA_LEN_RANGE && pd == CKR_ENCRYPTED_DATA_LEN_RANGE, what);
    }

    /* (P) */
    {
        char what[128];
        CK_MECHANISM none = { CKM_AES_XTS, NULL, 0 }, good = { CKM_AES_XTS, tw, 16 },
                     cbc = { CKM_AES_CBC, tw, 16 };
        CK_RV r0 = C_EncryptInit(s, &none, k128);
        snprintf(what, sizeof what, "(P) no tweak: PARAM_INVALID (0x%lx)", r0);
        ok(r0 == CKR_MECHANISM_PARAM_INVALID, what);
        CK_RV ra = C_EncryptInit(s, &good, aes);
        snprintf(what, sizeof what, "(P) CKK_AES key: KEY_TYPE_INCONSISTENT (0x%lx)", ra);
        ok(ra == CKR_KEY_TYPE_INCONSISTENT, what);
        CK_RV rc = C_EncryptInit(s, &cbc, k128);
        snprintf(what, sizeof what, "(P) XTS key with AES-CBC: KEY_TYPE_INCONSISTENT (0x%lx)", rc);
        ok(rc == CKR_KEY_TYPE_INCONSISTENT, what);
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
