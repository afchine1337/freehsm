/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_key_history.c --- CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, and what
 * a derived key keeps of its base key.
 *
 * The two attributes are history. They were read from the current flags, so a
 * key that had been in the clear reported that it never had.
 *
 * The second half is a separate rule found beside the first: the §6.43
 * mechanisms put the base key's bytes in their output. If the template decides
 * that output's protection, a sensitive key can be read back through it.
 *
 * What is asserted (S = CKA_ALWAYS_SENSITIVE, N = CKA_NEVER_EXTRACTABLE):
 *   (1) generated sensitive and not extractable: S and N
 *   (2) generated in the clear: neither; made sensitive and not extractable
 *       afterwards: still neither
 *   (3) C_CreateObject, sensitive and not extractable: neither (§5.7)
 *   (4) C_UnwrapKey, sensitive and not extractable: neither (§5.18)
 *   (5) C_CopyObject takes the original's, with a template or without (§5.7)
 *   (6) derived, from a base with both: as its own flags say (§6.42.7)
 *   (7) derived, from a base with neither: neither, however it is protected
 *   (8) the history survives a reload of a token object
 *   (9) CKM_CONCATENATE_BASE_AND_DATA, _DATA_AND_BASE, CKM_XOR_BASE_AND_DATA
 *       and CKM_CONCATENATE_BASE_AND_KEY from a sensitive, unextractable key:
 *       a template asking for the opposite is CKR_TEMPLATE_INCONSISTENT and
 *       creates nothing (2.7.0; 2.6.0 accepted it and sealed the key); a
 *       template that names neither gives a key that is sensitive, not
 *       extractable, and whose CKA_VALUE does not read
 *  (10) the same from a key in the clear: the template still decides
 *  (11) a generated sensitive key's bytes do not come back out through XOR
 *       with zeros or concatenation: a copy imported from them would compute
 *       the same HMAC
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { void *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_PRF_DATA_PARAM;
typedef struct { CK_BYTE bLittleEndian; CK_ULONG ulWidthInBits; } CK_SP800_108_COUNTER_FORMAT;
typedef struct { CK_ULONG prfType, ulNumberOfDataParams; CK_PRF_DATA_PARAM *pDataParams;
                 CK_ULONG ulAdditionalDerivedKeys; void *pAdditionalDerivedKeys; } CK_SP800_108_KDF_PARAMS;

#define CKR_OK               0UL
#define CKR_TEMPLATE_INCONSISTENT 0xD1UL
#define CKF_RW               6UL
#define CKA_CLASS            0x000UL
#define CKA_TOKEN            0x001UL
#define CKA_LABEL            0x003UL
#define CKA_VALUE            0x011UL
#define CKA_KEY_TYPE         0x100UL
#define CKA_SENSITIVE        0x103UL
#define CKA_ENCRYPT          0x104UL
#define CKA_SIGN             0x108UL
#define CKA_WRAP             0x106UL
#define CKA_UNWRAP           0x107UL
#define CKA_DERIVE           0x10CUL
#define CKA_VALUE_LEN        0x161UL
#define CKA_EXTRACTABLE      0x162UL
#define CKA_NEVER_EXTRACTABLE 0x164UL
#define CKA_ALWAYS_SENSITIVE 0x165UL
#define CKO_SECRET_KEY       4UL
#define CKK_GENERIC_SECRET   0x10UL
#define CKK_AES              0x1FUL
#define CKM_GENERIC_KEY_GEN  0x350UL
#define CKM_AES_KEY_GEN      0x1080UL
#define CKM_AES_KEY_WRAP     0x2109UL
#define CKM_CONCAT_KEY       0x360UL
#define CKM_CONCAT_BASE_DATA 0x362UL
#define CKM_CONCAT_DATA_BASE 0x363UL
#define CKM_XOR_BASE_DATA    0x364UL
#define CKM_COUNTER_KDF      0x3ACUL
#define CKM_SHA256_HMAC      0x251UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_CopyObject)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_WrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;
static CK_ULONG cls = CKO_SECRET_KEY, generic = CKK_GENERIC_SECRET, aes = CKK_AES, len32 = 32;

static int get_bool(CK_OBJECT_HANDLE h, CK_ULONG type) {
    CK_BYTE v = 2; CK_ATTRIBUTE a = { type, &v, 1 };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? v : -1;
}
/* 1 when CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE are as stated. */
static int hist(CK_OBJECT_HANDLE h, int always, int never) {
    return get_bool(h, CKA_ALWAYS_SENSITIVE) == always
        && get_bool(h, CKA_NEVER_EXTRACTABLE) == never;
}

static char token_label[] = "hist-token";

static CK_OBJECT_HANDLE gen_key(CK_ULONG mech, CK_BYTE sens, CK_BYTE extr, CK_BYTE tok,
                                char *label) {
    CK_MECHANISM m = { mech, NULL, 0 };
    CK_ATTRIBUTE t[] = { { CKA_TOKEN, &tok, 1 }, { CKA_VALUE_LEN, &len32, sizeof len32 },
                         { CKA_SENSITIVE, &sens, 1 }, { CKA_EXTRACTABLE, &extr, 1 },
                         { CKA_DERIVE, &yes, 1 }, { CKA_WRAP, &yes, 1 }, { CKA_UNWRAP, &yes, 1 },
                         { CKA_LABEL, label, label ? strlen(label) : 0 } };
    CK_OBJECT_HANDLE h = 0;
    CK_RV rv = C_GenerateKey(s, &m, t, label ? 8 : 7, &h);
    if (rv != CKR_OK) fprintf(stderr, "C_GenerateKey 0x%lx: 0x%lx\n", mech, rv);
    return h;
}

/* A derive template asking for the given protection. */
static CK_RV derive_as(CK_MECHANISM *m, CK_OBJECT_HANDLE base, CK_BYTE sens, CK_BYTE extr,
                       CK_ATTRIBUTE *extra, CK_OBJECT_HANDLE *h) {
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &generic, sizeof generic },
                         { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &sens, 1 },
                         { CKA_EXTRACTABLE, &extr, 1 }, { 0, NULL, 0 } };
    if (extra) t[5] = *extra;
    return C_DeriveKey(s, m, base, t, extra ? 6 : 5, h);
}

/* The same derivation with a template that names neither CKA_SENSITIVE nor
 * CKA_EXTRACTABLE: the base's protection is all the key gets. */
static CK_RV derive_plain(CK_MECHANISM *m, CK_OBJECT_HANDLE base, CK_OBJECT_HANDLE *h) {
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &generic, sizeof generic },
                         { CKA_TOKEN, &no, 1 } };
    return C_DeriveKey(s, m, base, t, 3, h);
}

static int value_readable(CK_OBJECT_HANDLE h) {
    CK_BYTE v[128]; CK_ATTRIBUTE a = { CKA_VALUE, v, sizeof v };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK;
}

int main(void)
{
    void *hl = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!hl) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*C_Initialize)(void*); CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(hl,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession); SYM(C_Login);
    SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKey); SYM(C_CreateObject); SYM(C_CopyObject);
    SYM(C_DeriveKey); SYM(C_WrapKey); SYM(C_UnwrapKey); SYM(C_GetAttributeValue);
    SYM(C_SetAttributeValue); SYM(C_FindObjectsInit); SYM(C_FindObjects); SYM(C_FindObjectsFinal);
    SYM(C_SignInit); SYM(C_Sign);

    printf("CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, and derived keys\n\n");

    CK_BYTE tl[32];
    memset(tl, ' ', 32); memcpy(tl, "history", 7);
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), tl) != CKR_OK) { fprintf(stderr, "C_InitToken\n"); return 2; }
    C_OpenSession(0, CKF_RW, NULL, NULL, &s);
    C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN));
    C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN));
    C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login\n"); return 2; }

    /* (1), (2) */
    CK_OBJECT_HANDLE locked = gen_key(CKM_GENERIC_KEY_GEN, 1, 0, 0, NULL);
    CK_OBJECT_HANDLE open_ = gen_key(CKM_GENERIC_KEY_GEN, 0, 1, 0, NULL);
    CK_OBJECT_HANDLE turned = gen_key(CKM_GENERIC_KEY_GEN, 0, 1, 0, NULL);
    if (!locked || !open_ || !turned) return 2;
    ok(hist(locked, 1, 1), "(1) generated sensitive, not extractable: both");
    ok(hist(open_, 0, 0), "(2) generated in the clear: neither");
    CK_ATTRIBUTE up[] = { { CKA_SENSITIVE, &yes, 1 }, { CKA_EXTRACTABLE, &no, 1 } };
    CK_RV rv = C_SetAttributeValue(s, turned, up, 2);
    ok(rv == CKR_OK && get_bool(turned, CKA_SENSITIVE) == 1 && get_bool(turned, CKA_EXTRACTABLE) == 0
       && hist(turned, 0, 0), "(2) made sensitive afterwards: still neither");

    /* (3) */
    CK_BYTE val[32];
    memset(val, 0x5A, sizeof val);
    CK_ATTRIBUTE ct[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &generic, sizeof generic },
                          { CKA_TOKEN, &no, 1 }, { CKA_VALUE, val, sizeof val },
                          { CKA_SENSITIVE, &yes, 1 }, { CKA_EXTRACTABLE, &no, 1 },
                          { CKA_DERIVE, &yes, 1 } };
    CK_OBJECT_HANDLE created = 0;
    rv = C_CreateObject(s, ct, 7, &created);
    ok(rv == CKR_OK && get_bool(created, CKA_SENSITIVE) == 1 && hist(created, 0, 0),
       "(3) C_CreateObject, sensitive: neither");

    /* (4) */
    CK_OBJECT_HANDLE kek = gen_key(CKM_AES_KEY_GEN, 1, 0, 0, NULL), target = gen_key(CKM_AES_KEY_GEN, 0, 1, 0, NULL), un = 0;
    CK_MECHANISM kw = { CKM_AES_KEY_WRAP, NULL, 0 };
    CK_BYTE wr[64]; CK_ULONG wl = sizeof wr;
    CK_ATTRIBUTE ut[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &aes, sizeof aes },
                          { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &yes, 1 }, { CKA_EXTRACTABLE, &no, 1 } };
    rv = C_WrapKey(s, &kw, kek, target, wr, &wl);
    rv = rv == CKR_OK ? C_UnwrapKey(s, &kw, kek, wr, wl, ut, 5, &un) : rv;
    ok(rv == CKR_OK && get_bool(un, CKA_SENSITIVE) == 1 && hist(un, 0, 0),
       "(4) C_UnwrapKey, sensitive: neither");

    /* (5) */
    CK_OBJECT_HANDLE c1 = 0, c2 = 0;
    rv = C_CopyObject(s, locked, NULL, 0, &c1);
    ok(rv == CKR_OK && hist(c1, 1, 1), "(5) a copy of a key with both has both");
    CK_ATTRIBUTE cu[] = { { CKA_SENSITIVE, &yes, 1 }, { CKA_EXTRACTABLE, &no, 1 } };
    rv = C_CopyObject(s, open_, cu, 2, &c2);
    ok(rv == CKR_OK && get_bool(c2, CKA_SENSITIVE) == 1 && hist(c2, 0, 0),
       "(5) a copy made sensitive of a key with neither has neither");

    /* (6), (7) through a KDF, whose template is free. */
    CK_SP800_108_COUNTER_FORMAT c16 = { 0, 16 };
    CK_PRF_DATA_PARAM dp[] = { { 1UL, &c16, sizeof c16 } };
    CK_SP800_108_KDF_PARAMS kp = { CKM_SHA256_HMAC, 1, dp, 0, NULL };
    CK_MECHANISM kdf = { CKM_COUNTER_KDF, &kp, sizeof kp };
    CK_ATTRIBUTE vl = { CKA_VALUE_LEN, &len32, sizeof len32 };
    CK_OBJECT_HANDLE d = 0;
    rv = derive_as(&kdf, locked, 1, 0, &vl, &d);
    ok(rv == CKR_OK && hist(d, 1, 1), "(6) base with both, derived sensitive: both");
    rv = derive_as(&kdf, locked, 0, 1, &vl, &d);
    ok(rv == CKR_OK && hist(d, 0, 0), "(6) base with both, derived in the clear: neither");
    rv = derive_as(&kdf, created, 1, 0, &vl, &d);
    ok(rv == CKR_OK && get_bool(d, CKA_SENSITIVE) == 1 && hist(d, 0, 0),
       "(7) base with neither, derived sensitive: neither");

    /* (8) */
    {
        CK_OBJECT_HANDLE tk = gen_key(CKM_GENERIC_KEY_GEN, 0, 1, 1, token_label);
        C_SetAttributeValue(s, tk, up, 2);
        C_Finalize(NULL);
        C_Initialize(NULL);
        C_OpenSession(0, CKF_RW, NULL, NULL, &s);
        C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN));
        CK_ATTRIBUTE f = { CKA_LABEL, token_label, 10 };
        CK_OBJECT_HANDLE found = 0; CK_ULONG n = 0;
        C_FindObjectsInit(s, &f, 1);
        C_FindObjects(s, &found, 1, &n);
        C_FindObjectsFinal(s);
        ok(n == 1 && get_bool(found, CKA_SENSITIVE) == 1 && hist(found, 0, 0),
           "(8) after a reload, a token key has still neither");
        locked = gen_key(CKM_GENERIC_KEY_GEN, 1, 0, 0, NULL);
        open_ = gen_key(CKM_GENERIC_KEY_GEN, 0, 1, 0, NULL);
    }

    /* (9), (10) */
    {
        CK_BYTE data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        CK_KEY_DERIVATION_STRING_DATA sd = { data, sizeof data };
        struct { CK_ULONG m; const char *name; } ms[] = {
            { CKM_CONCAT_BASE_DATA, "CKM_CONCATENATE_BASE_AND_DATA" },
            { CKM_CONCAT_DATA_BASE, "CKM_CONCATENATE_DATA_AND_BASE" },
            { CKM_XOR_BASE_DATA,    "CKM_XOR_BASE_AND_DATA" },
        };
        char what[96];
        for (int i = 0; i < 3; ++i) {
            CK_MECHANISM m = { ms[i].m, &sd, sizeof sd };
            CK_OBJECT_HANDLE h = 0;
            rv = derive_as(&m, locked, 0, 1, NULL, &h);
            snprintf(what, sizeof what, "(9) %s: asking for the opposite is refused", ms[i].name);
            ok(rv == CKR_TEMPLATE_INCONSISTENT && h == 0, what);
            rv = derive_plain(&m, locked, &h);
            snprintf(what, sizeof what, "(9) %s: guarded", ms[i].name);
            ok(rv == CKR_OK && get_bool(h, CKA_SENSITIVE) == 1
               && get_bool(h, CKA_EXTRACTABLE) == 0 && !value_readable(h), what);
            rv = derive_as(&m, open_, 0, 1, NULL, &h);
            snprintf(what, sizeof what, "(10) %s: template decides", ms[i].name);
            ok(rv == CKR_OK && value_readable(h), what);
        }
        /* The guarded key is the second operand: the first is in the clear. */
        CK_OBJECT_HANDLE h = 0, other = locked;
        CK_MECHANISM m = { CKM_CONCAT_KEY, &other, sizeof other };
        rv = derive_as(&m, open_, 0, 1, NULL, &h);
        ok(rv == CKR_TEMPLATE_INCONSISTENT && h == 0,
           "(9) CKM_CONCATENATE_BASE_AND_KEY, second key guarded: the opposite is refused");
        rv = derive_plain(&m, open_, &h);
        ok(rv == CKR_OK && get_bool(h, CKA_SENSITIVE) == 1 && get_bool(h, CKA_EXTRACTABLE) == 0
           && !value_readable(h) && hist(h, 0, 0),
           "(9) CKM_CONCATENATE_BASE_AND_KEY, second key guarded");
    }

    /* (11) The bytes themselves. A generated key, sensitive and not
     * extractable, whose value nobody knows: the first 32 bytes of what XOR
     * with zeros or concatenation gives back are imported in the clear, and
     * the copy must not compute the key's HMAC. A generated key rather than
     * an imported one, because before 2.3.1 C_CreateObject ignored
     * CKA_SENSITIVE and the comparison would prove nothing there. */
    {
        CK_BYTE zeros[32] = { 0 }, data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        CK_BYTE msg[] = "key history", mac0[32], mac1[32];
        CK_MECHANISM hm = { CKM_SHA256_HMAC, NULL, 0 };
        CK_ULONG ml = sizeof mac0;
        CK_MECHANISM gm = { CKM_GENERIC_KEY_GEN, NULL, 0 };
        CK_ATTRIBUTE gt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VALUE_LEN, &len32, sizeof len32 },
                              { CKA_SENSITIVE, &yes, 1 }, { CKA_EXTRACTABLE, &no, 1 },
                              { CKA_DERIVE, &yes, 1 }, { CKA_SIGN, &yes, 1 } };
        CK_OBJECT_HANDLE base = 0;
        if ((rv = C_GenerateKey(s, &gm, gt, 6, &base)) != CKR_OK) {
            fprintf(stderr, "(11) setup: C_GenerateKey 0x%lx\n", rv); return 2; }
        if (value_readable(base)) { fprintf(stderr, "(11) setup: value readable\n"); return 2; }
        if ((rv = C_SignInit(s, &hm, base)) != CKR_OK
            || (rv = C_Sign(s, msg, sizeof msg - 1, mac0, &ml)) != CKR_OK) {
            fprintf(stderr, "(11) setup: HMAC 0x%lx\n", rv); return 2; }
        CK_KEY_DERIVATION_STRING_DATA z = { zeros, sizeof zeros }, sd = { data, sizeof data };
        struct { CK_ULONG m; CK_KEY_DERIVATION_STRING_DATA *p; const char *what; } ms[] = {
            { CKM_XOR_BASE_DATA,    &z,  "(11) CKM_XOR_BASE_AND_DATA with zeros: value not recovered" },
            { CKM_CONCAT_BASE_DATA, &sd, "(11) CKM_CONCATENATE_BASE_AND_DATA: value not recovered" },
        };
        for (int i = 0; i < 2; ++i) {
            CK_MECHANISM m = { ms[i].m, ms[i].p, sizeof *ms[i].p };
            CK_OBJECT_HANDLE h = 0, copy = 0;
            CK_BYTE out[64]; CK_ATTRIBUTE a = { CKA_VALUE, out, sizeof out };
            int recovered = 0;
            rv = derive_as(&m, base, 0, 1, NULL, &h);
            if (rv == CKR_OK && C_GetAttributeValue(s, h, &a, 1) == CKR_OK && a.ulValueLen >= 32) {
                CK_ATTRIBUTE ct2[] = { { CKA_CLASS, &cls, sizeof cls },
                                       { CKA_KEY_TYPE, &generic, sizeof generic },
                                       { CKA_TOKEN, &no, 1 }, { CKA_VALUE, out, 32 },
                                       { CKA_SIGN, &yes, 1 } };
                ml = sizeof mac1;
                recovered = C_CreateObject(s, ct2, 5, &copy) == CKR_OK
                         && C_SignInit(s, &hm, copy) == CKR_OK
                         && C_Sign(s, msg, sizeof msg - 1, mac1, &ml) == CKR_OK
                         && memcmp(mac0, mac1, sizeof mac0) == 0;
            }
            ok(!recovered, ms[i].what);
        }
    }

    C_Finalize(NULL);
    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
