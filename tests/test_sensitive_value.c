/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_sensitive_value.c --- when C_GetAttributeValue may give a key's value,
 * and what it answers when it may not.
 *
 * Two defects, one rule. PKCS#11 v3.2, attribute tables, footnote 7: a
 * private or secret key's value "cannot be revealed if object has its
 * CKA_SENSITIVE attribute set to CK_TRUE or its CKA_EXTRACTABLE attribute set
 * to CK_FALSE"; and C_GetAttributeValue, for such an attribute, sets
 * CK_UNAVAILABLE_INFORMATION and returns CKR_ATTRIBUTE_SENSITIVE.
 *
 *   - The value was withheld from a sensitive key, but the call returned
 *     CKR_OK, so a caller checking the return code read a length that was
 *     not one.
 *   - A key that was not sensitive but not extractable -- derived or
 *     imported with CKA_SENSITIVE=FALSE and nothing said about
 *     CKA_EXTRACTABLE, whose default here is FALSE -- gave its value, though
 *     C_WrapKey refused to let it out wrapped.
 *
 * What is asserted:
 *   (1) a generated AES key (sensitive): CKR_ATTRIBUTE_SENSITIVE and
 *       CK_UNAVAILABLE_INFORMATION, for the size query and for the read
 *   (2) imported, not sensitive, extractable: the value, byte for byte
 *   (3) imported, not sensitive, CKA_EXTRACTABLE absent: withheld
 *   (4) imported, not sensitive, CKA_EXTRACTABLE=FALSE: withheld
 *   (5) asked together with CKA_LABEL: the label is given, the value is not,
 *       and the call returns CKR_ATTRIBUTE_SENSITIVE
 *   (6) a public key's CKA_VALUE is still given
 *   (7) C_CreateObject keeps what the template says: CKA_SENSITIVE and
 *       CKA_EXTRACTABLE read back as given, and a key imported sensitive and
 *       extractable is withheld. Import ignored both, so an imported secret
 *       key was never extractable -- unreadable under the rule above even
 *       when asked to be -- and one imported sensitive stayed readable.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                   0UL
#define CKR_ATTRIBUTE_SENSITIVE  0x11UL
#define UNAVAILABLE              ((CK_ULONG)-1)
#define CKF_RW                   6UL
#define CKA_CLASS                0x000UL
#define CKA_TOKEN                0x001UL
#define CKA_LABEL                0x003UL
#define CKA_VALUE                0x011UL
#define CKA_KEY_TYPE             0x100UL
#define CKA_SENSITIVE            0x103UL
#define CKA_ENCRYPT              0x104UL
#define CKA_VERIFY               0x10AUL
#define CKA_SIGN                 0x108UL
#define CKA_VALUE_LEN            0x161UL
#define CKA_EXTRACTABLE          0x162UL
#define CKA_EC_PARAMS            0x180UL
#define CKO_SECRET_KEY           4UL
#define CKK_AES                  0x1FUL
#define CKM_AES_KEY_GEN          0x1080UL
#define CKM_EC_KEY_PAIR_GEN      0x1040UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);

static const CK_BYTE KEYBYTES[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                      0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

/* An AES key imported as a session object; `sensitive` 1 or 0, and
 * `extractable` 1, 0, or -1 for "not in the template". */
static CK_OBJECT_HANDLE import_aes(CK_SESSION_HANDLE s, int sensitive, int extractable) {
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES;
    CK_BYTE no = 0, ex = (CK_BYTE)(extractable > 0), se = (CK_BYTE)(sensitive != 0);
    CK_ATTRIBUTE t[7] = {
        { CKA_CLASS,     &cls, sizeof cls },
        { CKA_KEY_TYPE,  &kt,  sizeof kt },
        { CKA_VALUE,     (void *)KEYBYTES, sizeof KEYBYTES },
        { CKA_TOKEN,     &no,  1 },
        { CKA_SENSITIVE, &se,  1 },
        { CKA_LABEL,     (void *)"imported", 8 },
    };
    CK_ULONG n = 6;
    if (extractable >= 0) t[n++] = (CK_ATTRIBUTE){ CKA_EXTRACTABLE, &ex, 1 };
    CK_OBJECT_HANDLE h = 0;
    CK_RV rv = C_CreateObject(s, t, n, &h);
    if (rv != CKR_OK) { fprintf(stderr, "C_CreateObject AES: 0x%lx\n", rv); return 0; }
    return h;
}

/* A CK_BBOOL attribute: 1, 0, or -1 when it cannot be read. */
static int flag(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ULONG type) {
    CK_BYTE v = 0xFF;
    CK_ATTRIBUTE a = { type, &v, 1 };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? (v != 0) : -1;
}

/* The value read the way a caller does it: size, then bytes. Returns the rv
 * of the second call (or the first, if that failed) and the length seen. */
static CK_RV read_value(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_BYTE *buf,
                        CK_ULONG cap, CK_ULONG *len, CK_RV *size_rv, CK_ULONG *size_len) {
    CK_ATTRIBUTE q = { CKA_VALUE, NULL, 0 };
    *size_rv = C_GetAttributeValue(s, h, &q, 1);
    *size_len = q.ulValueLen;
    CK_ATTRIBUTE a = { CKA_VALUE, buf, cap };
    CK_RV rv = C_GetAttributeValue(s, h, &a, 1);
    *len = a.ulValueLen;
    return rv;
}

int main(void)
{
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                               CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKey);
    SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue); SYM(C_CreateObject);
    if (!C_GetAttributeValue || !C_CreateObject || !C_GenerateKey || !C_GenerateKeyPair) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("C_GetAttributeValue: a key's value, and when it is withheld\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "sensitive")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    CK_BYTE buf[256]; CK_ULONG len = 0, size_len = 0; CK_RV size_rv = 0, rv;

    /* (1) Generated: sensitive by default here, and said so explicitly. */
    {
        CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_AES, vl = 16;
        CK_BYTE yes = 1, no = 0;
        CK_ATTRIBUTE t[] = {
            { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
            { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &no, 1 },
            { CKA_SENSITIVE, &yes, 1 }, { CKA_ENCRYPT, &yes, 1 },
        };
        CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL, 0 };
        CK_OBJECT_HANDLE k = 0;
        if (C_GenerateKey(s, &m, t, sizeof t / sizeof t[0], &k) != CKR_OK) {
            fprintf(stderr, "C_GenerateKey\n"); return 2;
        }
        memset(buf, 0xA5, sizeof buf);
        rv = read_value(s, k, buf, sizeof buf, &len, &size_rv, &size_len);
        ok(size_rv == CKR_ATTRIBUTE_SENSITIVE && size_len == UNAVAILABLE,
           "(1) generated, sensitive: the size query is refused");
        int untouched = 1;
        for (size_t i = 0; i < sizeof buf; i++) untouched &= buf[i] == 0xA5;
        ok(rv == CKR_ATTRIBUTE_SENSITIVE && len == UNAVAILABLE && untouched,
           "(1) and the read: CKR_ATTRIBUTE_SENSITIVE, nothing written");

        /* (5) Asked beside an attribute that may be given. */
        char lb[64] = "";
        CK_ATTRIBUTE two[2] = { { CKA_LABEL, lb, sizeof lb }, { CKA_VALUE, buf, sizeof buf } };
        rv = C_GetAttributeValue(s, k, two, 2);
        ok(rv == CKR_ATTRIBUTE_SENSITIVE && two[1].ulValueLen == UNAVAILABLE
           && two[0].ulValueLen != UNAVAILABLE,
           "(5) beside CKA_LABEL: the label is given, the value is not");
    }

    /* (2) to (4): imported, not sensitive. */
    CK_OBJECT_HANDLE ext = import_aes(s, 0, 1), absent = import_aes(s, 0, -1),
                     notext = import_aes(s, 0, 0), sens = import_aes(s, 1, 1);
    if (!ext || !absent || !notext || !sens) return 2;

    rv = read_value(s, ext, buf, sizeof buf, &len, &size_rv, &size_len);
    ok(size_rv == CKR_OK && size_len == 16 && rv == CKR_OK && len == 16
       && !memcmp(buf, KEYBYTES, 16),
       "(2) not sensitive, extractable: the value, byte for byte");

    rv = read_value(s, absent, buf, sizeof buf, &len, &size_rv, &size_len);
    ok(rv == CKR_ATTRIBUTE_SENSITIVE && len == UNAVAILABLE && size_rv == CKR_ATTRIBUTE_SENSITIVE,
       "(3) not sensitive, CKA_EXTRACTABLE left out: withheld");

    rv = read_value(s, notext, buf, sizeof buf, &len, &size_rv, &size_len);
    ok(rv == CKR_ATTRIBUTE_SENSITIVE && len == UNAVAILABLE && size_rv == CKR_ATTRIBUTE_SENSITIVE,
       "(4) not sensitive, CKA_EXTRACTABLE=FALSE: withheld");

    /* (7) The template, kept. */
    ok(flag(s, ext, CKA_SENSITIVE) == 0 && flag(s, ext, CKA_EXTRACTABLE) == 1,
       "(7) imported not sensitive, extractable: reads back so");
    ok(flag(s, absent, CKA_EXTRACTABLE) == 0 && flag(s, notext, CKA_EXTRACTABLE) == 0,
       "(7) CKA_EXTRACTABLE absent or FALSE: reads back FALSE");
    ok(flag(s, sens, CKA_SENSITIVE) == 1 && flag(s, sens, CKA_EXTRACTABLE) == 1,
       "(7) imported sensitive and extractable: reads back so");
    rv = read_value(s, sens, buf, sizeof buf, &len, &size_rv, &size_len);
    ok(rv == CKR_ATTRIBUTE_SENSITIVE && len == UNAVAILABLE,
       "(7) and its value is withheld: sensitive wins");

    /* (6) A public key is public. */
    {
        static const CK_BYTE P256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
        CK_BYTE yes = 1, no = 0;
        CK_ATTRIBUTE pt[] = { { CKA_EC_PARAMS, (void *)P256, sizeof P256 },
                              { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 } };
        CK_ATTRIBUTE kt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
        CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE pub = 0, priv = 0;
        if (C_GenerateKeyPair(s, &m, pt, 3, kt, 2, &pub, &priv) != CKR_OK) {
            fprintf(stderr, "C_GenerateKeyPair\n"); return 2;
        }
        rv = read_value(s, pub, buf, sizeof buf, &len, &size_rv, &size_len);
        ok(rv == CKR_OK && len != UNAVAILABLE && len > 0,
           "(6) a public key's CKA_VALUE is given");
        rv = read_value(s, priv, buf, sizeof buf, &len, &size_rv, &size_len);
        ok(rv == CKR_ATTRIBUTE_SENSITIVE && len == UNAVAILABLE,
           "(6) its private half's is not");
    }

    C_Finalize(NULL);
    printf("\n%s (%d failure%s)\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
