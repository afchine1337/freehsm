/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_derive_des_parity.c --- a DES-family key derived by a byte derivation
 * has its parity bits set.
 *
 * PKCS#11 v3.2 has the derivation mechanisms set the parity bits of a DES,
 * DES2, DES3 or CDMF key they produce. The module stored the bytes the
 * concatenation or XOR gave, low bits and all. Found by pkcs11-check 0.3.0
 * (TestDerivedDesParity, four mechanisms by four key types).
 *
 * The cases, with CKM_XOR_BASE_AND_DATA over a generic secret, so the
 * expected value is computed here byte by byte:
 *   - CKK_DES (8), CKK_DES2 (16), CKK_DES3 (24), CKK_CDMF (8): every byte of
 *     the derived value has odd parity, and its upper seven bits are the XOR;
 *   - CKM_CONCATENATE_BASE_AND_DATA to CKK_DES3: the same, on another
 *     mechanism;
 *   - control: CKK_GENERIC_SECRET keeps the XOR exactly, low bits included.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_BYTE *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;

#define CKR_OK                         0UL
#define CKF_RW                         6UL
#define CKA_CLASS                      0x0UL
#define CKA_TOKEN                      0x1UL
#define CKA_VALUE                      0x11UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_DERIVE                     0x10CUL
#define CKA_EXTRACTABLE                0x162UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_DES                        0x13UL
#define CKK_DES2                       0x14UL
#define CKK_DES3                       0x15UL
#define CKK_CDMF                       0x1EUL
#define CKM_CONCATENATE_BASE_AND_DATA  0x362UL
#define CKM_XOR_BASE_AND_DATA          0x364UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                            CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);

static CK_BYTE g_yes = 1, g_no = 0;
static CK_ULONG g_klass = CKO_SECRET_KEY, g_gen = CKK_GENERIC_SECRET;

static int odd_parity(CK_BYTE b) {
    int n = 0;
    for (; b; b &= (CK_BYTE)(b - 1)) n++;
    return n & 1;
}

/* Derives a `kt` key from `base` with `mech` over `data`, reads the value
 * into `out`. Returns its length, or 0. */
static CK_ULONG derive(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE base, CK_ULONG mech,
                       CK_BYTE *data, CK_ULONG dl, CK_ULONG kt, CK_BYTE *out)
{
    CK_KEY_DERIVATION_STRING_DATA p = { data, dl };
    CK_MECHANISM m = { mech, &p, sizeof p };
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &g_klass, sizeof g_klass },
                         { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &g_no, 1 }, { CKA_SENSITIVE, &g_no, 1 },
                         { CKA_EXTRACTABLE, &g_yes, 1 } };
    CK_OBJECT_HANDLE h = 0;
    if (C_DeriveKey(s, &m, base, t, 5, &h) != CKR_OK) return 0;
    CK_ATTRIBUTE v = { CKA_VALUE, out, 32 };
    if (C_GetAttributeValue(s, h, &v, 1) != CKR_OK) return 0;
    return v.ulValueLen;
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject);
    SYM(C_DeriveKey); SYM(C_GetAttributeValue);
    if (!C_DeriveKey || !C_GetAttributeValue || !C_Logout) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("Parity of derived DES-family keys\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"desparity",9);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    /* A base whose bytes, XORed with the data, have both parities. */
    CK_BYTE bv[24], data[24];
    for (int i = 0; i < 24; ++i) { bv[i] = (CK_BYTE)(i * 29 + 3); data[i] = (CK_BYTE)(i * 53 + 1); }
    CK_ATTRIBUTE bt[] = { { CKA_CLASS, &g_klass, sizeof g_klass },
                          { CKA_KEY_TYPE, &g_gen, sizeof g_gen },
                          { CKA_VALUE, bv, sizeof bv }, { CKA_TOKEN, &g_no, 1 },
                          { CKA_SENSITIVE, &g_no, 1 }, { CKA_EXTRACTABLE, &g_yes, 1 },
                          { CKA_DERIVE, &g_yes, 1 } };
    CK_OBJECT_HANDLE base = 0;
    if (C_CreateObject(s, bt, 7, &base) != CKR_OK) { fprintf(stderr, "base key\n"); return 2; }

    static const struct { const char *name; CK_ULONG kt; CK_ULONG len; } T[] = {
        { "CKK_DES",  CKK_DES,  8 },  { "CKK_DES2", CKK_DES2, 16 },
        { "CKK_DES3", CKK_DES3, 24 }, { "CKK_CDMF", CKK_CDMF, 8 },
    };
    for (size_t k = 0; k < sizeof T / sizeof T[0]; ++k) {
        CK_BYTE out[32];
        CK_ULONG n = derive(s, base, CKM_XOR_BASE_AND_DATA, data, T[k].len, T[k].kt, out);
        int good = n == T[k].len;
        for (CK_ULONG i = 0; good && i < n; ++i)
            good = odd_parity(out[i]) && (out[i] & 0xFE) == ((bv[i] ^ data[i]) & 0xFE);
        char what[96];
        snprintf(what, sizeof what, "XOR_BASE_AND_DATA -> %s: odd parity, XOR kept", T[k].name);
        ok(good, what);
    }

    {   /* Another mechanism: an 8-byte base and 16 bytes of data make the 24
         * bytes of a DES3 key. */
        CK_ATTRIBUTE b8[] = { { CKA_CLASS, &g_klass, sizeof g_klass },
                              { CKA_KEY_TYPE, &g_gen, sizeof g_gen },
                              { CKA_VALUE, bv, 8 }, { CKA_TOKEN, &g_no, 1 },
                              { CKA_SENSITIVE, &g_no, 1 }, { CKA_EXTRACTABLE, &g_yes, 1 },
                              { CKA_DERIVE, &g_yes, 1 } };
        CK_OBJECT_HANDLE base8 = 0;
        CK_BYTE out[32];
        CK_ULONG n = C_CreateObject(s, b8, 7, &base8) == CKR_OK
                   ? derive(s, base8, CKM_CONCATENATE_BASE_AND_DATA, data, 16, CKK_DES3, out) : 0;
        int good = n == 24;
        for (CK_ULONG i = 0; good && i < n; ++i) {
            CK_BYTE want = i < 8 ? bv[i] : data[i - 8];
            good = odd_parity(out[i]) && (out[i] & 0xFE) == (want & 0xFE);
        }
        ok(good, "CONCATENATE_BASE_AND_DATA -> CKK_DES3: odd parity, bytes kept");
    }

    {   /* The control: a generic secret is not touched. */
        CK_BYTE out[32];
        CK_ULONG n = derive(s, base, CKM_XOR_BASE_AND_DATA, data, 16, CKK_GENERIC_SECRET, out);
        int good = n == 16;
        for (CK_ULONG i = 0; good && i < n; ++i) good = out[i] == (CK_BYTE)(bv[i] ^ data[i]);
        ok(good, "control: CKK_GENERIC_SECRET keeps the XOR exactly");
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
