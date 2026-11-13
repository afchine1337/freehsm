/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_store_v5.c --- the two attributes the v5 record holds, through
 * PKCS#11.
 *
 *   (O) CKA_OBJECT_ID of a data object (#38, and #33 C10): kept at creation,
 *       read back, matched by C_FindObjects, changed by C_SetAttributeValue,
 *       carried and replaced by C_CopyObject, empty when never set, refused
 *       past 64 bytes, and not an attribute of a key;
 *   (K) CKA_KEY_GEN_MECHANISM of a key (#37 K3): the mechanism
 *       C_GenerateKey or C_GenerateKeyPair was called with, on both halves
 *       of a pair, carried by a copy, CK_UNAVAILABLE_INFORMATION for an
 *       imported key, and not an attribute of a data object;
 *   (R) both are still there after C_Finalize and C_Initialize: they are in
 *       the token file, not only in memory.
 * tests/test_v4_fixture.c covers the record itself and the older files.
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
#define CKR_ATTRIBUTE_READ_ONLY        0x010UL
#define CKR_ATTRIBUTE_TYPE_INVALID     0x012UL
#define CKR_ATTRIBUTE_VALUE_INVALID    0x013UL
#define CK_UNAVAILABLE_INFORMATION     (~0UL)
#define CKF_RW                         6UL
#define CKU_SO                         0UL
#define CKU_USER                       1UL
#define CKO_DATA                       0UL
#define CKO_SECRET_KEY                 4UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_LABEL                      0x003UL
#define CKA_VALUE                      0x011UL
#define CKA_OBJECT_ID                  0x012UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_KEY_GEN_MECHANISM          0x166UL
#define CKA_EC_PARAMS                  0x180UL
#define CKM_EC_KEY_PAIR_GEN            0x1040UL
#define CKM_AES_KEY_GEN                0x1080UL

/* Test PINs, for a token this program makes in a throwaway directory. */
#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_CopyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG,
                             CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                  CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;
static CK_BYTE oid1[] = { 0x06, 0x03, 0x2A, 0x03, 0x04 };
static CK_BYTE oid2[] = { 0x06, 0x04, 0x2A, 0x03, 0x04, 0x05 };
static CK_BYTE p256[] = { 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 };
static CK_BYTE lbl_data[] = { 'v','5','-','d','a','t','a' };
static CK_BYTE lbl_key[]  = { 'v','5','-','k','e','y' };
static CK_BYTE val[]      = { 'v','a','l','u','e' };

/* Objects matching the template; *first is the first of them. */
static CK_ULONG find(CK_ATTRIBUTE *t, CK_ULONG n, CK_OBJECT_HANDLE *first) {
    CK_OBJECT_HANDLE h[16]; CK_ULONG got = 0;
    if (C_FindObjectsInit(s, t, n) != CKR_OK) return (CK_ULONG)-1;
    (void)C_FindObjects(s, h, 16, &got);
    (void)C_FindObjectsFinal(s);
    if (first) *first = got ? h[0] : 0;
    return got;
}

/* CKA_OBJECT_ID of h: the return value, and the bytes and their length. */
static CK_RV get_oid(CK_OBJECT_HANDLE h, CK_BYTE *out, CK_ULONG *len) {
    CK_ATTRIBUTE q = { CKA_OBJECT_ID, out, 80 };
    CK_RV rv = C_GetAttributeValue(s, h, &q, 1);
    *len = q.ulValueLen;
    return rv;
}
static int oid_is(CK_OBJECT_HANDLE h, const CK_BYTE *want, CK_ULONG wl) {
    CK_BYTE b[80]; CK_ULONG l = 0;
    return get_oid(h, b, &l) == CKR_OK && l == wl && (wl == 0 || memcmp(b, want, wl) == 0);
}
/* CKA_KEY_GEN_MECHANISM of h. */
static CK_RV get_kgm(CK_OBJECT_HANDLE h, CK_ULONG *m) {
    CK_ATTRIBUTE q = { CKA_KEY_GEN_MECHANISM, m, sizeof *m };
    *m = 0x5555UL;
    return C_GetAttributeValue(s, h, &q, 1);
}

static int open_user(void) {
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) return 0;
    return C_Login(s, CKU_USER, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) == CKR_OK;
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_CopyObject);
    SYM(C_GetAttributeValue); SYM(C_SetAttributeValue); SYM(C_FindObjectsInit);
    SYM(C_FindObjects); SYM(C_FindObjectsFinal); SYM(C_GenerateKey); SYM(C_GenerateKeyPair);
    if (!C_CreateObject || !C_CopyObject || !C_SetAttributeValue || !C_GenerateKeyPair
        || !C_FindObjectsFinal) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("CKA_OBJECT_ID and CKA_KEY_GEN_MECHANISM, stored\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"storev5",7);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,CKU_SO,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,CKU_USER,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_ULONG datac = CKO_DATA, secc = CKO_SECRET_KEY, aesk = CKK_AES, len32 = 32;
    CK_OBJECT_HANDLE d = 0, d0 = 0, cp = 0, k = 0, imp = 0, pub = 0, prv = 0, h = 0;
    CK_RV rv;
    CK_ULONG m, l;
    CK_BYTE b[80];

    printf("(O) CKA_OBJECT_ID of a data object\n");
    { CK_ATTRIBUTE t[] = { { CKA_CLASS, &datac, sizeof datac }, { CKA_TOKEN, &yes, 1 },
                           { CKA_LABEL, lbl_data, sizeof lbl_data },
                           { CKA_VALUE, val, sizeof val }, { CKA_OBJECT_ID, oid1, sizeof oid1 } };
      rv = C_CreateObject(s, t, 5, &d);
      ok(rv == CKR_OK && d != 0, "C_CreateObject with CKA_OBJECT_ID: CKR_OK"); }
    ok(oid_is(d, oid1, sizeof oid1), "it reads back as given");
    { CK_ATTRIBUTE q = { CKA_OBJECT_ID, NULL, 0 };
      rv = C_GetAttributeValue(s, d, &q, 1);
      ok(rv == CKR_OK && q.ulValueLen == sizeof oid1, "a size query gives its length"); }
    { CK_ATTRIBUTE f1[] = { { CKA_OBJECT_ID, oid1, sizeof oid1 } };
      CK_ATTRIBUTE f2[] = { { CKA_OBJECT_ID, oid2, sizeof oid2 } };
      ok(find(f1, 1, &h) == 1 && h == d, "C_FindObjects by CKA_OBJECT_ID finds it");
      ok(find(f2, 1, NULL) == 0, "and by another identifier finds nothing"); }
    { CK_ATTRIBUTE t[] = { { CKA_CLASS, &datac, sizeof datac }, { CKA_TOKEN, &no, 1 },
                           { CKA_VALUE, val, sizeof val } };
      rv = C_CreateObject(s, t, 3, &d0);
      ok(rv == CKR_OK && oid_is(d0, NULL, 0), "a data object made without it has an empty one"); }
    { CK_ATTRIBUTE c = { CKA_TOKEN, &no, 1 };
      rv = C_CopyObject(s, d, &c, 1, &cp);
      ok(rv == CKR_OK && oid_is(cp, oid1, sizeof oid1), "C_CopyObject carries it");
      CK_ATTRIBUTE c2[] = { { CKA_TOKEN, &no, 1 }, { CKA_OBJECT_ID, oid2, sizeof oid2 } };
      cp = 0; rv = C_CopyObject(s, d, c2, 2, &cp);
      ok(rv == CKR_OK && oid_is(cp, oid2, sizeof oid2) && oid_is(d, oid1, sizeof oid1),
         "a copy template replaces it, and the source keeps its own"); }
    { CK_ATTRIBUTE a = { CKA_OBJECT_ID, oid2, sizeof oid2 };
      rv = C_SetAttributeValue(s, d, &a, 1);
      ok(rv == CKR_OK && oid_is(d, oid2, sizeof oid2), "C_SetAttributeValue changes it"); }
    { CK_BYTE big[65]; memset(big, 0x2A, sizeof big); big[0] = 0x06; big[1] = 63;
      CK_ATTRIBUTE a = { CKA_OBJECT_ID, big, sizeof big };
      rv = C_SetAttributeValue(s, d, &a, 1);
      ok(rv == CKR_ATTRIBUTE_VALUE_INVALID && oid_is(d, oid2, sizeof oid2),
         "65 bytes: CKR_ATTRIBUTE_VALUE_INVALID, and nothing changes");
      CK_ATTRIBUTE t[] = { { CKA_CLASS, &datac, sizeof datac }, { CKA_TOKEN, &no, 1 },
                           { CKA_OBJECT_ID, big, sizeof big } };
      h = 0; rv = C_CreateObject(s, t, 3, &h);
      ok(rv == CKR_ATTRIBUTE_VALUE_INVALID && h == 0, "the same at creation, and no object");
      a.ulValueLen = 64; rv = C_SetAttributeValue(s, d0, &a, 1);
      ok(rv == CKR_OK && oid_is(d0, big, 64), "64 bytes are kept"); }

    printf("\n(K) CKA_KEY_GEN_MECHANISM of a key\n");
    { CK_ATTRIBUTE t[] = { { CKA_VALUE_LEN, &len32, sizeof len32 }, { CKA_TOKEN, &yes, 1 },
                           { CKA_LABEL, lbl_key, sizeof lbl_key }, { CKA_ENCRYPT, &yes, 1 } };
      CK_MECHANISM g = { CKM_AES_KEY_GEN, NULL, 0 };
      if (C_GenerateKey(s, &g, t, 4, &k)) { fprintf(stderr, "AES key\n"); return 2; }
      rv = get_kgm(k, &m);
      ok(rv == CKR_OK && m == CKM_AES_KEY_GEN, "C_GenerateKey(CKM_AES_KEY_GEN): CKM_AES_KEY_GEN"); }
    { CK_MECHANISM g = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
      CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                            { CKA_EC_PARAMS, p256, sizeof p256 } };
      CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
      if (C_GenerateKeyPair(s, &g, pt, 3, vt, 2, &pub, &prv)) { fprintf(stderr, "EC pair\n"); return 2; }
      CK_ULONG m2 = 0;
      ok(get_kgm(pub, &m) == CKR_OK && m == CKM_EC_KEY_PAIR_GEN
         && get_kgm(prv, &m2) == CKR_OK && m2 == CKM_EC_KEY_PAIR_GEN,
         "C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN): on both halves"); }
    { CK_BYTE v[32]; memset(v, 0x33, sizeof v);
      CK_ATTRIBUTE t[] = { { CKA_CLASS, &secc, sizeof secc }, { CKA_KEY_TYPE, &aesk, sizeof aesk },
                           { CKA_TOKEN, &no, 1 }, { CKA_VALUE, v, sizeof v } };
      if (C_CreateObject(s, t, 4, &imp)) { fprintf(stderr, "import\n"); return 2; }
      rv = get_kgm(imp, &m);
      ok(rv == CKR_OK && m == CK_UNAVAILABLE_INFORMATION,
         "an imported key: CK_UNAVAILABLE_INFORMATION"); }
    { CK_ATTRIBUTE c = { CKA_TOKEN, &no, 1 };
      cp = 0; rv = C_CopyObject(s, k, &c, 1, &cp);
      ok(rv == CKR_OK && get_kgm(cp, &m) == CKR_OK && m == CKM_AES_KEY_GEN,
         "a copy of the generated key keeps its mechanism"); }
    { CK_ATTRIBUTE f[] = { { CKA_KEY_GEN_MECHANISM, &m, sizeof m } };
      m = CKM_EC_KEY_PAIR_GEN;
      ok(find(f, 1, NULL) == 2, "C_FindObjects by CKA_KEY_GEN_MECHANISM finds the pair"); }
    { CK_ULONG gm = CKM_AES_KEY_GEN;
      CK_ATTRIBUTE a = { CKA_KEY_GEN_MECHANISM, &gm, sizeof gm };
      ok(C_SetAttributeValue(s, k, &a, 1) == CKR_ATTRIBUTE_READ_ONLY,
         "C_SetAttributeValue of it: CKR_ATTRIBUTE_READ_ONLY"); }

    printf("\n    each on the other kind of object\n");
    ok(get_oid(k, b, &l) == CKR_ATTRIBUTE_TYPE_INVALID,
       "CKA_OBJECT_ID of a key: CKR_ATTRIBUTE_TYPE_INVALID");
    { CK_ATTRIBUTE a = { CKA_OBJECT_ID, oid1, sizeof oid1 };
      ok(C_SetAttributeValue(s, k, &a, 1) == CKR_ATTRIBUTE_TYPE_INVALID, "and to set it, the same");
      CK_ATTRIBUTE c[] = { { CKA_TOKEN, &no, 1 }, { CKA_OBJECT_ID, oid1, sizeof oid1 } };
      cp = 0; rv = C_CopyObject(s, k, c, 2, &cp);
      ok(rv == CKR_ATTRIBUTE_TYPE_INVALID && cp == 0, "and in a copy of the key, with no copy made"); }
    ok(get_kgm(d, &m) == CKR_ATTRIBUTE_TYPE_INVALID,
       "CKA_KEY_GEN_MECHANISM of a data object: CKR_ATTRIBUTE_TYPE_INVALID");

    printf("\n(R) after C_Finalize and C_Initialize\n");
    C_Finalize(NULL);
    if (C_Initialize(NULL) || !open_user()) { fprintf(stderr, "reopen\n"); return 2; }
    { CK_ATTRIBUTE fd[] = { { CKA_CLASS, &datac, sizeof datac },
                            { CKA_LABEL, lbl_data, sizeof lbl_data } };
      CK_ATTRIBUTE fk[] = { { CKA_CLASS, &secc, sizeof secc },
                            { CKA_LABEL, lbl_key, sizeof lbl_key } };
      d = k = 0;
      ok(find(fd, 2, &d) == 1 && find(fk, 2, &k) == 1, "the two token objects are found again");
      ok(d && oid_is(d, oid2, sizeof oid2), "the data object has the CKA_OBJECT_ID last set");
      ok(k && get_kgm(k, &m) == CKR_OK && m == CKM_AES_KEY_GEN,
         "the key has its CKA_KEY_GEN_MECHANISM"); }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
