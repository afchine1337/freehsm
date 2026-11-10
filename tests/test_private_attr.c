/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_private_attr.c --- a data object's CKA_PRIVATE is what the template
 * says, and access before login follows CKA_PRIVATE.
 *
 * PKCS#11 v3.2 §4.4 leaves the default to the token, and says a user "may not
 * access the object until the user has been authenticated to the token" when
 * it is TRUE. The module set CKA_PRIVATE by class and ignored the template:
 * a data object created with CKA_PRIVATE=FALSE read back TRUE, and every data
 * object, private by that rule, was readable before a login all the same.
 * Found by pkcs11-check 0.3.0 (test_logout_object_lifetime_across_two_sessions).
 *
 * The cases:
 *   (1) data objects: CKA_PRIVATE=FALSE reads back FALSE; absent or TRUE
 *       reads back TRUE;
 *   (2) a secret key created with CKA_PRIVATE=FALSE is private all the same;
 *   (3) a public key asked CKA_PRIVATE=TRUE stays public: the store records
 *       only the data-object direction, which an older build cannot loosen;
 *   (4) C_CopyObject: a private data object copied with CKA_PRIVATE=FALSE is
 *       public; a secret key copied so stays private;
 *   (5) after C_Logout: the public data objects and the public key are
 *       found, the private data objects are not; a public session data
 *       object survives the logout and a private one does not;
 *   (6) in a new process image (C_Finalize, C_Initialize), before any login:
 *       the public token data object is found and read from the public
 *       section, the private one is not found;
 *   (7) with the SO logged in, which decrypts the store, no handle that the
 *       search hides can be changed (C_SetAttributeValue), copied out with
 *       CKA_PRIVATE=FALSE (C_CopyObject) or destroyed (C_DestroyObject); the
 *       user then finds the private data objects intact. Those three calls
 *       ran no access check, and handles are small integers;
 *   (8) only the user makes a private object (#31): without a login, a data
 *       object without CKA_PRIVATE is refused (the store makes no object
 *       before a login at all, public or not); with the SO logged in,
 *       C_CreateObject of a private secret key or data object, C_GenerateKey,
 *       C_GenerateKeyPair and a copy made CKA_PRIVATE=TRUE are all
 *       CKR_USER_NOT_LOGGED_IN, while public data objects are still made;
 *   (9) a read-only session copies a token object into a session object
 *       only (#30): a template that leaves CKA_TOKEN out, and an empty one,
 *       inherit TRUE and are CKR_SESSION_READ_ONLY; CKA_TOKEN=FALSE is made;
 *  (10) with the SO logged in, every hidden handle gets from C_WrapKey (as the
 *       key wrapped), C_UnwrapKey (as the unwrapping key), C_DeriveKey (as
 *       the base key) and C_DecapsulateKey the answer a missing handle gets,
 *       for a data-object template and a secret-key one. C_WrapKey under a
 *       public RSA key took a private data object or key out, C_UnwrapKey
 *       and C_DeriveKey used the user's keys into a public data object, and
 *       their earlier checks told which hidden handles existed;
 *  (11) the user alone: C_DeriveKey and C_UnwrapKey make no data object and
 *       no public key, and C_WrapKey wraps no data object -- a data object
 *       derived from a key with CKA_EXTRACTABLE=FALSE took that key out --
 *       nor a public key. The non-extractable key is still refused.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                    0UL
#define CKR_USER_NOT_LOGGED_IN    0x101UL
#define CKR_SESSION_READ_ONLY     0xB5UL
#define CKR_KEY_HANDLE_INVALID    0x60UL
#define CKR_KEY_NOT_WRAPPABLE     0x69UL
#define CKR_KEY_UNEXTRACTABLE     0x6AUL
#define CKR_TEMPLATE_INCONSISTENT 0xD1UL
#define CKO_PUBLIC_KEY            2UL
#define CKA_SENSITIVE             0x103UL
#define CKA_WRAP                  0x106UL
#define CKA_UNWRAP                0x107UL
#define CKA_DERIVE                0x10CUL
#define CKA_MODULUS_BITS          0x121UL
#define CKA_PUBLIC_EXPONENT       0x122UL
#define CKA_EXTRACTABLE           0x162UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x0UL
#define CKM_RSA_PKCS_OAEP         0x9UL
#define CKM_SHA256                0x250UL
#define CKG_MGF1_SHA256           0x2UL
#define CKZ_DATA_SPECIFIED        0x1UL
#define CKM_ML_KEM                0x17UL
#define CKM_CONCATENATE_BASE_AND_DATA 0x362UL
#define MISSING_HANDLE            100000UL
#define CKF_SERIAL                4UL
#define CKK_GENERIC_SECRET        0x10UL
#define CKF_RW                    6UL
#define CKA_CLASS                 0x0UL
#define CKA_TOKEN                 0x1UL
#define CKA_PRIVATE               0x2UL
#define CKA_LABEL                 0x3UL
#define CKA_VALUE                 0x11UL
#define CKA_KEY_TYPE              0x100UL
#define CKA_SIGN                  0x108UL
#define CKA_VERIFY                0x10AUL
#define CKA_VALUE_LEN             0x161UL
#define CKA_EC_PARAMS             0x180UL
#define CKO_DATA                  0UL
#define CKO_SECRET_KEY            4UL
#define CKK_AES                   0x1FUL
#define CKM_AES_KEY_GEN           0x1080UL
#define CKM_EC_KEY_PAIR_GEN       0x1040UL

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
static CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_CopyObject)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,
                             CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                              CK_OBJECT_HANDLE*);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE);
static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
static CK_RV (*C_WrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,
                          CK_BYTE*,CK_ULONG*);
static CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG,
                            CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,
                            CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_DecapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,
                                 CK_ULONG,CK_BYTE*,CK_ULONG,CK_OBJECT_HANDLE*);

typedef struct { CK_ULONG hashAlg, mgf, source; void *pSourceData; CK_ULONG ulSourceDataLen; }
    CK_RSA_PKCS_OAEP_PARAMS;
typedef struct { CK_BYTE *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;

static CK_BYTE g_yes = 1, g_no = 0;
static CK_ULONG g_data = CKO_DATA, g_secret = CKO_SECRET_KEY, g_aes = CKK_AES;

/* A data object. `priv` is 1, 0 or -1 (the template does not name it). */
static CK_OBJECT_HANDLE mkdata(CK_SESSION_HANDLE s, const char *label, int token, int priv)
{
    CK_ATTRIBUTE t[5];
    CK_ULONG c = 0;
    t[c].type = CKA_CLASS; t[c].pValue = &g_data; t[c].ulValueLen = sizeof g_data; c++;
    t[c].type = CKA_LABEL; t[c].pValue = (void*)label; t[c].ulValueLen = (CK_ULONG)strlen(label); c++;
    t[c].type = CKA_VALUE; t[c].pValue = (void*)label; t[c].ulValueLen = (CK_ULONG)strlen(label); c++;
    t[c].type = CKA_TOKEN; t[c].pValue = token ? &g_yes : &g_no; t[c].ulValueLen = 1; c++;
    if (priv >= 0) { t[c].type = CKA_PRIVATE; t[c].pValue = priv ? &g_yes : &g_no;
                     t[c].ulValueLen = 1; c++; }
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, c, &h) == CKR_OK ? h : 0;
}

/* The same, returning C_CreateObject's answer. */
static CK_RV mkdata_rv(CK_SESSION_HANDLE s, const char *label, int token, int priv)
{
    CK_ATTRIBUTE t[5];
    CK_ULONG c = 0;
    t[c].type = CKA_CLASS; t[c].pValue = &g_data; t[c].ulValueLen = sizeof g_data; c++;
    t[c].type = CKA_LABEL; t[c].pValue = (void*)label; t[c].ulValueLen = (CK_ULONG)strlen(label); c++;
    t[c].type = CKA_VALUE; t[c].pValue = (void*)label; t[c].ulValueLen = (CK_ULONG)strlen(label); c++;
    t[c].type = CKA_TOKEN; t[c].pValue = token ? &g_yes : &g_no; t[c].ulValueLen = 1; c++;
    if (priv >= 0) { t[c].type = CKA_PRIVATE; t[c].pValue = priv ? &g_yes : &g_no;
                     t[c].ulValueLen = 1; c++; }
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, c, &h);
}

/* CKA_PRIVATE as read back: 1, 0, or -1. */
static int read_private(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h)
{
    CK_BYTE v = 0xFF;
    CK_ATTRIBUTE a = { CKA_PRIVATE, &v, 1 };
    if (C_GetAttributeValue(s, h, &a, 1) != CKR_OK) return -1;
    return v ? 1 : 0;
}

/* Handles whose CKA_LABEL is `label`; the count, the first in *first. */
static CK_ULONG find_label(CK_SESSION_HANDLE s, const char *label, CK_OBJECT_HANDLE *first)
{
    CK_ATTRIBUTE t = { CKA_LABEL, (void*)label, (CK_ULONG)strlen(label) };
    CK_OBJECT_HANDLE h[8];
    CK_ULONG n = 0;
    if (C_FindObjectsInit(s, &t, 1) != CKR_OK) return 0;
    (void)C_FindObjects(s, h, 8, &n);
    (void)C_FindObjectsFinal(s);
    if (first) *first = n ? h[0] : 0;
    return n;
}

/* 1 when the value of `h` reads back as `want`. */
static int value_is(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, const char *want)
{
    CK_BYTE buf[64];
    CK_ATTRIBUTE a = { CKA_VALUE, buf, sizeof buf };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK
        && a.ulValueLen == strlen(want) && memcmp(buf, want, a.ulValueLen) == 0;
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_CopyObject);
    SYM(C_GenerateKey); SYM(C_GenerateKeyPair); SYM(C_GetAttributeValue);
    SYM(C_FindObjectsInit); SYM(C_FindObjects); SYM(C_FindObjectsFinal);
    SYM(C_SetAttributeValue); SYM(C_DestroyObject);
    SYM(C_CloseSession); SYM(C_WrapKey); SYM(C_UnwrapKey); SYM(C_DeriveKey); SYM(C_DecapsulateKey);
    if (!C_CopyObject || !C_GenerateKeyPair || !C_FindObjectsFinal || !C_Logout
        || !C_SetAttributeValue || !C_DestroyObject || !C_WrapKey || !C_UnwrapKey
        || !C_DeriveKey || !C_DecapsulateKey || !C_CloseSession) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("CKA_PRIVATE from the template, and access by it\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"privattr",8);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    /* (1) Data objects. */
    CK_OBJECT_HANDLE d_pub = mkdata(s, "tok-public", 1, 0);
    CK_OBJECT_HANDLE d_dflt = mkdata(s, "tok-default", 1, -1);
    CK_OBJECT_HANDLE d_priv = mkdata(s, "tok-private", 1, 1);
    CK_OBJECT_HANDLE s_pub = mkdata(s, "sess-public", 0, 0);
    CK_OBJECT_HANDLE s_priv = mkdata(s, "sess-private", 0, 1);
    ok(d_pub && d_dflt && d_priv && s_pub && s_priv, "(1) five data objects are created");
    ok(read_private(s, d_pub) == 0, "(1) CKA_PRIVATE=FALSE reads back FALSE");
    ok(read_private(s, d_dflt) == 1, "(1) CKA_PRIVATE absent reads back TRUE");
    ok(read_private(s, d_priv) == 1, "(1) CKA_PRIVATE=TRUE reads back TRUE");

    /* (2) A secret key stays private. */
    CK_ULONG vl = 16;
    CK_ATTRIBUTE kt[] = { { CKA_CLASS, &g_secret, sizeof g_secret },
                          { CKA_KEY_TYPE, &g_aes, sizeof g_aes },
                          { CKA_VALUE_LEN, &vl, sizeof vl }, { CKA_TOKEN, &g_yes, 1 },
                          { CKA_PRIVATE, &g_no, 1 },
                          { CKA_LABEL, (void*)"tok-key", 7 } };
    CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = 0;
    ok(C_GenerateKey(s, &kg, kt, 6, &key) == CKR_OK && read_private(s, key) == 1,
       "(2) a secret key asked CKA_PRIVATE=FALSE is private");

    /* (3) A public key asked CKA_PRIVATE=TRUE stays public: the store records
     * only the data-object direction (FHSM_OBJF3_DATA_PUBLIC). */
    static CK_BYTE p256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
    CK_ATTRIBUTE pt[] = { { CKA_TOKEN, &g_yes, 1 }, { CKA_VERIFY, &g_yes, 1 },
                          { CKA_EC_PARAMS, p256, sizeof p256 }, { CKA_PRIVATE, &g_yes, 1 },
                          { CKA_LABEL, (void*)"tok-ecpub", 9 } };
    CK_ATTRIBUTE vt[] = { { CKA_TOKEN, &g_yes, 1 }, { CKA_SIGN, &g_yes, 1 } };
    CK_MECHANISM ecg = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE pub = 0, prv = 0;
    ok(C_GenerateKeyPair(s, &ecg, pt, 5, vt, 2, &pub, &prv) == CKR_OK
       && read_private(s, pub) == 0,
       "(3) a public key asked CKA_PRIVATE=TRUE stays public");

    /* (4) Copies. */
    {
        CK_ATTRIBUTE ct[] = { { CKA_PRIVATE, &g_no, 1 },
                              { CKA_LABEL, (void*)"tok-copied", 10 } };
        CK_OBJECT_HANDLE c1 = 0, c2 = 0;
        ok(C_CopyObject(s, d_priv, ct, 2, &c1) == CKR_OK && read_private(s, c1) == 0,
           "(4) a private data object copied CKA_PRIVATE=FALSE is public");
        CK_ATTRIBUTE kc[] = { { CKA_PRIVATE, &g_no, 1 } };
        ok(C_CopyObject(s, key, kc, 1, &c2) == CKR_OK && read_private(s, c2) == 1,
           "(4) a secret key copied CKA_PRIVATE=FALSE stays private");
    }

    /* (5) After a logout. */
    (void)C_Logout(s);
    CK_OBJECT_HANDLE h = 0;
    ok(find_label(s, "tok-public", &h) == 1 && value_is(s, h, "tok-public"),
       "(5) the public token data object is found and read");
    ok(find_label(s, "tok-copied", &h) == 1, "(5) so is the public copy");
    ok(find_label(s, "tok-default", NULL) == 0 && find_label(s, "tok-private", NULL) == 0,
       "(5) the private data objects are not found");
    ok(read_private(s, d_dflt) == -1 && read_private(s, d_priv) == -1,
       "(5) and their handles do not answer");
    ok(find_label(s, "tok-ecpub", NULL) == 1, "(5) the public key is found");
    ok(find_label(s, "sess-public", &h) == 1 && h == s_pub && value_is(s, h, "sess-public"),
       "(5) the public session object survives, under its handle");
    ok(find_label(s, "sess-private", NULL) == 0, "(5) the private session object is gone");

    /* (6) A new process image, before any login: the public section. */
    C_Finalize(NULL);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize (2)\n"); return 2; }
    CK_SESSION_HANDLE s2 = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s2)) { fprintf(stderr,"C_OpenSession (2)\n"); return 2; }
    ok(find_label(s2, "tok-public", &h) == 1 && value_is(s2, h, "tok-public")
       && read_private(s2, h) == 0,
       "(6) before a login, the public data object is read from the file");
    ok(find_label(s2, "tok-default", NULL) == 0 && find_label(s2, "tok-private", NULL) == 0,
       "(6) the private ones are not there");

    /* (7) The SO: every handle the search hides is refused. */
    if (C_Login(s2,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO (2)\n"); return 2; }
    {
        CK_OBJECT_HANDLE vis[64];
        CK_ULONG nv = 0;
        if (C_FindObjectsInit(s2, NULL, 0) == CKR_OK) {
            (void)C_FindObjects(s2, vis, 64, &nv);
            (void)C_FindObjectsFinal(s2);
        }
        CK_ATTRIBUTE st = { CKA_LABEL, (void*)"so-set", 6 };
        CK_ATTRIBUTE ct[] = { { CKA_PRIVATE, &g_no, 1 }, { CKA_TOKEN, &g_no, 1 } };
        int changed = 0, copied = 0, destroyed = 0;
        for (CK_OBJECT_HANDLE x = 1; x <= 256; x++) {
            int seen = 0;
            for (CK_ULONG i = 0; i < nv; i++) if (vis[i] == x) seen = 1;
            if (seen) continue;
            CK_OBJECT_HANDLE c = 0;
            CK_RV r1 = C_SetAttributeValue(s2, x, &st, 1);
            CK_RV r2 = C_CopyObject(s2, x, ct, 2, &c);
            CK_RV r3 = C_DestroyObject(s2, x);
            if (r1 == CKR_OK) changed++;
            if (r2 == CKR_OK) copied++;
            if (r3 == CKR_OK) destroyed++;
        }
        ok(changed == 0, "(7) the SO changes no hidden object");
        ok(copied == 0, "(7) the SO copies no hidden object out");
        ok(destroyed == 0, "(7) the SO destroys no hidden object");
    }
    (void)C_Logout(s2);
    if (C_Login(s2,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER (2)\n"); return 2; }
    ok(find_label(s2, "tok-private", &h) == 1 && value_is(s2, h, "tok-private")
       && find_label(s2, "tok-default", &h) == 1 && value_is(s2, h, "tok-default"),
       "(7) the user finds the private data objects intact");
    ok(find_label(s2, "so-set", NULL) == 0, "(7) and no object relabelled by the SO");

    /* (8) Only the user makes a private object (#31). */
    (void)C_Logout(s2);
    ok(mkdata_rv(s2, "pub-dflt", 0, -1) == CKR_USER_NOT_LOGGED_IN,
       "(8) no login: a data object without CKA_PRIVATE is refused");
    if (C_Login(s2,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO (3)\n"); return 2; }
    {
        CK_BYTE kv[16]; memset(kv, 0x5A, sizeof kv);
        CK_ULONG gs = CKK_GENERIC_SECRET;
        CK_ATTRIBUTE ct[] = { { CKA_CLASS, &g_secret, sizeof g_secret },
                              { CKA_KEY_TYPE, &gs, sizeof gs },
                              { CKA_VALUE, kv, sizeof kv }, { CKA_TOKEN, &g_no, 1 },
                              { CKA_PRIVATE, &g_yes, 1 } };
        CK_OBJECT_HANDLE x = 0;
        ok(C_CreateObject(s2, ct, 5, &x) == CKR_USER_NOT_LOGGED_IN,
           "(8) SO: C_CreateObject of a private secret key is refused");
        ok(mkdata_rv(s2, "so-priv", 0, 1) == CKR_USER_NOT_LOGGED_IN
           && mkdata_rv(s2, "so-dflt", 0, -1) == CKR_USER_NOT_LOGGED_IN,
           "(8) SO: a private data object, asked or by default, is refused");
        ok(mkdata_rv(s2, "so-pub", 0, 0) == CKR_OK,
           "(8) SO: a public data object is made");
        ok(C_GenerateKey(s2, &kg, kt, 6, &x) == CKR_USER_NOT_LOGGED_IN,
           "(8) SO: C_GenerateKey is refused");
        ok(C_GenerateKeyPair(s2, &ecg, pt, 5, vt, 2, &pub, &prv) == CKR_USER_NOT_LOGGED_IN,
           "(8) SO: C_GenerateKeyPair is refused");
        CK_OBJECT_HANDLE src = 0;
        CK_ATTRIBUTE cp[] = { { CKA_PRIVATE, &g_yes, 1 }, { CKA_TOKEN, &g_no, 1 } };
        ok(find_label(s2, "tok-public", &src) == 1
           && C_CopyObject(s2, src, cp, 2, &x) == CKR_USER_NOT_LOGGED_IN,
           "(8) SO: a public data object copied CKA_PRIVATE=TRUE is refused");
        /* Relabelled: a second "tok-public" would throw off (9)'s search. */
        CK_ATTRIBUTE cq[] = { { CKA_TOKEN, &g_no, 1 }, { CKA_LABEL, (void*)"so-copy", 7 } };
        ok(C_CopyObject(s2, src, cq, 2, &x) == CKR_OK,
           "(8) SO: and copied as it is, it is made");
    }
    (void)C_Logout(s2);

    /* (9) A read-only session copies a token object into a session object
     *     only (#30). */
    if (C_Login(s2,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER (3)\n"); return 2; }
    {
        CK_SESSION_HANDLE ro = 0;
        if (C_OpenSession(0,CKF_SERIAL,NULL,NULL,&ro)) { fprintf(stderr,"RO session\n"); return 2; }
        CK_OBJECT_HANDLE src = 0, x = 0;
        CK_ATTRIBUTE lt[] = { { CKA_LABEL, (void*)"ro-copy", 7 } };
        ok(find_label(ro, "tok-public", &src) == 1
           && C_CopyObject(ro, src, lt, 1, &x) == CKR_SESSION_READ_ONLY,
           "(9) RO: a copy that inherits CKA_TOKEN=TRUE is refused");
        ok(find_label(ro, "ro-copy", NULL) == 0, "(9) and nothing is made");
        CK_ATTRIBUTE st[] = { { CKA_LABEL, (void*)"ro-copy", 7 }, { CKA_TOKEN, &g_no, 1 } };
        CK_BYTE tv = 0xFF;
        CK_ATTRIBUTE ta = { CKA_TOKEN, &tv, 1 };
        ok(C_CopyObject(ro, src, st, 2, &x) == CKR_OK
           && C_GetAttributeValue(ro, x, &ta, 1) == CKR_OK && tv == 0,
           "(9) RO: a copy asked CKA_TOKEN=FALSE is a session object");
        ok(C_CopyObject(ro, src, lt, 0, &x) == CKR_SESSION_READ_ONLY,
           "(9) RO: a verbatim copy of a token object is refused");
        /* The SO cannot log in while a read-only session is open (10). */
        (void)C_CloseSession(ro);
    }

    /* (11) The user alone: key material goes into keys only. The objects made
     * here are also what (10) sweeps. */
    CK_RSA_PKCS_OAEP_PARAMS op = { CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, NULL, 0 };
    CK_MECHANISM oaep = { CKM_RSA_PKCS_OAEP, &op, sizeof op };
    CK_BYTE bang[] = "!";
    CK_KEY_DERIVATION_STRING_DATA kd = { bang, 1 };
    CK_MECHANISM cat = { CKM_CONCATENATE_BASE_AND_DATA, &kd, sizeof kd };
    CK_ULONG c_pub = CKO_PUBLIC_KEY, gsk = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE tdat[] = { { CKA_CLASS, &g_data, sizeof g_data }, { CKA_TOKEN, &g_no, 1 },
                            { CKA_PRIVATE, &g_no, 1 } };
    CK_ATTRIBUTE tpub[] = { { CKA_CLASS, &c_pub, sizeof c_pub }, { CKA_KEY_TYPE, &gsk, sizeof gsk },
                            { CKA_TOKEN, &g_no, 1 }, { CKA_PRIVATE, &g_no, 1 } };
    CK_ATTRIBUTE tsec[] = { { CKA_CLASS, &g_secret, sizeof g_secret },
                            { CKA_KEY_TYPE, &gsk, sizeof gsk }, { CKA_TOKEN, &g_no, 1 },
                            { CKA_EXTRACTABLE, &g_yes, 1 }, { CKA_SENSITIVE, &g_no, 1 } };
    CK_OBJECT_HANDLE upub = 0, upriv = 0, nx = 0;
    {
        CK_BYTE kv[16]; memcpy(kv, "USER-DERIVE-BASE", 16);
        CK_ATTRIBUTE nt[] = { { CKA_CLASS, &g_secret, sizeof g_secret },
                              { CKA_KEY_TYPE, &gsk, sizeof gsk }, { CKA_VALUE, kv, sizeof kv },
                              { CKA_TOKEN, &g_yes, 1 }, { CKA_DERIVE, &g_yes, 1 },
                              { CKA_EXTRACTABLE, &g_no, 1 }, { CKA_SENSITIVE, &g_yes, 1 } };
        ok(C_CreateObject(s2, nt, 7, &nx) == CKR_OK, "(11) a non-extractable derive key is made");
        CK_ULONG bits = 2048; CK_BYTE e[] = { 1, 0, 1 };
        CK_ATTRIBUTE rp[] = { { CKA_TOKEN, &g_yes, 1 }, { CKA_MODULUS_BITS, &bits, sizeof bits },
                              { CKA_PUBLIC_EXPONENT, e, sizeof e }, { CKA_WRAP, &g_yes, 1 },
                              { CKA_LABEL, (void*)"u-rsa", 5 } };
        CK_ATTRIBUTE rk[] = { { CKA_TOKEN, &g_yes, 1 }, { CKA_UNWRAP, &g_yes, 1 },
                              { CKA_EXTRACTABLE, &g_no, 1 } };
        CK_MECHANISM rg = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
        ok(C_GenerateKeyPair(s2, &rg, rp, 5, rk, 3, &upub, &upriv) == CKR_OK,
           "(11) an RSA key pair, the public half CKA_WRAP, is made");
        CK_OBJECT_HANDLE x = 0, d = 0;
        ok(C_DeriveKey(s2, &cat, nx, tdat, 3, &x) == CKR_TEMPLATE_INCONSISTENT,
           "(11) C_DeriveKey into a data object is refused");
        ok(C_DeriveKey(s2, &cat, nx, tpub, 4, &x) == CKR_TEMPLATE_INCONSISTENT,
           "(11) C_DeriveKey into a public key is refused");
        CK_BYTE ct[256]; memset(ct, 0x11, sizeof ct);
        ok(C_UnwrapKey(s2, &oaep, upriv, ct, sizeof ct, tdat, 3, &x) == CKR_TEMPLATE_INCONSISTENT,
           "(11) C_UnwrapKey into a data object is refused");
        ok(C_UnwrapKey(s2, &oaep, upriv, ct, sizeof ct, tpub, 4, &x) == CKR_TEMPLATE_INCONSISTENT,
           "(11) C_UnwrapKey into a public key is refused");
        CK_BYTE w[512]; CK_ULONG wl = sizeof w;
        ok(find_label(s2, "tok-private", &d) == 1
           && C_WrapKey(s2, &oaep, upub, d, w, &wl) == CKR_KEY_HANDLE_INVALID,
           "(11) C_WrapKey of a data object is refused");
        wl = sizeof w;
        ok(C_WrapKey(s2, &oaep, upub, upub, w, &wl) == CKR_KEY_NOT_WRAPPABLE,
           "(11) C_WrapKey of a public key is refused");
        wl = sizeof w;
        ok(C_WrapKey(s2, &oaep, upub, nx, w, &wl) == CKR_KEY_UNEXTRACTABLE,
           "(11) the non-extractable key is still refused");
    }
    (void)C_Logout(s2);

    /* (10) The SO: a hidden handle answers as a missing one. */
    { CK_RV lr = C_Login(s2,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN));
      if (lr) { fprintf(stderr,"SO (4): 0x%lx\n", lr); return 2; } }
    {
        CK_OBJECT_HANDLE vis[64];
        CK_ULONG nv = 0;
        if (C_FindObjectsInit(s2, NULL, 0) == CKR_OK) {
            (void)C_FindObjects(s2, vis, 64, &nv);
            (void)C_FindObjectsFinal(s2);
        }
        int pub_seen = find_label(s2, "u-rsa", &upub) == 1;
        CK_BYTE ct[256]; memset(ct, 0x11, sizeof ct);
        CK_BYTE kct[1568]; memset(kct, 0x22, sizeof kct);
        CK_MECHANISM kem = { CKM_ML_KEM, NULL, 0 };
        CK_ATTRIBUTE *tt[] = { tdat, tsec };
        CK_ULONG tn[] = { 3, 5 };
        CK_RV mu[2], md[2], mk[2];
        CK_OBJECT_HANDLE x = 0;
        CK_BYTE w[512]; CK_ULONG wl = sizeof w;
        CK_RV mw = C_WrapKey(s2, &oaep, upub, MISSING_HANDLE, w, &wl);
        for (int k = 0; k < 2; k++) {
            mu[k] = C_UnwrapKey(s2, &oaep, MISSING_HANDLE, ct, sizeof ct, tt[k], tn[k], &x);
            md[k] = C_DeriveKey(s2, &cat, MISSING_HANDLE, tt[k], tn[k], &x);
            mk[k] = C_DecapsulateKey(s2, &kem, MISSING_HANDLE, tt[k], tn[k], kct, sizeof kct, &x);
        }
        int wrapped = 0, unwrapped = 0, derived = 0, decapped = 0, swept = 0;
        for (CK_OBJECT_HANDLE hh = 1; hh <= 256; hh++) {
            int seen = 0;
            for (CK_ULONG i = 0; i < nv; i++) if (vis[i] == hh) seen = 1;
            if (seen) continue;
            swept++;
            wl = sizeof w;
            if (C_WrapKey(s2, &oaep, upub, hh, w, &wl) != mw) wrapped++;
            for (int k = 0; k < 2; k++) {
                if (C_UnwrapKey(s2, &oaep, hh, ct, sizeof ct, tt[k], tn[k], &x) != mu[k])
                    unwrapped++;
                if (C_DeriveKey(s2, &cat, hh, tt[k], tn[k], &x) != md[k]) derived++;
                if (C_DecapsulateKey(s2, &kem, hh, tt[k], tn[k], kct, sizeof kct, &x) != mk[k])
                    decapped++;
            }
        }
        ok(pub_seen && swept > 0, "(10) the SO sees the user's public key and sweeps the rest");
        ok(wrapped == 0, "(10) SO: C_WrapKey answers a hidden handle as a missing one");
        ok(unwrapped == 0, "(10) SO: C_UnwrapKey answers a hidden handle as a missing one");
        ok(derived == 0, "(10) SO: C_DeriveKey answers a hidden handle as a missing one");
        ok(decapped == 0, "(10) SO: C_DecapsulateKey answers a hidden handle as a missing one");
    }
    (void)C_Logout(s2);

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
