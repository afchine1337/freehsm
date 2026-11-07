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
 *       section, the private one is not found.
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
static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);

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
    if (!C_CopyObject || !C_GenerateKeyPair || !C_FindObjectsFinal || !C_Logout) {
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

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
