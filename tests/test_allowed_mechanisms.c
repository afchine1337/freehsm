/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_allowed_mechanisms.c --- CKA_ALLOWED_MECHANISMS, stored and enforced.
 *
 * The attribute was refused outright until the v4 record gave it somewhere to
 * live. Refusing was honest -- accepting it and dropping it would have been a
 * claim of protection that was not there -- but it is not the answer: §4.9
 * defines it, and an allow-list the module ignores is how a key meant for one
 * mechanism ends up used with another.
 *
 * Three cases, because the corpus distinguishes three and conflating any two
 * of them is the whole difficulty:
 *
 *   absent   -- no CKA_ALLOWED_MECHANISMS was ever set: every mechanism is
 *               permitted. Every key written before today is in this state,
 *               and getting it wrong would restrict all of them at once.
 *   listed   -- the named mechanisms are permitted and nothing else is.
 *   empty    -- the attribute is present with no entries: nothing is
 *               permitted. pkcs11-check sends exactly this and then checks
 *               that C_EncryptInit is refused afterwards.
 *
 * "Absent" and "empty" both store a count of zero. Only the presence bit in
 * flags2 separates them, and a reader that asks the count alone has inverted
 * the one case the attribute exists to express.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS, CK_MECHANISM_TYPE;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                        0UL
#define CKR_MECHANISM_INVALID         0x70UL
#define CKR_ATTRIBUTE_VALUE_INVALID   0x13UL
#define CKF_RW                        6UL
#define CKA_CLASS                     0UL
#define CKA_TOKEN                     1UL
#define CKA_LABEL                     3UL
#define CKA_KEY_TYPE                  0x100UL
#define CKA_SENSITIVE                 0x103UL
#define CKA_ENCRYPT                   0x104UL
#define CKA_DECRYPT                   0x105UL
#define CKA_VALUE                     0x11UL
#define CKA_VALUE_LEN                 0x161UL
#define CKA_EXTRACTABLE               0x162UL
#define CKA_ALLOWED_MECHANISMS        0x40000600UL
#define CKO_SECRET_KEY                4UL
#define CKK_AES                       0x1FUL
#define CKM_AES_ECB                   0x1081UL
#define CKM_AES_CBC                   0x1082UL
#define CKM_AES_KEY_GEN               0x1080UL

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
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Encrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_Decrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);

/* C_*Init that leaves the session clean.
 *
 * A successful C_EncryptInit leaves an operation active, and the next
 * C_EncryptInit on the same session answers CKR_OPERATION_ACTIVE -- which
 * would be read here as "the second mechanism was refused" and would be the
 * test lying about the module. tests/test_gmac_params was written with
 * exactly this defect on 2026-09-19 and reported a regression that did not
 * exist; the operation is finished here rather than left dangling. */
static CK_RV init_then_finish(int encrypt, CK_SESSION_HANDLE s,
                              CK_MECHANISM *m, CK_OBJECT_HANDLE h)
{
    CK_BYTE in[16] = { 0 }, out[64];
    CK_ULONG out_len = sizeof out;
    CK_RV rv = encrypt ? C_EncryptInit(s, m, h) : C_DecryptInit(s, m, h);
    if (rv != CKR_OK) return rv;                  /* nothing was started */
    (void)(encrypt ? C_Encrypt(s, in, sizeof in, out, &out_len)
                   : C_Decrypt(s, in, sizeof in, out, &out_len));
    return CKR_OK;
}

/* Import a 16-byte AES key, optionally with CKA_ALLOWED_MECHANISMS.
 * `mechs == NULL` omits the attribute entirely (the "absent" case);
 * `mechs != NULL` with `n == 0` sends it present and empty. */
static CK_RV make_key(CK_SESSION_HANDLE s, const char *label,
                      const CK_MECHANISM_TYPE *mechs, CK_ULONG n,
                      CK_OBJECT_HANDLE *out)
{
    static const CK_BYTE val[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    CK_ULONG klass = CKO_SECRET_KEY, ktype = CKK_AES;
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE t[9];
    CK_ULONG c = 0;
    t[c].type = CKA_CLASS;       t[c].pValue = &klass; t[c].ulValueLen = sizeof klass; c++;
    t[c].type = CKA_KEY_TYPE;    t[c].pValue = &ktype; t[c].ulValueLen = sizeof ktype; c++;
    t[c].type = CKA_VALUE;       t[c].pValue = (void*)val; t[c].ulValueLen = sizeof val; c++;
    t[c].type = CKA_TOKEN;       t[c].pValue = &no;    t[c].ulValueLen = 1; c++;
    t[c].type = CKA_SENSITIVE;   t[c].pValue = &no;    t[c].ulValueLen = 1; c++;
    t[c].type = CKA_EXTRACTABLE; t[c].pValue = &yes;   t[c].ulValueLen = 1; c++;
    t[c].type = CKA_ENCRYPT;     t[c].pValue = &yes;   t[c].ulValueLen = 1; c++;
    t[c].type = CKA_LABEL;       t[c].pValue = (void*)label;
                                 t[c].ulValueLen = (CK_ULONG)strlen(label); c++;
    if (mechs || n == 0) {
        /* n == 0 with a non-NULL pValue is the empty array; pValue NULL with
         * length 0 is the same thing and is what pkcs11-check sends. Either
         * shape must mean "present, allows nothing". */
        t[c].type = CKA_ALLOWED_MECHANISMS;
        t[c].pValue = (void*)mechs;
        t[c].ulValueLen = n * sizeof(CK_MECHANISM_TYPE);
        c++;
    }
    *out = 0;
    return C_CreateObject(s, t, c, out);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_GetAttributeValue);
    SYM(C_EncryptInit); SYM(C_DecryptInit); SYM(C_Encrypt); SYM(C_Decrypt);
    if (!C_CreateObject || !C_EncryptInit) { fprintf(stderr,"missing symbols\n"); return 2; }

    printf("CKA_ALLOWED_MECHANISMS: absent, listed, empty\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"allowmech",9);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_MECHANISM ecb = { CKM_AES_ECB, NULL, 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC, (void*)"0123456789abcdef", 16 };

    /* ---- absent: everything permitted, which is every existing key ---- */
    {
        CK_OBJECT_HANDLE h = 0;
        ok(make_key(s, "absent", NULL, 1, &h) == CKR_OK,
           "a key with no CKA_ALLOWED_MECHANISMS is created");
        ok(init_then_finish(1, s, &ecb, h) == CKR_OK,
           "  and AES-ECB is permitted");
        ok(init_then_finish(1, s, &cbc, h) == CKR_OK,
           "  and so is AES-CBC -- absent restricts nothing");
        CK_ATTRIBUTE q = { CKA_ALLOWED_MECHANISMS, NULL, 0 };
        (void)C_GetAttributeValue(s, h, &q, 1);
        ok(q.ulValueLen == (CK_ULONG)-1,
           "  and reading it back says unavailable, not an empty list");
    }

    /* ---- listed: the named mechanism, and nothing else ---- */
    {
        CK_MECHANISM_TYPE only_ecb[1] = { CKM_AES_ECB };
        CK_OBJECT_HANDLE h = 0;
        ok(make_key(s, "listed", only_ecb, 1, &h) == CKR_OK,
           "a key listing only AES-ECB is created");
        ok(init_then_finish(1, s, &ecb, h) == CKR_OK,
           "  and AES-ECB is permitted");
        ok(init_then_finish(1, s, &cbc, h) == CKR_MECHANISM_INVALID,
           "  and AES-CBC is CKR_MECHANISM_INVALID");
        /* The enforcement must not be wired to encryption only: the same key
         * refused for CBC on the encrypt path must be refused on the decrypt
         * path too. Half a guard is how three attributes before this one
         * reached the findings document. */
        ok(init_then_finish(0, s, &cbc, h) == CKR_MECHANISM_INVALID,
           "  and the decrypt path says the same");
        CK_MECHANISM_TYPE back[4] = { 0, 0, 0, 0 };
        CK_ATTRIBUTE q = { CKA_ALLOWED_MECHANISMS, back, sizeof back };
        ok(C_GetAttributeValue(s, h, &q, 1) == CKR_OK
           && q.ulValueLen == sizeof(CK_MECHANISM_TYPE)
           && back[0] == CKM_AES_ECB,
           "  and it reads back as the one mechanism it was given");
    }

    /* ---- empty: present, and allows nothing ---- */
    {
        CK_OBJECT_HANDLE h = 0;
        ok(make_key(s, "empty", NULL, 0, &h) == CKR_OK,
           "a key with an empty CKA_ALLOWED_MECHANISMS is created");
        ok(init_then_finish(1, s, &ecb, h) == CKR_MECHANISM_INVALID,
           "  and AES-ECB is refused");
        ok(init_then_finish(1, s, &cbc, h) == CKR_MECHANISM_INVALID,
           "  and so is AES-CBC -- empty allows nothing");
        CK_ATTRIBUTE q = { CKA_ALLOWED_MECHANISMS, NULL, 0 };
        ok(C_GetAttributeValue(s, h, &q, 1) == CKR_OK && q.ulValueLen == 0,
           "  and it reads back present with length zero, not unavailable");
    }

    /* ---- over the cap: refused, not truncated ---- */
    {
        CK_MECHANISM_TYPE many[9];
        for (int i = 0; i < 9; ++i) many[i] = CKM_AES_ECB + (CK_ULONG)i;
        CK_OBJECT_HANDLE h = 0;
        ok(make_key(s, "toomany", many, 9, &h) == CKR_ATTRIBUTE_VALUE_INVALID,
           "nine mechanisms is refused rather than silently cut to eight");
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
