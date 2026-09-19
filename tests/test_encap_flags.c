/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_encap_flags.c --- CKA_ENCAPSULATE / CKA_DECAPSULATE are enforced.
 *
 * The module accepted both attributes in a C_GenerateKeyPair template, dropped
 * them, and then encapsulated or decapsulated anyway. pkcs11-check 0.2.0 calls
 * that a self-contradiction and is right to: accepting an attribute without a
 * word is a claim to honour it, and a caller who sets CKA_DECAPSULATE=False,
 * gets CKR_OK, and watches decapsulation succeed has no way to learn it was
 * ignored.
 *
 * Under 0.1.9 the same behaviour was filed as honest non-support, because the
 * module neither stored nor reported the attributes. That was true and it was
 * not the point -- which is why the readback below matters as much as the
 * refusal: a restriction the caller cannot observe is half a control.
 *
 * Both per-object flag bytes were full. The bits live in the v3 record's pad
 * byte at offset 203, written zero and never read until now, and they are
 * negative -- set means restricted -- so every record written before
 * 2026-09-19 still reads as permitted. The store round trip at the end is what
 * checks that claim rather than asserting it.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                          0UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED  0x68UL
#define CKF_RW                          6UL
#define CKA_CLASS                       0UL
#define CKA_TOKEN                       1UL
#define CKA_LABEL                       3UL
#define CKA_VALUE                       0x11UL
#define CKA_KEY_TYPE                    0x100UL
#define CKA_EXTRACTABLE                 0x162UL
#define CKA_ENCAPSULATE                 0x633UL
#define CKA_DECAPSULATE                 0x634UL
#define CKO_PUBLIC_KEY                  2UL
#define CKO_PRIVATE_KEY                 3UL
#define CKK_ML_KEM                      0x49UL
#define CKM_ML_KEM_KEY_PAIR_GEN         0x0FUL
#define CKM_ML_KEM                      0x17UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                   CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_CopyObject)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_EncapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_BYTE*,CK_ULONG*,CK_OBJECT_HANDLE*);
static CK_RV (*C_DecapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_BYTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);

static int read_bool(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                      CK_ULONG attr, CK_BYTE *out) {
    CK_ATTRIBUTE q[] = { { attr, out, 1 } };
    return C_GetAttributeValue(s, h, q, 1) == CKR_OK && q[0].ulValueLen == 1;
}

/* One encapsulation attempt, return code only. */
static CK_RV try_encap(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE pub,
                        CK_BYTE *ct, CK_ULONG *ctl) {
    CK_MECHANISM m = { CKM_ML_KEM, NULL, 0 };
    CK_BYTE yes = 1;
    CK_ATTRIBUTE t[] = { { CKA_EXTRACTABLE, &yes, 1 } };
    CK_OBJECT_HANDLE ss = 0;
    return C_EncapsulateKey(s, &m, pub, t, 1, ct, ctl, &ss);
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_CloseSession); SYM(C_Login); SYM(C_InitPIN); SYM(C_GenerateKeyPair);
    SYM(C_GetAttributeValue); SYM(C_CopyObject);
    SYM(C_EncapsulateKey); SYM(C_DecapsulateKey);
    SYM(C_FindObjectsInit); SYM(C_FindObjects); SYM(C_FindObjectsFinal);
    if (!C_EncapsulateKey || !C_GenerateKeyPair) { fprintf(stderr,"missing symbols\n"); return 2; }

    printf("CKA_ENCAPSULATE / CKA_DECAPSULATE (PKCS#11 v3.2 §5.14.7, §5.14.8)\n\n");

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"encapflags",10);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"USER\n"); return 2; }

    CK_MECHANISM gen = { CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0 };
    CK_BYTE yes = 1, no = 0;
    CK_BYTE ct[4096]; CK_ULONG ctl;
    CK_BYTE v;

    /* (1) The default: nothing stated, everything permitted, and both read
     *     back TRUE. A module that reported FALSE here would be restricting
     *     by accident -- the negative-bit choice has to be checked from this
     *     side too. */
    {
        CK_ATTRIBUTE pub_t[]  = { { CKA_TOKEN, &yes, 1 } };
        CK_ATTRIBUTE priv_t[] = { { CKA_TOKEN, &yes, 1 } };
        CK_OBJECT_HANDLE hp = 0, hk = 0;
        ok(C_GenerateKeyPair(s, &gen, pub_t, 1, priv_t, 1, &hp, &hk) == CKR_OK,
           "a pair with neither attribute stated is generated");
        v = 0xFF;
        ok(read_bool(s, hp, CKA_ENCAPSULATE, &v) && v == 1,
           "CKA_ENCAPSULATE reads back TRUE by default");
        v = 0xFF;
        ok(read_bool(s, hk, CKA_DECAPSULATE, &v) && v == 1,
           "CKA_DECAPSULATE reads back TRUE by default");
        ctl = sizeof ct;
        ok(try_encap(s, hp, ct, &ctl) == CKR_OK, "and it encapsulates");
    }

    /* (2) CKA_ENCAPSULATE=False. The claim is now observable and the
     *     operation refused with the code §5.14.7 names. */
    {
        CK_ATTRIBUTE pub_t[]  = { { CKA_ENCAPSULATE, &no, 1 }, { CKA_TOKEN, &yes, 1 } };
        CK_ATTRIBUTE priv_t[] = { { CKA_TOKEN, &yes, 1 } };
        CK_OBJECT_HANDLE hp = 0, hk = 0;
        ok(C_GenerateKeyPair(s, &gen, pub_t, 2, priv_t, 1, &hp, &hk) == CKR_OK,
           "CKA_ENCAPSULATE=False is accepted at generation");
        v = 0xFF;
        ok(read_bool(s, hp, CKA_ENCAPSULATE, &v) && v == 0,
           "and reads back FALSE -- the claim is observable");
        ctl = sizeof ct;
        ok(try_encap(s, hp, ct, &ctl) == CKR_KEY_FUNCTION_NOT_PERMITTED,
           "C_EncapsulateKey refuses with CKR_KEY_FUNCTION_NOT_PERMITTED");

        /* The copy must not be a way around it. */
        CK_OBJECT_HANDLE copy = 0;
        CK_ATTRIBUTE cp[] = { { CKA_LABEL, (void*)"c", 1 } };
        if (C_CopyObject(s, hp, cp, 1, &copy) == CKR_OK) {
            v = 0xFF;
            ok(read_bool(s, copy, CKA_ENCAPSULATE, &v) && v == 0,
               "a copy of the restricted key is restricted too");
            ctl = sizeof ct;
            ok(try_encap(s, copy, ct, &ctl) == CKR_KEY_FUNCTION_NOT_PERMITTED,
               "and the copy refuses as well");
        } else {
            ok(0, "C_CopyObject on the restricted public key");
            ok(0, "(copy refusal not reached)");
        }
    }

    /* (3) CKA_DECAPSULATE=False. The half the harness found. */
    {
        CK_ATTRIBUTE pub_t[]  = { { CKA_TOKEN, &yes, 1 } };
        CK_ATTRIBUTE priv_t[] = { { CKA_DECAPSULATE, &no, 1 }, { CKA_TOKEN, &yes, 1 } };
        CK_OBJECT_HANDLE hp = 0, hk = 0;
        ok(C_GenerateKeyPair(s, &gen, pub_t, 1, priv_t, 2, &hp, &hk) == CKR_OK,
           "CKA_DECAPSULATE=False is accepted at generation");
        v = 0xFF;
        ok(read_bool(s, hk, CKA_DECAPSULATE, &v) && v == 0,
           "and reads back FALSE");
        ctl = sizeof ct;
        ok(try_encap(s, hp, ct, &ctl) == CKR_OK,
           "the public half still encapsulates -- the bits are independent");
        CK_MECHANISM m = { CKM_ML_KEM, NULL, 0 };
        CK_ATTRIBUTE ss_t[] = { { CKA_EXTRACTABLE, &yes, 1 } };
        CK_OBJECT_HANDLE ss = 0;
        ok(C_DecapsulateKey(s, &m, hk, ss_t, 1, ct, ctl, &ss)
             == CKR_KEY_FUNCTION_NOT_PERMITTED,
           "C_DecapsulateKey refuses with CKR_KEY_FUNCTION_NOT_PERMITTED");
    }

    /* (4) The attribute does not apply where the spec does not put it:
     *     a public key has no CKA_DECAPSULATE. Absent, not invented. */
    {
        CK_ATTRIBUTE pub_t[]  = { { CKA_TOKEN, &yes, 1 } };
        CK_ATTRIBUTE priv_t[] = { { CKA_TOKEN, &yes, 1 } };
        CK_OBJECT_HANDLE hp = 0, hk = 0;
        if (C_GenerateKeyPair(s, &gen, pub_t, 1, priv_t, 1, &hp, &hk) == CKR_OK) {
            CK_ATTRIBUTE q[] = { { CKA_DECAPSULATE, &v, 1 } };
            (void)C_GetAttributeValue(s, hp, q, 1);
            ok(q[0].ulValueLen == (CK_ULONG)-1,
               "a public key reports CKA_DECAPSULATE as absent");
        } else {
            ok(0, "keypair for the absent-attribute case");
        }
    }

    /* The store round trip is NOT here, and the reason is worth stating.
     *
     * It was written here first and could not do what it claimed. Closing a
     * session reloads nothing -- the objects stay in memory and the token
     * stays logged in -- and C_Finalize followed by C_Initialize does not
     * help either: the second C_Login answers CKR_USER_ALREADY_LOGGED_IN,
     * so the store is never parsed again. A round trip that never reads the
     * file would have gone green while proving nothing about the byte it
     * exists to check.
     *
     * tests/test_encap_flags_store.c does it at the token layer instead,
     * which is where this repository already stages a reload:
     * test_throttle_reboot puts it plainly -- "a reboot cannot be staged
     * inside a test, but it does not have to be: the file is the whole
     * interface between two boots".
     *
     * That login state survives C_Finalize is a separate observation, noted
     * in docs/PKCS11_CHECK_FINDINGS.md rather than fixed in passing. */

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
