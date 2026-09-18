/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_interface_v32.c --- the module's public surface, entered the way an
 * application enters it.
 *
 * Every other test in this suite reaches the module with dlsym. That is fine
 * for checking arithmetic and wrong for checking reachability, and the
 * difference cost us CKM_ML_KEM: the mechanism was advertised by
 * C_GetMechanismList, C_EncapsulateKey and C_DecapsulateKey were implemented
 * and exported, tests/mlkem_e2e.c passed -- and no application could call
 * them, because the only interface the module published was v3.0, whose
 * function list ends at slot 91. The encapsulation functions are v3.2
 * additions at slots 92 and 93.
 *
 * pkcs11-check saw it as "advertised, no canonical accept/reject observed":
 * never invoked, because there was nothing to invoke with.
 *
 * So this file uses dlsym exactly twice -- for C_GetInterfaceList and
 * C_GetInterface, which is how an application bootstraps -- and everything
 * after that goes through the function-list pointers the module hands back.
 * A function this test cannot reach is a function no caller can reach.
 *
 * It also pins the argument order of slots 92 and 93 against the OASIS v3.2
 * pkcs11f.h, because the module carried a permuted one until 2026-09-18 and
 * nothing noticed: the only caller was a test written from the same
 * assumption. Calling through the table, with the spec's order, is what makes
 * that disagreement visible.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS, CK_USER_TYPE;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { unsigned char major, minor; } CK_VERSION;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;

/* The published lists, read only through their two leading bytes and their
 * slots. Sized to the largest we expect; we never index past what the
 * version field entitles us to. */
struct FN_LIST { CK_VERSION version; void *pfn[104]; };

#define CKR_OK                         0UL
#define CKR_FUNCTION_FAILED            0x06UL
#define CKR_BUFFER_TOO_SMALL           0x150UL
#define CKR_FUNCTION_NOT_SUPPORTED     0x54UL

#define CKF_RW                         6UL
#define CKU_SO                         0UL
#define CKU_USER                       1UL

#define CKA_LABEL                      0x03UL
#define CKA_VALUE                      0x11UL
#define CKA_EXTRACTABLE                0x162UL
#define CKA_KEY_TYPE                   0x100UL
#define CKR_TEMPLATE_INCONSISTENT      0xD1UL

#define CKM_ML_KEM_KEY_PAIR_GEN        0x0FUL
#define CKM_ML_KEM                     0x17UL

/* Slot numbers from the OASIS v3.2 pkcs11f.h, whose header states that the
 * order of functions in it is significant and must not be altered. */
#define SLOT_C_Initialize        0
#define SLOT_C_Finalize          1
#define SLOT_C_InitToken         9
#define SLOT_C_InitPIN          10
#define SLOT_C_OpenSession      12
#define SLOT_C_Login            18
#define SLOT_C_GetAttributeValue 24
#define SLOT_C_GenerateKeyPair  59
#define SLOT_C_GetInterfaceList 68
#define SLOT_C_GetInterface     69
#define SLOT_C_LoginUser        70
#define SLOT_C_EncapsulateKey   92
#define SLOT_C_DecapsulateKey   93
#define SLOT_C_VerifySignatureInit 94

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

typedef CK_RV (*fn_init_t)(void*);
typedef CK_RV (*fn_fin_t)(void*);
typedef CK_RV (*fn_inittoken_t)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
typedef CK_RV (*fn_initpin_t)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
typedef CK_RV (*fn_open_t)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
typedef CK_RV (*fn_login_t)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE*, CK_ULONG);
typedef CK_RV (*fn_getattr_t)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
typedef CK_RV (*fn_keypair_t)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                               CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
/* OASIS v3.2 order: ciphertext pair, then the key handle. */
typedef CK_RV (*fn_encap_t)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE,
                             CK_ATTRIBUTE*, CK_ULONG,
                             CK_BYTE*, CK_ULONG*, CK_OBJECT_HANDLE*);
typedef CK_RV (*fn_decap_t)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE,
                             CK_ATTRIBUTE*, CK_ULONG,
                             CK_BYTE*, CK_ULONG, CK_OBJECT_HANDLE*);
typedef CK_RV (*fn_ifacelist_t)(CK_INTERFACE*, CK_ULONG*);
typedef CK_RV (*fn_iface_t)(CK_BYTE*, void*, CK_INTERFACE**, CK_FLAGS);

/* ISO C forbids casting void* straight to a function pointer; round-trip
 * through an object-pointer slot, as elsewhere in this suite. */
#define AS_FN(type, p) (*(type*)(void*)&(p))

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    /* The only two dlsym calls in this file. Everything else comes from the
     * tables these return. */
    void *sym_list = dlsym(lib, "C_GetInterfaceList");
    void *sym_get  = dlsym(lib, "C_GetInterface");
    if (!sym_list || !sym_get) { fprintf(stderr, "no v3.0 interface entry points\n"); return 2; }
    fn_ifacelist_t C_GetInterfaceList = AS_FN(fn_ifacelist_t, sym_list);
    fn_iface_t     C_GetInterface     = AS_FN(fn_iface_t, sym_get);

    printf("The module's published interfaces\n\n");

    /* (1) Two interfaces, both named "PKCS 11", told apart by version. */
    CK_ULONG n = 0;
    ok(C_GetInterfaceList(NULL, &n) == CKR_OK && n == 2,
       "C_GetInterfaceList reports 2 interfaces");
    CK_INTERFACE ifs[4];
    n = 4;
    CK_RV rv = C_GetInterfaceList(ifs, &n);
    ok(rv == CKR_OK && n == 2, "and fills 2 entries");
    if (rv == CKR_OK && n == 2) {
        struct FN_LIST *a = (struct FN_LIST *)ifs[0].pFunctionList;
        struct FN_LIST *b = (struct FN_LIST *)ifs[1].pFunctionList;
        ok(strcmp(ifs[0].pInterfaceName, "PKCS 11") == 0
           && strcmp(ifs[1].pInterfaceName, "PKCS 11") == 0,
           "both carry the name \"PKCS 11\"");
        ok(a->version.major == 3 && a->version.minor == 2,
           "the first is v3.2 (newest first)");
        ok(b->version.major == 3 && b->version.minor == 0,
           "the second is v3.0");
        /* The latent bug this change also closed: slots 68 and 69 of the v3.0
         * table used to be wired only inside C_GetInterface, so a caller who
         * arrived through the list found fhsm_not_supported in them. */
        ok(b->pfn[SLOT_C_GetInterfaceList] != NULL
           && b->pfn[SLOT_C_GetInterface] != NULL,
           "v3.0 slots 68/69 are wired without calling C_GetInterface first");
    }

    /* (2) Version selection, and the default. */
    CK_INTERFACE *sel = NULL;
    CK_VERSION v32 = { 3, 2 }, v30 = { 3, 0 }, v99 = { 9, 9 };

    ok(C_GetInterface(NULL, NULL, &sel, 0) == CKR_OK
       && ((struct FN_LIST *)sel->pFunctionList)->version.minor == 0,
       "a NULL version still yields v3.0 (the documented default)");

    ok(C_GetInterface((CK_BYTE*)"PKCS 11", &v30, &sel, 0) == CKR_OK
       && ((struct FN_LIST *)sel->pFunctionList)->version.minor == 0,
       "an explicit {3,0} yields v3.0");

    ok(C_GetInterface((CK_BYTE*)"PKCS 11", &v99, &sel, 0) != CKR_OK,
       "an unpublished version is refused, not silently substituted");

    /* (2b) A returned CK_INTERFACE survives the next call.
     *
     * The first version of this change used one static CK_INTERFACE for both
     * versions, rewritten per call. Asking for {3,2}, holding the pointer,
     * then asking for {3,0} silently turned the held pointer into a v3.0
     * description -- and a caller that then indexed slot 92, which is the
     * reason it asked for {3,2}, read past the end of a 92-slot array and
     * called whatever was there. Three crashes on the first run, against
     * crash 0 every day before it. pkcs11-check drives exactly this sequence.
     *
     * The spec does not say the returned interface may be invalidated by a
     * later call, and a caller is entitled to hold it. */
    {
        CK_INTERFACE *held32 = NULL, *held30 = NULL;
        if (C_GetInterface((CK_BYTE*)"PKCS 11", &v32, &held32, 0) == CKR_OK
            && C_GetInterface((CK_BYTE*)"PKCS 11", &v30, &held30, 0) == CKR_OK) {
            ok(((struct FN_LIST *)held32->pFunctionList)->version.minor == 2,
               "a held {3,2} interface is still v3.2 after asking for {3,0}");
            ok(held32 != held30,
               "the two interfaces are distinct objects, not one reused slot");
        } else {
            ok(0, "could not obtain both interfaces to compare");
        }
    }

    rv = C_GetInterface((CK_BYTE*)"PKCS 11", &v32, &sel, 0);
    ok(rv == CKR_OK, "an explicit {3,2} yields an interface");
    if (rv != CKR_OK) { printf("\nFAILURES\n"); return 1; }

    struct FN_LIST *f = (struct FN_LIST *)sel->pFunctionList;
    ok(f->version.major == 3 && f->version.minor == 2, "and it is v3.2");

    /* (3) Slots 92 and 93 are real, and 94 is honestly refused. A module that
     *     filled every v3.2 slot with the same stub would pass a presence
     *     check; this one distinguishes wired from refused. */
    ok(f->pfn[SLOT_C_EncapsulateKey] != f->pfn[SLOT_C_VerifySignatureInit],
       "slot 92 is not the not-supported stub");
    ok(f->pfn[SLOT_C_DecapsulateKey] != f->pfn[SLOT_C_VerifySignatureInit],
       "slot 93 is not the not-supported stub");
    ok(f->pfn[SLOT_C_LoginUser] == f->pfn[SLOT_C_VerifySignatureInit],
       "slot 70 (C_LoginUser) refuses through the same stub, as it should");

    /* (4) ML-KEM through the table, with the spec's argument order.
     *
     *     This is the whole point of the file. If the module's signature and
     *     the spec's disagree, the ciphertext pointer lands where the key
     *     handle is expected, and the call writes a handle into the buffer. */
    fn_init_t     f_init   = AS_FN(fn_init_t,     f->pfn[SLOT_C_Initialize]);
    fn_fin_t      f_fin    = AS_FN(fn_fin_t,      f->pfn[SLOT_C_Finalize]);
    fn_inittoken_t f_itok  = AS_FN(fn_inittoken_t, f->pfn[SLOT_C_InitToken]);
    fn_initpin_t  f_ipin   = AS_FN(fn_initpin_t,  f->pfn[SLOT_C_InitPIN]);
    fn_open_t     f_open   = AS_FN(fn_open_t,     f->pfn[SLOT_C_OpenSession]);
    fn_login_t    f_login  = AS_FN(fn_login_t,    f->pfn[SLOT_C_Login]);
    fn_keypair_t  f_kpair  = AS_FN(fn_keypair_t,  f->pfn[SLOT_C_GenerateKeyPair]);
    fn_getattr_t  f_getatt = AS_FN(fn_getattr_t,  f->pfn[SLOT_C_GetAttributeValue]);
    fn_encap_t    f_encap  = AS_FN(fn_encap_t,    f->pfn[SLOT_C_EncapsulateKey]);
    fn_decap_t    f_decap  = AS_FN(fn_decap_t,    f->pfn[SLOT_C_DecapsulateKey]);

    CK_BYTE label32[32]; memset(label32, ' ', 32); memcpy(label32, "ifacev32", 8);
    if (f_init(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize via table\n"); return 2; }
    if (f_itok(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label32) != CKR_OK) {
        fprintf(stderr, "C_InitToken via table\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (f_open(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (f_login(s, CKU_SO, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "SO\n"); return 2; }
    if (f_ipin(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    if (f_login(s, CKU_USER, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "USER\n"); return 2; }
    ok(1, "the whole session was opened through the v3.2 table");

    CK_BYTE yes = 1;
    char kplabel[] = "iface-mlkem";
    CK_ATTRIBUTE pub_t[]  = { { CKA_LABEL, kplabel, sizeof kplabel - 1 },
                              { CKA_EXTRACTABLE, &yes, 1 } };
    CK_ATTRIBUTE priv_t[] = { { CKA_LABEL, kplabel, sizeof kplabel - 1 } };
    CK_MECHANISM kpgen = { CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    rv = f_kpair(s, &kpgen, pub_t, 2, priv_t, 1, &hPub, &hPriv);
    ok(rv == CKR_OK, "ML-KEM key pair generated through the table");

    if (rv == CKR_OK) {
        CK_MECHANISM kem = { CKM_ML_KEM, NULL, 0 };
        char l1[] = "ss-a", l2[] = "ss-b";
        CK_ATTRIBUTE ss1_t[] = { { CKA_LABEL, l1, sizeof l1 - 1 },
                                 { CKA_EXTRACTABLE, &yes, 1 } };
        CK_ATTRIBUTE ss2_t[] = { { CKA_LABEL, l2, sizeof l2 - 1 },
                                 { CKA_EXTRACTABLE, &yes, 1 } };

        /* The size query first, which is also where a permuted signature
         * shows itself: a NULL ciphertext with a live length pointer. */
        CK_BYTE ct[4096];
        CK_ULONG ct_len = 0;
        CK_OBJECT_HANDLE hSS1 = 0, hSS2 = 0;
        rv = f_encap(s, &kem, hPub, ss1_t, 2, NULL, &ct_len, &hSS1);
        ok(rv == CKR_OK && ct_len == 1088,
           "C_EncapsulateKey size query returns 1088 (ML-KEM-768)");

        ct_len = sizeof ct;
        rv = f_encap(s, &kem, hPub, ss1_t, 2, ct, &ct_len, &hSS1);
        ok(rv == CKR_OK && hSS1 != 0, "C_EncapsulateKey through slot 92");

        if (rv == CKR_OK) {
            rv = f_decap(s, &kem, hPriv, ss2_t, 2, ct, ct_len, &hSS2);
            ok(rv == CKR_OK && hSS2 != 0, "C_DecapsulateKey through slot 93");
        }

        if (hSS1 && hSS2) {
            CK_BYTE a[64] = {0}, b[64] = {0};
            CK_ATTRIBUTE qa[] = { { CKA_VALUE, a, sizeof a } };
            CK_ATTRIBUTE qb[] = { { CKA_VALUE, b, sizeof b } };
            CK_RV ra = f_getatt(s, hSS1, qa, 1);
            CK_RV rb = f_getatt(s, hSS2, qb, 1);
            ok(ra == CKR_OK && rb == CKR_OK
               && qa[0].ulValueLen == 32 && qa[0].ulValueLen == qb[0].ulValueLen
               && memcmp(a, b, 32) == 0,
               "both sides hold the same 32-byte shared secret");
        }

        /* (5) The absurd template count, which is how the door being opened
         *     paid for itself on the first run.
         *
         *     pkcs11-check's security/test_arithmetic_overflow sends
         *     ulCount = 0xFFFFFFFFFFFFFFFF. fhsm_check_template exists because
         *     of that test and its comment names it -- and it had never been
         *     wired into these two, because the test could not reach them
         *     while they were in no function list. Three crashes, signal 11,
         *     against crash 0 every day before. */
        CK_ULONG absurd = (CK_ULONG)-1;
        CK_BYTE ct2[4096]; CK_ULONG ct2_len = sizeof ct2;
        CK_OBJECT_HANDLE hx = 0;
        ok(f_encap(s, &kem, hPub, ss1_t, absurd, ct2, &ct2_len, &hx) != CKR_OK,
           "C_EncapsulateKey refuses ulCount = 2^64-1 instead of walking it");
        ok(f_decap(s, &kem, hPriv, ss2_t, absurd, ct, ct_len, &hx) != CKR_OK,
           "C_DecapsulateKey refuses ulCount = 2^64-1 instead of walking it");
        /* A NULL template with a live count is the other half of the guard. */
        ok(f_encap(s, &kem, hPub, NULL, 4, ct2, &ct2_len, &hx) != CKR_OK,
           "and a NULL template with a non-zero count");

        /* (6) CKA_VALUE in the template.
         *
         *     The shared secret comes out of the KEM. A template that states
         *     one is asking to choose the secret bytes of a key that is
         *     supposed to be derived, and answering CKR_OK to it -- which the
         *     module did -- tells the caller it complied. It did not: the
         *     value was ignored. Silence about what one ignores is the shape
         *     removed from CKM_AES_GMAC on 2026-09-16. */
        CK_BYTE injected[] = "injected";
        CK_ULONG cko_secret = 4UL /* CKO_SECRET_KEY */, ckk_aes = 0x1FUL;
        CK_ATTRIBUTE inject_t[] = {
            { 0UL /* CKA_CLASS */, &cko_secret, sizeof(CK_ULONG) },
            { CKA_KEY_TYPE,        &ckk_aes,    sizeof(CK_ULONG) },
            { CKA_VALUE,           injected,    sizeof injected - 1 },
        };
        CK_RV rinj = f_decap(s, &kem, hPriv, inject_t, 3, ct, ct_len, &hx);
        ok(rinj == CKR_TEMPLATE_INCONSISTENT,
           "C_DecapsulateKey refuses CKA_VALUE injected into the template");
        ok(f_encap(s, &kem, hPub, inject_t, 3, ct2, &ct2_len, &hx)
             == CKR_TEMPLATE_INCONSISTENT,
           "and C_EncapsulateKey too, which nothing had probed");
    }

    if (f_fin) f_fin(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
