/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_advertised_operational.c --- every advertised mechanism must be
 * reachable through the operation its own flags claim.
 *
 * This module keeps two structures that describe what it can do, and nothing
 * holds them equal:
 *
 *   - fhsm_mechanism_table[], generated from scripts/gen_p11_thunks.py, read
 *     by C_GetMechanismList and C_GetMechanismInfo. This is what the module
 *     says about itself.
 *   - the switch statements inside C_SignInit, C_EncryptInit, C_DigestInit,
 *     C_DeriveKey and their siblings. This is what the module does.
 *
 * The table carries a handler pointer per entry, which suggests the two are
 * connected. They are not: no code in this repository dereferences
 * e->handler. The dispatch_* functions are reference implementations; the
 * PKCS#11 entry points are written separately by hand.
 *
 * Everything found in the week of 2026-09-07 is a symptom of that:
 *
 *   #14           advertised, not operational
 *   SHA256/384/512_RSA_PKCS, AES_GMAC
 *                 operational, not advertised
 *   CKM_PKCS5_PBKD2 and eleven other derive mechanisms
 *                 advertised with a handler, C_DeriveKey accepts two of them
 *   multipart HMAC verify
 *                 advertised for nine, operational for one
 *
 * Each was found by an external harness, one at a time, months apart. This
 * test finds the whole class at build time instead, and needs no list of its
 * own to maintain: C_GetMechanismInfo already reports which operation each
 * mechanism claims, so the test asks the module what to call and then calls
 * it.
 *
 * What counts as a failure is only CKR_MECHANISM_INVALID. An Init that
 * refuses because the key is the wrong type, because a parameter block is
 * required, or because the profile withdrew the mechanism has been reached
 * and has made a decision about the mechanism -- that is the property under
 * test. CKR_MECHANISM_INVALID means the entry point does not know the
 * mechanism exists.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize; CK_FLAGS flags; } CK_MECHANISM_INFO;

#define CKR_OK                     0UL
#define CKR_MECHANISM_INVALID      0x70UL
#define CKF_RW                     6UL
#define CKF_ENCRYPT                0x00000100UL
#define CKF_DECRYPT                0x00000200UL
#define CKF_DIGEST                 0x00000400UL
#define CKF_SIGN                   0x00000800UL
#define CKF_VERIFY                 0x00002000UL
#define CKF_SIGN_RECOVER           0x00001000UL
#define CKF_VERIFY_RECOVER         0x00004000UL
#define CKF_GENERATE               0x00008000UL
#define CKF_GENERATE_KEY_PAIR      0x00010000UL
#define CKF_WRAP                   0x00020000UL
#define CKF_UNWRAP                 0x00040000UL
#define CKF_DERIVE                 0x00080000UL
#define CKF_ENCAPSULATE            0x10000000UL
#define CKF_DECAPSULATE            0x20000000UL
/* Operations this test does not probe. Key generation needs a per-mechanism
 * template and wrapping needs a second key of the right type, so a generic
 * probe would report noise instead of the property under test. A mechanism
 * that advertises only these is counted, not failed. */
#define CKF_UNPROBED (CKF_GENERATE | CKF_GENERATE_KEY_PAIR | CKF_WRAP | \
                      CKF_UNWRAP  | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER)
#define CKA_CLASS                  0UL
#define CKA_KEY_TYPE               0x100UL
#define CKA_VALUE_LEN              0x161UL
#define CKA_SIGN                   0x108UL
#define CKA_VERIFY                 0x10AUL
#define CKA_ENCRYPT                0x104UL
#define CKA_DECRYPT                0x105UL
#define CKA_DERIVE                 0x10CUL
#define CKO_SECRET_KEY             4UL
#define CKK_GENERIC_SECRET         0x10UL
#define CKM_GENERIC_SECRET_KEY_GEN 0x350UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

/* The gaps this test found when it was written, on 2026-09-09. Every entry is
 * a mechanism the module advertises and no entry point accepts.
 *
 * This list is a ratchet, not an exemption. The test fails if a mechanism
 * outside it is unreachable -- a new gap -- and it also fails if a mechanism
 * inside it turns out to work, which forces the entry to be deleted when the
 * gap is closed. So it can only shrink, and it cannot quietly rot.
 *
 * Adding a line here is not a way to make the build green. It records a
 * decision to ship an advertisement the module does not honour, which is the
 * thing this file exists to make visible. */
static const struct { CK_ULONG ckm; const char *name; const char *why; } KNOWN_GAPS[] = {
    /* C_DeriveKey accepts CKM_ECDH1_DERIVE and its cofactor variant and
     * nothing else, while ten derive mechanisms are advertised with a
     * dispatch_* handler each. The handlers exist and are not called: no
     * code in this repository dereferences fhsm_mechanism_table[].handler. */
    { 0x00000384UL, "CKM_NIST_PRF_KDF",              "C_DeriveKey: ECDH1 only" },
    { 0x000003B0UL, "CKM_PKCS5_PBKD2",               "C_DeriveKey: ECDH1 only" },
    { 0x00001052UL, "CKM_X25519_DERIVE",             "C_DeriveKey: ECDH1 only" },
    { 0x00001054UL, "CKM_X448_DERIVE",               "C_DeriveKey: ECDH1 only" },
    { 0x0000402AUL, "CKM_HKDF_DERIVE",               "C_DeriveKey: ECDH1 only" },
    { 0x0000402BUL, "CKM_HKDF_DATA",                 "C_DeriveKey: ECDH1 only" },
    /* KMAC and the two hybrids: handlers exist, the entry points do not know
     * the mechanism. No external harness has ever reported these three --
     * pkcs11-check tests what it has vectors for, and it has none here. */
    { 0x00004080UL, "CKM_KMAC128",                   "C_SignInit / C_VerifyInit" },
    { 0x00004081UL, "CKM_KMAC256",                   "C_SignInit / C_VerifyInit" },
    { 0x80004200UL, "CKM_HYBRID_X25519_ML_KEM_768",  "C_EncapsulateKey" },
    { 0x80004201UL, "CKM_HYBRID_ED25519_ML_DSA_65",  "C_SignInit / C_VerifyInit" },
    { 0, NULL, NULL }
};

static int fails = 0, checked = 0, unprobed = 0;
static int gap_seen[64];

static int known_gap(CK_ULONG m) {
    for (int i = 0; KNOWN_GAPS[i].why; ++i) if (KNOWN_GAPS[i].ckm == m) return i;
    return -1;
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
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_GetMechanismList)(CK_SLOT_ID,CK_ULONG*,CK_ULONG*);
    CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID,CK_ULONG,CK_MECHANISM_INFO*);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_DigestInit)(CK_SESSION_HANDLE,CK_MECHANISM*);
    CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_EncapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_BYTE*,CK_ULONG*);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_GenerateKey);
    SYM(C_GetMechanismList); SYM(C_GetMechanismInfo);
    SYM(C_SignInit); SYM(C_VerifyInit); SYM(C_EncryptInit);
    SYM(C_DecryptInit); SYM(C_DigestInit); SYM(C_DeriveKey);
    SYM(C_EncapsulateKey);
    if (!C_GetMechanismList || !C_GetMechanismInfo || !C_DeriveKey) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("advertised mechanisms must be operational\n\n");

    CK_BYTE label[32];
    { size_t n = strlen("advop"); memset(label,' ',32); memcpy(label,"advop",n); }
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr,"C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr,"C_Login USER\n"); return 2; }

    /* One permissive generic-secret key. The point is to reach the mechanism
     * switch, not to make each operation succeed -- a key-type refusal counts
     * as reached. */
    CK_ULONG len32 = 32;
    CK_BYTE t_true = 1;
    CK_ATTRIBUTE ktmpl[] = {
        { CKA_CLASS,     &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,  &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_VALUE_LEN, &len32,                          sizeof(CK_ULONG) },
        { CKA_SIGN,      &t_true, 1 }, { CKA_VERIFY,  &t_true, 1 },
        { CKA_ENCRYPT,   &t_true, 1 }, { CKA_DECRYPT, &t_true, 1 },
        { CKA_DERIVE,    &t_true, 1 },
    };
    CK_MECHANISM keygen = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = 0;
    if (C_GenerateKey(s, &keygen, ktmpl, 8, &key) != CKR_OK) {
        fprintf(stderr, "C_GenerateKey (probe key)\n"); return 2;
    }

    CK_ULONG n = 0;
    if (C_GetMechanismList(0, NULL, &n) != CKR_OK || n == 0) {
        fprintf(stderr, "C_GetMechanismList\n"); return 2;
    }
    static CK_ULONG list[512];
    if (n > 512) n = 512;
    if (C_GetMechanismList(0, list, &n) != CKR_OK) { fprintf(stderr,"C_GetMechanismList fill\n"); return 2; }
    printf("  %lu mechanisms advertised\n\n", (unsigned long)n);

    for (CK_ULONG i = 0; i < n; ++i) {
        CK_MECHANISM_INFO info;
        memset(&info, 0, sizeof info);
        if (C_GetMechanismInfo(0, list[i], &info) != CKR_OK) {
            printf("  0x%04lx  C_GetMechanismInfo refuses an advertised mechanism   FAIL\n", list[i]);
            fails++; continue;
        }
        int gap = known_gap(list[i]);
        CK_MECHANISM m = { list[i], NULL, 0 };
        CK_OBJECT_HANDLE out = 0;
        struct { const char *op; CK_FLAGS flag; CK_RV rv; int tried; } probe[] = {
            { "C_SignInit",    CKF_SIGN,    0, 0 },
            { "C_VerifyInit",  CKF_VERIFY,  0, 0 },
            { "C_EncryptInit", CKF_ENCRYPT, 0, 0 },
            { "C_DecryptInit", CKF_DECRYPT, 0, 0 },
            { "C_DigestInit",  CKF_DIGEST,  0, 0 },
            { "C_DeriveKey",   CKF_DERIVE,  0, 0 },
            { "C_EncapsulateKey", CKF_ENCAPSULATE, 0, 0 },
        };
        if (info.flags & CKF_SIGN)    { probe[0].rv = C_SignInit(s,&m,key);    probe[0].tried = 1; }
        if (info.flags & CKF_VERIFY)  { probe[1].rv = C_VerifyInit(s,&m,key);  probe[1].tried = 1; }
        if (info.flags & CKF_ENCRYPT) { probe[2].rv = C_EncryptInit(s,&m,key); probe[2].tried = 1; }
        if (info.flags & CKF_DECRYPT) { probe[3].rv = C_DecryptInit(s,&m,key); probe[3].tried = 1; }
        if (info.flags & CKF_DIGEST)  { probe[4].rv = C_DigestInit(s,&m);      probe[4].tried = 1; }
        if (info.flags & CKF_DERIVE)  { probe[5].rv = C_DeriveKey(s,&m,key,ktmpl,3,&out); probe[5].tried = 1; }
        if ((info.flags & CKF_ENCAPSULATE) && C_EncapsulateKey) {
            CK_BYTE ct[64]; CK_ULONG ctlen = sizeof ct;
            probe[6].rv = C_EncapsulateKey(s,&m,key,ktmpl,3,&out,ct,&ctlen);
            probe[6].tried = 1;
        }

        int any = 0, unreachable = 0;
        for (size_t k = 0; k < 7; ++k) {
            if (!probe[k].tried) continue;
            any = 1; checked++;
            if (probe[k].rv != CKR_MECHANISM_INVALID) continue;
            unreachable = 1;
            if (gap >= 0) continue;
            printf("  0x%04lx  advertises %s but %s returns CKR_MECHANISM_INVALID   FAIL\n",
                   list[i], probe[k].op + 2, probe[k].op);
            fails++;
        }
        if (gap >= 0) {
            gap_seen[gap] = 1;
            if (unreachable) {
                printf("  0x%-9lx known gap: %-30s %s\n",
                       list[i], KNOWN_GAPS[gap].name, KNOWN_GAPS[gap].why);
            } else {
                printf("  0x%-9lx %s is reachable now -- delete its KNOWN_GAPS entry   FAIL\n",
                       list[i], KNOWN_GAPS[gap].name);
                fails++;
            }
        }
        if (!any) {
            if (info.flags & CKF_UNPROBED) { unprobed++; continue; }
            printf("  0x%04lx  advertised with no operation flag at all   FAIL\n", list[i]);
            fails++;
        }
    }

    /* A KNOWN_GAPS entry for a mechanism that is no longer advertised is
     * stale: it would hide the gap if the mechanism came back. */
    int gaps = 0;
    for (int i = 0; KNOWN_GAPS[i].why; ++i) {
        gaps++;
        if (!gap_seen[i]) {
            printf("  %s is in KNOWN_GAPS but not advertised -- stale entry   FAIL\n",
                   KNOWN_GAPS[i].name);
            fails++;
        }
    }

    if (C_Finalize) C_Finalize(NULL);
    printf("\n  %d operations probed across %lu mechanisms"
           " (%d keygen/wrap-only, %d known gaps)\n",
           checked, (unsigned long)n, unprobed, gaps);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
