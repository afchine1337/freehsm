/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_public_session.c --- public session objects without a login (#45).
 *
 * PKCS#11 v3.2 §5.6: a R/W public session has read/write access to public
 * objects, and a R/O one to public session objects. The module refused every
 * object before a login. pkcs11-provider imports the keys an application
 * hands it -- a key read from a PEM file, the input key of an HKDF -- as
 * session objects, and failed without a login where SoftHSM, softokn and
 * Kryoptic accept them. The six objects of the reproducer in #45 open the
 * test; FreeHSM now answers as SoftHSM does on all six but the token object,
 * which is the second part of #45.
 *
 * In a R/W session, never logged in:
 *   (R) the reproducer: a secret key and an EC private key with
 *       CKA_PRIVATE=FALSE and an EC public key, as session objects, are made
 *       and read back public; the same keys without CKA_PRIVATE are private
 *       and refused; the public key as a token object is refused;
 *   (U) the public private key signs and the public key verifies; the public
 *       secret key derives a public session key, and not a private or token
 *       one; it is renamed, copied into a session object and not into a token
 *       object, and generated keys follow the same rule;
 *   (P) a private key copied with CKA_PRIVATE=FALSE stays out of reach: the
 *       copy of a public one with CKA_PRIVATE=TRUE needs the user;
 *   (L) the user logs in: the objects are there with their handles; after
 *       C_CloseSession they are gone;
 *   (S) in strict mode (this program again, FHSM_MODE=strict, same token), a
 *       private key asked CKA_PRIVATE=FALSE stays private and is refused
 *       without a login; a public secret key is still made.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_BYTE *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;

#define CKR_OK                 0UL
#define CKR_USER_NOT_LOGGED_IN 0x101UL
#define CKF_RW                 6UL
#define CKO_PUBLIC_KEY         2UL
#define CKO_PRIVATE_KEY        3UL
#define CKO_SECRET_KEY         4UL
#define CKK_EC                 3UL
#define CKK_GENERIC_SECRET     0x10UL
#define CKK_AES                0x1FUL
#define CKA_CLASS              0x0UL
#define CKA_TOKEN              0x1UL
#define CKA_PRIVATE            0x2UL
#define CKA_LABEL              0x3UL
#define CKA_VALUE              0x11UL
#define CKA_KEY_TYPE           0x100UL
#define CKA_SIGN               0x108UL
#define CKA_VERIFY             0x10AUL
#define CKA_DERIVE             0x10CUL
#define CKA_VALUE_LEN          0x161UL
#define CKA_EC_PARAMS          0x180UL
#define CKA_EC_POINT           0x181UL
#define CKM_AES_KEY_GEN        0x1080UL
#define CKM_ECDSA              0x1041UL
#define CKM_CONCATENATE_BASE_AND_DATA 0x362UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-70s %s\n", what, cond ? "OK" : "FAIL");
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
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,
                            CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);

static CK_BYTE T = 1, F = 0;
static CK_ULONG c_sec = CKO_SECRET_KEY, c_pub = CKO_PUBLIC_KEY, c_prv = CKO_PRIVATE_KEY;
static CK_ULONG k_gen = CKK_GENERIC_SECRET, k_ec = CKK_EC, k_aes = CKK_AES;
static CK_BYTE key[32] = { 1, 2, 3 };
static CK_BYTE p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
/* 7G on P-256, the public key of d = 7, as a DER OCTET STRING. */
static CK_BYTE point7[] = { 0x04, 0x41, 0x04,
    0x8e,0x53,0x3b,0x6f,0xa0,0xbf,0x7b,0x46,0x25,0xbb,0x30,0x66,0x7c,0x01,0xfb,0x60,
    0x7e,0xf9,0xf8,0xb8,0xa8,0x0f,0xef,0x5b,0x30,0x06,0x28,0x70,0x31,0x87,0xb2,0xa3,
    0x73,0xeb,0x1d,0xbd,0xe0,0x33,0x18,0x36,0x6d,0x06,0x9f,0x83,0xa6,0xf5,0x90,0x00,
    0x53,0xc7,0x36,0x33,0xcb,0x04,0x1b,0x21,0xc5,0x5e,0x1a,0x86,0xc1,0xf4,0x00,0xb4 };
static CK_BYTE d7[32] = { [31] = 7 };

/* CKA_PRIVATE as read back: 1, 0, or -1. */
static int read_private(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h) {
    CK_BYTE v = 0xFF;
    CK_ATTRIBUTE a = { CKA_PRIVATE, &v, 1 };
    if (C_GetAttributeValue(s, h, &a, 1) != CKR_OK) return -1;
    return v ? 1 : 0;
}

static int label_is(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, const char *want) {
    char buf[64] = "";
    CK_ATTRIBUTE a = { CKA_LABEL, buf, sizeof buf - 1 };
    if (C_GetAttributeValue(s, h, &a, 1) != CKR_OK) return 0;
    buf[a.ulValueLen < sizeof buf ? a.ulValueLen : sizeof buf - 1] = 0;
    return strcmp(buf, want) == 0;
}

/* The six objects of the reproducer in #45. */
static CK_RV secret(CK_SESSION_HANDLE s, int priv, CK_OBJECT_HANDLE *h) {
    CK_ATTRIBUTE t[] = { {CKA_CLASS,&c_sec,sizeof c_sec}, {CKA_KEY_TYPE,&k_gen,sizeof k_gen},
        {CKA_TOKEN,&F,1}, {CKA_DERIVE,&T,1}, {CKA_VALUE,key,sizeof key},
        {CKA_LABEL,(void*)"sec",3}, {CKA_PRIVATE,&F,1} };
    return C_CreateObject(s, t, priv < 0 ? 6 : 7, h);
}
static CK_RV pubkey(CK_SESSION_HANDLE s, int token, CK_OBJECT_HANDLE *h) {
    CK_ATTRIBUTE t[] = { {CKA_CLASS,&c_pub,sizeof c_pub}, {CKA_KEY_TYPE,&k_ec,sizeof k_ec},
        {CKA_TOKEN,token ? &T : &F,1}, {CKA_VERIFY,&T,1}, {CKA_EC_PARAMS,p256,sizeof p256},
        {CKA_EC_POINT,point7,sizeof point7} };
    return C_CreateObject(s, t, 6, h);
}
static CK_RV privkey(CK_SESSION_HANDLE s, int priv, CK_OBJECT_HANDLE *h) {
    CK_ATTRIBUTE t[] = { {CKA_CLASS,&c_prv,sizeof c_prv}, {CKA_KEY_TYPE,&k_ec,sizeof k_ec},
        {CKA_TOKEN,&F,1}, {CKA_SIGN,&T,1}, {CKA_EC_PARAMS,p256,sizeof p256},
        {CKA_VALUE,d7,sizeof d7}, {CKA_PRIVATE,&F,1} };
    return C_CreateObject(s, t, priv < 0 ? 6 : 7, h);
}

static int strict_run(void) {
    printf("\nStrict mode (FHSM_MODE=strict)\n");
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize (strict)\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    CK_OBJECT_HANDLE h = 0;
    ok(privkey(s, 0, &h) == CKR_USER_NOT_LOGGED_IN,
       "(S) a private key asked CKA_PRIVATE=FALSE is private: refused");
    ok(secret(s, 0, &h) == CKR_OK && read_private(s, h) == 0,
       "(S) a public secret key session object is still made");
    (void)C_CloseSession(s);
    (void)C_Finalize(NULL);
    return 0;
}

int main(int argc, char **argv)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_CloseSession); SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN);
    SYM(C_CreateObject); SYM(C_CopyObject); SYM(C_GenerateKey);
    SYM(C_GetAttributeValue); SYM(C_SetAttributeValue); SYM(C_DeriveKey);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_CopyObject || !C_GenerateKey || !C_DeriveKey || !C_Verify || !C_CloseSession) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }
    if (argc > 1 && strcmp(argv[1], "strict") == 0) {
        int r = strict_run();
        return r ? r : (fails ? 1 : 0);
    }

    printf("Public session objects through the PKCS#11 calls (#45)\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "pubsess", 7);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))
        || C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    (void)C_Logout(s);

    /* (R) */
    CK_OBJECT_HANDLE hs = 0, hp = 0, hk = 0, x = 0;
    ok(secret(s, 0, &hs) == CKR_OK && read_private(s, hs) == 0,
       "(R) secret key, session, CKA_PRIVATE=FALSE: made, public");
    ok(secret(s, -1, &x) == CKR_USER_NOT_LOGGED_IN,
       "(R) secret key, session, no CKA_PRIVATE: private, refused");
    ok(pubkey(s, 0, &hp) == CKR_OK && read_private(s, hp) == 0,
       "(R) EC public key, session: made, public");
    ok(pubkey(s, 1, &x) == CKR_USER_NOT_LOGGED_IN,
       "(R) EC public key, token object: refused");
    ok(privkey(s, 0, &hk) == CKR_OK && read_private(s, hk) == 0,
       "(R) EC private key, session, CKA_PRIVATE=FALSE: made, public");
    ok(privkey(s, -1, &x) == CKR_USER_NOT_LOGGED_IN,
       "(R) EC private key, session, no CKA_PRIVATE: private, refused");

    /* (U) */
    {
        CK_MECHANISM m = { CKM_ECDSA, NULL, 0 };
        CK_BYTE hash[32]; memset(hash, 0x42, sizeof hash);
        CK_BYTE sig[72]; CK_ULONG sl = sizeof sig;
        ok(C_SignInit(s, &m, hk) == CKR_OK && C_Sign(s, hash, 32, sig, &sl) == CKR_OK,
           "(U) the public private key signs");
        ok(C_VerifyInit(s, &m, hp) == CKR_OK && C_Verify(s, hash, 32, sig, sl) == CKR_OK,
           "(U) and the public key verifies the signature");
    }
    {
        CK_BYTE extra[4] = { 9, 9, 9, 9 };
        CK_KEY_DERIVATION_STRING_DATA sd = { extra, sizeof extra };
        CK_MECHANISM m = { CKM_CONCATENATE_BASE_AND_DATA, &sd, sizeof sd };
        CK_ATTRIBUTE dpub[] = { {CKA_CLASS,&c_sec,sizeof c_sec}, {CKA_KEY_TYPE,&k_gen,sizeof k_gen},
                                {CKA_TOKEN,&F,1}, {CKA_PRIVATE,&F,1} };
        CK_ATTRIBUTE dprv[] = { {CKA_CLASS,&c_sec,sizeof c_sec}, {CKA_KEY_TYPE,&k_gen,sizeof k_gen},
                                {CKA_TOKEN,&F,1} };
        CK_ATTRIBUTE dtok[] = { {CKA_CLASS,&c_sec,sizeof c_sec}, {CKA_KEY_TYPE,&k_gen,sizeof k_gen},
                                {CKA_TOKEN,&T,1}, {CKA_PRIVATE,&F,1} };
        ok(C_DeriveKey(s, &m, hs, dpub, 4, &x) == CKR_OK && read_private(s, x) == 0,
           "(U) the public secret key derives a public session key");
        ok(C_DeriveKey(s, &m, hs, dprv, 3, &x) == CKR_USER_NOT_LOGGED_IN,
           "(U) not a private one");
        ok(C_DeriveKey(s, &m, hs, dtok, 4, &x) == CKR_USER_NOT_LOGGED_IN,
           "(U) nor a token one");
    }
    {
        CK_ATTRIBUTE rl = { CKA_LABEL, (void*)"renamed", 7 };
        ok(C_SetAttributeValue(s, hs, &rl, 1) == CKR_OK && label_is(s, hs, "renamed"),
           "(U) the public secret key is renamed");
        CK_ATTRIBUTE cs[] = { {CKA_TOKEN,&F,1}, {CKA_LABEL,(void*)"copy",4} };
        CK_ATTRIBUTE ct[] = { {CKA_TOKEN,&T,1} };
        ok(C_CopyObject(s, hs, cs, 2, &x) == CKR_OK && read_private(s, x) == 0
           && label_is(s, x, "copy"),
           "(U) copied into a public session object");
        ok(C_CopyObject(s, hs, ct, 1, &x) == CKR_USER_NOT_LOGGED_IN,
           "(U) not into a token object");
        CK_ATTRIBUTE cp[] = { {CKA_TOKEN,&F,1}, {CKA_PRIVATE,&T,1} };
        ok(C_CopyObject(s, hs, cp, 2, &x) == CKR_USER_NOT_LOGGED_IN,
           "(U) nor into a private one");
    }
    {
        CK_ULONG vl = 16;
        CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };
        CK_ATTRIBUTE gpub[] = { {CKA_CLASS,&c_sec,sizeof c_sec}, {CKA_KEY_TYPE,&k_aes,sizeof k_aes},
                                {CKA_VALUE_LEN,&vl,sizeof vl}, {CKA_TOKEN,&F,1}, {CKA_PRIVATE,&F,1} };
        CK_ATTRIBUTE gprv[] = { {CKA_CLASS,&c_sec,sizeof c_sec}, {CKA_KEY_TYPE,&k_aes,sizeof k_aes},
                                {CKA_VALUE_LEN,&vl,sizeof vl}, {CKA_TOKEN,&F,1} };
        ok(C_GenerateKey(s, &kg, gpub, 5, &x) == CKR_OK && read_private(s, x) == 0,
           "(U) C_GenerateKey makes a public session key");
        ok(C_GenerateKey(s, &kg, gprv, 4, &x) == CKR_USER_NOT_LOGGED_IN,
           "(U) and refuses a private one");
    }

    /* (L) */
    ok(C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) == CKR_OK, "(L) the user logs in");
    ok(label_is(s, hs, "renamed") && read_private(s, hk) == 0 && read_private(s, hp) == 0,
       "(L) the session objects are there, same handles");
    (void)C_Logout(s);
    ok(label_is(s, hs, "renamed"), "(L) after C_Logout, the public ones are still there");
    (void)C_CloseSession(s);
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession (2)\n"); return 2; }
    ok(read_private(s, hs) == -1 && read_private(s, hk) == -1,
       "(L) after C_CloseSession, they are gone");
    (void)C_CloseSession(s);
    (void)C_Finalize(NULL);

    /* Strict mode is read once per process, so it is this program again,
     * with FHSM_MODE=strict and the same token directory. */
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        setenv("FHSM_MODE", "strict", 1);
        char *const av[] = { argv[0], (char *)"strict", NULL };
        execv("/proc/self/exe", av);
        _exit(3);
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("  %-70s FAIL\n", "strict-mode run");
        fails++;
    }

    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
