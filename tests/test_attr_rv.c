/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_attr_rv.c --- four answers that named the wrong error.
 *
 * Reported by AlexLaroche (#33, C2, C3, C4, C12). Each call was refused, and
 * rightly, but with a return code that sent the caller looking elsewhere:
 *   C2  a sensitive RSA private key's CKA_PRIVATE_EXPONENT (and the primes,
 *       exponents and coefficient) was CKR_ATTRIBUTE_TYPE_INVALID: the
 *       attributes had no case at all. PKCS#11 v3.2 §5.7.5 makes it
 *       CKR_ATTRIBUTE_SENSITIVE, as a sensitive EC key's CKA_VALUE already
 *       was. Every private key here is sensitive, so they always are.
 *   C3  C_SetAttributeValue of an RSA public key's CKA_MODULUS was
 *       CKR_ATTRIBUTE_TYPE_INVALID, "no such attribute", for an attribute
 *       C_GetAttributeValue reads: §4.1.2, CKR_ATTRIBUTE_READ_ONLY.
 *   C4  CKA_MODULUS into a 16-byte buffer was CKR_ATTRIBUTE_TYPE_INVALID:
 *       §5.7.5, CKR_BUFFER_TOO_SMALL with CK_UNAVAILABLE_INFORMATION.
 *   C12 CKM_AES_GCM with ulTagBits 136 was CKR_ARGUMENTS_BAD: a tag length
 *       GCM does not have is CKR_MECHANISM_PARAM_INVALID.
 *
 * What is asserted:
 *   (1) C2: a sensitive key's six private components are
 *       CKR_ATTRIBUTE_SENSITIVE, and so are those of a key asked
 *       CKA_SENSITIVE=FALSE (private keys are always sensitive here); a
 *       public key does not have them (CKR_ATTRIBUTE_TYPE_INVALID)
 *   (2) C3: CKA_MODULUS of the public key, CKA_PRIME_1 of the private key,
 *       CKA_VALUE_LEN of an AES key are CKR_ATTRIBUTE_READ_ONLY;
 *       CKA_MODULUS of the AES key stays CKR_ATTRIBUTE_TYPE_INVALID
 *   (3) C4: CKA_MODULUS into 16 bytes is CKR_BUFFER_TOO_SMALL with
 *       CK_UNAVAILABLE_INFORMATION; the size query then answers 256
 *   (4) C12: ulTagBits 136 and 100 are CKR_MECHANISM_PARAM_INVALID; 128
 *       initializes
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { void *pIv; CK_ULONG ulIvLen, ulIvBits; void *pAAD; CK_ULONG ulAADLen, ulTagBits; }
        CK_GCM_PARAMS;

#define CKR_OK                       0UL
#define CKR_ATTRIBUTE_READ_ONLY      0x10UL
#define CKR_ATTRIBUTE_SENSITIVE      0x11UL
#define CKR_ATTRIBUTE_TYPE_INVALID   0x12UL
#define CKR_MECHANISM_PARAM_INVALID  0x71UL
#define CKR_BUFFER_TOO_SMALL         0x150UL
#define CKF_RW                       6UL
#define CKA_TOKEN                    0x001UL
#define CKA_ENCRYPT                  0x104UL
#define CKA_SENSITIVE                0x103UL
#define CKA_SIGN                     0x108UL
#define CKA_VERIFY                   0x10AUL
#define CKA_MODULUS                  0x120UL
#define CKA_MODULUS_BITS             0x121UL
#define CKA_PRIVATE_EXPONENT         0x123UL
#define CKA_PRIME_1                  0x124UL
#define CKA_VALUE_LEN                0x161UL
#define CKA_EXTRACTABLE              0x162UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN    0x000UL
#define CKM_AES_KEY_GEN              0x1080UL
#define CKM_AES_GCM                  0x1087UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                  CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_SESSION_HANDLE s;

/* An RSA-2048 pair; the private key sensitive or not (and then extractable). */
static int rsa_pair(int sensitive, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv) {
    CK_ULONG bits = 2048;
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE pt[] = { { CKA_MODULUS_BITS, &bits, sizeof bits }, { CKA_VERIFY, &yes, 1 } };
    CK_ATTRIBUTE vt[] = { { CKA_SIGN, &yes, 1 },
                          { CKA_SENSITIVE, sensitive ? &yes : &no, 1 },
                          { CKA_EXTRACTABLE, sensitive ? &no : &yes, 1 } };
    CK_MECHANISM m = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    return C_GenerateKeyPair(s, &m, pt, 2, vt, 3, pub, prv) == CKR_OK;
}

/* The answer to reading `type` of `h` into a 600-byte buffer; length in *l. */
static CK_RV get(CK_OBJECT_HANDLE h, CK_ULONG type, CK_ULONG *l) {
    static CK_BYTE buf[600];
    CK_ATTRIBUTE a = { type, buf, sizeof buf };
    CK_RV rv = C_GetAttributeValue(s, h, &a, 1);
    *l = a.ulValueLen;
    return rv;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    #define SYM(n) *(void**)&n = dlsym(lib, #n); \
                   if (!n) { fprintf(stderr, "missing %s\n", #n); return 2; }
    SYM(C_Initialize) SYM(C_Finalize) SYM(C_InitToken) SYM(C_OpenSession) SYM(C_Login)
    SYM(C_Logout) SYM(C_InitPIN) SYM(C_GenerateKeyPair) SYM(C_GenerateKey)
    SYM(C_GetAttributeValue) SYM(C_SetAttributeValue) SYM(C_EncryptInit)

    printf("Return codes of attribute and parameter refusals\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "attrrv", 6);
    if (C_Initialize(NULL) || C_InitToken(0, (CK_BYTE *)SO_PIN, strlen(SO_PIN), label)
        || C_OpenSession(0, CKF_RW, NULL, NULL, &s)
        || C_Login(s, 0, (CK_BYTE *)SO_PIN, strlen(SO_PIN))
        || C_InitPIN(s, (CK_BYTE *)USER_PIN, strlen(USER_PIN))
        || C_Logout(s)
        || C_Login(s, 1, (CK_BYTE *)USER_PIN, strlen(USER_PIN))) {
        fprintf(stderr, "token setup failed\n"); return 2;
    }

    CK_OBJECT_HANDLE spub = 0, sprv = 0, opub = 0, oprv = 0;
    if (!rsa_pair(1, &spub, &sprv) || !rsa_pair(0, &opub, &oprv)) {
        fprintf(stderr, "RSA key pairs\n"); return 2;
    }
    CK_ULONG l = 0;
    CK_RV rv;
    char what[96];

    /* (1) C2 */
    {
        int all = 1;
        for (CK_ULONG a = 0x123; a <= 0x128; a++)
            all &= get(sprv, a, &l) == CKR_ATTRIBUTE_SENSITIVE && l == (CK_ULONG)-1;
        ok(all, "(1) sensitive key: the six private components are SENSITIVE");
        /* Asked CKA_SENSITIVE=FALSE, CKA_EXTRACTABLE=TRUE: a private key here
         * is sensitive all the same, so the answer is the same. */
        all = 1;
        for (CK_ULONG a = 0x123; a <= 0x128; a++)
            all &= get(oprv, a, &l) == CKR_ATTRIBUTE_SENSITIVE && l == (CK_ULONG)-1;
        ok(all, "(1) a key asked not sensitive: still SENSITIVE");
        rv = get(opub, CKA_PRIVATE_EXPONENT, &l);
        snprintf(what, sizeof what, "(1) a public key has no private exponent: TYPE_INVALID (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_TYPE_INVALID, what);
    }

    /* (2) C3 */
    {
        CK_BYTE junk[4] = { 1, 2, 3, 4 };
        CK_ATTRIBUTE m = { CKA_MODULUS, junk, sizeof junk };
        rv = C_SetAttributeValue(s, spub, &m, 1);
        snprintf(what, sizeof what, "(2) set CKA_MODULUS of an RSA public key: READ_ONLY (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_READ_ONLY, what);
        CK_ATTRIBUTE p1 = { CKA_PRIME_1, junk, sizeof junk };
        rv = C_SetAttributeValue(s, oprv, &p1, 1);
        snprintf(what, sizeof what, "(2) set CKA_PRIME_1 of an RSA private key: READ_ONLY (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_READ_ONLY, what);

        CK_ULONG klen = 16; CK_BYTE yes = 1;
        CK_ATTRIBUTE kt[] = { { CKA_VALUE_LEN, &klen, sizeof klen }, { CKA_ENCRYPT, &yes, 1 } };
        CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };
        CK_OBJECT_HANDLE aes = 0;
        if (C_GenerateKey(s, &kg, kt, 2, &aes) != CKR_OK) { fprintf(stderr, "AES key\n"); return 2; }
        CK_ULONG nl = 32;
        CK_ATTRIBUTE vl = { CKA_VALUE_LEN, &nl, sizeof nl };
        rv = C_SetAttributeValue(s, aes, &vl, 1);
        snprintf(what, sizeof what, "(2) set CKA_VALUE_LEN of an AES key: READ_ONLY (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_READ_ONLY, what);
        rv = C_SetAttributeValue(s, aes, &m, 1);
        snprintf(what, sizeof what, "(2) set CKA_MODULUS of an AES key: TYPE_INVALID (0x%lx)", rv);
        ok(rv == CKR_ATTRIBUTE_TYPE_INVALID, what);

        /* (4) C12, with the same key. */
        CK_BYTE iv[12] = { 0 };
        CK_GCM_PARAMS g = { iv, 12, 96, NULL, 0, 136 };
        CK_MECHANISM gm = { CKM_AES_GCM, &g, sizeof g };
        rv = C_EncryptInit(s, &gm, aes);
        snprintf(what, sizeof what, "(4) AES-GCM, ulTagBits 136: MECHANISM_PARAM_INVALID (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, what);
        g.ulTagBits = 100;
        rv = C_EncryptInit(s, &gm, aes);
        snprintf(what, sizeof what, "(4) AES-GCM, ulTagBits 100: MECHANISM_PARAM_INVALID (0x%lx)", rv);
        ok(rv == CKR_MECHANISM_PARAM_INVALID, what);
        g.ulTagBits = 128;
        ok(C_EncryptInit(s, &gm, aes) == CKR_OK, "(4) AES-GCM, ulTagBits 128: initializes");
    }

    /* (3) C4 */
    {
        CK_BYTE small[16];
        CK_ATTRIBUTE a = { CKA_MODULUS, small, sizeof small };
        rv = C_GetAttributeValue(s, spub, &a, 1);
        snprintf(what, sizeof what, "(3) CKA_MODULUS into 16 bytes: BUFFER_TOO_SMALL (0x%lx)", rv);
        ok(rv == CKR_BUFFER_TOO_SMALL && a.ulValueLen == (CK_ULONG)-1, what);
        CK_ATTRIBUTE q = { CKA_MODULUS, NULL, 0 };
        ok(C_GetAttributeValue(s, spub, &q, 1) == CKR_OK && q.ulValueLen == 256,
           "(3) the size query then answers 256");
    }

    C_Finalize(NULL);
    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
