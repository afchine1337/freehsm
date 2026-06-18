/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * mlkem_e2e.c --- end-to-end ML-KEM-768 test via dlsym.
 *
 *  Exercises the v3.0-extended C_EncapsulateKey / C_DecapsulateKey
 *  symbols which are NOT in the legacy CK_FUNCTION_LIST. We dlopen the
 *  module and call them directly.
 *
 *  Scenario :
 *    1. C_Initialize
 *    2. Find slot 0 token, open session, login as USER
 *    3. C_GenerateKeyPair (CKM_ML_KEM_KEY_PAIR_GEN, ML-KEM-768)
 *    4. C_EncapsulateKey with the pubkey → ciphertext + shared secret 1
 *    5. C_DecapsulateKey with the privkey → shared secret 2
 *    6. CKA_VALUE on both secrets ; verify they are byte-identical
 *
 *  Build : cc tests/mlkem_e2e.c -ldl -o tests/mlkem_e2e
 *  Run   : sudo -u freehsm FHSM_TOKENS_DIR=/path tests/mlkem_e2e
 *
 *  Pre-requisite : slot 0 must be initialized with USER PIN "user0000".
 *  Use multi_slot_pkcs11.sh or full_crypto_pkcs11.sh first.
 * ========================================================================= */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MODULE      "/opt/freehsm/lib/libfreehsm-fips.so"
#define USER_PIN    "user0000"

/* PKCS#11 typedefs (minimal subset for this test). */
typedef unsigned long CK_ULONG;
typedef CK_ULONG      CK_FLAGS;
typedef CK_ULONG      CK_RV;
typedef CK_ULONG      CK_MECHANISM_TYPE;
typedef CK_ULONG      CK_ATTRIBUTE_TYPE;
typedef CK_ULONG      CK_SESSION_HANDLE;
typedef CK_ULONG      CK_OBJECT_HANDLE;
typedef CK_ULONG      CK_SLOT_ID;
typedef CK_ULONG      CK_USER_TYPE;

typedef struct {
    CK_MECHANISM_TYPE mechanism;
    void             *pParameter;
    CK_ULONG          ulParameterLen;
} CK_MECHANISM;

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    void             *pValue;
    CK_ULONG          ulValueLen;
} CK_ATTRIBUTE;

#define CKM_ML_KEM_KEY_PAIR_GEN  0x0000403CUL
#define CKM_ML_KEM               0x0000403DUL
#define CKA_LABEL                0x00000003UL
#define CKA_VALUE                0x00000011UL
#define CKA_EXTRACTABLE          0x00000162UL
#define CKR_OK                   0x00000000UL
#define CKU_USER                 1UL

typedef CK_RV (*pf_init_t)(void *);
typedef CK_RV (*pf_open_t)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
typedef CK_RV (*pf_login_t)(CK_SESSION_HANDLE, CK_USER_TYPE,
                             unsigned char*, CK_ULONG);
typedef CK_RV (*pf_keypair_t)(CK_SESSION_HANDLE, CK_MECHANISM*,
                               CK_ATTRIBUTE*, CK_ULONG,
                               CK_ATTRIBUTE*, CK_ULONG,
                               CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
typedef CK_RV (*pf_encap_t)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE,
                             CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*,
                             unsigned char*, CK_ULONG*);
typedef CK_RV (*pf_decap_t)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE,
                             CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*,
                             unsigned char*, CK_ULONG);
typedef CK_RV (*pf_getattr_t)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                               CK_ATTRIBUTE*, CK_ULONG);

/* POSIX dlsym returns a void*. ISO C forbids casting a void* directly
 * to a function pointer (`-Wpedantic`). The POSIX-blessed idiom is to
 * round-trip through an object-pointer slot, which is bit-identical at
 * the ABI level and accepted by every PKCS#11-relevant platform. We
 * already build with -fno-strict-aliasing so this is safe. */
#define LOAD(h, name, type)                                                  \
    type name;                                                                \
    *(void **)(&name) = dlsym(h, #name);                                      \
    if (!name) { fprintf(stderr, "dlsym %s : %s\n", #name, dlerror()); return 1; }

int main(void) {
    void *h = dlopen(MODULE, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen %s : %s\n", MODULE, dlerror()); return 1; }

    LOAD(h, C_Initialize,        pf_init_t)
    LOAD(h, C_OpenSession,       pf_open_t)
    LOAD(h, C_Login,             pf_login_t)
    LOAD(h, C_GenerateKeyPair,   pf_keypair_t)
    LOAD(h, C_EncapsulateKey,    pf_encap_t)
    LOAD(h, C_DecapsulateKey,    pf_decap_t)
    LOAD(h, C_GetAttributeValue, pf_getattr_t)

    CK_RV rv = C_Initialize(NULL);
    if (rv != CKR_OK) { fprintf(stderr, "C_Initialize : 0x%lx\n", rv); return 1; }

    CK_SESSION_HANDLE session = 0;
    rv = C_OpenSession(0, 1 << 2 /*SERIAL_SESSION*/, NULL, NULL, &session);
    if (rv != CKR_OK) { fprintf(stderr, "C_OpenSession : 0x%lx\n", rv); return 1; }

    rv = C_Login(session, CKU_USER, (unsigned char*)USER_PIN, strlen(USER_PIN));
    if (rv != CKR_OK) { fprintf(stderr, "C_Login : 0x%lx\n", rv); return 1; }

    /* 1. Generate ML-KEM-768 key pair. */
    CK_MECHANISM kpgm = { CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0 };
    char label[] = "mlkem-e2e";
    char extract = 1;   /* mark public extractable */
    CK_ATTRIBUTE pub_tpl[] = {
        { CKA_LABEL,       label,     sizeof(label) - 1 },
        { CKA_EXTRACTABLE, &extract,  1 },
    };
    CK_ATTRIBUTE priv_tpl[] = {
        { CKA_LABEL,       label,     sizeof(label) - 1 },
    };
    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    rv = C_GenerateKeyPair(session, &kpgm,
                            pub_tpl, sizeof(pub_tpl)/sizeof(pub_tpl[0]),
                            priv_tpl, sizeof(priv_tpl)/sizeof(priv_tpl[0]),
                            &hPub, &hPriv);
    if (rv != CKR_OK) { fprintf(stderr, "C_GenerateKeyPair : 0x%lx\n", rv); return 1; }
    printf("[mlkem] keypair handles : pub=%lu priv=%lu\n", hPub, hPriv);

    /* 2. Encapsulate : pubkey → ciphertext + shared secret 1. */
    CK_MECHANISM kemm = { CKM_ML_KEM, NULL, 0 };
    char label_ss1[] = "ml-kem-ss-alice";
    CK_ATTRIBUTE ss_tpl[] = {
        { CKA_LABEL,       label_ss1, sizeof(label_ss1) - 1 },
        { CKA_EXTRACTABLE, &extract,  1 },
    };
    unsigned char ct[2048];     /* ML-KEM-768 ciphertext = 1088 bytes */
    CK_ULONG ct_len = sizeof(ct);
    CK_OBJECT_HANDLE hSS1 = 0;
    rv = C_EncapsulateKey(session, &kemm, hPub,
                           ss_tpl, sizeof(ss_tpl)/sizeof(ss_tpl[0]),
                           &hSS1, ct, &ct_len);
    if (rv != CKR_OK) { fprintf(stderr, "C_EncapsulateKey : 0x%lx\n", rv); return 1; }
    printf("[mlkem] encapsulated : ct_len=%lu, ss_alice handle=%lu\n",
           ct_len, hSS1);

    /* 3. Decapsulate : privkey + ciphertext → shared secret 2. */
    char label_ss2[] = "ml-kem-ss-bob";
    CK_ATTRIBUTE ss_tpl2[] = {
        { CKA_LABEL,       label_ss2, sizeof(label_ss2) - 1 },
        { CKA_EXTRACTABLE, &extract,  1 },
    };
    CK_OBJECT_HANDLE hSS2 = 0;
    rv = C_DecapsulateKey(session, &kemm, hPriv,
                           ss_tpl2, sizeof(ss_tpl2)/sizeof(ss_tpl2[0]),
                           &hSS2, ct, ct_len);
    if (rv != CKR_OK) { fprintf(stderr, "C_DecapsulateKey : 0x%lx\n", rv); return 1; }
    printf("[mlkem] decapsulated : ss_bob handle=%lu\n", hSS2);

    /* 4. Read both secret values and compare. */
    unsigned char ss1[64] = {0}, ss2[64] = {0};
    CK_ATTRIBUTE getv[1] = { { CKA_VALUE, ss1, sizeof(ss1) } };
    rv = C_GetAttributeValue(session, hSS1, getv, 1);
    if (rv != CKR_OK) { fprintf(stderr, "GetAttrValue ss1 : 0x%lx\n", rv); return 1; }
    size_t ss1_len = getv[0].ulValueLen;
    if (ss1_len == (CK_ULONG)-1) {
        fprintf(stderr, "GetAttrValue ss1 : CKA_VALUE blocked (sensitive ?)\n");
        return 1;
    }

    getv[0].pValue = ss2; getv[0].ulValueLen = sizeof(ss2);
    rv = C_GetAttributeValue(session, hSS2, getv, 1);
    if (rv != CKR_OK) { fprintf(stderr, "GetAttrValue ss2 : 0x%lx\n", rv); return 1; }
    size_t ss2_len = getv[0].ulValueLen;
    if (ss2_len == (CK_ULONG)-1) {
        fprintf(stderr, "GetAttrValue ss2 : CKA_VALUE blocked (sensitive ?)\n");
        return 1;
    }

    printf("[mlkem] ss_alice = %zu bytes ; ss_bob = %zu bytes\n", ss1_len, ss2_len);
    if (ss1_len > 0 && ss1_len == ss2_len && memcmp(ss1, ss2, ss1_len) == 0) {
        printf("[mlkem] PASS : ML-KEM-768 shared secrets match\n");
        printf("[mlkem]        Alice and Bob derived the same 32-byte secret\n");
        printf("[mlkem]        through encapsulation+decapsulation\n");
        return 0;
    }
    printf("[mlkem] FAIL : shared secrets DIFFER\n");
    printf("       ss_alice = "); for (size_t i=0;i<ss1_len;i++) printf("%02x", ss1[i]);
    printf("\n       ss_bob   = "); for (size_t i=0;i<ss2_len;i++) printf("%02x", ss2[i]);
    printf("\n");
    return 1;
}
