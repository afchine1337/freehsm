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
 * mldsa_e2e.c --- end-to-end ML-DSA-65 sign/verify test via dlsym.
 *
 *  Exercises the post-quantum signature path : C_GenerateKeyPair
 *  (CKM_ML_DSA_KEY_PAIR_GEN with "ML-DSA-65" parameter set) +
 *  C_SignInit / C_Sign / C_VerifyInit / C_Verify with CKM_ML_DSA_OP.
 *
 *  Scenario :
 *    1. C_Initialize, open session, login as USER
 *    2. C_GenerateKeyPair (ML-DSA-65) → pubkey + privkey handles
 *    3. C_SignInit(privkey, CKM_ML_DSA) + C_Sign(message)
 *       → signature (~3309 bytes for ML-DSA-65)
 *    4. C_VerifyInit(pubkey, CKM_ML_DSA) + C_Verify(message, signature)
 *       → CKR_OK on success
 *
 *  ML-DSA-65 is FIPS 204 approved (August 2024) with NIST security
 *  level 3 (192-bit classical / 128-bit quantum).
 *
 *  Build : cc tests/mldsa_e2e.c -ldl -o tests/mldsa_e2e
 *  Run   : sudo -u freehsm ./tests/mldsa_e2e
 *
 *  Pre-req : slot 0 initialized with USER PIN "user0000".
 * ========================================================================= */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define MODULE      "/opt/freehsm/lib/libfreehsm-fips.so"
#define USER_PIN    "user0000"

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

#define CKM_ML_DSA_KEY_PAIR_GEN  0x0000403EUL
#define CKM_ML_DSA               0x0000403FUL
#define CKA_LABEL                0x00000003UL
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
typedef CK_RV (*pf_signinit_t)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
typedef CK_RV (*pf_sign_t)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG,
                            unsigned char*, CK_ULONG*);
typedef CK_RV (*pf_verifyinit_t)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
typedef CK_RV (*pf_verify_t)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG,
                              unsigned char*, CK_ULONG);

#define LOAD(h, name, type)                                                  \
    type name = (type)dlsym(h, #name);                                       \
    if (!name) { fprintf(stderr, "dlsym %s : %s\n", #name, dlerror()); return 1; }

static double elapsed_sec(struct timespec t0, struct timespec t1) {
    return (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
}

int main(void) {
    void *h = dlopen(MODULE, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen : %s\n", dlerror()); return 1; }

    LOAD(h, C_Initialize,      pf_init_t)
    LOAD(h, C_OpenSession,     pf_open_t)
    LOAD(h, C_Login,           pf_login_t)
    LOAD(h, C_GenerateKeyPair, pf_keypair_t)
    LOAD(h, C_SignInit,        pf_signinit_t)
    LOAD(h, C_Sign,            pf_sign_t)
    LOAD(h, C_VerifyInit,      pf_verifyinit_t)
    LOAD(h, C_Verify,          pf_verify_t)

    CK_RV rv = C_Initialize(NULL);
    if (rv != CKR_OK) { fprintf(stderr, "C_Initialize : 0x%lx\n", rv); return 1; }

    CK_SESSION_HANDLE session = 0;
    rv = C_OpenSession(0, 1 << 2, NULL, NULL, &session);
    if (rv != CKR_OK) { fprintf(stderr, "C_OpenSession : 0x%lx\n", rv); return 1; }

    rv = C_Login(session, CKU_USER, (unsigned char*)USER_PIN, strlen(USER_PIN));
    if (rv != CKR_OK) { fprintf(stderr, "C_Login : 0x%lx\n", rv); return 1; }

    /* 1. Generate ML-DSA-65 key pair. */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    CK_MECHANISM kpgm = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
    char label[] = "mldsa-e2e";
    CK_ATTRIBUTE pub_tpl[] = {
        { CKA_LABEL,       label,    sizeof(label) - 1 },
    };
    CK_ATTRIBUTE priv_tpl[] = {
        { CKA_LABEL,       label,    sizeof(label) - 1 },
    };
    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    rv = C_GenerateKeyPair(session, &kpgm,
                            pub_tpl, sizeof(pub_tpl)/sizeof(pub_tpl[0]),
                            priv_tpl, sizeof(priv_tpl)/sizeof(priv_tpl[0]),
                            &hPub, &hPriv);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rv != CKR_OK) { fprintf(stderr, "C_GenerateKeyPair : 0x%lx\n", rv); return 1; }
    printf("[mldsa] keypair generated in %.2f s (pub=%lu priv=%lu)\n",
           elapsed_sec(t0, t1), hPub, hPriv);

    /* 2. Sign a message. */
    unsigned char msg[] = "post-quantum sign/verify with ML-DSA-65";
    CK_MECHANISM sigm = { CKM_ML_DSA, NULL, 0 };
    rv = C_SignInit(session, &sigm, hPriv);
    if (rv != CKR_OK) { fprintf(stderr, "C_SignInit : 0x%lx\n", rv); return 1; }

    /* Pre-allocate worst-case buffer (8KB ≥ ML-DSA-87 max 4627 bytes). */
    CK_ULONG sig_len = 8192;
    unsigned char *sig = malloc(sig_len);
    if (!sig) { fprintf(stderr, "malloc(%lu)\n", sig_len); return 1; }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    rv = C_Sign(session, msg, sizeof(msg) - 1, sig, &sig_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rv != CKR_OK) { fprintf(stderr, "C_Sign : 0x%lx\n", rv); free(sig); return 1; }
    printf("[mldsa] signed in %.3f s, signature size = %lu bytes\n",
           elapsed_sec(t0, t1), sig_len);

    /* 3. Verify the signature. */
    rv = C_VerifyInit(session, &sigm, hPub);
    if (rv != CKR_OK) { fprintf(stderr, "C_VerifyInit : 0x%lx\n", rv); free(sig); return 1; }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    rv = C_Verify(session, msg, sizeof(msg) - 1, sig, sig_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rv != CKR_OK) {
        fprintf(stderr, "[mldsa] FAIL : verify returned 0x%lx\n", rv);
        free(sig); return 1;
    }
    printf("[mldsa] verified in %.3f s\n", elapsed_sec(t0, t1));

    /* 4. Tamper test : flip one bit, verify should now fail. */
    rv = C_VerifyInit(session, &sigm, hPub);
    if (rv != CKR_OK) { fprintf(stderr, "C_VerifyInit (3) : 0x%lx\n", rv); free(sig); return 1; }
    sig[0] ^= 0x01;
    rv = C_Verify(session, msg, sizeof(msg) - 1, sig, sig_len);
    free(sig);
    if (rv == CKR_OK) {
        fprintf(stderr, "[mldsa] FAIL : tampered signature accepted (should have been rejected)\n");
        return 1;
    }
    printf("[mldsa] tamper test : verify rejected tampered sig (rv=0x%lx)\n", rv);

    printf("[mldsa] PASS : ML-DSA-65 sign + verify + tamper-reject round-trip\n");
    printf("[mldsa]        FIPS 204 approved signature mechanism\n");
    return 0;
}
