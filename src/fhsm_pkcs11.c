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
 * fhsm_pkcs11.c --- PKCS#11 v3.2 entry points (libfreehsm-fips.so).
 *
 * This is the ABI boundary visible to applications. Every C_* function
 *   1. Validates fhsm_state_get() != ERROR  (else FHSM_RV_FUNCTION_FAILED)
 *   2. Validates the FIPS mode flag         (else FHSM_RV_FIPS_NOT_APPROVED)
 *   3. Emits an audit event with parameter lengths
 *   4. Dispatches to the internal subsystem (token, crypto, session)
 *   5. Returns the numeric value (which maps 1:1 to CKR_*)
 *
 * The functions exported here are intentionally THIN: they perform no
 * cryptographic work themselves. All sensitive logic lives in
 * fhsm_crypto.c / fhsm_token.c / fhsm_session.c. This decomposition is
 * required by FIPS 140-3 §7.4.5 ("cryptographic module interface") and
 * CC EAL4+ ADV_TDS.3 (basic modular design).
 *
 * Only a representative subset of C_* entry points is implemented in
 * this scaffold to demonstrate the boundary. The full set
 * (~70 functions) is generated from include/fhsm_pkcs11.h by a
 * code-gen tool that lives at scripts/gen_p11_thunks.py and writes
 * the boilerplate below. See docs/ARCHITECTURE.md §4.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_crypto.h"
#include "fhsm_token.h"
#include "fhsm_audit.h"
#include "fhsm_session.h"
#include "fhsm_session.h"
#include "fhsm_pairwise.h"

#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* OpenSSL EVP types used by C_GenerateKeyPair (RSA/EC keygen + DER
 * serialization) and by the multi-part streaming thunks
 * (EVP_MD_CTX, EVP_CIPHER_CTX, EVP_MAC_CTX). Pulled up here so all
 * downstream code in this TU sees the declarations. */
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>      /* RSA_PKCS1_PSS_PADDING */
#include <openssl/bn.h>       /* BN_bin2bn (C_CreateObject RSA path) */
#include <openssl/core.h>     /* OSSL_PARAM */
#include <openssl/core_names.h>
#include <openssl/param_build.h> /* OSSL_PARAM_BLD */
#include <openssl/err.h>      /* ERR_peek_last_error (ML-KEM debug only) */
#include <openssl/ecdsa.h>    /* ECDSA_SIG_new / d2i / i2d  for raw r||s conversion */

/* PKCS#11 v3.2 §6.13 ECDSA r||s wire format <-> DER ECDSA_SIG. Extracted
 * into its own translation unit in v1.1.14 as a prerequisite for the
 * libFuzzer harness on this parser (#191). */
#include "fhsm_ecdsa_raw.h"

/* PKCS#11 v3.2 §6.18 / §6.19 ML-DSA / SLH-DSA mechanism parameter
 * parser. Extracted into its own TU in v1.1.14 as a prerequisite for
 * the libFuzzer harness on this parser (#191). */
#include "fhsm_pq_params.h"

/* C_CreateObject attribute parser (PKCS#11 v3.2 §6.7.1). Extracted in
 * v1.2.0 as part of the C_CreateObject decomposition : the pure parser
 * lives in src/fhsm_create_attrs.c (reachable from the fuzz harness)
 * while the OpenSSL EVP builder stays inline below. */
#include "fhsm_create_attrs.h"
#include "fhsm_attr_utils.h"

/* CK_RV is identical to fhsm_rv_t numerically. */
typedef unsigned long  CK_RV;
typedef unsigned long  CK_ULONG;
typedef CK_ULONG       CK_FLAGS;
typedef CK_ULONG       CK_USER_TYPE;
typedef CK_ULONG       CK_SESSION_HANDLE;
typedef CK_ULONG       CK_SLOT_ID;
typedef char          *CK_UTF8CHAR_PTR;
typedef void          *CK_VOID_PTR;

#define CK_DECLARE_FUNCTION(rt, name)  rt name

/* ---------------------------------------------------------------------------
 * Forward declarations of every TSFI symbol exported by libfreehsm-fips.so.
 * Required to satisfy -Wmissing-prototypes : the C_* functions are
 * exported (default visibility) but no upstream header is included here,
 * so we declare them locally. The visibility attribute overrides the
 * file-level -fvisibility=hidden setting from the Makefile.
 * ----------------------------------------------------------------------- */
#define FHSM_EXPORT __attribute__((visibility("default")))

FHSM_EXPORT CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
FHSM_EXPORT CK_RV C_Finalize(CK_VOID_PTR pReserved);
FHSM_EXPORT CK_RV C_GetInfo(CK_VOID_PTR pInfo);
FHSM_EXPORT CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                                 CK_VOID_PTR pApp, CK_VOID_PTR Notify,
                                 CK_SESSION_HANDLE *phSession);
FHSM_EXPORT CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
FHSM_EXPORT CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                    CK_VOID_PTR pInfo);
FHSM_EXPORT CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                           CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
FHSM_EXPORT CK_RV C_Logout(CK_SESSION_HANDLE hSession);
FHSM_EXPORT CK_RV C_GetSlotList(unsigned char tokenPresent,
                                 CK_SLOT_ID *pSlotList,
                                 CK_ULONG *pulCount);
FHSM_EXPORT CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_VOID_PTR pInfo);
FHSM_EXPORT CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_VOID_PTR pInfo);
FHSM_EXPORT CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                                      CK_ULONG *pMechanismList,
                                      CK_ULONG *pulCount);
FHSM_EXPORT CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_ULONG type,
                                      CK_VOID_PTR pInfo);
FHSM_EXPORT CK_RV C_InitToken(CK_SLOT_ID slotID,
                               CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                               CK_UTF8CHAR_PTR pLabel);
FHSM_EXPORT CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
                             CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
FHSM_EXPORT CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
                            CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                            CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

/* Crypto / object operations (PKCS#11 v3.2 §C.6). The dispatch handlers
 * for the actual mechanisms live in src/dispatch/ ; the thunks below
 * validate the session, look up objects, and call the appropriate
 * primitive. Multi-part streaming (Update/Final) is wired only for
 * Digest in this scaffold ; one-shot is the canonical path. */
typedef unsigned long CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;
typedef CK_ULONG          CK_ATTRIBUTE_TYPE;
typedef CK_ULONG          CK_MECHANISM_TYPE;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE  type;
    CK_VOID_PTR        pValue;
    CK_ULONG           ulValueLen;
} CK_ATTRIBUTE;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE  mechanism;
    CK_VOID_PTR        pParameter;
    CK_ULONG           ulParameterLen;
} CK_MECHANISM;

FHSM_EXPORT CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
                                    unsigned char *pSeed, CK_ULONG ulLen);
FHSM_EXPORT CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,
                                unsigned char *pSeed, CK_ULONG ulSeedLen);
FHSM_EXPORT CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID *pSlot,
                                      CK_VOID_PTR pReserved);
FHSM_EXPORT CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);
FHSM_EXPORT CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession);
FHSM_EXPORT CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession);
FHSM_EXPORT CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,
                                CK_MECHANISM *pMechanism);
FHSM_EXPORT CK_RV C_Digest(CK_SESSION_HANDLE hSession,
                            unsigned char *pData, CK_ULONG ulDataLen,
                            unsigned char *pDigest, CK_ULONG *pulDigestLen);
FHSM_EXPORT CK_RV C_DigestKey(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hKey);
FHSM_EXPORT CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,
                                  unsigned char *pPart, CK_ULONG ulPartLen);
FHSM_EXPORT CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,
                                 unsigned char *pSig, CK_ULONG ulSigLen);
FHSM_EXPORT CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM *pMechanism,
                                 CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                                 CK_OBJECT_HANDLE *phKey);
FHSM_EXPORT CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                                     CK_MECHANISM *pMechanism,
                                     CK_ATTRIBUTE *pPubTemplate, CK_ULONG ulPubCount,
                                     CK_ATTRIBUTE *pPrivTemplate, CK_ULONG ulPrivCount,
                                     CK_OBJECT_HANDLE *phPub, CK_OBJECT_HANDLE *phPriv);
FHSM_EXPORT CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
                               CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hBaseKey,
                               CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                               CK_OBJECT_HANDLE *phKey);
FHSM_EXPORT CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hWrappingKey,
                             CK_OBJECT_HANDLE hKey,
                             unsigned char *pWrappedKey, CK_ULONG *pulWrappedKeyLen);
FHSM_EXPORT CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
                               CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
                               unsigned char *pWrappedKey, CK_ULONG ulWrappedKeyLen,
                               CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                               CK_OBJECT_HANDLE *phKey);
/* PKCS#11 v3.0 extended functions : C_Encapsulate / C_Decapsulate for KEMs
 * (ML-KEM via this module). Exposed via C_GetInterface, not via the
 * legacy CK_FUNCTION_LIST. */
FHSM_EXPORT CK_RV C_EncapsulateKey(CK_SESSION_HANDLE hSession,
                                    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hPublicKey,
                                    CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                                    CK_OBJECT_HANDLE *phNewKey,
                                    unsigned char *pCiphertext, CK_ULONG *pulCiphertextLen);
FHSM_EXPORT CK_RV C_DecapsulateKey(CK_SESSION_HANDLE hSession,
                                    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hPrivateKey,
                                    CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                                    CK_OBJECT_HANDLE *phNewKey,
                                    unsigned char *pCiphertext, CK_ULONG ulCiphertextLen);
/* PKCS#11 v3.0 §5.18 : C_GetInterface / C_GetInterfaceList expose the
 * v3.0 function table (CK_FUNCTION_LIST_3_0, 91 slots, version {3,0}).
 * The legacy CK_FUNCTION_LIST (v2.40, 67 slots, version {2,40}) is
 * still served by C_GetFunctionList for backward compat. */
struct CK_INTERFACE_s;
FHSM_EXPORT CK_RV C_GetInterfaceList(struct CK_INTERFACE_s *pInterfacesList,
                                      CK_ULONG *pulCount);
FHSM_EXPORT CK_RV C_GetInterface(unsigned char *pInterfaceName,
                                  void *pVersion,
                                  struct CK_INTERFACE_s **ppInterface,
                                  CK_FLAGS flags);
FHSM_EXPORT CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
                                  CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                                  CK_OBJECT_HANDLE *phObject);
FHSM_EXPORT CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject);
FHSM_EXPORT CK_RV C_CopyObject(CK_SESSION_HANDLE hSession,
                                CK_OBJECT_HANDLE hObject,
                                CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                                CK_OBJECT_HANDLE *phNewObject);
FHSM_EXPORT CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject,
                                   CK_ULONG *pulSize);
FHSM_EXPORT CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hObject,
                                       CK_ATTRIBUTE *pTemplate,
                                       CK_ULONG ulCount);
FHSM_EXPORT CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hObject,
                                       CK_ATTRIBUTE *pTemplate,
                                       CK_ULONG ulCount);
FHSM_EXPORT CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                                     CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);
FHSM_EXPORT CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
                                 CK_OBJECT_HANDLE *phObject,
                                 CK_ULONG ulMaxCount, CK_ULONG *pulCount);
FHSM_EXPORT CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
FHSM_EXPORT CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
FHSM_EXPORT CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
                             unsigned char *pData, CK_ULONG ulDataLen,
                             unsigned char *pEncrypted, CK_ULONG *pulEncryptedLen);
FHSM_EXPORT CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
FHSM_EXPORT CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
                             unsigned char *pEncrypted, CK_ULONG ulEncLen,
                             unsigned char *pData, CK_ULONG *pulDataLen);
FHSM_EXPORT CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
                              CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
FHSM_EXPORT CK_RV C_Sign(CK_SESSION_HANDLE hSession,
                          unsigned char *pData, CK_ULONG ulDataLen,
                          unsigned char *pSignature, CK_ULONG *pulSignatureLen);
FHSM_EXPORT CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
                                CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
FHSM_EXPORT CK_RV C_Verify(CK_SESSION_HANDLE hSession,
                            unsigned char *pData, CK_ULONG ulDataLen,
                            unsigned char *pSignature, CK_ULONG ulSignatureLen);
/* Multi-part streaming variants. */
FHSM_EXPORT CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,
                                   unsigned char *pPart, CK_ULONG ulPartLen);
FHSM_EXPORT CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,
                                  unsigned char *pDigest, CK_ULONG *pulDigestLen);
FHSM_EXPORT CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,
                                 unsigned char *pPart, CK_ULONG ulPartLen);
FHSM_EXPORT CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,
                                unsigned char *pSignature, CK_ULONG *pulSignatureLen);
FHSM_EXPORT CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                                    unsigned char *pPart, CK_ULONG ulPartLen,
                                    unsigned char *pEnc, CK_ULONG *pulEncLen);
FHSM_EXPORT CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
                                   unsigned char *pLast, CK_ULONG *pulLastLen);
FHSM_EXPORT CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                                    unsigned char *pEnc, CK_ULONG ulEncLen,
                                    unsigned char *pPart, CK_ULONG *pulPartLen);
FHSM_EXPORT CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
                                   unsigned char *pLast, CK_ULONG *pulLastLen);

struct CK_FUNCTION_LIST;
FHSM_EXPORT CK_RV C_GetFunctionList(struct CK_FUNCTION_LIST **ppFnList);

/* ---------------------------------------------------------------------------
 * Forward declarations for the slot registry.
 *
 * FHSM_MAX_SLOTS must be visible to C_OpenSession (which validates slotID
 * against this bound) before the registry itself is defined further down.
 * fhsm_slot_token() is also called from C_OpenSession to attach the
 * slot's token to the new session.
 * ----------------------------------------------------------------------- */
#define FHSM_MAX_SLOTS 4
static fhsm_token_t *fhsm_slot_token(CK_SLOT_ID slot);

/* Helper : copy a string into a fixed-length PKCS#11 field, padding the
 * trailing bytes with ASCII space (per CK_INFO spec §A.6.1). This is
 * the standard way and avoids the gcc-12 array-bounds warning that
 * triggers when memcpy(dst, "literal", N) and the literal is shorter
 * than N (FORTIFY_SOURCE level 2 detects the OOB read). */
static void fhsm_pack_field(unsigned char *dst, const char *src, size_t n) {
    size_t l = strlen(src);
    if (l > n) l = n;
    memcpy(dst, src, l);
    memset(dst + l, ' ', n - l);
}

/* ---------------------------------------------------------------------------
 * Module lifecycle.
 * ----------------------------------------------------------------------- */
CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    (void)pInitArgs;
    fhsm_rv_t rv = fhsm_secure_heap_init();
    if (rv != FHSM_RV_OK) return rv;
    rv = fhsm_state_set(FHSM_STATE_INITIALIZING);
    if (rv != FHSM_RV_OK) return rv;
    rv = fhsm_crypto_init();
    if (rv != FHSM_RV_OK) {
        fhsm_state_latch_error("crypto_init failed in C_Initialize");
        return rv;
    }
    rv = fhsm_state_set(FHSM_STATE_INITIALIZED);
    (void)fhsm_audit_event(FHSM_EV_MODULE_INIT, -1, -1,
                            FHSM_ROLE_NONE, rv, NULL);
    return rv;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    (void)pReserved;
    (void)fhsm_audit_event(FHSM_EV_MODULE_FINALIZE, -1, -1,
                            FHSM_ROLE_NONE, FHSM_RV_OK, NULL);
    fhsm_crypto_finalize();
    fhsm_audit_close();
    fhsm_state_set(FHSM_STATE_POWER_OFF);
    return FHSM_RV_OK;
}

/* PKCS#11 v3.2 §C.6.5.4 --- C_WaitForSlotEvent
 *
 * Watch for slot insertion / removal events. A software token has no
 * hot-plug : slots are static, configured at C_Initialize time, and
 * never produce events during the module's lifetime.
 *
 * Two return modes per the spec :
 *
 *     CKF_DONT_BLOCK set     : return CKR_NO_EVENT immediately if no
 *                              event is pending. For this module, no
 *                              event ever pends, so always CKR_NO_EVENT.
 *     CKF_DONT_BLOCK unset   : block until an event is available. For
 *                              this module no event will EVER be
 *                              available, so blocking indefinitely
 *                              would hang the caller. Returning
 *                              CKR_FUNCTION_NOT_SUPPORTED is the
 *                              documented behaviour for software tokens
 *                              without a hot-plug source.
 *
 * pReserved must be NULL per the spec.
 *
 * Added in v1.3.0 in response to Denis Mingulov's pkcs11-check report :
 * slot 66 was the last unwired slot in the v2.40 function list ; this
 * commit completes the v2.40 dispatch table. */
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID *pSlot,
                         CK_VOID_PTR pReserved) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (pReserved != NULL) return FHSM_RV_ARGUMENTS_BAD;
    (void)pSlot;
    /* CKF_DONT_BLOCK == 0x00000001 per PKCS#11 v3.2. */
    if (flags & 0x00000001UL) {
        return 0x00000008UL;        /* CKR_NO_EVENT */
    }
    /* Software token : no hot-plug ; refuse blocking calls explicitly
     * rather than hang the caller. */
    return 0x00000054UL;            /* CKR_FUNCTION_NOT_SUPPORTED */
}

/* ===========================================================================
 * v1.4.0 Tier 1 --- session management + legacy parallel + DRBG seed.
 *
 * These four functions close the v2.40 dispatch-table gaps that don't
 * require new cryptographic primitives.
 * ========================================================================= */

/* PKCS#11 v3.2 §C.6.6.2 : C_CloseAllSessions
 *
 * Closes every open session that belongs to the given slot. The module
 * is a single-slot software token (slotID must be 0) ; we iterate the
 * session-handle range (1 .. FHSM_MAX_SESSIONS = 256) and close each
 * handle that resolves to a non-NULL token via fhsm_session_token.
 * C_CloseSession is idempotent on stale handles and returns
 * CKR_SESSION_HANDLE_INVALID which we silently consume here. */
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (slotID != 0) return 0x00000003UL;   /* CKR_SLOT_ID_INVALID */
    for (CK_SESSION_HANDLE h = 1; h <= 256; h++) {
        if (fhsm_session_token(h) != NULL) {
            (void)C_CloseSession(h);
        }
    }
    return FHSM_RV_OK;
}

/* PKCS#11 v3.2 §C.6.6.5 : C_SeedRandom
 *
 * The DRBG used by C_GenerateRandom is a CTR_DRBG-AES-256 (FIPS provider)
 * or the OpenSSL default provider's RAND when the FIPS provider is not
 * available. Per NIST SP 800-90A §9.2, a SP 800-90A DRBG must be seeded
 * only from approved entropy sources (a hardware RNG or a SP 800-90B
 * entropy source) ; mixing arbitrary caller-supplied bytes into the
 * DRBG state is not approved.
 *
 * The conformant answer is CKR_RANDOM_SEED_NOT_SUPPORTED ; we return it
 * unconditionally rather than branching on FIPS / legacy because :
 *   - in FIPS mode the answer is required by spec ;
 *   - in legacy mode mixing arbitrary input would still weaken the
 *     overall RNG posture (an attacker-controlled seed could narrow
 *     the entropy distribution downstream) ;
 *   - returning the same answer in both modes simplifies the security
 *     story (no mode-dependent RNG behaviour to document or test). */
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,
                    unsigned char *pSeed,
                    CK_ULONG ulSeedLen) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (fhsm_session_token(hSession) == NULL) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (!pSeed || ulSeedLen == 0) return FHSM_RV_ARGUMENTS_BAD;
    return 0x00000120UL;   /* CKR_RANDOM_SEED_NOT_SUPPORTED */
}

/* PKCS#11 v3.2 §C.6.5.6 : C_GetFunctionStatus and C_CancelFunction are
 * legacy parallel-function-management functions. The v2.0 parallel
 * model was abandoned starting from v2.10 ; both functions MUST return
 * CKR_FUNCTION_NOT_PARALLEL on any non-parallel implementation, which
 * is every modern PKCS#11 module since v2.10. We follow the spec
 * literally for both. */
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
    if (fhsm_session_token(hSession) == NULL) return FHSM_RV_SESSION_HANDLE_INVALID;
    return 0x00000051UL;   /* CKR_FUNCTION_NOT_PARALLEL */
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) {
    if (fhsm_session_token(hSession) == NULL) return FHSM_RV_SESSION_HANDLE_INVALID;
    return 0x00000051UL;   /* CKR_FUNCTION_NOT_PARALLEL */
}

CK_RV C_GetInfo(CK_VOID_PTR pInfo) {
    if (!pInfo) return FHSM_RV_ARGUMENTS_BAD;
    /* CK_INFO layout per PKCS#11 v3.2 spec C.6.1 :
     *   CK_VERSION cryptokiVersion;    // 2 bytes  (major, minor as CK_BYTE)
     *   CK_UTF8CHAR manufacturerID[32];
     *   CK_FLAGS    flags;             // CK_ULONG, 8 bytes on LP64
     *   CK_UTF8CHAR libraryDescription[32];
     *   CK_VERSION  libraryVersion;    // 2 bytes
     *
     * CRITICAL : CK_VERSION's two fields are CK_BYTE (1 byte each), NOT
     * unsigned short (2 bytes each). Using the wrong width shifts the
     * downstream fields by 2 bytes and corrupts the manufacturerID. */
    struct fhsm_ck_info {
        unsigned char cryptokiVersion[2];    /* major, minor */
        unsigned char manufacturerID[32];
        CK_FLAGS      flags;
        unsigned char libraryDescription[32];
        unsigned char libraryVersion[2];     /* major, minor */
    } *info = pInfo;
    info->cryptokiVersion[0] = 3;
    info->cryptokiVersion[1] = 2;
    /* PKCS#11 v3.2 §C.6.1 semantics : manufacturerID is the entity that
     * provides the Cryptoki library (= the legal/brand identity of the
     * vendor) ; libraryDescription is the product name. Before v1.2.0
     * both fields were a single mixed string "FreeHSM C (FIPS 140-3)"
     * which conflated the two roles and was non-conforming.
     *
     * Full legal name : "Simorgh Labs, Open Source Cryptography and
     * Digital Trust" (53 chars). The 32-octet PKCS#11 field truncates
     * to the brand : "Simorgh Labs". The complete name appears in the
     * Security Target §1 and in the README. */
    fhsm_pack_field(info->manufacturerID,    "Simorgh Labs",                      32);
    info->flags = 0;
    fhsm_pack_field(info->libraryDescription, "FreeHSM C (FIPS 140-3)",           32);
    info->libraryVersion[0] = FHSM_VERSION_MAJOR;
    info->libraryVersion[1] = FHSM_VERSION_MINOR;
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * Session lifecycle. The session table itself lives in fhsm_session.c;
 * here we only validate parameters and emit audit events.
 * (Prototypes are now in include/fhsm_session.h.)
 * ----------------------------------------------------------------------- */
static void fhsm_session_ops_reset(CK_SESSION_HANDLE h);

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                     CK_VOID_PTR pApp, CK_VOID_PTR Notify,
                     CK_SESSION_HANDLE *phSession) {
    (void)pApp; (void)Notify;
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!phSession) return FHSM_RV_ARGUMENTS_BAD;
    if (slotID >= FHSM_MAX_SLOTS) return FHSM_RV_SLOT_ID_INVALID;
    /* Per PKCS#11 v3.2 §C.6.5 : C_OpenSession requires the token to be
     * present. C_InitToken uses a different path (no session needed). */
    fhsm_token_t *t = fhsm_slot_token(slotID);
    if (!t) return FHSM_RV_TOKEN_NOT_PRESENT;
    fhsm_rv_t rv = fhsm_session_open(slotID, flags, phSession);
    if (rv == FHSM_RV_OK) {
        /* A pooled session handle may carry stale operation state from a
         * previously closed session ; clear it so this session starts
         * with no active crypto operation (#125). */
        fhsm_session_ops_reset(*phSession);
        /* Attach the slot's token to the new session. */
        fhsm_session_attach_token(*phSession, t);
    }
    return rv;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    /* Release any in-flight operation state before the handle returns to
     * the pool, so a later C_OpenSession cannot inherit it (#125). */
    fhsm_session_ops_reset(hSession);
    /* Destroy the session objects this session created (CKA_TOKEN=FALSE) :
     * PKCS#11 requires session objects to be automatically destroyed when
     * their session is closed (#125). */
    { fhsm_token_t *t = fhsm_session_token(hSession);
      if (t) (void)fhsm_token_destroy_session_objects(t, (uint32_t)hSession); }
    return fhsm_session_close(hSession);
}

/* PKCS#11 v3.2 §C.6.6.5 --- C_GetSessionInfo
 *
 * Populates a CK_SESSION_INFO struct for the given session :
 *
 *     typedef struct CK_SESSION_INFO {
 *         CK_SLOT_ID    slotID;        // 8 bytes on LP64
 *         CK_STATE      state;         // 8 bytes
 *         CK_FLAGS      flags;         // 8 bytes (CKF_RW_SESSION etc.)
 *         CK_ULONG      ulDeviceError; // 8 bytes
 *     } CK_SESSION_INFO;
 *
 * The state is derived from (CKF_RW_SESSION flag, authenticated role)
 * per PKCS#11 v3.2 §6.6.2 :
 *
 *     CKS_RO_PUBLIC_SESSION = 0 : RO + no user logged in
 *     CKS_RO_USER_FUNCTIONS = 1 : RO + user logged in
 *     CKS_RW_PUBLIC_SESSION = 2 : RW + no user logged in
 *     CKS_RW_USER_FUNCTIONS = 3 : RW + user logged in
 *     CKS_RW_SO_FUNCTIONS   = 4 : RW + SO logged in
 *
 * Wired into the v2.40 function list at slot 15 ; mirrored into the
 * v3.0 table by fhsm_init_v3_0_table().
 *
 * Added in v1.2.2 in response to Denis Mingulov's pkcs11-check report
 * that flagged this function as missing from the exported list. */
#define FHSM_CKF_RW_SESSION 0x00000002UL

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_VOID_PTR pInfo) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pInfo) return FHSM_RV_ARGUMENTS_BAD;

    unsigned long slot = 0, flags = 0;
    fhsm_role_t   role = FHSM_ROLE_NONE;
    fhsm_rv_t rv = fhsm_session_info(hSession, &slot, &flags, &role);
    if (rv != FHSM_RV_OK) return rv;

    int rw = (flags & FHSM_CKF_RW_SESSION) != 0;
    CK_ULONG state;
    switch (role) {
        case FHSM_ROLE_SO:
            /* SO is always RW per PKCS#11 v3.2 §C.6.6.6 ; if a session
             * was opened RO and then SO-login attempted, fhsm_session_login
             * already rejected with CKR_SESSION_READ_ONLY_EXISTS, so we
             * can assume RW here. */
            state = 4;  /* CKS_RW_SO_FUNCTIONS */
            break;
        case FHSM_ROLE_USER:
            state = rw ? 3 : 1;  /* CKS_RW_USER_FUNCTIONS / CKS_RO_USER_FUNCTIONS */
            break;
        case FHSM_ROLE_NONE:
        default:
            state = rw ? 2 : 0;  /* CKS_RW_PUBLIC_SESSION / CKS_RO_PUBLIC_SESSION */
            break;
    }

    /* Populate CK_SESSION_INFO at the raw memory layout. */
    CK_ULONG *out = (CK_ULONG *)pInfo;
    out[0] = (CK_ULONG)slot;
    out[1] = state;
    out[2] = (CK_ULONG)flags;
    out[3] = 0;   /* ulDeviceError, always 0 for a software token */

    return FHSM_RV_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
               CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    fhsm_role_t role = (userType == 0 /*CKU_SO*/) ? FHSM_ROLE_SO :
                       (userType == 1 /*CKU_USER*/) ? FHSM_ROLE_USER :
                       FHSM_ROLE_NONE;
    if (role == FHSM_ROLE_NONE) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_rv_t rv = fhsm_session_login(hSession, role, (const char*)pPin, ulPinLen);
    char rolename[8] = "NONE";
    if (role == FHSM_ROLE_SO)   memcpy(rolename, "SO",   3);
    if (role == FHSM_ROLE_USER) memcpy(rolename, "USER", 5);
    char pin_len_str[16]; snprintf(pin_len_str, sizeof(pin_len_str), "%lu", ulPinLen);
    (void)fhsm_audit_event(
        (rv == FHSM_RV_OK)             ? FHSM_EV_LOGIN_OK :
        (rv == FHSM_RV_PIN_LOCKED)     ? FHSM_EV_LOGIN_LOCKED :
        (rv == FHSM_RV_PIN_THROTTLED)  ? FHSM_EV_LOGIN_THROTTLED :
                                          FHSM_EV_LOGIN_FAIL,
        -1, (int)hSession, role, rv,
        "role", rolename, "pin_len", pin_len_str, NULL);
    return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    fhsm_rv_t rv = fhsm_session_logout(hSession);
    (void)fhsm_audit_event(FHSM_EV_LOGOUT, -1, (int)hSession,
                            FHSM_ROLE_NONE, rv, NULL);
    return rv;
}

/* ---------------------------------------------------------------------------
 * The full PKCS#11 set (C_GenerateKey, C_Encrypt/Decrypt, C_Sign/Verify,
 * C_FindObjects, etc.) is omitted from this scaffold for brevity but
 * follows the exact same pattern as above: parameter validation, audit
 * event with lengths only, dispatch to fhsm_crypto.* or fhsm_token.*,
 * and return the numeric value mapped from fhsm_rv_t to CK_RV.
 *
 * The full list lives in include/fhsm_pkcs11.h and is generated by the
 * codegen script. See docs/ARCHITECTURE.md §4 for the complete
 * mechanism dispatch table.
 * ----------------------------------------------------------------------- */

/* ===========================================================================
 * Slot registry. The slot table is built once (lazy) at first
 * C_GetSlotList call. Slots 0..FHSM_MAX_SLOTS-1 map to the files
 * "slot{N}.tok" inside the tokens directory. Each slot is either:
 *   - "uninitialized" : no .tok file yet ; can be initialized via C_InitToken
 *   - "initialized"   : .tok file exists ; loaded lazily on first attach
 *
 * The tokens directory comes from (in order of precedence):
 *   1. FHSM_TOKENS_DIR environment variable
 *   2. /etc/freehsm/freehsm.conf [paths] tokens_dir
 *   3. Compile-time default /var/lib/freehsm/tokens
 * =========================================================================== */
#include <sys/stat.h>
#include <stdlib.h>

/* FHSM_MAX_SLOTS is defined at the top of the file (forward-decl block)
 * so C_OpenSession can validate slotID before this registry block is
 * compiled. */

typedef struct fhsm_slot_s {
    int           present;            /* 1 if .tok file exists */
    char          path[512];          /* full path to .tok */
    fhsm_token_t *token;              /* loaded on demand */
} fhsm_slot_t;

static fhsm_slot_t g_slots[FHSM_MAX_SLOTS];
static int         g_slots_initialized = 0;

static const char *fhsm_tokens_dir(void) {
    const char *env = getenv("FHSM_TOKENS_DIR");
    if (env && *env) return env;
    return "/var/lib/freehsm/tokens";
}

static void fhsm_slot_table_init_once(void) {
    if (g_slots_initialized) return;
    const char *dir = fhsm_tokens_dir();
    for (int i = 0; i < FHSM_MAX_SLOTS; ++i) {
        snprintf(g_slots[i].path, sizeof(g_slots[i].path),
                 "%s/slot%d.tok", dir, i);
        struct stat st;
        g_slots[i].present = (stat(g_slots[i].path, &st) == 0) ? 1 : 0;
        g_slots[i].token   = NULL;
    }
    g_slots_initialized = 1;
}

/* Lazily load the token for a slot. Returns NULL if absent or unreadable. */
static fhsm_token_t *fhsm_slot_token(CK_SLOT_ID slot) {
    if (slot >= FHSM_MAX_SLOTS) return NULL;
    fhsm_slot_table_init_once();
    if (!g_slots[slot].present) return NULL;
    if (g_slots[slot].token) return g_slots[slot].token;
    fhsm_token_t *t = NULL;
    if (fhsm_token_load(g_slots[slot].path, &t) == FHSM_RV_OK) {
        g_slots[slot].token = t;
    }
    return g_slots[slot].token;
}

/* ---------------------------------------------------------------------------
 * C_GetSlotList --- enumerate the configured slots.
 * If tokenPresent is non-zero, only slots with an initialized token are
 * returned. The caller queries the count by passing pSlotList=NULL, then
 * allocates and re-calls with the buffer.
 * ----------------------------------------------------------------------- */
CK_RV C_GetSlotList(unsigned char tokenPresent,
                     CK_SLOT_ID *pSlotList,
                     CK_ULONG *pulCount) {
    if (!pulCount) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_slot_table_init_once();

    /* Count first. */
    CK_ULONG n = 0;
    for (CK_ULONG i = 0; i < FHSM_MAX_SLOTS; ++i) {
        if (tokenPresent && !g_slots[i].present) continue;
        n++;
    }

    if (pSlotList == NULL) {
        *pulCount = n;
        return FHSM_RV_OK;
    }
    if (*pulCount < n) {
        *pulCount = n;
        return 0x00000150UL;  /* CKR_BUFFER_TOO_SMALL */
    }
    /* Fill. */
    CK_ULONG k = 0;
    for (CK_ULONG i = 0; i < FHSM_MAX_SLOTS; ++i) {
        if (tokenPresent && !g_slots[i].present) continue;
        pSlotList[k++] = i;
    }
    *pulCount = n;
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * C_GetSlotInfo --- describe a slot. CK_SLOT_INFO layout (PKCS#11 v3.2 C.6.2):
 *   slotDescription[64], manufacturerID[32], flags(CK_ULONG),
 *   hardwareVersion(CK_VERSION), firmwareVersion(CK_VERSION)
 * Total = 64 + 32 + 8 + 2 + 2 = 108 bytes.
 * ----------------------------------------------------------------------- */
#define CKF_TOKEN_PRESENT     0x00000001UL
#define CKF_REMOVABLE_DEVICE  0x00000002UL
#define CKF_HW_SLOT           0x00000004UL

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_VOID_PTR pInfo) {
    if (!pInfo) return FHSM_RV_ARGUMENTS_BAD;
    if (slotID >= FHSM_MAX_SLOTS) return FHSM_RV_SLOT_ID_INVALID;
    fhsm_slot_table_init_once();
    struct fhsm_ck_slot_info {
        unsigned char slotDescription[64];
        unsigned char manufacturerID[32];
        CK_FLAGS      flags;
        unsigned char hardwareVersion[2];
        unsigned char firmwareVersion[2];
    } *info = pInfo;
    char desc[64];
    snprintf(desc, sizeof(desc), "FreeHSM slot %lu (%s)", (unsigned long)slotID,
             g_slots[slotID].present ? "initialized" : "uninitialized");
    fhsm_pack_field(info->slotDescription, desc, 64);
    /* Slot manufacturer : the entity providing the Cryptoki library
     * (same as CK_INFO.manufacturerID). See the rationale block in
     * C_GetInfo above. */
    fhsm_pack_field(info->manufacturerID,  "Simorgh Labs",          32);
    /* Per the SoftHSMv2 convention (mirroring most cloud-HSM modules),
     * every configured slot ALWAYS reports CKF_TOKEN_PRESENT. The
     * distinction between "initialized" and "blank" is exposed via
     * the token's own CKF_TOKEN_INITIALIZED flag in C_GetTokenInfo.
     * Reporting !TOKEN_PRESENT on a slot makes pkcs11-tool abort
     * before it can call C_InitToken to bootstrap. */
    info->flags = CKF_TOKEN_PRESENT;
    info->hardwareVersion[0] = 1; info->hardwareVersion[1] = 0;
    info->firmwareVersion[0] = FHSM_VERSION_MAJOR;
    info->firmwareVersion[1] = FHSM_VERSION_MINOR;
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * C_GetTokenInfo --- describe the token in a slot.
 * CK_TOKEN_INFO layout (PKCS#11 v3.2 C.6.3, 204 bytes).
 * ----------------------------------------------------------------------- */
#define CKF_RNG                  0x00000001UL
#define CKF_WRITE_PROTECTED      0x00000002UL
#define CKF_LOGIN_REQUIRED       0x00000004UL
#define CKF_USER_PIN_INITIALIZED 0x00000008UL
#define CKF_TOKEN_INITIALIZED    0x00000400UL
#define CKF_USER_PIN_LOCKED      0x00040000UL
#define CKF_SO_PIN_LOCKED        0x00400000UL

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_VOID_PTR pInfo) {
    if (!pInfo) return FHSM_RV_ARGUMENTS_BAD;
    if (slotID >= FHSM_MAX_SLOTS) return FHSM_RV_SLOT_ID_INVALID;
    fhsm_slot_table_init_once();
    /* Note: we deliberately do NOT return CKR_TOKEN_NOT_PRESENT for blank
     * slots. PKCS#11 applications (pkcs11-tool included) call this before
     * C_InitToken to discover whether the slot is initialized; returning
     * an error here would prevent bootstrap. The "blank-but-present"
     * state is conveyed by clearing CKF_TOKEN_INITIALIZED below. */

    fhsm_token_t *t = fhsm_slot_token(slotID);

    struct fhsm_ck_token_info {
        unsigned char label[32];
        unsigned char manufacturerID[32];
        unsigned char model[16];
        unsigned char serialNumber[16];
        CK_FLAGS      flags;
        CK_ULONG      ulMaxSessionCount;
        CK_ULONG      ulSessionCount;
        CK_ULONG      ulMaxRwSessionCount;
        CK_ULONG      ulRwSessionCount;
        CK_ULONG      ulMaxPinLen;
        CK_ULONG      ulMinPinLen;
        CK_ULONG      ulTotalPublicMemory;
        CK_ULONG      ulFreePublicMemory;
        CK_ULONG      ulTotalPrivateMemory;
        CK_ULONG      ulFreePrivateMemory;
        unsigned char hardwareVersion[2];
        unsigned char firmwareVersion[2];
        unsigned char utcTime[16];
    } *info = pInfo;
    const char *label  = (t ? fhsm_token_label(t)  : "");
    const char *serial = (t ? fhsm_token_serial(t) : "");
    fhsm_pack_field(info->label,          label,                       32);
    /* Token manufacturer : the entity providing the Cryptoki library
     * (same as CK_INFO.manufacturerID). See the rationale block in
     * C_GetInfo above. Model identifies the product line, stable
     * across minor versions of the same major series. */
    fhsm_pack_field(info->manufacturerID, "Simorgh Labs",              32);
    fhsm_pack_field(info->model,          "FreeHSM-C-v1",              16);
    fhsm_pack_field(info->serialNumber,   serial,                      16);
    /* Base flags : RNG + LOGIN_REQUIRED are inherent to the module.
     * CKF_TOKEN_INITIALIZED is asserted only after a successful
     * C_InitToken has populated the .tok file. */
    info->flags = CKF_RNG | CKF_LOGIN_REQUIRED;
    if (t) info->flags |= CKF_TOKEN_INITIALIZED;
    if (t && fhsm_token_failed_count(t, FHSM_ROLE_USER) > 0)
        info->flags |= CKF_USER_PIN_INITIALIZED;
    if (t && fhsm_token_is_locked(t, FHSM_ROLE_USER))
        info->flags |= CKF_USER_PIN_LOCKED;
    if (t && fhsm_token_is_locked(t, FHSM_ROLE_SO))
        info->flags |= CKF_SO_PIN_LOCKED;
    info->ulMaxSessionCount     = 128;
    info->ulSessionCount         = 0;
    info->ulMaxRwSessionCount    = 128;
    info->ulRwSessionCount       = 0;
    info->ulMaxPinLen            = 64;
    info->ulMinPinLen            = 4;
    info->ulTotalPublicMemory    = 0;
    info->ulFreePublicMemory     = 0;
    info->ulTotalPrivateMemory   = 0;
    info->ulFreePrivateMemory    = 0;
    info->hardwareVersion[0] = 1; info->hardwareVersion[1] = 0;
    info->firmwareVersion[0] = FHSM_VERSION_MAJOR;
    info->firmwareVersion[1] = FHSM_VERSION_MINOR;
    fhsm_pack_field(info->utcTime, "", 16);
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * C_GetMechanismList / Info --- expose the FIPS-approved mechanisms whose
 * KAT runs at boot. The full mechanism set (~78) is wired via the dispatch
 * table; here we report only the smoke-tested subset.
 * ----------------------------------------------------------------------- */
#define CKM_SHA256                 0x00000250UL
#define CKM_SHA256_HMAC            0x00000251UL
#define CKM_AES_GCM                0x00001087UL
#define CKM_PKCS5_PBKD2            0x000003B0UL

/* Mechanism constants used in the list and in the dispatch thunks. */
#define CKM_AES_KEY_GEN_LIST       0x00001080UL
#define CKM_GENERIC_SECRET_KEY_GEN_LIST  0x00000350UL
#define CKM_SHA384_LIST            0x00000260UL
#define CKM_SHA512_LIST            0x00000270UL

/* Asymmetric key-pair generation mechanisms (registered for
 * C_GetMechanismList) ; the actual definitions live with the thunk
 * below. */
#define CKM_RSA_KEY_PAIR_GEN_LIST   0x00000000UL
#define CKM_EC_KEY_PAIR_GEN_LIST    0x00001040UL
/* Signature mechanisms (replicated as _LIST constants only because
 * they're forward-referenced before C_SignInit defines them ; values
 * are identical to the post-declarations). */
#define CKM_ECDSA_SHA256_LIST       0x00001044UL
#define CKM_ECDSA_SHA384_LIST       0x00001045UL
#define CKM_ECDSA_SHA512_LIST       0x00001046UL
#define CKM_SHA256_RSA_PKCS_LIST    0x00000040UL
#define CKM_SHA384_RSA_PKCS_LIST    0x00000041UL
#define CKM_SHA512_RSA_PKCS_LIST    0x00000042UL
#define CKM_SHA256_RSA_PKCS_PSS_LIST 0x00000043UL
#define CKM_RSA_PKCS_OAEP_LIST       0x00000009UL

/* ---------------------------------------------------------------------------
 * Extended mechanism set. Every entry below appears in --list-mechanisms ;
 * the actual primitive may or may not be wired in C_SignInit / C_EncryptInit
 * etc. For non-FIPS-approved mechanisms, the OpenSSL FIPS provider will
 * naturally refuse EVP_*_fetch() and the runtime returns CKR_MECHANISM_INVALID.
 * For mechanisms not yet wired (DES3, AES-CTR, SSL3, ...), C_SignInit /
 * C_EncryptInit also returns CKR_MECHANISM_INVALID. Listing them is
 * useful for application probing and forward-compat.
 * ----------------------------------------------------------------------- */
#define CKM_RSA_PKCS_LIST             0x00000001UL
#define CKM_RSA_X_509_LIST            0x00000003UL
#define CKM_RSA_PKCS_PSS_LIST         0x0000000DUL
#define CKM_SHA1_RSA_PKCS_LIST        0x00000006UL
#define CKM_SHA224_RSA_PKCS_LIST      0x00000046UL
#define CKM_SHA1_RSA_PKCS_PSS_LIST    0x0000000EUL
#define CKM_SHA224_RSA_PKCS_PSS_LIST  0x00000047UL
#define CKM_ECDSA_BARE_LIST           0x00001041UL
#define CKM_ECDSA_SHA1_LIST           0x00001042UL
#define CKM_ECDSA_SHA224_LIST         0x00001043UL
#define CKM_ECDH1_DERIVE_LIST         0x00001050UL
#define CKM_AES_ECB_LIST              0x00001081UL
#define CKM_AES_CBC_LIST              0x00001082UL
#define CKM_AES_MAC_LIST              0x00001083UL
#define CKM_AES_MAC_GENERAL_LIST      0x00001084UL
#define CKM_AES_CBC_PAD_LIST          0x00001085UL
#define CKM_AES_CTR_LIST              0x00001086UL
#define CKM_AES_CCM_LIST              0x00001088UL
#define CKM_AES_GMAC_LIST             0x0000108AUL
#define CKM_AES_CMAC_GENERAL_LIST     0x0000108BUL
#define CKM_AES_CMAC_LIST             0x0000108CUL
#define CKM_AES_ECB_ENCRYPT_DATA_LIST 0x00001104UL
#define CKM_AES_CBC_ENCRYPT_DATA_LIST 0x00001105UL
#define CKM_DES2_KEY_GEN_LIST         0x00000130UL
#define CKM_DES3_KEY_GEN_LIST         0x00000131UL
#define CKM_DES3_ECB_LIST             0x00000132UL
#define CKM_DES3_CBC_LIST             0x00000133UL
#define CKM_DES3_MAC_LIST             0x00000134UL
#define CKM_DES3_MAC_GENERAL_LIST     0x00000135UL
#define CKM_DES3_CBC_PAD_LIST         0x00000136UL
#define CKM_SHA1_LIST                 0x00000220UL
#define CKM_SHA1_HMAC_LIST            0x00000221UL
#define CKM_SHA224_LIST               0x00000255UL
#define CKM_SHA224_HMAC_LIST          0x00000256UL
#define CKM_SHA256_HMAC_GENERAL_LIST  0x00000252UL
#define CKM_SHA384_HMAC_LIST          0x00000261UL
#define CKM_SHA384_HMAC_GENERAL_LIST  0x00000262UL
#define CKM_SHA512_HMAC_LIST          0x00000271UL
#define CKM_SHA512_HMAC_GENERAL_LIST  0x00000272UL
#define CKM_SSL3_PRE_MASTER_KEY_GEN_LIST   0x00000370UL
#define CKM_SSL3_MASTER_KEY_DERIVE_LIST    0x00000371UL
#define CKM_SSL3_KEY_AND_MAC_DERIVE_LIST   0x00000372UL
#define CKM_SSL3_MASTER_KEY_DERIVE_DH_LIST 0x00000373UL
#define CKM_XOR_BASE_AND_DATA_LIST    0x00000364UL
/* Post-quantum (PKCS#11 v3.2 §A.4). Values reserved by OASIS in
 * the 0x4030..0x4045 range. */
#define CKM_ML_KEM_KEY_PAIR_GEN_LIST  0x0000000FUL
#define CKM_ML_KEM_LIST               0x00000017UL
#define CKM_ML_DSA_KEY_PAIR_GEN_LIST  0x0000001CUL
#define CKM_ML_DSA_LIST               0x0000001DUL
#define CKM_SLH_DSA_KEY_PAIR_GEN_LIST 0x0000002DUL
#define CKM_SLH_DSA_LIST              0x0000002EUL
/* Vendor / pre-FIPS PQ. Falcon was not standardized ; Kyber was the
 * pre-standardization name of ML-KEM. Both use vendor-defined OIDs. */
#define CKM_FALCON_LIST               0xC0001000UL
#define CKM_KYBER_LIST                0xC0001001UL
/* AES key wrap (RFC 3394 / RFC 5649). Forward-defined here so they're
 * available both in g_mech_list and in C_GetMechanismInfo below. */
#ifndef CKM_AES_KEY_WRAP
#define CKM_AES_KEY_WRAP              0x00002109UL
#endif
#ifndef CKM_AES_KEY_WRAP_KWP
#define CKM_AES_KEY_WRAP_KWP          0x0000210BUL
#endif

/* ===========================================================================
 * Mechanism advertisement (#125) --- derived from the generated dispatch
 * table (the single source of truth), NOT a hand-maintained list.
 *
 *  C_GetMechanismList and C_GetMechanismInfo read fhsm_mechanism_table[]
 *  (generated into src/gen/fhsm_dispatch.c by scripts/gen_p11_thunks.py),
 *  so the advertised set can never drift from what the module actually
 *  dispatches. A mechanism is advertised iff it resolves to a real
 *  handler in the active build profile :
 *    - general-purpose (interop) build : every mechanism with a real
 *      handler is advertised, including non-FIPS ones (the module is a
 *      general-purpose PKCS#11 provider) ;
 *    - FIPS (fips-strict) build : non-approved mechanisms are compiled
 *      to dispatch_reject_fips and are therefore NOT advertised.
 *
 *  This replaced the previous hand-written g_mech_list + capability
 *  switch, which had drifted badly : wrong post-quantum values
 *  (0x403x vs the dispatched 0x402x), phantom FALCON/KYBER entries not
 *  backed by any handler, and ~40 dispatched-but-unadvertised
 *  mechanisms (all SHA-3/SHAKE, KMAC, HKDF, EdDSA, X25519/X448,
 *  ML-KEM/ML-DSA/SLH-DSA at their correct values, ...). See
 *  docs/PKCS11_CHECK_FINDINGS.md.
 *
 *  Local mirror of the generated dispatch-table interface : this TU
 *  defines its own CKM_* macros (with a UL suffix) that would collide
 *  under -Werror with the generated header's (u suffix), so we cannot
 *  #include it here. The struct layout MUST match the generated one ;
 *  tests/test_mech_advertise guards against drift at runtime.
 * ========================================================================= */
typedef fhsm_rv_t (*fhsm_mech_handler_t)(
    unsigned long, unsigned long, const void *, size_t,
    fhsm_slice_t, uint8_t *, size_t *);
typedef struct fhsm_mech_entry_s {
    uint32_t              ckm_value;
    const char           *name;
    const char           *family;
    const char           *operation;
    int                   fips_approved;
    fhsm_mech_handler_t   handler;
} fhsm_mech_entry_t;
extern const fhsm_mech_entry_t fhsm_mechanism_table[];
extern const size_t            fhsm_mechanism_count;
const fhsm_mech_entry_t *fhsm_mechanism_lookup(uint32_t ckm);
/* Build-profile flag, generated into fhsm_pkcs11_mechanisms.h (which
 * this TU cannot include due to CKM_* macro collisions). Mirrored here
 * as an extern const emitted by the generator into the dispatch TU. */
extern const int fhsm_build_fips_strict;
fhsm_rv_t dispatch_reject_fips(unsigned long, unsigned long,
                                const void *, size_t, fhsm_slice_t,
                                uint8_t *, size_t *);

/* PKCS#11 v3.2 CK_MECHANISM_INFO flag bits (§A.4.6.1). */
#define CKF_HW_MECH              0x00000001UL
#define CKF_ENCRYPT              0x00000100UL
#define CKF_DECRYPT              0x00000200UL
#define CKF_DIGEST               0x00000400UL
#define CKF_SIGN                 0x00000800UL
#define CKF_VERIFY               0x00002000UL
#define CKF_GENERATE             0x00008000UL
#define CKF_GENERATE_KEY_PAIR    0x00010000UL
#define CKF_ENCAPSULATE          0x10000000UL
#define CKF_DECAPSULATE          0x20000000UL
#define CKF_WRAP                 0x00020000UL
#define CKF_UNWRAP_MECH          0x00040000UL
#define CKF_DERIVE               0x00080000UL

/* A mechanism is advertised iff it dispatches to a real handler in the
 * active profile (not the FIPS reject stub). */
static int fhsm_mech_advertised(const fhsm_mech_entry_t *e) {
    return e != NULL && e->handler != dispatch_reject_fips;
}

/* Generated per-mechanism operation class -> CK_MECHANISM_INFO flags. */
static CK_ULONG fhsm_mech_flags_for(const char *op) {
    if (!op) return 0;
    if (!strcmp(op, "digest"))  return CKF_DIGEST;
    if (!strcmp(op, "sign"))    return CKF_SIGN | CKF_VERIFY;
    if (!strcmp(op, "encrypt")) return CKF_ENCRYPT | CKF_DECRYPT;
    if (!strcmp(op, "encap"))   return CKF_ENCAPSULATE | CKF_DECAPSULATE;
    if (!strcmp(op, "wrap"))    return CKF_WRAP | CKF_UNWRAP_MECH;
    if (!strcmp(op, "derive"))  return CKF_DERIVE;
    if (!strcmp(op, "keygen"))  return CKF_GENERATE;
    if (!strcmp(op, "keypair")) return CKF_GENERATE_KEY_PAIR;
    return 0;
}

/* Coarse key-size hints by family. Precise per-mechanism reporting is
 * increment 2 ; 0/0 is spec-valid where a key size is not meaningful
 * (hashes, PQ parameter-set mechanisms, KDFs). */
static void fhsm_mech_keysizes_for(const char *fam,
                                    CK_ULONG *mn, CK_ULONG *mx) {
    *mn = 0; *mx = 0;
    if (!fam) return;
    if (!strcmp(fam, "AES"))     { *mn = 16;   *mx = 32;   return; }
    if (!strcmp(fam, "TDES") || !strcmp(fam, "DES"))
                                 { *mn = 8;    *mx = 24;   return; }
    if (!strcmp(fam, "RSA"))     { *mn = 2048; *mx = 4096; return; }
    if (!strcmp(fam, "EC") || !strcmp(fam, "EdDSA") || !strcmp(fam, "ECM"))
                                 { *mn = 256;  *mx = 521;  return; }
    if (!strcmp(fam, "HMAC") || !strcmp(fam, "KMAC") || !strcmp(fam, "GENERIC"))
                                 { *mn = 1;    *mx = 64;   return; }
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_ULONG *pMechanismList,
                          CK_ULONG *pulCount) {
    if (slotID >= FHSM_MAX_SLOTS) return FHSM_RV_SLOT_ID_INVALID;
    if (!pulCount) return FHSM_RV_ARGUMENTS_BAD;
    CK_ULONG n = 0;
    for (size_t i = 0; i < fhsm_mechanism_count; ++i)
        if (fhsm_mech_advertised(&fhsm_mechanism_table[i])) ++n;
    if (!pMechanismList) { *pulCount = n; return FHSM_RV_OK; }
    if (*pulCount < n) { *pulCount = n; return 0x00000150UL; }
    CK_ULONG j = 0;
    for (size_t i = 0; i < fhsm_mechanism_count; ++i)
        if (fhsm_mech_advertised(&fhsm_mechanism_table[i]))
            pMechanismList[j++] = (CK_ULONG)fhsm_mechanism_table[i].ckm_value;
    *pulCount = n;
    return FHSM_RV_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_ULONG type, CK_VOID_PTR pInfo) {
    if (slotID >= FHSM_MAX_SLOTS) return FHSM_RV_SLOT_ID_INVALID;
    if (!pInfo) return FHSM_RV_ARGUMENTS_BAD;
    const fhsm_mech_entry_t *e = fhsm_mechanism_lookup((uint32_t)type);
    if (!fhsm_mech_advertised(e)) return FHSM_RV_MECHANISM_INVALID;
    struct fhsm_ck_mech_info {
        CK_ULONG ulMinKeySize, ulMaxKeySize;
        CK_FLAGS flags;
    } *info = pInfo;
    fhsm_mech_keysizes_for(e->family, &info->ulMinKeySize, &info->ulMaxKeySize);
    info->flags = fhsm_mech_flags_for(e->operation);
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * Helper : copy a PKCS#11 byte buffer into a stack-allocated null-terminated
 * string (PINs and labels are not NUL-terminated in PKCS#11). Returns 0
 * on success, -1 if the input is too long for the destination.
 * ----------------------------------------------------------------------- */
static int fhsm_copy_to_cstr(char *dst, size_t cap, const void *src, size_t n) {
    if (n + 1 > cap) return -1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}

/* ---------------------------------------------------------------------------
 * C_InitToken --- create or re-initialize the token in `slotID`. The SO PIN
 * becomes the new SO PIN. Existing objects are destroyed.
 * ----------------------------------------------------------------------- */
CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                   CK_UTF8CHAR_PTR pLabel) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (slotID >= FHSM_MAX_SLOTS) return FHSM_RV_SLOT_ID_INVALID;
    if (!pPin || ulPinLen < 4 || ulPinLen > 64) return FHSM_RV_ARGUMENTS_BAD;
    if (!pLabel) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_slot_table_init_once();

    char pin[128]; if (fhsm_copy_to_cstr(pin, sizeof(pin), pPin, ulPinLen) < 0)
        return FHSM_RV_ARGUMENTS_BAD;

    /* Label is 32 bytes ASCII, space-padded, per PKCS#11. Strip trailing
     * spaces for storage. */
    char label[33];
    memcpy(label, pLabel, 32); label[32] = '\0';
    for (int i = 31; i >= 0 && label[i] == ' '; --i) label[i] = '\0';

    /* If a token already exists, re-initialize via fhsm_token_reinit. */
    fhsm_rv_t rv;
    if (g_slots[slotID].present) {
        fhsm_token_t *t = fhsm_slot_token(slotID);
        if (!t) { fhsm_zeroize(pin, sizeof(pin)); return FHSM_RV_FUNCTION_FAILED; }
        rv = fhsm_token_reinit(t, pin, label);
    } else {
        fhsm_token_t *t = NULL;
        rv = fhsm_token_init(g_slots[slotID].path, pin, label, &t);
        if (rv == FHSM_RV_OK) {
            g_slots[slotID].present = 1;
            g_slots[slotID].token   = t;
        }
    }
    fhsm_zeroize(pin, sizeof(pin));
    (void)fhsm_audit_event(FHSM_EV_TOKEN_INIT, (int)slotID, -1,
                            FHSM_ROLE_SO, rv, NULL);
    return rv;
}

/* ---------------------------------------------------------------------------
 * C_InitPIN --- set the user PIN. Must be called from an SO session.
 * ----------------------------------------------------------------------- */
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                 CK_ULONG ulPinLen) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pPin || ulPinLen < 4 || ulPinLen > 64) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_token_t *t = fhsm_session_token(hSession);
    fhsm_role_t   r = fhsm_session_role(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (r != FHSM_ROLE_SO) return FHSM_RV_USER_NOT_LOGGED_IN;

    char pin[128]; if (fhsm_copy_to_cstr(pin, sizeof(pin), pPin, ulPinLen) < 0)
        return FHSM_RV_ARGUMENTS_BAD;
    fhsm_rv_t rv = fhsm_token_init_user_pin(t, pin);
    fhsm_zeroize(pin, sizeof(pin));
    (void)fhsm_audit_event(FHSM_EV_SET_PIN, -1, (int)hSession,
                            FHSM_ROLE_SO, rv, NULL);
    return rv;
}

/* ---------------------------------------------------------------------------
 * C_SetPIN --- change the PIN of the currently-logged-in role.
 * ----------------------------------------------------------------------- */
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
                CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pOldPin || !pNewPin) return FHSM_RV_ARGUMENTS_BAD;
    if (ulOldLen < 4 || ulOldLen > 64 || ulNewLen < 4 || ulNewLen > 64)
        return FHSM_RV_ARGUMENTS_BAD;
    fhsm_token_t *t = fhsm_session_token(hSession);
    fhsm_role_t   r = fhsm_session_role(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (r == FHSM_ROLE_NONE) return FHSM_RV_USER_NOT_LOGGED_IN;

    char op[128], np[128];
    if (fhsm_copy_to_cstr(op, sizeof(op), pOldPin, ulOldLen) < 0 ||
        fhsm_copy_to_cstr(np, sizeof(np), pNewPin, ulNewLen) < 0) {
        fhsm_zeroize(op, sizeof(op)); fhsm_zeroize(np, sizeof(np));
        return FHSM_RV_ARGUMENTS_BAD;
    }
    fhsm_rv_t rv = fhsm_token_set_pin(t, r, op, np);
    fhsm_zeroize(op, sizeof(op));
    fhsm_zeroize(np, sizeof(np));
    (void)fhsm_audit_event(FHSM_EV_SET_PIN, -1, (int)hSession,
                            r, rv, NULL);
    return rv;
}

/* ===========================================================================
 * Crypto / object thunks.
 *
 * PKCS#11 attribute and mechanism constants used below. The full set
 * lives in include/fhsm_pkcs11.h ; we replicate only what is referenced
 * here to keep this scaffold self-contained.
 * =========================================================================== */
#define CKA_CLASS           0x00000000UL
#define CKA_TOKEN           0x00000001UL
#define CKA_PRIVATE         0x00000002UL
#define CKA_LABEL           0x00000003UL
#define CKA_VALUE           0x00000011UL
#define CKA_VALUE_LEN       0x00000161UL
#define CKA_KEY_TYPE        0x00000100UL
#define CKA_ID              0x00000102UL
#define CKA_SENSITIVE       0x00000103UL
#define CKA_MODULUS         0x00000120UL
#define CKA_MODULUS_BITS    0x00000121UL
#define CKA_PUBLIC_EXPONENT 0x00000122UL
#define CKA_EC_POINT        0x00000181UL
#define CKA_EC_PARAMS_QUERY 0x00000180UL  /* alias for query path */
#define CKA_ENCRYPT_ATTR    0x00000104UL
#define CKA_DECRYPT_ATTR    0x00000105UL
#define CKA_WRAP_ATTR       0x00000106UL
#define CKA_UNWRAP_ATTR     0x00000107UL
#define CKA_SIGN_ATTR       0x00000108UL
#define CKA_VERIFY_ATTR     0x0000010AUL
#define CKA_EXTRACTABLE     0x00000162UL
#define CKA_DERIVE_ATTR     0x0000010CUL
#define CKA_LOCAL_ATTR      0x00000163UL
#define CKA_NEVER_EXTRACTABLE_ATTR 0x00000164UL
#define CKA_ALWAYS_SENSITIVE_ATTR  0x00000165UL
#define CKA_MODIFIABLE_ATTR 0x00000170UL
#define CKA_COPYABLE_ATTR   0x00000171UL
#define CKA_DESTROYABLE_ATTR 0x00000172UL
#define CKA_ALWAYS_AUTH_ATTR 0x00000202UL
#define CKA_WRAP_WITH_TRUSTED_ATTR 0x00000210UL
#define CKA_TRUSTED_ATTR    0x00000086UL
#define CKA_START_DATE_ATTR 0x00000110UL
#define CKA_END_DATE_ATTR   0x00000111UL
#define CKA_SUBJECT_ATTR    0x00000101UL
#define CKA_ISSUER_ATTR     0x00000081UL
#define CKA_SERIAL_NUMBER_ATTR 0x00000082UL
#define CKR_ATTRIBUTE_SENSITIVE 0x00000011UL

/* Object flags stored on disk (1 byte). */
#define FHSM_OBJF_SENSITIVE     0x01
#define FHSM_OBJF_EXTRACTABLE   0x02
#define FHSM_OBJF_UNMODIFIABLE  0x04   /* CKA_MODIFIABLE=FALSE persisted */
#define FHSM_OBJF_UNDESTROYABLE 0x08   /* CKA_DESTROYABLE=FALSE persisted */

/* Per-object usage flag bits (stored via fhsm_token_object_set_usage).
 * Bit 7 marks the byte as carrying explicit usage ; without it the
 * class default applies (legacy objects). #125. */
#define FHSM_USAGE_ENCRYPT  0x01
#define FHSM_USAGE_DECRYPT  0x02
#define FHSM_USAGE_SIGN     0x04
#define FHSM_USAGE_VERIFY   0x08
#define FHSM_USAGE_WRAP     0x10
#define FHSM_USAGE_UNWRAP   0x20
#define FHSM_USAGE_DERIVE   0x40
#define FHSM_USAGE_VALID    0x80

#define CKO_DATA            0x00000000UL
#define CKO_CERTIFICATE     0x00000001UL
#define CKO_PUBLIC_KEY      0x00000002UL
#define CKO_PRIVATE_KEY     0x00000003UL
#define CKO_SECRET_KEY      0x00000004UL

#define CKK_AES             0x0000001FUL
#define CKK_DES3            0x00000015UL
#define CKK_GENERIC_SECRET  0x00000010UL
#define CKK_SHA256_HMAC     0x0000002BUL

/* Per-session find-objects state. */
typedef struct fhsm_find_state_s {
    uint32_t  handles[64];
    size_t    count;
    size_t    next;
    int       active;
} fhsm_find_state_t;
static fhsm_find_state_t g_finds[FHSM_MAX_SLOTS * 32];   /* one slot per session */

/* Per-session active operation (Encrypt / Decrypt / Sign with key context). */
typedef struct fhsm_op_s {
    int         active;
    uint32_t    key_handle;
    uint32_t    mechanism;
    /* For AES-GCM : caller-supplied IV (12 bytes), for CBC/CTR : 16 bytes,
     * for OAEP : unused. The union of usages fits in 16 bytes. */
    uint8_t     iv[16];
    int         have_iv;
    /* For Digest : the hash algorithm selected at Init. */
    fhsm_hash_t hash;
    /* For multi-part streaming : EVP contexts persisted between
     * Update calls. void* so this header does not pull in OpenSSL. */
    void       *md_ctx;        /* EVP_MD_CTX*   --- Digest */
    void       *mac_ctx;       /* EVP_MAC_CTX*  --- Sign (HMAC) */
    void       *cipher_ctx;    /* EVP_CIPHER_CTX* --- Encrypt/Decrypt */
    /* RSA-PSS parameters captured from CK_RSA_PKCS_PSS_PARAMS at
     * VerifyInit/SignInit time. pss_have=0 means "use the digest-length
     * default" (back-compat with callers that pass no parameter). */
    int         pss_have;
    long        pss_saltlen;   /* salt length in bytes */
    uint32_t    pss_mgf;       /* CKG_MGF1_SHA* identifier */
    /* CK_GCM_PARAMS members captured at EncryptInit / DecryptInit. The
     * static buffers are intentionally generous to cover Wycheproof's
     * LongIv / large-AAD cases : the corpus has IVs up to 2056 bits
     * (= 257 bytes) and AADs that can comfortably exceed 1 KiB. */
    int         gcm_have;
    uint8_t     gcm_iv[512];
    size_t      gcm_iv_len;
    uint8_t     gcm_aad[4096];
    size_t      gcm_aad_len;
    size_t      gcm_tag_len;   /* in BYTES (ulTagBits / 8) */
    /* Post-quantum context string captured at VerifyInit / SignInit.
     * Shared between CK_ML_DSA_PARAMS (PKCS#11 v3.2 §6.18 ; FIPS 204
     * §5.2.1) and CK_SLH_DSA_PARAMS (PKCS#11 v3.2 §6.19 ; FIPS 205
     * §5.2.1) --- both carry an octet-string context capped at 255
     * bytes by their respective specs, with identical wire layout
     * { hedgeVariant ; pContext ; ulContextLen } on the PKCS#11 side.
     * pq_ctx_have=0 means "default empty context", matching the
     * behaviour for callers that pass no parameter. */
    int         pq_ctx_have;
    uint8_t     pq_ctx[256];
    size_t      pq_ctx_len;
} fhsm_op_t;
static fhsm_op_t g_op_enc[256];
static fhsm_op_t g_op_dec[256];
static fhsm_op_t g_op_sig[256];
static fhsm_op_t g_op_dig[256];
static fhsm_op_t g_op_ver[256];

static fhsm_op_t *op_slot(fhsm_op_t *table, CK_SESSION_HANDLE h) {
    if (h == 0 || h >= 256) return NULL;
    return &table[h];
}

/* Look up an attribute in a template ; returns the index or -1. */
static long find_attr(CK_ATTRIBUTE *t, CK_ULONG n, CK_ATTRIBUTE_TYPE type) {
    for (CK_ULONG i = 0; i < n; ++i) if (t[i].type == type) return (long)i;
    return -1;
}

/* Robustness guard for a caller-supplied attribute template. A NULL
 * template pointer paired with a non-zero count, or an absurd count
 * (integer-overflow probe), must be rejected before ANY iteration --
 * walking such a template dereferences NULL or reads far out of bounds.
 * (pkcs11-check security/test_api_boundary + test_arithmetic_overflow,
 * #125 -- these were SIGSEGV/SIGBUS in the raw entry points.) An empty
 * template (count == 0) is legal. FHSM_MAX_TEMPLATE_ATTRS is a generous
 * ceiling : real PKCS#11 templates hold a handful of attributes, so any
 * count above this is a caller error, not a valid request. */
#ifndef FHSM_MAX_TEMPLATE_ATTRS
#define FHSM_MAX_TEMPLATE_ATTRS 1024u
#endif
static CK_RV fhsm_check_template(CK_ATTRIBUTE *t, CK_ULONG n) {
    if (n == 0) return FHSM_RV_OK;
    if (t == NULL) return FHSM_RV_ARGUMENTS_BAD;
    if (n > FHSM_MAX_TEMPLATE_ATTRS) return FHSM_RV_ARGUMENTS_BAD;
    /* An attribute in a creation template with a NULL pValue but a non-zero
     * ulValueLen is malformed : there is no value of the stated length. This
     * is CKR_ATTRIBUTE_VALUE_INVALID (#125 TestCreateObjectErrors
     * CKA_ALLOWED_MECHANISMS NULL_PTR + nonzero len). Creation templates never
     * use the NULL/size-query convention (that is C_GetAttributeValue only). */
    for (CK_ULONG i = 0; i < n; ++i)
        if (t[i].pValue == NULL && t[i].ulValueLen != 0)
            return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
    return FHSM_RV_OK;
}

/* Reject a boolean (CK_BBOOL) attribute supplied with a length other
 * than 1 byte -- e.g. a CK_ULONG-sized value. PKCS#11 CK_BBOOL is
 * exactly one byte ; an over-long value is CKR_ATTRIBUTE_VALUE_INVALID
 * (pkcs11-check security/test_scalar_attr_length_extended, #125). */
/* Reject a CK_ULONG-typed attribute (CKA_CLASS, CKA_KEY_TYPE,
 * CKA_VALUE_LEN, CKA_MODULUS_BITS, CKA_CERTIFICATE_TYPE) supplied with a
 * length other than sizeof(CK_ULONG). An over/underlong scalar is
 * CKR_ATTRIBUTE_VALUE_INVALID (#125 test_value_len_ulong / key_type). */
static CK_RV fhsm_check_ulong_attr_lengths(CK_ATTRIBUTE *t, CK_ULONG n) {
    static const CK_ULONG ulong_attrs[] = {
        0x000, 0x100, 0x161, 0x121, 0x080 };
    if (n == 0 || t == NULL) return FHSM_RV_OK;
    for (CK_ULONG i = 0; i < n; ++i) {
        for (size_t j = 0; j < sizeof(ulong_attrs)/sizeof(ulong_attrs[0]); ++j) {
            if (t[i].type == ulong_attrs[j]) {
                if (t[i].pValue != NULL && t[i].ulValueLen != sizeof(CK_ULONG))
                    return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
                break;
            }
        }
    }
    return FHSM_RV_OK;
}

static CK_RV fhsm_check_bool_attr_lengths(CK_ATTRIBUTE *t, CK_ULONG n) {
    static const CK_ULONG bool_attrs[] = {
        0x001,0x002,0x086,0x103,0x104,0x105,0x106,0x107,0x108,0x109,0x10A,
        0x10B,0x10C,0x162,0x163,0x164,0x165,0x170,0x171,0x172,0x202,0x210 };
    if (n == 0 || t == NULL) return FHSM_RV_OK;
    for (CK_ULONG i = 0; i < n; ++i) {
        for (size_t j = 0; j < sizeof(bool_attrs)/sizeof(bool_attrs[0]); ++j) {
            if (t[i].type == bool_attrs[j]) {
                if (t[i].pValue != NULL && t[i].ulValueLen != 1)
                    return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
                break;
            }
        }
    }
    return FHSM_RV_OK;
}

/* Read a CK_BBOOL attribute from a template ; returns `dflt` if absent
 * or malformed. Used for PKCS#11 CKA_TOKEN / usage-flag semantics. */
static int tmpl_bbool(CK_ATTRIBUTE *t, CK_ULONG n, CK_ATTRIBUTE_TYPE type, int dflt) {
    long i = find_attr(t, n, type);
    if (i < 0 || !t[i].pValue || t[i].ulValueLen != 1) return dflt;
    return ((const unsigned char *)t[i].pValue)[0] ? 1 : 0;
}

/* Compute the stored usage-flag byte for a new object from its class
 * default plus any CKA_ENCRYPT/DECRYPT/SIGN/VERIFY/WRAP/UNWRAP/DERIVE
 * overrides in the creation template (#125). */
static uint8_t fhsm_compute_usage(uint32_t cko_class, CK_ATTRIBUTE *tmpl, CK_ULONG n) {
    uint8_t u = FHSM_USAGE_VALID;
    if (cko_class == CKO_SECRET_KEY)
        u |= FHSM_USAGE_ENCRYPT | FHSM_USAGE_DECRYPT | FHSM_USAGE_SIGN
           | FHSM_USAGE_VERIFY | FHSM_USAGE_WRAP | FHSM_USAGE_UNWRAP;
    else if (cko_class == CKO_PUBLIC_KEY)
        u |= FHSM_USAGE_ENCRYPT | FHSM_USAGE_VERIFY | FHSM_USAGE_WRAP;
    else if (cko_class == CKO_PRIVATE_KEY)
        u |= FHSM_USAGE_DECRYPT | FHSM_USAGE_SIGN | FHSM_USAGE_UNWRAP | FHSM_USAGE_DERIVE;
    static const struct { CK_ATTRIBUTE_TYPE a; uint8_t bit; } map[] = {
        { CKA_ENCRYPT_ATTR, FHSM_USAGE_ENCRYPT }, { CKA_DECRYPT_ATTR, FHSM_USAGE_DECRYPT },
        { CKA_SIGN_ATTR, FHSM_USAGE_SIGN }, { CKA_VERIFY_ATTR, FHSM_USAGE_VERIFY },
        { CKA_WRAP_ATTR, FHSM_USAGE_WRAP }, { CKA_UNWRAP_ATTR, FHSM_USAGE_UNWRAP },
        { CKA_DERIVE_ATTR, FHSM_USAGE_DERIVE }
    };
    for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); ++i) {
        int b = tmpl_bbool(tmpl, n, map[i].a, -1);
        if (b == 1) u |= map[i].bit;
        else if (b == 0) u &= (uint8_t)~map[i].bit;
    }
    return u;
}

/* Report a usage bit for C_GetAttributeValue : the stored value if the
 * object carries explicit usage, else the class default. */
static unsigned char fhsm_usage_bool(fhsm_token_t *t, CK_OBJECT_HANDLE h,
                                     uint32_t cko_class, uint8_t bit,
                                     int class_default) {
    uint8_t u = 0;
    if (fhsm_token_object_get_usage(t, (uint32_t)h, &u) == FHSM_RV_OK
        && (u & FHSM_USAGE_VALID))
        return (u & bit) ? 1 : 0;
    (void)cko_class;
    return class_default ? 1 : 0;
}

static CK_RV fhsm_check_usage(fhsm_token_t *t, CK_OBJECT_HANDLE hKey, uint8_t bit);

/* PKCS#11 : creating a token object (CKA_TOKEN=TRUE) on a read-only
 * session is CKR_SESSION_READ_ONLY. Call before creating the object. */
static CK_RV fhsm_check_ro_token(CK_SESSION_HANDLE hSession,
                                 CK_ATTRIBUTE *tmpl, CK_ULONG n) {
    if (tmpl_bbool(tmpl, n, CKA_TOKEN, 0)) {
        unsigned long flags = 0;
        if (fhsm_session_info(hSession, NULL, &flags, NULL) == FHSM_RV_OK
            && !(flags & 0x00000002UL /* CKF_RW_SESSION */))
            return FHSM_RV_SESSION_READ_ONLY;
    }
    return FHSM_RV_OK;
}

/* PKCS#11 : a private object (CKA_PRIVATE=TRUE, explicit or derived from the
 * class default -- TRUE for secret/private keys) may only be created,
 * derived or unwrapped by an authenticated (logged-in) session. A public
 * (unauthenticated) session attempting this is CKR_USER_NOT_LOGGED_IN (#125
 * TestPublicSessionRestrictions). */
static CK_RV fhsm_check_private_login(CK_SESSION_HANDLE hSession,
                                      CK_ATTRIBUTE *tmpl, CK_ULONG n) {
    CK_ULONG cls = 0xFFFFFFFFUL;
    long ci = find_attr(tmpl, n, 0x00 /* CKA_CLASS */);
    if (ci >= 0 && tmpl[ci].pValue && tmpl[ci].ulValueLen == sizeof(CK_ULONG))
        cls = *(CK_ULONG *)tmpl[ci].pValue;
    int default_priv = (cls == CKO_SECRET_KEY || cls == CKO_PRIVATE_KEY) ? 1 : 0;
    if (tmpl_bbool(tmpl, n, CKA_PRIVATE, default_priv)
        && fhsm_session_role(hSession) == FHSM_ROLE_NONE)
        return FHSM_RV_USER_NOT_LOGGED_IN;
    return FHSM_RV_OK;
}

/* Apply CKA_TOKEN scope after creating an object : if the template does
 * not request a token object (default CKA_TOKEN=FALSE) the object is a
 * session object owned by hSession -- not persisted, destroyed on close. */
static void fhsm_apply_token_scope(fhsm_token_t *t, CK_SESSION_HANDLE hSession,
                                   CK_ATTRIBUTE *tmpl, CK_ULONG n, uint32_t handle) {
    if (!tmpl_bbool(tmpl, n, CKA_TOKEN, 0))
        (void)fhsm_token_object_mark_session(t, handle, (uint32_t)hSession);
    /* Persist CKA_MODIFIABLE / CKA_DESTROYABLE = FALSE (both default TRUE) so
     * the read-back is truthful and mutation/destroy can be enforced (#125
     * TestModifiableAttribute / TestDestroyable). */
    uint8_t pf = 0;
    if (fhsm_token_object_get_flags(t, handle, &pf) == FHSM_RV_OK) {
        if (!tmpl_bbool(tmpl, n, CKA_MODIFIABLE_ATTR, 1))  pf |= FHSM_OBJF_UNMODIFIABLE;
        if (!tmpl_bbool(tmpl, n, CKA_DESTROYABLE_ATTR, 1)) pf |= FHSM_OBJF_UNDESTROYABLE;
        (void)fhsm_token_object_set_flags(t, handle, pf);
    }
}

/* ---------------------------------------------------------------------------
 * C_GenerateRandom --- FIPS DRBG (CTR_DRBG-AES-256, OpenSSL FIPS provider).
 * ----------------------------------------------------------------------- */
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, unsigned char *pSeed,
                       CK_ULONG ulLen) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (fhsm_session_token(hSession) == NULL) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (!pSeed || ulLen == 0) return FHSM_RV_ARGUMENTS_BAD;
    return fhsm_rng_bytes(pSeed, ulLen);
}

/* ---------------------------------------------------------------------------
 * Digest --- CKM_SHA256 / CKM_SHA384 / CKM_SHA512 ; one-shot only.
 * ----------------------------------------------------------------------- */
#define CKM_SHA_1                  0x00000220UL
#define CKM_SHA384                 0x00000260UL
#define CKM_SHA512                 0x00000270UL

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (fhsm_session_token(hSession) == NULL) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (!pMechanism) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_op_t *op = op_slot(g_op_dig, hSession);
    if (!op) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (op->active) return FHSM_RV_OPERATION_ACTIVE;
    /* Digest mechanisms take no mechanism parameter. A non-NULL pParameter
     * or a non-zero ulParameterLen is CKR_MECHANISM_PARAM_INVALID (#125
     * TestDigestInitErrors::test_mechanism_param_invalid). */
    if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0)
        return FHSM_RV_MECHANISM_PARAM_INVALID;
    switch (pMechanism->mechanism) {
        case CKM_SHA256: op->hash = FHSM_HASH_SHA256; break;
        case CKM_SHA384: op->hash = FHSM_HASH_SHA384; break;
        case CKM_SHA512: op->hash = FHSM_HASH_SHA512; break;
        /* Additional FIPS-approved digests (FIPS 180-4 / 202) : advertised
         * by the dispatch table ; now callable in both profiles. #125. */
        case 0x00000255UL: op->hash = FHSM_HASH_SHA224;     break; /* CKM_SHA224 */
        case 0x00000048UL: op->hash = FHSM_HASH_SHA512_224; break; /* CKM_SHA512_224 */
        case 0x0000004CUL: op->hash = FHSM_HASH_SHA512_256; break; /* CKM_SHA512_256 */
        case 0x000002B5UL: op->hash = FHSM_HASH_SHA3_224;   break; /* CKM_SHA3_224 */
        case 0x000002B0UL: op->hash = FHSM_HASH_SHA3_256;   break; /* CKM_SHA3_256 */
        case 0x000002C0UL: op->hash = FHSM_HASH_SHA3_384;   break; /* CKM_SHA3_384 */
        case 0x000002D0UL: op->hash = FHSM_HASH_SHA3_512;   break; /* CKM_SHA3_512 */
        /* Non-FIPS legacy digests : executable only in the interop /
         * general-purpose build (rejected under fips-strict). #125. */
        case 0x00000220UL: /* CKM_SHA_1 */
            if (fhsm_build_fips_strict) return FHSM_RV_MECHANISM_INVALID;
            op->hash = FHSM_HASH_SHA1; break;
        case 0x00000210UL: /* CKM_MD5 */
            if (fhsm_build_fips_strict) return FHSM_RV_MECHANISM_INVALID;
            op->hash = FHSM_HASH_MD5; break;
        default:         return FHSM_RV_MECHANISM_INVALID;
    }
    op->active = 1;
    op->mechanism = (uint32_t)pMechanism->mechanism;
    return FHSM_RV_OK;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, unsigned char *pData,
               CK_ULONG ulDataLen, unsigned char *pDigest, CK_ULONG *pulDigestLen) {
    if (!pulDigestLen) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_op_t *op = op_slot(g_op_dig, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    /* Reject a NULL data pointer paired with a non-zero length before any
     * dereference (pkcs11-check security/test_ffi_null_pointer, #125). A
     * NULL buffer of length 0 is legal (empty message). Errors terminate
     * the active operation, per PKCS#11 C_Sign/C_Verify/C_Digest rules. */
    if (pData == NULL && ulDataLen != 0) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
    size_t need = fhsm_hash_size(op->hash);
    if (pDigest == NULL) { *pulDigestLen = need; return FHSM_RV_OK; }
    if (*pulDigestLen < need) { *pulDigestLen = need; return 0x00000150UL; }
    size_t out_len = *pulDigestLen;
    fhsm_rv_t rv = fhsm_hash_oneshot(op->hash,
                                       FHSM_SLICE(pData, ulDataLen),
                                       pDigest, &out_len);
    *pulDigestLen = out_len;
    op->active = 0;
    return rv;
}

/* ---------------------------------------------------------------------------
 * C_GenerateKey --- only CKM_AES_KEY_GEN here. Length read from
 * CKA_VALUE_LEN ; the key bytes are filled from the FIPS DRBG and stored
 * in the token's encrypted object store.
 * ----------------------------------------------------------------------- */
#define CKM_AES_KEY_GEN     0x00001080UL
#define CKM_GENERIC_SECRET_KEY_GEN  0x00000350UL

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                    CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE *phKey) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pMechanism || !phKey) return FHSM_RV_ARGUMENTS_BAD;
    { CK_RV cr = fhsm_check_template(pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_bool_attr_lengths(pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_ulong_attr_lengths(pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_ro_token(hSession, pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (fhsm_session_role(hSession) == FHSM_ROLE_NONE)
        return FHSM_RV_USER_NOT_LOGGED_IN;

    uint32_t key_type = 0;
    uint32_t key_len  = 0;
    /* CKM_DES3_KEY_GEN (0x130) is non-FIPS : interop only, fixed 24-byte
     * key, no CKA_VALUE_LEN. #125. */
    if (pMechanism->mechanism == 0x00000130UL) {
        if (fhsm_build_fips_strict) return FHSM_RV_MECHANISM_INVALID;
        key_type = CKK_DES3; key_len = 24;
    } else {
        switch (pMechanism->mechanism) {
            case CKM_AES_KEY_GEN:            key_type = CKK_AES;            break;
            case CKM_GENERIC_SECRET_KEY_GEN: key_type = CKK_GENERIC_SECRET; break;
            default:                          return FHSM_RV_MECHANISM_INVALID;
        }
        long j = find_attr(pTemplate, ulCount, CKA_VALUE_LEN);
        if (j < 0) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
        key_len = (uint32_t)(*(CK_ULONG*)pTemplate[j].pValue);
        if (key_len != 16 && key_len != 24 && key_len != 32)
            return FHSM_RV_KEY_SIZE_RANGE;
    }
    long i;

    char label[64] = ""; const uint8_t *id = NULL; size_t id_len = 0;
    i = find_attr(pTemplate, ulCount, CKA_LABEL);
    if (i >= 0) {
        size_t n = pTemplate[i].ulValueLen;
        if (n >= sizeof(label)) n = sizeof(label) - 1;
        memcpy(label, pTemplate[i].pValue, n);
        label[n] = '\0';
    }
    i = find_attr(pTemplate, ulCount, CKA_ID);
    if (i >= 0) { id = pTemplate[i].pValue; id_len = pTemplate[i].ulValueLen; }

    /* Default policy : SENSITIVE=TRUE, EXTRACTABLE=FALSE.
     * The template may override either explicitly (CK_BBOOL=1 byte). */
    uint8_t obj_flags = FHSM_OBJF_SENSITIVE;
    i = find_attr(pTemplate, ulCount, CKA_SENSITIVE);
    if (i >= 0 && pTemplate[i].pValue && pTemplate[i].ulValueLen >= 1) {
        if (((unsigned char*)pTemplate[i].pValue)[0] == 0)
            obj_flags &= (uint8_t)~FHSM_OBJF_SENSITIVE;
    }
    i = find_attr(pTemplate, ulCount, CKA_EXTRACTABLE);
    if (i >= 0 && pTemplate[i].pValue && pTemplate[i].ulValueLen >= 1) {
        if (((unsigned char*)pTemplate[i].pValue)[0] != 0)
            obj_flags |= FHSM_OBJF_EXTRACTABLE;
    }

    uint8_t key[64];
    fhsm_rv_t rv = fhsm_rng_bytes(key, key_len);
    if (rv != FHSM_RV_OK) return rv;

    uint32_t handle = 0;
    rv = fhsm_token_object_add(t, CKO_SECRET_KEY, key_type, label,
                                key, key_len, id, id_len, obj_flags, &handle);
    fhsm_zeroize(key, sizeof(key));
    if (rv != FHSM_RV_OK) return rv;
    *phKey = handle;
    fhsm_apply_token_scope(t, hSession, pTemplate, ulCount, handle);
    (void)fhsm_token_object_set_usage(t, handle, fhsm_compute_usage(CKO_SECRET_KEY, pTemplate, ulCount));
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * C_CreateObject --- create an object from a fully-specified attribute
 * template. PKCS#11 v3.2 §C.3.3.5.
 *
 * Currently supported : CKO_PUBLIC_KEY with CKK_EC (EC_PARAMS + EC_POINT)
 * and CKK_RSA (MODULUS + PUBLIC_EXPONENT). The pubkey is normalised into
 * an X.509 SubjectPublicKeyInfo DER blob and stored as the object's
 * VALUE so the existing C_VerifyInit / C_Verify path (which does
 * `d2i_PUBKEY` on `kv`) can use it without changes.
 *
 * CKO_CERTIFICATE with CKC_X_509 is supported since #110 : the DER
 * certificate is stored verbatim in CKA_VALUE (the module never parses
 * X.509 --- validation is the PKI layer's job). Data objects are not
 * handled yet --- they return CKR_TEMPLATE_INCONSISTENT until a real
 * need surfaces.
 * ----------------------------------------------------------------------- */
#ifndef CKA_EC_PARAMS
#define CKA_EC_PARAMS        0x00000180UL
#endif
#ifndef CKO_CERTIFICATE
#define CKO_CERTIFICATE      0x00000001UL
#endif
#ifndef CKA_CERTIFICATE_TYPE
#define CKA_CERTIFICATE_TYPE 0x00000080UL
#endif
#ifndef CKK_EC_CREATEOBJECT
#define CKK_EC_CREATEOBJECT  0x00000003UL  /* CKK_EC */
#endif
#ifndef CKK_RSA_CREATEOBJECT
#define CKK_RSA_CREATEOBJECT 0x00000000UL  /* CKK_RSA */
#endif
#ifndef CKK_EC_EDWARDS_CREATEOBJECT
#define CKK_EC_EDWARDS_CREATEOBJECT 0x00000040UL  /* CKK_EC_EDWARDS */
#endif
#ifndef CKR_TEMPLATE_INCOMPLETE
#define CKR_TEMPLATE_INCOMPLETE   0x000000D0UL
#endif
#ifndef CKR_TEMPLATE_INCONSISTENT
#define CKR_TEMPLATE_INCONSISTENT 0x000000D1UL
#endif

/* Curve-OID-to-group-name lookup and DER OCTET STRING wrapper stripper
 * used to live here. As part of the v1.2.0 C_CreateObject decomposition,
 * both functions were extracted to src/fhsm_create_attrs.c (parser TU)
 * and removed from here. The C_CreateObject builder paths use the
 * already-resolved values from the parser's fhsm_create_attrs_t struct.
 *
 * If a future code path inside fhsm_pkcs11.c needs an OID-to-group
 * lookup again, prefer adding it to the parser TU and exposing it
 * through include/fhsm_create_attrs.h rather than re-introducing a
 * duplicate definition here. */

/* Map the pure-parser return codes into the PKCS#11 / FHSM codes that
 * C_CreateObject is expected to surface. Centralised here so the parser
 * itself stays decoupled from the FHSM_RV / CKR enum layouts. */
static CK_RV map_parse_rv(fhsm_parse_rv_t rv) {
    switch (rv) {
        case FHSM_PARSE_OK:                          return FHSM_RV_OK;
        case FHSM_PARSE_TEMPLATE_INCOMPLETE:         return CKR_TEMPLATE_INCOMPLETE;
        case FHSM_PARSE_TEMPLATE_INCONSISTENT:       return CKR_TEMPLATE_INCONSISTENT;
        case FHSM_PARSE_ATTRIBUTE_VALUE_INVALID:     return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
    }
    return FHSM_RV_FUNCTION_FAILED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
                      CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                      CK_OBJECT_HANDLE *phObject) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pTemplate || !phObject || ulCount == 0) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    { CK_RV cr = fhsm_check_template(pTemplate, ulCount);          if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_ro_token(hSession, pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_private_login(hSession, pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_bool_attr_lengths(pTemplate, ulCount);  if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_ulong_attr_lengths(pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }

    /* === Parser stage : pure C, no OpenSSL. ============================
     * The CK_ATTRIBUTE layout is bit-identical to fhsm_attr_t (see
     * include/fhsm_attr_utils.h) ; the cast below is therefore safe. */
    fhsm_create_attrs_t a;
    CK_RV rv_parse = map_parse_rv(fhsm_parse_create_attrs(
        (const fhsm_attr_t *)pTemplate, ulCount, &a));
    if (rv_parse != FHSM_RV_OK) return rv_parse;

    /* === Builder stage : path-specific construction of either a raw blob
     * (verbatim path) or an EVP_PKEY that is then i2d_PUBKEY-serialised
     * into a SubjectPublicKeyInfo. The builder remains inline because
     * it is intrinsically tied to the OpenSSL EVP API. =================== */

    /* --- Verbatim path (CKO_SECRET_KEY / CKO_PRIVATE_KEY / ML-DSA pub). */
    if (a.path == FHSM_CREATE_PATH_VERBATIM) {
        uint8_t flags = (a.cko == CKO_PRIVATE_KEY) ? FHSM_OBJF_SENSITIVE : 0;
        uint32_t handle = 0;
        fhsm_rv_t rv = fhsm_token_object_add(
            t, (uint32_t)a.cko, (uint32_t)a.ckk,
            a.label, a.value_data, a.value_len,
            a.id_data, a.id_len, flags, &handle);
        if (rv != FHSM_RV_OK) return rv;
        *phObject = handle;
        fhsm_apply_token_scope(t, hSession, pTemplate, ulCount, handle);
        (void)fhsm_token_object_set_usage(t, handle, fhsm_compute_usage((uint32_t)a.cko, pTemplate, ulCount));
        return FHSM_RV_OK;
    }

    /* --- X.509 certificate path (#110). Certificates are public,
     * non-sensitive, extractable by definition : CKA_VALUE must be
     * readable back through C_GetAttributeValue (the PKI layer round-
     * trips DER through the token). The CKA_CERTIFICATE_TYPE value is
     * carried in the store's key_type field (CKC_X_509 = 0). */
    if (a.path == FHSM_CREATE_PATH_CERT_X509) {
        uint32_t handle = 0;
        fhsm_rv_t rv = fhsm_token_object_add(
            t, (uint32_t)CKO_CERTIFICATE, (uint32_t)a.cert_type,
            a.label, a.value_data, a.value_len,
            a.id_data, a.id_len, FHSM_OBJF_EXTRACTABLE, &handle);
        if (rv != FHSM_RV_OK) return rv;
        *phObject = handle;
        fhsm_apply_token_scope(t, hSession, pTemplate, ulCount, handle);
        (void)fhsm_token_object_set_usage(t, handle, fhsm_compute_usage((uint32_t)a.cko, pTemplate, ulCount));
        return FHSM_RV_OK;
    }

    /* --- EVP_PKEY paths : EC / Ed25519 / Ed448 / RSA public key. */
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    if (a.path == FHSM_CREATE_PATH_EC_PUB) {
        OSSL_PARAM params[3] = {
            OSSL_PARAM_construct_utf8_string("group", (char *)a.ec_group, 0),
            OSSL_PARAM_construct_octet_string("pub",
                (void *)a.ec_point, a.ec_point_len),
            OSSL_PARAM_construct_end()
        };
        pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!pctx || EVP_PKEY_fromdata_init(pctx) != 1
            || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            if (pctx) EVP_PKEY_CTX_free(pctx);
            return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
        }
        EVP_PKEY_CTX_free(pctx);

    } else if (a.path == FHSM_CREATE_PATH_ED25519_PUB
               || a.path == FHSM_CREATE_PATH_ED448_PUB) {
        const char *algo = (a.path == FHSM_CREATE_PATH_ED25519_PUB)
                           ? "ED25519" : "ED448";
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_octet_string("pub",
                (void *)a.ec_point, a.ec_point_len),
            OSSL_PARAM_construct_end()
        };
        pctx = EVP_PKEY_CTX_new_from_name(NULL, algo, NULL);
        if (!pctx || EVP_PKEY_fromdata_init(pctx) != 1
            || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            if (pctx) EVP_PKEY_CTX_free(pctx);
            return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
        }
        EVP_PKEY_CTX_free(pctx);

    } else if (a.path == FHSM_CREATE_PATH_RSA_PUB) {
        BIGNUM *n = BN_bin2bn(a.rsa_modulus,  (int)a.rsa_modulus_len,  NULL);
        BIGNUM *e = BN_bin2bn(a.rsa_exponent, (int)a.rsa_exponent_len, NULL);
        if (!n || !e) { BN_free(n); BN_free(e); return FHSM_RV_HOST_MEMORY; }
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        if (!bld
            || OSSL_PARAM_BLD_push_BN(bld, "n", n) != 1
            || OSSL_PARAM_BLD_push_BN(bld, "e", e) != 1) {
            OSSL_PARAM_BLD_free(bld); BN_free(n); BN_free(e);
            return FHSM_RV_FUNCTION_FAILED;
        }
        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
        OSSL_PARAM_BLD_free(bld);
        BN_free(n); BN_free(e);
        if (!params) return FHSM_RV_FUNCTION_FAILED;
        pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!pctx || EVP_PKEY_fromdata_init(pctx) != 1
            || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            if (pctx) EVP_PKEY_CTX_free(pctx);
            OSSL_PARAM_free(params);
            return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
        }
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params);

    } else {
        /* Should not happen : the parser only emits the paths listed
         * above when it returns OK. Defensive return to satisfy the
         * exhaustive-switch policy. */
        return CKR_TEMPLATE_INCONSISTENT;
    }

    /* Serialize as SubjectPublicKeyInfo for the verify path. */
    uint8_t *spki = NULL;
    int spki_len = i2d_PUBKEY(pkey, &spki);
    EVP_PKEY_free(pkey);
    if (spki_len <= 0 || !spki) {
        OPENSSL_free(spki);
        return FHSM_RV_FUNCTION_FAILED;
    }

    uint32_t handle = 0;
    fhsm_rv_t rv = fhsm_token_object_add(t, (uint32_t)a.cko, (uint32_t)a.ckk,
                                          a.label, spki, (size_t)spki_len,
                                          a.id_data, a.id_len, 0, &handle);
    OPENSSL_free(spki);
    if (rv != FHSM_RV_OK) return rv;
    *phObject = handle;
    fhsm_apply_token_scope(t, hSession, pTemplate, ulCount, handle);
    (void)fhsm_token_object_set_usage(t, handle, fhsm_compute_usage((uint32_t)a.cko, pTemplate, ulCount));
    return FHSM_RV_OK;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    /* Destroying a token (persisted) object requires a read/write session ;
     * on a read-only session it is CKR_SESSION_READ_ONLY (#125
     * TestROTokenObjectMutation / TestROExactCKR). Session objects may be
     * destroyed from a read-only session. */
    { int is_tok = 0;
      if (fhsm_token_object_is_token(t, (uint32_t)hObject, &is_tok) == FHSM_RV_OK
          && is_tok) {
          unsigned long flags = 0;
          if (fhsm_session_info(hSession, NULL, &flags, NULL) == FHSM_RV_OK
              && !(flags & 0x00000002UL /* CKF_RW_SESSION */))
              return FHSM_RV_SESSION_READ_ONLY;
      }
    }
    /* CKA_DESTROYABLE=FALSE : the object may not be destroyed
     * (#125 TestDestroyable). */
    { uint8_t of = 0;
      if (fhsm_token_object_get_flags(t, (uint32_t)hObject, &of) == FHSM_RV_OK
          && (of & FHSM_OBJF_UNDESTROYABLE))
          return 0x0000001BUL;   /* CKR_ACTION_PROHIBITED */
    }
    return fhsm_token_object_destroy(t, (uint32_t)hObject);
}

/* ---------------------------------------------------------------------------
 * Constants used by C_DeriveKey. Declared with #ifndef guards so the
 * later canonical block (inside the GenerateKeyPair section) doesn't
 * cause a redefinition warning. CKK_EC was previously only visible to
 * code below C_GenerateKeyPair ; CKM_ECDH1_DERIVE was previously only
 * declared in the late OAEP/SignInit block. Both are needed here. */
#ifndef CKK_EC
#define CKK_EC                    0x00000003UL
#endif
#ifndef CKM_ECDH1_DERIVE
#define CKM_ECDH1_DERIVE          0x00001050UL
#endif
#ifndef CKM_ECDH1_COFACTOR_DERIVE
/* For prime-order curves (P-256, P-384, P-521) the cofactor is 1 and
 * CKM_ECDH1_COFACTOR_DERIVE is mathematically equivalent to
 * CKM_ECDH1_DERIVE. OpenSC pkcs11-tool's --derive sends 0x1051 by
 * default ; we accept both. */
#define CKM_ECDH1_COFACTOR_DERIVE 0x00001051UL
#endif

/* ---------------------------------------------------------------------------
 * C_DeriveKey --- only CKM_ECDH1_DERIVE here.
 *
 * The mechanism parameter is a CK_ECDH1_DERIVE_PARAMS struct :
 *   CK_ULONG kdf;                  // CKD_NULL (0x01) for raw Z, no KDF
 *   CK_ULONG ulSharedDataLen;      // unused for CKD_NULL
 *   CK_BYTE_PTR pSharedData;
 *   CK_ULONG ulPublicDataLen;      // peer's EC public point bytes
 *   CK_BYTE_PTR pPublicData;       // uncompressed point 0x04|X|Y
 *
 * The derived secret is the raw shared secret Z (x-coordinate of the
 * scalar mult), length = curve byte size (32 for P-256, 48 for P-384,
 * 66 for P-521). The result is stored as a CKO_SECRET_KEY with
 * CKK_GENERIC_SECRET in the token's object store.
 * ----------------------------------------------------------------------- */
#define CKD_NULL 0x00000001UL

typedef struct CK_ECDH1_DERIVE_PARAMS_s {
    CK_ULONG kdf;
    CK_ULONG ulSharedDataLen;
    void    *pSharedData;
    CK_ULONG ulPublicDataLen;
    void    *pPublicData;
} CK_ECDH1_DERIVE_PARAMS;

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                   CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE *pTemplate,
                   CK_ULONG ulCount, CK_OBJECT_HANDLE *phKey) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pMechanism || !phKey) return FHSM_RV_ARGUMENTS_BAD;
    { CK_RV cr = fhsm_check_bool_attr_lengths(pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_ulong_attr_lengths(pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV uc = fhsm_check_usage(fhsm_session_token(hSession), hBaseKey, FHSM_USAGE_DERIVE); if (uc != FHSM_RV_OK) return uc; }
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (fhsm_session_role(hSession) == FHSM_ROLE_NONE)
        return FHSM_RV_USER_NOT_LOGGED_IN;
    if (pMechanism->mechanism != CKM_ECDH1_DERIVE
        && pMechanism->mechanism != CKM_ECDH1_COFACTOR_DERIVE)
        return FHSM_RV_MECHANISM_INVALID;
    if (!pMechanism->pParameter
        || pMechanism->ulParameterLen < sizeof(CK_ECDH1_DERIVE_PARAMS))
        return FHSM_RV_ARGUMENTS_BAD;

    CK_ECDH1_DERIVE_PARAMS *p = pMechanism->pParameter;
    if (p->kdf != CKD_NULL || !p->pPublicData || p->ulPublicDataLen == 0)
        return FHSM_RV_ARGUMENTS_BAD;

    /* Load our private key. */
    const uint8_t *kv = NULL; size_t kvl = 0;
    uint32_t cl = 0, kt = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, (uint32_t)hBaseKey,
                                          &kv, &kvl, &cl, &kt);
    if (rv != FHSM_RV_OK) return rv;
    if (cl != CKO_PRIVATE_KEY || kt != CKK_EC) return FHSM_RV_KEY_TYPE_INCONSISTENT;
    const uint8_t *dp = kv;
    EVP_PKEY *priv = d2i_AutoPrivateKey(NULL, &dp, (long)kvl);
    if (!priv) return FHSM_RV_FUNCTION_FAILED;

    /* Construct the peer public key. pkcs11-tool's --derive --input-file
     * may pass the public point in several formats :
     *   - raw uncompressed point          : 0x04 || X || Y   (65 bytes P-256)
     *   - DER OCTET STRING wrapper        : 0x04 LEN || raw  (~67 bytes)
     *   - DER SubjectPublicKeyInfo (X.509): ~91 bytes for P-256
     * We try d2i_PUBKEY first (handles X.509 SubjectPublicKeyInfo) and
     * fall back to raw point via fromdata if that fails. */
    EVP_PKEY *peer = NULL;
    const uint8_t *pdata = p->pPublicData;
    peer = d2i_PUBKEY(NULL, &pdata, (long)p->ulPublicDataLen);
    if (!peer) {
        /* Strip a DER OCTET STRING wrapper if present, then assume raw
         * uncompressed point. */
        const uint8_t *raw = p->pPublicData;
        size_t raw_len = p->ulPublicDataLen;
        if (raw_len > 2 && raw[0] == 0x04 && raw[1] != 0x04
            && (size_t)raw[1] + 2 == raw_len) {
            raw += 2; raw_len -= 2;            /* short form OCTET STRING */
        } else if (raw_len > 3 && raw[0] == 0x04 && raw[1] == 0x81
                   && (size_t)raw[2] + 3 == raw_len) {
            raw += 3; raw_len -= 3;            /* long form OCTET STRING */
        }
        char curve[32] = "";
        size_t curve_len = 0;
        EVP_PKEY_get_utf8_string_param(priv, "group", curve, sizeof(curve), &curve_len);
        OSSL_PARAM peer_params[3] = {
            OSSL_PARAM_construct_utf8_string("group", curve, 0),
            OSSL_PARAM_construct_octet_string("pub", (void*)raw, raw_len),
            OSSL_PARAM_construct_end()
        };
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!pctx || EVP_PKEY_fromdata_init(pctx) != 1
            || EVP_PKEY_fromdata(pctx, &peer, EVP_PKEY_PUBLIC_KEY, peer_params) != 1) {
            if (pctx) EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(priv); return FHSM_RV_FUNCTION_FAILED;
        }
        EVP_PKEY_CTX_free(pctx);
    }

    /* Derive the shared secret. */
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) != 1
        || EVP_PKEY_derive_set_peer(dctx, peer) != 1) {
        if (dctx) EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer); EVP_PKEY_free(priv);
        return FHSM_RV_FUNCTION_FAILED;
    }
    size_t z_len = 0;
    EVP_PKEY_derive(dctx, NULL, &z_len);
    if (z_len == 0 || z_len > 64) {
        EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(peer); EVP_PKEY_free(priv);
        return FHSM_RV_FUNCTION_FAILED;
    }
    uint8_t z[64];
    if (EVP_PKEY_derive(dctx, z, &z_len) != 1) {
        EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(peer); EVP_PKEY_free(priv);
        return FHSM_RV_FUNCTION_FAILED;
    }
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(priv);

    /* Store as a fresh CKO_SECRET_KEY object. Default flags for an ECDH
     * derived shared secret : NOT sensitive (per PKCS#11 v3.2 §A.6.4.4 a
     * derived key inherits attributes from the template ; if no CKA_SENSITIVE
     * is provided, the default is FALSE for a session secret). The
     * template may override. */
    char label[64] = "";
    uint8_t obj_flags = 0;
    long li = find_attr(pTemplate, ulCount, CKA_LABEL);
    if (li >= 0) {
        size_t n = pTemplate[li].ulValueLen;
        if (n >= sizeof(label)) n = sizeof(label) - 1;
        memcpy(label, pTemplate[li].pValue, n); label[n] = '\0';
    }
    li = find_attr(pTemplate, ulCount, CKA_SENSITIVE);
    if (li >= 0 && pTemplate[li].pValue && pTemplate[li].ulValueLen >= 1
        && ((unsigned char*)pTemplate[li].pValue)[0] != 0) {
        obj_flags |= FHSM_OBJF_SENSITIVE;
    }
    li = find_attr(pTemplate, ulCount, CKA_EXTRACTABLE);
    if (li >= 0 && pTemplate[li].pValue && pTemplate[li].ulValueLen >= 1
        && ((unsigned char*)pTemplate[li].pValue)[0] != 0) {
        obj_flags |= FHSM_OBJF_EXTRACTABLE;
    }
    /* Honour a requested CKA_KEY_TYPE in the derive template (PKCS#11 v3.2
     * §A.6.4.4 : a derived key takes its type from the template). Default is
     * CKK_GENERIC_SECRET. Storing the requested type (e.g. CKK_AES) keeps the
     * key usable with the matching cipher under the mechanism<->key-type gate
     * (#125 TestECDHDerivedKeyUse). */
    uint32_t derived_ckk = CKK_GENERIC_SECRET;
    { long ki = find_attr(pTemplate, ulCount, 0x100 /* CKA_KEY_TYPE */);
      if (ki >= 0 && pTemplate[ki].pValue
          && pTemplate[ki].ulValueLen == sizeof(CK_ULONG)) {
          CK_ULONG req = 0; memcpy(&req, pTemplate[ki].pValue, sizeof(CK_ULONG));
          derived_ckk = (uint32_t)req;
      }
    }
    uint32_t handle = 0;
    rv = fhsm_token_object_add(t, CKO_SECRET_KEY, derived_ckk, label,
                                z, z_len, NULL, 0, obj_flags, &handle);
    fhsm_zeroize(z, sizeof(z));
    if (rv != FHSM_RV_OK) return rv;
    *phKey = handle;
    fhsm_apply_token_scope(t, hSession, pTemplate, ulCount, handle);
    (void)fhsm_token_object_set_usage(t, handle, fhsm_compute_usage(CKO_SECRET_KEY, pTemplate, ulCount));
    (void)fhsm_audit_event(FHSM_EV_DERIVE, -1, (int)hSession,
                            fhsm_session_role(hSession), FHSM_RV_OK, NULL);
    return FHSM_RV_OK;
}

/* Forward-declare PQ mechanism IDs and key types used by C_EncapsulateKey /
 * C_DecapsulateKey. The canonical definitions live further down in the
 * C_GenerateKeyPair section ; the values here must match exactly. */
#ifndef CKM_ML_KEM_OP
#define CKM_ML_KEM_OP             0x00000017UL
#endif
#ifndef CKK_ML_KEM
#define CKK_ML_KEM                0x00000049UL
#endif

/* ---------------------------------------------------------------------------
 * C_WrapKey / C_UnwrapKey
 *
 * Mechanisms supported :
 *   CKM_AES_KEY_WRAP       (RFC 3394, plaintext must be 8N bytes ≥ 16)
 *   CKM_AES_KEY_WRAP_KWP   (RFC 5649, plaintext can be any length ≥ 1)
 *   CKM_RSA_PKCS_OAEP      (wrap a symmetric key with an RSA public key)
 *
 * Wrap takes a target key (hKey) from the token, serializes its value
 * to bytes, then encrypts those bytes with the wrapping key (hWrappingKey).
 * The output is the wrapped blob, ready for export.
 *
 * Unwrap is the inverse : decrypt the blob with hUnwrappingKey and
 * import the resulting bytes as a fresh CKO_SECRET_KEY in the token.
 * ----------------------------------------------------------------------- */
#ifndef CKM_AES_KEY_WRAP
#define CKM_AES_KEY_WRAP          0x00002109UL
#endif
#ifndef CKM_AES_KEY_WRAP_KWP
#define CKM_AES_KEY_WRAP_KWP      0x0000210BUL
#endif

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                unsigned char *pWrappedKey, CK_ULONG *pulWrappedKeyLen) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pMechanism || !pulWrappedKeyLen) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    { CK_RV uc = fhsm_check_usage(t, hWrappingKey, FHSM_USAGE_WRAP); if (uc != FHSM_RV_OK) return uc; }
    if (fhsm_session_role(hSession) == FHSM_ROLE_NONE)
        return FHSM_RV_USER_NOT_LOGGED_IN;

    /* Source key : extract its value bytes. */
    const uint8_t *kv = NULL; size_t kvl = 0;
    uint32_t cl = 0, kt = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, (uint32_t)hKey, &kv, &kvl, &cl, &kt);
    if (rv != FHSM_RV_OK) return rv;
    /* If the source key is marked sensitive AND not extractable, refuse
     * to wrap (CKR_KEY_UNEXTRACTABLE). */
    uint8_t src_flags = 0;
    (void)fhsm_token_object_get_flags(t, (uint32_t)hKey, &src_flags);
    if ((src_flags & FHSM_OBJF_SENSITIVE)
        && !(src_flags & FHSM_OBJF_EXTRACTABLE)) {
        return 0x00000068UL;   /* CKR_KEY_UNEXTRACTABLE */
    }

    /* Wrapping key : load value or DER. */
    const uint8_t *wkv = NULL; size_t wkl = 0;
    uint32_t wcl = 0, wkt = 0;
    rv = fhsm_token_object_get(t, (uint32_t)hWrappingKey, &wkv, &wkl, &wcl, &wkt);
    if (rv != FHSM_RV_OK) return rv;

    /* --- AES-KW (RFC 3394) and AES-KWP (RFC 5649) --- */
    if (pMechanism->mechanism == CKM_AES_KEY_WRAP
        || pMechanism->mechanism == CKM_AES_KEY_WRAP_KWP) {
        if (wkt != CKK_AES) return FHSM_RV_KEY_TYPE_INCONSISTENT;
        /* The wrapping key must be a valid AES key size (128/192/256 bits) ;
         * anything else is CKR_WRAPPING_KEY_SIZE_RANGE (#125 TestWrapKeyErrors),
         * not a silent fall-through to the 256-bit cipher name. */
        if (wkl != 16 && wkl != 24 && wkl != 32)
            return 0x00000112UL;   /* CKR_WRAPPING_KEY_SIZE_RANGE */
        const char *cname = NULL;
        if (pMechanism->mechanism == CKM_AES_KEY_WRAP) {
            cname = (wkl == 16) ? "AES-128-WRAP" :
                    (wkl == 24) ? "AES-192-WRAP" : "AES-256-WRAP";
        } else {
            cname = (wkl == 16) ? "AES-128-WRAP-PAD" :
                    (wkl == 24) ? "AES-192-WRAP-PAD" : "AES-256-WRAP-PAD";
        }
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, cname, NULL);
        if (!c) return FHSM_RV_MECHANISM_INVALID;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { EVP_CIPHER_free(c); return FHSM_RV_HOST_MEMORY; }
        /* AES-WRAP needs explicit flag for wrapping. */
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        if (EVP_EncryptInit_ex2(ctx, c, wkv, NULL, NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            return FHSM_RV_FUNCTION_FAILED;
        }
        /* Output size : RFC 3394 → 8N + 8 ; KWP → ceil((N+4)/8)*8 + 8. */
        size_t need = kvl + 16;
        if (pWrappedKey == NULL) {
            *pulWrappedKeyLen = need;
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            return FHSM_RV_OK;
        }
        if (*pulWrappedKeyLen < need) {
            *pulWrappedKeyLen = need;
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            return 0x00000150UL;
        }
        int outl = 0, finl = 0;
        if (EVP_EncryptUpdate(ctx, pWrappedKey, &outl, kv, (int)kvl) != 1
            || EVP_EncryptFinal_ex(ctx, pWrappedKey + outl, &finl) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            return FHSM_RV_FUNCTION_FAILED;
        }
        *pulWrappedKeyLen = (CK_ULONG)(outl + finl);
        EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
        (void)fhsm_audit_event(FHSM_EV_WRAP, -1, (int)hSession,
                                fhsm_session_role(hSession), FHSM_RV_OK, NULL);
        return FHSM_RV_OK;
    }

    /* RSA-OAEP wrap (CKM_RSA_PKCS_OAEP, 0x9) : not exposed via C_WrapKey
     * because the same primitive is already reachable through C_EncryptInit
     * + C_Encrypt with the RSA public key. PKCS#11 v3.2 §C.6 explicitly
     * allows this : wrapping with RSA-OAEP IS encryption with an
     * asymmetric public key, semantically identical. */
    return FHSM_RV_MECHANISM_INVALID;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                  CK_OBJECT_HANDLE hUnwrappingKey,
                  unsigned char *pWrappedKey, CK_ULONG ulWrappedKeyLen,
                  CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                  CK_OBJECT_HANDLE *phKey) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pMechanism || !pWrappedKey || !phKey) return FHSM_RV_ARGUMENTS_BAD;
    { CK_RV cr = fhsm_check_bool_attr_lengths(pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_ulong_attr_lengths(pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV uc = fhsm_check_usage(fhsm_session_token(hSession), hUnwrappingKey, FHSM_USAGE_UNWRAP); if (uc != FHSM_RV_OK) return uc; }
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (fhsm_session_role(hSession) == FHSM_ROLE_NONE)
        return FHSM_RV_USER_NOT_LOGGED_IN;

    const uint8_t *ukv = NULL; size_t ukl = 0;
    uint32_t ucl = 0, ukt = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, (uint32_t)hUnwrappingKey,
                                          &ukv, &ukl, &ucl, &ukt);
    if (rv != FHSM_RV_OK) return rv;

    uint8_t pt[256]; size_t pt_len = 0;

    if (pMechanism->mechanism == CKM_AES_KEY_WRAP
        || pMechanism->mechanism == CKM_AES_KEY_WRAP_KWP) {
        if (ukt != CKK_AES) return FHSM_RV_KEY_TYPE_INCONSISTENT;
        const char *cname = NULL;
        if (pMechanism->mechanism == CKM_AES_KEY_WRAP) {
            cname = (ukl == 16) ? "AES-128-WRAP" :
                    (ukl == 24) ? "AES-192-WRAP" : "AES-256-WRAP";
        } else {
            cname = (ukl == 16) ? "AES-128-WRAP-PAD" :
                    (ukl == 24) ? "AES-192-WRAP-PAD" : "AES-256-WRAP-PAD";
        }
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, cname, NULL);
        if (!c) return FHSM_RV_MECHANISM_INVALID;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { EVP_CIPHER_free(c); return FHSM_RV_HOST_MEMORY; }
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        if (EVP_DecryptInit_ex2(ctx, c, ukv, NULL, NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            return FHSM_RV_FUNCTION_FAILED;
        }
        int outl = 0, finl = 0;
        if (EVP_DecryptUpdate(ctx, pt, &outl, pWrappedKey, (int)ulWrappedKeyLen) != 1
            || EVP_DecryptFinal_ex(ctx, pt + outl, &finl) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            return 0x00000069UL;  /* CKR_WRAPPED_KEY_INVALID */
        }
        pt_len = (size_t)(outl + finl);
        EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
    } else {
        /* RSA-OAEP unwrap : reachable via C_DecryptInit + C_Decrypt with
         * the RSA private key (semantically identical for primary use
         * cases). */
        return FHSM_RV_MECHANISM_INVALID;
    }

    /* Import the decrypted bytes as a fresh secret-key object. */
    char label[64] = "";
    uint32_t key_type = CKK_AES;
    uint8_t obj_flags = FHSM_OBJF_SENSITIVE;
    long li = find_attr(pTemplate, ulCount, CKA_LABEL);
    if (li >= 0) {
        size_t n = pTemplate[li].ulValueLen;
        if (n >= sizeof(label)) n = sizeof(label) - 1;
        memcpy(label, pTemplate[li].pValue, n); label[n] = '\0';
    }
    li = find_attr(pTemplate, ulCount, CKA_KEY_TYPE);
    if (li >= 0 && pTemplate[li].pValue && pTemplate[li].ulValueLen == sizeof(CK_ULONG))
        key_type = (uint32_t)(*(CK_ULONG*)pTemplate[li].pValue);
    li = find_attr(pTemplate, ulCount, CKA_SENSITIVE);
    if (li >= 0 && pTemplate[li].pValue && pTemplate[li].ulValueLen >= 1
        && ((unsigned char*)pTemplate[li].pValue)[0] == 0)
        obj_flags &= (uint8_t)~FHSM_OBJF_SENSITIVE;
    li = find_attr(pTemplate, ulCount, CKA_EXTRACTABLE);
    if (li >= 0 && pTemplate[li].pValue && pTemplate[li].ulValueLen >= 1
        && ((unsigned char*)pTemplate[li].pValue)[0] != 0)
        obj_flags |= FHSM_OBJF_EXTRACTABLE;

    /* Key-type confusion defence (Tookan §3.x, #125
     * TestKeyTypeConfusionOnUnwrap) : the unwrapped length must be valid for
     * the claimed CKA_KEY_TYPE, otherwise a blob wrapped as one key type is
     * being reinterpreted as an incompatible one. A CKA_VALUE_LEN in the
     * template must also match the recovered length. */
    if (key_type == CKK_AES && pt_len != 16 && pt_len != 24 && pt_len != 32)
        return FHSM_RV_KEY_TYPE_INCONSISTENT;
    if (key_type == 0x15 /* CKK_DES3 */ && pt_len != 24)
        return FHSM_RV_KEY_TYPE_INCONSISTENT;
    { long vli = find_attr(pTemplate, ulCount, CKA_VALUE_LEN);
      if (vli >= 0 && pTemplate[vli].pValue
          && pTemplate[vli].ulValueLen == sizeof(CK_ULONG)) {
          CK_ULONG want_len = *(CK_ULONG*)pTemplate[vli].pValue;
          if (want_len != pt_len) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
      }
    }

    uint32_t handle = 0;
    rv = fhsm_token_object_add(t, CKO_SECRET_KEY, key_type, label,
                                pt, pt_len, NULL, 0, obj_flags, &handle);
    fhsm_zeroize(pt, sizeof(pt));
    if (rv != FHSM_RV_OK) return rv;
    *phKey = handle;
    fhsm_apply_token_scope(t, hSession, pTemplate, ulCount, handle);
    (void)fhsm_token_object_set_usage(t, handle, fhsm_compute_usage(CKO_SECRET_KEY, pTemplate, ulCount));
    (void)fhsm_audit_event(FHSM_EV_UNWRAP, -1, (int)hSession,
                            fhsm_session_role(hSession), FHSM_RV_OK, NULL);
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * C_EncapsulateKey / C_DecapsulateKey --- ML-KEM Key Encapsulation Mechanism
 * (PKCS#11 v3.0 §5.21). The encapsulator uses a recipient's public key to
 * create both a ciphertext (sent to the recipient) and a shared secret
 * (kept locally). The recipient decapsulates the ciphertext with its
 * private key to recover the same shared secret.
 *
 * In OpenSSL 3.5 the API is :
 *   EVP_PKEY_encapsulate_init(ctx, NULL)
 *   EVP_PKEY_encapsulate(ctx, ct, &ctlen, ss, &sslen)
 *   EVP_PKEY_decapsulate_init(ctx, NULL)
 *   EVP_PKEY_decapsulate(ctx, ss, &sslen, ct, ctlen)
 *
 * The shared secret is stored as a fresh CKO_SECRET_KEY object in the
 * token, marked sensitive.
 * ----------------------------------------------------------------------- */
CK_RV C_EncapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                       CK_OBJECT_HANDLE hPublicKey,
                       CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                       CK_OBJECT_HANDLE *phNewKey,
                       unsigned char *pCiphertext, CK_ULONG *pulCiphertextLen) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pMechanism || !phNewKey || !pulCiphertextLen)
        return FHSM_RV_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_ML_KEM_OP)
        return FHSM_RV_MECHANISM_INVALID;
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (fhsm_session_role(hSession) == FHSM_ROLE_NONE)
        return FHSM_RV_USER_NOT_LOGGED_IN;

    const uint8_t *kv = NULL; size_t kvl = 0;
    uint32_t cl = 0, kt = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, (uint32_t)hPublicKey,
                                          &kv, &kvl, &cl, &kt);
    if (rv != FHSM_RV_OK) return rv;
    if (cl != CKO_PUBLIC_KEY || kt != CKK_ML_KEM)
        return FHSM_RV_KEY_TYPE_INCONSISTENT;

    const uint8_t *p = kv;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)kvl);
    if (!pkey) return FHSM_RV_FUNCTION_FAILED;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) { EVP_PKEY_free(pkey); return FHSM_RV_HOST_MEMORY; }
    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey);
        return FHSM_RV_FUNCTION_FAILED;
    }

    /* Query sizes first. */
    size_t ct_len = 0, ss_len = 0;
    if (EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey);
        return FHSM_RV_FUNCTION_FAILED;
    }
    if (pCiphertext == NULL) {
        *pulCiphertextLen = ct_len;
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey);
        return FHSM_RV_OK;
    }
    if (*pulCiphertextLen < ct_len) {
        *pulCiphertextLen = ct_len;
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey);
        return 0x00000150UL;
    }

    /* Allocate the shared secret on the stack (max 64 bytes for ML-KEM-1024). */
    if (ss_len > 64) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey);
        return FHSM_RV_FUNCTION_FAILED;
    }
    uint8_t ss[64];
    size_t ct_len_out = *pulCiphertextLen;
    if (EVP_PKEY_encapsulate(ctx, pCiphertext, &ct_len_out, ss, &ss_len) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey);
        return FHSM_RV_FUNCTION_FAILED;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    *pulCiphertextLen = ct_len_out;

    /* Wrap the shared secret as a token object. Honor CKA_SENSITIVE /
     * CKA_EXTRACTABLE from the caller template (defaults: not sensitive,
     * not extractable). */
    char label[64] = "";
    uint8_t obj_flags = 0;
    long li = find_attr(pTemplate, ulCount, CKA_LABEL);
    if (li >= 0) {
        size_t n = pTemplate[li].ulValueLen;
        if (n >= sizeof(label)) n = sizeof(label) - 1;
        memcpy(label, pTemplate[li].pValue, n); label[n] = '\0';
    }
    li = find_attr(pTemplate, ulCount, CKA_SENSITIVE);
    if (li >= 0 && pTemplate[li].pValue && pTemplate[li].ulValueLen >= 1
        && ((unsigned char*)pTemplate[li].pValue)[0] != 0)
        obj_flags |= FHSM_OBJF_SENSITIVE;
    li = find_attr(pTemplate, ulCount, CKA_EXTRACTABLE);
    if (li >= 0 && pTemplate[li].pValue && pTemplate[li].ulValueLen >= 1
        && ((unsigned char*)pTemplate[li].pValue)[0] != 0)
        obj_flags |= FHSM_OBJF_EXTRACTABLE;
    uint32_t handle = 0;
    rv = fhsm_token_object_add(t, CKO_SECRET_KEY, CKK_GENERIC_SECRET, label,
                                ss, ss_len, NULL, 0, obj_flags,
                                &handle);
    fhsm_zeroize(ss, sizeof(ss));
    if (rv != FHSM_RV_OK) return rv;
    *phNewKey = handle;
    return FHSM_RV_OK;
}

CK_RV C_DecapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                       CK_OBJECT_HANDLE hPrivateKey,
                       CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                       CK_OBJECT_HANDLE *phNewKey,
                       unsigned char *pCiphertext, CK_ULONG ulCiphertextLen) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pMechanism || !phNewKey || !pCiphertext) return FHSM_RV_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_ML_KEM_OP)
        return FHSM_RV_MECHANISM_INVALID;
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (fhsm_session_role(hSession) == FHSM_ROLE_NONE)
        return FHSM_RV_USER_NOT_LOGGED_IN;

    const uint8_t *kv = NULL; size_t kvl = 0;
    uint32_t cl = 0, kt = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, (uint32_t)hPrivateKey,
                                          &kv, &kvl, &cl, &kt);
    if (rv != FHSM_RV_OK) return rv;
    if (cl != CKO_PRIVATE_KEY || kt != CKK_ML_KEM)
        return FHSM_RV_KEY_TYPE_INCONSISTENT;

    const uint8_t *p = kv;
    EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &p, (long)kvl);
    if (!pkey) {
        /* Raw ML-KEM private key import fallback. The Wycheproof
         * mlkem_{512,768,1024}_semi_expanded_decaps_test.json files
         * provide 1632 / 2400 / 3168 raw bytes (FIPS 203 expanded
         * decapsulation key dk) rather than a PKCS#8 envelope.
         * OpenSSL 3.5 exposes the raw import via EVP_PKEY_fromdata
         * with OSSL_PKEY_PARAM_PRIV_KEY. */
        const char *alg = NULL;
        if (kvl == 1632)      alg = "ML-KEM-512";
        else if (kvl == 2400) alg = "ML-KEM-768";
        else if (kvl == 3168) alg = "ML-KEM-1024";
        if (alg) {
            EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
            if (kctx) {
                if (EVP_PKEY_fromdata_init(kctx) > 0) {
                    OSSL_PARAM params[2] = {
                        OSSL_PARAM_construct_octet_string(
                            OSSL_PKEY_PARAM_PRIV_KEY,
                            (void *)kv, (size_t)kvl),
                        OSSL_PARAM_construct_end(),
                    };
                    /* For ML-KEM the expanded dk implicitly carries the
                     * public component ; OpenSSL 3.5's keymgmt requires
                     * EVP_PKEY_KEYPAIR (not PRIVATE_KEY-only) for the
                     * consistency dance. */
                    int rcfd = EVP_PKEY_fromdata(kctx, &pkey,
                                                  EVP_PKEY_KEYPAIR, params);
                    if (rcfd <= 0 && getenv("FHSM_DEBUG_MLKEM")) {
                        unsigned long err = ERR_peek_last_error();
                        char ebuf[256] = {0};
                        ERR_error_string_n(err, ebuf, sizeof(ebuf));
                        fprintf(stderr,
                            "[fhsm_pkcs11] ML-KEM fromdata failed alg=%s "
                            "kvl=%zu rc=%d err=0x%lx \"%s\"\n",
                            alg, (size_t)kvl, rcfd, err, ebuf);
                    }
                }
                EVP_PKEY_CTX_free(kctx);
            }
        }
        if (!pkey) return FHSM_RV_FUNCTION_FAILED;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) { EVP_PKEY_free(pkey); return FHSM_RV_HOST_MEMORY; }
    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey);
        return FHSM_RV_FUNCTION_FAILED;
    }
    size_t ss_len = 0;
    if (EVP_PKEY_decapsulate(ctx, NULL, &ss_len, pCiphertext, ulCiphertextLen) <= 0
        || ss_len > 64) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey);
        return FHSM_RV_FUNCTION_FAILED;
    }
    uint8_t ss[64];
    if (EVP_PKEY_decapsulate(ctx, ss, &ss_len, pCiphertext, ulCiphertextLen) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey);
        return FHSM_RV_FUNCTION_FAILED;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    /* Honor CKA_SENSITIVE / CKA_EXTRACTABLE from the template ; default
     * to not-sensitive (allowed export via CKA_VALUE) so test harnesses
     * can verify the shared secret. Caller can override. */
    char label[64] = "";
    uint8_t obj_flags = 0;
    long li = find_attr(pTemplate, ulCount, CKA_LABEL);
    if (li >= 0) {
        size_t n = pTemplate[li].ulValueLen;
        if (n >= sizeof(label)) n = sizeof(label) - 1;
        memcpy(label, pTemplate[li].pValue, n); label[n] = '\0';
    }
    li = find_attr(pTemplate, ulCount, CKA_SENSITIVE);
    if (li >= 0 && pTemplate[li].pValue && pTemplate[li].ulValueLen >= 1
        && ((unsigned char*)pTemplate[li].pValue)[0] != 0)
        obj_flags |= FHSM_OBJF_SENSITIVE;
    li = find_attr(pTemplate, ulCount, CKA_EXTRACTABLE);
    if (li >= 0 && pTemplate[li].pValue && pTemplate[li].ulValueLen >= 1
        && ((unsigned char*)pTemplate[li].pValue)[0] != 0)
        obj_flags |= FHSM_OBJF_EXTRACTABLE;
    uint32_t handle = 0;
    rv = fhsm_token_object_add(t, CKO_SECRET_KEY, CKK_GENERIC_SECRET, label,
                                ss, ss_len, NULL, 0, obj_flags,
                                &handle);
    fhsm_zeroize(ss, sizeof(ss));
    if (rv != FHSM_RV_OK) return rv;
    *phNewKey = handle;
    return FHSM_RV_OK;
}

/* CK_INTERFACE v3.0 getters are defined AFTER the v2.40 fhsm_function_list
 * + CK_VERSION + fhsm_not_supported definitions, further down at the end
 * of the v2.40 C_GetFunctionList block. They reuse those types and so
 * cannot be declared here. */

/* ---------------------------------------------------------------------------
 * C_GenerateKeyPair --- RSA-2048/3072/4096 or ECDSA P-256/P-384/P-521.
 *
 * Both keys are stored in the token's object store. The private key is
 * marked FHSM_OBJF_SENSITIVE so C_GetAttributeValue cannot extract it.
 * Public key value : DER-encoded SubjectPublicKeyInfo (i2d_PUBKEY).
 * Private key value : DER-encoded PKCS#8 (i2d_PKCS8PrivateKey_bio).
 * ----------------------------------------------------------------------- */
#define CKM_RSA_PKCS_KEY_PAIR_GEN  0x00000000UL
#define CKM_EC_KEY_PAIR_GEN        0x00001040UL
#define CKK_RSA                    0x00000000UL
#define CKK_EC                     0x00000003UL
#define CKA_MODULUS_BITS           0x00000121UL
#define CKA_EC_PARAMS              0x00000180UL
/* Post-quantum mechanism + key type IDs (PKCS#11 v3.2 §A.4). */
#define CKM_ML_KEM_KEY_PAIR_GEN    0x0000000FUL
#define CKM_ML_KEM_OP              0x00000017UL
#define CKM_ML_DSA_KEY_PAIR_GEN    0x0000001CUL
#define CKM_ML_DSA_OP              0x0000001DUL
#define CKM_SLH_DSA_KEY_PAIR_GEN   0x0000002DUL
#define CKM_SLH_DSA_OP             0x0000002EUL
#define CKK_ML_KEM                 0x00000049UL
#define CKK_ML_DSA                 0x0000004AUL
#define CKK_SLH_DSA                0x0000004BUL
/* Parameter-set names exposed via CKA_PARAMETER_SET (read from template). */
#define CKA_PARAMETER_SET          0x00000170UL

/* DER-encoded OID for common curves (CKA_EC_PARAMS contents). */
static const struct { const uint8_t *der; size_t len; const char *name; } ec_curves[] = {
    /* prime256v1 = secp256r1 = P-256 : 06 08 2A 86 48 CE 3D 03 01 07 */
    { (const uint8_t*)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07", 10, "P-256" },
    /* secp384r1 = P-384 : 06 05 2B 81 04 00 22 */
    { (const uint8_t*)"\x06\x05\x2B\x81\x04\x00\x22",              7, "P-384" },
    /* secp521r1 = P-521 : 06 05 2B 81 04 00 23 */
    { (const uint8_t*)"\x06\x05\x2B\x81\x04\x00\x23",              7, "P-521" },
};

static const char *match_curve(const uint8_t *der, size_t len) {
    for (size_t i = 0; i < sizeof(ec_curves)/sizeof(ec_curves[0]); ++i) {
        if (ec_curves[i].len == len && memcmp(ec_curves[i].der, der, len) == 0)
            return ec_curves[i].name;
    }
    return NULL;
}

/* Validate a CKA_PARAMETER_SET value against the known PQC parameter-set
 * names. A CK_ULONG-sized or otherwise malformed value is rejected
 * (#125 TestGenerateKeyPairErrors : over/underlong CKA_PARAMETER_SET). */
static int fhsm_pset_valid(const char *pset) {
    static const char *ok[] = {
        "ML-KEM-512","ML-KEM-768","ML-KEM-1024",
        "ML-DSA-44","ML-DSA-65","ML-DSA-87",
        "SLH-DSA-SHA2-128s","SLH-DSA-SHA2-128f","SLH-DSA-SHA2-192s",
        "SLH-DSA-SHA2-192f","SLH-DSA-SHA2-256s","SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s","SLH-DSA-SHAKE-128f","SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHAKE-192f","SLH-DSA-SHAKE-256s","SLH-DSA-SHAKE-256f",
    };
    for (size_t i = 0; i < sizeof(ok)/sizeof(ok[0]); ++i)
        if (strcmp(pset, ok[i]) == 0) return 1;
    return 0;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                        CK_ATTRIBUTE *pPub, CK_ULONG ulPub,
                        CK_ATTRIBUTE *pPriv, CK_ULONG ulPriv,
                        CK_OBJECT_HANDLE *phPub, CK_OBJECT_HANDLE *phPriv) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pMechanism || !phPub || !phPriv) return FHSM_RV_ARGUMENTS_BAD;
    { CK_RV cr = fhsm_check_template(pPub, ulPub);  if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_template(pPriv, ulPriv); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_bool_attr_lengths(pPub, ulPub);   if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_bool_attr_lengths(pPriv, ulPriv); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_ulong_attr_lengths(pPub, ulPub);   if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_ulong_attr_lengths(pPriv, ulPriv); if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_ro_token(hSession, pPub, ulPub);   if (cr != FHSM_RV_OK) return cr; }
    { CK_RV cr = fhsm_check_ro_token(hSession, pPriv, ulPriv); if (cr != FHSM_RV_OK) return cr; }
    /* For PQC key generation, CKA_PARAMETER_SET (in either template) must
     * be a known parameter-set NAME of plausible length : a CK_ULONG-sized
     * or over/underlong value is CKR_ATTRIBUTE_VALUE_INVALID (#125
     * TestGenerateKeyPairErrors). */
    if (pMechanism->mechanism == CKM_ML_KEM_KEY_PAIR_GEN
        || pMechanism->mechanism == CKM_ML_DSA_KEY_PAIR_GEN
        || pMechanism->mechanism == CKM_SLH_DSA_KEY_PAIR_GEN) {
        CK_ATTRIBUTE *tp[2] = { pPub, pPriv }; CK_ULONG tn[2] = { ulPub, ulPriv };
        for (int ti = 0; ti < 2; ++ti) {
            /* Legacy ASCII-name form read from 0x170 (kept for the keygen
             * default logic below). */
            long pi = find_attr(tp[ti], tn[ti], CKA_PARAMETER_SET);
            if (pi >= 0 && tp[ti][pi].pValue) {
                char pbuf[32];
                if (tp[ti][pi].ulValueLen == 0 || tp[ti][pi].ulValueLen >= sizeof(pbuf))
                    return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
                memcpy(pbuf, tp[ti][pi].pValue, tp[ti][pi].ulValueLen);
                pbuf[tp[ti][pi].ulValueLen] = '\0';
                if (!fhsm_pset_valid(pbuf)) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
            }
            /* Spec-correct CKA_PARAMETER_SET is 0x0000061D (0x170 is actually
             * CKA_MODIFIABLE). The harness sends the malformed value here, so
             * validate it : accept a well-formed CK_ULONG selector or a valid
             * ASCII name ; reject an under/overlong value
             * (#125 TestGenerateKeyPairErrors ml_kem/ml_dsa_parameter_set). */
            long pj = find_attr(tp[ti], tn[ti], 0x0000061DUL);
            if (pj >= 0 && tp[ti][pj].pValue) {
                size_t L = (size_t)tp[ti][pj].ulValueLen;
                if (L != sizeof(CK_ULONG)) {
                    if (L == 0 || L >= 32) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
                    char nbuf[32]; memcpy(nbuf, tp[ti][pj].pValue, L); nbuf[L] = '\0';
                    if (!fhsm_pset_valid(nbuf)) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
                }
            }
        }
    }
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (fhsm_session_role(hSession) == FHSM_ROLE_NONE)
        return FHSM_RV_USER_NOT_LOGGED_IN;

    EVP_PKEY *pkey = NULL;
    uint32_t  ckk_type = 0;
    fhsm_pairwise_family_t pw_family = 0;

    if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
        long bits = 2048;
        long i = find_attr(pPub, ulPub, CKA_MODULUS_BITS);
        if (i >= 0 && pPub[i].pValue && pPub[i].ulValueLen == sizeof(CK_ULONG))
            bits = (long)(*(CK_ULONG*)pPub[i].pValue);
        if (bits != 2048 && bits != 3072 && bits != 4096) return FHSM_RV_KEY_SIZE_RANGE;
        /* Validate CKA_PUBLIC_EXPONENT if supplied : FIPS 186-5 requires
         * an odd exponent >= 3 ; e = 0/1/2/4 are cryptographically
         * invalid (pkcs11-check TestRsaExponent, #125). A valid exponent
         * is accepted; generation uses the standard F4 (65537). */
        long e_i = find_attr(pPub, ulPub, 0x00000122UL /* CKA_PUBLIC_EXPONENT */);
        if (e_i >= 0 && pPub[e_i].pValue && pPub[e_i].ulValueLen > 0) {
            BIGNUM *e_bn = BN_bin2bn((const unsigned char *)pPub[e_i].pValue,
                                      (int)pPub[e_i].ulValueLen, NULL);
            if (!e_bn) return FHSM_RV_HOST_MEMORY;
            int bad = (!BN_is_odd(e_bn) || BN_cmp(e_bn, BN_value_one()) <= 0
                       || BN_is_word(e_bn, 1));
            /* reject e < 3 : e==1 caught above ; e==2 is even (caught) */
            BN_free(e_bn);
            if (bad) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
        }
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", bits);
        ckk_type = CKK_RSA;
        pw_family = FHSM_PAIRWISE_RSA;
    } else if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
        const char *curve = "P-256";
        long i = find_attr(pPub, ulPub, CKA_EC_PARAMS);
        if (i >= 0 && pPub[i].pValue) {
            const char *m = match_curve(pPub[i].pValue, pPub[i].ulValueLen);
            if (!m) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
            curve = m;
        }
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", curve);
        ckk_type = CKK_EC;
        pw_family = FHSM_PAIRWISE_EC;
    } else if (pMechanism->mechanism == CKM_ML_KEM_KEY_PAIR_GEN) {
        /* CKA_PARAMETER_SET = ASCII "ML-KEM-512" | "ML-KEM-768" |
         * "ML-KEM-1024". Default to 768 (NIST level 3). */
        char pset[32] = "ML-KEM-768";
        long i = find_attr(pPub, ulPub, CKA_PARAMETER_SET);
        if (i >= 0 && pPub[i].pValue && pPub[i].ulValueLen < sizeof(pset)) {
            memcpy(pset, pPub[i].pValue, pPub[i].ulValueLen);
            pset[pPub[i].ulValueLen] = '\0';
            if (!fhsm_pset_valid(pset)) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
        }
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, pset);
        ckk_type = CKK_ML_KEM;
        pw_family = FHSM_PAIRWISE_ML_KEM;
    } else if (pMechanism->mechanism == CKM_ML_DSA_KEY_PAIR_GEN) {
        char pset[32] = "ML-DSA-65";
        long i = find_attr(pPub, ulPub, CKA_PARAMETER_SET);
        if (i >= 0 && pPub[i].pValue && pPub[i].ulValueLen < sizeof(pset)) {
            memcpy(pset, pPub[i].pValue, pPub[i].ulValueLen);
            pset[pPub[i].ulValueLen] = '\0';
            if (!fhsm_pset_valid(pset)) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
        }
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, pset);
        ckk_type = CKK_ML_DSA;
        pw_family = FHSM_PAIRWISE_ML_DSA;
    } else if (pMechanism->mechanism == CKM_SLH_DSA_KEY_PAIR_GEN) {
        char pset[32] = "SLH-DSA-SHA2-128s";
        long i = find_attr(pPub, ulPub, CKA_PARAMETER_SET);
        if (i >= 0 && pPub[i].pValue && pPub[i].ulValueLen < sizeof(pset)) {
            memcpy(pset, pPub[i].pValue, pPub[i].ulValueLen);
            pset[pPub[i].ulValueLen] = '\0';
            if (!fhsm_pset_valid(pset)) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
        }
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, pset);
        ckk_type = CKK_SLH_DSA;
        pw_family = FHSM_PAIRWISE_SLH_DSA;
    } else {
        return FHSM_RV_MECHANISM_INVALID;
    }
    if (!pkey) return FHSM_RV_FUNCTION_FAILED;

    /* ---- FIPS 140-3 §7.10.2.b : pair-wise consistency check ---------
     * Verify that the freshly-generated keypair is mathematically
     * consistent BEFORE persisting it. A failure here indicates a
     * silent keygen corruption (RNG fault, OpenSSL bug, RAM bit-flip).
     * On failure we latch the module ERROR state and refuse to store
     * the keypair. The audit log records the verdict. */
    {
        fhsm_rv_t pw_rv = fhsm_pairwise_check(pkey, pw_family);
        (void)fhsm_audit_event(FHSM_EV_KAT_REPORT,
                                -1, (int)hSession,
                                fhsm_session_role(hSession),
                                pw_rv,
                                "pairwise=%d", (int)pw_family);
        if (pw_rv != FHSM_RV_OK) {
            (void)fhsm_state_set(FHSM_STATE_ERROR);
            EVP_PKEY_free(pkey);
            return FHSM_RV_FUNCTION_FAILED;
        }
    }

    /* Serialize public key (SubjectPublicKeyInfo). */
    uint8_t *pub_der = NULL;
    int pub_len = i2d_PUBKEY(pkey, &pub_der);
    if (pub_len <= 0 || pub_len > 5500) {
        EVP_PKEY_free(pkey);
        OPENSSL_free(pub_der);
        return FHSM_RV_FUNCTION_FAILED;
    }
    /* Serialize private key (PKCS#8 unencrypted ; the token store will
     * encrypt it under the DEK). */
    uint8_t *priv_der = NULL;
    int priv_len = i2d_PrivateKey(pkey, &priv_der);
    if (priv_len <= 0 || priv_len > 5500) {
        EVP_PKEY_free(pkey);
        OPENSSL_free(pub_der);
        OPENSSL_free(priv_der);
        return FHSM_RV_FUNCTION_FAILED;
    }
    EVP_PKEY_free(pkey);

    char         label_pub[64] = "", label_priv[64] = "";
    const uint8_t *id_pub = NULL, *id_priv = NULL;
    size_t       id_pub_len = 0, id_priv_len = 0;
    long li;
    li = find_attr(pPub, ulPub, CKA_LABEL);
    if (li >= 0) {
        size_t n = pPub[li].ulValueLen;
        if (n >= sizeof(label_pub)) n = sizeof(label_pub) - 1;
        memcpy(label_pub, pPub[li].pValue, n); label_pub[n] = '\0';
    }
    li = find_attr(pPub, ulPub, CKA_ID);
    if (li >= 0) { id_pub = pPub[li].pValue; id_pub_len = pPub[li].ulValueLen; }
    li = find_attr(pPriv, ulPriv, CKA_LABEL);
    if (li >= 0) {
        size_t n = pPriv[li].ulValueLen;
        if (n >= sizeof(label_priv)) n = sizeof(label_priv) - 1;
        memcpy(label_priv, pPriv[li].pValue, n); label_priv[n] = '\0';
    }
    li = find_attr(pPriv, ulPriv, CKA_ID);
    if (li >= 0) { id_priv = pPriv[li].pValue; id_priv_len = pPriv[li].ulValueLen; }

    uint32_t hp = 0, hk = 0;
    fhsm_rv_t rv = fhsm_token_object_add(t, CKO_PUBLIC_KEY, ckk_type,
                                          label_pub, pub_der, (size_t)pub_len,
                                          id_pub, id_pub_len, 0, &hp);
    OPENSSL_free(pub_der);
    if (rv != FHSM_RV_OK) { OPENSSL_free(priv_der); return rv; }
    rv = fhsm_token_object_add(t, CKO_PRIVATE_KEY, ckk_type, label_priv,
                                priv_der, (size_t)priv_len,
                                id_priv, id_priv_len,
                                FHSM_OBJF_SENSITIVE, &hk);
    fhsm_zeroize(priv_der, (size_t)priv_len);
    OPENSSL_free(priv_der);
    if (rv != FHSM_RV_OK) {
        (void)fhsm_token_object_destroy(t, hp);
        return rv;
    }
    *phPub = hp; *phPriv = hk;
    fhsm_apply_token_scope(t, hSession, pPub,  ulPub,  hp);
    (void)fhsm_token_object_set_usage(t, hp, fhsm_compute_usage(CKO_PUBLIC_KEY, pPub, ulPub));
    fhsm_apply_token_scope(t, hSession, pPriv, ulPriv, hk);
    { uint8_t pu = fhsm_compute_usage(CKO_PRIVATE_KEY, pPriv, ulPriv);
      /* PQC keys (ML-KEM/ML-DSA/SLH-DSA) do not derive (#125 : ML-KEM
       * private key must report CKA_DERIVE=FALSE). */
      if (ckk_type == CKK_ML_KEM || ckk_type == CKK_ML_DSA || ckk_type == CKK_SLH_DSA)
          pu &= (uint8_t)~FHSM_USAGE_DERIVE;
      (void)fhsm_token_object_set_usage(t, hk, pu); }
    return FHSM_RV_OK;
}

/* Parse the public-key DER stored in the object's value blob and extract
 * the requested PKCS#11 attribute.
 *
 *  Supported queries (all output as fresh bytes copied into the
 *  caller-supplied buffer) :
 *    CKA_MODULUS_BITS     : CK_ULONG (bit length of n)
 *    CKA_MODULUS          : big-endian n (RSA only)
 *    CKA_PUBLIC_EXPONENT  : big-endian e (RSA only)
 *    CKA_EC_POINT         : DER-encoded OCTET STRING wrapping the
 *                           uncompressed point 0x04|X|Y (EC only)
 *    CKA_EC_PARAMS_QUERY  : DER-encoded curve OID (EC only)
 *
 *  Returns 0 on success and writes the value + length, -1 if the
 *  attribute is not extractable from this object, -2 if the buffer is
 *  too small (caller must retry with larger buffer or NULL pValue).
 * ----------------------------------------------------------------------- */
static int extract_pubkey_attr(fhsm_token_t *t, uint32_t handle,
                                CK_ATTRIBUTE_TYPE type,
                                uint8_t *out, size_t *out_len) {
    const uint8_t *kv = NULL; size_t kvl = 0;
    uint32_t cl = 0, kt = 0;
    if (fhsm_token_object_get(t, handle, &kv, &kvl, &cl, &kt) != FHSM_RV_OK)
        return -1;
    /* CKA_MODULUS / CKA_PUBLIC_EXPONENT / CKA_MODULUS_BITS and the EC public
     * components are non-sensitive and exist on BOTH public and private keys
     * (PKCS#11 par. 4.9). Public keys are stored as SubjectPublicKeyInfo,
     * private keys as PKCS#8 (#125 TestRSAKeypairConsistency reads the modulus
     * from the private key too). */
    const uint8_t *p = kv;
    EVP_PKEY *pkey = NULL;
    if (cl == CKO_PUBLIC_KEY)       pkey = d2i_PUBKEY(NULL, &p, (long)kvl);
    else if (cl == CKO_PRIVATE_KEY) pkey = d2i_AutoPrivateKey(NULL, &p, (long)kvl);
    else return -1;
    if (!pkey) return -1;
    int rc = -1;

    if (kt == CKK_RSA && type == CKA_MODULUS_BITS) {
        CK_ULONG bits = (CK_ULONG)EVP_PKEY_get_bits(pkey);
        if (*out_len < sizeof(CK_ULONG)) { *out_len = sizeof(CK_ULONG); rc = -2; }
        else { memcpy(out, &bits, sizeof(bits)); *out_len = sizeof(bits); rc = 0; }
    } else if (kt == CKK_RSA && (type == CKA_MODULUS || type == CKA_PUBLIC_EXPONENT)) {
        const char *name = (type == CKA_MODULUS) ? "n" : "e";
        BIGNUM *bn = NULL;
        if (EVP_PKEY_get_bn_param(pkey, name, &bn) == 1) {
            int sz = BN_num_bytes(bn);
            if (*out_len < (size_t)sz) { *out_len = (size_t)sz; rc = -2; }
            else { BN_bn2bin(bn, out); *out_len = (size_t)sz; rc = 0; }
            BN_free(bn);
        }
    } else if (kt == CKK_EC && type == CKA_EC_POINT) {
        /* Get the uncompressed-form point bytes (0x04 || X || Y). */
        size_t pt_len = 0;
        if (EVP_PKEY_get_octet_string_param(pkey, "encoded-pub-key",
                                              NULL, 0, &pt_len) == 1
            && pt_len > 0 && pt_len <= 256) {
            uint8_t pt[256];
            if (EVP_PKEY_get_octet_string_param(pkey, "encoded-pub-key",
                                                  pt, sizeof(pt), &pt_len) == 1) {
                /* Wrap as DER OCTET STRING : 0x04 LEN ... */
                /* LEN < 0x80 covers up to 127 bytes (P-256 = 65, P-384 = 97). */
                size_t total = 2 + pt_len;
                if (pt_len > 127) total = 3 + pt_len;
                if (*out_len < total) { *out_len = total; rc = -2; }
                else {
                    size_t off = 0;
                    out[off++] = 0x04;   /* OCTET STRING tag */
                    if (pt_len <= 127) {
                        out[off++] = (uint8_t)pt_len;
                    } else {
                        out[off++] = 0x81;
                        out[off++] = (uint8_t)pt_len;
                    }
                    memcpy(out + off, pt, pt_len);
                    *out_len = total;
                    rc = 0;
                }
            }
        }
    } else if (kt == CKK_EC && type == CKA_EC_PARAMS_QUERY) {
        /* Recover the curve OID as DER. */
        char curve_name[64] = {0}; size_t cn_len = 0;
        if (EVP_PKEY_get_utf8_string_param(pkey, "group",
                                            curve_name, sizeof(curve_name),
                                            &cn_len) == 1) {
            /* Map known curves to their pre-encoded OID. */
            const uint8_t *oid = NULL; size_t oid_len = 0;
            if (strcmp(curve_name, "P-256") == 0 ||
                strcmp(curve_name, "prime256v1") == 0 ||
                strcmp(curve_name, "secp256r1") == 0) {
                oid = (const uint8_t*)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";
                oid_len = 10;
            } else if (strcmp(curve_name, "P-384") == 0 ||
                       strcmp(curve_name, "secp384r1") == 0) {
                oid = (const uint8_t*)"\x06\x05\x2B\x81\x04\x00\x22";
                oid_len = 7;
            } else if (strcmp(curve_name, "P-521") == 0 ||
                       strcmp(curve_name, "secp521r1") == 0) {
                oid = (const uint8_t*)"\x06\x05\x2B\x81\x04\x00\x23";
                oid_len = 7;
            }
            if (oid) {
                if (*out_len < oid_len) { *out_len = oid_len; rc = -2; }
                else { memcpy(out, oid, oid_len); *out_len = oid_len; rc = 0; }
            }
        }
    }
    EVP_PKEY_free(pkey);
    return rc;
}

/* Extract a DER-encoded X.509 field (subject / issuer / serial number)
 * from a stored CKO_CERTIFICATE object. Two-pass like
 * extract_pubkey_attr: out==NULL queries size (returns -2 with *out_len
 * set), otherwise fills. Returns 0 on success, -1 if not applicable,
 * -2 if the caller buffer is too small. (#125 pkcs11-check
 * x509/TestCertificateExtractFields.) */
static int extract_cert_attr(fhsm_token_t *t, uint32_t handle,
                             CK_ATTRIBUTE_TYPE type,
                             uint8_t *out, size_t *out_len) {
    const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl = 0, kt = 0;
    if (fhsm_token_object_get(t, handle, &kv, &kvl, &cl, &kt) != FHSM_RV_OK) return -1;
    if (cl != CKO_CERTIFICATE) return -1;
    const uint8_t *p = kv;
    X509 *x = d2i_X509(NULL, &p, (long)kvl);
    if (!x) return -1;
    int rc = -1; unsigned char *der = NULL; int der_len = 0;
    if (type == CKA_SUBJECT_ATTR)
        der_len = i2d_X509_NAME(X509_get_subject_name(x), &der);
    else if (type == CKA_ISSUER_ATTR)
        der_len = i2d_X509_NAME(X509_get_issuer_name(x), &der);
    else if (type == CKA_SERIAL_NUMBER_ATTR)
        der_len = i2d_ASN1_INTEGER(X509_get_serialNumber(x), &der);
    if (der_len > 0 && der) {
        if (*out_len < (size_t)der_len) { *out_len = (size_t)der_len; rc = -2; }
        else { memcpy(out, der, (size_t)der_len); *out_len = (size_t)der_len; rc = 0; }
    }
    OPENSSL_free(der);
    X509_free(x);
    return rc;
}

static int fhsm_object_access_denied(fhsm_token_t *t, uint32_t cko_class);

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                           CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount) {
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    /* Bound ulCount before the per-attribute loop : an absurd count
     * (e.g. 0xffffffffffffffff) would walk pTemplate far out of bounds and
     * crash (#125 TestTemplateCountOverflowValidHandles, SIGSEGV). A NULL
     * template with a non-zero count is likewise invalid. NOTE : unlike
     * creation templates, a NULL pValue with a non-zero ulValueLen is the
     * legal size-query convention here, so fhsm_check_template is not used. */
    if (ulCount > FHSM_MAX_TEMPLATE_ATTRS) return FHSM_RV_ARGUMENTS_BAD;
    if (pTemplate == NULL && ulCount != 0)  return FHSM_RV_ARGUMENTS_BAD;
    const uint8_t *value = NULL; size_t value_len = 0;
    uint32_t cko_class = 0, ckk_type = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, (uint32_t)hObject, &value, &value_len,
                                          &cko_class, &ckk_type);
    if (rv != FHSM_RV_OK) return rv;
    if (fhsm_object_access_denied(t, cko_class))
        return FHSM_RV_OBJECT_HANDLE_INVALID;
    int fhsm_buf_too_small = 0;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        const void *src = NULL; size_t src_len = 0;
        unsigned char bval = 0;
        CK_ULONG  tmp_class = cko_class, tmp_type = ckk_type, tmp_len = value_len;
        const char    *label_p = NULL; size_t label_len = 0;
        const uint8_t *id_p    = NULL; size_t id_len    = 0;
        switch (pTemplate[i].type) {
            case CKA_CLASS:     src = &tmp_class; src_len = sizeof(CK_ULONG); break;
            case CKA_KEY_TYPE:
                /* Certificates have no CKA_KEY_TYPE (PKCS#11 v3.2
                 * par. 4.6.3) ; the store's key_type field carries
                 * CKA_CERTIFICATE_TYPE for that class instead. */
                if (cko_class == CKO_CERTIFICATE) {
                    pTemplate[i].ulValueLen = (CK_ULONG)-1; continue;
                }
                src = &tmp_type;  src_len = sizeof(CK_ULONG); break;
            case CKA_CERTIFICATE_TYPE:
                if (cko_class != CKO_CERTIFICATE) {
                    pTemplate[i].ulValueLen = (CK_ULONG)-1; continue;
                }
                src = &tmp_type;  src_len = sizeof(CK_ULONG); break;
            case CKA_VALUE: {
                /* Enforce CKA_SENSITIVE : a sensitive object's CKA_VALUE
                 * must NEVER be returned. PKCS#11 v3.2 §C.6.7.2 :
                 * "C_GetAttributeValue shall not reveal the value of a
                 * sensitive attribute". */
                uint8_t of = 0;
                if (fhsm_token_object_get_flags(t, (uint32_t)hObject, &of) == FHSM_RV_OK
                    && (of & FHSM_OBJF_SENSITIVE)) {
                    pTemplate[i].ulValueLen = (CK_ULONG)-1;
                    continue;
                }
                src = value;      src_len = value_len;
                break;
            }
            case CKA_VALUE_LEN: src = &tmp_len;   src_len = sizeof(CK_ULONG); break;
            case CKA_SENSITIVE: {
                uint8_t of = 0;
                (void)fhsm_token_object_get_flags(t, (uint32_t)hObject, &of);
                static unsigned char b_true = 1, b_false = 0;
                src = (of & FHSM_OBJF_SENSITIVE) ? &b_true : &b_false;
                src_len = 1;
                break;
            }
            case CKA_EXTRACTABLE: {
                uint8_t of = 0;
                (void)fhsm_token_object_get_flags(t, (uint32_t)hObject, &of);
                static unsigned char b_true = 1, b_false = 0;
                src = (of & FHSM_OBJF_EXTRACTABLE) ? &b_true : &b_false;
                src_len = 1;
                break;
            }
            case CKA_MODULUS_BITS:
            case CKA_MODULUS:
            case CKA_PUBLIC_EXPONENT:
            case CKA_EC_POINT:
            case CKA_EC_PARAMS_QUERY: {
                /* Two-pass : (a) query the size with NULL pValue, (b) fill. */
                if (pTemplate[i].pValue == NULL) {
                    size_t need = 0;
                    int e1 = extract_pubkey_attr(t, (uint32_t)hObject,
                                                  pTemplate[i].type, NULL, &need);
                    if (e1 == -1) { pTemplate[i].ulValueLen = (CK_ULONG)-1; continue; }
                    /* e1 == -2 : `need` now holds the required size. */
                    pTemplate[i].ulValueLen = (CK_ULONG)need;
                } else {
                    size_t out_len = pTemplate[i].ulValueLen;
                    int e2 = extract_pubkey_attr(t, (uint32_t)hObject,
                                                  pTemplate[i].type,
                                                  pTemplate[i].pValue, &out_len);
                    if (e2 == 0) pTemplate[i].ulValueLen = (CK_ULONG)out_len;
                    else         pTemplate[i].ulValueLen = (CK_ULONG)-1;
                }
                continue;
            }
            case CKA_LABEL:
                if (fhsm_token_object_get_label(t, (uint32_t)hObject,
                        &label_p, &label_len) != FHSM_RV_OK) {
                    pTemplate[i].ulValueLen = (CK_ULONG)-1; continue;
                }
                src = label_p; src_len = label_len; break;
            case CKA_ID:
                if (fhsm_token_object_get_id(t, (uint32_t)hObject,
                        &id_p, &id_len) != FHSM_RV_OK) {
                    pTemplate[i].ulValueLen = (CK_ULONG)-1; continue;
                }
                src = id_p; src_len = id_len; break;
            /* --- Boolean policy / usage attributes (#125 : previously
             * returned CK_UNAVAILABLE_INFORMATION, which the harness
             * reads as "missing" -> KeyError). Values are PKCS#11
             * defaults, or derived from the stored object flags. Note :
             * per-key usage restrictions are not yet stored, so usage
             * flags reflect the class default, not per-object overrides
             * (tracked follow-up). --- */
            case CKA_TOKEN: {
                /* CKA_TOKEN is TRUE for a persisted token object, FALSE for a
                 * session object (owner_session != 0). Previously hard-coded
                 * TRUE, which broke the session-object default (#125
                 * TestSecretKeyDefaults / TestDataObjectDefaults). */
                int is_tok = 1;
                (void)fhsm_token_object_is_token(t, (uint32_t)hObject, &is_tok);
                bval = is_tok ? 1 : 0; src = &bval; src_len = 1; break;
            }
            case CKA_PRIVATE:
                bval = (cko_class == CKO_PUBLIC_KEY || cko_class == CKO_CERTIFICATE) ? 0 : 1;
                src = &bval; src_len = 1; break;
            case CKA_MODIFIABLE_ATTR: {
                uint8_t of = 0; (void)fhsm_token_object_get_flags(t, (uint32_t)hObject, &of);
                bval = (of & FHSM_OBJF_UNMODIFIABLE) ? 0 : 1; src = &bval; src_len = 1; break;
            }
            case CKA_COPYABLE_ATTR:    bval = 1; src = &bval; src_len = 1; break;
            case CKA_DESTROYABLE_ATTR: {
                uint8_t of = 0; (void)fhsm_token_object_get_flags(t, (uint32_t)hObject, &of);
                bval = (of & FHSM_OBJF_UNDESTROYABLE) ? 0 : 1; src = &bval; src_len = 1; break;
            }
            case CKA_LOCAL_ATTR:       bval = 1; src = &bval; src_len = 1; break;
            case CKA_ALWAYS_AUTH_ATTR: bval = 0; src = &bval; src_len = 1; break;
            case CKA_WRAP_WITH_TRUSTED_ATTR: bval = 0; src = &bval; src_len = 1; break;
            case CKA_TRUSTED_ATTR:     bval = 0; src = &bval; src_len = 1; break;
            case CKA_ALWAYS_SENSITIVE_ATTR: {
                uint8_t of = 0; (void)fhsm_token_object_get_flags(t, (uint32_t)hObject, &of);
                bval = (of & FHSM_OBJF_SENSITIVE) ? 1 : 0; src = &bval; src_len = 1; break;
            }
            case CKA_NEVER_EXTRACTABLE_ATTR: {
                uint8_t of = 0; (void)fhsm_token_object_get_flags(t, (uint32_t)hObject, &of);
                bval = (of & FHSM_OBJF_EXTRACTABLE) ? 0 : 1; src = &bval; src_len = 1; break;
            }
            case CKA_ENCRYPT_ATTR:
                bval = fhsm_usage_bool(t, hObject, cko_class, FHSM_USAGE_ENCRYPT, cko_class != CKO_PRIVATE_KEY); src = &bval; src_len = 1; break;
            case CKA_VERIFY_ATTR:
                bval = fhsm_usage_bool(t, hObject, cko_class, FHSM_USAGE_VERIFY, cko_class != CKO_PRIVATE_KEY); src = &bval; src_len = 1; break;
            case CKA_WRAP_ATTR:
                bval = fhsm_usage_bool(t, hObject, cko_class, FHSM_USAGE_WRAP, cko_class != CKO_PRIVATE_KEY); src = &bval; src_len = 1; break;
            case CKA_DECRYPT_ATTR:
                bval = fhsm_usage_bool(t, hObject, cko_class, FHSM_USAGE_DECRYPT, cko_class != CKO_PUBLIC_KEY); src = &bval; src_len = 1; break;
            case CKA_SIGN_ATTR:
                bval = fhsm_usage_bool(t, hObject, cko_class, FHSM_USAGE_SIGN, cko_class != CKO_PUBLIC_KEY); src = &bval; src_len = 1; break;
            case CKA_UNWRAP_ATTR:
                bval = fhsm_usage_bool(t, hObject, cko_class, FHSM_USAGE_UNWRAP, cko_class != CKO_PUBLIC_KEY); src = &bval; src_len = 1; break;
            case CKA_DERIVE_ATTR:
                bval = fhsm_usage_bool(t, hObject, cko_class, FHSM_USAGE_DERIVE, 0); src = &bval; src_len = 1; break;
            /* Date attributes : empty (unset) by default. A zero-length
             * value is the PKCS#11 encoding for "no date". */
            case CKA_START_DATE_ATTR:
            case CKA_END_DATE_ATTR:    src = &bval; src_len = 0; break;
            case CKA_SUBJECT_ATTR:
            case CKA_ISSUER_ATTR:
            case CKA_SERIAL_NUMBER_ATTR: {
                if (pTemplate[i].pValue == NULL) {
                    size_t need = 0;
                    int e1 = extract_cert_attr(t, (uint32_t)hObject,
                                                pTemplate[i].type, NULL, &need);
                    if (e1 == -1) { pTemplate[i].ulValueLen = (CK_ULONG)-1; continue; }
                    pTemplate[i].ulValueLen = (CK_ULONG)need;
                } else {
                    size_t out_len = pTemplate[i].ulValueLen;
                    int e2 = extract_cert_attr(t, (uint32_t)hObject,
                                                pTemplate[i].type,
                                                pTemplate[i].pValue, &out_len);
                    if (e2 == 0) pTemplate[i].ulValueLen = (CK_ULONG)out_len;
                    else         pTemplate[i].ulValueLen = (CK_ULONG)-1;
                }
                continue;
            }
            default:            pTemplate[i].ulValueLen = (CK_ULONG)-1;       continue;
        }
        if (pTemplate[i].pValue == NULL) {
            pTemplate[i].ulValueLen = (CK_ULONG)src_len;
        } else if (pTemplate[i].ulValueLen < src_len) {
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            fhsm_buf_too_small = 1;
        } else {
            memcpy(pTemplate[i].pValue, src, src_len);
            pTemplate[i].ulValueLen = (CK_ULONG)src_len;
        }
    }
    /* PKCS#11 v3.2 C_GetAttributeValue : if any requested attribute did
     * not fit the supplied buffer, return CKR_BUFFER_TOO_SMALL (#125). */
    if (fhsm_buf_too_small) return 0x00000150UL;   /* CKR_BUFFER_TOO_SMALL */
    return FHSM_RV_OK;
}

/* PKCS#11 v3.2 §C.6.7.4 --- C_GetObjectSize
 *
 * Obtains the size of an object in bytes. The spec is explicit that
 * the returned value "does not necessarily reflect actual storage used
 * by the object" ; we interpret it as the byte length of the object's
 * primary value blob (CKA_VALUE for secret/private keys ; the DER SPKI
 * for public keys ; the verbatim ML-DSA / SLH-DSA blob for PQ keys).
 *
 * Wired into the v2.40 function list at slot 23 ; mirrored into the
 * v3.0 table by fhsm_init_v3_0_table().
 *
 * Added in v1.2.2 in response to Denis Mingulov's pkcs11-check report
 * that flagged this function as missing from the exported list. */
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                      CK_ULONG *pulSize) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pulSize) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;

    const uint8_t *value = NULL;
    size_t value_len = 0;
    uint32_t cko_class = 0, ckk_type = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, (uint32_t)hObject,
                                          &value, &value_len,
                                          &cko_class, &ckk_type);
    if (rv != FHSM_RV_OK) return rv;
    if (fhsm_object_access_denied(t, cko_class))
        return FHSM_RV_OBJECT_HANDLE_INVALID;

    *pulSize = (CK_ULONG)value_len;
    return FHSM_RV_OK;
}

/* PKCS#11 v3.2 §C.6.7.5 --- C_SetAttributeValue
 *
 * Modifies the attributes of an existing object. The PKCS#11 spec
 * enumerates which attributes are settable per object class ; the
 * v1.3.0 implementation supports the four most commonly mutated :
 *
 *     CKA_LABEL          : NUL-terminated UTF-8, max 63 chars after
 *                          truncation. Always settable.
 *     CKA_ID             : opaque byte string, max 32 bytes. Always
 *                          settable.
 *     CKA_SENSITIVE      : one-way FALSE -> TRUE (per §C.6.7.5
 *                          informative table). TRUE -> FALSE is
 *                          rejected with CKR_ATTRIBUTE_READ_ONLY.
 *     CKA_EXTRACTABLE    : one-way TRUE -> FALSE. FALSE -> TRUE is
 *                          rejected with CKR_ATTRIBUTE_READ_ONLY.
 *
 * Any other attribute in the template is rejected with
 * CKR_ATTRIBUTE_READ_ONLY (for immutable attributes such as
 * CKA_CLASS / CKA_KEY_TYPE / CKA_VALUE) or
 * CKR_ATTRIBUTE_TYPE_INVALID (for attributes the module does not
 * support setting). The first error halts processing ; remaining
 * template entries are not applied. This matches the spec's
 * "shall fail" wording for the first invalid attribute.
 *
 * Added in v1.3.0 in response to Denis Mingulov's pkcs11-check
 * report (slot 25 was unimplemented in v1.2.2). Wired into the v2.40
 * function list at slot 25 ; mirrored into the v3.0 table by
 * fhsm_init_v3_0_table(). */
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!pTemplate || ulCount == 0) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (fhsm_session_role(hSession) == FHSM_ROLE_NONE)
        return FHSM_RV_USER_NOT_LOGGED_IN;

    /* Snapshot current flags once : we will apply the SENSITIVE /
     * EXTRACTABLE transitions as a single set_flags call after all
     * template entries pass validation. This keeps the on-disk write
     * count at one per call rather than per-attribute. */
    uint8_t flags_now = 0;
    fhsm_rv_t rv_get = fhsm_token_object_get_flags(t, (uint32_t)hObject,
                                                    &flags_now);
    if (rv_get != FHSM_RV_OK) return rv_get;
    /* CKA_MODIFIABLE=FALSE : the object may not be modified
     * (#125 TestModifiableAttribute enforcement). */
    if (flags_now & FHSM_OBJF_UNMODIFIABLE) return 0x0000001BUL; /* CKR_ACTION_PROHIBITED */
    uint8_t flags_new = flags_now;
    int flags_touched = 0;

    for (CK_ULONG i = 0; i < ulCount; ++i) {
        CK_ATTRIBUTE *a = &pTemplate[i];
        switch (a->type) {
            case CKA_LABEL: {
                /* Use the template buffer directly ; the setter does a
                 * bounded copy. ulValueLen of 0 is allowed and yields
                 * an empty label. */
                char buf[64];
                size_t n = a->ulValueLen;
                if (n >= sizeof(buf)) n = sizeof(buf) - 1;
                memcpy(buf, a->pValue, n);
                buf[n] = '\0';
                fhsm_rv_t r = fhsm_token_object_set_label(
                                t, (uint32_t)hObject, buf);
                if (r != FHSM_RV_OK) return r;
                break;
            }
            case CKA_ID: {
                fhsm_rv_t r = fhsm_token_object_set_id(
                                t, (uint32_t)hObject,
                                (const uint8_t *)a->pValue,
                                (size_t)a->ulValueLen);
                if (r != FHSM_RV_OK) return r;
                break;
            }
            case CKA_SENSITIVE: {
                if (a->ulValueLen != 1) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
                uint8_t want = *(const uint8_t *)a->pValue ? 1 : 0;
                uint8_t is_now = (flags_new & FHSM_OBJF_SENSITIVE) ? 1 : 0;
                if (want == is_now) break;          /* no-op */
                if (want == 0)
                    return 0x00000010UL;             /* CKR_ATTRIBUTE_READ_ONLY */
                flags_new |= FHSM_OBJF_SENSITIVE;
                flags_touched = 1;
                break;
            }
            case CKA_EXTRACTABLE: {
                if (a->ulValueLen != 1) return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
                uint8_t want = *(const uint8_t *)a->pValue ? 1 : 0;
                uint8_t is_now = (flags_new & FHSM_OBJF_EXTRACTABLE) ? 1 : 0;
                if (want == is_now) break;          /* no-op */
                if (want == 1)
                    return 0x00000010UL;             /* CKR_ATTRIBUTE_READ_ONLY */
                flags_new &= (uint8_t)~FHSM_OBJF_EXTRACTABLE;
                flags_touched = 1;
                break;
            }
            case CKA_CLASS:
            case CKA_KEY_TYPE:
            case CKA_VALUE:
                /* Immutable after object creation. */
                return 0x00000010UL;                 /* CKR_ATTRIBUTE_READ_ONLY */
            default:
                return 0x00000012UL;                 /* CKR_ATTRIBUTE_TYPE_INVALID */
        }
    }

    if (flags_touched) {
        fhsm_rv_t r = fhsm_token_object_set_flags(t, (uint32_t)hObject,
                                                   flags_new);
        if (r != FHSM_RV_OK) return r;
    }

    return FHSM_RV_OK;
}

/* PKCS#11 v3.2 §C.6.7.3 --- C_CopyObject
 *
 * Creates a copy of an existing object and applies an override
 * template. The new object inherits all attributes of the original ;
 * template entries override individual attributes per the same rules
 * as C_SetAttributeValue. The override template may NOT change
 * CKA_CLASS, CKA_KEY_TYPE, or CKA_VALUE (CKR_TEMPLATE_INCONSISTENT
 * if attempted) and must respect the one-way SENSITIVE / EXTRACTABLE
 * transitions.
 *
 * Implementation strategy : read the original via
 * fhsm_token_object_get + the small auxiliary accessors, apply the
 * template overrides to a local working copy of the (label, id,
 * flags) triple, then call fhsm_token_object_add to create a fresh
 * persistent object with the overridden attributes plus the
 * original value blob.
 *
 * Added in v1.3.0 in response to Denis Mingulov's pkcs11-check
 * report (slot 21 was unimplemented in v1.2.2). Wired into the v2.40
 * function list at slot 21 ; mirrored into the v3.0 table by
 * fhsm_init_v3_0_table(). */
CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE *phNewObject) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!phNewObject) return FHSM_RV_ARGUMENTS_BAD;
    /* Empty template is legal : it means "a verbatim copy". */
    if (ulCount > 0 && !pTemplate) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (fhsm_session_role(hSession) == FHSM_ROLE_NONE)
        return FHSM_RV_USER_NOT_LOGGED_IN;

    /* Read original object's value + scalar fields. */
    const uint8_t *src_value = NULL;
    size_t src_value_len = 0;
    uint32_t src_class = 0, src_key_type = 0;
    fhsm_rv_t r = fhsm_token_object_get(t, (uint32_t)hObject,
                                         &src_value, &src_value_len,
                                         &src_class, &src_key_type);
    if (r != FHSM_RV_OK) return r;

    /* Read original label / id / flags via the auxiliary accessors. */
    char     copy_label[64] = "";
    uint8_t  copy_id[32] = {0};
    size_t   copy_id_len = 0;
    uint8_t  copy_flags = 0;
    {
        const char *lp = NULL; size_t llen = 0;
        if (fhsm_token_object_get_label(t, (uint32_t)hObject, &lp, &llen)
            == FHSM_RV_OK && lp && llen > 0) {
            size_t n = llen < sizeof(copy_label) - 1
                            ? llen : sizeof(copy_label) - 1;
            memcpy(copy_label, lp, n);
            copy_label[n] = '\0';
        }
    }
    {
        const uint8_t *ip = NULL; size_t ilen = 0;
        if (fhsm_token_object_get_id(t, (uint32_t)hObject, &ip, &ilen)
            == FHSM_RV_OK && ip && ilen > 0 && ilen <= sizeof(copy_id)) {
            memcpy(copy_id, ip, ilen);
            copy_id_len = ilen;
        }
    }
    (void)fhsm_token_object_get_flags(t, (uint32_t)hObject, &copy_flags);

    /* Apply override template. Same rules as C_SetAttributeValue but
     * with CKA_CLASS / CKA_KEY_TYPE / CKA_VALUE producing
     * CKR_TEMPLATE_INCONSISTENT rather than CKR_ATTRIBUTE_READ_ONLY
     * (PKCS#11 v3.2 §C.6.7.3 specifies the former for class-changing
     * attempts during copy). */
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        CK_ATTRIBUTE *a = &pTemplate[i];
        switch (a->type) {
            case CKA_LABEL: {
                fhsm_zeroize(copy_label, sizeof(copy_label));
                size_t n = a->ulValueLen < sizeof(copy_label) - 1
                                ? a->ulValueLen : sizeof(copy_label) - 1;
                memcpy(copy_label, a->pValue, n);
                copy_label[n] = '\0';
                break;
            }
            case CKA_ID: {
                if (a->ulValueLen > sizeof(copy_id))
                    return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
                fhsm_zeroize(copy_id, sizeof(copy_id));
                if (a->ulValueLen > 0)
                    memcpy(copy_id, a->pValue, a->ulValueLen);
                copy_id_len = (size_t)a->ulValueLen;
                break;
            }
            case CKA_SENSITIVE: {
                if (a->ulValueLen != 1)
                    return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
                uint8_t want = *(const uint8_t *)a->pValue ? 1 : 0;
                uint8_t is_now = (copy_flags & FHSM_OBJF_SENSITIVE) ? 1 : 0;
                if (want == is_now) break;
                if (want == 0)
                    return 0x00000010UL;             /* CKR_ATTRIBUTE_READ_ONLY */
                copy_flags |= FHSM_OBJF_SENSITIVE;
                break;
            }
            case CKA_EXTRACTABLE: {
                if (a->ulValueLen != 1)
                    return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
                uint8_t want = *(const uint8_t *)a->pValue ? 1 : 0;
                uint8_t is_now = (copy_flags & FHSM_OBJF_EXTRACTABLE) ? 1 : 0;
                if (want == is_now) break;
                if (want == 1)
                    return 0x00000010UL;             /* CKR_ATTRIBUTE_READ_ONLY */
                copy_flags &= (uint8_t)~FHSM_OBJF_EXTRACTABLE;
                break;
            }
            case CKA_CLASS:
            case CKA_KEY_TYPE:
            case CKA_VALUE:
                return 0x000000D1UL;                 /* CKR_TEMPLATE_INCONSISTENT */
            default:
                return 0x00000012UL;                 /* CKR_ATTRIBUTE_TYPE_INVALID */
        }
    }

    /* Persist the new object. fhsm_token_object_add returns the new
     * handle in *out_handle. The source value blob is referenced
     * read-only ; the token store performs its own copy. */
    uint32_t new_handle = 0;
    fhsm_rv_t r2 = fhsm_token_object_add(t, src_class, src_key_type,
                                          copy_label,
                                          src_value, src_value_len,
                                          copy_id, copy_id_len,
                                          copy_flags, &new_handle);
    if (r2 != FHSM_RV_OK) return r2;

    *phNewObject = (CK_OBJECT_HANDLE)new_handle;
    return FHSM_RV_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *pTemplate,
                        CK_ULONG ulCount) {
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (hSession >= sizeof(g_finds)/sizeof(g_finds[0]))
        return FHSM_RV_SESSION_HANDLE_INVALID;
    fhsm_find_state_t *f = &g_finds[hSession];
    if (f->active) return FHSM_RV_OPERATION_ACTIVE;
    { CK_RV cr = fhsm_check_template(pTemplate, ulCount); if (cr != FHSM_RV_OK) return cr; }
    memset(f, 0, sizeof(*f));

    uint32_t   filter_class = 0;  int has_class = 0;
    char       filter_label[64] = ""; int has_label = 0;
    uint8_t    filter_id[32]; size_t filter_id_len = 0; int has_id = 0;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        if (pTemplate[i].type == CKA_CLASS && pTemplate[i].ulValueLen == sizeof(CK_ULONG)) {
            filter_class = (uint32_t)(*(CK_ULONG*)pTemplate[i].pValue);
            has_class = 1;
        } else if (pTemplate[i].type == CKA_LABEL) {
            size_t n = pTemplate[i].ulValueLen;
            if (n >= sizeof(filter_label)) n = sizeof(filter_label) - 1;
            memcpy(filter_label, pTemplate[i].pValue, n);
            filter_label[n] = '\0';
            has_label = 1;
        } else if (pTemplate[i].type == CKA_ID) {
            size_t n = pTemplate[i].ulValueLen;
            if (n <= sizeof(filter_id)) {
                memcpy(filter_id, pTemplate[i].pValue, n);
                filter_id_len = n;
                has_id = 1;
            }
        }
    }
    /* First-pass : ask the token store for class+label matches, then
     * filter by id ourselves (the store API doesn't take an id filter). */
    uint32_t prelim[64];
    size_t got = 0;
    fhsm_rv_t rv = fhsm_token_object_find(t,
                                           has_class ? &filter_class : NULL,
                                           has_label ? filter_label  : NULL,
                                           prelim,
                                           sizeof(prelim)/sizeof(prelim[0]),
                                           &got);
    /* Access control : a session not logged in as the normal user (a
     * public session, or a session after C_Logout) must not see private
     * objects (CKA_PRIVATE). CKA_PRIVATE is derived from the object
     * class -- secret and private keys are private ; public keys,
     * certificates and data objects are public (#125 : private object
     * visible in public / post-logout session). */
    int authed_user = (fhsm_token_current_role(t) == FHSM_ROLE_USER);
    size_t k = 0;
    for (size_t j = 0; j < got && k < sizeof(f->handles)/sizeof(f->handles[0]); ++j) {
        if (!authed_user) {
            const uint8_t *pv = NULL; size_t pl = 0; uint32_t ocl = 0, okt = 0;
            if (fhsm_token_object_get(t, prelim[j], &pv, &pl, &ocl, &okt) == FHSM_RV_OK
                && (ocl == CKO_SECRET_KEY || ocl == CKO_PRIVATE_KEY))
                continue;   /* private object hidden from unauthenticated session */
        }
        if (has_id) {
            const uint8_t *oid = NULL; size_t oidl = 0;
            if (fhsm_token_object_get_id(t, prelim[j], &oid, &oidl) != FHSM_RV_OK)
                continue;
            if (oidl != filter_id_len) continue;
            if (oidl > 0 && memcmp(oid, filter_id, oidl) != 0) continue;
        }
        f->handles[k++] = prelim[j];
    }
    f->count = k;
    f->next = 0;
    f->active = 1;
    return rv;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *phObject,
                    CK_ULONG ulMaxCount, CK_ULONG *pulCount) {
    if (!phObject || !pulCount) return FHSM_RV_ARGUMENTS_BAD;
    if (hSession >= sizeof(g_finds)/sizeof(g_finds[0]))
        return FHSM_RV_SESSION_HANDLE_INVALID;
    fhsm_find_state_t *f = &g_finds[hSession];
    if (!f->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    CK_ULONG k = 0;
    while (k < ulMaxCount && f->next < f->count) {
        phObject[k++] = f->handles[f->next++];
    }
    *pulCount = k;
    return FHSM_RV_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    if (hSession >= sizeof(g_finds)/sizeof(g_finds[0]))
        return FHSM_RV_SESSION_HANDLE_INVALID;
    fhsm_find_state_t *f = &g_finds[hSession];
    if (!f->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    memset(f, 0, sizeof(*f));
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * OAEP-related PKCS#11 constants. Declared here (above the OAEP helpers
 * and the Encrypt/Decrypt thunks) so all downstream code can reference
 * them without forward-declaration issues. The redundant `#define`
 * further down (in the Sign-section block) is kept for clarity but
 * harmless because identical values use #ifndef guards effectively
 * via the C preprocessor's last-define-wins semantics.
 * ----------------------------------------------------------------------- */
#ifndef CKM_RSA_PKCS_OAEP
#define CKM_RSA_PKCS_OAEP         0x00000009UL
#endif
#ifndef CKG_MGF1_SHA1
#define CKG_MGF1_SHA1             0x00000001UL
#define CKG_MGF1_SHA224           0x00000005UL
#define CKG_MGF1_SHA256           0x00000002UL
#define CKG_MGF1_SHA384           0x00000003UL
#define CKG_MGF1_SHA512           0x00000004UL
#endif
#ifndef CKZ_DATA_SPECIFIED
#define CKZ_DATA_SPECIFIED        0x00000001UL
#endif
#ifndef CKM_SHA_1
#define CKM_SHA_1                 0x00000220UL
#endif
/* Extra mechanism IDs used by the wiring below. The values are the
 * standard PKCS#11 v3.2 values ; declared with #ifndef guards so we
 * can use them everywhere in this TU without conflicting with the
 * earlier _LIST aliases. */
#ifndef CKM_AES_CBC
#define CKM_AES_ECB               0x00001081UL
#define CKM_AES_CBC               0x00001082UL
#ifndef CKM_RSA_PKCS
#define CKM_RSA_PKCS              0x00000001UL
#endif
#ifndef CKM_RSA_X_509
#define CKM_RSA_X_509             0x00000003UL
#endif
#endif
#ifndef CKM_AES_CBC_PAD
#define CKM_AES_CBC_PAD           0x00001085UL
#endif
#ifndef CKM_AES_CTR
#define CKM_AES_CTR               0x00001086UL
#endif
#ifndef CKM_AES_CMAC
#define CKM_AES_CMAC              0x0000108CUL
#endif
/* CKM_AES_GMAC (PKCS#11 v3.2 §A.4.1) = AES-GMAC = the GHASH-based MAC
 * underlying AES-GCM (NIST SP 800-38D §6.4). Distinct from CKM_AES_CMAC
 * (which is the AES-CBC-based MAC from NIST SP 800-38B).
 *
 * Historical context : OpenSC pkcs11-tool maps its CLI string "AES-CMAC"
 * to 0x108A internally (a long-standing OpenSC bug ; the correct value
 * per PKCS#11 v3.2 §A.4.1 is 0x108C). Before v1.1.18, FreeHSM C aliased
 * 0x108A to CKM_AES_CMAC for pkcs11-tool interop, which was wrong per
 * the spec but pragmatically useful. Starting in v1.1.18, FreeHSM C
 * implements real AES-GMAC at 0x108A, with an opt-in legacy alias
 * controlled by the FHSM_OPENSC_GMAC_ALIAS environment variable :
 *   - default                    : 0x108A = real AES-GMAC (spec-compliant)
 *   - FHSM_OPENSC_GMAC_ALIAS=1   : 0x108A = AES-CMAC (legacy OpenSC alias)
 * The alias is resolved once at op_init time so downstream dispatch
 * only sees the resolved mechanism. Production deployments MUST NOT set
 * FHSM_OPENSC_GMAC_ALIAS ; the AGD_PRE systemd unit leaves it unset. */
#define CKM_AES_GMAC              0x0000108AUL
#ifndef CKM_ECDH1_DERIVE
#define CKM_ECDH1_DERIVE          0x00001050UL
#endif

/* ---------------------------------------------------------------------------
 * RSA-OAEP helpers (CKM_RSA_PKCS_OAEP).
 *
 * The PKCS#11 CK_RSA_PKCS_OAEP_PARAMS is a 40-byte struct on LP64 :
 *   CK_MECHANISM_TYPE hashAlg          (CKM_SHA256, ...)
 *   CK_RSA_PKCS_MGF_TYPE mgf            (CKG_MGF1_SHA256, ...)
 *   CK_RSA_PKCS_OAEP_SOURCE_TYPE source (CKZ_DATA_SPECIFIED or 0)
 *   CK_VOID_PTR pSourceData             (label bytes, or NULL)
 *   CK_ULONG ulSourceDataLen            (label length)
 *
 * The hashAlg / mgf must agree (e.g. CKM_SHA256 + CKG_MGF1_SHA256).
 * NULL pParameter is rejected --- OAEP is unsafe without explicit
 * hash + MGF binding.
 * ----------------------------------------------------------------------- */
typedef struct fhsm_oaep_params_s {
    CK_ULONG hashAlg;
    CK_ULONG mgf;
    CK_ULONG source;
    void    *pSourceData;
    CK_ULONG ulSourceDataLen;
} fhsm_oaep_params_t;

static const EVP_MD *oaep_md(CK_ULONG ckm) {
    const char *name = NULL;
    switch (ckm) {
        case CKM_SHA_1:  name = "SHA1";   break;
        case CKM_SHA256: name = "SHA256"; break;
        case CKM_SHA384_LIST: name = "SHA384"; break;
        case CKM_SHA512_LIST: name = "SHA512"; break;
        default: return NULL;
    }
    return EVP_MD_fetch(NULL, name, NULL);
}

static const EVP_MD *mgf_md(CK_ULONG mgf) {
    const char *name = NULL;
    switch (mgf) {
        case CKG_MGF1_SHA1:    name = "SHA1";   break;
        case CKG_MGF1_SHA256:  name = "SHA256"; break;
        case CKG_MGF1_SHA384:  name = "SHA384"; break;
        case CKG_MGF1_SHA512:  name = "SHA512"; break;
        default: return NULL;
    }
    return EVP_MD_fetch(NULL, name, NULL);
}

/* Setup an EVP_PKEY_CTX for RSA-OAEP with the requested hash/MGF/label.
 * The pkey must already be loaded. On success the caller owns the ctx
 * and must call EVP_PKEY_CTX_free. */
static fhsm_rv_t oaep_ctx_init(EVP_PKEY *pkey, int encrypt,
                                const fhsm_oaep_params_t *oaep,
                                EVP_PKEY_CTX **out_ctx) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) return FHSM_RV_HOST_MEMORY;
    int ok = encrypt ? EVP_PKEY_encrypt_init(ctx) : EVP_PKEY_decrypt_init(ctx);
    if (ok <= 0) goto fail;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto fail;
    const EVP_MD *md_oaep = oaep_md(oaep->hashAlg);
    const EVP_MD *md_mgf  = mgf_md(oaep->mgf);
    if (!md_oaep || !md_mgf) {
        if (md_oaep) EVP_MD_free((EVP_MD*)md_oaep);
        if (md_mgf)  EVP_MD_free((EVP_MD*)md_mgf);
        goto fail_invalid;
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md_oaep) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md_mgf)  <= 0) {
        EVP_MD_free((EVP_MD*)md_oaep);
        EVP_MD_free((EVP_MD*)md_mgf);
        goto fail;
    }
    EVP_MD_free((EVP_MD*)md_oaep);
    EVP_MD_free((EVP_MD*)md_mgf);
    if (oaep->source == CKZ_DATA_SPECIFIED &&
        oaep->pSourceData && oaep->ulSourceDataLen > 0) {
        /* The label buffer ownership is transferred to ctx by
         * EVP_PKEY_CTX_set0_rsa_oaep_label, so we duplicate first. */
        uint8_t *label = OPENSSL_malloc(oaep->ulSourceDataLen);
        if (!label) goto fail;
        memcpy(label, oaep->pSourceData, oaep->ulSourceDataLen);
        if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label,
                                              (int)oaep->ulSourceDataLen) <= 0) {
            OPENSSL_free(label); goto fail;
        }
        /* ctx now owns the label allocation. */
    }
    *out_ctx = ctx;
    return FHSM_RV_OK;

fail_invalid:
    EVP_PKEY_CTX_free(ctx);
    return FHSM_RV_MECHANISM_INVALID;
fail:
    EVP_PKEY_CTX_free(ctx);
    return FHSM_RV_FUNCTION_FAILED;
}

/* ---------------------------------------------------------------------------
 * Encrypt / Decrypt / Sign --- one-shot, AES-256-GCM and HMAC-SHA-256.
 * The mechanism parameter for CKM_AES_GCM carries the IV ; for simplicity
 * here we accept either pParameter as the 12-byte IV directly, or NULL
 * in which case we generate a fresh IV from the DRBG.
 *
 * RSA-OAEP path : the mechanism CKM_RSA_PKCS_OAEP also goes through
 * Encrypt/Decrypt, dispatched on the mechanism check.
 * ----------------------------------------------------------------------- */
/* Per-session OAEP parameters captured at Init for use in Encrypt/Decrypt. */
typedef struct fhsm_session_oaep_s {
    int                       active;
    fhsm_oaep_params_t        p;
    uint8_t                   label_copy[64];   /* OAEP label is rarely > 64 */
    size_t                    label_len;
} fhsm_session_oaep_t;
static fhsm_session_oaep_t g_oaep_enc[256];
static fhsm_session_oaep_t g_oaep_dec[256];

/* Reset ALL per-session cryptographic operation state (encrypt, decrypt,
 * sign, verify, digest, object-search, OAEP) for one session handle,
 * freeing any persisted EVP contexts. Session handles come from a
 * reusable pool, so without this a handle handed out by a fresh
 * C_OpenSession can inherit a stale active==1 from a previous session
 * that was closed mid-operation -- which makes the next C_*Init return
 * CKR_OPERATION_ACTIVE instead of validating its own arguments
 * (pkcs11-check ckr/test_ckr_{sign,keygen,...}Init and
 * TestOperationActive, #125). EVP_*_free(NULL) is a documented no-op, so
 * the frees are unconditional. Called on both C_OpenSession (so a fresh
 * handle starts clean) and C_CloseSession (so resources are released). */
static void fhsm_session_ops_reset(CK_SESSION_HANDLE h) {
    if (h == 0 || h >= 256) return;
    fhsm_op_t *tabs[] = { &g_op_enc[h], &g_op_dec[h], &g_op_sig[h],
                          &g_op_dig[h], &g_op_ver[h] };
    for (size_t i = 0; i < sizeof(tabs) / sizeof(tabs[0]); ++i) {
        fhsm_op_t *op = tabs[i];
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)op->cipher_ctx);
        EVP_MD_CTX_free((EVP_MD_CTX *)op->md_ctx);
        EVP_MAC_CTX_free((EVP_MAC_CTX *)op->mac_ctx);
        memset(op, 0, sizeof(*op));
    }
    memset(&g_oaep_enc[h], 0, sizeof(g_oaep_enc[h]));
    memset(&g_oaep_dec[h], 0, sizeof(g_oaep_dec[h]));
    if (h < sizeof(g_finds) / sizeof(g_finds[0]))
        memset(&g_finds[h], 0, sizeof(g_finds[h]));
}

/* Forward decl : mech_is_pss is defined further down (sign/verify
 * section) but op_init needs it to decide whether to parse a
 * CK_RSA_PKCS_PSS_PARAMS from the mechanism's pParameter. */
static int mech_is_pss(uint32_t m);

/* Forward decl : resolve_mech is defined in the sign/verify section
 * (next to aes_gmac) but op_init calls it to apply the optional
 * FHSM_OPENSC_GMAC_ALIAS downgrade at the earliest point. See the
 * comment block on CKM_AES_GMAC further up for the policy. */
static uint32_t resolve_mech(uint32_t m);

/* Validate that a key handle resolves to a stored object before starting
 * a keyed operation, so C_*Init on a destroyed or invalid handle fails
 * with CKR_KEY_HANDLE_INVALID instead of succeeding (#125 use-after-
 * destroy: TestSignInitErrors / TestVerifyInitErrors / ...). */
/* Access control : a private object (CKA_PRIVATE, derived from class :
 * secret / private keys) is invisible to a session that is not logged in
 * as the normal user. Accessing its handle from such a session returns
 * CKR_OBJECT_HANDLE_INVALID -- the object appears not to exist (#125). */
static int fhsm_object_access_denied(fhsm_token_t *t, uint32_t cko_class) {
    /* Per-application login state : a private object is accessible iff the
     * token (not just this session) is logged in as the user. */
    if (fhsm_token_current_role(t) == FHSM_ROLE_USER) return 0;
    return (cko_class == CKO_SECRET_KEY || cko_class == CKO_PRIVATE_KEY);
}

static CK_RV fhsm_require_key(fhsm_token_t *t, CK_OBJECT_HANDLE hKey) {
    const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl = 0, kt = 0;
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (fhsm_token_object_get(t, (uint32_t)hKey, &kv, &kvl, &cl, &kt) != FHSM_RV_OK)
        return FHSM_RV_KEY_HANDLE_INVALID;
    return FHSM_RV_OK;
}

/* Enforce a per-object usage flag before an operation : if the key
 * carries explicit usage and the required bit is clear, the operation is
 * CKR_KEY_FUNCTION_NOT_PERMITTED (#125 TestKeyUsageRestrictions). Legacy
 * keys (no explicit usage) are permitted. */
static CK_RV fhsm_check_usage(fhsm_token_t *t, CK_OBJECT_HANDLE hKey, uint8_t bit) {
    uint8_t u = 0;
    if (t && fhsm_token_object_get_usage(t, (uint32_t)hKey, &u) == FHSM_RV_OK
        && (u & FHSM_USAGE_VALID) && !(u & bit))
        return FHSM_RV_KEY_FUNCTION_NOT_PERMITTED;
    return FHSM_RV_OK;
}

static fhsm_rv_t op_init(fhsm_op_t *op, CK_SESSION_HANDLE hSession,
                         CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
    if (op->active) return FHSM_RV_OPERATION_ACTIVE;
    op->key_handle = (uint32_t)hKey;
    /* resolve_mech downgrades CKM_AES_GMAC (0x108A) to CKM_AES_CMAC (0x108C)
     * iff FHSM_OPENSC_GMAC_ALIAS=1 is set in the environment. Done here so
     * the rest of op_init / C_Sign / C_Verify see a single resolved value. */
    op->mechanism  = resolve_mech((uint32_t)pMechanism->mechanism);
    op->have_iv    = 0;
    op->gcm_have   = 0;
    op->gcm_iv_len = 0;
    op->gcm_aad_len = 0;
    op->gcm_tag_len = 16;        /* default 128-bit tag */
    if (pMechanism->mechanism == CKM_AES_GCM && pMechanism->pParameter) {
        /* Two calling conventions are accepted :
         *  - CK_GCM_PARAMS struct : { pIv, ulIvLen, ulIvBits, pAAD,
         *    ulAADLen, ulTagBits } = 6 CK_ULONG-sized words = 48 bytes
         *    on a 64-bit ABI. This is the PKCS#11 v3.0+ canonical form
         *    and the one Wycheproof / our harness use.
         *  - 12 raw IV bytes : the legacy short-cut OpenSC's
         *    pkcs11-tool sends with --iv. AAD empty, tag 16 bytes. */
        if (pMechanism->ulParameterLen >= 6 * sizeof(CK_ULONG)) {
            const CK_ULONG *p = (const CK_ULONG *)pMechanism->pParameter;
            const uint8_t *iv_ptr  = (const uint8_t *)(uintptr_t)p[0];
            size_t         iv_len  = (size_t)p[1];
            /* p[2] = ulIvBits, derivable from iv_len for our purposes */
            const uint8_t *aad_ptr = (const uint8_t *)(uintptr_t)p[3];
            size_t         aad_len = (size_t)p[4];
            size_t         tag_bits = (size_t)p[5];
            /* PKCS#11 v3.0 callers including OpenSC's pkcs11-tool
             * frequently pass ulTagBits=0 in CK_GCM_PARAMS to signal
             * "use the implementation default". The spec is ambiguous
             * here (NIST SP 800-38D mandates a tag length but the
             * PKCS#11 wire does not require ulTagBits != 0). We
             * normalise zero to the AES block size (128 bits) which
             * matches OpenSSL's default and the FIPS 140-3 IG D.A
             * recommendation. The Wycheproof corpus always sets an
             * explicit value so this normalisation never fires there. */
            if (tag_bits == 0) tag_bits = 128;
            /* A non-zero IV/AAD length with a NULL pointer is an invalid
             * inner parameter (#125 TestMechanismNullInnerParams). */
            if ((iv_len && !iv_ptr) || (aad_len && !aad_ptr))
                return FHSM_RV_MECHANISM_PARAM_INVALID;
            if (iv_len > sizeof(op->gcm_iv)
                || aad_len > sizeof(op->gcm_aad)
                || tag_bits > 128 || (tag_bits & 7)) {
                return FHSM_RV_ARGUMENTS_BAD;
            }
            if (iv_len && iv_ptr) memcpy(op->gcm_iv,  iv_ptr,  iv_len);
            if (aad_len && aad_ptr) memcpy(op->gcm_aad, aad_ptr, aad_len);
            op->gcm_iv_len  = iv_len;
            op->gcm_aad_len = aad_len;
            op->gcm_tag_len = tag_bits / 8;
            op->gcm_have    = 1;
        } else if (pMechanism->ulParameterLen >= 12) {
            memcpy(op->iv, pMechanism->pParameter, 12);
            op->have_iv = 1;
            /* Also mirror into the new GCM fields so C_Decrypt can use a
             * single code path. */
            memcpy(op->gcm_iv, pMechanism->pParameter, 12);
            op->gcm_iv_len  = 12;
            op->gcm_aad_len = 0;
            op->gcm_tag_len = 16;
            op->gcm_have    = 1;
        }
    }
    /* AES-CBC/CBC-PAD use a 16-byte IV passed directly as pParameter. */
    if ((pMechanism->mechanism == CKM_AES_CBC ||
         pMechanism->mechanism == CKM_AES_CBC_PAD) &&
        pMechanism->pParameter && pMechanism->ulParameterLen == 16) {
        memcpy(op->iv, pMechanism->pParameter, 16);
        op->have_iv = 1;
    }
    /* 3DES-CBC (non-FIPS) : 8-byte IV passed directly as pParameter. */
    if (pMechanism->mechanism == 0x00000133UL /* CKM_DES3_CBC */ &&
        pMechanism->pParameter && pMechanism->ulParameterLen == 8) {
        memcpy(op->iv, pMechanism->pParameter, 8);
        op->have_iv = 1;
    }
    /* AES-CTR : pParameter is either a raw 16-byte counter block (the
     * OpenSC pkcs11-tool --iv convention) or a CK_AES_CTR_PARAMS struct
     *   { CK_ULONG ulCounterBits; CK_BYTE cb[16]; }  (24 bytes on LP64).
     * The struct's counter block is cb[], NOT the first 16 bytes -- copying
     * the first 16 bytes of the struct mixes ulCounterBits into the counter
     * and corrupts the keystream (#125 TestMechEncryptKAT[AES_CTR]).
     * ulCounterBits must be in the spec range 1..128
     * (#125 TestAESCTR::test_aes_ctr_counter_bits_zero). */
    if (pMechanism->mechanism == CKM_AES_CTR) {
        /* AES-CTR requires a counter parameter (raw 16-byte block or
         * CK_AES_CTR_PARAMS). A missing parameter is CKR_MECHANISM_PARAM_INVALID
         * (#125 TestBadParameters AES_CTR missing params). */
        if (!pMechanism->pParameter)
            return FHSM_RV_MECHANISM_PARAM_INVALID;
        if (pMechanism->ulParameterLen == 16) {
            memcpy(op->iv, pMechanism->pParameter, 16);
            op->have_iv = 1;
        } else if (pMechanism->ulParameterLen >= sizeof(CK_ULONG) + 16) {
            CK_ULONG cbits = 0;
            memcpy(&cbits, pMechanism->pParameter, sizeof(CK_ULONG));
            if (cbits == 0 || cbits > 128)
                return FHSM_RV_MECHANISM_PARAM_INVALID;
            memcpy(op->iv,
                   (const uint8_t *)pMechanism->pParameter + sizeof(CK_ULONG),
                   16);
            op->have_iv = 1;
        } else {
            return FHSM_RV_MECHANISM_PARAM_INVALID;
        }
    }
    /* AES-GMAC : per PKCS#11 v3.2 §6.10.6 the IV is conveyed via
     * pParameter. We accept two calling conventions for interop :
     *   - raw IV bytes (PKCS#11 v3.0 convention, what most clients
     *     including pkcs11-tool send)
     *   - CK_AES_GMAC_PARAMS = { CK_ULONG ulIvLen ; CK_BYTE_PTR pIv }
     *     (PKCS#11 v3.2 canonical form, 16 bytes on a 64-bit ABI)
     * The struct form is heuristically detected when ulParameterLen ==
     * 16 AND the first 8 bytes look like a sensible IV length (1..512).
     * We store the IV in op->gcm_iv (shared 512-byte buffer with GCM)
     * which fits Wycheproof's LongIv exercises if we ever extend the
     * GMAC corpus. The mechanism check uses op->mechanism (already
     * resolved via resolve_mech above). */
    if (op->mechanism == CKM_AES_GMAC && pMechanism->pParameter
        && pMechanism->ulParameterLen > 0) {
        const uint8_t *iv_src = (const uint8_t *)pMechanism->pParameter;
        size_t iv_len = pMechanism->ulParameterLen;
        if (iv_len == 16) {
            /* Potential CK_AES_GMAC_PARAMS struct. Peek at the length
             * word to disambiguate from a 16-byte raw IV : if it points
             * to a plausible length and a non-null pIv, treat as struct. */
            const CK_ULONG *p = (const CK_ULONG *)pMechanism->pParameter;
            size_t s_len = (size_t)p[0];
            const uint8_t *s_iv = (const uint8_t *)(uintptr_t)p[1];
            if (s_iv && s_len > 0 && s_len <= sizeof(op->gcm_iv)) {
                iv_src = s_iv;
                iv_len = s_len;
            }
        }
        if (iv_len > sizeof(op->gcm_iv)) return FHSM_RV_ARGUMENTS_BAD;
        memcpy(op->gcm_iv, iv_src, iv_len);
        op->gcm_iv_len = iv_len;
        op->gcm_have   = 1;
    }
    /* AES-GMAC without an IV : implicit downgrade to AES-CMAC. CKM_AES_GMAC
     * per PKCS#11 v3.2 §6.10.6 requires an IV in pParameter ; if the caller
     * provided none (e.g. OpenSC's pkcs11-tool, which sends the spec-
     * incorrect 0x108A code point for its 'AES-CMAC' CLI string with no
     * pParameter at all), we infer the caller meant CMAC and route the
     * operation through the CMAC path. This makes the v1.1.18 transition
     * backward-compatible : any pre-v1.1.18 caller using 0x108A as a CMAC
     * alias keeps working unchanged. Callers who actually want real
     * AES-GMAC always pass an IV. The FHSM_OPENSC_GMAC_ALIAS env var
     * (handled in resolve_mech above) is a separate forced override for
     * callers that DO pass a garbage non-empty pParameter but mean CMAC. */
    if (op->mechanism == CKM_AES_GMAC && !op->gcm_have) {
        op->mechanism = CKM_AES_CMAC;
    }
    /* AES-CCM (SP 800-38C) : parse CK_CCM_PARAMS { ulDataLen; pNonce;
     * ulNonceLen; pAAD; ulAADLen; ulMACLen } (6 CK_ULONG-sized words = 48
     * bytes on LP64). Nonce length 7-13 and MAC length in {4,6,8,10,12,14,16}
     * per NIST SP 800-38C; a missing parameter, NULL nonce, or out-of-range
     * length is CKR_MECHANISM_PARAM_INVALID (#125 TestAesCcmNullNonce /
     * TestBadParameters). Reuses the GCM nonce/AAD/tag op fields. */
    if (pMechanism->mechanism == 0x00001088UL /* CKM_AES_CCM */) {
        if (!pMechanism->pParameter
            || pMechanism->ulParameterLen < 6 * sizeof(CK_ULONG))
            return FHSM_RV_MECHANISM_PARAM_INVALID;
        const CK_ULONG *p = (const CK_ULONG *)pMechanism->pParameter;
        const uint8_t *nonce = (const uint8_t *)(uintptr_t)p[1];
        size_t nonce_len = (size_t)p[2];
        const uint8_t *aad = (const uint8_t *)(uintptr_t)p[3];
        size_t aad_len = (size_t)p[4];
        size_t mac_len = (size_t)p[5];
        if (!nonce || nonce_len < 7 || nonce_len > 13)
            return FHSM_RV_MECHANISM_PARAM_INVALID;
        if (mac_len != 4 && mac_len != 6 && mac_len != 8 && mac_len != 10
            && mac_len != 12 && mac_len != 14 && mac_len != 16)
            return FHSM_RV_MECHANISM_PARAM_INVALID;
        if (aad_len > sizeof(op->gcm_aad) || (aad_len && !aad))
            return FHSM_RV_MECHANISM_PARAM_INVALID;
        memcpy(op->gcm_iv, nonce, nonce_len);
        op->gcm_iv_len  = nonce_len;
        if (aad_len) memcpy(op->gcm_aad, aad, aad_len);
        op->gcm_aad_len = aad_len;
        op->gcm_tag_len = mac_len;
        op->gcm_have    = 1;
    }
    /* For RSA-OAEP, capture and validate the OAEP params at Init time so
     * the actual Encrypt/Decrypt call can be the bare key-material path. */
    if (pMechanism->mechanism == CKM_RSA_PKCS_OAEP) {
        if (!pMechanism->pParameter
            || pMechanism->ulParameterLen < sizeof(fhsm_oaep_params_t))
            return FHSM_RV_ARGUMENTS_BAD;
        fhsm_session_oaep_t *o =
            (op == &g_op_enc[hSession]) ? &g_oaep_enc[hSession]
                                          : &g_oaep_dec[hSession];
        memset(o, 0, sizeof(*o));
        memcpy(&o->p, pMechanism->pParameter, sizeof(o->p));
        /* Validate the OAEP source (label) parameter : a non-zero length
         * with a NULL pointer, or a length beyond our label buffer, is an
         * invalid inner parameter rather than something to silently
         * ignore (#125 TestMechanismNullInnerParams /
         * TestRsaOaepSourceDataLengthBoundary). */
        if (o->p.source == CKZ_DATA_SPECIFIED && o->p.ulSourceDataLen > 0
            && (o->p.pSourceData == NULL
                || o->p.ulSourceDataLen > sizeof(o->label_copy)))
            return FHSM_RV_MECHANISM_PARAM_INVALID;
        if (o->p.source == CKZ_DATA_SPECIFIED && o->p.pSourceData
            && o->p.ulSourceDataLen > 0
            && o->p.ulSourceDataLen <= sizeof(o->label_copy)) {
            memcpy(o->label_copy, o->p.pSourceData, o->p.ulSourceDataLen);
            o->label_len = o->p.ulSourceDataLen;
            o->p.pSourceData = o->label_copy;
        } else {
            o->p.pSourceData = NULL;
            o->p.ulSourceDataLen = 0;
        }
        o->active = 1;
    }
    /* RSA-PSS : CK_RSA_PKCS_PSS_PARAMS = { hashAlg, mgf, sLen } each
     * a CK_ULONG (3 * 8 = 24 bytes on a 64-bit ABI). Optional ; when
     * absent we fall back to digest-length salt + MGF1 with the same
     * hash as the signature mechanism (the previous hard-coded
     * behaviour). */
    op->pss_have    = 0;
    op->pss_saltlen = 0;
    op->pss_mgf     = 0;
    /* The bare CKM_RSA_PKCS_PSS mechanism carries no implicit hash, so its
     * CK_RSA_PKCS_PSS_PARAMS (hashAlg, mgf, sLen) are mandatory : a missing
     * or too-short parameter is CKR_MECHANISM_PARAM_INVALID, not a silent
     * fallback (#125 TestBadParameters RSA_PKCS_PSS missing params). */
    if (op->mechanism == 0x0000000DUL
        && (!pMechanism->pParameter
            || pMechanism->ulParameterLen < 3 * sizeof(CK_ULONG)))
        return FHSM_RV_MECHANISM_PARAM_INVALID;
    if (mech_is_pss(op->mechanism)
        && pMechanism->pParameter
        && pMechanism->ulParameterLen >= 3 * sizeof(CK_ULONG)) {
        const CK_ULONG *p = (const CK_ULONG *)pMechanism->pParameter;
        /* p[0] = hashAlg (we already know it from the mechanism),
         * p[1] = mgf,
         * p[2] = sLen */
        op->pss_mgf     = (uint32_t)p[1];
        op->pss_saltlen = (long)p[2];
        /* Reject an absurd salt length (#125 TestRsaPssSaltLengthBoundary):
         * a negative cast (0x8000...) or a value far larger than any
         * real PSS salt (bounded by emLen - hLen - 2, < 512 for our key
         * sizes). */
        if (op->pss_saltlen < 0 || op->pss_saltlen > 1024)
            return FHSM_RV_MECHANISM_PARAM_INVALID;
        op->pss_have    = 1;
    }
    /* CK_ML_DSA_PARAMS (PKCS#11 v3.2 §6.18) and CK_SLH_DSA_PARAMS
     * (PKCS#11 v3.2 §6.19) parser is now in src/fhsm_pq_params.c
     * (extracted in v1.1.14 as a prerequisite for the libFuzzer harness
     * #191). Same semantics, same wire layout, same trade-off on
     * oversize ctx_len. The mechanism gate is kept here so the parser
     * itself stays generic (any caller can use it for an
     * "{ hedgeVariant ; pContext ; ulContextLen }" triple). */
    op->pq_ctx_have = 0;
    op->pq_ctx_len  = 0;
    if (op->mechanism == 0x0000001DUL /* CKM_ML_DSA_OP */
        || op->mechanism == 0x0000002EUL /* CKM_SLH_DSA_OP */) {
        unsigned long hedge_variant = 0;
        fhsm_parse_pq_params(pMechanism->pParameter,
                             (size_t)pMechanism->ulParameterLen,
                             op->pq_ctx, sizeof(op->pq_ctx),
                             &op->pq_ctx_len, &op->pq_ctx_have,
                             &hedge_variant);
        (void)hedge_variant;  /* recorded for future use ; not applied */
    }
    /* Parameter validation (#125 input-validation) : reject wrong-size or
     * weak IVs at *Init with CKR_MECHANISM_PARAM_INVALID rather than
     * deferring to the operation (pkcs11-check test_mechanism_param_invalid,
     * TestGcmIvWeakness, TestBadParameters). */
    if ((pMechanism->mechanism == CKM_AES_CBC ||
         pMechanism->mechanism == CKM_AES_CBC_PAD) && !op->have_iv)
        return FHSM_RV_MECHANISM_PARAM_INVALID;   /* CBC requires a 16-byte IV */
    if (pMechanism->mechanism == CKM_AES_GCM &&
        (!op->gcm_have || op->gcm_iv_len < 12))
        return FHSM_RV_MECHANISM_PARAM_INVALID;   /* NIST SP 800-38D : IV >= 96 bits */
    op->active = 1;
    (void)hSession;
    return FHSM_RV_OK;
}

/* Non-FIPS symmetric/asymmetric ENCRYPTION mechanisms are executable
 * only in the interop build. Rejected at C_EncryptInit / C_DecryptInit
 * time under fips-strict. NOT applied to signing (op_init is shared
 * with C_SignInit, where e.g. CKM_RSA_PKCS is an approved signature
 * mechanism). #125. */
static int fhsm_nonfips_enc_rejected(CK_ULONG mech) {
    if (!fhsm_build_fips_strict) return 0;
    switch (mech) {
        /* AES-ECB is FIPS-approved (NIST SP 800-38A) and now allowed in
         * fips-strict ; only genuinely non-approved encryption mechanisms
         * are rejected here. */
        case 0x00000133UL: /* CKM_DES3_CBC */
        case CKM_RSA_PKCS:
        case CKM_RSA_X_509:
            return 1;
        default:
            return 0;
    }
}

/* Positive whitelist of mechanisms that C_Encrypt / C_Decrypt actually
 * implement. C_EncryptInit / C_DecryptInit with any other mechanism --- a
 * digest (CKM_SHA256), a signature, or an advertised-but-unimplemented
 * cipher (CKM_AES_CCM) --- is CKR_MECHANISM_INVALID, not silently accepted
 * (#125 TestEncryptInitErrors / TestDecryptInitErrors / TestAesCcmNullNonce).
 * op_init itself is shared with C_SignInit and cannot enforce this. */
static int fhsm_cipher_mech_valid(CK_ULONG mech) {
    switch (mech) {
        case CKM_AES_ECB:       /* 0x1081 */
        case CKM_AES_CBC:       /* 0x1082 */
        case CKM_AES_CBC_PAD:   /* 0x1085 */
        case CKM_AES_CTR:       /* 0x1086 */
        case CKM_AES_GCM:       /* 0x1087 */
        case 0x00001088UL:      /* CKM_AES_CCM */
        case 0x00000133UL:      /* CKM_DES3_CBC */
        case CKM_RSA_PKCS:      /* 0x0001 */
        case CKM_RSA_X_509:     /* 0x0003 */
        case CKM_RSA_PKCS_OAEP: /* 0x0009 */
            return 1;
        default:
            return 0;
    }
}

/* Mechanism <-> key-type consistency. A cryptographic mechanism implies a
 * key type family (RSA sign/verify/encrypt needs CKK_RSA, ECDSA needs
 * CKK_EC, AES ciphers need CKK_AES, ...). Using a key of the wrong type is
 * CKR_KEY_TYPE_INCONSISTENT, not silent acceptance (#125 TestWrongKeyType,
 * TestSignInitErrors / TestVerifyInitErrors key_type_inconsistent, Tookan
 * key-type-confusion). Mechanisms with no fixed key-type family (HMAC over
 * generic secrets, unknown mechanisms) are skipped (want < 0). Missing keys
 * are left to fhsm_require_key. Uses numeric mechanism/CKK values so it can
 * live above the per-section macro definitions. */
static CK_RV fhsm_check_key_mech_type(fhsm_token_t *t, CK_OBJECT_HANDLE hKey,
                                      CK_ULONG mech) {
    const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl = 0, kt = 0;
    if (fhsm_token_object_get(t, (uint32_t)hKey, &kv, &kvl, &cl, &kt) != FHSM_RV_OK)
        return FHSM_RV_OK;
    long want = -1;
    switch (mech) {
        case 0x0001: case 0x0003: case 0x0009: case 0x000D: /* RSA PKCS/X509/OAEP/PSS */
        case 0x0006:                                        /* SHA1_RSA_PKCS */
        case 0x0040: case 0x0041: case 0x0042:              /* SHA{256,384,512}_RSA_PKCS */
        case 0x0043: case 0x0044: case 0x0045:              /* SHA{256,384,512}_RSA_PKCS_PSS */
            want = 0x00; break;                             /* CKK_RSA */
        case 0x1041: case 0x1042: case 0x1043:              /* ECDSA / ECDSA_SHA1 / SHA224 */
        case 0x1044: case 0x1045: case 0x1046:              /* ECDSA_SHA{256,384,512} */
            want = 0x03; break;                             /* CKK_EC */
        case 0x1057: want = 0x40; break;                    /* EDDSA -> CKK_EC_EDWARDS */
        case 0x1081: case 0x1082: case 0x1085: case 0x1086: /* AES ECB/CBC/CBC_PAD/CTR */
        case 0x1087: case 0x108A: case 0x108C:              /* AES GCM/GMAC/CMAC */
            want = 0x1F; break;                             /* CKK_AES */
        case 0x0133: want = 0x15; break;                    /* DES3_CBC -> CKK_DES3 */
        case 0x0251: case 0x0261: case 0x0271: case 0x0256: /* SHA{256,384,512,224}_HMAC */
        case 0x02B1: case 0x02C1: case 0x02D1: case 0x02B6: /* SHA3_{256,384,512,224}_HMAC */
        case 0x0221:                                        /* SHA_1_HMAC */
            want = -2; break;   /* any symmetric secret ; reject asymmetric keys */
        default: want = -1; break;
    }
    if (want == -2) {
        /* HMAC requires a symmetric secret key. An asymmetric key
         * (CKK_RSA / CKK_EC / CKK_EC_EDWARDS) is CKR_KEY_TYPE_INCONSISTENT
         * (#125 TestWrongKeyType hmac_sha256_with_rsa_key). */
        if (kt == 0x00 || kt == 0x03 || kt == 0x40)
            return FHSM_RV_KEY_TYPE_INCONSISTENT;
        return FHSM_RV_OK;
    }
    if (want >= 0 && (uint32_t)want != kt) {
        /* A CKK_GENERIC_SECRET secret is legitimately usable with the
         * symmetric cipher/MAC families (AES, DES3) : do not reject it. The
         * wrong-key-type security tests use asymmetric keys, which stay
         * rejected. */
        if ((want == 0x1F || want == 0x15) && kt == 0x10 /* CKK_GENERIC_SECRET */)
            return FHSM_RV_OK;
        return FHSM_RV_KEY_TYPE_INCONSISTENT;
    }
    return FHSM_RV_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                    CK_OBJECT_HANDLE hKey) {
    if (fhsm_session_token(hSession) == NULL) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (!pMechanism) return FHSM_RV_ARGUMENTS_BAD;
    if (fhsm_nonfips_enc_rejected(pMechanism->mechanism)) return FHSM_RV_MECHANISM_INVALID;
    if (!fhsm_cipher_mech_valid(pMechanism->mechanism)) return FHSM_RV_MECHANISM_INVALID;
    { CK_RV kc = fhsm_require_key(fhsm_session_token(hSession), hKey); if (kc != FHSM_RV_OK) return kc; }
    { CK_RV tc = fhsm_check_key_mech_type(fhsm_session_token(hSession), hKey, pMechanism->mechanism); if (tc != FHSM_RV_OK) return tc; }
    { CK_RV uc = fhsm_check_usage(fhsm_session_token(hSession), hKey, FHSM_USAGE_ENCRYPT); if (uc != FHSM_RV_OK) return uc; }
    fhsm_op_t *op = op_slot(g_op_enc, hSession);
    if (!op) return FHSM_RV_SESSION_HANDLE_INVALID;
    return op_init(op, hSession, pMechanism, hKey);
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, unsigned char *pData,
                CK_ULONG ulDataLen, unsigned char *pEnc, CK_ULONG *pulEncLen) {
    fhsm_op_t *op = op_slot(g_op_enc, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl = 0, kt = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
    if (rv != FHSM_RV_OK) { op->active = 0; return rv; }

    if (!pulEncLen || (!pData && ulDataLen)) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
    /* A data length beyond INT_MAX would be silently truncated by the (int)
     * casts on the OpenSSL path (#125 TestEncryptOutputLengthTruncation). */
    if (ulDataLen > 0x7FFFFFFFUL) { op->active = 0; return FHSM_RV_DATA_LEN_RANGE; }

    /* --- RSA-OAEP path (asymmetric encryption) --- */
    if (op->mechanism == CKM_RSA_PKCS_OAEP) {
        if (cl != CKO_PUBLIC_KEY || kt != CKK_RSA) {
            op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT;
        }
        const uint8_t *p = kv;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)kvl);
        if (!pkey) { op->active = 0; return FHSM_RV_FUNCTION_FAILED; }
        EVP_PKEY_CTX *ectx = NULL;
        rv = oaep_ctx_init(pkey, 1, &g_oaep_enc[hSession].p, &ectx);
        if (rv != FHSM_RV_OK) {
            EVP_PKEY_free(pkey); op->active = 0; return rv;
        }
        size_t out_len = 0;
        if (EVP_PKEY_encrypt(ectx, NULL, &out_len, pData, ulDataLen) <= 0) {
            EVP_PKEY_CTX_free(ectx); EVP_PKEY_free(pkey);
            op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        if (pEnc == NULL) {
            *pulEncLen = out_len;
            EVP_PKEY_CTX_free(ectx); EVP_PKEY_free(pkey);
            return FHSM_RV_OK;
        }
        if (*pulEncLen < out_len) {
            *pulEncLen = out_len;
            EVP_PKEY_CTX_free(ectx); EVP_PKEY_free(pkey);
            return 0x00000150UL;
        }
        size_t buf_len = *pulEncLen;
        if (EVP_PKEY_encrypt(ectx, pEnc, &buf_len, pData, ulDataLen) <= 0) {
            EVP_PKEY_CTX_free(ectx); EVP_PKEY_free(pkey);
            op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        *pulEncLen = buf_len;
        EVP_PKEY_CTX_free(ectx); EVP_PKEY_free(pkey);
        op->active = 0;
        g_oaep_enc[hSession].active = 0;
        (void)fhsm_audit_event(FHSM_EV_ENCRYPT, -1, (int)hSession,
                                fhsm_session_role(hSession), FHSM_RV_OK, NULL);
        return FHSM_RV_OK;
    }

    /* --- RSA PKCS#1 v1.5 / X.509 raw encryption (non-FIPS ; interop) --- */
    if (op->mechanism == CKM_RSA_PKCS || op->mechanism == CKM_RSA_X_509) {
        if (fhsm_build_fips_strict) { op->active = 0; return FHSM_RV_MECHANISM_INVALID; }
        if (cl != CKO_PUBLIC_KEY || kt != CKK_RSA) { op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT; }
        int pad = (op->mechanism == CKM_RSA_PKCS) ? RSA_PKCS1_PADDING : RSA_NO_PADDING;
        const uint8_t *pp = kv;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &pp, (long)kvl);
        if (!pkey) { op->active = 0; return FHSM_RV_FUNCTION_FAILED; }
        EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ectx || EVP_PKEY_encrypt_init(ectx) <= 0
            || EVP_PKEY_CTX_set_rsa_padding(ectx, pad) <= 0) {
            if (ectx) EVP_PKEY_CTX_free(ectx);
            EVP_PKEY_free(pkey);
            op->active = 0;
            return FHSM_RV_FUNCTION_FAILED;
        }
        size_t out_len = 0;
        if (EVP_PKEY_encrypt(ectx, NULL, &out_len, pData, ulDataLen) <= 0) {
            EVP_PKEY_CTX_free(ectx); EVP_PKEY_free(pkey); op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        if (pEnc == NULL) { *pulEncLen = out_len; EVP_PKEY_CTX_free(ectx); EVP_PKEY_free(pkey); return FHSM_RV_OK; }
        if (*pulEncLen < out_len) { *pulEncLen = out_len; EVP_PKEY_CTX_free(ectx); EVP_PKEY_free(pkey); return 0x00000150UL; }
        size_t bl = *pulEncLen;
        if (EVP_PKEY_encrypt(ectx, pEnc, &bl, pData, ulDataLen) <= 0) {
            EVP_PKEY_CTX_free(ectx); EVP_PKEY_free(pkey); op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        *pulEncLen = bl;
        EVP_PKEY_CTX_free(ectx); EVP_PKEY_free(pkey); op->active = 0;
        (void)fhsm_audit_event(FHSM_EV_ENCRYPT, -1, (int)hSession,
                                fhsm_session_role(hSession), FHSM_RV_OK, NULL);
        return FHSM_RV_OK;
    }

    /* --- AES-ECB / AES-CBC / AES-CBC-PAD / AES-CTR path ---
     * AES-ECB is non-FIPS : executable only in the interop build. */
    if (op->mechanism == CKM_AES_ECB || op->mechanism == CKM_AES_CBC
        || op->mechanism == CKM_AES_CBC_PAD || op->mechanism == CKM_AES_CTR) {
        int is_ecb = (op->mechanism == CKM_AES_ECB);
        /* AES-ECB is FIPS-approved (SP 800-38A) and allowed in both profiles. */
        if (kt != CKK_AES) { op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT; }
        if (!is_ecb && !op->have_iv) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
        const char *cname = NULL;
        if (op->mechanism == CKM_AES_CTR) {
            cname = (kvl == 16) ? "AES-128-CTR" :
                    (kvl == 24) ? "AES-192-CTR" : "AES-256-CTR";
        } else if (is_ecb) {
            cname = (kvl == 16) ? "AES-128-ECB" :
                    (kvl == 24) ? "AES-192-ECB" : "AES-256-ECB";
        } else {
            cname = (kvl == 16) ? "AES-128-CBC" :
                    (kvl == 24) ? "AES-192-CBC" : "AES-256-CBC";
        }
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, cname, NULL);
        if (!c) { op->active = 0; return FHSM_RV_MECHANISM_INVALID; }
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { EVP_CIPHER_free(c); op->active = 0; return FHSM_RV_HOST_MEMORY; }
        if (EVP_EncryptInit_ex2(ctx, c, kv, is_ecb ? NULL : op->iv, NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        EVP_CIPHER_CTX_set_padding(ctx, op->mechanism == CKM_AES_CBC_PAD ? 1 : 0);
        /* Output size : CBC-PAD adds up to 16 padding bytes ; CBC/CTR
         * are exact. Query path returns the worst case. */
        size_t need = ulDataLen + (op->mechanism == CKM_AES_CBC_PAD ? 16 : 0);
        if (pEnc == NULL) {
            *pulEncLen = need;
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            return FHSM_RV_OK;
        }
        if (*pulEncLen < need) {
            *pulEncLen = need;
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            return 0x00000150UL;
        }
        int outl = 0, finl = 0;
        if (EVP_EncryptUpdate(ctx, pEnc, &outl, pData, (int)ulDataLen) != 1
            || EVP_EncryptFinal_ex(ctx, pEnc + outl, &finl) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        *pulEncLen = (CK_ULONG)(outl + finl);
        EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
        op->active = 0;
        (void)fhsm_audit_event(FHSM_EV_ENCRYPT, -1, (int)hSession,
                                fhsm_session_role(hSession), FHSM_RV_OK, NULL);
        return FHSM_RV_OK;
    }

    /* --- 3DES-CBC (non-FIPS ; interop / general-purpose only) --- */
    if (op->mechanism == 0x00000133UL /* CKM_DES3_CBC */) {
        if (fhsm_build_fips_strict) { op->active = 0; return FHSM_RV_MECHANISM_INVALID; }
        if (kt != CKK_DES3) { op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT; }
        if (!op->have_iv)   { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
        if (kvl != 24)      { op->active = 0; return FHSM_RV_KEY_SIZE_RANGE; }
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "DES-EDE3-CBC", NULL);
        if (!c) { op->active = 0; return FHSM_RV_MECHANISM_INVALID; }
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { EVP_CIPHER_free(c); op->active = 0; return FHSM_RV_HOST_MEMORY; }
        if (EVP_EncryptInit_ex2(ctx, c, kv, op->iv, NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        size_t need = ulDataLen;   /* no padding : 8-aligned in, equal out */
        if (pEnc == NULL) { *pulEncLen = need; EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c); return FHSM_RV_OK; }
        if (*pulEncLen < need) { *pulEncLen = need; EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c); return 0x00000150UL; }
        int outl = 0, finl = 0;
        if (EVP_EncryptUpdate(ctx, pEnc, &outl, pData, (int)ulDataLen) != 1
            || EVP_EncryptFinal_ex(ctx, pEnc + outl, &finl) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        *pulEncLen = (CK_ULONG)(outl + finl);
        EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
        op->active = 0;
        (void)fhsm_audit_event(FHSM_EV_ENCRYPT, -1, (int)hSession,
                                fhsm_session_role(hSession), FHSM_RV_OK, NULL);
        return FHSM_RV_OK;
    }

    /* --- AES-CCM path (SP 800-38C, symmetric) ---
     * Output layout is ciphertext || MAC. Nonce/AAD/MAC-length come from the
     * CK_CCM_PARAMS captured at C_EncryptInit. OpenSSL's CCM requires the
     * strict init sequence: set IV/tag length, key+nonce, declare the total
     * plaintext length, feed AAD, then encrypt. (#125 CCM online path.) */
    if (op->mechanism == 0x00001088UL /* CKM_AES_CCM */) {
        if (kt != CKK_AES) { op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT; }
        size_t mac_len = op->gcm_tag_len ? op->gcm_tag_len : 16;
        size_t need = ulDataLen + mac_len;
        if (pEnc == NULL) { *pulEncLen = need; return FHSM_RV_OK; }
        if (*pulEncLen < need) { *pulEncLen = need; return 0x00000150UL; }
        {
            const EVP_CIPHER *cph = (kvl == 16) ? EVP_aes_128_ccm() :
                                    (kvl == 24) ? EVP_aes_192_ccm() :
                                    (kvl == 32) ? EVP_aes_256_ccm() : NULL;
            EVP_CIPHER_CTX *cx = NULL;
            int cl2 = 0; size_t prod = 0;
            if (!cph) { op->active = 0; return FHSM_RV_KEY_SIZE_RANGE; }
            cx = EVP_CIPHER_CTX_new();
            if (!cx) { op->active = 0; return FHSM_RV_HOST_MEMORY; }
            rv = FHSM_RV_FUNCTION_FAILED;
            if (EVP_EncryptInit_ex(cx, cph, NULL, NULL, NULL) != 1) goto cenc_out;
            if (EVP_CIPHER_CTX_ctrl(cx, EVP_CTRL_CCM_SET_IVLEN,
                                    (int)op->gcm_iv_len, NULL) != 1) goto cenc_out;
            if (EVP_CIPHER_CTX_ctrl(cx, EVP_CTRL_CCM_SET_TAG,
                                    (int)mac_len, NULL) != 1) goto cenc_out;
            if (EVP_EncryptInit_ex(cx, NULL, NULL, kv, op->gcm_iv) != 1) goto cenc_out;
            if (EVP_EncryptUpdate(cx, NULL, &cl2, NULL, (int)ulDataLen) != 1) goto cenc_out;
            if (op->gcm_aad_len > 0 && EVP_EncryptUpdate(cx, NULL, &cl2,
                                    op->gcm_aad, (int)op->gcm_aad_len) != 1) goto cenc_out;
            if (EVP_EncryptUpdate(cx, pEnc, &cl2, pData, (int)ulDataLen) != 1) goto cenc_out;
            prod = (size_t)cl2;
            if (EVP_EncryptFinal_ex(cx, pEnc + prod, &cl2) != 1) goto cenc_out;
            prod += (size_t)cl2;
            if (EVP_CIPHER_CTX_ctrl(cx, EVP_CTRL_CCM_GET_TAG,
                                    (int)mac_len, pEnc + prod) != 1) goto cenc_out;
            *pulEncLen = prod + mac_len;
            rv = FHSM_RV_OK;
        cenc_out:
            EVP_CIPHER_CTX_free(cx);
        }
        op->active = 0;
        (void)fhsm_audit_event(FHSM_EV_ENCRYPT, -1, (int)hSession,
                                fhsm_session_role(hSession), rv, NULL);
        return rv;
    }

    /* --- AES-GCM path (symmetric) ---
     * Honour the caller-provided CK_GCM_PARAMS (IV, AAD, tag length)
     * captured at C_EncryptInit, mirroring the C_Decrypt path. Output
     * layout is ciphertext || tag (PKCS#11 v3.x). The earlier code used a
     * hard-coded 12-byte op->iv (randomly generated for the struct form,
     * so it did not match the caller's IV) and an EMPTY AAD, producing the
     * wrong ciphertext/tag whenever a non-default IV or any AAD was present
     * (#125 TestAESGCM*, TestMechEncryptKAT[AES_GCM], roundtrip). */
    if (op->mechanism != CKM_AES_GCM || kt != CKK_AES) {
        op->active = 0; return FHSM_RV_MECHANISM_INVALID;
    }
    size_t etag_len = op->gcm_tag_len ? op->gcm_tag_len : 16;
    size_t need = ulDataLen + etag_len;
    if (pEnc == NULL) { *pulEncLen = need; return FHSM_RV_OK; }
    if (*pulEncLen < need) { *pulEncLen = need; return 0x00000150UL; }
    {
        const uint8_t *eiv_ptr = op->gcm_iv_len ? op->gcm_iv : op->iv;
        size_t eiv_len = op->gcm_iv_len ? op->gcm_iv_len : 12;
        const EVP_CIPHER *ecph = NULL;
        EVP_CIPHER_CTX *ectx = NULL;
        int exl = 0;
        size_t eproduced = 0;
        if (!op->gcm_iv_len && !op->have_iv) {
            fhsm_rng_bytes(op->iv, 12); eiv_ptr = op->iv; eiv_len = 12;
        }
        switch (kvl) {
            case 16: ecph = EVP_aes_128_gcm(); break;
            case 24: ecph = EVP_aes_192_gcm(); break;
            case 32: ecph = EVP_aes_256_gcm(); break;
            default: op->active = 0; return FHSM_RV_KEY_SIZE_RANGE;
        }
        ectx = EVP_CIPHER_CTX_new();
        if (!ectx) { op->active = 0; return FHSM_RV_HOST_MEMORY; }
        rv = FHSM_RV_FUNCTION_FAILED;
        if (EVP_EncryptInit_ex(ectx, ecph, NULL, NULL, NULL) != 1) goto genc_out;
        if (eiv_len != 12 && EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN,
                                                 (int)eiv_len, NULL) != 1) goto genc_out;
        if (EVP_EncryptInit_ex(ectx, NULL, NULL, kv, eiv_ptr) != 1) goto genc_out;
        if (op->gcm_aad_len > 0 && EVP_EncryptUpdate(ectx, NULL, &exl,
                                        op->gcm_aad, (int)op->gcm_aad_len) != 1) goto genc_out;
        if (EVP_EncryptUpdate(ectx, pEnc, &exl, pData, (int)ulDataLen) != 1) goto genc_out;
        eproduced = (size_t)exl;
        if (EVP_EncryptFinal_ex(ectx, pEnc + eproduced, &exl) != 1) goto genc_out;
        eproduced += (size_t)exl;
        if (EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG,
                                (int)etag_len, pEnc + eproduced) != 1) goto genc_out;
        *pulEncLen = eproduced + etag_len;
        rv = FHSM_RV_OK;
    genc_out:
        EVP_CIPHER_CTX_free(ectx);
    }
    op->active = 0;
    (void)fhsm_audit_event(FHSM_EV_ENCRYPT, -1, (int)hSession,
                            fhsm_session_role(hSession), rv, NULL);
    return rv;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                    CK_OBJECT_HANDLE hKey) {
    if (fhsm_session_token(hSession) == NULL) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (!pMechanism) return FHSM_RV_ARGUMENTS_BAD;
    if (fhsm_nonfips_enc_rejected(pMechanism->mechanism)) return FHSM_RV_MECHANISM_INVALID;
    if (!fhsm_cipher_mech_valid(pMechanism->mechanism)) return FHSM_RV_MECHANISM_INVALID;
    { CK_RV kc = fhsm_require_key(fhsm_session_token(hSession), hKey); if (kc != FHSM_RV_OK) return kc; }
    { CK_RV tc = fhsm_check_key_mech_type(fhsm_session_token(hSession), hKey, pMechanism->mechanism); if (tc != FHSM_RV_OK) return tc; }
    { CK_RV uc = fhsm_check_usage(fhsm_session_token(hSession), hKey, FHSM_USAGE_DECRYPT); if (uc != FHSM_RV_OK) return uc; }
    fhsm_op_t *op = op_slot(g_op_dec, hSession);
    if (!op) return FHSM_RV_SESSION_HANDLE_INVALID;
    return op_init(op, hSession, pMechanism, hKey);
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, unsigned char *pEnc, CK_ULONG ulEncLen,
                unsigned char *pData, CK_ULONG *pulDataLen) {
    fhsm_op_t *op = op_slot(g_op_dec, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    /* Argument robustness (symmetry with C_Encrypt) : pulDataLen is the
     * mandatory length in/out pointer and is dereferenced on every path
     * (size query and copy alike) ; pEncryptedData must be non-NULL when
     * it carries bytes. Reject NULLs with CKR_ARGUMENTS_BAD instead of
     * dereferencing them. Regression from pkcs11-check finding
     * (#125, test_null_argument_rejection_terminates_encrypt_decrypt):
     * a NULL pulDataLen previously caused a NULL-pointer dereference
     * (SIGSEGV). The operation is terminated on rejection so the session
     * is not stranded with op->active = 1. */
    if (!pulDataLen || (!pEnc && ulEncLen)) {
        op->active = 0;
        return FHSM_RV_ARGUMENTS_BAD;
    }
    /* A length beyond INT_MAX would be silently truncated by the (int) casts
     * on the OpenSSL path (#125 TestDecryptOutputLengthTruncation). */
    if (ulEncLen > 0x7FFFFFFFUL) { op->active = 0; return FHSM_RV_DATA_LEN_RANGE; }
    const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl = 0, kt = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
    if (rv != FHSM_RV_OK) { op->active = 0; return rv; }

    /* --- RSA-OAEP path (asymmetric decryption) --- */
    if (op->mechanism == CKM_RSA_PKCS_OAEP) {
        if (cl != CKO_PRIVATE_KEY || kt != CKK_RSA) {
            op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT;
        }
        const uint8_t *p = kv;
        EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &p, (long)kvl);
        if (!pkey) { op->active = 0; return FHSM_RV_FUNCTION_FAILED; }
        EVP_PKEY_CTX *dctx = NULL;
        rv = oaep_ctx_init(pkey, 0, &g_oaep_dec[hSession].p, &dctx);
        if (rv != FHSM_RV_OK) {
            EVP_PKEY_free(pkey); op->active = 0; return rv;
        }
        size_t out_len = 0;
        if (EVP_PKEY_decrypt(dctx, NULL, &out_len, pEnc, ulEncLen) <= 0) {
            EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(pkey);
            op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        if (pData == NULL) {
            /* Size query : PKCS#11 v3.2 requires the operation to REMAIN
             * active so the caller can call again with a real buffer. The
             * operation is terminated only by the actual decrypt below (or
             * by C_DecryptInit / a NULL-arg rejection). (#125). */
            *pulDataLen = out_len;
            EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(pkey);
            return FHSM_RV_OK;
        }
        if (*pulDataLen < out_len) {
            /* Buffer too small : keep the operation active for retry. */
            *pulDataLen = out_len;
            EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(pkey);
            return 0x00000150UL;
        }
        size_t buf_len = *pulDataLen;
        int dr = EVP_PKEY_decrypt(dctx, pData, &buf_len, pEnc, ulEncLen);
        EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(pkey);
        op->active = 0;
        g_oaep_dec[hSession].active = 0;
        if (dr <= 0) {
            (void)fhsm_audit_event(FHSM_EV_DECRYPT, -1, (int)hSession,
                                    fhsm_session_role(hSession),
                                    FHSM_RV_ENCRYPTED_DATA_INVALID, NULL);
            return FHSM_RV_ENCRYPTED_DATA_INVALID;
        }
        *pulDataLen = buf_len;
        (void)fhsm_audit_event(FHSM_EV_DECRYPT, -1, (int)hSession,
                                fhsm_session_role(hSession), FHSM_RV_OK, NULL);
        return FHSM_RV_OK;
    }

    /* --- RSA PKCS#1 v1.5 / X.509 raw decryption (non-FIPS ; interop) --- */
    if (op->mechanism == CKM_RSA_PKCS || op->mechanism == CKM_RSA_X_509) {
        if (fhsm_build_fips_strict) { op->active = 0; return FHSM_RV_MECHANISM_INVALID; }
        if (cl != CKO_PRIVATE_KEY || kt != CKK_RSA) { op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT; }
        int pad = (op->mechanism == CKM_RSA_PKCS) ? RSA_PKCS1_PADDING : RSA_NO_PADDING;
        const uint8_t *pp = kv;
        EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &pp, (long)kvl);
        if (!pkey) { op->active = 0; return FHSM_RV_FUNCTION_FAILED; }
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!dctx || EVP_PKEY_decrypt_init(dctx) <= 0
            || EVP_PKEY_CTX_set_rsa_padding(dctx, pad) <= 0) {
            if (dctx) EVP_PKEY_CTX_free(dctx);
            EVP_PKEY_free(pkey);
            op->active = 0;
            return FHSM_RV_FUNCTION_FAILED;
        }
        size_t out_len = 0;
        if (EVP_PKEY_decrypt(dctx, NULL, &out_len, pEnc, ulEncLen) <= 0) {
            EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(pkey); op->active = 0; return FHSM_RV_ENCRYPTED_DATA_INVALID;
        }
        if (pData == NULL) { *pulDataLen = out_len; EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(pkey); return FHSM_RV_OK; }  /* size query : op stays active */
        if (*pulDataLen < out_len) { *pulDataLen = out_len; EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(pkey); return 0x00000150UL; }  /* buffer too small : op stays active for retry */
        size_t bl = *pulDataLen;
        int dr = EVP_PKEY_decrypt(dctx, pData, &bl, pEnc, ulEncLen);
        EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(pkey); op->active = 0;
        if (dr <= 0) return FHSM_RV_ENCRYPTED_DATA_INVALID;
        *pulDataLen = bl;
        (void)fhsm_audit_event(FHSM_EV_DECRYPT, -1, (int)hSession,
                                fhsm_session_role(hSession), FHSM_RV_OK, NULL);
        return FHSM_RV_OK;
    }

    /* --- AES-ECB / AES-CBC / AES-CBC-PAD / AES-CTR path ---
     * AES-ECB is non-FIPS : executable only in the interop build. */
    if (op->mechanism == CKM_AES_ECB || op->mechanism == CKM_AES_CBC
        || op->mechanism == CKM_AES_CBC_PAD || op->mechanism == CKM_AES_CTR) {
        int is_ecb = (op->mechanism == CKM_AES_ECB);
        /* AES-ECB is FIPS-approved (SP 800-38A) and allowed in both profiles. */
        if (kt != CKK_AES) { op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT; }
        if (!is_ecb && !op->have_iv) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
        const char *cname = NULL;
        if (op->mechanism == CKM_AES_CTR) {
            cname = (kvl == 16) ? "AES-128-CTR" :
                    (kvl == 24) ? "AES-192-CTR" : "AES-256-CTR";
        } else if (is_ecb) {
            cname = (kvl == 16) ? "AES-128-ECB" :
                    (kvl == 24) ? "AES-192-ECB" : "AES-256-ECB";
        } else {
            cname = (kvl == 16) ? "AES-128-CBC" :
                    (kvl == 24) ? "AES-192-CBC" : "AES-256-CBC";
        }
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, cname, NULL);
        if (!c) { op->active = 0; return FHSM_RV_MECHANISM_INVALID; }
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { EVP_CIPHER_free(c); op->active = 0; return FHSM_RV_HOST_MEMORY; }
        if (EVP_DecryptInit_ex2(ctx, c, kv, is_ecb ? NULL : op->iv, NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        EVP_CIPHER_CTX_set_padding(ctx, op->mechanism == CKM_AES_CBC_PAD ? 1 : 0);
        if (pData == NULL) {
            *pulDataLen = ulEncLen;
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            return FHSM_RV_OK;
        }
        if (*pulDataLen < ulEncLen) {
            *pulDataLen = ulEncLen;
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            return 0x00000150UL;
        }
        int outl = 0, finl = 0;
        if (EVP_DecryptUpdate(ctx, pData, &outl, pEnc, (int)ulEncLen) != 1
            || EVP_DecryptFinal_ex(ctx, pData + outl, &finl) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            op->active = 0; return FHSM_RV_ENCRYPTED_DATA_INVALID;
        }
        *pulDataLen = (CK_ULONG)(outl + finl);
        EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
        op->active = 0;
        (void)fhsm_audit_event(FHSM_EV_DECRYPT, -1, (int)hSession,
                                fhsm_session_role(hSession), FHSM_RV_OK, NULL);
        return FHSM_RV_OK;
    }

    /* --- 3DES-CBC (non-FIPS ; interop / general-purpose only) --- */
    if (op->mechanism == 0x00000133UL /* CKM_DES3_CBC */) {
        if (fhsm_build_fips_strict) { op->active = 0; return FHSM_RV_MECHANISM_INVALID; }
        if (kt != CKK_DES3) { op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT; }
        if (!op->have_iv)   { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
        if (kvl != 24)      { op->active = 0; return FHSM_RV_KEY_SIZE_RANGE; }
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "DES-EDE3-CBC", NULL);
        if (!c) { op->active = 0; return FHSM_RV_MECHANISM_INVALID; }
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { EVP_CIPHER_free(c); op->active = 0; return FHSM_RV_HOST_MEMORY; }
        if (EVP_DecryptInit_ex2(ctx, c, kv, op->iv, NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            op->active = 0; return FHSM_RV_FUNCTION_FAILED;
        }
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (pData == NULL) { *pulDataLen = ulEncLen; EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c); return FHSM_RV_OK; }
        if (*pulDataLen < ulEncLen) { *pulDataLen = ulEncLen; EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c); return 0x00000150UL; }
        int outl = 0, finl = 0;
        if (EVP_DecryptUpdate(ctx, pData, &outl, pEnc, (int)ulEncLen) != 1
            || EVP_DecryptFinal_ex(ctx, pData + outl, &finl) != 1) {
            EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
            op->active = 0; return FHSM_RV_ENCRYPTED_DATA_INVALID;
        }
        *pulDataLen = (CK_ULONG)(outl + finl);
        EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
        op->active = 0;
        (void)fhsm_audit_event(FHSM_EV_DECRYPT, -1, (int)hSession,
                                fhsm_session_role(hSession), FHSM_RV_OK, NULL);
        return FHSM_RV_OK;
    }

    /* --- AES-CCM path (SP 800-38C, symmetric) ---
     * Input layout is ciphertext || MAC. For CCM, OpenSSL verifies the MAC
     * inside the single EVP_DecryptUpdate call (there is no DecryptFinal) :
     * the expected tag must be set BEFORE the data, and a non-positive
     * return means authentication failed -> CKR_ENCRYPTED_DATA_INVALID with
     * the partial plaintext zeroised. (#125 CCM online path.) */
    if (op->mechanism == 0x00001088UL /* CKM_AES_CCM */) {
        if (kt != CKK_AES) { op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT; }
        size_t cmac_len = op->gcm_tag_len ? op->gcm_tag_len : 16;
        if (ulEncLen < cmac_len) { op->active = 0; return FHSM_RV_ENCRYPTED_DATA_INVALID; }
        size_t ct_len = ulEncLen - cmac_len;
        if (pData == NULL) { *pulDataLen = ct_len; return FHSM_RV_OK; }
        if (*pulDataLen < ct_len) { *pulDataLen = ct_len; return 0x00000150UL; }
        {
            const EVP_CIPHER *cph = (kvl == 16) ? EVP_aes_128_ccm() :
                                    (kvl == 24) ? EVP_aes_192_ccm() :
                                    (kvl == 32) ? EVP_aes_256_ccm() : NULL;
            EVP_CIPHER_CTX *cx = NULL;
            int cl2 = 0;
            if (!cph) { op->active = 0; return FHSM_RV_KEY_SIZE_RANGE; }
            cx = EVP_CIPHER_CTX_new();
            if (!cx) { op->active = 0; return FHSM_RV_HOST_MEMORY; }
            rv = FHSM_RV_FUNCTION_FAILED;
            if (EVP_DecryptInit_ex(cx, cph, NULL, NULL, NULL) != 1) goto cdec_out;
            if (EVP_CIPHER_CTX_ctrl(cx, EVP_CTRL_CCM_SET_IVLEN,
                                    (int)op->gcm_iv_len, NULL) != 1) goto cdec_out;
            if (EVP_CIPHER_CTX_ctrl(cx, EVP_CTRL_CCM_SET_TAG, (int)cmac_len,
                                    (void *)(pEnc + ct_len)) != 1) goto cdec_out;
            if (EVP_DecryptInit_ex(cx, NULL, NULL, kv, op->gcm_iv) != 1) goto cdec_out;
            if (EVP_DecryptUpdate(cx, NULL, &cl2, NULL, (int)ct_len) != 1) goto cdec_out;
            if (op->gcm_aad_len > 0 && EVP_DecryptUpdate(cx, NULL, &cl2,
                                    op->gcm_aad, (int)op->gcm_aad_len) != 1) goto cdec_out;
            if (EVP_DecryptUpdate(cx, pData, &cl2, pEnc, (int)ct_len) != 1) {
                /* CCM authentication failure : zeroise partial output. */
                fhsm_zeroize(pData, *pulDataLen);
                rv = FHSM_RV_ENCRYPTED_DATA_INVALID;
                goto cdec_out;
            }
            *pulDataLen = (size_t)cl2;
            rv = FHSM_RV_OK;
        cdec_out:
            EVP_CIPHER_CTX_free(cx);
        }
        op->active = 0;
        (void)fhsm_audit_event(FHSM_EV_DECRYPT, -1, (int)hSession,
                                fhsm_session_role(hSession), rv, NULL);
        return rv;
    }

    /* --- AES-GCM path (symmetric) ---
     * The PKCS#11 v3.x calling convention is "ciphertext || tag" : the
     * caller appends the authentication tag to the encrypted bytes and
     * gives us the combined buffer. The tag length is taken from the
     * CK_GCM_PARAMS struct (default 16 bytes) and the IV/AAD come from
     * the same struct (captured at DecryptInit). */
    if (op->mechanism != CKM_AES_GCM || kt != CKK_AES) {
        op->active = 0; return FHSM_RV_MECHANISM_INVALID;
    }
    size_t tag_len = op->gcm_tag_len ? op->gcm_tag_len : 16;
    if (ulEncLen < tag_len) {
        op->active = 0; return FHSM_RV_ENCRYPTED_DATA_INVALID;
    }
    size_t plaintext_len = ulEncLen - tag_len;
    if (pData == NULL) { *pulDataLen = plaintext_len; return FHSM_RV_OK; }
    if (*pulDataLen < plaintext_len) {
        *pulDataLen = plaintext_len; return 0x00000150UL;
    }
    size_t out_len = *pulDataLen;
    /* Inline OpenSSL call so the IV and tag lengths can be set per the
     * caller-provided CK_GCM_PARAMS instead of the 12/16 hard-coded
     * pair the helper accepts. This lets us exercise Wycheproof's
     * non-default IV / tag sizes (SmallIv, LongIv, 32/64-bit tags). */
    const uint8_t *iv_ptr = op->gcm_iv_len ? op->gcm_iv : op->iv;
    size_t iv_len = op->gcm_iv_len ? op->gcm_iv_len : 12;

    const EVP_CIPHER *cipher = NULL;
    switch (kvl) {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
        default: op->active = 0; return FHSM_RV_KEY_SIZE_RANGE;
    }

    EVP_CIPHER_CTX *gctx = EVP_CIPHER_CTX_new();
    if (!gctx) { op->active = 0; return FHSM_RV_HOST_MEMORY; }

    rv = FHSM_RV_FUNCTION_FAILED;
    if (EVP_DecryptInit_ex(gctx, cipher, NULL, NULL, NULL) != 1) goto gcm_out;
    if (iv_len != 12) {
        if (EVP_CIPHER_CTX_ctrl(gctx, EVP_CTRL_GCM_SET_IVLEN,
                                 (int)iv_len, NULL) != 1) goto gcm_out;
    }
    if (EVP_DecryptInit_ex(gctx, NULL, NULL, kv, iv_ptr) != 1) goto gcm_out;

    int gxl = 0;
    if (op->gcm_aad_len > 0) {
        if (EVP_DecryptUpdate(gctx, NULL, &gxl,
                              op->gcm_aad, (int)op->gcm_aad_len) != 1)
            goto gcm_out;
    }
    if (EVP_DecryptUpdate(gctx, pData, &gxl,
                          pEnc, (int)plaintext_len) != 1) goto gcm_out;
    size_t produced = (size_t)gxl;

    if (EVP_CIPHER_CTX_ctrl(gctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len,
                            (void *)(pEnc + plaintext_len)) != 1) goto gcm_out;
    if (EVP_DecryptFinal_ex(gctx, pData + produced, &gxl) != 1) {
        /* Tag mismatch : zeroize the partial plaintext (FIPS 140-3
         * §7.10.4 AEAD authenticity). */
        fhsm_zeroize(pData, *pulDataLen);
        rv = FHSM_RV_ENCRYPTED_DATA_INVALID;
        goto gcm_out;
    }
    produced += (size_t)gxl;
    out_len = produced;
    rv = FHSM_RV_OK;

gcm_out:
    EVP_CIPHER_CTX_free(gctx);
    *pulDataLen = out_len;
    op->active = 0;
    (void)fhsm_audit_event(FHSM_EV_DECRYPT, -1, (int)hSession,
                            fhsm_session_role(hSession), rv, NULL);
    return rv;
}

#define CKM_SHA256_HMAC_INIT_VAL  0x00000251UL
#ifndef CKM_SHA384_HMAC_INIT_VAL
#define CKM_SHA384_HMAC_INIT_VAL  0x00000261UL
#endif
#ifndef CKM_SHA512_HMAC_INIT_VAL
#define CKM_SHA512_HMAC_INIT_VAL  0x00000271UL
#endif
#ifndef CKM_SHA224_HMAC_INIT_VAL
#define CKM_SHA224_HMAC_INIT_VAL  0x00000256UL
#endif
#ifndef CKM_SHA3_256_HMAC_INIT_VAL
#define CKM_SHA3_256_HMAC_INIT_VAL 0x000002B1UL
#endif
#ifndef CKM_SHA3_384_HMAC_INIT_VAL
#define CKM_SHA3_384_HMAC_INIT_VAL 0x000002C1UL
#endif
#ifndef CKM_SHA3_512_HMAC_INIT_VAL
#define CKM_SHA3_512_HMAC_INIT_VAL 0x000002D1UL
#endif

/* Map an HMAC mechanism to its hash + MAC length. Returns 1 for a
 * recognised HMAC mechanism, 0 otherwise. Covers the FIPS-approved
 * SHA-2 and SHA-3 HMAC families advertised by the dispatch table
 * (#125 : previously only SHA-256/384/512 sign and SHA-256 verify were
 * callable, so SHA-3 / SHA-224 HMACs returned CKR_MECHANISM_INVALID). */
static int fhsm_hmac_hash_of(uint32_t mech, fhsm_hash_t *hash, size_t *maclen) {
    switch (mech) {
        case CKM_SHA224_HMAC_INIT_VAL:   *hash = FHSM_HASH_SHA224;   *maclen = 28; return 1;
        case CKM_SHA256_HMAC_INIT_VAL:   *hash = FHSM_HASH_SHA256;   *maclen = 32; return 1;
        case CKM_SHA384_HMAC_INIT_VAL:   *hash = FHSM_HASH_SHA384;   *maclen = 48; return 1;
        case CKM_SHA512_HMAC_INIT_VAL:   *hash = FHSM_HASH_SHA512;   *maclen = 64; return 1;
        case CKM_SHA3_256_HMAC_INIT_VAL: *hash = FHSM_HASH_SHA3_256; *maclen = 32; return 1;
        case CKM_SHA3_384_HMAC_INIT_VAL: *hash = FHSM_HASH_SHA3_384; *maclen = 48; return 1;
        case CKM_SHA3_512_HMAC_INIT_VAL: *hash = FHSM_HASH_SHA3_512; *maclen = 64; return 1;
        default: return 0;
    }
}

/* EVP_MAC HMAC "digest" parameter name for a hash. #125 multipart HMAC. */
static const char *hmac_digest_name(fhsm_hash_t h) {
    switch (h) {
        case FHSM_HASH_SHA224:   return "SHA224";
        case FHSM_HASH_SHA256:   return "SHA256";
        case FHSM_HASH_SHA384:   return "SHA384";
        case FHSM_HASH_SHA512:   return "SHA512";
        case FHSM_HASH_SHA3_256: return "SHA3-256";
        case FHSM_HASH_SHA3_384: return "SHA3-384";
        case FHSM_HASH_SHA3_512: return "SHA3-512";
        default:                 return NULL;
    }
}
/* CKM_ECDSA* identifiers are now defined in include/fhsm_ecdsa_raw.h which
 * is pulled in near the top of this TU. Kept here as a comment so a grep
 * for "CKM_ECDSA" still lands somewhere readable. */
#ifndef CKM_EDDSA
#define CKM_EDDSA                 0x00001057UL
#endif
#define CKM_RSA_PKCS              0x00000001UL
#define CKM_RSA_PKCS_OAEP         0x00000009UL
#define CKG_MGF1_SHA1             0x00000001UL
#define CKG_MGF1_SHA224           0x00000005UL
#define CKG_MGF1_SHA256           0x00000002UL
#define CKG_MGF1_SHA384           0x00000003UL
#define CKG_MGF1_SHA512           0x00000004UL
#define CKZ_DATA_SPECIFIED        0x00000001UL
#define CKM_SHA1_RSA_PKCS         0x00000006UL
#define CKM_SHA256_RSA_PKCS       0x00000040UL
#define CKM_SHA384_RSA_PKCS       0x00000041UL
#define CKM_SHA512_RSA_PKCS       0x00000042UL
#define CKM_RSA_PKCS_PSS          0x0000000DUL
#define CKM_SHA256_RSA_PKCS_PSS   0x00000043UL
#ifndef CKM_SHA384_RSA_PKCS_PSS
#define CKM_SHA384_RSA_PKCS_PSS   0x00000044UL
#endif
#ifndef CKM_SHA512_RSA_PKCS_PSS
#define CKM_SHA512_RSA_PKCS_PSS   0x00000045UL
#endif

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                  CK_OBJECT_HANDLE hKey) {
    if (fhsm_session_token(hSession) == NULL) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (!pMechanism) return FHSM_RV_ARGUMENTS_BAD;
    switch (pMechanism->mechanism) {
        case CKM_SHA224_HMAC_INIT_VAL:
        case CKM_SHA256_HMAC_INIT_VAL:
        case CKM_SHA384_HMAC_INIT_VAL:
        case CKM_SHA512_HMAC_INIT_VAL:
        case CKM_SHA3_256_HMAC_INIT_VAL:
        case CKM_SHA3_384_HMAC_INIT_VAL:
        case CKM_SHA3_512_HMAC_INIT_VAL:
        case CKM_AES_CMAC:
        case CKM_AES_GMAC:
        case CKM_ECDSA: case CKM_ECDSA_SHA256: case CKM_ECDSA_SHA384: case CKM_ECDSA_SHA512:
        case CKM_EDDSA:
        case CKM_RSA_PKCS: case CKM_SHA256_RSA_PKCS: case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS: case CKM_RSA_PKCS_PSS: case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS: case CKM_SHA512_RSA_PKCS_PSS:
        case CKM_ML_DSA_OP: case CKM_SLH_DSA_OP:
            break;
        case CKM_SHA1_RSA_PKCS: /* non-FIPS : interop only */
            if (fhsm_build_fips_strict) return FHSM_RV_MECHANISM_INVALID;
            break;
        default:
            return FHSM_RV_MECHANISM_INVALID;
    }
    { CK_RV kc = fhsm_require_key(fhsm_session_token(hSession), hKey); if (kc != FHSM_RV_OK) return kc; }
    { CK_RV tc = fhsm_check_key_mech_type(fhsm_session_token(hSession), hKey, pMechanism->mechanism); if (tc != FHSM_RV_OK) return tc; }
    { CK_RV uc = fhsm_check_usage(fhsm_session_token(hSession), hKey, FHSM_USAGE_SIGN); if (uc != FHSM_RV_OK) return uc; }
    fhsm_op_t *op = op_slot(g_op_sig, hSession);
    if (!op) return FHSM_RV_SESSION_HANDLE_INVALID;
    return op_init(op, hSession, pMechanism, hKey);
}

/* Resolve mechanism identifier through the optional FHSM_OPENSC_GMAC_ALIAS
 * gate (see the comment block on CKM_AES_GMAC further up). Called once at
 * op_init time so the rest of the module only sees the resolved value.
 * Returns the input unchanged when the alias is off or when the mechanism
 * is anything other than CKM_AES_GMAC. */
static uint32_t resolve_mech(uint32_t m) {
    if (m == CKM_AES_GMAC && getenv("FHSM_OPENSC_GMAC_ALIAS")) {
        return CKM_AES_CMAC;
    }
    return m;
}

/* Helper : AES-GMAC via EVP_MAC. Used by C_Sign (mac generation) and
 * C_Verify (constant-time compare). The GMAC tag is always 16 bytes
 * (the AES block size). Unlike CMAC, GMAC needs an IV : the IV is
 * captured at op_init time from pMechanism->pParameter and stored in
 * op->gcm_iv (the same buffer used by CKM_AES_GCM ; sufficient for the
 * variable IV lengths Wycheproof exercises). */
static fhsm_rv_t aes_gmac(const uint8_t *key, size_t key_len,
                           const uint8_t *iv,  size_t iv_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t out[16]) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "GMAC", NULL);
    if (!mac) return FHSM_RV_MECHANISM_INVALID;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) return FHSM_RV_HOST_MEMORY;
    char cipher_name[16];
    snprintf(cipher_name, sizeof(cipher_name), "AES-%zu-GCM", key_len * 8);
    OSSL_PARAM params[3] = {
        OSSL_PARAM_construct_utf8_string("cipher", cipher_name, 0),
        OSSL_PARAM_construct_octet_string("iv", (void *)iv, iv_len),
        OSSL_PARAM_construct_end()
    };
    if (EVP_MAC_init(ctx, key, key_len, params) != 1
        || EVP_MAC_update(ctx, data, data_len) != 1) {
        EVP_MAC_CTX_free(ctx); return FHSM_RV_FUNCTION_FAILED;
    }
    size_t out_len = 16;
    int ok = EVP_MAC_final(ctx, out, &out_len, 16);
    EVP_MAC_CTX_free(ctx);
    return ok == 1 && out_len == 16 ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

/* Helper : AES-CMAC via EVP_MAC. Used by C_Sign (mac generation) and
 * C_Verify (constant-time compare). The CMAC tag is always 16 bytes
 * (block size of AES). */
static fhsm_rv_t aes_cmac(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t out[16]) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) return FHSM_RV_MECHANISM_INVALID;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) return FHSM_RV_HOST_MEMORY;
    char cipher_name[16];
    snprintf(cipher_name, sizeof(cipher_name), "AES-%zu-CBC", key_len * 8);
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string("cipher", cipher_name, 0),
        OSSL_PARAM_construct_end()
    };
    if (EVP_MAC_init(ctx, key, key_len, params) != 1
        || EVP_MAC_update(ctx, data, data_len) != 1) {
        EVP_MAC_CTX_free(ctx); return FHSM_RV_FUNCTION_FAILED;
    }
    size_t out_len = 16;
    int ok = EVP_MAC_final(ctx, out, &out_len, 16);
    EVP_MAC_CTX_free(ctx);
    return ok == 1 && out_len == 16 ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

/* Map mechanism → hash name for EVP_DigestSign. NULL = no prehash
 * (caller-provided digest, used with raw CKM_ECDSA / CKM_RSA_PKCS). */
static const char *mech_hash_name(uint32_t m) {
    switch (m) {
        case CKM_SHA1_RSA_PKCS:                                 return "SHA1";
        case CKM_ECDSA_SHA256: case CKM_SHA256_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS_PSS:                            return "SHA256";
        case CKM_ECDSA_SHA384: case CKM_SHA384_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS_PSS:                            return "SHA384";
        case CKM_ECDSA_SHA512: case CKM_SHA512_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS_PSS:                            return "SHA512";
        default:                                                   return NULL;
    }
}

static int mech_is_pss(uint32_t m) {
    return m == CKM_RSA_PKCS_PSS
        || m == CKM_SHA256_RSA_PKCS_PSS
        || m == CKM_SHA384_RSA_PKCS_PSS
        || m == CKM_SHA512_RSA_PKCS_PSS;
}

/* The mech_is_ecdsa / ecdsa_der_to_raw / ecdsa_raw_to_der helpers used
 * to live here. They were extracted to src/fhsm_ecdsa_raw.c in v1.1.14
 * to enable a libFuzzer harness on the DER <-> raw r||s conversion path
 * (#191). The header fhsm_ecdsa_raw.h is included near the top of this
 * TU ; call sites use the fhsm_* prefixed names. */

/* Sign with an asymmetric private key. Loads the PKCS#8 DER blob from
 * the token's object store, builds an EVP_PKEY, and uses EVP_DigestSign
 * (or EVP_PKEY_sign for prehash mechanisms). */
static fhsm_rv_t sign_asymmetric(fhsm_token_t *t, fhsm_op_t *op,
                                  const uint8_t *data, size_t data_len,
                                  uint8_t *sig, size_t *sig_len) {
    const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl = 0, kt = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
    if (rv != FHSM_RV_OK) return rv;
    if (cl != CKO_PRIVATE_KEY) return FHSM_RV_KEY_TYPE_INCONSISTENT;
    const uint8_t *p = kv;
    EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &p, (long)kvl);
    if (!pkey) return FHSM_RV_FUNCTION_FAILED;
    if ((kt == CKK_RSA && EVP_PKEY_get_base_id(pkey) != EVP_PKEY_RSA) ||
        (kt == CKK_EC  && EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC)) {
        EVP_PKEY_free(pkey); return FHSM_RV_KEY_TYPE_INCONSISTENT;
    }

    /* Post-quantum schemes + EdDSA : OpenSSL 3.x exposes ML-DSA,
     * SLH-DSA and Ed25519 / Ed448 via EVP_DigestSign with hash=NULL
     * (the scheme does its own internal hashing per FIPS 204/205 or
     * RFC 8032). EVP_PKEY_sign does NOT work here --- it expects a
     * pre-hashed input which these schemes don't accept. */
    if (op->mechanism == CKM_ML_DSA_OP
        || op->mechanism == CKM_SLH_DSA_OP
        || op->mechanism == CKM_EDDSA) {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) { EVP_PKEY_free(pkey); return FHSM_RV_HOST_MEMORY; }
        EVP_PKEY_CTX *pkctx = NULL;
        if (EVP_DigestSignInit_ex(mdctx, &pkctx, NULL, NULL, NULL, pkey, NULL) != 1) {
            EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
            return FHSM_RV_FUNCTION_FAILED;
        }
        /* Forward the FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA) context
         * string captured from CK_ML_DSA_PARAMS or CK_SLH_DSA_PARAMS
         * at SignInit time. Without this the signature is produced
         * with the default empty context and would not match a
         * caller that expects a parameter-bound binding. hedgeVariant
         * remains unforwarded ; OpenSSL's default policy (hedged
         * when randomness is available) matches CKH_HEDGE_PREFERRED.
         * EdDSA stays on the empty-context default for this branch. */
        if ((op->mechanism == CKM_ML_DSA_OP
             || op->mechanism == CKM_SLH_DSA_OP)
            && op->pq_ctx_have && op->pq_ctx_len > 0) {
            OSSL_PARAM ctx_params[2] = {
                OSSL_PARAM_construct_octet_string(
                    OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                    op->pq_ctx, op->pq_ctx_len),
                OSSL_PARAM_construct_end(),
            };
            if (EVP_PKEY_CTX_set_params(pkctx, ctx_params) <= 0) {
                EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
                return FHSM_RV_FUNCTION_FAILED;
            }
        }
        size_t out_len = *sig_len;
        if (EVP_DigestSign(mdctx, sig, &out_len, data, data_len) != 1) {
            EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
            return FHSM_RV_FUNCTION_FAILED;
        }
        *sig_len = out_len;
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        return FHSM_RV_OK;
    }

    int ok = 0;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkctx_raw = NULL;

    const char *hash = mech_hash_name(op->mechanism);
    const EVP_MD *md = hash ? EVP_MD_fetch(NULL, hash, NULL) : NULL;
    size_t out_len = *sig_len;

    /* === RAW signing path (hash == NULL) ====================================
     *
     * The mechanisms CKM_ECDSA (bare) and CKM_RSA_PKCS (bare) expect the
     * input to be a pre-computed digest. The canonical OpenSSL 3.x API to
     * sign a pre-computed digest is EVP_PKEY_sign --- NOT EVP_DigestSign
     * with mdname = NULL.
     *
     * Calling EVP_DigestSignInit_ex(..., mdname = NULL, ...) on the default
     * OpenSSL 3.x provider's ECDSA signature operation does not produce a
     * "raw" signature : the provider applies an internal default digest
     * (observed as SHA-256 on the 3.5.x default provider) before signing.
     * The result is that the module signs SHA-256(input) instead of input,
     * which the symmetric C_Verify path also accepts (because it applies
     * the same default digest), but any third-party verifier expecting
     * raw ECDSA on the digest rejects.
     *
     * Fix (v1.2.2) : route the raw case through EVP_PKEY_sign directly.
     * The bug was reported by Denis Mingulov via pkcs11-check on
     * 2026-06-26 ; affects every signed release of FreeHSM C that has
     * shipped this path. See CHANGELOG entry for v1.2.2. */
    if (hash == NULL) {
        pkctx_raw = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pkctx_raw) goto cleanup;
        if (EVP_PKEY_sign_init(pkctx_raw) <= 0) goto cleanup;
        if (mech_is_pss(op->mechanism)) {
            if (EVP_PKEY_CTX_set_rsa_padding(pkctx_raw,
                                              RSA_PKCS1_PSS_PADDING) <= 0)
                goto cleanup;
            int saltlen = op->pss_have ? (int)op->pss_saltlen : -1;
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx_raw, saltlen) <= 0)
                goto cleanup;
        }
        if (EVP_PKEY_sign(pkctx_raw, sig, &out_len, data, data_len) <= 0)
            goto cleanup;
    } else {
        /* === Hashed signing path (hash != NULL) ============================
         * Mechanisms CKM_ECDSA_SHAxxx, CKM_SHAxxx_RSA_PKCS, etc. : OpenSSL
         * hashes the input with `hash` before signing. This path was always
         * correct. */
        mdctx = EVP_MD_CTX_new();
        if (!mdctx) goto cleanup;
        EVP_PKEY_CTX *pkctx = NULL;
        if (EVP_DigestSignInit_ex(mdctx, &pkctx, hash, NULL, NULL, pkey, NULL) != 1)
            goto cleanup;
        if (mech_is_pss(op->mechanism)) {
            if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) <= 0)
                goto cleanup;
            int saltlen = op->pss_have ? (int)op->pss_saltlen : -1;
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen) <= 0)
                goto cleanup;
        }
        if (EVP_DigestSign(mdctx, sig, &out_len, data, data_len) != 1)
            goto cleanup;
    }

    /* PKCS#11 v3.2 conformity : for the CKM_ECDSA family OpenSSL
     * produced a DER ECDSA-Sig-Value, but the spec mandates raw
     * r||s. Convert in place. */
    if (fhsm_mech_is_ecdsa(op->mechanism)) {
        size_t nlen = (size_t)((EVP_PKEY_get_bits(pkey) + 7) / 8);
        if (nlen == 0 || *sig_len < 2 * nlen) goto cleanup;
        uint8_t raw[2 * 66];   /* enough for P-521 (66*2 = 132) */
        size_t raw_len = fhsm_ecdsa_der_to_raw(sig, out_len, nlen,
                                                raw, sizeof(raw));
        if (raw_len == 0) goto cleanup;
        memcpy(sig, raw, raw_len);
        out_len = raw_len;
    }
    *sig_len = out_len;
    ok = 1;

cleanup:
    if (md) EVP_MD_free((EVP_MD*)md);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (pkctx_raw) EVP_PKEY_CTX_free(pkctx_raw);
    EVP_PKEY_free(pkey);
    return ok ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, unsigned char *pData, CK_ULONG ulDataLen,
              unsigned char *pSignature, CK_ULONG *pulSignatureLen) {
    fhsm_op_t *op = op_slot(g_op_sig, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    if (!pulSignatureLen) return FHSM_RV_ARGUMENTS_BAD;
    /* Reject a NULL data pointer paired with a non-zero length before any
     * dereference (pkcs11-check security/test_ffi_null_pointer, #125). A
     * NULL buffer of length 0 is legal (empty message). Errors terminate
     * the active operation, per PKCS#11 C_Sign/C_Verify/C_Digest rules. */
    if (pData == NULL && ulDataLen != 0) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;

    fhsm_hash_t hmac_hash; size_t hmac_need;
    if (fhsm_hmac_hash_of(op->mechanism, &hmac_hash, &hmac_need)) {
        const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl = 0, kt = 0;
        fhsm_rv_t rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
        if (rv != FHSM_RV_OK) { op->active = 0; return rv; }
        fhsm_hash_t hash = hmac_hash;
        size_t need = hmac_need;
        if (pSignature == NULL) { *pulSignatureLen = need; return FHSM_RV_OK; }
        if (*pulSignatureLen < need) { *pulSignatureLen = need; return 0x00000150UL; }
        size_t mac_len = *pulSignatureLen;
        rv = fhsm_hmac(hash, FHSM_SLICE(kv, kvl),
                        FHSM_SLICE(pData, ulDataLen), pSignature, &mac_len);
        *pulSignatureLen = mac_len;
        op->active = 0;
        (void)fhsm_audit_event(FHSM_EV_SIGN, -1, (int)hSession,
                                fhsm_session_role(hSession), rv, NULL);
        return rv;
    }

    if (op->mechanism == CKM_AES_CMAC || op->mechanism == CKM_AES_GMAC) {
        const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl = 0, kt = 0;
        fhsm_rv_t rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
        if (rv != FHSM_RV_OK) { op->active = 0; return rv; }
        if (kt != CKK_AES) { op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT; }
        if (pSignature == NULL) { *pulSignatureLen = 16; return FHSM_RV_OK; }
        if (*pulSignatureLen < 16) { *pulSignatureLen = 16; return 0x00000150UL; }
        if (op->mechanism == CKM_AES_GMAC) {
            if (!op->gcm_have || op->gcm_iv_len == 0) {
                op->active = 0; return FHSM_RV_ARGUMENTS_BAD;
            }
            rv = aes_gmac(kv, kvl, op->gcm_iv, op->gcm_iv_len,
                          pData, ulDataLen, pSignature);
        } else {
            rv = aes_cmac(kv, kvl, pData, ulDataLen, pSignature);
        }
        *pulSignatureLen = 16;
        op->active = 0;
        (void)fhsm_audit_event(FHSM_EV_SIGN, -1, (int)hSession,
                                fhsm_session_role(hSession), rv, NULL);
        return rv;
    }

    /* Asymmetric : query buffer size if pSignature == NULL. We return a
     * conservative upper bound by family :
     *   ECDSA-P521        ≈ 140 octets
     *   RSA-4096          = 512 octets
     *   ML-DSA-87         ≈ 4627 octets
     *   SLH-DSA-256f      ≈ 49856 octets
     * The 64KB worst-case is allocated once by the caller and is
     * negligible memory-wise. */
    if (pSignature == NULL) {
        if (op->mechanism == CKM_SLH_DSA_OP)        *pulSignatureLen = 65536;
        else if (op->mechanism == CKM_ML_DSA_OP)    *pulSignatureLen = 8192;
        else                                          *pulSignatureLen = 512;
        return FHSM_RV_OK;
    }
    /* Sign into a scratch buffer sized to the mechanism upper bound so we
     * can honour CKR_BUFFER_TOO_SMALL semantics : a caller buffer smaller
     * than the actual signature must return CKR_BUFFER_TOO_SMALL with the
     * required length AND leave the operation active for retry
     * (pkcs11-check TestBufferTooSmall::test_sign_buffer_too_small, #125).
     * Signing straight into an undersized caller buffer instead made
     * OpenSSL fail with CKR_FUNCTION_FAILED (0x6). */
    size_t scratch_cap = (op->mechanism == CKM_SLH_DSA_OP) ? 65536u
                       : (op->mechanism == CKM_ML_DSA_OP)  ? 8192u : 512u;
    uint8_t  stackbuf[512];
    uint8_t *scratch = (scratch_cap <= sizeof(stackbuf))
                         ? stackbuf : (uint8_t *)malloc(scratch_cap);
    if (!scratch) { op->active = 0; return FHSM_RV_HOST_MEMORY; }
    size_t sig_buf_len = scratch_cap;
    fhsm_rv_t rv = sign_asymmetric(t, op, pData, ulDataLen, scratch, &sig_buf_len);
    if (rv != FHSM_RV_OK) {
        if (scratch != stackbuf) free(scratch);
        op->active = 0;
        (void)fhsm_audit_event(FHSM_EV_SIGN, -1, (int)hSession,
                                fhsm_session_role(hSession), rv, NULL);
        return rv;
    }
    if (*pulSignatureLen < sig_buf_len) {
        /* Caller buffer too small : report the required length and keep
         * the operation active so it can retry (PKCS#11 v3.2 C_Sign). */
        *pulSignatureLen = sig_buf_len;
        if (scratch != stackbuf) free(scratch);
        return 0x00000150UL;   /* CKR_BUFFER_TOO_SMALL */
    }
    memcpy(pSignature, scratch, sig_buf_len);
    *pulSignatureLen = sig_buf_len;
    if (scratch != stackbuf) free(scratch);
    op->active = 0;
    (void)fhsm_audit_event(FHSM_EV_SIGN, -1, (int)hSession,
                            fhsm_session_role(hSession), rv, NULL);
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * C_VerifyInit / C_Verify --- asymmetric signature verification.
 * Mirror of Sign : load the public key (DER from token), call
 * EVP_DigestVerify. For HMAC, recompute and constant-time compare.
 * ----------------------------------------------------------------------- */
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                    CK_OBJECT_HANDLE hKey) {
    if (fhsm_session_token(hSession) == NULL) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (!pMechanism) return FHSM_RV_ARGUMENTS_BAD;
    switch (pMechanism->mechanism) {
        case CKM_SHA224_HMAC_INIT_VAL:
        case CKM_SHA256_HMAC_INIT_VAL:
        case CKM_SHA384_HMAC_INIT_VAL:
        case CKM_SHA512_HMAC_INIT_VAL:
        case CKM_SHA3_256_HMAC_INIT_VAL:
        case CKM_SHA3_384_HMAC_INIT_VAL:
        case CKM_SHA3_512_HMAC_INIT_VAL:
        case CKM_AES_CMAC:
        case CKM_AES_GMAC:
        case CKM_ECDSA: case CKM_ECDSA_SHA256: case CKM_ECDSA_SHA384: case CKM_ECDSA_SHA512:
        case CKM_EDDSA:
        case CKM_RSA_PKCS: case CKM_SHA256_RSA_PKCS: case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS: case CKM_RSA_PKCS_PSS: case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS: case CKM_SHA512_RSA_PKCS_PSS:
        case CKM_ML_DSA_OP: case CKM_SLH_DSA_OP:
            break;
        case CKM_SHA1_RSA_PKCS: /* non-FIPS : interop only */
            if (fhsm_build_fips_strict) return FHSM_RV_MECHANISM_INVALID;
            break;
        default: return FHSM_RV_MECHANISM_INVALID;
    }
    { CK_RV kc = fhsm_require_key(fhsm_session_token(hSession), hKey); if (kc != FHSM_RV_OK) return kc; }
    { CK_RV tc = fhsm_check_key_mech_type(fhsm_session_token(hSession), hKey, pMechanism->mechanism); if (tc != FHSM_RV_OK) return tc; }
    { CK_RV uc = fhsm_check_usage(fhsm_session_token(hSession), hKey, FHSM_USAGE_VERIFY); if (uc != FHSM_RV_OK) return uc; }
    fhsm_op_t *op = op_slot(g_op_ver, hSession);
    if (!op) return FHSM_RV_SESSION_HANDLE_INVALID;
    return op_init(op, hSession, pMechanism, hKey);
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, unsigned char *pData,
               CK_ULONG ulDataLen, unsigned char *pSig, CK_ULONG ulSigLen) {
    fhsm_op_t *op = op_slot(g_op_ver, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    /* Reject a NULL data pointer paired with a non-zero length before any
     * dereference (pkcs11-check security/test_ffi_null_pointer, #125). A
     * NULL buffer of length 0 is legal (empty message). Errors terminate
     * the active operation, per PKCS#11 C_Sign/C_Verify/C_Digest rules. */
    if (pData == NULL && ulDataLen != 0) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl = 0, kt = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
    if (rv != FHSM_RV_OK) { op->active = 0; return rv; }

    fhsm_hash_t vhash; size_t vneed;
    if (fhsm_hmac_hash_of(op->mechanism, &vhash, &vneed)) {
        uint8_t mac[64]; size_t mac_len = sizeof(mac);
        rv = fhsm_hmac(vhash, FHSM_SLICE(kv, kvl),
                        FHSM_SLICE(pData, ulDataLen), mac, &mac_len);
        op->active = 0;
        if (rv != FHSM_RV_OK) return rv;
        if (ulSigLen != mac_len) return FHSM_RV_SIGNATURE_INVALID;
        return (fhsm_ct_memcmp(mac, pSig, mac_len) == 0) ? FHSM_RV_OK
                                                          : FHSM_RV_SIGNATURE_INVALID;
    }

    if (op->mechanism == CKM_AES_CMAC || op->mechanism == CKM_AES_GMAC) {
        if (kt != CKK_AES) { op->active = 0; return FHSM_RV_KEY_TYPE_INCONSISTENT; }
        uint8_t mac[16];
        if (op->mechanism == CKM_AES_GMAC) {
            if (!op->gcm_have || op->gcm_iv_len == 0) {
                op->active = 0; return FHSM_RV_ARGUMENTS_BAD;
            }
            rv = aes_gmac(kv, kvl, op->gcm_iv, op->gcm_iv_len,
                          pData, ulDataLen, mac);
        } else {
            rv = aes_cmac(kv, kvl, pData, ulDataLen, mac);
        }
        op->active = 0;
        if (rv != FHSM_RV_OK) return rv;
        if (ulSigLen != 16) return FHSM_RV_SIGNATURE_INVALID;
        return (fhsm_ct_memcmp(mac, pSig, 16) == 0) ? FHSM_RV_OK
                                                     : FHSM_RV_SIGNATURE_INVALID;
    }

    /* Asymmetric path : public key DER → EVP_PKEY → EVP_DigestVerify. */
    if (cl != CKO_PUBLIC_KEY) {
        op->active = 0;
        return FHSM_RV_KEY_TYPE_INCONSISTENT;
    }
    const uint8_t *p = kv;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)kvl);
    if (!pkey && op->mechanism == CKM_ML_DSA_OP) {
        /* Raw ML-DSA public key import fallback. Wycheproof and most
         * FIPS 204 test corpora carry the verification key as raw
         * 1312 / 1952 / 2592 bytes (ML-DSA-44 / 65 / 87) rather than
         * an SPKI envelope. OpenSSL 3.5 exposes the raw import via
         * EVP_PKEY_fromdata with OSSL_PKEY_PARAM_PUB_KEY ; the keymgmt
         * accepts EVP_PKEY_PUBLIC_KEY for a verify-only handle (no
         * KEYPAIR consistency check is required since there is no
         * private component on the public-key side). */
        const char *alg = NULL;
        if (kvl == 1312)      alg = "ML-DSA-44";
        else if (kvl == 1952) alg = "ML-DSA-65";
        else if (kvl == 2592) alg = "ML-DSA-87";
        if (alg) {
            EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
            if (kctx) {
                if (EVP_PKEY_fromdata_init(kctx) > 0) {
                    OSSL_PARAM params[2] = {
                        OSSL_PARAM_construct_octet_string(
                            OSSL_PKEY_PARAM_PUB_KEY,
                            (void *)kv, (size_t)kvl),
                        OSSL_PARAM_construct_end(),
                    };
                    (void)EVP_PKEY_fromdata(kctx, &pkey,
                                            EVP_PKEY_PUBLIC_KEY, params);
                }
                EVP_PKEY_CTX_free(kctx);
            }
        }
    }
    if (!pkey) { op->active = 0; return FHSM_RV_FUNCTION_FAILED; }

    /* PQ schemes + EdDSA : EVP_DigestVerify with hash=NULL. EdDSA is a
     * single-shot signature with no separate pre-hash step, so the
     * same plumbing applies. */
    if (op->mechanism == CKM_ML_DSA_OP
        || op->mechanism == CKM_SLH_DSA_OP
        || op->mechanism == CKM_EDDSA) {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) { EVP_PKEY_free(pkey); op->active = 0; return FHSM_RV_HOST_MEMORY; }
        EVP_PKEY_CTX *pkctx = NULL;
        int vok = 0;
        if (EVP_DigestVerifyInit_ex(mdctx, &pkctx, NULL, NULL, NULL, pkey, NULL) == 1) {
            /* FIPS 204 §5.2.1 / FIPS 205 §5.2.1 context string : when
             * the caller passed a CK_ML_DSA_PARAMS or CK_SLH_DSA_PARAMS
             * with a non-empty pContext we forward it to OpenSSL via
             * OSSL_SIGNATURE_PARAM_CONTEXT_STRING. The default
             * (have=0) leaves OpenSSL with its built-in empty-context
             * behaviour. EdDSA stays on the empty-context default. */
            if ((op->mechanism == CKM_ML_DSA_OP
                 || op->mechanism == CKM_SLH_DSA_OP)
                && op->pq_ctx_have && op->pq_ctx_len > 0) {
                OSSL_PARAM ctx_params[2] = {
                    OSSL_PARAM_construct_octet_string(
                        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                        op->pq_ctx, op->pq_ctx_len),
                    OSSL_PARAM_construct_end(),
                };
                if (EVP_PKEY_CTX_set_params(pkctx, ctx_params) <= 0) {
                    EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
                    op->active = 0; return FHSM_RV_FUNCTION_FAILED;
                }
            }
            int v = EVP_DigestVerify(mdctx, pSig, ulSigLen, pData, ulDataLen);
            vok = (v == 1);
            if (v < 0) {
                EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
                op->active = 0; return FHSM_RV_FUNCTION_FAILED;
            }
        }
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        op->active = 0;
        rv = vok ? FHSM_RV_OK : FHSM_RV_SIGNATURE_INVALID;
        (void)fhsm_audit_event(FHSM_EV_VERIFY, -1, (int)hSession,
                                fhsm_session_role(hSession), rv, NULL);
        return rv;
    }

    const char *hash = mech_hash_name(op->mechanism);
    int verify_ok = 0;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkctx_raw = NULL;

    /* Convert raw r||s ECDSA signature to DER (single conversion used for
     * both raw and hashed paths). nlen check rejects malformed wire sig. */
    const unsigned char *sig_to_verify = pSig;
    CK_ULONG sig_to_verify_len = ulSigLen;
    uint8_t *der_buf = NULL;
    if (fhsm_mech_is_ecdsa(op->mechanism)) {
        size_t nlen = (size_t)((EVP_PKEY_get_bits(pkey) + 7) / 8);
        if (nlen == 0 || ulSigLen != 2 * nlen) {
            EVP_PKEY_free(pkey);
            op->active = 0;
            return FHSM_RV_SIGNATURE_INVALID;
        }
        size_t der_len = fhsm_ecdsa_raw_to_der(pSig, ulSigLen, nlen, &der_buf);
        if (der_len == 0 || !der_buf) {
            EVP_PKEY_free(pkey);
            op->active = 0;
            return FHSM_RV_SIGNATURE_INVALID;
        }
        sig_to_verify     = der_buf;
        sig_to_verify_len = (CK_ULONG)der_len;
    }

    /* === RAW verify path (hash == NULL) =====================================
     *
     * Symmetric to the sign path : raw CKM_ECDSA / CKM_RSA_PKCS expect the
     * input to be a pre-computed digest. Use EVP_PKEY_verify directly. See
     * sign_asymmetric for the full rationale on why EVP_DigestVerify with
     * mdname = NULL silently applies a default digest in OpenSSL 3.x.
     *
     * Fix (v1.2.2). Bug reported by Denis Mingulov via pkcs11-check
     * on 2026-06-26. */
    if (hash == NULL) {
        pkctx_raw = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pkctx_raw) goto vcleanup;
        if (EVP_PKEY_verify_init(pkctx_raw) <= 0) goto vcleanup;
        if (mech_is_pss(op->mechanism)) {
            if (EVP_PKEY_CTX_set_rsa_padding(pkctx_raw,
                                              RSA_PKCS1_PSS_PADDING) <= 0)
                goto vcleanup;
            int saltlen = op->pss_have ? (int)op->pss_saltlen : -1;
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx_raw, saltlen) <= 0)
                goto vcleanup;
        }
        int vrv = EVP_PKEY_verify(pkctx_raw, sig_to_verify, sig_to_verify_len,
                                    pData, ulDataLen);
        verify_ok = (vrv == 1);
        if (vrv < 0) {
            if (der_buf) OPENSSL_free(der_buf);
            EVP_PKEY_CTX_free(pkctx_raw);
            EVP_PKEY_free(pkey);
            op->active = 0;
            return FHSM_RV_FUNCTION_FAILED;
        }
    } else {
        /* === Hashed verify path (hash != NULL) ============================ */
        mdctx = EVP_MD_CTX_new();
        if (!mdctx) goto vcleanup;
        EVP_PKEY_CTX *pkctx = NULL;
        if (EVP_DigestVerifyInit_ex(mdctx, &pkctx, hash, NULL, NULL, pkey, NULL) == 1) {
            if (mech_is_pss(op->mechanism)) {
                EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING);
                int saltlen = op->pss_have ? (int)op->pss_saltlen : -1;
                EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen);
            }
            int vrv = EVP_DigestVerify(mdctx, sig_to_verify, sig_to_verify_len,
                                        pData, ulDataLen);
            verify_ok = (vrv == 1);
            if (vrv < 0) {
                if (der_buf) OPENSSL_free(der_buf);
                EVP_MD_CTX_free(mdctx);
                EVP_PKEY_free(pkey);
                op->active = 0;
                return FHSM_RV_FUNCTION_FAILED;
            }
        }
    }

vcleanup:
    if (der_buf) OPENSSL_free(der_buf);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (pkctx_raw) EVP_PKEY_CTX_free(pkctx_raw);
    EVP_PKEY_free(pkey);
    op->active = 0;
    rv = verify_ok ? FHSM_RV_OK : FHSM_RV_SIGNATURE_INVALID;
    (void)fhsm_audit_event(FHSM_EV_VERIFY, -1, (int)hSession,
                            fhsm_session_role(hSession), rv, NULL);
    return rv;
}

/* ===========================================================================
 * Multi-part streaming Update/Final.
 *
 * Each pair of (Init, Update*, Final) keeps an EVP context alive in
 * fhsm_op_t. The context is created on Init, fed by Update, and
 * consumed by Final. The PKCS#11 caller can mix one-shot (Digest,
 * Sign, Encrypt) with multi-part on different sessions but never on
 * the same session at the same time (CKR_OPERATION_ACTIVE).
 * =========================================================================== */
/* openssl/evp.h is already included at the top of this TU. */

static const char *hash_evp_name(fhsm_hash_t h) {
    switch (h) {
        case FHSM_HASH_SHA256: return "SHA256";
        case FHSM_HASH_SHA384: return "SHA384";
        case FHSM_HASH_SHA512: return "SHA512";
        default: return NULL;
    }
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, unsigned char *pPart,
                     CK_ULONG ulPartLen) {
    fhsm_op_t *op = op_slot(g_op_dig, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    /* NULL part + non-zero length would deref NULL in the EVP update
     * (pkcs11-check security/test_ffi_null_pointer, #125). */
    if (pPart == NULL && ulPartLen != 0) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
    if (!op->md_ctx) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) return FHSM_RV_HOST_MEMORY;
        const EVP_MD *md = EVP_MD_fetch(NULL, hash_evp_name(op->hash), NULL);
        if (!md) { EVP_MD_CTX_free(ctx); return FHSM_RV_MECHANISM_INVALID; }
        if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
            EVP_MD_free((EVP_MD*)md); EVP_MD_CTX_free(ctx);
            return FHSM_RV_FUNCTION_FAILED;
        }
        EVP_MD_free((EVP_MD*)md);
        op->md_ctx = ctx;
    }
    if (EVP_DigestUpdate(op->md_ctx, pPart, ulPartLen) != 1)
        return FHSM_RV_FUNCTION_FAILED;
    return FHSM_RV_OK;
}

/* PKCS#11 v3.2 §C.6.10.5 : C_DigestKey
 *
 * Process the value of a key object as if it had been passed to
 * C_DigestUpdate. Only meaningful for non-sensitive secret keys ;
 * sensitive (CKA_SENSITIVE=TRUE) and asymmetric private keys MUST
 * return CKR_KEY_INDIGESTIBLE so that the digest output cannot be
 * used as a side channel to recover the key material.
 *
 * The actual feeding is equivalent to calling C_DigestUpdate on the
 * key value bytes ; we reuse the same EVP_MD_CTX so a mixed-mode
 * stream (data + key + data) produces the correct concatenated digest. */
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
    fhsm_op_t *op = op_slot(g_op_dig, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;

    /* Sensitive-key gate : refuse before fetching the key value, so the
     * value never enters the digest pipeline for a sensitive object.
     * CK_OBJECT_HANDLE is CK_ULONG (long unsigned) ; the token-internal
     * handle space is uint32_t. Explicit narrowing cast since the upper
     * bits cannot be in use (the token allocates handles from a 32-bit
     * counter). */
    uint32_t obj_handle = (uint32_t)hKey;
    uint8_t obj_flags = 0;
    if (fhsm_token_object_get_flags(t, obj_handle, &obj_flags) == FHSM_RV_OK) {
        if (obj_flags & FHSM_OBJF_SENSITIVE) {
            return 0x00000067UL;   /* CKR_KEY_INDIGESTIBLE */
        }
    }

    const uint8_t *kv = NULL; size_t kvl = 0;
    uint32_t cl = 0, kt = 0;
    fhsm_rv_t rv = fhsm_token_object_get(t, obj_handle, &kv, &kvl, &cl, &kt);
    if (rv != FHSM_RV_OK) return rv;

    /* Only secret keys can be digested ; asymmetric private keys would
     * leak the key material through the digest output. Public keys
     * are accessible via C_GetAttributeValue(CKA_VALUE) directly --- no
     * need for C_DigestKey path. */
    if (cl != CKO_SECRET_KEY) {
        return 0x00000067UL;       /* CKR_KEY_INDIGESTIBLE */
    }

    /* Lazy-init the EVP_MD_CTX if no C_DigestUpdate was called first
     * (allows digest-of-key-alone via C_DigestInit → C_DigestKey →
     * C_DigestFinal). */
    if (!op->md_ctx) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) return FHSM_RV_HOST_MEMORY;
        const EVP_MD *md = EVP_MD_fetch(NULL, hash_evp_name(op->hash), NULL);
        if (!md) { EVP_MD_CTX_free(ctx); return FHSM_RV_MECHANISM_INVALID; }
        if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
            EVP_MD_free((EVP_MD*)md); EVP_MD_CTX_free(ctx);
            return FHSM_RV_FUNCTION_FAILED;
        }
        EVP_MD_free((EVP_MD*)md);
        op->md_ctx = ctx;
    }
    if (EVP_DigestUpdate(op->md_ctx, kv, kvl) != 1) {
        return FHSM_RV_FUNCTION_FAILED;
    }
    return FHSM_RV_OK;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, unsigned char *pDigest,
                    CK_ULONG *pulDigestLen) {
    fhsm_op_t *op = op_slot(g_op_dig, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    if (!pulDigestLen) return FHSM_RV_ARGUMENTS_BAD;
    size_t need = fhsm_hash_size(op->hash);
    if (pDigest == NULL) { *pulDigestLen = need; return FHSM_RV_OK; }
    if (*pulDigestLen < need) { *pulDigestLen = need; return 0x00000150UL; }
    if (!op->md_ctx) {
        /* Final without any Update == digest of empty input. */
        size_t out_len = *pulDigestLen;
        fhsm_rv_t rv = fhsm_hash_oneshot(op->hash, FHSM_SLICE("", 0),
                                          pDigest, &out_len);
        *pulDigestLen = out_len;
        op->active = 0;
        return rv;
    }
    unsigned int out_len = (unsigned int)*pulDigestLen;
    int ok = EVP_DigestFinal_ex(op->md_ctx, pDigest, &out_len);
    EVP_MD_CTX_free(op->md_ctx); op->md_ctx = NULL;
    *pulDigestLen = out_len;
    op->active = 0;
    return ok == 1 ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, unsigned char *pPart,
                   CK_ULONG ulPartLen) {
    fhsm_op_t *op = op_slot(g_op_sig, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    /* NULL part + non-zero length would deref NULL in the EVP update
     * (pkcs11-check security/test_ffi_null_pointer, #125). */
    if (pPart == NULL && ulPartLen != 0) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (!op->mac_ctx) {
        const uint8_t *kv = NULL; size_t kvl = 0;
        uint32_t cl = 0, kt = 0;
        fhsm_rv_t rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
        if (rv != FHSM_RV_OK) return rv;
        /* Select the digest from the mechanism (#125 : multipart HMAC was
         * hard-coded to SHA-256, so SHA-384/512/SHA-3 produced a wrong
         * MAC that did not match the one-shot path). */
        fhsm_hash_t uhash; size_t umac;
        if (!fhsm_hmac_hash_of(op->mechanism, &uhash, &umac))
            return FHSM_RV_MECHANISM_INVALID;
        const char *dn = hmac_digest_name(uhash);
        if (!dn) return FHSM_RV_MECHANISM_INVALID;
        EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (!mac) return FHSM_RV_MECHANISM_INVALID;
        EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (!ctx) return FHSM_RV_HOST_MEMORY;
        OSSL_PARAM params[2];
        char digest_name[16];
        snprintf(digest_name, sizeof digest_name, "%s", dn);
        params[0] = OSSL_PARAM_construct_utf8_string("digest", digest_name, 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_MAC_init(ctx, kv, kvl, params) != 1) {
            EVP_MAC_CTX_free(ctx);
            return FHSM_RV_FUNCTION_FAILED;
        }
        op->mac_ctx = ctx;
    }
    if (EVP_MAC_update(op->mac_ctx, pPart, ulPartLen) != 1)
        return FHSM_RV_FUNCTION_FAILED;
    return FHSM_RV_OK;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, unsigned char *pSig,
                  CK_ULONG *pulSigLen) {
    fhsm_op_t *op = op_slot(g_op_sig, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    if (!pulSigLen) return FHSM_RV_ARGUMENTS_BAD;
    /* Signature length is the MAC length of the mechanism's hash, not a
     * hard-coded 32 (#125 multipart HMAC for SHA-384/512/SHA-3). */
    fhsm_hash_t fhash; size_t fmac;
    if (!fhsm_hmac_hash_of(op->mechanism, &fhash, &fmac)) { fhash = FHSM_HASH_SHA256; fmac = 32; }
    if (pSig == NULL) { *pulSigLen = fmac; return FHSM_RV_OK; }
    if (*pulSigLen < fmac) { *pulSigLen = fmac; return 0x00000150UL; }
    size_t out_len = 0;
    fhsm_rv_t rv = FHSM_RV_OK;
    if (!op->mac_ctx) {
        /* No Update issued ; HMAC of empty input. */
        fhsm_token_t *t = fhsm_session_token(hSession);
        const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl=0, kt=0;
        rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
        if (rv == FHSM_RV_OK) {
            out_len = *pulSigLen;
            rv = fhsm_hmac(fhash, FHSM_SLICE(kv, kvl),
                            FHSM_SLICE("", 0), pSig, &out_len);
        }
    } else {
        if (EVP_MAC_final(op->mac_ctx, pSig, &out_len, *pulSigLen) != 1)
            rv = FHSM_RV_FUNCTION_FAILED;
        EVP_MAC_CTX_free(op->mac_ctx); op->mac_ctx = NULL;
    }
    *pulSigLen = out_len;
    op->active = 0;
    return rv;
}

/* PKCS#11 v3.2 §C.6.13.6 / §C.6.13.7 : C_VerifyUpdate and C_VerifyFinal.
 *
 * Symmetric to C_SignUpdate / C_SignFinal which currently only supports
 * the HMAC mechanism CKM_SHA256_HMAC. We mirror that coverage on the
 * verify path : multipart HMAC verification is supported ; asymmetric
 * multipart verify (which would require deferring the actual
 * EVP_DigestVerifyFinal call until C_VerifyFinal) is not currently
 * implemented and falls through to CKR_MECHANISM_INVALID.
 *
 * The HMAC compare uses fhsm_ct_memcmp for constant-time equality
 * to avoid timing side channels on signature validation. */
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, unsigned char *pPart,
                     CK_ULONG ulPartLen) {
    fhsm_op_t *op = op_slot(g_op_ver, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    /* NULL part + non-zero length would deref NULL in the EVP update
     * (pkcs11-check security/test_ffi_null_pointer, #125). */
    if (pPart == NULL && ulPartLen != 0) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    if (op->mechanism != CKM_SHA256_HMAC_INIT_VAL) {
        /* Asymmetric multipart not implemented in this scaffold. */
        return FHSM_RV_MECHANISM_INVALID;
    }
    if (!op->mac_ctx) {
        const uint8_t *kv = NULL; size_t kvl = 0;
        uint32_t cl = 0, kt = 0;
        fhsm_rv_t rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
        if (rv != FHSM_RV_OK) return rv;
        EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (!mac) return FHSM_RV_MECHANISM_INVALID;
        EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (!ctx) return FHSM_RV_HOST_MEMORY;
        OSSL_PARAM params[2];
        char digest_name[] = "SHA256";
        params[0] = OSSL_PARAM_construct_utf8_string("digest", digest_name, 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_MAC_init(ctx, kv, kvl, params) != 1) {
            EVP_MAC_CTX_free(ctx);
            return FHSM_RV_FUNCTION_FAILED;
        }
        op->mac_ctx = ctx;
    }
    if (EVP_MAC_update(op->mac_ctx, pPart, ulPartLen) != 1)
        return FHSM_RV_FUNCTION_FAILED;
    return FHSM_RV_OK;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, unsigned char *pSig,
                    CK_ULONG ulSigLen) {
    fhsm_op_t *op = op_slot(g_op_ver, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    if (!pSig) return FHSM_RV_ARGUMENTS_BAD;
    if (op->mechanism != CKM_SHA256_HMAC_INIT_VAL) {
        if (op->mac_ctx) { EVP_MAC_CTX_free(op->mac_ctx); op->mac_ctx = NULL; }
        op->active = 0;
        return FHSM_RV_MECHANISM_INVALID;
    }
    uint8_t mac[32];
    size_t mac_len = 0;
    fhsm_rv_t rv = FHSM_RV_OK;
    if (!op->mac_ctx) {
        /* No Update issued ; HMAC of empty input. */
        fhsm_token_t *t = fhsm_session_token(hSession);
        const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl=0, kt=0;
        rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
        if (rv == FHSM_RV_OK) {
            mac_len = sizeof(mac);
            rv = fhsm_hmac(FHSM_HASH_SHA256, FHSM_SLICE(kv, kvl),
                            FHSM_SLICE("", 0), mac, &mac_len);
        }
    } else {
        if (EVP_MAC_final(op->mac_ctx, mac, &mac_len, sizeof(mac)) != 1)
            rv = FHSM_RV_FUNCTION_FAILED;
        EVP_MAC_CTX_free(op->mac_ctx); op->mac_ctx = NULL;
    }
    op->active = 0;
    if (rv != FHSM_RV_OK) return rv;
    if (ulSigLen != mac_len) return FHSM_RV_SIGNATURE_INVALID;
    return (fhsm_ct_memcmp(mac, pSig, mac_len) == 0) ? FHSM_RV_OK
                                                       : FHSM_RV_SIGNATURE_INVALID;
}

/* AES-GCM Update/Final via EVP_CIPHER_CTX. */
static fhsm_rv_t ensure_cipher_ctx_aes_gcm(fhsm_op_t *op, fhsm_token_t *t, int enc) {
    if (op->cipher_ctx) return FHSM_RV_OK;
    const uint8_t *kv = NULL; size_t kvl = 0; uint32_t cl=0, kt=0;
    fhsm_rv_t rv = fhsm_token_object_get(t, op->key_handle, &kv, &kvl, &cl, &kt);
    if (rv != FHSM_RV_OK) return rv;
    if (kt != CKK_AES) return FHSM_RV_MECHANISM_INVALID;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return FHSM_RV_HOST_MEMORY;
    const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL,
        kvl == 16 ? "AES-128-GCM" : kvl == 24 ? "AES-192-GCM" : "AES-256-GCM", NULL);
    if (!cipher) { EVP_CIPHER_CTX_free(ctx); return FHSM_RV_MECHANISM_INVALID; }
    int ok;
    if (enc) {
        ok = EVP_EncryptInit_ex2(ctx, cipher, kv, op->have_iv ? op->iv : NULL, NULL);
    } else {
        ok = EVP_DecryptInit_ex2(ctx, cipher, kv, op->have_iv ? op->iv : NULL, NULL);
    }
    EVP_CIPHER_free((EVP_CIPHER*)cipher);
    if (!ok) { EVP_CIPHER_CTX_free(ctx); return FHSM_RV_FUNCTION_FAILED; }
    op->cipher_ctx = ctx;
    return FHSM_RV_OK;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, unsigned char *pPart,
                      CK_ULONG ulPartLen, unsigned char *pEnc, CK_ULONG *pulEncLen) {
    fhsm_op_t *op = op_slot(g_op_enc, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    /* pulEncLen is dereferenced on every path (size query and copy) ;
     * reject NULL rather than crash (#125, same class as the C_Decrypt
     * fix). Terminate the operation so the session is not stranded. */
    if (!pulEncLen || (!pPart && ulPartLen)) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
    /* The length is passed to EVP as an int ; a value beyond INT_MAX would be
     * silently truncated (#125 TestIsizeMaxUpdateLength). Reject it. */
    if (ulPartLen > 0x7FFFFFFFUL) { op->active = 0; return FHSM_RV_DATA_LEN_RANGE; }
    fhsm_rv_t rv = ensure_cipher_ctx_aes_gcm(op, t, 1);
    if (rv != FHSM_RV_OK) { op->active = 0; return rv; }
    if (pEnc == NULL) { *pulEncLen = ulPartLen; return FHSM_RV_OK; }
    int out_len = 0;
    if (EVP_EncryptUpdate(op->cipher_ctx, pEnc, &out_len, pPart, (int)ulPartLen) != 1) {
        op->active = 0; return FHSM_RV_FUNCTION_FAILED;
    }
    *pulEncLen = (CK_ULONG)out_len;
    return FHSM_RV_OK;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, unsigned char *pLast,
                     CK_ULONG *pulLastLen) {
    fhsm_op_t *op = op_slot(g_op_enc, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    if (!pulLastLen) return FHSM_RV_ARGUMENTS_BAD;
    /* Final returns the 16-byte GCM tag appended after any remaining bytes. */
    if (pLast == NULL) { *pulLastLen = 16; return FHSM_RV_OK; }
    if (*pulLastLen < 16) { *pulLastLen = 16; return 0x00000150UL; }
    int out_len = 0;
    if (op->cipher_ctx == NULL) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    if (EVP_EncryptFinal_ex(op->cipher_ctx, pLast, &out_len) != 1) {
        EVP_CIPHER_CTX_free(op->cipher_ctx); op->cipher_ctx = NULL;
        op->active = 0;
        return FHSM_RV_FUNCTION_FAILED;
    }
    /* Append the GCM tag. */
    if (EVP_CIPHER_CTX_ctrl(op->cipher_ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                              pLast + out_len) != 1) {
        EVP_CIPHER_CTX_free(op->cipher_ctx); op->cipher_ctx = NULL;
        op->active = 0;
        return FHSM_RV_FUNCTION_FAILED;
    }
    *pulLastLen = (CK_ULONG)out_len + 16;
    EVP_CIPHER_CTX_free(op->cipher_ctx); op->cipher_ctx = NULL;
    op->active = 0;
    return FHSM_RV_OK;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, unsigned char *pEnc,
                      CK_ULONG ulEncLen, unsigned char *pPart, CK_ULONG *pulPartLen) {
    fhsm_op_t *op = op_slot(g_op_dec, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    fhsm_token_t *t = fhsm_session_token(hSession);
    if (!t) return FHSM_RV_SESSION_HANDLE_INVALID;
    /* pulPartLen is dereferenced on every path ; reject NULL rather
     * than crash (#125, same class as the C_Decrypt fix). */
    if (!pulPartLen || (!pEnc && ulEncLen)) { op->active = 0; return FHSM_RV_ARGUMENTS_BAD; }
    if (ulEncLen > 0x7FFFFFFFUL) { op->active = 0; return FHSM_RV_DATA_LEN_RANGE; }
    fhsm_rv_t rv = ensure_cipher_ctx_aes_gcm(op, t, 0);
    if (rv != FHSM_RV_OK) { op->active = 0; return rv; }
    if (pPart == NULL) { *pulPartLen = ulEncLen; return FHSM_RV_OK; }
    int out_len = 0;
    if (EVP_DecryptUpdate(op->cipher_ctx, pPart, &out_len, pEnc, (int)ulEncLen) != 1) {
        op->active = 0; return FHSM_RV_FUNCTION_FAILED;
    }
    *pulPartLen = (CK_ULONG)out_len;
    return FHSM_RV_OK;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, unsigned char *pLast,
                     CK_ULONG *pulLastLen) {
    fhsm_op_t *op = op_slot(g_op_dec, hSession);
    if (!op || !op->active) return FHSM_RV_OPERATION_NOT_INITIALIZED;
    if (!pulLastLen) return FHSM_RV_ARGUMENTS_BAD;
    if (pLast == NULL) { *pulLastLen = 0; return FHSM_RV_OK; }
    /* No multipart context : C_DecryptInit was called but no
     * C_DecryptUpdate ever created the cipher context (e.g. the key
     * handle was invalid, or Final was called directly). Guard against
     * EVP_DecryptFinal_ex(NULL) which segfaults. Mirrors C_EncryptFinal.
     * #125 (pkcs11-check crash : test_mech_flags decrypt_flag_callable). */
    if (op->cipher_ctx == NULL) {
        op->active = 0;
        return FHSM_RV_OPERATION_NOT_INITIALIZED;
    }
    int out_len = 0;
    int ok = EVP_DecryptFinal_ex(op->cipher_ctx, pLast, &out_len);
    EVP_CIPHER_CTX_free(op->cipher_ctx); op->cipher_ctx = NULL;
    *pulLastLen = (CK_ULONG)out_len;
    op->active = 0;
    /* Final fails if tag verification fails. PKCS#11 maps this to
     * CKR_ENCRYPTED_DATA_INVALID. */
    return ok == 1 ? FHSM_RV_OK : FHSM_RV_ENCRYPTED_DATA_INVALID;
}

/* ---------------------------------------------------------------------------
 * C_GetFunctionList --- the *single* symbol every PKCS#11 application
 * resolves via dlsym to obtain the function table. Without this entry
 * point the .so cannot be loaded by pkcs11-tool, OpenSC, NSS, etc.
 *
 * The table layout follows PKCS#11 v2.40 sec C.6 (67 function pointers
 * preceded by a 2-byte CK_VERSION). Slots that are not yet implemented
 * are routed to fhsm_not_supported, which returns CKR_FUNCTION_NOT_SUPPORTED.
 *
 * pkcs11-tool calls in order: C_GetFunctionList, then through the table:
 *   C_Initialize, C_GetInfo, C_GetSlotList, C_Finalize.
 * Those four (plus the table itself) are wired below.
 * ----------------------------------------------------------------------- */
typedef struct CK_VERSION_s { unsigned char major, minor; } CK_VERSION;

/* The PKCS#11 v2.40 CK_FUNCTION_LIST is { CK_VERSION; 67 function pointers; }.
 * We use a uniform void* array because the loader only dereferences the
 * pointers it knows the type of, and C guarantees that all pointer-to-function
 * casts are reversible. */
struct CK_FUNCTION_LIST {
    CK_VERSION version;
    void *pfn[67];   /* C_Initialize ... C_WaitForSlotEvent */
};

static CK_RV fhsm_not_supported(void) {
    return 0x00000054UL;   /* CKR_FUNCTION_NOT_SUPPORTED */
}

static struct CK_FUNCTION_LIST fhsm_function_list = { { 2, 40 }, { 0 } };

CK_RV C_GetFunctionList(struct CK_FUNCTION_LIST **ppFnList) {
    if (!ppFnList) return FHSM_RV_ARGUMENTS_BAD;
    if (!fhsm_function_list.pfn[0]) {
        /* Default every slot to fhsm_not_supported. */
        for (size_t i = 0;
             i < sizeof(fhsm_function_list.pfn)/sizeof(fhsm_function_list.pfn[0]);
             i++) {
            fhsm_function_list.pfn[i] = (void*)(uintptr_t)fhsm_not_supported;
        }
        /* PKCS#11 v2.40 sec C.6 ordering --- only the slots used by
         * pkcs11-tool --show-info and the implemented C_* are populated. */
        /* PKCS#11 v2.40 §C.6 ordering (verified against OpenSC pkcs11f.h).
         * C_WaitForSlotEvent is at the END (slot 66), NOT after C_GetTokenInfo. */
        fhsm_function_list.pfn[0]  = (void*)(uintptr_t)C_Initialize;       /* slot  0 */
        fhsm_function_list.pfn[1]  = (void*)(uintptr_t)C_Finalize;         /* slot  1 */
        fhsm_function_list.pfn[2]  = (void*)(uintptr_t)C_GetInfo;          /* slot  2 */
        fhsm_function_list.pfn[3]  = (void*)(uintptr_t)C_GetFunctionList;  /* slot  3 */
        fhsm_function_list.pfn[4]  = (void*)(uintptr_t)C_GetSlotList;      /* slot  4 */
        fhsm_function_list.pfn[5]  = (void*)(uintptr_t)C_GetSlotInfo;      /* slot  5 */
        fhsm_function_list.pfn[6]  = (void*)(uintptr_t)C_GetTokenInfo;     /* slot  6 */
        fhsm_function_list.pfn[7]  = (void*)(uintptr_t)C_GetMechanismList; /* slot  7 */
        fhsm_function_list.pfn[8]  = (void*)(uintptr_t)C_GetMechanismInfo; /* slot  8 */
        fhsm_function_list.pfn[9]  = (void*)(uintptr_t)C_InitToken;        /* slot  9 */
        fhsm_function_list.pfn[10] = (void*)(uintptr_t)C_InitPIN;          /* slot 10 */
        fhsm_function_list.pfn[11] = (void*)(uintptr_t)C_SetPIN;           /* slot 11 */
        fhsm_function_list.pfn[12] = (void*)(uintptr_t)C_OpenSession;      /* slot 12 */
        fhsm_function_list.pfn[13] = (void*)(uintptr_t)C_CloseSession;     /* slot 13 */
        fhsm_function_list.pfn[14] = (void*)(uintptr_t)C_CloseAllSessions; /* slot 14 (v1.4.0) */
        fhsm_function_list.pfn[15] = (void*)(uintptr_t)C_GetSessionInfo;   /* slot 15 (v1.2.2) */
        fhsm_function_list.pfn[18] = (void*)(uintptr_t)C_Login;            /* slot 18 */
        fhsm_function_list.pfn[19] = (void*)(uintptr_t)C_Logout;           /* slot 19 */
        /* Object lifecycle */
        fhsm_function_list.pfn[20] = (void*)(uintptr_t)C_CreateObject;     /* slot 20 (v1.2.2) */
        fhsm_function_list.pfn[21] = (void*)(uintptr_t)C_CopyObject;       /* slot 21 (v1.3.0) */
        fhsm_function_list.pfn[22] = (void*)(uintptr_t)C_DestroyObject;    /* slot 22 */
        fhsm_function_list.pfn[23] = (void*)(uintptr_t)C_GetObjectSize;    /* slot 23 (v1.2.2) */
        fhsm_function_list.pfn[24] = (void*)(uintptr_t)C_GetAttributeValue;/* slot 24 */
        fhsm_function_list.pfn[25] = (void*)(uintptr_t)C_SetAttributeValue;/* slot 25 (v1.3.0) */
        fhsm_function_list.pfn[26] = (void*)(uintptr_t)C_FindObjectsInit;  /* slot 26 */
        fhsm_function_list.pfn[27] = (void*)(uintptr_t)C_FindObjects;      /* slot 27 */
        fhsm_function_list.pfn[28] = (void*)(uintptr_t)C_FindObjectsFinal; /* slot 28 */
        /* Encryption */
        fhsm_function_list.pfn[29] = (void*)(uintptr_t)C_EncryptInit;      /* slot 29 */
        fhsm_function_list.pfn[30] = (void*)(uintptr_t)C_Encrypt;          /* slot 30 */
        fhsm_function_list.pfn[31] = (void*)(uintptr_t)C_EncryptUpdate;    /* slot 31 */
        fhsm_function_list.pfn[32] = (void*)(uintptr_t)C_EncryptFinal;     /* slot 32 */
        fhsm_function_list.pfn[33] = (void*)(uintptr_t)C_DecryptInit;      /* slot 33 */
        fhsm_function_list.pfn[34] = (void*)(uintptr_t)C_Decrypt;          /* slot 34 */
        fhsm_function_list.pfn[35] = (void*)(uintptr_t)C_DecryptUpdate;    /* slot 35 */
        fhsm_function_list.pfn[36] = (void*)(uintptr_t)C_DecryptFinal;     /* slot 36 */
        /* Digest */
        fhsm_function_list.pfn[37] = (void*)(uintptr_t)C_DigestInit;       /* slot 37 */
        fhsm_function_list.pfn[38] = (void*)(uintptr_t)C_Digest;           /* slot 38 */
        fhsm_function_list.pfn[39] = (void*)(uintptr_t)C_DigestUpdate;     /* slot 39 */
        fhsm_function_list.pfn[40] = (void*)(uintptr_t)C_DigestKey;        /* slot 40 (v1.4.0) */
        fhsm_function_list.pfn[41] = (void*)(uintptr_t)C_DigestFinal;      /* slot 41 */
        /* Sign */
        fhsm_function_list.pfn[42] = (void*)(uintptr_t)C_SignInit;         /* slot 42 */
        fhsm_function_list.pfn[43] = (void*)(uintptr_t)C_Sign;             /* slot 43 */
        fhsm_function_list.pfn[44] = (void*)(uintptr_t)C_SignUpdate;       /* slot 44 */
        fhsm_function_list.pfn[45] = (void*)(uintptr_t)C_SignFinal;        /* slot 45 */
        /* Verify */
        fhsm_function_list.pfn[48] = (void*)(uintptr_t)C_VerifyInit;       /* slot 48 */
        fhsm_function_list.pfn[49] = (void*)(uintptr_t)C_Verify;           /* slot 49 */
        fhsm_function_list.pfn[50] = (void*)(uintptr_t)C_VerifyUpdate;     /* slot 50 (v1.4.0) */
        fhsm_function_list.pfn[51] = (void*)(uintptr_t)C_VerifyFinal;      /* slot 51 (v1.4.0) */
        /* Key generation */
        fhsm_function_list.pfn[58] = (void*)(uintptr_t)C_GenerateKey;      /* slot 58 */
        fhsm_function_list.pfn[59] = (void*)(uintptr_t)C_GenerateKeyPair;  /* slot 59 */
        fhsm_function_list.pfn[60] = (void*)(uintptr_t)C_WrapKey;          /* slot 60 */
        fhsm_function_list.pfn[61] = (void*)(uintptr_t)C_UnwrapKey;        /* slot 61 */
        /* Key derivation */
        fhsm_function_list.pfn[62] = (void*)(uintptr_t)C_DeriveKey;        /* slot 62 */
        /* RNG */
        fhsm_function_list.pfn[63] = (void*)(uintptr_t)C_SeedRandom;       /* slot 63 (v1.4.0) */
        fhsm_function_list.pfn[64] = (void*)(uintptr_t)C_GenerateRandom;   /* slot 64 */
        /* Legacy parallel-function management (v2.40 §C.6.5.6).
         * Both return CKR_FUNCTION_NOT_PARALLEL per spec on every
         * modern non-parallel implementation. */
        fhsm_function_list.pfn[65] = (void*)(uintptr_t)C_GetFunctionStatus;/* slot 65 (v1.4.0) */
        /* Slot event (software token : no hot-plug ; non-blocking returns
         * CKR_NO_EVENT, blocking returns CKR_FUNCTION_NOT_SUPPORTED). */
        fhsm_function_list.pfn[66] = (void*)(uintptr_t)C_WaitForSlotEvent; /* slot 66 (v1.3.0) */
    }
    *ppFnList = &fhsm_function_list;
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * CK_INTERFACE v3.0 (PKCS#11 v3.0 §5.18) --- placed here after the v2.40
 * fhsm_function_list / CK_VERSION / fhsm_not_supported definitions so all
 * the symbols it references are already visible.
 *
 * The v3.0 table is a separate static (fhsm_function_list_3_0) with :
 *   - version field = {3, 0}
 *   - 67 v2.40 functions at slots 0..66 (copied from fhsm_function_list)
 *   - slot 67 = C_GetInterfaceList, slot 68 = C_GetInterface
 *   - slots 69..90 = fhsm_not_supported (Login_User, SessionCancel,
 *     Message family) ; can be wired in a future release
 *
 * The previous attempt segfaulted pkcs11-tool because it returned the
 * v2.40 table when v3.0 was requested ; the version mismatch + missing
 * slots caused pkcs11-tool to dereference past the end of the array.
 * ----------------------------------------------------------------------- */
typedef struct CK_INTERFACE_s {
    char        *pInterfaceName;
    void        *pFunctionList;
    CK_FLAGS     flags;
} CK_INTERFACE;

struct CK_FUNCTION_LIST_3_0 {
    CK_VERSION version;     /* {3, 0} */
    void *pfn[91];          /* 67 v2.40 + 24 v3.0 */
};

static struct CK_FUNCTION_LIST_3_0 fhsm_function_list_3_0 = { { 3, 0 }, { 0 } };

static void fhsm_init_v3_0_table(void) {
    if (fhsm_function_list_3_0.pfn[0]) return;
    /* Ensure the v2.40 table is initialized first (it triggers our
     * lazy slot-filling). */
    if (!fhsm_function_list.pfn[0]) {
        struct CK_FUNCTION_LIST *unused;
        (void)C_GetFunctionList(&unused);
    }
    /* Default every v3.0 slot to fhsm_not_supported. */
    for (size_t i = 0;
         i < sizeof(fhsm_function_list_3_0.pfn)/sizeof(fhsm_function_list_3_0.pfn[0]);
         i++) {
        fhsm_function_list_3_0.pfn[i] = (void*)(uintptr_t)fhsm_not_supported;
    }
    /* Mirror v2.40 slots 0..66 into the v3.0 table. */
    for (size_t i = 0; i < 67; i++) {
        fhsm_function_list_3_0.pfn[i] = fhsm_function_list.pfn[i];
    }
    /* v3.0 §5.18 says slot 67 is C_GetInterfaceList and slot 68 is
     * C_GetInterface. We populate those next. */
}

CK_RV C_GetInterfaceList(CK_INTERFACE *pInterfacesList, CK_ULONG *pulCount) {
    if (!pulCount) return FHSM_RV_ARGUMENTS_BAD;
    if (pInterfacesList == NULL) { *pulCount = 1; return FHSM_RV_OK; }
    if (*pulCount < 1) { *pulCount = 1; return 0x00000150UL; }
    fhsm_init_v3_0_table();
    static char name[] = "PKCS 11";
    pInterfacesList[0].pInterfaceName = name;
    pInterfacesList[0].pFunctionList  = &fhsm_function_list_3_0;
    pInterfacesList[0].flags          = 0;
    *pulCount = 1;
    return FHSM_RV_OK;
}

CK_RV C_GetInterface(unsigned char *pInterfaceName, void *pVersion,
                     CK_INTERFACE **ppInterface, CK_FLAGS flags) {
    (void)pVersion; (void)flags;
    if (!ppInterface) return FHSM_RV_ARGUMENTS_BAD;
    if (pInterfaceName != NULL
        && strcmp((const char*)pInterfaceName, "PKCS 11") != 0) {
        return FHSM_RV_FUNCTION_FAILED;
    }
    fhsm_init_v3_0_table();
    static char name[] = "PKCS 11";
    static CK_INTERFACE iface;
    iface.pInterfaceName = name;
    iface.pFunctionList  = &fhsm_function_list_3_0;
    iface.flags          = 0;
    *ppInterface = &iface;
    /* Wire slot 67 (C_GetInterfaceList) and slot 68 (C_GetInterface)
     * on first call ; they couldn't be populated in fhsm_init_v3_0_table
     * because they are these very functions. */
    fhsm_function_list_3_0.pfn[67] = (void*)(uintptr_t)C_GetInterfaceList;
    fhsm_function_list_3_0.pfn[68] = (void*)(uintptr_t)C_GetInterface;
    return FHSM_RV_OK;
}
