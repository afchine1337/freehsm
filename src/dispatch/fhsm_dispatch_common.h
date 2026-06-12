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
 * fhsm_dispatch_common.h --- Shared definitions for the dispatch handlers.
 *
 * Each handler in `src/dispatch/` overrides a weak symbol declared in
 * src/gen/fhsm_dispatch.c. The handler signature is documented in
 * include/fhsm_pkcs11_mechanisms.h --- this header adds the conventions
 * used by *every* concrete handler:
 *
 *   1. Parameter encoding (until the object store is fully wired):
 *      The `params` argument is a typed, length-prefixed buffer that
 *      contains either an inline key + IV/nonce/AAD, or a reference
 *      to a previously created object. The format is a sequence of
 *      TLV records:
 *
 *        type(1 byte) || length(4 BE) || value(length bytes)
 *
 *      Types defined below as FHSM_TLV_*.
 *
 *   2. Audit emission:
 *      Each handler emits FHSM_EV_<op> on entry and FHSM_EV_<op> on
 *      exit with the result. Lengths of inputs and outputs are passed;
 *      key material is NEVER logged.
 *
 *   3. Constant-time invariants:
 *      Decrypt/verify handlers must NOT leak the failure path through
 *      timing or short-circuit returns past the security-relevant
 *      compares. fhsm_ct_memcmp is mandatory; manual loops are forbidden.
 *
 *   4. Zeroize on exit:
 *      Any sensitive intermediate (derived keys, KAT vectors,
 *      decrypted plaintext on failure) must be zeroized before return.
 * ========================================================================= */

#ifndef FHSM_DISPATCH_COMMON_H
#define FHSM_DISPATCH_COMMON_H

#include "fhsm_common.h"
/* Generated header containing the extern prototypes of every
 * dispatch_ handler. Including it here propagates the prototypes
 * to every dispatch source file. */
#include "fhsm_pkcs11_mechanisms.h"
/* Generated header containing the extern prototypes of every
 * dispatch_* handler. Including it here lets every dispatch source
 * file satisfy -Wmissing-prototypes by transitivity. */
#include "fhsm_pkcs11_mechanisms.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TLV record types for the params buffer. */
#define FHSM_TLV_KEY            0x01  /* raw symmetric key bytes              */
#define FHSM_TLV_IV             0x02  /* IV / nonce                           */
#define FHSM_TLV_AAD            0x03  /* Additional authenticated data        */
#define FHSM_TLV_TAG            0x04  /* AEAD tag (for decrypt)               */
#define FHSM_TLV_SALT           0x05  /* PBKDF2 / HKDF salt                   */
#define FHSM_TLV_INFO           0x06  /* HKDF info                            */
#define FHSM_TLV_ITERATIONS     0x07  /* PBKDF2 iter (4 BE bytes)             */
#define FHSM_TLV_PASSWORD       0x08  /* PBKDF2 password bytes                */
#define FHSM_TLV_HASH_ALG       0x09  /* fhsm_hash_t (1 byte)                 */
#define FHSM_TLV_PEM            0x0A  /* PEM-encoded key (asymmetric)         */
#define FHSM_TLV_PEM_PUB        0x0B  /* PEM-encoded public key               */
#define FHSM_TLV_CURVE          0x0C  /* curve name (ASCII, e.g. "P-256")     */
#define FHSM_TLV_KEY_BITS       0x0D  /* key size hint (2 BE bytes)           */
#define FHSM_TLV_PARAM_SET      0x0E  /* PQ parameter set (ASCII)             */
#define FHSM_TLV_TAG_LEN        0x0F  /* AEAD tag length in bytes (1 byte)    */

/* Scan a params buffer for a TLV of the given type. Returns FHSM_RV_OK
 * and fills out on success, FHSM_RV_ARGUMENTS_BAD if absent. */
fhsm_rv_t fhsm_tlv_find(const void *params, size_t plen,
                         uint8_t type, fhsm_slice_t *out);

/* Convenience : optional TLV lookup (no error if absent, out is zeroed). */
void fhsm_tlv_find_optional(const void *params, size_t plen,
                              uint8_t type, fhsm_slice_t *out);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_DISPATCH_COMMON_H */
