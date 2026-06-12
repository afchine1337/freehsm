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
 * fhsm_dispatch_hmac.c --- HMAC-SHA{2,3} sign handlers.
 *
 * The HMAC key is provided in params as TLV record FHSM_TLV_KEY. Once
 * the object store is fully wired, the key handle will be resolved
 * here instead. The handler signature remains stable across that
 * migration; only the body of "fetch key" changes.
 *
 * Approved per FIPS 198-1 with the corresponding SHA-2 / SHA-3 hash.
 * The minimum key length is enforced by OpenSSL (NIST SP 800-107 rev. 1
 * recommends key length >= L/2 where L is the hash output size).
 * ========================================================================= */

#include "fhsm_dispatch_common.h"
#include "fhsm_crypto.h"

#include <string.h>

#define HMAC_HANDLER(name, alg)                                               \
    fhsm_rv_t name(unsigned long session, unsigned long key,                  \
                    const void *params, size_t plen,                          \
                    fhsm_slice_t in, uint8_t *out, size_t *outlen)            \
    {                                                                         \
        (void)session; (void)key;                                             \
        if (out == NULL || outlen == NULL) return FHSM_RV_ARGUMENTS_BAD;      \
        fhsm_slice_t k;                                                       \
        fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k);         \
        if (rv != FHSM_RV_OK) return rv;                                      \
        size_t need = fhsm_hash_size(alg);                                    \
        if (*outlen < need) return FHSM_RV_ARGUMENTS_BAD;                     \
        *outlen = need;                                                       \
        return fhsm_hmac(alg, k, in, out, outlen);                            \
    }

HMAC_HANDLER(dispatch_hmac_sha256,   FHSM_HASH_SHA256)
HMAC_HANDLER(dispatch_hmac_sha384,   FHSM_HASH_SHA384)
HMAC_HANDLER(dispatch_hmac_sha512,   FHSM_HASH_SHA512)
HMAC_HANDLER(dispatch_hmac_sha3_256, FHSM_HASH_SHA3_256)
HMAC_HANDLER(dispatch_hmac_sha3_384, FHSM_HASH_SHA3_384)
HMAC_HANDLER(dispatch_hmac_sha3_512, FHSM_HASH_SHA3_512)
