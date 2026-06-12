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
 * fhsm_pairwise.h --- Pair-wise consistency check (FIPS 140-3 §7.10.2.b).
 *
 *  After a successful C_GenerateKeyPair, the module MUST verify that
 *  the public and private halves of the freshly-generated keypair are
 *  mathematically consistent. Failure to do so leaves the module
 *  vulnerable to silent keygen corruption (e.g. RAM bit-flips, faulty
 *  RNG, OpenSSL bug). The check exercises the SAME primitive that the
 *  application will eventually use :
 *
 *    RSA      : encrypt a fixed plaintext under pub, decrypt under priv,
 *               compare.
 *    EC       : sign a fixed digest under priv, verify with pub.
 *    ML-DSA   : sign a fixed message, verify (deterministic signature
 *               not assumed --- verify is the real check).
 *    SLH-DSA  : same as ML-DSA.
 *    ML-KEM   : encapsulate, decapsulate, compare the shared secret.
 *
 *  The check runs in ~5 ms on a modern CPU for RSA-2048, sub-ms for EC,
 *  ~3 ms for ML-DSA-65, and ~50 ms for SLH-DSA-128s. The cost is paid
 *  ONCE per keygen and is acceptable for a CC EAL4+ / FIPS 140-3 module.
 *
 *  On failure : the function returns FHSM_RV_FUNCTION_FAILED and the
 *  caller MUST NOT store the keypair in the token. The module SHOULD
 *  also enter the FHSM_STATE_ERROR state because a failed pair-wise
 *  check indicates a hardware or OpenSSL fault.
 * ========================================================================= */

#ifndef FHSM_PAIRWISE_H
#define FHSM_PAIRWISE_H

#include "fhsm_common.h"

/* Forward declaration to avoid pulling all of OpenSSL into every TU. */
typedef struct evp_pkey_st EVP_PKEY;

#ifdef __cplusplus
extern "C" {
#endif

/* Family selector. Matches the ckk_type used by C_GenerateKeyPair. */
typedef enum {
    FHSM_PAIRWISE_RSA      = 1,
    FHSM_PAIRWISE_EC       = 2,
    FHSM_PAIRWISE_ML_KEM   = 3,
    FHSM_PAIRWISE_ML_DSA   = 4,
    FHSM_PAIRWISE_SLH_DSA  = 5,
} fhsm_pairwise_family_t;

/* Run the pair-wise consistency check on `pkey` (which must contain
 * BOTH the public and private parts, as returned by EVP_PKEY_Q_keygen).
 *
 * Returns FHSM_RV_OK if the check passes ;
 *         FHSM_RV_FUNCTION_FAILED otherwise (and module SHOULD enter
 *         error state). */
fhsm_rv_t fhsm_pairwise_check(EVP_PKEY *pkey, fhsm_pairwise_family_t family);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_PAIRWISE_H */
