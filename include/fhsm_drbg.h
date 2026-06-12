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
 * fhsm_drbg.h --- Hardened DRBG front-end for FreeHSM C.
 *
 * Wraps OpenSSL's FIPS-validated CTR_DRBG-AES-256 with :
 *   - Multi-source entropy seed (getrandom + RDRAND + /dev/urandom +
 *     CPU TSC jitter), SHA-256 conditioned per SP 800-90C.
 *   - NIST SP 800-90B health tests on every byte produced :
 *       * RCT : Repetition Count Test (cutoff C=6 for H=8, α=2^-40)
 *       * APT : Adaptive Proportion Test (W=512, C=51, α=2^-40)
 *   - Continuous test (CRNGT) : compare 16-byte blocks across calls.
 *   - Auto-reseed every 1,000,000 bytes OR every 3600 seconds, whichever
 *     comes first (SP 800-90A §10.2.1.5 conservative interpretation).
 *
 * On any health-test failure the module is latched into ERROR state
 * and every subsequent fhsm_rng_bytes call returns FHSM_RV_RNG_FAILURE.
 * This is intentional --- a failed DRBG is a Category 1 incident and
 * the operator MUST restart the service after diagnostics.
 *
 * Thread-safety : all state is guarded by a pthread mutex (fhsm_drbg_mtx).
 * ========================================================================= */

#ifndef FHSM_DRBG_H
#define FHSM_DRBG_H

#include "fhsm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise the hardened DRBG layer. Called from fhsm_crypto_init
 * after the FIPS provider has been loaded. */
fhsm_rv_t fhsm_drbg_init(void);

/* Public output entry point. Replaces the body of fhsm_rng_bytes in
 * production. Runs the multi-source seed if it has expired, fetches
 * bytes from RAND_bytes, runs RCT+APT+CRNGT on the output. */
fhsm_rv_t fhsm_drbg_bytes(uint8_t *out, size_t n);

/* Force a reseed from all entropy sources. Useful after fork() or
 * after a long idle period. Returns FHSM_RV_OK if at least one source
 * yielded entropy, FHSM_RV_RNG_FAILURE otherwise. */
fhsm_rv_t fhsm_drbg_reseed(void);

/* Health report (for /proc-style introspection) :
 *   bytes_emitted : total bytes returned to callers since init
 *   reseeds       : number of reseed events
 *   rct_failures  : number of RCT alarms (always 0 unless ERROR)
 *   apt_failures  : same for APT
 *   crngt_failures: same for CRNGT */
typedef struct fhsm_drbg_stats_s {
    uint64_t bytes_emitted;
    uint32_t reseeds;
    uint32_t rct_failures;
    uint32_t apt_failures;
    uint32_t crngt_failures;
    uint32_t entropy_sources_active;  /* bitmask : 1=getrandom, 2=RDRAND, 4=/dev/urandom, 8=TSC */
} fhsm_drbg_stats_t;

void fhsm_drbg_get_stats(fhsm_drbg_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_DRBG_H */
