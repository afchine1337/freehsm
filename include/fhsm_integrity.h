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
 * fhsm_integrity.h --- Module integrity self-test (FIPS 140-3 §7.10.2).
 *
 *  The cryptographic module performs an integrity check before any
 *  approved service is exposed to callers. The check is required by
 *  FIPS 140-3 §7.10.2 ("pre-operational integrity test"). It also
 *  serves as evidence for CC EAL4+ FPT_TST.1 (TSF testing).
 *
 *  Mechanism :
 *    1. At build time, `scripts/sign_module.sh` computes SHA-256 of
 *       the final libfreehsm-fips.so with the bytes inside the
 *       dedicated ELF section `.fhsm_digest` set to zero.
 *    2. The script patches the resulting 32-byte digest into that
 *       same section, so the shipped .so contains its own digest at
 *       a stable, easily locatable offset.
 *    3. At runtime, `fhsm_integrity_verify()` :
 *         - locates its own .so via dl_iterate_phdr (no /proc/self/exe
 *           dependency to remain portable across containerized envs),
 *         - mmaps the file read-only,
 *         - zeroizes the same .fhsm_digest section in the in-memory
 *           copy (NOT on disk),
 *         - computes SHA-256 of the resulting bytes,
 *         - constant-time compares against the digest embedded in
 *           `fhsm_module_integrity_digest[]`.
 *    4. Mismatch latches FHSM_STATE_ERROR (irrecoverable until restart).
 *
 *  The "zero the digest area before hashing" pattern is the standard
 *  approach used by OpenSSL's FIPS provider integrity check, by Linux
 *  kernel module signing (mod_check_sig), and by most CMVP-certified
 *  modules. It avoids the chicken-and-egg problem of including the
 *  digest in its own input.
 * ========================================================================= */

#ifndef FHSM_INTEGRITY_H
#define FHSM_INTEGRITY_H

#include "fhsm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The expected digest, embedded in the .fhsm_digest section. Filled
 * by scripts/sign_module.sh after the .so is built. Until the script
 * runs, the section contains all zeros, which fhsm_integrity_verify()
 * detects as "unsigned build" and rejects in shipping mode (and
 * accepts in development mode under FHSM_INTEGRITY_ALLOW_UNSIGNED).
 *
 * Declared in fhsm_integrity.c with __attribute__((section(".fhsm_digest"))). */
extern const uint8_t fhsm_module_integrity_digest[32];

/* Size of the trailing section, used by the verifier to skip the
 * digest bytes when re-computing the hash. Build-time constant. */
#define FHSM_INTEGRITY_DIGEST_LEN  32

/* Section name --- used by both the linker map and the sign script. */
#define FHSM_INTEGRITY_SECTION     ".fhsm_digest"

/* ---------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

/* Run the integrity check. Returns :
 *   FHSM_RV_OK              digest matches
 *   FHSM_RV_INTEGRITY_FAILED digest mismatch (also latches ERROR state)
 *   FHSM_RV_FUNCTION_FAILED unable to read self (rare ; treat as fatal)
 *
 * Called from fhsm_crypto_init() before any KAT runs. Idempotent and
 * thread-safe (the pthread_once gate is internal). */
fhsm_rv_t fhsm_integrity_verify(void);

/* Read-only accessor : tells whether the module was signed. The .fhsm_digest
 * section is set to all-zero in unsigned development builds. Used by the
 * audit emit to tag the boot event ("signed_build": true/false). */
int fhsm_integrity_is_signed(void);

/* Diagnostic : return the digest that was *just computed* on the last
 * verify call. Useful to debug a signing pipeline that fails. The
 * returned pointer references static storage and is valid until the
 * next verify call. Length is always FHSM_INTEGRITY_DIGEST_LEN. */
const uint8_t *fhsm_integrity_last_computed(void);

/* Path of the .so the verifier loaded. Static-string, never NULL after
 * fhsm_integrity_verify() has been called once. */
const char *fhsm_integrity_so_path(void);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_INTEGRITY_H */
