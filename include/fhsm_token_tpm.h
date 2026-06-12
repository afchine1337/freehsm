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
 * fhsm_token_tpm.h --- Glue between fhsm_token and fhsm_tpm.
 *
 *  TPM sealing of the per-token DEK is opt-in via the environment
 *  variable FHSM_TPM_SEALING=1. When activated :
 *
 *    - fhsm_token_init writes the DEK to a {path}.tpm companion file
 *      via TPM seal in addition to the normal PBKDF2 wrap.
 *    - fhsm_token_login compares the PBKDF2-unwrapped DEK against the
 *      TPM-unsealed DEK ; mismatch is treated as wrong PIN (so an
 *      attacker cannot probe TPM presence).
 *
 *  Companion-file approach (zero changes to the .tok binary format)
 *  keeps the implementation forward/backward compatible.
 * ========================================================================= */

#ifndef FHSM_TOKEN_TPM_H
#define FHSM_TOKEN_TPM_H

#include "fhsm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 1 if FHSM_TPM_SEALING=1 (or y/Y) is set in the environment. */
int       fhsm_token_tpm_required(void);

/* Returns 1 if {tok_path}.tpm exists and is readable. */
int       fhsm_token_tpm_blob_exists(const char *tok_path);

/* Seal `dek` (32 bytes) to the TPM and persist to {tok_path}.tpm.
 * Returns FHSM_RV_TPM_UNAVAILABLE if no TPM. */
fhsm_rv_t fhsm_token_tpm_seal(const char *tok_path, const uint8_t dek[32]);

/* Read {tok_path}.tpm, unseal via TPM, return DEK in dek_out. */
fhsm_rv_t fhsm_token_tpm_unseal(const char *tok_path, uint8_t dek_out[32]);

/* Constant-time 32-byte compare. Returns 1 if equal, 0 otherwise. */
int       fhsm_token_tpm_dek_match(const uint8_t a[32], const uint8_t b[32]);

/* Best-effort unlink of the companion file (used during reinit). */
void      fhsm_token_tpm_unlink(const char *tok_path);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_TOKEN_TPM_H */
