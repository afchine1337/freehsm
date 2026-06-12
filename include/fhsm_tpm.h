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
 * fhsm_tpm.h --- TPM 2.0 sealing layer for the token DEK.
 *
 *  Adds a second wrapping layer over the per-token DEK :
 *
 *    DEK plaintext (32 B) ──PBKDF2(SO_PIN)+AES-GCM──> primary wrap
 *                          ──TPM2_Create+Seal────────> sealed blob
 *                          stored alongside slot{N}.tok
 *
 *  Reading the token requires BOTH the SO/USER PIN (to unwrap PBKDF2)
 *  AND the TPM (to unseal). An attacker who copies the .tok file but
 *  cannot reproduce the TPM's identity (typically bound to PCR 0-7 +
 *  EK + a stable Owner password) cannot recover the DEK even if they
 *  know the PIN.
 *
 *  Sealing policy (default in fhsm_tpm_seal) :
 *    --- Bound to PCRs 0..7 (firmware + bootloader + kernel + initrd)
 *    --- Persistent key handle 0x81010001 (configurable in conf)
 *    --- Algorithm : RSA-2048 / AES-128-CFB (TCG-default)
 *
 *  Implementation : subprocess invocation of the tpm2-tools utilities
 *  rather than direct libtss2 binding. Trade-off : an extra spawn per
 *  seal/unseal (~50ms) but the implementation surface is minuscule
 *  and avoids the tpm2-tss API churn.
 *
 *  Requires : `apt install tpm2-tools libtpm2-pkcs11-tools` and a
 *  functioning /dev/tpmrm0 (kernel resource manager).
 * ========================================================================= */

#ifndef FHSM_TPM_H
#define FHSM_TPM_H

#include "fhsm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Test whether the host has a usable TPM 2.0. Returns 1 if `tpm2 startup`
 * succeeds and the resource manager is responsive, 0 otherwise. Cached
 * after first call. Used by fhsm_token to decide whether sealing is
 * available at the current boot. */
int fhsm_tpm_available(void);

/* Seal a 32-byte secret to the TPM. Output is written to `out_blob`
 * (caller-provided buffer of size out_cap ≥ 512 bytes typical) and the
 * final size returned in *out_len.
 *
 * The PCR selection used by default is "sha256:0,1,2,3,4,5,6,7" which
 * matches the standard secure-boot chain on x86_64. Override via the
 * FHSM_TPM_PCRS environment variable (comma-separated PCR indices).
 *
 * Returns FHSM_RV_OK on success ; FHSM_RV_TPM_UNAVAILABLE if no TPM ;
 * FHSM_RV_FUNCTION_FAILED on tpm2 subprocess error. */
fhsm_rv_t fhsm_tpm_seal(const uint8_t secret[32],
                         uint8_t *out_blob, size_t out_cap,
                         size_t *out_len);

/* Unseal a previously sealed blob. Returns the 32-byte secret in
 * `out_secret`. The TPM will refuse to unseal if the bound PCRs have
 * changed since seal time (i.e. if the boot chain was tampered with).
 *
 * Returns FHSM_RV_OK on success ; FHSM_RV_TPM_UNAVAILABLE if no TPM ;
 * FHSM_RV_FUNCTION_FAILED on tpm2 subprocess error (most likely policy
 * mismatch). */
fhsm_rv_t fhsm_tpm_unseal(const uint8_t *blob, size_t blob_len,
                           uint8_t out_secret[32]);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_TPM_H */
