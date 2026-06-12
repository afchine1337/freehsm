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
 * fhsm_token_tpm.c --- TPM 2.0 sealing companion file for token DEK.
 *
 *  Companion-file approach :
 *
 *    /var/lib/freehsm/slot0.tok          (existing format, PBKDF2 wrap)
 *    /var/lib/freehsm/slot0.tok.tpm      (new : TPM-sealed DEK blob)
 *
 *  Token init :
 *    1. Generate DEK as usual.
 *    2. PBKDF2-wrap the DEK under SO PIN (existing logic).
 *    3. If FHSM_TPM_SEALING=1 in the environment AND a TPM is available,
 *       seal the DEK to the TPM, write the blob to {path}.tpm.
 *    4. If TPM activation is requested but TPM is missing, FAIL HARD so
 *       the operator notices.
 *
 *  Token login :
 *    1. PBKDF2-unwrap the DEK (existing logic).
 *    2. If {path}.tpm exists, unseal the TPM blob.
 *    3. Constant-time compare the two DEKs. Mismatch → FHSM_RV_PIN_INCORRECT
 *       (we deliberately do not distinguish from a wrong-PIN scenario so
 *       an attacker cannot probe whether the TPM is online).
 *    4. If {path}.tpm exists but TPM is unavailable, FAIL CLOSED.
 *
 *  Rationale : zero changes to the .tok binary format means full
 *  forward / backward compatibility. Operators can opt in and out
 *  per-token without re-keying anything.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_tpm.h"
#include "fhsm_token_tpm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Return 1 if the operator requested TPM sealing for this token. */
int fhsm_token_tpm_required(void) {
    const char *v = getenv("FHSM_TPM_SEALING");
    if (!v) return 0;
    return (v[0] == '1' || v[0] == 'y' || v[0] == 'Y');
}

/* Build the companion-file path : append ".tpm" to the token path. */
static int build_tpm_path(const char *tok_path, char *out, size_t cap) {
    if (snprintf(out, cap, "%s.tpm", tok_path) >= (int)cap) return 0;
    return 1;
}

/* Seal a DEK to the TPM and persist to {path}.tpm. */
fhsm_rv_t fhsm_token_tpm_seal(const char *tok_path, const uint8_t dek[32]) {
    if (!fhsm_tpm_available()) return FHSM_RV_TPM_UNAVAILABLE;

    char tpm_path[1024];
    if (!build_tpm_path(tok_path, tpm_path, sizeof(tpm_path)))
        return FHSM_RV_ARGUMENTS_BAD;

    uint8_t blob[2048];
    size_t  blob_len = 0;
    fhsm_rv_t rv = fhsm_tpm_seal(dek, blob, sizeof(blob), &blob_len);
    if (rv != FHSM_RV_OK) return rv;

    /* Write atomically via temp+rename so a power loss can never leave
     * the file half-written. */
    char tmp_path[1024];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.new", tpm_path) >= (int)sizeof(tmp_path)) {
        fhsm_zeroize(blob, sizeof(blob));
        return FHSM_RV_FUNCTION_FAILED;
    }
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        fhsm_zeroize(blob, sizeof(blob));
        return FHSM_RV_FUNCTION_FAILED;
    }
    ssize_t w = write(fd, blob, blob_len);
    close(fd);
    fhsm_zeroize(blob, sizeof(blob));
    if (w != (ssize_t)blob_len) {
        unlink(tmp_path);
        return FHSM_RV_FUNCTION_FAILED;
    }
    if (rename(tmp_path, tpm_path) != 0) {
        unlink(tmp_path);
        return FHSM_RV_FUNCTION_FAILED;
    }
    return FHSM_RV_OK;
}

/* Return 1 if a {path}.tpm companion file exists. */
int fhsm_token_tpm_blob_exists(const char *tok_path) {
    char tpm_path[1024];
    if (!build_tpm_path(tok_path, tpm_path, sizeof(tpm_path))) return 0;
    return (access(tpm_path, R_OK) == 0);
}

/* Read the companion file, unseal via TPM, return the 32-byte DEK. */
fhsm_rv_t fhsm_token_tpm_unseal(const char *tok_path, uint8_t dek_out[32]) {
    if (!fhsm_tpm_available()) return FHSM_RV_TPM_UNAVAILABLE;

    char tpm_path[1024];
    if (!build_tpm_path(tok_path, tpm_path, sizeof(tpm_path)))
        return FHSM_RV_ARGUMENTS_BAD;

    int fd = open(tpm_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return FHSM_RV_FUNCTION_FAILED;
    uint8_t blob[2048];
    ssize_t n = read(fd, blob, sizeof(blob));
    close(fd);
    if (n <= 0) { fhsm_zeroize(blob, sizeof(blob)); return FHSM_RV_FUNCTION_FAILED; }

    fhsm_rv_t rv = fhsm_tpm_unseal(blob, (size_t)n, dek_out);
    fhsm_zeroize(blob, sizeof(blob));
    return rv;
}

/* Constant-time DEK comparison helper exposed to fhsm_token.c. */
int fhsm_token_tpm_dek_match(const uint8_t a[32], const uint8_t b[32]) {
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* Remove the companion file --- used during reinit. */
void fhsm_token_tpm_unlink(const char *tok_path) {
    char tpm_path[1024];
    if (!build_tpm_path(tok_path, tpm_path, sizeof(tpm_path))) return;
    (void)unlink(tpm_path);
}
