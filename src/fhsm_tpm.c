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
 * fhsm_tpm.c --- TPM 2.0 sealing via tpm2-tools subprocess invocations.
 *
 *  Implementation uses fork+exec of the tpm2 CLI rather than direct
 *  linkage to libtss2 because :
 *    1. The libtss2 API has had multiple breaking changes (esys, fapi)
 *       and pinning to one version is brittle.
 *    2. tpm2-tools is a Debian-supported package with a stable CLI.
 *    3. The subprocess overhead (~50 ms per seal/unseal) is negligible
 *       compared to PBKDF2 (200 000 iterations ≈ 100 ms).
 *
 *  Each operation writes / reads a temporary file under
 *  /var/lib/freehsm/tpm/ (mode 700, owner freehsm). Files are unlinked
 *  on success. On failure the files are kept for post-mortem.
 *
 *  Threading : tpm2-tools serializes access through the TPM resource
 *  manager (kernel) ; concurrent calls from multiple threads are
 *  globally serialized. fhsm_token holds the per-token mutex around
 *  TPM ops so no additional serialization is needed here.
 *
 *  Security note : the sealed blob is integrity-protected by the TPM ;
 *  any tampering will be detected at unseal time. We do NOT add
 *  additional MAC over the blob.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_tpm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#define TPM_DIR        "/var/lib/freehsm/tpm"
#define TPM_PCR_LIST   "sha256:0,1,2,3,4,5,6,7"
#define TPM_PARENT_HANDLE "0x81010001"   /* persistent primary key */

/* ---------------------------------------------------------------------------
 * Run a shell command, return its exit code. Output captured to
 * /dev/null. Used to test for tpm2 availability and to perform the
 * actual seal/unseal pipeline.
 * ----------------------------------------------------------------------- */
static int run_silent(const char *cmd) {
    /* Callers pass a `cmd` of up to 2048 bytes (see TPM_DIR-based
     * snprintf calls below). Size `wrapped` with headroom for the
     * " >/dev/null 2>&1" suffix so GCC fortify is silent. */
    char wrapped[2560];
    snprintf(wrapped, sizeof(wrapped),
             "%s >/dev/null 2>&1", cmd);
    int rc = system(wrapped);
    if (rc == -1) return -1;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

/* ---------------------------------------------------------------------------
 * Availability check. Cached after first call (only one TPM per host).
 * ----------------------------------------------------------------------- */
static int g_tpm_available = -1;   /* -1 = unknown, 0 = no, 1 = yes */

int fhsm_tpm_available(void) {
    if (g_tpm_available != -1) return g_tpm_available;

    /* `tpm2 startup -c` is the standard probe. Returns 0 if a TPM is
     * accessible (with the resource manager). */
    if (access("/dev/tpmrm0", F_OK) != 0) {
        g_tpm_available = 0;
        return 0;
    }
    if (run_silent("tpm2 startup -c") != 0) {
        g_tpm_available = 0;
        return 0;
    }
    /* Ensure the working dir exists. */
    mkdir(TPM_DIR, 0700);
    g_tpm_available = 1;
    return 1;
}

/* ---------------------------------------------------------------------------
 * Helper : write `data` to a temp file under TPM_DIR. Returns the
 * filename in `path_out` (must be at least PATH_MAX bytes). On error
 * `path_out` is set to "".
 * ----------------------------------------------------------------------- */
static fhsm_rv_t write_temp(const char *prefix, const void *data, size_t len,
                              char *path_out, size_t path_cap) {
    snprintf(path_out, path_cap, "%s/%s-XXXXXX", TPM_DIR, prefix);
    int fd = mkstemp(path_out);
    if (fd < 0) { path_out[0] = '\0'; return FHSM_RV_FUNCTION_FAILED; }
    fchmod(fd, 0600);
    ssize_t w = write(fd, data, len);
    close(fd);
    if (w != (ssize_t)len) {
        unlink(path_out); path_out[0] = '\0';
        return FHSM_RV_FUNCTION_FAILED;
    }
    return FHSM_RV_OK;
}

static fhsm_rv_t read_file(const char *path, uint8_t *out, size_t cap,
                            size_t *out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return FHSM_RV_FUNCTION_FAILED;
    ssize_t n = read(fd, out, cap);
    close(fd);
    if (n < 0) return FHSM_RV_FUNCTION_FAILED;
    *out_len = (size_t)n;
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * Seal the 32-byte secret. The output blob is the concatenation of
 * `tpm2 create -C ... -i secret -u pub -r priv` outputs, with a small
 * header indicating their lengths.
 *
 *  Blob layout :
 *    [0..3]    : magic "TPS1" (TPM Seal v1)
 *    [4..7]    : uint32 LE pub_len
 *    [8..11]   : uint32 LE priv_len
 *    [12..]    : pub bytes
 *    [12+pub..]: priv bytes
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_tpm_seal(const uint8_t secret[32],
                         uint8_t *out_blob, size_t out_cap,
                         size_t *out_len) {
    if (!fhsm_tpm_available()) return FHSM_RV_TPM_UNAVAILABLE;
    if (!secret || !out_blob || !out_len) return FHSM_RV_ARGUMENTS_BAD;

    char in_path[256], pub_path[256], priv_path[256];
    fhsm_rv_t rv = write_temp("seal-in", secret, 32, in_path, sizeof(in_path));
    if (rv != FHSM_RV_OK) return rv;
    snprintf(pub_path,  sizeof(pub_path),  "%s/seal-pub-%d",  TPM_DIR, getpid());
    snprintf(priv_path, sizeof(priv_path), "%s/seal-priv-%d", TPM_DIR, getpid());

    /* Build the policy : seal under PCR 0-7. Then create the data object. */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "tpm2 createpolicy --policy-pcr -l %s -L %s/policy-%d.dat",
             TPM_PCR_LIST, TPM_DIR, getpid());
    if (run_silent(cmd) != 0) goto fail;

    snprintf(cmd, sizeof(cmd),
             "tpm2 create -C %s -i %s -u %s -r %s -L %s/policy-%d.dat -g sha256",
             TPM_PARENT_HANDLE, in_path, pub_path, priv_path,
             TPM_DIR, getpid());
    if (run_silent(cmd) != 0) goto fail;

    /* Read back pub + priv and pack. */
    uint8_t pub_buf[512], priv_buf[512];
    size_t pub_len = 0, priv_len = 0;
    if (read_file(pub_path,  pub_buf,  sizeof(pub_buf),  &pub_len)  != FHSM_RV_OK) goto fail;
    if (read_file(priv_path, priv_buf, sizeof(priv_buf), &priv_len) != FHSM_RV_OK) goto fail;

    size_t total = 12 + pub_len + priv_len;
    if (total > out_cap) { rv = FHSM_RV_FUNCTION_FAILED; goto fail; }
    memcpy(out_blob, "TPS1", 4);
    out_blob[4] = (uint8_t)(pub_len);        out_blob[5] = (uint8_t)(pub_len  >> 8);
    out_blob[6] = (uint8_t)(pub_len  >> 16); out_blob[7] = (uint8_t)(pub_len  >> 24);
    out_blob[8] = (uint8_t)(priv_len);       out_blob[9] = (uint8_t)(priv_len >> 8);
    out_blob[10] = (uint8_t)(priv_len >> 16); out_blob[11] = (uint8_t)(priv_len >> 24);
    memcpy(out_blob + 12, pub_buf, pub_len);
    memcpy(out_blob + 12 + pub_len, priv_buf, priv_len);
    *out_len = total;

    unlink(in_path); unlink(pub_path); unlink(priv_path);
    return FHSM_RV_OK;

fail:
    if (in_path[0])   unlink(in_path);
    if (pub_path[0])  unlink(pub_path);
    if (priv_path[0]) unlink(priv_path);
    return rv != FHSM_RV_OK ? rv : FHSM_RV_FUNCTION_FAILED;
}

fhsm_rv_t fhsm_tpm_unseal(const uint8_t *blob, size_t blob_len,
                           uint8_t out_secret[32]) {
    if (!fhsm_tpm_available()) return FHSM_RV_TPM_UNAVAILABLE;
    if (!blob || blob_len < 12 || !out_secret) return FHSM_RV_ARGUMENTS_BAD;
    if (memcmp(blob, "TPS1", 4) != 0) return FHSM_RV_FUNCTION_FAILED;

    size_t pub_len  = (size_t)blob[4]  | ((size_t)blob[5]  << 8)
                     | ((size_t)blob[6]  << 16) | ((size_t)blob[7]  << 24);
    size_t priv_len = (size_t)blob[8]  | ((size_t)blob[9]  << 8)
                     | ((size_t)blob[10] << 16) | ((size_t)blob[11] << 24);
    if (12 + pub_len + priv_len != blob_len) return FHSM_RV_FUNCTION_FAILED;

    char pub_path[256], priv_path[256], out_path[256];
    fhsm_rv_t rv = write_temp("unseal-pub", blob + 12, pub_len,
                                pub_path, sizeof(pub_path));
    if (rv != FHSM_RV_OK) return rv;
    rv = write_temp("unseal-priv", blob + 12 + pub_len, priv_len,
                     priv_path, sizeof(priv_path));
    if (rv != FHSM_RV_OK) { unlink(pub_path); return rv; }
    snprintf(out_path, sizeof(out_path), "%s/unseal-out-%d", TPM_DIR, getpid());

    /* Re-derive the policy and load + unseal. */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "tpm2 createpolicy --policy-pcr -l %s -L %s/policy-u-%d.dat",
             TPM_PCR_LIST, TPM_DIR, getpid());
    if (run_silent(cmd) != 0) goto fail;

    snprintf(cmd, sizeof(cmd),
             "tpm2 load -C %s -u %s -r %s -c %s/loaded-%d.ctx",
             TPM_PARENT_HANDLE, pub_path, priv_path, TPM_DIR, getpid());
    if (run_silent(cmd) != 0) goto fail;

    snprintf(cmd, sizeof(cmd),
             "tpm2 unseal -c %s/loaded-%d.ctx -p pcr:%s -o %s",
             TPM_DIR, getpid(), TPM_PCR_LIST, out_path);
    if (run_silent(cmd) != 0) goto fail;

    size_t got = 0;
    if (read_file(out_path, out_secret, 32, &got) != FHSM_RV_OK
        || got != 32) goto fail;

    unlink(pub_path); unlink(priv_path); unlink(out_path);
    return FHSM_RV_OK;

fail:
    if (pub_path[0])  unlink(pub_path);
    if (priv_path[0]) unlink(priv_path);
    if (out_path[0])  unlink(out_path);
    return FHSM_RV_FUNCTION_FAILED;
}
