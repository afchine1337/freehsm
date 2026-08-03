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
 *  Each operation passes file paths to the CLI. Those files are anonymous
 *  memfd_create objects reached through /proc/self/fd/N, never files on a
 *  filesystem -- see the long comment at memfd_make for why (#109). There is
 *  consequently nothing to unlink and nothing left behind on failure.
 *
 *  Threading : tpm2-tools serializes access through the TPM resource
 *  manager (kernel), so concurrent calls into the hardware are safe. The
 *  earlier version of this comment went on to claim fhsm_token's per-token
 *  mutex covered the rest; it did not. Two threads sealing two *different*
 *  tokens hold two different mutexes, and the temp filenames were built from
 *  getpid() -- identical for both. Anonymous descriptors have no shared name,
 *  so there is no longer anything for that argument to have to be true about.
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
#include <sys/mman.h>

#include <openssl/crypto.h>   /* OPENSSL_cleanse */
#include <errno.h>

#define TPM_DIR        "/var/lib/freehsm/tpm"
#define TPM_PCR_LIST   "sha256:0,1,2,3,4,5,6,7"
#define TPM_PARENT_HANDLE "0x81010001"   /* persistent primary key */

/* ---------------------------------------------------------------------------
 * Test seam.
 *
 * Everything below funnels through two constants: the device node we probe to
 * decide a TPM exists, and the name of the CLI we exec. In production both are
 * fixed. Under -DFHSM_TPM_TEST_HOOKS -- set only by the test target, never by
 * the shipped library -- they can be redirected by environment variables so a
 * machine with no TPM can still exercise the plumbing.
 *
 * This is a compile-time seam on purpose. An environment variable that could
 * point the module at a fake TPM has no business existing in a binary an
 * operator deploys, however convenient it is here. `strings libfreehsm.so`
 * will not find FHSM_TPM_DEVICE in a normal build.
 *
 * What the seam buys is limited and worth stating: it exercises blob packing,
 * the memfd descriptor plumbing, and the error routing at login. It proves
 * nothing whatsoever about the TPM's own guarantees -- PCR binding, the
 * sealing crypto, tamper detection -- because on the other side of the seam
 * there is no TPM. Those need real hardware.
 * ----------------------------------------------------------------------- */
#ifdef FHSM_TPM_TEST_HOOKS
static const char *tpm_device(void) {
    const char *v = getenv("FHSM_TPM_DEVICE");
    return (v && v[0]) ? v : "/dev/tpmrm0";
}
static const char *tpm_cmd(void) {
    const char *v = getenv("FHSM_TPM_CMD");
    return (v && v[0]) ? v : "tpm2";
}
#else
static const char *tpm_device(void) { return "/dev/tpmrm0"; }
static const char *tpm_cmd(void)    { return "tpm2"; }
#endif

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
    if (access(tpm_device(), F_OK) != 0) {
        g_tpm_available = 0;
        return 0;
    }
    char probe[512];
    snprintf(probe, sizeof(probe), "%s startup -c", tpm_cmd());
    if (run_silent(probe) != 0) {
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
/* ---------------------------------------------------------------------------
 * Anonymous in-memory files (#109).
 *
 * These used to be mkstemp() files under TPM_DIR, which meant the DEK -- the
 * key the whole token hangs off -- was written to a filesystem in the clear so
 * the tpm2 CLI could read it, and written back in the clear by `tpm2 unseal
 * -o`. Mode 0600 and an unlink() afterwards do not undo that: on a journalling
 * filesystem or an SSD with wear levelling the bytes outlive the file. v1.6.0
 * had just moved that same DEK into an mlock'd arena so it could not reach
 * swap (#127); writing it to disk on the sealing path was strictly worse than
 * the paging we had gone to trouble to prevent.
 *
 * memfd_create gives a file that exists only in anonymous memory. The child
 * process inherits the descriptor (no CLOEXEC) and reaches it through
 * /proc/self/fd/N, so tpm2 reads and writes exactly as it did before while the
 * bytes never touch a filesystem.
 *
 * Non-secret material -- the sealed public and private blobs, which are
 * TPM-encrypted -- goes through the same path for uniformity: one mechanism is
 * easier to keep correct than two, and it removes the per-pid filenames that
 * collided between threads (#109, second finding).
 * ----------------------------------------------------------------------- */
typedef struct { int fd; char path[64]; } fhsm_memfd_t;

static void memfd_close(fhsm_memfd_t *m) {
    if (m && m->fd >= 0) { close(m->fd); m->fd = -1; m->path[0] = '\0'; }
}

/* Create an in-memory file, optionally filled with `data`. On failure fd is
 * -1 and path is empty, which every caller checks before use. */
static fhsm_rv_t memfd_make(fhsm_memfd_t *m, const char *name,
                             const void *data, size_t len) {
    m->fd = -1; m->path[0] = '\0';
    int fd = memfd_create(name, 0);          /* deliberately NOT MFD_CLOEXEC:
                                                the child must inherit it */
    if (fd < 0) return FHSM_RV_FUNCTION_FAILED;
    if (data && len) {
        ssize_t w = write(fd, data, len);
        if (w != (ssize_t)len) { close(fd); return FHSM_RV_FUNCTION_FAILED; }
        if (lseek(fd, 0, SEEK_SET) < 0) { close(fd); return FHSM_RV_FUNCTION_FAILED; }
    }
    m->fd = fd;
    snprintf(m->path, sizeof(m->path), "/proc/self/fd/%d", fd);
    return FHSM_RV_OK;
}

/* Read the whole contents of an in-memory file from offset 0. */
static fhsm_rv_t memfd_read(fhsm_memfd_t *m, uint8_t *out, size_t cap,
                             size_t *out_len) {
    if (!m || m->fd < 0) return FHSM_RV_FUNCTION_FAILED;
    if (lseek(m->fd, 0, SEEK_SET) < 0) return FHSM_RV_FUNCTION_FAILED;
    ssize_t n = read(m->fd, out, cap);
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

    /* Four in-memory files: the secret going in, the policy digest, and the
     * two halves of the sealed object coming out. None of them reaches a
     * filesystem, so there is nothing to unlink and nothing to leave behind
     * for post-mortem -- see the memfd comment above for why that matters
     * for `in`, and #109 for why it matters for the rest (the old pid-based
     * names collided between threads sealing different tokens). */
    fhsm_memfd_t in = {-1, {0}}, pol = {-1, {0}},
                 pub = {-1, {0}}, priv = {-1, {0}};
    fhsm_rv_t rv;

    rv = memfd_make(&in, "fhsm-seal-in", secret, 32);
    if (rv != FHSM_RV_OK) goto out;
    rv = memfd_make(&pol,  "fhsm-seal-policy", NULL, 0);
    if (rv != FHSM_RV_OK) goto out;
    rv = memfd_make(&pub,  "fhsm-seal-pub",  NULL, 0);
    if (rv != FHSM_RV_OK) goto out;
    rv = memfd_make(&priv, "fhsm-seal-priv", NULL, 0);
    if (rv != FHSM_RV_OK) goto out;

    /* Build the policy : seal under PCR 0-7. Then create the data object. */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "%s createpolicy --policy-pcr -l %s -L %s",
             tpm_cmd(), TPM_PCR_LIST, pol.path);
    if (run_silent(cmd) != 0) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }

    snprintf(cmd, sizeof(cmd),
             "%s create -C %s -i %s -u %s -r %s -L %s -g sha256",
             tpm_cmd(), TPM_PARENT_HANDLE, in.path, pub.path, priv.path, pol.path);
    if (run_silent(cmd) != 0) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }

    /* Read back pub + priv and pack. */
    uint8_t pub_buf[512], priv_buf[512];
    size_t pub_len = 0, priv_len = 0;
    if (memfd_read(&pub,  pub_buf,  sizeof(pub_buf),  &pub_len)  != FHSM_RV_OK ||
        memfd_read(&priv, priv_buf, sizeof(priv_buf), &priv_len) != FHSM_RV_OK) {
        rv = FHSM_RV_FUNCTION_FAILED; goto out;
    }
    if (pub_len == 0 || priv_len == 0) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }

    size_t total = 12 + pub_len + priv_len;
    if (total > out_cap) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }
    memcpy(out_blob, "TPS1", 4);
    out_blob[4] = (uint8_t)(pub_len);        out_blob[5] = (uint8_t)(pub_len  >> 8);
    out_blob[6] = (uint8_t)(pub_len  >> 16); out_blob[7] = (uint8_t)(pub_len  >> 24);
    out_blob[8] = (uint8_t)(priv_len);       out_blob[9] = (uint8_t)(priv_len >> 8);
    out_blob[10] = (uint8_t)(priv_len >> 16); out_blob[11] = (uint8_t)(priv_len >> 24);
    memcpy(out_blob + 12, pub_buf, pub_len);
    memcpy(out_blob + 12 + pub_len, priv_buf, priv_len);
    *out_len = total;
    rv = FHSM_RV_OK;

out:
    memfd_close(&in); memfd_close(&pol);
    memfd_close(&pub); memfd_close(&priv);
    return rv;
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

    /* `out` receives the unsealed DEK. It is the reason this function exists
     * and the reason it must not be a file on disk: `tpm2 unseal -o` writes
     * whatever the TPM released, in the clear, wherever we point it. */
    fhsm_memfd_t pub = {-1, {0}}, priv = {-1, {0}},
                 pol = {-1, {0}}, ctx = {-1, {0}}, out = {-1, {0}};
    fhsm_rv_t rv;

    /* Zero the caller's buffer up front rather than on the one failure path
     * that used to do it. There are five ways out of this function that are
     * not success -- a failed memfd, three failed subcommands, a short read --
     * and on any of them the caller must be left holding zeros, not whatever
     * was on its stack. Clearing once at the top covers all of them and
     * cannot be forgotten when a sixth is added. */
    OPENSSL_cleanse(out_secret, 32);

    rv = memfd_make(&pub,  "fhsm-unseal-pub",  blob + 12, pub_len);
    if (rv != FHSM_RV_OK) goto done;
    rv = memfd_make(&priv, "fhsm-unseal-priv", blob + 12 + pub_len, priv_len);
    if (rv != FHSM_RV_OK) goto done;
    rv = memfd_make(&pol,  "fhsm-unseal-policy", NULL, 0);
    if (rv != FHSM_RV_OK) goto done;
    rv = memfd_make(&ctx,  "fhsm-unseal-ctx",    NULL, 0);
    if (rv != FHSM_RV_OK) goto done;
    rv = memfd_make(&out,  "fhsm-unseal-out",    NULL, 0);
    if (rv != FHSM_RV_OK) goto done;

    /* Re-derive the policy and load + unseal. */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "%s createpolicy --policy-pcr -l %s -L %s",
             tpm_cmd(), TPM_PCR_LIST, pol.path);
    if (run_silent(cmd) != 0) { rv = FHSM_RV_FUNCTION_FAILED; goto done; }

    snprintf(cmd, sizeof(cmd),
             "%s load -C %s -u %s -r %s -c %s",
             tpm_cmd(), TPM_PARENT_HANDLE, pub.path, priv.path, ctx.path);
    if (run_silent(cmd) != 0) { rv = FHSM_RV_FUNCTION_FAILED; goto done; }

    snprintf(cmd, sizeof(cmd),
             "%s unseal -c %s -p pcr:%s -o %s",
             tpm_cmd(), ctx.path, TPM_PCR_LIST, out.path);
    if (run_silent(cmd) != 0) { rv = FHSM_RV_FUNCTION_FAILED; goto done; }

    size_t got = 0;
    if (memfd_read(&out, out_secret, 32, &got) != FHSM_RV_OK || got != 32) {
        OPENSSL_cleanse(out_secret, 32);   /* never hand back a partial DEK */
        rv = FHSM_RV_FUNCTION_FAILED; goto done;
    }
    rv = FHSM_RV_OK;

done:
    memfd_close(&pub); memfd_close(&priv);
    memfd_close(&pol); memfd_close(&ctx); memfd_close(&out);
    return rv;
}
