/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * fhsm_audit_key_provision() --- the key that chains the audit log.
 *
 * Scope, stated so nobody reads more into a green run than is there: this
 * covers the file-backed path, which is the default and what every host
 * without FHSM_TPM_SEALING will use. The sealed path goes through
 * fhsm_tpm_seal/unseal, which tests/test_tpm.c already exercises against
 * tests/tpm2-stub.sh through the -DFHSM_TPM_TEST_HOOKS seam -- and that stub
 * performs no cryptography, so it says nothing about PCR binding either.
 *
 * What is being checked is the part that is ours: which file, with which
 * permissions, what happens on the second call, and what happens when the
 * file on disk is not what it should be.
 */
#include "fhsm_audit.h"
#include "fhsm_common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

static char g_dir[] = "/tmp/fhsm-audit-key-XXXXXX";
static char g_key[512];

static void kill_key(void) { unlink(g_key); }

int main(void)
{
    printf("Audit log chaining key\n\n");

    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 2; }
    snprintf(g_key, sizeof g_key, "%s/audit.key", g_dir);

    uint8_t a[32], b[32];
    int sealed = -1;

    /* --- first use: the key is created ---------------------------------- */
    memset(a, 0, sizeof a);
    fhsm_rv_t rv = fhsm_audit_key_provision(g_dir, a, &sealed);
    ok(rv == FHSM_RV_OK, "the first provisioning succeeds");
    ok(sealed == 0, "  and reports the key is not sealed (no TPM here)");

    {
        int nonzero = 0;
        for (size_t i = 0; i < sizeof a; i++) if (a[i]) nonzero = 1;
        ok(nonzero, "  the key is not all zeroes");
    }

    struct stat st;
    ok(stat(g_key, &st) == 0 && st.st_size == 32,
       "  audit.key exists and is 32 bytes");
    ok((st.st_mode & (S_IRWXG | S_IRWXO)) == 0,
       "  and is readable by nobody but its owner");

    /* --- second call: the same key, or the chain breaks at the next start
     *     and every earlier record becomes unverifiable ------------------- */
    memset(b, 0, sizeof b);
    rv = fhsm_audit_key_provision(g_dir, b, &sealed);
    ok(rv == FHSM_RV_OK && memcmp(a, b, 32) == 0,
       "a second call returns exactly the same key");

    /* --- two provisionings in two different directories must give two
     *     different keys -------------------------------------------------- */
    {
        char other[] = "/tmp/fhsm-audit-key2-XXXXXX";
        uint8_t c[32];
        if (mkdtemp(other)) {
            rv = fhsm_audit_key_provision(other, c, NULL);
            ok(rv == FHSM_RV_OK && memcmp(a, c, 32) != 0,
               "a different directory gets a different key");
            char p[512]; snprintf(p, sizeof p, "%s/audit.key", other);
            unlink(p); rmdir(other);
        } else {
            ok(0, "a different directory gets a different key");
        }
    }

    /* --- a key the group can read is refused -----------------------------
     * Continuing would produce a log that looks authenticated and is not --
     * worse than no log, because the first invites trust. */
    ok(chmod(g_key, 0640) == 0, "make the key group-readable");
    rv = fhsm_audit_key_provision(g_dir, b, NULL);
    ok(rv != FHSM_RV_OK, "  provisioning refuses a group-readable key");
    ok(chmod(g_key, 0600) == 0, "restore 0600");
    rv = fhsm_audit_key_provision(g_dir, b, NULL);
    ok(rv == FHSM_RV_OK && memcmp(a, b, 32) == 0, "  and it becomes acceptable again");

    /* --- a truncated key is refused, not padded -------------------------- */
    {
        kill_key();
        int fd = open(g_key, O_WRONLY | O_CREAT | O_EXCL, 0600);
        ok(fd >= 0 && write(fd, a, 16) == 16, "write a truncated 16-byte key");
        if (fd >= 0) close(fd);
        rv = fhsm_audit_key_provision(g_dir, b, NULL);
        ok(rv != FHSM_RV_OK, "  provisioning refuses a key of the wrong size");
    }

    /* --- arguments ------------------------------------------------------- */
    ok(fhsm_audit_key_provision(NULL, b, NULL) == FHSM_RV_ARGUMENTS_BAD,
       "an absent directory is refused");
    ok(fhsm_audit_key_provision(g_dir, NULL, NULL) == FHSM_RV_ARGUMENTS_BAD,
       "an absent output is refused");
    {
        char loooong[600];
        memset(loooong, 'x', sizeof loooong - 1); loooong[sizeof loooong - 1] = 0;
        ok(fhsm_audit_key_provision(loooong, b, NULL) == FHSM_RV_ARGUMENTS_BAD,
           "an over-long path is refused rather than truncated");
    }

    kill_key();
    rmdir(g_dir);

    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
