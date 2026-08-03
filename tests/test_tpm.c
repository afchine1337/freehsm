/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_tpm.c --- TPM 2.0 sealing backend (#109).
 *
 *  There is no TPM here and there is no TPM in CI, so this test drives
 *  fhsm_tpm.c against tests/tpm2-stub.sh through the compile-time seam that
 *  -DFHSM_TPM_TEST_HOOKS opens. Be clear about what that can and cannot
 *  establish:
 *
 *    It CANNOT tell you TPM sealing is secure. PCR binding, the sealing
 *    crypto and tamper detection all live inside the TPM, and there is no
 *    TPM on the other side of the stub.
 *
 *    It CAN tell you that the code on our side of the CLI boundary is
 *    correct, and that side had three defects, all found by reading:
 *
 *      1. The DEK was written to a file in the clear so tpm2 could read it,
 *         and written back in the clear by `tpm2 unseal -o`. v1.6.0 had just
 *         moved that same key into an mlock'd arena to keep it out of swap
 *         (#127); putting it on a disk was strictly worse than the paging we
 *         had gone to trouble to prevent. Asserted here by checking every
 *         path handed to tpm2 is under /proc/self/fd/.
 *
 *      2. Temp filenames were built from getpid(), so two threads sealing
 *         two different tokens in one process wrote the same files. The
 *         comment claimed the per-token mutex covered it; it does not,
 *         different tokens hold different mutexes. Asserted by test E.
 *
 *      3. A failed unseal bumped the PIN failure counter. The seal is bound
 *         to PCR 0-7, so a BIOS or kernel update makes every unseal fail --
 *         and the legitimate operator, holding the correct PIN, would burn
 *         one attempt per login until the token locked for good. A routine
 *         firmware update destroyed the token. Asserted by test F, which is
 *         the one worth keeping.
 * ========================================================================= */
#include "fhsm_common.h"
#include "fhsm_tpm.h"
#include "fhsm_token.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails = 0;

static void ck(const char *what, int ok) {
    printf("  %-58s %s\n", what, ok ? "OK" : "<<< FAIL");
    if (!ok) fails++;
}

/* ------------------------------------------------------------------ */
static const char *STUB_LOG = "/tmp/fhsm_tpm_stub.log";

static void stub_log_reset(void) {
    unlink(STUB_LOG);
    setenv("FHSM_TPM_FAKE_LOG", STUB_LOG, 1);
}

/* Every argument the stub was handed, checked for filesystem paths. Returns
 * the number of arguments that look like a path but are not an anonymous
 * in-memory file. */
static int stub_log_disk_paths(void) {
    FILE *f = fopen(STUB_LOG, "r");
    if (!f) return -1;
    char line[4096];
    int bad = 0;
    while (fgets(line, sizeof(line), f)) {
        char *tok = strtok(line, " \t\n");
        while (tok) {
            /* Anything that starts with '/' is a path we handed over. The
             * only acceptable ones are /proc/self/fd/N. */
            if (tok[0] == '/' && strncmp(tok, "/proc/self/fd/", 14) != 0) {
                printf("      disk path handed to tpm2: %s\n", tok);
                bad++;
            }
            tok = strtok(NULL, " \t\n");
        }
    }
    fclose(f);
    return bad;
}

/* ------------------------------------------------------------------ */
static void test_roundtrip_and_no_disk(void) {
    printf("[A] seal/unseal round trip, and nothing touches a filesystem\n");
    uint8_t secret[32], back[32];
    for (int i = 0; i < 32; ++i) secret[i] = (uint8_t)(i * 7 + 3);
    secret[5] = 0x00;                 /* NUL bytes must survive */
    secret[6] = 0xff;

    stub_log_reset();
    uint8_t blob[2048]; size_t blob_len = 0;
    fhsm_rv_t rv = fhsm_tpm_seal(secret, blob, sizeof(blob), &blob_len);
    ck("seal returns OK", rv == FHSM_RV_OK);
    ck("blob carries the TPS1 magic", blob_len > 12 && memcmp(blob, "TPS1", 4) == 0);

    memset(back, 0, sizeof(back));
    rv = fhsm_tpm_unseal(blob, blob_len, back);
    ck("unseal returns OK", rv == FHSM_RV_OK);
    ck("unsealed DEK is byte-identical", memcmp(secret, back, 32) == 0);

    int bad = stub_log_disk_paths();
    ck("no filesystem path was ever handed to tpm2 (#109.1)", bad == 0);
}

static void test_tamper(void) {
    printf("[B] a corrupted blob is refused\n");
    uint8_t secret[32], back[32];
    memset(secret, 0xA5, sizeof(secret));
    uint8_t blob[2048]; size_t blob_len = 0;
    if (fhsm_tpm_seal(secret, blob, sizeof(blob), &blob_len) != FHSM_RV_OK) {
        ck("seal (precondition)", 0); return;
    }
    uint8_t bad_magic[2048]; memcpy(bad_magic, blob, blob_len);
    bad_magic[0] = 'X';
    ck("wrong magic refused",
       fhsm_tpm_unseal(bad_magic, blob_len, back) != FHSM_RV_OK);

    ck("truncated blob refused",
       fhsm_tpm_unseal(blob, blob_len - 1, back) != FHSM_RV_OK);

    ck("short blob refused",
       fhsm_tpm_unseal(blob, 4, back) == FHSM_RV_ARGUMENTS_BAD);
}

static void test_pcr_moved(void) {
    printf("[C] PCRs move (firmware update): unseal fails, cleanly\n");
    uint8_t secret[32], back[32];
    memset(secret, 0x5A, sizeof(secret));
    setenv("FHSM_TPM_FAKE_PCR", "boot-state-1", 1);
    uint8_t blob[2048]; size_t blob_len = 0;
    if (fhsm_tpm_seal(secret, blob, sizeof(blob), &blob_len) != FHSM_RV_OK) {
        ck("seal (precondition)", 0); return;
    }
    setenv("FHSM_TPM_FAKE_PCR", "boot-state-2", 1);   /* the BIOS update */
    memset(back, 0xCC, sizeof(back));
    fhsm_rv_t rv = fhsm_tpm_unseal(blob, blob_len, back);
    ck("unseal fails after the PCRs move", rv != FHSM_RV_OK);

    /* And it must not leave anything key-shaped in the caller's buffer. */
    uint8_t zero[32] = {0};
    ck("output buffer is zeroed, not left half-filled",
       memcmp(back, zero, 32) == 0);

    setenv("FHSM_TPM_FAKE_PCR", "boot-state-1", 1);
    ck("unseal works again once the PCRs are restored",
       fhsm_tpm_unseal(blob, blob_len, back) == FHSM_RV_OK
       && memcmp(back, secret, 32) == 0);
}

static void test_command_failure(void) {
    printf("[D] a tpm2 subcommand that fails is reported, not ignored\n");
    uint8_t secret[32]; memset(secret, 1, sizeof(secret));
    uint8_t blob[2048]; size_t blob_len = 0;
    setenv("FHSM_TPM_FAKE_FAIL", "create", 1);
    ck("`tpm2 create` failing makes seal fail",
       fhsm_tpm_seal(secret, blob, sizeof(blob), &blob_len) != FHSM_RV_OK);
    unsetenv("FHSM_TPM_FAKE_FAIL");
}

/* ------------------------------------------------------------------ *
 * [E] The getpid() collision. Under the old code the four temp files were
 * named seal-{in,pub,priv}-<pid>, identical for every thread in the process,
 * so two threads sealing two different tokens overwrote each other's files
 * and could hand back the wrong DEK -- or a torn one. Each thread here seals
 * a secret only it knows and checks it gets exactly that back.
 * ------------------------------------------------------------------ */
#define NTHREADS 8
static pthread_barrier_t g_start;

static void *seal_thread(void *arg) {
    long id = (long)arg;
    uint8_t secret[32], back[32];
    memset(secret, (int)(id + 1), sizeof(secret));
    uint8_t blob[2048]; size_t blob_len = 0;

    pthread_barrier_wait(&g_start);          /* open the window as wide as
                                                possible: all eight at once */
    for (int round = 0; round < 10; ++round) {
        if (fhsm_tpm_seal(secret, blob, sizeof(blob), &blob_len) != FHSM_RV_OK)
            return (void *)1;
        memset(back, 0, sizeof(back));
        if (fhsm_tpm_unseal(blob, blob_len, back) != FHSM_RV_OK)
            return (void *)2;
        if (memcmp(secret, back, 32) != 0)
            return (void *)3;                /* got another thread's key */
    }
    return NULL;
}

static void test_concurrent_seal(void) {
    printf("[E] eight threads sealing at once do not collide (#109.2)\n");
    pthread_t th[NTHREADS];
    pthread_barrier_init(&g_start, NULL, NTHREADS);
    for (long i = 0; i < NTHREADS; ++i)
        pthread_create(&th[i], NULL, seal_thread, (void *)i);
    int bad = 0;
    for (int i = 0; i < NTHREADS; ++i) {
        void *r = NULL; pthread_join(th[i], &r);
        if (r) { printf("      thread %d failed, code %ld\n", i, (long)r); bad++; }
    }
    pthread_barrier_destroy(&g_start);
    ck("every thread got back its own DEK", bad == 0);
}

/* ------------------------------------------------------------------ *
 * [F] The denial of service. This is the test that matters.
 * ------------------------------------------------------------------ */
static void test_tpm_failure_does_not_lock_token(void) {
    printf("[F] a broken TPM must not lock the token out (#109.3)\n");
    const char *path = "/tmp/fhsm_test_tpm_token.bin";
    const char *SO_PIN = "12345678";
    unlink(path);
    { char c[512]; snprintf(c, sizeof(c), "%s.tpm", path); unlink(c); }

    setenv("FHSM_TPM_SEALING", "1", 1);
    setenv("FHSM_TPM_FAKE_PCR", "boot-state-1", 1);

    fhsm_token_t *t = NULL;
    fhsm_rv_t rv = fhsm_token_init(path, SO_PIN, "tpm-dos-test", &t);
    if (rv != FHSM_RV_OK || !t) {
        ck("token init with sealing enabled (precondition)", 0);
        return;
    }
    ck("login works while the TPM is healthy",
       fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN) == FHSM_RV_OK);
    fhsm_token_logout(t);

    /* The firmware update. Every unseal from here fails. */
    setenv("FHSM_TPM_FAKE_PCR", "boot-state-2", 1);

    int all_device_error = 1;
    const int attempts = FHSM_PIN_MAX_FAILED + 3;
    for (int i = 0; i < attempts; ++i) {
        rv = fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN);   /* correct PIN */
        if (rv != FHSM_RV_DEVICE_ERROR) {
            printf("      attempt %d returned 0x%08x, expected DEVICE_ERROR\n",
                   i + 1, (unsigned)rv);
            all_device_error = 0;
        }
    }
    ck("a correct PIN against a broken TPM reports a device fault,"
       " not a bad PIN", all_device_error);

    /* The engineer replaces the machine's firmware policy / re-seals.
     * The operator's PIN was correct every single time; the token must
     * still be usable. Under the old code it locked after 5. */
    setenv("FHSM_TPM_FAKE_PCR", "boot-state-1", 1);
    rv = fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN);
    ck("token still opens once the TPM recovers -- no lockout", rv == FHSM_RV_OK);
    if (rv != FHSM_RV_OK)
        printf("      got 0x%08x (0x%08x would be PIN_LOCKED)\n",
               (unsigned)rv, (unsigned)FHSM_RV_PIN_LOCKED);

    /* Belt and braces: a genuinely wrong PIN must still count. Removing the
     * TPM path from the counter must not have removed the counter. */
    fhsm_token_logout(t);
    ck("a wrong PIN is still rejected as a wrong PIN",
       fhsm_token_login(t, FHSM_ROLE_SO, "wrongwrong") == FHSM_RV_PIN_INCORRECT);

    fhsm_token_close(t);
    unlink(path);
    { char c[512]; snprintf(c, sizeof(c), "%s.tpm", path); unlink(c); }
    unsetenv("FHSM_TPM_SEALING");
}

/* ------------------------------------------------------------------ */
int main(void) {
    /* Point the module at the stub before anything calls
     * fhsm_tpm_available(), which caches its answer. */
    const char *stub = getenv("FHSM_TPM_STUB");
    /* Invoked through `sh` rather than executed directly: a checkout that
     * loses the executable bit (git stash round trips, some archive
     * exports, some CI checkouts) would otherwise turn this test into a
     * silent skip -- and a test that skips itself is worse than no test. */
    if (!stub) stub = "sh tests/tpm2-stub.sh";
    setenv("FHSM_TPM_CMD", stub, 1);

    /* The probe wants a device node to exist. Any file will do -- the stub
     * is what actually answers. */
    const char *fake_dev = "/tmp/fhsm_fake_tpmrm0";
    FILE *f = fopen(fake_dev, "w");
    if (f) fclose(f);
    setenv("FHSM_TPM_DEVICE", fake_dev, 1);
    setenv("FHSM_TPM_FAKE_PCR", "boot-state-1", 1);

    if (!fhsm_tpm_available()) {
        printf("fhsm_tpm_available() said no -- the stub is not wired up.\n"
               "  FHSM_TPM_CMD=%s\n", stub);
        return 2;
    }

    printf("=== test_tpm : TPM 2.0 sealing backend (#109) ===\n");
    printf("    driven against tests/tpm2-stub.sh -- proves the plumbing,\n"
           "    proves nothing about the TPM itself.\n\n");

    test_roundtrip_and_no_disk();
    test_tamper();
    test_pcr_moved();
    test_command_failure();
    test_concurrent_seal();
    test_tpm_failure_does_not_lock_token();

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    unlink(fake_dev);
    return fails ? 1 : 0;
}
