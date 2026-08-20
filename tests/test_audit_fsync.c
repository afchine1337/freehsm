/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * A failed fsync must stop the module, like a failed write does.
 *
 * `fhsm_audit_event` checked `write()` and latched ERROR when it failed, then
 * called `fsync()` and threw the answer away. On most filesystems a deferred
 * write error is reported at fsync and nowhere else — so the control that
 * exists to stop the module when the log cannot be written was wired to the
 * call that usually succeeds, and not to the call that usually reports.
 *
 * The same shape as #61, #49 and the ulPinLen defect: a rule applied to some
 * of the paths that reach a state and not the rest. Both fsyncs in the
 * key-provisioning code check their return; the one in the hot path did not.
 *
 * Staging a failing fsync portably: `fsync` on a pipe returns EINVAL, while
 * `write` to it succeeds. So the log is pointed at a FIFO with a reader
 * draining it. Every write lands, every fsync fails, and nothing about the
 * audit code knows it is not a file.
 *
 *     write -> 6
 *     fsync -> -1  errno=22 (Invalid argument)
 *
 * The reader matters: opening a FIFO for writing blocks until someone opens it
 * for reading, so the thread is started first and drains until EOF.
 */
#include "fhsm_common.h"
#include "fhsm_audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

static char g_fifo[512];

static void *drain(void *v) {
    (void)v;
    int fd = open(g_fifo, O_RDONLY);
    if (fd < 0) return NULL;
    char b[256];
    while (read(fd, b, sizeof b) > 0) { }
    close(fd);
    return NULL;
}

int main(void)
{
    const char *dir = getenv("FHSM_TOKENS_DIR");
    snprintf(g_fifo, sizeof g_fifo, "%s/audit.fifo", dir ? dir : "/tmp");
    unlink(g_fifo);

    printf("A failed fsync stops the module\n\n");

    if (mkfifo(g_fifo, 0600) != 0) {
        printf("  cannot create a FIFO at %s -- skipped\n", g_fifo);
        return 0;                      /* not a failure of the module */
    }

    pthread_t reader;
    if (pthread_create(&reader, NULL, drain, NULL) != 0) {
        printf("  cannot start the reader -- skipped\n");
        unlink(g_fifo);
        return 0;
    }

    uint8_t key[32];
    memset(key, 0x42, sizeof key);

    /* Opening blocks until the reader arrives; it writes nothing itself. */
    fhsm_rv_t rv = fhsm_audit_open(g_fifo, FHSM_SLICE(key, 32));
    ok(rv == FHSM_RV_OK, "the log opens on a FIFO (write works, fsync will not)");

    ok(fhsm_state_get() != FHSM_STATE_ERROR,
       "the module is not in ERROR before the first event");

    /* The write lands in the pipe. The fsync cannot succeed on a pipe. */
    rv = fhsm_audit_event(FHSM_EV_LOGIN_FAIL, -1, -1, FHSM_ROLE_USER,
                           FHSM_RV_PIN_INCORRECT, "actor", "CN=fsync", NULL);
    ok(rv != FHSM_RV_OK, "an event whose fsync fails reports failure");
    ok(fhsm_state_get() == FHSM_STATE_ERROR,
       "and the module has latched ERROR");

    fhsm_audit_close();
    pthread_join(reader, NULL);
    unlink(g_fifo);

    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
