/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Group commit: the barrier is shared, and the chain survives it.
 *
 * Every audit event must be durable before the operation that caused it
 * returns — a signature must not reach a client before the record of it is on
 * disk. What is negotiable is how many `fsync` calls that takes: one barrier
 * serves every write already in the file, so writers arriving while a barrier
 * is in flight can wait for the next one instead of queueing their own.
 * Measured at eight writers: 1469 lines/s against 363, 118 barriers for 480
 * lines. See docs/AUDIT_DURABILITY.md.
 *
 * The delicate part is not the waiting, it is the ordering. `fhsm_audit_event`
 * now releases the audit mutex while the barrier runs, so another writer takes
 * the lock and reads `g_prev_hmac` in the middle of it. The chain therefore has
 * to advance BEFORE the barrier rather than after. Get that wrong and two
 * lines claim the same predecessor: the log still looks fine, every event
 * still returns OK, and only the verifier disagrees — which is why the third
 * assertion below runs the real verifier over the real file rather than
 * counting lines.
 *
 * Two mutations this must catch:
 *   - fsync back inside the lock  -> barriers == events, assertion 2 fails
 *   - chain advanced after the barrier -> assertion 3 fails
 */
#include "fhsm_common.h"
#include "fhsm_audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define THREADS      8
#define PER_THREAD  40

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

static int g_bad_rv = 0;

static void *writer(void *v)
{
    (void)v;
    for (int i = 0; i < PER_THREAD; i++) {
        fhsm_rv_t rv = fhsm_audit_event(FHSM_EV_LOGIN_FAIL, -1, -1,
                                         FHSM_ROLE_USER, FHSM_RV_PIN_INCORRECT,
                                         "actor", "CN=concurrent", NULL);
        if (rv != FHSM_RV_OK) __atomic_add_fetch(&g_bad_rv, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

int main(void)
{
    const char *dir = getenv("FHSM_TOKENS_DIR");
    char path[512];
    snprintf(path, sizeof path, "%s/concurrent.log", dir ? dir : "/tmp");
    unlink(path);

    printf("Group commit under concurrency\n\n");

    uint8_t key[32];
    memset(key, 0x42, sizeof key);
    if (fhsm_audit_open(path, FHSM_SLICE(key, 32)) != FHSM_RV_OK) {
        printf("  cannot open %s\n", path);
        return 2;
    }

    pthread_t th[THREADS];
    for (int i = 0; i < THREADS; i++) {
        if (pthread_create(&th[i], NULL, writer, NULL) != 0) {
            printf("  cannot start thread %d\n", i);
            return 2;
        }
    }
    for (int i = 0; i < THREADS; i++) pthread_join(th[i], NULL);

    const int expected = THREADS * PER_THREAD;

    /* 1. Nothing was refused. A writer only returns after a barrier that
     *    covered it, so this is also the statement that every one of them
     *    got one. */
    ok(g_bad_rv == 0, "every concurrent event reports success");

    /* 2. The barrier was shared. Without this the change is a no-op with extra
     *    locking, and the whole point of it is unobservable. */
    uint64_t events = 0, barriers = 0;
    fhsm_audit_barrier_stats(&events, &barriers);
    printf("    (%llu events, %llu durable barriers)\n",
           (unsigned long long)events, (unsigned long long)barriers);
    ok(barriers >= 1 && barriers < events,
       "concurrent events shared barriers instead of one each");

    /* 3. The chain is intact. This is the assertion that catches the ordering
     *    mistake the optimisation invites, and nothing cheaper would. */
    fhsm_audit_close();
    size_t broken = 0;
    fhsm_rv_t vr = fhsm_audit_verify(path, FHSM_SLICE(key, 32), &broken);
    if (vr != FHSM_RV_OK) printf("    (chain breaks at line %zu)\n", broken);
    ok(vr == FHSM_RV_OK, "the HMAC chain verifies over the whole file");

    /* 4. And every line is there — a barrier that silently dropped writes
     *    would still verify, because a shorter chain verifies perfectly. */
    FILE *f = fopen(path, "r");
    int lines = 0;
    if (f) { int c; while ((c = fgetc(f)) != EOF) if (c == '\n') lines++; fclose(f); }
    printf("    (%d lines for %d events)\n", lines, expected);
    ok(lines >= expected, "no line was lost");

    unlink(path);
    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
