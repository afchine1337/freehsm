/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_apilock.c --- the PKCS#11 entry lock's deferred release,
 * deterministically (#111-prep).
 *
 *  tests/test_concurrency_store shows the lock closing races, but only when
 *  the threads happen to overlap. The deferred-release path -- a value freed
 *  inside a SHARED call -- is reached from the API only through a rollback or
 *  a CKA_SENSITIVE migration, with a window too narrow to aim at. So it is
 *  driven here directly, with the interleaving fixed by hand:
 *
 *   1. outside any call, a release is immediate;
 *   2. inside a SHARED call, it is parked and the bytes stay intact;
 *   3. while another thread is still inside a SHARED call, leaving does not
 *      drain -- that thread may be reading the value;
 *   4. the last SHARED call out drains;
 *   5. inside an EXCLUSIVE call, a release is immediate, and a nested entry
 *      neither deadlocks nor downgrades the mode.
 *
 *  The drain at an EXCLUSIVE entry is not checked on its own: any interleaving
 *  that parks a value and then lets a writer in also lets the last reader's
 *  exit drain first, and which one wins is the scheduler's choice.
 * ========================================================================= */
#include "fhsm_common.h"
#include "fhsm_apilock.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
#define CHECK(c, msg) do { if (c) printf("  ok    %s\n", msg); \
                           else { printf("  FAIL  %s\n", msg); g_fail++; } } while (0)

static pthread_barrier_t g_in, g_out;

/* Holds a SHARED call open between the two barriers. */
static void *holder(void *arg) {
    (void)arg;
    {
        FHSM_API_SHARED();
        pthread_barrier_wait(&g_in);
        pthread_barrier_wait(&g_out);
    }
    return NULL;
}

static unsigned char *filled(size_t n) {
    unsigned char *p = malloc(n);
    if (!p) { perror("malloc"); exit(2); }
    memset(p, 0xA5, n);
    return p;
}

static int intact(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i] != 0xA5) return 0;
    return 1;
}

/* A C_ function called from another, as C_CloseAllSessions calls
 * C_CloseSession: its own guard, in its own frame. */
static void nested_shared(void) {
    FHSM_API_SHARED();
    CHECK(fhsm_api_mode() == FHSM_API_EXCLUSIVE, "nested entry: outermost mode kept");
    fhsm_api_free_value(filled(32), 32, 0);
    CHECK(fhsm_api_retired_count() == 0, "nested in EXCLUSIVE: released at once");
}

int main(void) {
    printf("test_apilock\n");

    /* 1 */
    fhsm_api_free_value(filled(32), 32, 0);
    CHECK(fhsm_api_retired_count() == 0, "outside any call: released at once");
    CHECK(fhsm_api_mode() == FHSM_API_NONE, "outside any call: mode NONE");

    /* 2, 3, 4 */
    pthread_barrier_init(&g_in, NULL, 2);
    pthread_barrier_init(&g_out, NULL, 2);
    pthread_t th;
    pthread_create(&th, NULL, holder, NULL);
    pthread_barrier_wait(&g_in);              /* the holder is inside */

    unsigned char *v = filled(32);
    {
        FHSM_API_SHARED();
        CHECK(fhsm_api_mode() == FHSM_API_SHARED, "SHARED call: mode SHARED");
        fhsm_api_free_value(v, 32, 0);
        CHECK(fhsm_api_retired_count() == 1, "SHARED call: release parked");
        CHECK(intact(v, 32), "SHARED call: parked value still intact");
    }
    CHECK(fhsm_api_retired_count() == 1,
          "another call still in flight: leaving does not drain");
    CHECK(intact(v, 32), "another call still in flight: value still intact");

    pthread_barrier_wait(&g_out);             /* the holder leaves */
    pthread_join(th, NULL);
    CHECK(fhsm_api_retired_count() == 0, "last SHARED call out: drained");

    {
        FHSM_API_EXCLUSIVE();
        /* 5 */
        CHECK(fhsm_api_mode() == FHSM_API_EXCLUSIVE, "EXCLUSIVE call: mode EXCLUSIVE");
        fhsm_api_free_value(filled(32), 32, 0);
        CHECK(fhsm_api_retired_count() == 0, "EXCLUSIVE call: released at once");
        nested_shared();                      /* must not deadlock */
        CHECK(fhsm_api_mode() == FHSM_API_EXCLUSIVE,
              "nested exit: lock still held by the outer call");
    }
    CHECK(fhsm_api_mode() == FHSM_API_NONE, "outer exit: mode NONE");

    printf("\ntest_apilock : %s\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
