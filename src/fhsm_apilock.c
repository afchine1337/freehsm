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
 * fhsm_apilock.c --- the PKCS#11 entry lock and deferred value release.
 *
 * See include/fhsm_apilock.h for why it exists. Two pieces of state:
 *
 *   g_api_rw     the module-wide read-write lock, writer-preferring;
 *   g_retired    values freed while their thread held the lock SHARED, kept
 *                intact until no call is in flight, then zeroized and freed.
 *
 * The retired list is drained under the lock held EXCLUSIVE, which by
 * construction means no other thread is between a fhsm_token_object_get and
 * its last use of the pointer. That happens at every EXCLUSIVE entry, and at a
 * SHARED exit that finds the list non-empty and the lock free (trywrlock): a
 * module that only ever signs and rolls back still gets its values wiped as
 * soon as it is idle, rather than at the next destroy.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_apilock.h"

#include <pthread.h>
#include <stdlib.h>

typedef struct fhsm_retired_s {
    void                  *p;
    size_t                 len;
    int                    secure;
    struct fhsm_retired_s *next;
} fhsm_retired_t;

static pthread_rwlock_t  g_api_rw;
static pthread_once_t    g_api_once  = PTHREAD_ONCE_INIT;
static pthread_mutex_t   g_retire_mu = PTHREAD_MUTEX_INITIALIZER;
static fhsm_retired_t   *g_retired   = NULL;

static _Thread_local fhsm_api_mode_t tl_mode = FHSM_API_NONE;

static void release_now(void *p, size_t len, int secure) {
    if (!p) return;
    if (len) fhsm_zeroize(p, len);
    if (secure) fhsm_secure_free(p);
    else        free(p);
}

static void api_rw_init(void) {
    pthread_rwlockattr_t a;
    pthread_rwlockattr_init(&a);
    /* glibc's default prefers readers: under a steady stream of C_Sign a
     * C_DestroyObject would wait for a gap that never comes. The cost of
     * writer preference is that a reader may not re-enter while a writer
     * waits -- which tl_mode already guarantees it never does. */
    pthread_rwlockattr_setkind_np(&a, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    pthread_rwlock_init(&g_api_rw, &a);
    pthread_rwlockattr_destroy(&a);
}

/* A forked child inherits the lock in whatever state the parent's other
 * threads left it, and those threads do not exist in the child. A fresh lock
 * and an empty retired list; the parked values are zeroized but not handed to
 * the secure-heap allocator, whose own lock may be in the same state. They
 * are the child's copy-on-write pages and go with it. */
static void api_after_fork_child(void) {
    api_rw_init();
    pthread_mutex_init(&g_retire_mu, NULL);
    for (fhsm_retired_t *r = g_retired, *n; r; r = n) {
        n = r->next;
        if (r->len) fhsm_zeroize(r->p, r->len);
        if (!r->secure) free(r->p);
        free(r);
    }
    g_retired = NULL;
    tl_mode = FHSM_API_NONE;
}

static void api_once(void) {
    api_rw_init();
    pthread_atfork(NULL, NULL, api_after_fork_child);
}

/* Caller holds g_api_rw EXCLUSIVE. */
static void drain_retired(void) {
    pthread_mutex_lock(&g_retire_mu);
    fhsm_retired_t *r = g_retired;
    g_retired = NULL;
    pthread_mutex_unlock(&g_retire_mu);
    while (r) {
        fhsm_retired_t *n = r->next;
        release_now(r->p, r->len, r->secure);
        free(r);
        r = n;
    }
}

static int have_retired(void) {
    pthread_mutex_lock(&g_retire_mu);
    int any = g_retired != NULL;
    pthread_mutex_unlock(&g_retire_mu);
    return any;
}

void fhsm_api_enter(fhsm_api_guard_t *g, fhsm_api_mode_t mode) {
    g->taken = 0;
    /* Nested C_ call: the outermost one holds the lock. The only nesting in
     * the module is C_CloseAllSessions -> C_CloseSession, both EXCLUSIVE. */
    if (tl_mode != FHSM_API_NONE) return;
    pthread_once(&g_api_once, api_once);
    if (mode == FHSM_API_EXCLUSIVE) {
        pthread_rwlock_wrlock(&g_api_rw);
        drain_retired();
    } else {
        pthread_rwlock_rdlock(&g_api_rw);
    }
    tl_mode = mode;
    g->taken = 1;
}

void fhsm_api_leave(fhsm_api_guard_t *g) {
    if (!g->taken) return;
    fhsm_api_mode_t was = tl_mode;
    tl_mode = FHSM_API_NONE;
    pthread_rwlock_unlock(&g_api_rw);
    g->taken = 0;
    if (was == FHSM_API_SHARED && have_retired()
        && pthread_rwlock_trywrlock(&g_api_rw) == 0) {
        drain_retired();
        pthread_rwlock_unlock(&g_api_rw);
    }
}

fhsm_api_mode_t fhsm_api_mode(void) {
    return tl_mode;
}

void fhsm_api_free_value(void *p, size_t len, int secure) {
    if (!p) return;
    if (tl_mode != FHSM_API_SHARED) {
        release_now(p, len, secure);
        return;
    }
    fhsm_retired_t *r = malloc(sizeof(*r));
    if (!r) {
        /* Neither choice is clean. Freeing now is the use-after-free this
         * file exists to prevent; zeroizing now would hand a concurrent C_Sign
         * a key of zeros. Leaking the buffer is the one that cannot produce a
         * wrong answer, and the host is out of memory anyway. */
        return;
    }
    r->p = p; r->len = len; r->secure = secure;
    pthread_mutex_lock(&g_retire_mu);
    r->next = g_retired;
    g_retired = r;
    pthread_mutex_unlock(&g_retire_mu);
}

size_t fhsm_api_retired_count(void) {
    size_t n = 0;
    pthread_mutex_lock(&g_retire_mu);
    for (const fhsm_retired_t *r = g_retired; r; r = r->next) n++;
    pthread_mutex_unlock(&g_retire_mu);
    return n;
}
