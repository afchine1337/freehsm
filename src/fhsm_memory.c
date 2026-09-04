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
 * fhsm_memory.c --- Secure heap + zeroize + constant-time comparison.
 *
 * Required by FIPS 140-3 §7.9 ("sensitive security parameter management")
 * and §7.10 ("self-tests"). The secure heap is a single mlock()-ed arena
 * managed by OpenSSL's CRYPTO_secure_malloc family; allocations are
 * cleared on free, and the entire arena is excluded from swap.
 *
 * fhsm_zeroize() uses an explicit memset_s-equivalent guarded by a
 * volatile pointer + compiler barrier to defeat dead-store elimination.
 *
 * fhsm_ct_memcmp() is the only comparison primitive allowed for
 * sensitive data (PINs, HMAC tags, KAT outputs). It runs in time
 * proportional to the buffer length, independent of the position of
 * the first mismatching byte.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_conf.h"

#include <openssl/crypto.h>
#include <pthread.h>
#include <stdio.h>              /* fprintf on the heap-init failure path */
#include <string.h>
#include <sys/resource.h>       /* getrlimit(RLIMIT_MEMLOCK) --- so the message
                                 * can name the limit instead of the operator
                                 * having to guess which one is in the way */

/* Volatile function pointer to memset --- prevents the compiler from
 * eliding the call as dead-store when the caller is about to free /
 * leave-scope. Same trick as OpenSSL's OPENSSL_cleanse. */
static void * (* const volatile g_memset_fn)(void *, int, size_t) = memset;

static pthread_once_t g_heap_once = PTHREAD_ONCE_INIT;
static int            g_heap_ok   = 0;
static size_t         g_heap_bytes = (size_t)FHSM_SECURE_HEAP_BYTES;

static void heap_init_once(void) {
    /* OPENSSL_secure_malloc_init: arg1 = arena size in bytes, arg2 = min
     * allocation size (must be a power of 2). Both are build-time
     * configurable through FHSM_SECURE_HEAP_BYTES / FHSM_SECURE_HEAP_MINSIZE.
     * The arena is mmap()-ed and mlock()-ed; if mlock fails (rlimit too low),
     * OpenSSL falls back to a regular mmap arena and
     * OPENSSL_secure_malloc_initialized() returns 1 but secure-allocations are
     * *not* swap-excluded.
     *
     * THE `== 1` BELOW IS THAT CHECK, and it is stricter than it looks.
     * CRYPTO_secure_malloc_init distinguishes three outcomes: 0 for failure,
     * 1 for an arena that is allocated AND locked, and 2 for an arena that was
     * allocated but could not be locked. Accepting only 1 therefore rejects
     * the swappable fallback, which is what an evaluation document claiming
     * swap-excluded key material requires.
     *
     * This paragraph has now been wrong twice, in opposite directions, and the
     * history is worth keeping because both errors were about the same gap.
     *
     *   until 2026-09-04  "We re-check the result and reject the init in
     *                      strict mode" -- describing a separate re-check that
     *                      does not exist anywhere in this file.
     *   on 2026-09-04     I replaced it with "OpenSSL returns 1 but the arena
     *                      is not locked, and this code does not detect that"
     *                      -- also false, and worse, because it accused
     *                      working code of a hole it does not have.
     *
     * What settled it was neither reading: an external reporter set
     * secure_heap_kb = 65536 on a host with RLIMIT_MEMLOCK = 8 MiB, and
     * C_Initialize returned CKR_HOST_MEMORY. If the unlocked fallback were
     * accepted, it would have started.
     *
     * The consequence for operators is real and belongs in AGD_PRE rather than
     * here: raising secure_heap_kb above `ulimit -l` does not give you a bigger
     * arena, it stops the module. The two must be raised together.
     *
     * tests/probe_secure_heap reports what the kernel actually locked across
     * C_Initialize, so the property is observable rather than argued. Measured
     * 2026-09-04 on Debian 13: 8192 kB, the whole default arena.
     */
    /* Arena size is operator-configurable via `secure_heap_kb` (#128). It has
     * to be: once sensitive key material lives in this arena (#127) and
     * exhaustion is a hard failure rather than a silent fallback, an operator
     * with a large token needs a way to raise the ceiling. A compile-time
     * constant would make that a rebuild. */
    g_heap_bytes = fhsm_conf_secure_heap_bytes();
    int rc = CRYPTO_secure_malloc_init(g_heap_bytes, FHSM_SECURE_HEAP_MINSIZE);
    if (rc == 1) {
        g_heap_ok = 1;
        return;
    }

    /* Say which of the two failures this is, and name the limit.
     *
     * C_Initialize returned a bare CKR_HOST_MEMORY here. The reporter who hit
     * it had raised secure_heap_kb to 65536 on a host with RLIMIT_MEMLOCK at
     * 8 MiB, and concluded "there is some problem with the config" -- which is
     * true and unactionable. The module knew the size it asked for and could
     * have said so. */
    {
        struct rlimit rl;
        unsigned long lim_kb = 0;
        if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
            lim_kb = (unsigned long)(rl.rlim_cur / 1024);

        fprintf(stderr,
            "[freehsm-c] FATAL : the secure heap could not be created.\n"
            "  Asked for %lu kB (secure_heap_kb in /etc/freehsm/freehsm.conf,\n"
            "  default %lu kB).\n",
            (unsigned long)(g_heap_bytes / 1024),
            (unsigned long)(FHSM_SECURE_HEAP_BYTES / 1024));
        if (rc == 2) {
            fputs("  OpenSSL allocated it but could NOT lock it in memory, and\n"
                  "  an unlocked arena is refused: key material there could be\n"
                  "  written to swap, which is exactly what this heap prevents.\n",
                  stderr);
        } else {
            fputs("  OpenSSL could not allocate it at all.\n", stderr);
        }
        if (lim_kb)
            fprintf(stderr,
                "  Your locked-memory limit is %lu kB (ulimit -l). The arena must\n"
                "  fit inside it -- raising secure_heap_kb alone does not give you\n"
                "  a bigger arena, it stops the module. Raise both, or neither.\n",
                lim_kb);
        else
            fputs("  Check `ulimit -l` : the arena must fit inside it.\n", stderr);
    }
}

fhsm_rv_t fhsm_secure_heap_init(void) {
    pthread_once(&g_heap_once, heap_init_once);
    return g_heap_ok ? FHSM_RV_OK : FHSM_RV_HOST_MEMORY;
}

void *fhsm_secure_malloc(size_t n) {
    if (!g_heap_ok) {
        if (fhsm_secure_heap_init() != FHSM_RV_OK) {
            return NULL;
        }
    }
    void *p = OPENSSL_secure_malloc(n);
    if (p == NULL) {
        /* Out of arena --- the *caller* must handle this gracefully and
         * decide whether to enter ERROR state. We do not auto-latch
         * because non-critical paths (e.g. resizing a search buffer)
         * may legitimately exhaust the arena under heavy load. */
        return NULL;
    }
    return p;
}

void *fhsm_secure_zalloc(size_t n) {
    void *p = fhsm_secure_malloc(n);
    if (p) {
        /* OPENSSL_secure_malloc does NOT zero --- do it ourselves. */
        g_memset_fn(p, 0, n);
    }
    return p;
}

void fhsm_secure_free(void *p) {
    if (p == NULL) return;
    /* CRYPTO_secure_clear_free zeroizes (size is tracked in arena
     * metadata) before returning the block to the allocator. */
    OPENSSL_secure_clear_free(p, 0);
}

size_t fhsm_secure_heap_used(void) {
    return CRYPTO_secure_used();
}

size_t fhsm_secure_heap_total(void) {
    /* Report what was actually requested, not the compiled default -- a
     * caller checking headroom against a number the arena does not have is
     * exactly the kind of quiet disagreement this series exists to remove. */
    if (!g_heap_ok) (void)fhsm_secure_heap_init();
    return g_heap_bytes;
}

void fhsm_zeroize(void *p, size_t n) {
    if (p == NULL || n == 0) return;
    g_memset_fn(p, 0, n);
    /* Compiler memory barrier --- ensures the memset is not reordered
     * past subsequent code that could observe the buffer. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

int fhsm_ct_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned int diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (unsigned int)(pa[i] ^ pb[i]);
    }
    /* Returns 0 if equal, non-zero otherwise. The value of non-zero
     * is intentionally not stable across compilers --- the caller MUST
     * treat the result as a boolean. */
    return (int)diff;
}
