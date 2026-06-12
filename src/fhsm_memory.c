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

#include <openssl/crypto.h>
#include <pthread.h>
#include <string.h>

/* Volatile function pointer to memset --- prevents the compiler from
 * eliding the call as dead-store when the caller is about to free /
 * leave-scope. Same trick as OpenSSL's OPENSSL_cleanse. */
static void * (* const volatile g_memset_fn)(void *, int, size_t) = memset;

static pthread_once_t g_heap_once = PTHREAD_ONCE_INIT;
static int            g_heap_ok   = 0;

static void heap_init_once(void) {
    /* OPENSSL_secure_malloc_init: arg1 = arena size in bytes, arg2 = min
     * allocation size (must be a power of 2). Both are build-time
     * configurable through FHSM_SECURE_HEAP_BYTES / FHSM_SECURE_HEAP_MINSIZE.
     * The arena is mmap()-ed and mlock()-ed; if mlock fails (rlimit too
     * low), OpenSSL falls back to a regular mmap arena and OPENSSL_secure_malloc_initialized()
     * returns 1 but secure-allocations are *not* swap-excluded. We re-
     * check the result and reject the init in strict mode.
     */
    if (CRYPTO_secure_malloc_init(FHSM_SECURE_HEAP_BYTES,
                                   FHSM_SECURE_HEAP_MINSIZE) == 1) {
        g_heap_ok = 1;
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
    return FHSM_SECURE_HEAP_BYTES;
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
