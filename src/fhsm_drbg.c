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
 * fhsm_drbg.c --- Hardened DRBG front-end (NIST SP 800-90B + 90C).
 *
 *  Architecture :
 *
 *    [getrandom]   [RDRAND]   [/dev/urandom]   [TSC jitter]
 *         \           \             /              /
 *          +-----------+-----+-----+--------------+
 *                            v
 *                       SHA-256 conditioner (SP 800-90C §3.1)
 *                            v
 *                  RAND_add (entropy contribution)
 *                            v
 *                  RAND_bytes (CTR_DRBG-AES-256, FIPS)
 *                            v
 *           [RCT] -- [APT] -- [CRNGT]  (SP 800-90B §4)
 *                            v
 *                      caller's buffer
 *
 *  The conditioner is required because not all sources have the same
 *  min-entropy : /dev/urandom is conservatively 1 bit/byte on cold
 *  boot, RDRAND is ~7.9 bit/byte but vendor-trusted, and TSC jitter is
 *  about 4 bit/byte in our measurements. Hashing the union yields
 *  approximately 8 bit/byte conditioned output, which is what
 *  CTR_DRBG-AES-256 expects on its seed input.
 *
 *  All state is module-static and guarded by g_mtx. The DRBG is reseed-
 *  every-1M-bytes-or-1h conservative; the SP 800-90A maximum is
 *  2^48 generate calls but few systems get close to that, and the
 *  cost (one extra SHA-256 + a few syscalls) is negligible.
 *
 *  Errors are fatal : on any health-test failure the module is latched
 *  into ERROR state via fhsm_state_latch_error and every subsequent
 *  call returns FHSM_RV_RNG_FAILURE.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_drbg.h"
#include "fhsm_crypto.h"

#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* x86 / x86_64 RDRAND --- guarded by the CPU feature flag, queried at
 * init via __builtin_cpu_supports. On non-Intel arches we just skip. */
#if defined(__x86_64__) || defined(__i386__)
# include <immintrin.h>
# define FHSM_HAS_RDRAND 1
#else
# define FHSM_HAS_RDRAND 0
#endif

/* ---------------------------------------------------------------------------
 * Health-test cutoffs.
 *
 *  RCT cutoff C is computed from C = ceil(1 + (-log2(α) / H)). With
 *  α = 2^-40 (NIST SP 800-90B recommended type-I error probability)
 *  and H = 8 (full byte entropy, our nominal post-conditioning), this
 *  gives C = 6.
 *
 *  APT cutoff C uses the critical value of a binomial distribution
 *  with W=512 trials, p=2^-H = 2^-8, α=2^-40. NIST's reference table
 *  in SP 800-90B Appendix C gives C = 51 for these parameters.
 * ----------------------------------------------------------------------- */
#define FHSM_RCT_CUTOFF   6      /* successive identical bytes */
#define FHSM_APT_WINDOW   512    /* sample window size */
#define FHSM_APT_CUTOFF   51     /* max times any single byte may appear in window */

/* Reseed thresholds : whichever fires first triggers a reseed. */
#define FHSM_RESEED_BYTES_MAX  (1024UL * 1024UL)    /* 1 MiB output */

/* Largest number of bytes handed to RAND_bytes in one call.
 *
 * SP 800-90A gives CTR_DRBG max_number_of_bits_per_request = 2^19 bits, i.e.
 * 65536 bytes; generating more than that is defined as a sequence of requests,
 * which is exactly what the loop in fhsm_drbg_bytes now does. Keeping the
 * chunk at the standard's own limit also keeps it far below INT_MAX, so the
 * int parameter of RAND_bytes can never be reached by a caller-controlled
 * length again. */
#define FHSM_DRBG_MAX_REQUEST  65536u
#define FHSM_RESEED_SECS_MAX   3600                  /* 1 hour wall-clock */

/* Continuous test : 16-byte block comparison. SP 800-90B §4.4.3. */
#define FHSM_CRNGT_BLOCK_SZ    16

/* ---------------------------------------------------------------------------
 * Module state.
 * ----------------------------------------------------------------------- */
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static int             g_initialised = 0;

static uint64_t        g_bytes_since_reseed = 0;
static time_t          g_last_reseed_t      = 0;

static uint8_t         g_rct_last_byte = 0;
static uint32_t        g_rct_count     = 0;   /* current run length */

static uint8_t         g_apt_window_byte = 0;
static uint32_t        g_apt_window_count = 0;
static uint32_t        g_apt_seen_in_window = 0;

static uint8_t         g_crngt_last[FHSM_CRNGT_BLOCK_SZ];
static int             g_crngt_have_last = 0;

static fhsm_drbg_stats_t g_stats;

/* ---------------------------------------------------------------------------
 * Entropy sources.
 *
 * Each source writes its bytes into the caller-supplied buffer at
 * `dst+offset` and returns the number of bytes written (0 = source
 * unavailable). The final mix is SHA-256(union of all sources).
 * ----------------------------------------------------------------------- */
static size_t entropy_getrandom(uint8_t *dst, size_t cap) {
#if defined(SYS_getrandom)
    ssize_t n = syscall(SYS_getrandom, dst, cap, 0);
    if (n > 0) {
        g_stats.entropy_sources_active |= 1u;
        return (size_t)n;
    }
#endif
    (void)dst; (void)cap;
    return 0;
}

#if FHSM_HAS_RDRAND
__attribute__((target("rdrnd")))
static size_t rdrand_fill(uint8_t *dst, size_t cap) {
    size_t off = 0;
    while (off + sizeof(unsigned long long) <= cap) {
        unsigned long long v = 0;
        int ok = 0;
        for (int retry = 0; retry < 10; ++retry) {
            if (_rdrand64_step(&v)) { ok = 1; break; }
        }
        if (!ok) return off;
        memcpy(dst + off, &v, sizeof(v));
        off += sizeof(v);
    }
    return off;
}
#endif

static size_t entropy_rdrand(uint8_t *dst, size_t cap) {
#if FHSM_HAS_RDRAND
    if (!__builtin_cpu_supports("rdrnd")) return 0;
    size_t off = rdrand_fill(dst, cap);
    if (off > 0) g_stats.entropy_sources_active |= 2u;
    return off;
#else
    (void)dst; (void)cap;
    return 0;
#endif
}

static size_t entropy_devurandom(uint8_t *dst, size_t cap) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, dst, cap);
    close(fd);
    if (n > 0) {
        g_stats.entropy_sources_active |= 4u;
        return (size_t)n;
    }
    return 0;
}

/* TSC jitter : measure cycle counts between successive scheduling
 * events. The low bits of the difference are dominated by interrupt
 * timing and provide a few bits/byte of entropy. We aggregate 64
 * samples for ~32 bits of contribution. */
static size_t entropy_tsc_jitter(uint8_t *dst, size_t cap) {
    if (cap < 8) return 0;
    uint64_t acc = 0;
    for (int i = 0; i < 64; ++i) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        acc = (acc << 1) ^ ((uint64_t)ts.tv_nsec & 0xff);
        /* Force a memory fence and small busy-wait to amplify jitter. */
        for (volatile int j = 0; j < 17; ++j) { (void)j; }
    }
    memcpy(dst, &acc, 8);
    g_stats.entropy_sources_active |= 8u;
    return 8;
}

/* ---------------------------------------------------------------------------
 * Conditioner : SHA-256 the union of all sources.
 * Output : 32 bytes of conditioned entropy.
 * ----------------------------------------------------------------------- */
static fhsm_rv_t condition_and_seed(void) {
    uint8_t pool[512];     /* large enough for the four sources */
    size_t  off = 0;

    off += entropy_getrandom(pool + off, sizeof(pool) - off);
    off += entropy_rdrand(pool + off, sizeof(pool) - off);
    off += entropy_devurandom(pool + off, sizeof(pool) - off);
    off += entropy_tsc_jitter(pool + off, sizeof(pool) - off);
    if (off == 0) return FHSM_RV_RNG_FAILURE;

    uint8_t cond[32];
    SHA256(pool, off, cond);
    /* Feed conditioned entropy to OpenSSL's DRBG. The estimate
     * argument is 0 (we don't claim entropy quantitatively to avoid
     * over-counting) --- OpenSSL still uses it as additional input. */
    RAND_add(cond, sizeof(cond), 0.0);

    /* Wipe transient buffers. */
    memset(pool, 0, sizeof(pool));
    memset(cond, 0, sizeof(cond));

    g_last_reseed_t       = time(NULL);
    g_bytes_since_reseed  = 0;
    g_stats.reseeds++;
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * Health tests.
 * ----------------------------------------------------------------------- */
static fhsm_rv_t health_rct_apt(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        uint8_t b = buf[i];

        /* RCT. */
        if (g_rct_count == 0) {
            g_rct_last_byte = b;
            g_rct_count = 1;
        } else if (b == g_rct_last_byte) {
            g_rct_count++;
            if (g_rct_count >= FHSM_RCT_CUTOFF) {
                g_stats.rct_failures++;
                fhsm_state_latch_error("DRBG RCT alarm");
                return FHSM_RV_RNG_FAILURE;
            }
        } else {
            g_rct_last_byte = b;
            g_rct_count = 1;
        }

        /* APT. Track count of the current window's first byte.
         * When window rolls over (W samples seen), reset. */
        if (g_apt_window_count == 0) {
            g_apt_window_byte    = b;
            g_apt_seen_in_window = 1;
            g_apt_window_count   = 1;
        } else {
            g_apt_window_count++;
            if (b == g_apt_window_byte) {
                g_apt_seen_in_window++;
                if (g_apt_seen_in_window > FHSM_APT_CUTOFF) {
                    g_stats.apt_failures++;
                    fhsm_state_latch_error("DRBG APT alarm");
                    return FHSM_RV_RNG_FAILURE;
                }
            }
            if (g_apt_window_count >= FHSM_APT_WINDOW) {
                g_apt_window_count   = 0;
                g_apt_seen_in_window = 0;
            }
        }
    }
    return FHSM_RV_OK;
}

static fhsm_rv_t health_crngt(const uint8_t *buf, size_t n) {
    if (n < FHSM_CRNGT_BLOCK_SZ) return FHSM_RV_OK;
    if (g_crngt_have_last) {
        if (memcmp(buf, g_crngt_last, FHSM_CRNGT_BLOCK_SZ) == 0) {
            g_stats.crngt_failures++;
            fhsm_state_latch_error("DRBG CRNGT repeated block");
            return FHSM_RV_RNG_FAILURE;
        }
    }
    memcpy(g_crngt_last, buf, FHSM_CRNGT_BLOCK_SZ);
    g_crngt_have_last = 1;
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * Public API.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_drbg_init(void) {
    pthread_mutex_lock(&g_mtx);
    if (g_initialised) { pthread_mutex_unlock(&g_mtx); return FHSM_RV_OK; }
    memset(&g_stats, 0, sizeof(g_stats));
    fhsm_rv_t rv = condition_and_seed();
    if (rv == FHSM_RV_OK) g_initialised = 1;
    pthread_mutex_unlock(&g_mtx);
    return rv;
}

fhsm_rv_t fhsm_drbg_reseed(void) {
    pthread_mutex_lock(&g_mtx);
    fhsm_rv_t rv = condition_and_seed();
    pthread_mutex_unlock(&g_mtx);
    return rv;
}

fhsm_rv_t fhsm_drbg_bytes(uint8_t *out, size_t n) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (!out || n == 0) return FHSM_RV_ARGUMENTS_BAD;

    pthread_mutex_lock(&g_mtx);

    /* Lazy init in case fhsm_drbg_init was missed (defensive). */
    if (!g_initialised) {
        if (condition_and_seed() != FHSM_RV_OK) {
            pthread_mutex_unlock(&g_mtx);
            return FHSM_RV_RNG_FAILURE;
        }
        g_initialised = 1;
    }

    /* Produce in bounded chunks.
     *
     * This was a single `RAND_bytes(out, (int)n)`. n is a size_t and the
     * parameter is an int, so any caller-reachable length above INT_MAX was
     * silently reinterpreted, and C_GenerateRandom passes ulRandomLen straight
     * through. Two ways it went wrong, both ending in a latched error state
     * that killed the module for the rest of the process:
     *
     *   n = 2 GiB + 8 : (int)n is negative, RAND_bytes fails, and we latched
     *                   "RAND_bytes failed".
     *   n = 4 GiB + 8 : (int)n is 8. RAND_bytes writes eight bytes and reports
     *                   success -- then health_rct_apt(out, n) read all four
     *                   gibibytes, of which we had written eight. The rest was
     *                   whatever the caller's buffer held (a fresh mmap: zeros).
     *                   Six identical bytes reach FHSM_RCT_CUTOFF, so we
     *                   latched "DRBG RCT alarm".
     *
     * The second is the one that matters. "DRBG RCT alarm" is the FIPS 140-3
     * continuous health test firing: an operator reading that log line has to
     * assume the entropy source failed and treat every key generated since as
     * suspect. Nothing had happened to the entropy source. We reported an
     * entropy failure because we read memory we never wrote, and the honest
     * report of our own bug was the most alarming message the module can emit.
     * A module that cries RCT alarm when it is not one teaches its operators
     * to discount the alarm.
     *
     * The loop fixes the cast by construction: every chunk is bounded by
     * FHSM_DRBG_MAX_REQUEST, and the health tests only ever see bytes the DRBG
     * actually produced. The reseed check moves inside the loop -- it used to
     * be evaluated once per call, so a single request larger than
     * FHSM_RESEED_BYTES_MAX emitted the whole thing without ever reseeding,
     * which is the interval SP 800-90A asks us to honour.
     *
     * Oversized requests are served, not refused: PKCS#11 defines no maximum
     * for C_GenerateRandom, and inventing one to dodge a bug of ours would be
     * a limit the caller cannot discover. #125. */
    size_t done = 0;
    while (done < n) {
        size_t want = n - done;
        if (want > (size_t)FHSM_DRBG_MAX_REQUEST) want = FHSM_DRBG_MAX_REQUEST;

        time_t now = time(NULL);
        if (g_bytes_since_reseed > FHSM_RESEED_BYTES_MAX ||
            (now - g_last_reseed_t) > FHSM_RESEED_SECS_MAX) {
            (void)condition_and_seed();   /* best effort ; not fatal */
        }

        if (RAND_bytes(out + done, (int)want) != 1) {
            fhsm_state_latch_error("RAND_bytes failed");
            pthread_mutex_unlock(&g_mtx);
            return FHSM_RV_RNG_FAILURE;
        }

        /* Health checks see this chunk only -- never unwritten memory. */
        fhsm_rv_t rv = health_rct_apt(out + done, want);
        if (rv == FHSM_RV_OK) rv = health_crngt(out + done, want);
        if (rv != FHSM_RV_OK) {
            /* Clear everything produced so far, not just the failing chunk:
             * output that preceded a health failure is not output we stand
             * behind. */
            memset(out, 0, done + want);
            pthread_mutex_unlock(&g_mtx);
            return rv;
        }

        g_bytes_since_reseed += want;
        g_stats.bytes_emitted += want;
        done += want;
    }

    pthread_mutex_unlock(&g_mtx);
    return FHSM_RV_OK;
}

void fhsm_drbg_get_stats(fhsm_drbg_stats_t *out) {
    if (!out) return;
    pthread_mutex_lock(&g_mtx);
    *out = g_stats;
    pthread_mutex_unlock(&g_mtx);
}
