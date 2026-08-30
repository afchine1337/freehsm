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
 * fhsm_audit.c --- Append-only audit log with HMAC chaining.
 *
 * Events are serialized as one JSON object per line and HMAC-chained
 * (prev_hmac of line N+1 == hmac of line N). The HMAC key is supplied
 * by the token (HKDF-derived from the DEK). On any write failure, the
 * module ERROR state is latched.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_audit.h"
#include "fhsm_crypto.h"
#include "fhsm_drbg.h"
#include "fhsm_tpm.h"
#include "fhsm_token_tpm.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>

static pthread_mutex_t g_audit_mu = PTHREAD_MUTEX_INITIALIZER;
static int             g_audit_fd = -1;
static uint8_t         g_audit_key[64];
static size_t          g_audit_key_len = 0;
static uint64_t        g_audit_seq = 0;
static uint8_t         g_prev_hmac[32];

/* See fhsm_audit_set_actor(). Thread-local: the service serves one request
 * per thread, and attributing a line to the wrong client would be worse
 * than not attributing it at all. */
static _Thread_local char g_actor[FHSM_AUDIT_ACTOR_MAX];

/* ---------------------------------------------------------------------------
 * Group commit.
 *
 * Every event must be durable before the operation that caused it returns --
 * a signature must not reach a client before the record of it is on disk.
 * That is not negotiable and is argued in docs/AUDIT_DURABILITY.md.
 *
 * What IS negotiable is how many barriers it takes. One fsync serves every
 * write already in the file, so a writer that arrives while a barrier is in
 * flight can wait for the next one instead of queueing its own -- and still
 * return only after a barrier that covered its own write. Measured at eight
 * concurrent writers: 1469 lines/s against 363, 118 barriers for 480 lines,
 * with the guarantee unchanged.
 *
 * `wanted` counts writes that have landed in the file and are waiting for a
 * barrier. A syncer takes the current value as the generation it will cover,
 * drops the mutex, calls fsync, and publishes that generation. A writer waits
 * until `done` reaches its own number. Writes that land DURING a barrier get a
 * higher number and are conservatively not counted as covered by it.
 *
 * `failed` is sticky: a barrier that fails latches the module into ERROR, and
 * every writer waiting behind it must fail too rather than believe a barrier
 * that did not happen.
 * ------------------------------------------------------------------------- */
static pthread_cond_t  g_sync_cv     = PTHREAD_COND_INITIALIZER;
static unsigned long   g_sync_wanted = 0;
static unsigned long   g_sync_done   = 0;
static int             g_syncing     = 0;
static int             g_sync_failed = 0;
static uint64_t        g_stat_events   = 0;   /* diagnostics only */
static uint64_t        g_stat_barriers = 0;
static char            g_audit_path[600];   /* the file actually opened */

static const char *event_name(fhsm_audit_event_t ev) {
    switch (ev) {
        case FHSM_EV_MODULE_INIT:      return "module_init";
        case FHSM_EV_MODULE_FINALIZE:  return "module_finalize";
        case FHSM_EV_KAT_REPORT:       return "kat_report";
        case FHSM_EV_INTEGRITY_OK:     return "integrity_ok";
        case FHSM_EV_INTEGRITY_FAIL:   return "integrity_fail";
        case FHSM_EV_STATE_TRANSITION: return "state_transition";
        case FHSM_EV_TOKEN_INIT:       return "token_init";
        case FHSM_EV_TOKEN_REINIT:     return "token_reinit";
        case FHSM_EV_LOGIN_OK:         return "login_ok";
        case FHSM_EV_LOGIN_FAIL:       return "login_fail";
        case FHSM_EV_LOGIN_LOCKED:     return "login_locked";
        case FHSM_EV_LOGIN_THROTTLED:  return "login_throttled";
        case FHSM_EV_LOGOUT:           return "logout";
        case FHSM_EV_SET_PIN:          return "set_pin";
        case FHSM_EV_DEK_ROTATION:     return "dek_rotation";
        case FHSM_EV_OBJECT_CREATE:    return "object_create";
        case FHSM_EV_OBJECT_DESTROY:   return "object_destroy";
        case FHSM_EV_OBJECT_FIND:      return "object_find";
        case FHSM_EV_ENCRYPT:          return "encrypt";
        case FHSM_EV_DECRYPT:          return "decrypt";
        case FHSM_EV_SIGN:             return "sign";
        case FHSM_EV_VERIFY:           return "verify";
        case FHSM_EV_WRAP:             return "wrap";
        case FHSM_EV_UNWRAP:           return "unwrap";
        case FHSM_EV_DERIVE:           return "derive";
        case FHSM_EV_GENERATE_KEY:     return "generate_key";
        case FHSM_EV_GENERATE_KEYPAIR: return "generate_keypair";
        case FHSM_EV_DIGEST:           return "digest";
        case FHSM_EV_RNG_RESEED:       return "rng_reseed";
        case FHSM_EV_SEAL_SUCCESS:     return "seal_success";
        case FHSM_EV_SEAL_FAILURE:     return "seal_failure";
        case FHSM_EV_UNSEAL_SUCCESS:   return "unseal_success";
        case FHSM_EV_UNSEAL_FAILURE:   return "unseal_failure";
        case FHSM_EV_SERVICE_START:    return "service_start";
        case FHSM_EV_SERVICE_STOP:     return "service_stop";
        case FHSM_EV_REQUEST_ACCEPTED: return "request_accepted";
        case FHSM_EV_REQUEST_REFUSED:  return "request_refused";
        case FHSM_EV_IDENTITY_RESUMED: return "identity_resumed";
        case FHSM_EV_IDENTITY_LIMITED: return "identity_limited";
        default:                       return "unknown";
    }
}

/* Render 32 bytes as 64 hex chars (no NUL). out must hold 64 bytes. */
static void hex32(const uint8_t *in, char *out) {
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[2*i]   = d[(in[i] >> 4) & 0xf];
        out[2*i+1] = d[in[i] & 0xf];
    }
}

/* Reject any non-safe-ASCII byte (newline, quote, control, > 0x7E) so
 * the JSON line is unambiguously parseable. Returns 1 if OK. */
static int safe_ascii(const char *s) {
    if (!s) return 0;
    for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
        if (*p < 0x20 || *p > 0x7e || *p == '"' || *p == '\\') return 0;
    }
    return 1;
}

/* Set the actor for this thread. See the header for why it is thread-local
 * and why the input is treated as hostile: it arrives in an HTTP header, and
 * a quote or a backslash in it would let the caller write JSON into a line
 * that is supposed to describe them. Rejected wholesale rather than escaped
 * -- an audit line saying INVALID is readable, one that has been repaired is
 * a line whose meaning depends on the repair. */
void fhsm_audit_set_actor(const char *subject) {
    if (!subject) { fhsm_zeroize(g_actor, sizeof g_actor); return; }
    char tmp[FHSM_AUDIT_ACTOR_MAX];
    snprintf(tmp, sizeof tmp, "%s", subject);
    if (!safe_ascii(tmp)) {
        snprintf(g_actor, sizeof g_actor, "INVALID");
        return;
    }
    memcpy(g_actor, tmp, sizeof tmp);
}

/* --- the chaining key -----------------------------------------------------
 * See fhsm_audit.h for why it is its own key and not the token DEK, and for
 * what the two storage paths do and do not protect. */

static fhsm_rv_t key_read_file(const char *p, uint8_t key[32]) {
    struct stat st;
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return FHSM_RV_FUNCTION_FAILED;

    /* Refuse a key anyone else can read. Continuing would produce a log that
     * looks authenticated and is not, which is worse than no log: the first
     * invites trust, the second does not. */
    if (fstat(fd, &st) != 0 || (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        close(fd);
        return FHSM_RV_FUNCTION_FAILED;
    }
    if (st.st_size != 32) { close(fd); return FHSM_RV_FUNCTION_FAILED; }

    ssize_t n = read(fd, key, 32);
    close(fd);
    return (n == 32) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

static fhsm_rv_t key_write_file(const char *p, const uint8_t key[32]) {
    /* O_EXCL: two modules starting at once must not both decide they are the
     * one provisioning, or the second would overwrite a key the first has
     * already chained entries with, and every one of those entries becomes
     * unverifiable. The loser re-reads instead. */
    int fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return FHSM_RV_FUNCTION_FAILED;
    ssize_t n = write(fd, key, 32);
    int ok = (n == 32) && (fsync(fd) == 0);
    close(fd);
    if (!ok) { unlink(p); return FHSM_RV_FUNCTION_FAILED; }
    return FHSM_RV_OK;
}

fhsm_rv_t fhsm_audit_key_provision(const char *dir, uint8_t key[32],
                                    int *sealed)
{
    if (!dir || !key) return FHSM_RV_ARGUMENTS_BAD;
    if (sealed) *sealed = 0;

    char plain[512], blob_p[512];
    if (snprintf(plain,  sizeof plain,  "%s/audit.key",     dir) >= (int)sizeof plain ||
        snprintf(blob_p, sizeof blob_p, "%s/audit.key.tpm", dir) >= (int)sizeof blob_p)
        return FHSM_RV_ARGUMENTS_BAD;

    const int want_tpm = fhsm_token_tpm_required();

    /* 1. Recover, if we have provisioned before. The sealed blob wins: if both
     *    exist the operator turned sealing on at some point, and the sealed
     *    one is the stronger statement. */
    if (want_tpm) {
        uint8_t blob[2048];
        int fd = open(blob_p, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t n = read(fd, blob, sizeof blob);
            close(fd);
            if (n > 0) {
                fhsm_rv_t rv = fhsm_tpm_unseal(blob, (size_t)n, key);
                fhsm_zeroize(blob, sizeof blob);
                if (rv == FHSM_RV_OK) { if (sealed) *sealed = 1; return FHSM_RV_OK; }
                /* Unsealing failed with a blob present. Either the boot chain
                 * changed or the TPM is gone. Falling back to a fresh key
                 * would silently start a second chain in the same file and
                 * make the existing entries unverifiable -- which is the
                 * failure this whole task exists to prevent. Refuse. */
                return rv;
            }
        }
    }
    if (key_read_file(plain, key) == FHSM_RV_OK) return FHSM_RV_OK;

    /* 2. First use: generate. The module's own DRBG, not OpenSSL's -- this key
     *    authenticates the record of everything the module does, so it should
     *    come from the generator the module is accountable for. */
    fhsm_rv_t rv = fhsm_drbg_bytes(key, 32);
    if (rv != FHSM_RV_OK) return rv;

    if (want_tpm) {
        uint8_t blob[2048]; size_t bl = 0;
        rv = fhsm_tpm_seal(key, blob, sizeof blob, &bl);
        if (rv == FHSM_RV_OK) {
            int fd = open(blob_p, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            int good = 0;
            if (fd >= 0) {
                good = (write(fd, blob, bl) == (ssize_t)bl) && (fsync(fd) == 0);
                close(fd);
                if (!good) unlink(blob_p);
            }
            fhsm_zeroize(blob, sizeof blob);
            if (good) { if (sealed) *sealed = 1; return FHSM_RV_OK; }
            fhsm_zeroize(key, 32);
            return FHSM_RV_FUNCTION_FAILED;
        }
        /* Sealing was asked for and could not be done. Writing the key in the
         * clear instead would quietly downgrade a control the operator turned
         * on. Refuse and let them see it. */
        fhsm_zeroize(key, 32);
        return rv;
    }

    rv = key_write_file(plain, key);
    if (rv != FHSM_RV_OK) {
        /* Lost a race, most likely. Whoever won wrote a key; use theirs. */
        if (key_read_file(plain, key) == FHSM_RV_OK) return FHSM_RV_OK;
        fhsm_zeroize(key, 32);
        return rv;
    }
    return FHSM_RV_OK;
}

/* Read hex32 back into bytes. Returns 0 on any non-hex digit. */
static int unhex32(const char *in, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) {
        int v = 0;
        for (int k = 0; k < 2; ++k) {
            char c = in[2*i + k];
            int d = (c >= '0' && c <= '9') ? c - '0'
                  : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                  : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
            if (d < 0) return 0;
            v = (v << 4) | d;
        }
        out[i] = (uint8_t)v;
    }
    return 1;
}

/* chain_resume() lived here. It read the tail of an existing log and picked
 * the chain up from the last line, which is what allowed two openings to share
 * one file -- and what let two processes each believe they were the successor
 * of the same line. Logs are now created per opening with O_EXCL, so every
 * file starts at the chain head and there is nothing to resume. The function
 * went with the reason for it. */

/* ---------------------------------------------------------------------------
 * One log per opening.
 *
 * A hash chain has exactly one author by construction, and nothing here
 * required that. Two processes each opened the log, each resumed the chain
 * from the tail of the file, and from then on each believed itself the
 * successor of the same line. Their appends interleaved and the chain was
 * destroyed -- not by an attacker, by two ordinary clients. Sixty lines,
 * broken at the second. Run one after the other, the same two processes
 * produce a chain that verifies, so it is the concurrency and not the resume.
 *
 * Found through `p11-kit server`, which forks a child per client and so makes
 * the situation systematic; but two `fhsm-sign` invocations in a script do the
 * same thing.
 *
 * Three answers were weighed (docs/AUDIT_DURABILITY.md). Refusing the second
 * opening would have made concurrent tools fail, which is normal use. Locking
 * between processes would put a file lock on a path that already costs 3 ms.
 * So: each opening creates its own file, `base.NNNNNN`, with O_EXCL. Every
 * file then has a single author from line 1 and needs no coordination at all.
 *
 * The sequence number is not decoration. With one file, deleting the middle
 * breaks the chain and deleting the tail is undetectable -- a gap already
 * recorded. With per-file logs, deleting a whole file would remove a process's
 * entire history while every remaining chain still verified. Numbering makes
 * that a hole between 6 and 8. Deleting the highest-numbered files leaves no
 * hole, which is the same tail-truncation gap as before: the scheme reproduces
 * the existing limit rather than adding one.
 *
 * A base that already exists and is NOT a regular file -- a FIFO, /dev/null, a
 * character device -- is opened as given, with no numbering and no chain to
 * resume. It is a stream, not a log, and the operator asked for it by naming
 * one.
 * ------------------------------------------------------------------------- */
#define FHSM_AUDIT_SEQ_DIGITS 6

/* Highest NNNNNN already present for this base, or 0 if none. */
static unsigned long audit_highest_seq(const char *base)
{
    char dirbuf[512];
    snprintf(dirbuf, sizeof dirbuf, "%s", base);
    char *slash = strrchr(dirbuf, '/');
    const char *dirname, *leaf;
    if (slash) { *slash = '\0'; dirname = dirbuf; leaf = slash + 1; }
    else       { dirname = "."; leaf = dirbuf; }

    DIR *d = opendir(dirname);
    if (!d) return 0;
    size_t leaflen = strlen(leaf);
    unsigned long best = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, leaf, leaflen) != 0) continue;
        const char *rest = e->d_name + leaflen;
        if (rest[0] != '.' || strlen(rest) != FHSM_AUDIT_SEQ_DIGITS + 1) continue;
        char *end = NULL;
        unsigned long v = strtoul(rest + 1, &end, 10);
        if (end && *end == '\0' && v > best) best = v;
    }
    closedir(d);
    return best;
}

fhsm_rv_t fhsm_audit_open(const char *path, fhsm_slice_t audit_key) {
    if (!path || !audit_key.data || audit_key.len == 0
        || audit_key.len > sizeof(g_audit_key))
        return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_audit_mu);

    int fd = -1;
    int numbered = 1;
    g_audit_path[0] = '\0';

    /* A named stream is used as given -- see the note above. */
    struct stat sb;
    if (stat(path, &sb) == 0 && !S_ISREG(sb.st_mode)) {
        numbered = 0;
        fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
        if (fd >= 0) snprintf(g_audit_path, sizeof g_audit_path, "%s", path);
    } else {
        /* O_EXCL is what makes this file ours alone. On a collision another
         * process took the number between our scan and our create; step past
         * it and try again rather than share. */
        unsigned long next = audit_highest_seq(path) + 1;
        for (int attempt = 0; attempt < 4096 && fd < 0; attempt++, next++) {
            char cand[600];
            snprintf(cand, sizeof cand, "%s.%0*lu", path,
                     FHSM_AUDIT_SEQ_DIGITS, next);
            fd = open(cand, O_RDWR | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (fd >= 0) snprintf(g_audit_path, sizeof g_audit_path, "%s", cand);
            if (fd < 0 && errno != EEXIST) break;
        }
    }
    if (fd < 0) {
        pthread_mutex_unlock(&g_audit_mu);
        return FHSM_RV_FUNCTION_FAILED;
    }
    (void)numbered;

    memcpy(g_audit_key, audit_key.data, audit_key.len);
    g_audit_key_len = audit_key.len;

    /* The chain always starts at its head. The file is either brand new,
     * because O_EXCL created it, or a stream that cannot be read back. There
     * is nothing to resume, which is why chain_resume no longer has a caller:
     * resuming existed only to share one file between openings, and that is
     * the thing this change removes.
     *
     * Chain head = HMAC(audit_key, "FHSM-AUDIT-INIT|seq=0"). The length used
     * to be 20 for a 21-character string, so the final '0' was cut and the
     * head matched neither the comment above it nor the format the header
     * documents. Nobody could notice: no log was ever written, and the
     * verifier that would have disagreed was a stub returning OK. */
    static const char INIT[] = "FHSM-AUDIT-INIT|seq=0";
    size_t nh = 32;
    g_audit_seq = 0;
    fhsm_rv_t rv = fhsm_hmac(FHSM_HASH_SHA256,
                              FHSM_SLICE(g_audit_key, g_audit_key_len),
                              FHSM_SLICE(INIT, sizeof INIT - 1),
                              g_prev_hmac, &nh);

    if (rv != FHSM_RV_OK) {
        close(fd);
        fhsm_zeroize(g_audit_key, sizeof g_audit_key);
        g_audit_key_len = 0;
        pthread_mutex_unlock(&g_audit_mu);
        return rv;
    }

    g_audit_fd = fd;
    pthread_mutex_unlock(&g_audit_mu);
    return FHSM_RV_OK;
}

void fhsm_audit_close(void) {
    pthread_mutex_lock(&g_audit_mu);
    /* A barrier runs with the mutex released and a copy of the descriptor. If
     * we closed it here the fsync would land on a descriptor number the kernel
     * may already have handed to something else. Wait for it. */
    while (g_syncing) pthread_cond_wait(&g_sync_cv, &g_audit_mu);
    if (g_audit_fd >= 0) { close(g_audit_fd); g_audit_fd = -1; }
    g_sync_wanted = g_sync_done = 0;
    g_sync_failed = 0;
    fhsm_zeroize(g_audit_key, sizeof(g_audit_key));
    g_audit_key_len = 0;
    fhsm_zeroize(g_prev_hmac, sizeof(g_prev_hmac));
    g_audit_path[0] = '\0';
    pthread_mutex_unlock(&g_audit_mu);
}

/* How many events were written and how many durable barriers that took.
 * Diagnostics: it is what makes "the barrier is shared" observable from
 * outside, and a test that cannot observe it cannot assert it. */
/* The file this process is writing to. Not the path handed to
 * fhsm_audit_open: that is a base, and the opening picked the next free
 * sequence number under it. An operator reviewing the log, and a test
 * inspecting it, both need to be told which file it actually is rather than
 * reconstruct the naming rule. */
size_t fhsm_audit_current_path(char *out, size_t cap) {
    pthread_mutex_lock(&g_audit_mu);
    size_t n = strlen(g_audit_path);
    if (out && cap) { snprintf(out, cap, "%s", g_audit_path); }
    pthread_mutex_unlock(&g_audit_mu);
    return n;
}

/* Whether this build lets the log be switched off. A compile-time decision
 * that nothing could observe was the previous state of FHSM_AUDIT_MANDATORY,
 * and it is how the constant stayed aspirational for so long. */
int fhsm_audit_mandatory(void) { return FHSM_AUDIT_MANDATORY ? 1 : 0; }

void fhsm_audit_barrier_stats(uint64_t *events, uint64_t *barriers) {
    pthread_mutex_lock(&g_audit_mu);
    if (events)   *events   = g_stat_events;
    if (barriers) *barriers = g_stat_barriers;
    pthread_mutex_unlock(&g_audit_mu);
}

/* Re-entrance guard.
 *
 * A failed write calls fhsm_state_latch_error, which emits a
 * state_transition event, whose write also fails, which latches again. That
 * is unbounded recursion and it ends in a stack overflow -- measured, as a
 * SIGSEGV, the first time a write was ever made to fail.
 *
 * Per-thread rather than global: a concurrent, healthy write on another
 * thread has no reason to be dropped because this one is failing.
 *
 * Dropping the nested entry is the right answer and not merely the easy one.
 * The nested event exists to record that we could not write; there is by
 * definition nowhere to record it. What survives is the ERROR state itself,
 * which is what stops the module. */
static __thread int g_in_event = 0;

fhsm_rv_t fhsm_audit_event(fhsm_audit_event_t ev, int slot, int session,
                            fhsm_role_t role, fhsm_rv_t rv, ...) {
    if (g_in_event) return FHSM_RV_FUNCTION_FAILED;
    if (g_audit_fd < 0) {
        /* Audit not yet open --- silently drop (called during early init).
         * In shipping builds with FHSM_AUDIT_MANDATORY = 1 we could
         * latch ERROR here, but events generated *before* audit_open
         * are part of the open-call itself, so dropping them is OK. */
        return FHSM_RV_OK;
    }

    g_in_event = 1;
    char line[2048];
    char hmac_hex[65]; hmac_hex[64] = '\0';
    char prev_hex[65]; prev_hex[64] = '\0';

    /* Build the line --- prev_hmac filled in from g_prev_hmac, hmac
     * computed after the rest is serialized. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int64_t ts_ns = (int64_t)ts.tv_sec * 1000000000ll + ts.tv_nsec;

    pthread_mutex_lock(&g_audit_mu);
    g_audit_seq++;
    hex32(g_prev_hmac, prev_hex);

    /* Variadic key/value params --- copied verbatim, only safe-ASCII
     * accepted. Length-only convention: callers never pass key material. */
    va_list ap; va_start(ap, rv);
    char params[1024]; size_t pp = 0;
    int first = 1;
    params[pp++] = '{';
    while (1) {
        const char *k = va_arg(ap, const char*);
        if (!k) break;
        const char *v = va_arg(ap, const char*);
        if (!safe_ascii(k) || !safe_ascii(v)) {
            v = "INVALID";
        }
        int n = snprintf(params + pp, sizeof(params) - pp,
                          "%s\"%s\":\"%s\"", first ? "" : ",", k, v);
        if (n < 0 || (size_t)n >= sizeof(params) - pp) {
            pp = 0; /* truncate --- evaluator sees an empty params object */
            break;
        }
        pp += (size_t)n;
        first = 0;
    }
    va_end(ap);
    if (pp == 0) {
        params[0] = '{'; params[1] = '}'; pp = 2;
    } else {
        if (pp < sizeof(params) - 1) { params[pp++] = '}'; }
    }
    params[pp] = '\0';

    int line_len = snprintf(line, sizeof(line),
        "{\"seq\":%llu,\"ts\":%lld,\"event\":\"%s\","
        "\"slot\":%d,\"session\":%d,\"role\":\"%s\",\"actor\":\"%s\","
        "\"result\":\"%s\",\"rv\":%u,\"params\":%s,\"prev_hmac\":\"%s\",",
        (unsigned long long)g_audit_seq, (long long)ts_ns,
        event_name(ev), slot, session,
        (role == FHSM_ROLE_SO ? "SO" :
         role == FHSM_ROLE_USER ? "USER" : "NONE"),
        g_actor,
        (rv == FHSM_RV_OK ? "OK" : "FAIL"),
        (unsigned int)rv, params, prev_hex);
    if (line_len < 0 || line_len >= (int)sizeof(line)) {
        pthread_mutex_unlock(&g_audit_mu);
        g_in_event = 0;
        fhsm_state_latch_error("audit line truncated");
        return FHSM_RV_FUNCTION_FAILED;
    }

    /* Compute hmac of the line as currently formatted (everything before
     * the final ",\"hmac\":...\"" suffix). */
    uint8_t h[32]; size_t hl = sizeof(h);
    fhsm_rv_t hr = fhsm_hmac(FHSM_HASH_SHA256,
                              FHSM_SLICE(g_audit_key, g_audit_key_len),
                              FHSM_SLICE(line, line_len),
                              h, &hl);
    if (hr != FHSM_RV_OK) {
        pthread_mutex_unlock(&g_audit_mu);
        g_in_event = 0;
        fhsm_state_latch_error("audit HMAC failed");
        return hr;
    }
    hex32(h, hmac_hex);

    int suffix = snprintf(line + line_len, sizeof(line) - line_len,
                          "\"hmac\":\"%s\"}\n", hmac_hex);
    if (suffix < 0 || line_len + suffix >= (int)sizeof(line)) {
        pthread_mutex_unlock(&g_audit_mu);
        g_in_event = 0;
        fhsm_state_latch_error("audit suffix truncated");
        return FHSM_RV_FUNCTION_FAILED;
    }
    int total = line_len + suffix;

    ssize_t w = write(g_audit_fd, line, (size_t)total);
    if (w != total) {
        pthread_mutex_unlock(&g_audit_mu);
        g_in_event = 0;
        fhsm_state_latch_error("audit write failed");
        return FHSM_RV_FUNCTION_FAILED;
    }
    /* The chain advances BEFORE the barrier, and that ordering is the whole
     * reason this is delicate. The mutex is released while the fsync runs, so
     * another writer will take the lock and read g_prev_hmac -- if it still
     * held the previous value the two lines would claim the same predecessor
     * and the chain would be broken by the optimisation meant to be invisible.
     * The line is already in the file, and a failed barrier stops the module,
     * so advancing here costs nothing. */
    memcpy(g_prev_hmac, h, 32);
    g_stat_events++;

    /* Wait for a barrier that covers this write. See the note on group commit
     * where g_sync_wanted is declared. */
    unsigned long need = ++g_sync_wanted;
    while (g_sync_done < need && !g_sync_failed) {
        if (!g_syncing) {
            unsigned long covering = g_sync_wanted;
            int fd = g_audit_fd;
            g_syncing = 1;
            pthread_mutex_unlock(&g_audit_mu);
            /* fdatasync, not fsync: measured marginally cheaper and it means
             * the same thing for an append-only file, where the size change is
             * metadata the call has to flush anyway for the data to be
             * retrievable. Worth ~10 % and free. */
            int sr = fdatasync(fd);
            pthread_mutex_lock(&g_audit_mu);
            g_stat_barriers++;
            g_syncing = 0;
            if (sr != 0)                    g_sync_failed = 1;
            else if (g_sync_done < covering) g_sync_done = covering;
            pthread_cond_broadcast(&g_sync_cv);
        } else {
            pthread_cond_wait(&g_sync_cv, &g_audit_mu);
        }
    }
    if (g_sync_failed) {
        pthread_mutex_unlock(&g_audit_mu);
        g_in_event = 0;
        /* The write() above was checked and latched ERROR on failure; the
         * fsync() was called and its answer thrown away. On most filesystems a
         * deferred write error is reported at fsync and nowhere else, so the
         * one control the log has against losing entries was wired to the call
         * that usually succeeds and not to the one that usually reports. Both
         * fsyncs in the key-provisioning code above are checked; this was the
         * third and the only one that was not. */
        fhsm_state_latch_error("audit fsync failed");
        return FHSM_RV_FUNCTION_FAILED;
    }
    pthread_mutex_unlock(&g_audit_mu);
    g_in_event = 0;
    return FHSM_RV_OK;
}

/* Verifier --- reads the whole file, computes the HMAC of each line and
 * checks the prev_hmac of the next line matches. Implementation
 * sketch; full implementation lives in tests/test_audit_verify.c. */
/* Walk the chain.
 *
 * This was a stub that returned FHSM_RV_OK without looking at its arguments,
 * pointing at a tests/test_audit_verify.c that did not exist. Any caller
 * verifying a log through this function was told "intact" about any file at
 * all, including a forged one -- which is worse than having no verifier, since
 * a verifier that always agrees invites the trust it cannot justify.
 *
 * Three checks per line, and all three are needed:
 *
 *   1. The recorded HMAC matches the line. Catches modification.
 *   2. `prev_hmac` equals the previous line's `hmac` -- the init head for the
 *      first line. Catches deletion, insertion and reordering, which check 1
 *      alone cannot: with this format every line authenticates itself, so a
 *      removed line leaves the survivors individually valid.
 *   3. `seq` equals the line number. This catches a record removed from the
 *      middle by a forger who also renumbered, and nothing more.
 *
 * What none of the three catches, and cannot: truncation at the end. Cut the
 * last k records off and what remains is a shorter chain, perfectly linked,
 * with seq still matching position -- indistinguishable from a log that simply
 * stopped there. No check confined to the file can tell those apart, because
 * they are the same file.
 *
 * Closing it needs an anchor the forger does not control: the last seq and
 * hmac, themselves authenticated, kept somewhere else -- a companion file
 * updated on every write, or a log shipped off the host. The companion file
 * costs one more fsync per event, which on the measurement in
 * docs/TOKEN_STORE_FORMAT.md is about 2.7 ms. Recorded in docs/ROADMAP.md
 * with that price attached rather than chosen here.
 *
 * tools/freehsm-audit deliberately reimplements this rather than linking the
 * module: an auditor should be able to build the verifier alone, and a check
 * that shares code with the thing it checks is a mirror. The price is that the
 * two can drift -- they had, in three separate ways -- so
 * tests/test_audit_verify.c runs both against the same real log.
 */
fhsm_rv_t fhsm_audit_verify(const char *path, fhsm_slice_t audit_key,
                             size_t *broken_at_line) {
    if (broken_at_line) *broken_at_line = 0;
    if (!path || !audit_key.data || audit_key.len == 0)
        return FHSM_RV_ARGUMENTS_BAD;

    FILE *f = fopen(path, "r");
    if (!f) return FHSM_RV_FUNCTION_FAILED;

    static const char INIT[] = "FHSM-AUDIT-INIT|seq=0";
    uint8_t expect_prev[32]; size_t hl = 32;
    fhsm_rv_t rv = fhsm_hmac(FHSM_HASH_SHA256, audit_key,
                              FHSM_SLICE(INIT, sizeof INIT - 1),
                              expect_prev, &hl);
    if (rv != FHSM_RV_OK) { fclose(f); return rv; }

    char line[4096];
    size_t n = 0;
    while (fgets(line, sizeof line, f)) {
        n++;
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n') line[--len] = '\0';

        const char *h = strstr(line, "\"hmac\":\"");
        const char *p = strstr(line, "\"prev_hmac\":\"");
        const char *s = strstr(line, "\"seq\":");
        if (!h || !p || !s) goto broken;
        if ((size_t)(h + 8 + 64 - line) > len) goto broken;

        uint8_t recorded[32], recomputed[32], prev_field[32];
        if (!unhex32(h + 8, recorded))  goto broken;
        if (!unhex32(p + 13, prev_field)) goto broken;

        size_t body = (size_t)(h - line);
        size_t rl = 32;
        rv = fhsm_hmac(FHSM_HASH_SHA256, audit_key,
                        FHSM_SLICE(line, body), recomputed, &rl);
        if (rv != FHSM_RV_OK) { fclose(f); return rv; }

        if (memcmp(recomputed, recorded, 32) != 0) goto broken;
        if (memcmp(prev_field, expect_prev, 32) != 0) goto broken;
        if (strtoull(s + 6, NULL, 10) != (unsigned long long)n) goto broken;

        memcpy(expect_prev, recorded, 32);
        continue;
broken:
        if (broken_at_line) *broken_at_line = n;
        fclose(f);
        return FHSM_RV_SIGNATURE_INVALID;
    }

    fclose(f);
    return FHSM_RV_OK;
}
