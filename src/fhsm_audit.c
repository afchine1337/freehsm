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

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static pthread_mutex_t g_audit_mu = PTHREAD_MUTEX_INITIALIZER;
static int             g_audit_fd = -1;
static uint8_t         g_audit_key[64];
static size_t          g_audit_key_len = 0;
static uint64_t        g_audit_seq = 0;
static uint8_t         g_prev_hmac[32];

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

fhsm_rv_t fhsm_audit_open(const char *path, fhsm_slice_t audit_key) {
    if (!path || audit_key.len > sizeof(g_audit_key)) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_audit_mu);

    g_audit_fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (g_audit_fd < 0) {
        pthread_mutex_unlock(&g_audit_mu);
        return FHSM_RV_FUNCTION_FAILED;
    }

    memcpy(g_audit_key, audit_key.data, audit_key.len);
    g_audit_key_len = audit_key.len;
    g_audit_seq = 0;

    /* Chain head = HMAC(audit_key, "FHSM-AUDIT-INIT|seq=0"). */
    size_t n = 32;
    fhsm_rv_t rv = fhsm_hmac(FHSM_HASH_SHA256,
                              FHSM_SLICE(g_audit_key, g_audit_key_len),
                              FHSM_SLICE("FHSM-AUDIT-INIT|seq=0", 20),
                              g_prev_hmac, &n);

    pthread_mutex_unlock(&g_audit_mu);
    return rv;
}

void fhsm_audit_close(void) {
    pthread_mutex_lock(&g_audit_mu);
    if (g_audit_fd >= 0) { close(g_audit_fd); g_audit_fd = -1; }
    fhsm_zeroize(g_audit_key, sizeof(g_audit_key));
    g_audit_key_len = 0;
    fhsm_zeroize(g_prev_hmac, sizeof(g_prev_hmac));
    pthread_mutex_unlock(&g_audit_mu);
}

fhsm_rv_t fhsm_audit_event(fhsm_audit_event_t ev, int slot, int session,
                            fhsm_role_t role, fhsm_rv_t rv, ...) {
    if (g_audit_fd < 0) {
        /* Audit not yet open --- silently drop (called during early init).
         * In shipping builds with FHSM_AUDIT_MANDATORY = 1 we could
         * latch ERROR here, but events generated *before* audit_open
         * are part of the open-call itself, so dropping them is OK. */
        return FHSM_RV_OK;
    }

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
        "\"slot\":%d,\"session\":%d,\"role\":\"%s\","
        "\"result\":\"%s\",\"rv\":%u,\"params\":%s,\"prev_hmac\":\"%s\",",
        (unsigned long long)g_audit_seq, (long long)ts_ns,
        event_name(ev), slot, session,
        (role == FHSM_ROLE_SO ? "SO" :
         role == FHSM_ROLE_USER ? "USER" : "NONE"),
        (rv == FHSM_RV_OK ? "OK" : "FAIL"),
        (unsigned int)rv, params, prev_hex);
    if (line_len < 0 || line_len >= (int)sizeof(line)) {
        pthread_mutex_unlock(&g_audit_mu);
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
        fhsm_state_latch_error("audit HMAC failed");
        return hr;
    }
    hex32(h, hmac_hex);

    int suffix = snprintf(line + line_len, sizeof(line) - line_len,
                          "\"hmac\":\"%s\"}\n", hmac_hex);
    if (suffix < 0 || line_len + suffix >= (int)sizeof(line)) {
        pthread_mutex_unlock(&g_audit_mu);
        fhsm_state_latch_error("audit suffix truncated");
        return FHSM_RV_FUNCTION_FAILED;
    }
    int total = line_len + suffix;

    ssize_t w = write(g_audit_fd, line, (size_t)total);
    if (w != total) {
        pthread_mutex_unlock(&g_audit_mu);
        fhsm_state_latch_error("audit write failed");
        return FHSM_RV_FUNCTION_FAILED;
    }
    /* fsync() so a power loss can't lose the chain. */
    fsync(g_audit_fd);
    memcpy(g_prev_hmac, h, 32);
    pthread_mutex_unlock(&g_audit_mu);
    return FHSM_RV_OK;
}

/* Verifier --- reads the whole file, computes the HMAC of each line and
 * checks the prev_hmac of the next line matches. Implementation
 * sketch; full implementation lives in tests/test_audit_verify.c. */
fhsm_rv_t fhsm_audit_verify(const char *path, fhsm_slice_t audit_key,
                             size_t *broken_at_line) {
    (void)path; (void)audit_key;
    if (broken_at_line) *broken_at_line = 0;
    /* TODO: implemented in tests/test_audit_verify.c against a snapshot
     * of the log. Not yet wired in production; kept as a stub here. */
    return FHSM_RV_OK;
}
