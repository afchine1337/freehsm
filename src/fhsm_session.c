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
 * fhsm_session.c --- Session table.
 *
 * Pure book-keeping : sessions hold a slot id, the open flags, the
 * authenticated role, and a pointer to the slot's token. The token
 * lives in fhsm_token.c; multiple sessions share the same token but
 * each is independent at the PKCS#11 level (operations, find-results).
 *
 * Allocated count is bounded by FHSM_MAX_SESSIONS (compile-time, default
 * 128). Beyond that, C_OpenSession returns FHSM_RV_HOST_MEMORY.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_session.h"
#include "fhsm_session.h"
#include "fhsm_token.h"

#include <pthread.h>
#include <string.h>

#ifndef FHSM_MAX_SESSIONS
#define FHSM_MAX_SESSIONS 128
#endif

typedef struct fhsm_session_s {
    int            in_use;
    unsigned long  slot;
    unsigned long  flags;
    fhsm_role_t    role;
    fhsm_token_t  *token;
} fhsm_session_entry_t;

static pthread_mutex_t      g_sess_mu = PTHREAD_MUTEX_INITIALIZER;
static fhsm_session_entry_t g_sessions[FHSM_MAX_SESSIONS];

fhsm_rv_t fhsm_session_open(unsigned long slot, unsigned long flags,
                              unsigned long *out_handle) {
    pthread_mutex_lock(&g_sess_mu);
    for (size_t i = 1; i < FHSM_MAX_SESSIONS; ++i) {  /* skip index 0 */
        if (!g_sessions[i].in_use) {
            g_sessions[i].in_use = 1;
            g_sessions[i].slot   = slot;
            g_sessions[i].flags  = flags;
            g_sessions[i].role   = FHSM_ROLE_NONE;
            g_sessions[i].token  = NULL;   /* attached at login */
            pthread_mutex_unlock(&g_sess_mu);
            *out_handle = i;
            return FHSM_RV_OK;
        }
    }
    pthread_mutex_unlock(&g_sess_mu);
    return FHSM_RV_HOST_MEMORY;
}

fhsm_rv_t fhsm_session_close(unsigned long h) {
    if (h == 0 || h >= FHSM_MAX_SESSIONS) return FHSM_RV_SESSION_HANDLE_INVALID;
    pthread_mutex_lock(&g_sess_mu);
    if (!g_sessions[h].in_use) {
        pthread_mutex_unlock(&g_sess_mu);
        return FHSM_RV_SESSION_HANDLE_INVALID;
    }
    /* zeroize the entry so a stale handle cannot inherit residual state */
    fhsm_zeroize(&g_sessions[h], sizeof(g_sessions[h]));
    pthread_mutex_unlock(&g_sess_mu);
    return FHSM_RV_OK;
}

fhsm_rv_t fhsm_session_login(unsigned long h, fhsm_role_t role,
                               const char *pin, size_t pin_len) {
    (void)pin_len;
    if (h == 0 || h >= FHSM_MAX_SESSIONS) return FHSM_RV_SESSION_HANDLE_INVALID;
    pthread_mutex_lock(&g_sess_mu);
    fhsm_session_entry_t *s = &g_sessions[h];
    if (!s->in_use) {
        pthread_mutex_unlock(&g_sess_mu);
        return FHSM_RV_SESSION_HANDLE_INVALID;
    }
    pthread_mutex_unlock(&g_sess_mu);

    /* The token attach + login lives in fhsm_token_login; this function
     * is the boundary that the PKCS#11 façade calls. */
    if (!s->token) return FHSM_RV_TOKEN_NOT_PRESENT;
    fhsm_rv_t rv = fhsm_token_login(s->token, role, pin);
    /* Set this session's role when the token is (already) logged in as
     * that role : CKR_USER_ALREADY_LOGGED_IN means the application is
     * authenticated, so this session must reflect it too (#125). */
    if (rv == FHSM_RV_OK || rv == FHSM_RV_USER_ALREADY_LOGGED_IN) s->role = role;
    return rv;
}

fhsm_rv_t fhsm_session_logout(unsigned long h) {
    if (h == 0 || h >= FHSM_MAX_SESSIONS) return FHSM_RV_SESSION_HANDLE_INVALID;
    pthread_mutex_lock(&g_sess_mu);
    fhsm_session_entry_t *s = &g_sessions[h];
    if (!s->in_use) {
        pthread_mutex_unlock(&g_sess_mu);
        return FHSM_RV_SESSION_HANDLE_INVALID;
    }
    if (s->token) fhsm_token_logout(s->token);
    s->role = FHSM_ROLE_NONE;
    pthread_mutex_unlock(&g_sess_mu);
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * Token attachment / accessors. The session table owns the per-session
 * state but the token itself lives in the slot registry (fhsm_pkcs11.c).
 * These helpers let the PKCS#11 façade wire the two together without
 * exposing the internal session struct.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_session_attach_token(unsigned long h, fhsm_token_t *t) {
    if (h == 0 || h >= FHSM_MAX_SESSIONS) return FHSM_RV_SESSION_HANDLE_INVALID;
    pthread_mutex_lock(&g_sess_mu);
    if (!g_sessions[h].in_use) {
        pthread_mutex_unlock(&g_sess_mu);
        return FHSM_RV_SESSION_HANDLE_INVALID;
    }
    g_sessions[h].token = t;
    pthread_mutex_unlock(&g_sess_mu);
    return FHSM_RV_OK;
}

fhsm_token_t *fhsm_session_token(unsigned long h) {
    if (h == 0 || h >= FHSM_MAX_SESSIONS) return NULL;
    pthread_mutex_lock(&g_sess_mu);
    fhsm_token_t *t = g_sessions[h].in_use ? g_sessions[h].token : NULL;
    pthread_mutex_unlock(&g_sess_mu);
    return t;
}

fhsm_role_t fhsm_session_role(unsigned long h) {
    if (h == 0 || h >= FHSM_MAX_SESSIONS) return FHSM_ROLE_NONE;
    pthread_mutex_lock(&g_sess_mu);
    fhsm_role_t r = FHSM_ROLE_NONE;
    if (g_sessions[h].in_use) {
        /* PKCS#11 v3.2 §5.6: login state is per-application (per-token),
         * shared across every session the application holds with the token.
         * When one session performs C_Login, all sibling sessions of the
         * same token become authenticated. Query the token's authenticated
         * role rather than this session's local copy, so a key op issued in
         * a sibling session isn't spuriously rejected USER_NOT_LOGGED_IN.
         * Fall back to the local role only if no token is attached yet. */
        const fhsm_token_t *tok = g_sessions[h].token;
        r = tok ? fhsm_token_current_role(tok) : g_sessions[h].role;
    }
    pthread_mutex_unlock(&g_sess_mu);
    return r;
}

fhsm_rv_t fhsm_session_info(unsigned long h,
                              unsigned long *out_slot,
                              unsigned long *out_flags,
                              fhsm_role_t   *out_role) {
    if (h == 0 || h >= FHSM_MAX_SESSIONS) {
        return FHSM_RV_SESSION_HANDLE_INVALID;
    }
    pthread_mutex_lock(&g_sess_mu);
    if (!g_sessions[h].in_use) {
        pthread_mutex_unlock(&g_sess_mu);
        return FHSM_RV_SESSION_HANDLE_INVALID;
    }
    if (out_slot)  *out_slot  = g_sessions[h].slot;
    if (out_flags) *out_flags = g_sessions[h].flags;
    if (out_role)  *out_role  = g_sessions[h].role;
    pthread_mutex_unlock(&g_sess_mu);
    return FHSM_RV_OK;
}
