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
 * fhsm_state.c --- Cryptographic-module state machine (FIPS 140-3 §7.4.2).
 *
 * Single global state guarded by a single pthread mutex. All transitions
 * are logged to the audit log. The ERROR state is latched (irreversible
 * without a restart) per FIPS 140-3 §7.10.5.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_audit.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

static pthread_mutex_t       g_state_mu     = PTHREAD_MUTEX_INITIALIZER;
static fhsm_module_state_t   g_state        = FHSM_STATE_POWER_OFF;
static char                  g_error_reason[128] = {0};

/* Valid forward transitions. Each entry is {from, to}. Anything else
 * (including any transition into ERROR) is allowed only via
 * fhsm_state_latch_error(). */
static const struct { fhsm_module_state_t from, to; } g_valid_transitions[] = {
    { FHSM_STATE_POWER_OFF,     FHSM_STATE_INITIALIZING },
    { FHSM_STATE_INITIALIZING,  FHSM_STATE_INITIALIZED  },
    { FHSM_STATE_INITIALIZED,   FHSM_STATE_AUTHENTICATED },
    { FHSM_STATE_AUTHENTICATED, FHSM_STATE_INITIALIZED  },  /* logout */
    { FHSM_STATE_INITIALIZED,   FHSM_STATE_POWER_OFF    },  /* finalize */
    { FHSM_STATE_AUTHENTICATED, FHSM_STATE_POWER_OFF    }
};

fhsm_module_state_t fhsm_state_get(void) {
    pthread_mutex_lock(&g_state_mu);
    fhsm_module_state_t s = g_state;
    pthread_mutex_unlock(&g_state_mu);
    return s;
}

fhsm_rv_t fhsm_state_set(fhsm_module_state_t s) {
    pthread_mutex_lock(&g_state_mu);

    /* ERROR is latched. Once entered, only a process restart unsticks it. */
    if (g_state == FHSM_STATE_ERROR) {
        pthread_mutex_unlock(&g_state_mu);
        return FHSM_RV_FUNCTION_FAILED;
    }

    /* Verify the transition is in the white-list. */
    int ok = 0;
    for (size_t i = 0; i < sizeof(g_valid_transitions)/sizeof(g_valid_transitions[0]); ++i) {
        if (g_valid_transitions[i].from == g_state &&
            g_valid_transitions[i].to == s) {
            ok = 1;
            break;
        }
    }
    if (!ok) {
        pthread_mutex_unlock(&g_state_mu);
        return FHSM_RV_FUNCTION_FAILED;
    }

    fhsm_module_state_t prev = g_state;
    g_state = s;
    pthread_mutex_unlock(&g_state_mu);

    /* Emit audit event outside the mutex (audit subsystem has its own
     * synchronization). */
    char from_s[8], to_s[8];
    snprintf(from_s, sizeof(from_s), "%d", prev);
    snprintf(to_s,   sizeof(to_s),   "%d", s);
    (void)fhsm_audit_event(FHSM_EV_STATE_TRANSITION, -1, -1,
                            FHSM_ROLE_NONE, FHSM_RV_OK,
                            "from", from_s, "to", to_s, NULL);
    return FHSM_RV_OK;
}

void fhsm_state_latch_error(const char *reason) {
    pthread_mutex_lock(&g_state_mu);
    if (g_state != FHSM_STATE_ERROR) {
        g_state = FHSM_STATE_ERROR;
        if (reason) {
            /* snprintf for gcc 14 -Wstringop-truncation compliance. */
            (void)snprintf(g_error_reason, sizeof(g_error_reason), "%s", reason);
        }
    }
    pthread_mutex_unlock(&g_state_mu);

    (void)fhsm_audit_event(FHSM_EV_STATE_TRANSITION, -1, -1,
                            FHSM_ROLE_NONE, FHSM_RV_FUNCTION_FAILED,
                            "to", "ERROR",
                            "reason", reason ? reason : "(none)",
                            NULL);
}
