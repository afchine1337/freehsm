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
 * fhsm_audit.h --- Append-only audit log with chained HMAC.
 *
 *  Required by FIPS 140-3 §7.3 ("identification and authentication") and
 *  CC EAL4+ FAU_GEN.1 (audit data generation), FAU_GEN.2 (user identity
 *  association), FAU_SAA.1 (potential violation analysis).
 *
 *  Each line of the log is a JSON object terminated by '\n'. The fields
 *  are:
 *
 *      { "seq":       <int>,            // monotonic, starts at 1
 *        "ts":        <int>,            // ns since CLOCK_REALTIME epoch
 *        "event":     "<event-name>",   // see fhsm_audit_event_t below
 *        "slot":      <int>,            // slot index, or -1 if N/A
 *        "session":   <int>,            // session handle, or -1
 *        "role":      "SO|USER|NONE",
 *        "result":    "OK|FAIL",
 *        "rv":        <int>,            // FreeHSM return value
 *        "params":    { ... },          // event-specific, lengths only
 *        "prev_hmac": "<hex-32>",       // HMAC of previous line
 *        "hmac":      "<hex-32>"        // HMAC of this line (excluded)
 *      }
 *
 *  The HMAC key is the audit-MAC key, derived from the token DEK via
 *  HKDF-SHA-256(salt="freehsm-audit-v1", info="audit-mac-2026"). It
 *  rotates with the DEK so a SO PIN change automatically invalidates
 *  all previously trusted log lines for that slot, which is captured
 *  by the audit verifier (fhsm_audit_verify).
 *
 *  Tamper detection : any insertion, deletion, or modification of a
 *  line breaks the chain (prev_hmac of line N+1 ≠ hmac of line N).
 *  fhsm_audit_verify() walks the file from line 1 and reports the
 *  first broken link.
 *
 *  Backpressure : if the file cannot be written (disk full, EROFS),
 *  fhsm_audit_event() returns FHSM_RV_FUNCTION_FAILED *and* the module
 *  is latched into the ERROR state (FHSM_AUDIT_MANDATORY = 1). This
 *  enforces that no security-relevant action is allowed without a
 *  durable trace.
 *
 * ========================================================================= */

#ifndef FHSM_AUDIT_H
#define FHSM_AUDIT_H

#include "fhsm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Canonical event names. Add new ones at the end --- evaluators rely
 * on the stable list in docs/FIPS_140_3.md §6. */
typedef enum fhsm_audit_event_e {
    FHSM_EV_MODULE_INIT      = 1,
    FHSM_EV_MODULE_FINALIZE  = 2,
    FHSM_EV_KAT_REPORT       = 3,
    FHSM_EV_INTEGRITY_OK     = 4,
    FHSM_EV_INTEGRITY_FAIL   = 5,
    FHSM_EV_STATE_TRANSITION = 6,
    FHSM_EV_TOKEN_INIT       = 10,
    FHSM_EV_TOKEN_REINIT     = 11,
    FHSM_EV_LOGIN_OK         = 12,
    FHSM_EV_LOGIN_FAIL       = 13,
    FHSM_EV_LOGIN_LOCKED     = 14,
    FHSM_EV_LOGIN_THROTTLED  = 15,
    FHSM_EV_LOGOUT           = 16,
    FHSM_EV_SET_PIN          = 17,
    FHSM_EV_DEK_ROTATION     = 18,
    FHSM_EV_OBJECT_CREATE    = 30,
    FHSM_EV_OBJECT_DESTROY   = 31,
    FHSM_EV_OBJECT_FIND      = 32,
    FHSM_EV_ENCRYPT          = 40,
    FHSM_EV_DECRYPT          = 41,
    FHSM_EV_SIGN             = 42,
    FHSM_EV_VERIFY           = 43,
    FHSM_EV_WRAP             = 44,
    FHSM_EV_UNWRAP           = 45,
    FHSM_EV_DERIVE           = 46,
    FHSM_EV_GENERATE_KEY     = 47,
    FHSM_EV_GENERATE_KEYPAIR = 48,
    FHSM_EV_DIGEST           = 49,
    FHSM_EV_RNG_RESEED       = 60,
    FHSM_EV_SEAL_SUCCESS     = 70,
    FHSM_EV_SEAL_FAILURE     = 71,
    FHSM_EV_UNSEAL_SUCCESS   = 72,
    FHSM_EV_UNSEAL_FAILURE   = 73
} fhsm_audit_event_t;

/* Open the audit log for a given token. Creates the file if absent,
 * initializes the HMAC chain head with HMAC(audit_key, "FHSM-AUDIT-INIT|seq=0"),
 * appends the FHSM_EV_MODULE_INIT line. */
fhsm_rv_t fhsm_audit_open(const char *path,
                           fhsm_slice_t audit_key);

void fhsm_audit_close(void);

/* Emit one event line. The variadic part is a NULL-terminated list of
 * (const char *key, const char *value) pairs that will be serialized
 * into the JSON "params" object. Values must be safe-ASCII (the
 * function rejects anything > 0x7E or < 0x20 to defeat log-injection).
 * Lengths of sensitive material are passed as "len=NN" pairs --- the
 * material itself is NEVER written to the log.
 */
fhsm_rv_t fhsm_audit_event(fhsm_audit_event_t ev,
                            int slot,
                            int session,
                            fhsm_role_t role,
                            fhsm_rv_t rv,
                            ...);

/* Walk the file and verify the chain. Returns FHSM_RV_OK if every
 * prev_hmac matches the previous line's hmac, otherwise
 * FHSM_RV_FUNCTION_FAILED. The first broken line index is written to
 * *broken_at_line (0-based). */
fhsm_rv_t fhsm_audit_verify(const char *path,
                             fhsm_slice_t audit_key,
                             size_t *broken_at_line);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_AUDIT_H */
