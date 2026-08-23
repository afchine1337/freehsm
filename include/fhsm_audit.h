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
    FHSM_EV_UNSEAL_FAILURE   = 73,
    /* The network service (#111). Appended, never renumbered: the comment
     * above is not decoration -- docs/FIPS_140_3.md lists these by value.
     *
     * REQUEST_REFUSED covers every guard the service applies before it will
     * touch the module: no identity, a peer that is not the proxy, a body it
     * will not parse. It is a separate event from a failed operation because
     * the two answer different questions for a reviewer -- "who was turned
     * away" and "what went wrong for someone who was let in". */
    FHSM_EV_SERVICE_START    = 80,
    FHSM_EV_SERVICE_STOP     = 81,
    FHSM_EV_REQUEST_ACCEPTED = 82,
    FHSM_EV_REQUEST_REFUSED  = 83
} fhsm_audit_event_t;

/* Open the audit log for a given token. Creates the file if absent,
 * initializes the HMAC chain head with HMAC(audit_key, "FHSM-AUDIT-INIT|seq=0"),
 * appends the FHSM_EV_MODULE_INIT line. */
fhsm_rv_t fhsm_audit_open(const char *path,
                           fhsm_slice_t audit_key);

/* ---------------------------------------------------------------------------
 * Where the chaining key comes from.
 *
 * `fhsm_audit_open` takes a key and asks no questions. Something has to decide
 * what that key is, and the decision is not obvious, so it lives here rather
 * than at the call site.
 *
 * Deriving it from the token DEK was the tempting answer and is the wrong one:
 * the log would only be writable while logged in, leaving `login_fail`,
 * `login_locked` and `integrity_fail` untraceable — exactly the three events
 * AGD_OPE §4.3 tells the Security Officer to investigate.
 *
 * So the key is its own, provisioned on first use and recovered afterwards:
 *
 *   {dir}/audit.key.tpm   sealed to the TPM, when FHSM_TPM_SEALING is on and
 *                         a TPM is present. Bound to the same PCRs as the DEK,
 *                         so a changed boot chain makes it unreadable.
 *   {dir}/audit.key       32 raw bytes, mode 0600, otherwise.
 *
 * `*sealed` says which happened, so the caller can record it — an operator
 * reading the log should be able to tell which of the two protected it.
 *
 * What this protects, stated plainly because the difference matters:
 *
 *   - Against someone who takes the disk, or edits the file offline: yes. They
 *     do not have the key, so they cannot recompute the chain.
 *   - Against someone who is root on the running host: no, in either case. The
 *     sealed key is unsealed into this process's memory to be used at all, and
 *     the file-based one is readable by root by definition. A TPM raises the
 *     bar for offline attacks and for a tampered boot chain; it does not make
 *     a live compromise survivable, and saying otherwise would be a lie an
 *     evaluator would find.
 *
 * A key file that is group- or world-readable is refused rather than used. A
 * chaining key everyone can read is a chain everyone can forge, and continuing
 * would produce a log that looks authenticated and is not.
 * ------------------------------------------------------------------------- */
fhsm_rv_t fhsm_audit_key_provision(const char *dir, uint8_t key[32],
                                    int *sealed);

void fhsm_audit_close(void);

/* Who the current thread is acting for, written into the "actor" field of
 * every line this thread logs until it is cleared.
 *
 * CC EAL4+ FAU_GEN.2 asks for user identity association, and until the
 * service existed there was no user to associate: every event was the
 * module acting on its own behalf, and "actor" is empty for those. The
 * service sets it from the client certificate subject the proxy passed,
 * and clears it when the request ends.
 *
 * Thread-local on purpose. One session per concurrent request means one
 * actor per thread, and a global here would attribute a signature to
 * whoever happened to be served last -- a wrong entry in an audit log is
 * worse than a missing one.
 *
 * `subject` is copied, truncated to FHSM_AUDIT_ACTOR_MAX-1, and filtered
 * to safe ASCII exactly like a params value: it arrives in an HTTP header
 * and is not to be trusted with the shape of a JSON line. NULL clears it. */
#define FHSM_AUDIT_ACTOR_MAX 128
void fhsm_audit_set_actor(const char *subject);

/* Events written, and durable barriers that took. Every event returns only
 * after a barrier that covered its own write; concurrent events share one, so
 * `barriers` is at most `events` and well below it under load. Diagnostics --
 * the only way a test can observe that the sharing is happening. */
/* The path of the file this process is writing to, which is NOT the path
 * passed to fhsm_audit_open(): that is a base name, and each opening creates
 * `base.NNNNNN` with O_EXCL so that every chain has exactly one author. Copies
 * into `out` if given and returns the length. Empty when the log is closed. */
/* Whether this build permits FHSM_AUDIT=off. 1 means the module refuses to
 * start without a log, which is the default; see FHSM_AUDIT_MANDATORY in
 * fhsm_common.h for what it does and does not govern. */
int fhsm_audit_mandatory(void);

size_t fhsm_audit_current_path(char *out, size_t cap);

void fhsm_audit_barrier_stats(uint64_t *events, uint64_t *barriers);

/* Emit one event line. The variadic part is a NULL-terminated list of
 * (const char *key, const char *value) pairs that will be serialized
 * into the JSON "params" object. Values must be safe-ASCII (the
 * function rejects anything > 0x7E or < 0x20 to defeat log-injection).
 * Lengths of sensitive material are passed as "len=NN" pairs --- the
 * material itself is NEVER written to the log.
 */
/* __attribute__((sentinel)): the compiler now refuses a call whose last
 * argument is not NULL. Five sites were missing it, and one passed an int
 * where a char* was expected -- none of them ever ran, because the log was
 * never open and the function returned before reading its arguments. A
 * variadic contract nobody can check by reading is one the compiler should
 * check instead. */
#if defined(__GNUC__)
__attribute__((sentinel))
#endif
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
