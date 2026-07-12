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
 * fhsm_token.h --- Encrypted token store (slot persistence).
 *
 *  One file per slot (slot0.tok, slot1.tok, ...). On-disk format is a
 *  compact fixed-layout binary : a 317-byte header followed by an
 *  optional AES-256-GCM-encrypted objects section. The full byte-level
 *  specification lives in docs/TOKEN_STORE_FORMAT.md (#108).
 *
 *  NOTE --- the Python POC used a JSON token layout ; the C TOE does
 *  NOT retain byte-level interop with POC token files (an earlier
 *  revision of this comment claimed otherwise). Migration from the POC
 *  is by re-importing objects, not by copying .tok files.
 *
 *  Authentication model:
 *    --- Two roles : Security Officer (SO) and User (USER), each with its
 *        own PBKDF2-wrapped DEK ("so_wrap" and "user_wrap" in the JSON).
 *    --- A successful SO C_SetPIN rotates the DEK (NIST SP 800-57 §5.4
 *        "rotate KEK on change of custodian"). USER C_SetPIN does NOT
 *        rotate.
 *    --- Failed login attempts increment per-role counter (failed_so /
 *        failed_user). After FHSM_PIN_MAX_FAILED, the role is locked
 *        (FHSM_RV_PIN_LOCKED). Between attempts, exponential throttle
 *        is enforced (FHSM_RV_PIN_THROTTLED with delay).
 *
 *  Optional sealing backends:
 *    The DEK can be additionally sealed to a TPM 2.0 before being
 *    stored (companion file {path}.tpm, see fhsm_token_tpm.h). KMS /
 *    quorum sealing backends are roadmap items (#109 stream). The .tok
 *    format itself is unchanged by sealing.
 *
 *  On-disk layout (summary --- authoritative spec in
 *  docs/TOKEN_STORE_FORMAT.md):
 *
 *      [317-byte fixed header]
 *        magic "FHSM" | version | label | serial | pbkdf2_iter |
 *        salt_so | so_wrap (nonce + DEK ct + GCM tag) |
 *        salt_user | user_wrap | user_initialized |
 *        failed_so/user | throttle_so/user_until_ms
 *      [optional objects section]
 *        u32 ct_len | nonce[12] | AES-256-GCM ct | tag[16]
 *        (plaintext = u32 count | u32 next_handle | count x 5620-byte
 *         fixed records ; AAD = token serial)
 *
 * ========================================================================= */

#ifndef FHSM_TOKEN_H
#define FHSM_TOKEN_H

#include "fhsm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle. Lifetime managed by fhsm_token_load / fhsm_token_close. */
typedef struct fhsm_token_s fhsm_token_t;

/* fhsm_role_t is defined in fhsm_common.h (shared with audit / pkcs11). */

/* Open an existing token file. Returns FHSM_RV_TOKEN_NOT_PRESENT if the
 * file does not exist; the caller should then call fhsm_token_init()
 * to create a new one. */
fhsm_rv_t fhsm_token_load(const char *path, fhsm_token_t **out);

/* Initialize a fresh token. Generates a 256-bit DEK via fhsm_rng_bytes(),
 * wraps it under PBKDF2(so_pin) into so_wrap, writes the file
 * atomically (write to .tmp + rename). The token starts in a state
 * where USER has no PIN yet (failed_user is set to "uninitialized").
 * The SO must then call fhsm_token_init_user_pin() to enable user
 * login.
 */
fhsm_rv_t fhsm_token_init(const char *path,
                           const char *so_pin,
                           const char *label,
                           fhsm_token_t **out);

void fhsm_token_close(fhsm_token_t *t);

/* Authentication. Increments the failure counter on PIN mismatch and
 * returns FHSM_RV_PIN_INCORRECT. After FHSM_PIN_MAX_FAILED consecutive
 * failures returns FHSM_RV_PIN_LOCKED. Throttle (exponential backoff)
 * is enforced *before* the PBKDF2 derivation to make the side channel
 * useless for timing attacks. On success returns FHSM_RV_OK and the
 * unwrapped DEK is kept in the token's secure-heap arena until
 * fhsm_token_logout() / fhsm_token_close() is called.
 */
fhsm_rv_t fhsm_token_login(fhsm_token_t *t, fhsm_role_t role, const char *pin);

/* End the current session: zeroize the in-memory DEK, increment audit
 * sequence number. The on-disk file is not touched. */
void fhsm_token_logout(fhsm_token_t *t);

/* Current per-token login role (shared by all sessions). #125. */
fhsm_role_t fhsm_token_current_role(const fhsm_token_t *t);

/* PIN administration. SO can change either PIN; USER can change only
 * its own. SO C_SetPIN rotates the DEK; USER does not (see header
 * comment). */
fhsm_rv_t fhsm_token_set_pin(fhsm_token_t *t,
                              fhsm_role_t role,
                              const char *old_pin,
                              const char *new_pin);

fhsm_rv_t fhsm_token_init_user_pin(fhsm_token_t *t, const char *user_pin);

/* Re-initialize the token (C_InitToken). All objects are destroyed,
 * the DEK is regenerated, both failure counters are cleared. The
 * caller MUST be the SO and the new SO PIN replaces the old one.
 */
fhsm_rv_t fhsm_token_reinit(fhsm_token_t *t,
                             const char *new_so_pin,
                             const char *label);

/* Token-info accessors --- read-only after login. */
const char *fhsm_token_label(const fhsm_token_t *t);
const char *fhsm_token_serial(const fhsm_token_t *t);
uint32_t    fhsm_token_failed_count(const fhsm_token_t *t, fhsm_role_t role);
int         fhsm_token_is_locked(const fhsm_token_t *t, fhsm_role_t role);
uint64_t    fhsm_token_throttle_remaining_ms(const fhsm_token_t *t, fhsm_role_t role);

/* ---------------------------------------------------------------------------
 * Object store API. Used by the PKCS#11 layer to back C_GenerateKey,
 * C_CreateObject, C_FindObjects, C_GetAttributeValue, C_DestroyObject.
 *
 * Objects are persisted as an AES-256-GCM-encrypted blob appended to the
 * token's .tok file. The blob is decrypted into memory at login time;
 * writes happen on every mutation (encrypted, atomic rename).
 * ----------------------------------------------------------------------- */

/* Add a new object to the store. Returns the freshly assigned opaque
 * handle in *out_handle. The caller passes the object's class
 * (CKO_SECRET_KEY, ...), key_type (CKK_AES, ...), label, key material
 * (or empty for non-key objects), and optional CKA_ID. flags carries
 * the CKA_PRIVATE / CKA_EXTRACTABLE bits.
 * Returns FHSM_RV_HOST_MEMORY if the store is full (FHSM_MAX_OBJECTS). */
fhsm_rv_t fhsm_token_object_add(fhsm_token_t *t,
                                 uint32_t cko_class,
                                 uint32_t ckk_type,
                                 const char *label,
                                 const uint8_t *value, size_t value_len,
                                 const uint8_t *id,    size_t id_len,
                                 uint8_t  flags,
                                 uint32_t *out_handle);

/* Lookup by handle. Returns FHSM_RV_KEY_HANDLE_INVALID if not found.
 * The output pointer references storage owned by the token; valid until
 * the next mutation. The caller must NOT free it. */
fhsm_rv_t fhsm_token_object_get(fhsm_token_t *t, uint32_t handle,
                                 const uint8_t **value, size_t *value_len,
                                 uint32_t *out_class, uint32_t *out_key_type);

/* Find objects matching the optional class/label filter. NULL filters
 * are wildcards. Returns up to `cap` handles in `handles_out` and the
 * total count in `*count_out`. Out-of-bounds matches are silently
 * truncated to `cap`. */
fhsm_rv_t fhsm_token_object_find(fhsm_token_t *t,
                                  const uint32_t *opt_class,
                                  const char     *opt_label,
                                  uint32_t *handles_out, size_t cap,
                                  size_t *count_out);

/* Attribute accessors. Used by C_GetAttributeValue to fill the parts of
 * CK_ATTRIBUTE templates that don't fit through fhsm_token_object_get.
 * Return FHSM_RV_KEY_HANDLE_INVALID if the handle is unknown. The
 * pointers reference token-owned storage ; the caller must not free. */
fhsm_rv_t fhsm_token_object_get_label(fhsm_token_t *t, uint32_t handle,
                                       const char **out, size_t *out_len);
fhsm_rv_t fhsm_token_object_get_id(fhsm_token_t *t, uint32_t handle,
                                    const uint8_t **out, size_t *out_len);

/* Read the object's flags byte (FHSM_OBJF_SENSITIVE | EXTRACTABLE).
 * Returns FHSM_RV_KEY_HANDLE_INVALID if the handle is unknown. */
fhsm_rv_t fhsm_token_object_get_flags(fhsm_token_t *t, uint32_t handle,
                                       uint8_t *out_flags);
fhsm_rv_t fhsm_token_object_is_token(fhsm_token_t *t, uint32_t handle,
                                     int *out_is_token);

/* Mutation accessors used by C_SetAttributeValue and C_CopyObject
 * (added in v1.3.0 in response to Denis Mingulov's pkcs11-check
 * Finding 2 ; the v1.2.2 release wired three of the five missing
 * function-list slots and deferred C_CopyObject + C_SetAttributeValue
 * to v1.3.0 pending the underlying token-level mutation primitives).
 *
 * Each setter requires the token to be in the logged-in state and
 * persists the change atomically to disk before returning (same model
 * as fhsm_token_object_destroy). The caller is responsible for
 * enforcing PKCS#11's one-way state transitions on CKA_SENSITIVE and
 * CKA_EXTRACTABLE before calling set_flags ; this layer accepts the
 * new flags byte unconditionally. */
fhsm_rv_t fhsm_token_object_set_label(fhsm_token_t *t, uint32_t handle,
                                       const char *label);
fhsm_rv_t fhsm_token_object_set_id(fhsm_token_t *t, uint32_t handle,
                                    const uint8_t *id, size_t id_len);
fhsm_rv_t fhsm_token_object_set_flags(fhsm_token_t *t, uint32_t handle,
                                       uint8_t flags);

/* Destroy an object by handle. The slot is marked free and the on-disk
 * blob is rewritten. Returns FHSM_RV_KEY_HANDLE_INVALID if not found. */
fhsm_rv_t fhsm_token_object_destroy(fhsm_token_t *t, uint32_t handle);

/* Mark an object as a session object owned by `owner_session` (non-zero) :
 * not persisted, destroyed on session close. #125. */
fhsm_rv_t fhsm_token_object_mark_session(fhsm_token_t *t, uint32_t handle,
                                         uint32_t owner_session);

/* Per-object usage flags (CKA_ENCRYPT/... bits, 0x80 = explicit). #125. */
fhsm_rv_t fhsm_token_object_set_usage(fhsm_token_t *t, uint32_t handle, uint8_t usage_flags);
fhsm_rv_t fhsm_token_object_get_usage(fhsm_token_t *t, uint32_t handle, uint8_t *out);

/* Destroy all session objects owned by `owner_session`. #125. */
fhsm_rv_t fhsm_token_destroy_session_objects(fhsm_token_t *t,
                                             uint32_t owner_session);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_TOKEN_H */
