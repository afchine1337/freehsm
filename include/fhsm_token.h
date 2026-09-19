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
/* `pin` is ulPinLen bytes, NOT a C string. PKCS#11 never promised a
 * terminator: C_Login used to derive the KEK over strlen(pPin), which read
 * past the caller's buffer and refused the correct PIN whenever the byte
 * after it was not zero. Every caller that does hold a C string passes
 * strlen() explicitly, at the call site, where that fact is true. */
fhsm_rv_t fhsm_token_login(fhsm_token_t *t, fhsm_role_t role,
                            const char *pin, size_t pin_len);

/* Verify a PIN without logging in and without changing the login state.
 * Used by C_Login(CKU_CONTEXT_SPECIFIC) to re-authenticate the user for one
 * active operation on a key whose CKA_ALWAYS_AUTHENTICATE is set (PKCS#11
 * v3.2 §5.6). fhsm_token_login() cannot serve: it short-circuits with
 * FHSM_RV_USER_ALREADY_LOGGED_IN before examining the PIN.
 *
 * Same failure counters and throttle as fhsm_token_login, so this is not an
 * unthrottled PIN oracle. Returns FHSM_RV_OK, FHSM_RV_PIN_INCORRECT,
 * FHSM_RV_PIN_LOCKED or FHSM_RV_PIN_THROTTLED. `pin` is pin_len bytes and is
 * not a C string, as everywhere else. */
fhsm_rv_t fhsm_token_verify_pin(fhsm_token_t *t, fhsm_role_t role,
                                 const char *pin, size_t pin_len);

/* End the current session: zeroize the in-memory DEK, increment audit
 * sequence number. The on-disk file is not touched. */
void fhsm_token_logout(fhsm_token_t *t);

/* Current per-token login role (shared by all sessions). #125. */
/* Per-token object-store capacity. Overridable via -DFHSM_MAX_OBJECTS ;
 * kept in the public header so unit tests track the implementation (#125). */
#ifndef FHSM_MAX_OBJECTS
#define FHSM_MAX_OBJECTS 1024
#endif

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

/* Whether C_InitPIN has ever run on this token, i.e. whether a user PIN
 * exists. Persisted at byte 292 of the header. Exposed because C_GetTokenInfo
 * has to report CKF_USER_PIN_INITIALIZED and had no way to ask. */
int         fhsm_token_user_initialized(const fhsm_token_t *t);
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
/* Which of the in-memory metadata attributes to read. */
typedef enum {
    FHSM_OBJ_META_START_DATE = 0,
    FHSM_OBJ_META_END_DATE   = 1,
    FHSM_OBJ_META_APPLICATION = 2
} fhsm_obj_meta_t;

/* CKA_START_DATE / CKA_END_DATE / CKA_APPLICATION. NOT persisted: the object
 * blob has no field for them yet, so the PKCS#11 layer only accepts them on
 * session objects. Pass NULL for a component to leave it unchanged. */
fhsm_rv_t fhsm_token_object_set_meta(fhsm_token_t *t, uint32_t handle,
                                     const uint8_t *start, size_t start_len,
                                     const uint8_t *end,   size_t end_len,
                                     const uint8_t *app,   size_t app_len);
fhsm_rv_t fhsm_token_object_get_meta(fhsm_token_t *t, uint32_t handle,
                                     fhsm_obj_meta_t which,
                                     const uint8_t **out, size_t *out_len);

fhsm_rv_t fhsm_token_object_get_id(fhsm_token_t *t, uint32_t handle,
                                    const uint8_t **out, size_t *out_len);

/* Object flags stored on disk (1 byte). */
#define FHSM_OBJF_SENSITIVE     0x01
#define FHSM_OBJF_EXTRACTABLE   0x02
#define FHSM_OBJF_UNMODIFIABLE  0x04   /* CKA_MODIFIABLE=FALSE persisted */
#define FHSM_OBJF_UNDESTROYABLE 0x08   /* CKA_DESTROYABLE=FALSE persisted */
/* CKA_LOCAL (PKCS#11 v3.2 §4.9) : TRUE only for a key generated on the token
 * by C_GenerateKey / C_GenerateKeyPair. FALSE for anything created by
 * C_CreateObject, C_UnwrapKey, C_DeriveKey or (de)encapsulation. This was
 * previously hard-coded TRUE in C_GetAttributeValue, so an *imported* key
 * claimed to have been generated on the token and never to have existed
 * outside it -- a false statement about key provenance, which is exactly what
 * CKA_LOCAL exists to attest (#125). */
#define FHSM_OBJF_LOCAL         0x10
/* CKA_ALWAYS_AUTHENTICATE : was hard-coded FALSE, so setting it at keygen
 * silently did nothing (#125). */
#define FHSM_OBJF_ALWAYS_AUTH   0x20
/* CKA_TRUSTED (PKCS#11 v3.2 §4.6) : may only be set to TRUE by the SO. It
 * gates CKA_WRAP_WITH_TRUSTED -- a key marked WRAP_WITH_TRUSTED may only be
 * wrapped by a wrapping key that is CKA_TRUSTED. If an application could
 * declare its own key trusted, that control would be worthless (the classic
 * Tookan-style key-export escape). Previously the module accepted
 * CKA_TRUSTED=TRUE from any session and then reported it back as a hard-coded
 * FALSE, so the attribute was both unenforced and unreadable (#125). */
#define FHSM_OBJF_TRUSTED       0x40
/* CKA_UNWRAP_TEMPLATE (§4.9) present on this key and requiring that keys
 * unwrapped with it be CKA_SENSITIVE. This is the spec's answer to Tookan
 * §3.3: the module cannot tell an attacker's CKA_SENSITIVE=FALSE downgrade
 * from a non-sensitive key being legitimately re-imported (RFC 3394 carries no
 * attributes), but the *wrapping key's owner* knows what that key wraps and
 * can say so up front. §4.9: the user template is applied "as if the object
 * has already been created", so the one-way CKA_SENSITIVE rule (FALSE->TRUE
 * only) makes a downgrade CKR_ATTRIBUTE_READ_ONLY.
 *
 * NOTE: this is the last bit of the flags byte. A further per-object boolean
 * needs a wider field; the v3 record (#125) exists now, so that is a matter of
 * spending a byte in it rather than a format change. */
#define FHSM_OBJF_UNWRAP_SENS   0x80

/* Second per-object flags byte. The note above was right that the first one
 * was full and that the v3 record could spend a byte: it ends with a pad byte
 * at offset 203, written zero and never read. This is that byte.
 *
 * The bits are NEGATIVE -- set means restricted -- so that zero means
 * permitted. That is the spec default for a KEM key and it is also what every
 * record written before 2026-09-19 already says, so v1, v2 and older v3
 * records keep their meaning without a migration. Backward compatibility here
 * is a consequence of the polarity rather than something added afterwards.
 *
 * CKA_ENCAPSULATE (§5.14.7) and CKA_DECAPSULATE (§5.14.8) were accepted in a
 * C_GenerateKeyPair template, silently dropped, and then contradicted by the
 * operation succeeding. C_GenerateKey had rejected them on a symmetric
 * template since #125, with a comment calling that better than ignoring them
 * -- the rule existed and was wired to the path where the attributes are
 * meaningless, not to the one where they mean something. */
#define FHSM_OBJF2_NO_ENCAPSULATE 0x01
#define FHSM_OBJF2_NO_DECAPSULATE 0x02
/* CKA_COPYABLE = FALSE (§4.4 : C_CopyObject must answer CKR_ACTION_PROHIBITED).
 * The attribute was accepted in a creation template, dropped, and reported
 * back as a hard-coded TRUE -- the same shape as CKA_LOCAL before #125 and
 * CKA_ALWAYS_AUTHENTICATE before 2026-09-17. Negative like its neighbours, so
 * an object written before this bit existed is copyable, which is the
 * default. */
#define FHSM_OBJF2_NOT_COPYABLE   0x04

/* Presence of the four policy attributes carried by the v4 record.
 *
 * These are presence bits, not restriction bits, and they are here rather than
 * derived from a count because a count of zero has two meanings. An absent
 * CKA_ALLOWED_MECHANISMS permits every mechanism; one set to the empty list
 * permits none, and pkcs11-check sends that case deliberately. Both store a
 * count of zero, so the count cannot be asked which one it is -- the same
 * problem CKA_START_DATE solved with an explicit length byte.
 *
 * The polarity still holds: a set bit means a restriction exists, a clear bit
 * means none, and a record written before these bits existed carries zero,
 * which is no policy. That is what those records mean. */
#define FHSM_OBJF2_HAS_ALLOWED_MECH 0x08
#define FHSM_OBJF2_HAS_WRAP_TMPL    0x10
#define FHSM_OBJF2_HAS_UNWRAP_TMPL  0x20
#define FHSM_OBJF2_HAS_DERIVE_TMPL  0x40

/* Read / write the second flags byte. Separate accessors rather than a wider
 * type on the existing pair: every current caller of the first byte keeps
 * compiling unchanged, and a caller that has not been taught about the second
 * cannot silently drop it by passing the old width. */
fhsm_rv_t fhsm_token_object_get_flags2(fhsm_token_t *t, uint32_t handle,
                                        uint8_t *out_flags2);
fhsm_rv_t fhsm_token_object_set_flags2(fhsm_token_t *t, uint32_t handle,
                                        uint8_t flags2);

/* What a v4 record can hold, per object. Measured against pkcs11-check 0.2.0
 * rather than chosen: the corpus sends one mechanism and at most two template
 * entries, and the longest value in a template is a 41-byte CKA_LABEL. These
 * are in the header because a caller has to know the limit before it calls --
 * a cap discoverable only by being refused is a cap met in production. */
#define FHSM_POLICY_MECH_MAX     8u    /* CKA_ALLOWED_MECHANISMS entries */
#define FHSM_POLICY_ATTR_MAX     4u    /* entries per nested template */
#define FHSM_POLICY_VALUE_MAX    48u   /* bytes of value per template entry */

/* One entry of a nested policy template.
 *
 * `kind` is recorded rather than derived. The three value shapes cannot be
 * told apart from the bytes -- a one-byte CK_BBOOL and the first byte of a
 * one-character label are the same octet -- and deriving it from the attribute
 * number would make the store's reading of a stored value depend on a table
 * that changes over releases. The PKCS#11 layer knows which shape it was
 * handed, because it still has the caller's CK_ATTRIBUTE; it says so once,
 * here, and the store never has to guess. */
#define FHSM_POLICY_KIND_NONE   0u
#define FHSM_POLICY_KIND_BOOL   1u    /* value[0] is a CK_BBOOL */
#define FHSM_POLICY_KIND_ULONG  2u    /* value[0..7] is a u64 little-endian */
#define FHSM_POLICY_KIND_BYTES  3u    /* value[0..len-1] */
typedef struct {
    uint32_t type;                    /* the CKA_ attribute constrained */
    uint8_t  kind;                    /* FHSM_POLICY_KIND_* */
    uint8_t  len;                     /* significant bytes of value */
    uint8_t  value[FHSM_POLICY_VALUE_MAX];
} fhsm_policy_attr_t;

/* Which of the three nested templates. */
typedef enum {
    FHSM_TMPL_WRAP   = 0,
    FHSM_TMPL_UNWRAP = 1,
    FHSM_TMPL_DERIVE = 2
} fhsm_tmpl_which_t;

/* Store / read one nested template. Setting marks it present, count 0
 * included. A count above FHSM_POLICY_ATTR_MAX, or an entry whose len exceeds
 * FHSM_POLICY_VALUE_MAX, is FHSM_RV_ATTRIBUTE_VALUE_INVALID -- never a
 * truncation, for the same reason as the mechanism list: a policy silently cut
 * short is a restriction the caller believes is there and is not.
 *
 * For get, *io_count is capacity in, stored count out; `out` NULL is a size
 * query. Presence is FHSM_OBJF2_HAS_*_TMPL in flags2, never the count. */
fhsm_rv_t fhsm_token_object_set_tmpl(fhsm_token_t *t, uint32_t handle,
                                      fhsm_tmpl_which_t which,
                                      const fhsm_policy_attr_t *a,
                                      uint8_t count);
fhsm_rv_t fhsm_token_object_get_tmpl(fhsm_token_t *t, uint32_t handle,
                                      fhsm_tmpl_which_t which,
                                      fhsm_policy_attr_t *out,
                                      uint8_t *io_count);

/* CKA_ALLOWED_MECHANISMS. Setting marks the attribute present, count 0
 * included: an empty list allows nothing and is a real answer. A count above
 * the cap is FHSM_RV_ATTRIBUTE_VALUE_INVALID, never a truncation. */
fhsm_rv_t fhsm_token_object_set_allowed_mechs(fhsm_token_t *t, uint32_t handle,
                                               const uint32_t *mechs,
                                               uint8_t count);
/* *io_count is capacity in, stored count out. `out` NULL is a size query.
 * FHSM_RV_BUFFER_TOO_SMALL when the capacity is short, count still written. */
fhsm_rv_t fhsm_token_object_get_allowed_mechs(fhsm_token_t *t, uint32_t handle,
                                               uint32_t *out, uint8_t *io_count);
/* FHSM_RV_OK if permitted, FHSM_RV_MECHANISM_INVALID if not. An object with no
 * CKA_ALLOWED_MECHANISMS permits everything; an unknown handle answers OK and
 * leaves the handle error to the caller that is about to look it up. */
fhsm_rv_t fhsm_token_object_mech_allowed(fhsm_token_t *t, uint32_t handle,
                                          uint32_t mech);

/* The four policy counts carried by the v4 record, read together. Any out
 * pointer may be NULL. A zero count means "allows nothing" when the matching
 * FHSM_OBJF2_HAS_* bit is set in flags2, and "no policy" when it is not --
 * the count alone cannot say which. */
fhsm_rv_t fhsm_token_object_get_policy_counts(fhsm_token_t *t, uint32_t handle,
                                               uint8_t *out_allowed,
                                               uint8_t *out_wrap,
                                               uint8_t *out_unwrap,
                                               uint8_t *out_derive);

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
