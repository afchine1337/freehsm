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
#ifndef FHSM_SESSION_H
#define FHSM_SESSION_H
#include "fhsm_common.h"

/* Opaque token handle, defined in fhsm_token.h. Forward-declared here so
 * fhsm_session.h does not need to pull in the full token header. */
typedef struct fhsm_token_s fhsm_token_t;

fhsm_rv_t fhsm_session_open(unsigned long slot, unsigned long flags,
                             unsigned long *out_handle);
fhsm_rv_t fhsm_session_close(unsigned long h);
fhsm_rv_t fhsm_session_login(unsigned long h, fhsm_role_t role,
                              const char *pin, size_t pin_len);
fhsm_rv_t fhsm_session_logout(unsigned long h);

/* Attach the slot's token to a session. Called by C_OpenSession after a
 * successful fhsm_session_open. The token pointer is owned by the slot
 * registry; the session only borrows it. */
fhsm_rv_t fhsm_session_attach_token(unsigned long h, fhsm_token_t *t);

/* Accessors used by C_InitPIN / C_SetPIN / C_FindObjects to retrieve the
 * session's current token and role without exposing the internal session
 * table. Returns NULL / FHSM_ROLE_NONE if the handle is invalid. */
fhsm_token_t *fhsm_session_token(unsigned long h);
fhsm_role_t   fhsm_session_role(unsigned long h);

/* Drop every session without touching the tokens they point at. Used by the
 * post-fork reset in C_Initialize: a forked child inherits the parent's whole
 * session table -- handles, roles, token pointers -- and must not keep using
 * sessions it never opened (#125). */
void fhsm_session_reset_all(void);

/* Aggregate accessor for C_GetSessionInfo : populates slot ID, open
 * flags, and authenticated role for the given session handle in one
 * mutex-protected lookup. Returns FHSM_RV_OK on success, or
 * FHSM_RV_SESSION_HANDLE_INVALID if the handle is unknown. Any out
 * pointer may be NULL if the caller does not need that field. */
fhsm_rv_t fhsm_session_info(unsigned long h,
                              unsigned long *out_slot,
                              unsigned long *out_flags,
                              fhsm_role_t   *out_role);

#endif
