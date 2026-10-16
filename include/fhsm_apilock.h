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
#ifndef FHSM_APILOCK_H
#define FHSM_APILOCK_H
#include <stddef.h>

/* ---------------------------------------------------------------------------
 * The PKCS#11 entry lock (#111-prep).
 *
 * fhsm_token_object_get() hands back a pointer to an object's value and
 * releases the token mutex; the caller then parses or copies it, sometimes
 * across an EVP call that takes milliseconds. Thirty-nine call sites do this.
 * A C_DestroyObject or C_CloseSession in another session, between the two,
 * zeroized and freed the value under a running C_Sign: a use-after-free that
 * tests/test_concurrency_store --destroy shows as CKR_FUNCTION_FAILED.
 *
 * Copying the value out at each of the 39 sites would fix it one site at a
 * time, and the fortieth would bring it back. So the borrow is bounded by the
 * API call instead:
 *
 *   - every C_ function runs under one module-wide read-write lock. Most take
 *     it SHARED, so signatures in N sessions still run in parallel;
 *   - the calls that free what others may be borrowing -- C_DestroyObject,
 *     C_CloseSession, C_CloseAllSessions, C_InitToken, C_Initialize,
 *     C_Finalize -- take it EXCLUSIVE, and wait for in-flight calls to finish;
 *   - a value freed under a SHARED call (the rollback in C_GenerateKey and its
 *     siblings, a value migrated into the secure heap by C_SetAttributeValue)
 *     is not freed there: fhsm_api_free_value() parks it, intact, and it is
 *     zeroized and freed at the next moment no call is in flight.
 *
 * The lock is writer-preferring, so a destroy is not starved by a stream of
 * signatures. Nested C_ calls (C_CloseAllSessions -> C_CloseSession) do not
 * take it twice: a per-thread mode records that the outermost call holds it.
 * ------------------------------------------------------------------------- */

typedef enum {
    FHSM_API_NONE      = 0,
    FHSM_API_SHARED    = 1,
    FHSM_API_EXCLUSIVE = 2
} fhsm_api_mode_t;

typedef struct { int taken; } fhsm_api_guard_t;

void fhsm_api_enter(fhsm_api_guard_t *g, fhsm_api_mode_t mode);
void fhsm_api_leave(fhsm_api_guard_t *g);

/* The mode the calling thread holds the lock in; FHSM_API_NONE outside any
 * C_ call (the CLI tools and unit tests that drive fhsm_token_* directly). */
fhsm_api_mode_t fhsm_api_mode(void);

/* Zeroize and free an object value now, or -- when the calling thread holds
 * the lock SHARED, so another call may be reading it -- later. `secure` says
 * which allocator owns it, as fhsm_object_t.value_secure does. */
void fhsm_api_free_value(void *p, size_t len, int secure);

/* How many values are parked. For tests/test_apilock, which has no other way
 * to see whether a release was deferred or done. */
size_t fhsm_api_retired_count(void);

/* One line at the top of a C_ function. The guard is released by the
 * compiler on every return path (GCC/Clang cleanup attribute), so the 59
 * guarded functions and their hundreds of early returns cannot leak the lock. */
#define FHSM_API_GUARD(mode) \
    fhsm_api_guard_t fhsm_api_guard_ __attribute__((cleanup(fhsm_api_leave))); \
    fhsm_api_enter(&fhsm_api_guard_, (mode))

#define FHSM_API_SHARED()    FHSM_API_GUARD(FHSM_API_SHARED)
#define FHSM_API_EXCLUSIVE() FHSM_API_GUARD(FHSM_API_EXCLUSIVE)

#endif /* FHSM_APILOCK_H */
