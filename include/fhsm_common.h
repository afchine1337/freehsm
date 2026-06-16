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
 * fhsm_common.h --- Types, error codes, build-time configuration.
 *
 * FreeHSM C natif --- module cryptographique FIPS 140-3 / CC EAL4+ candidate.
 * ===========================================================================
 *
 *  This header is part of the security perimeter (TOE boundary). Every
 *  translation unit of the cryptographic module includes it as its first
 *  non-standard include. It is intentionally kept dependency-free
 *  (only <stddef.h> / <stdint.h> from the C11 freestanding subset) so the
 *  evaluator can prove that no host-OS API leaks into the security-relevant
 *  call graph.
 *
 *  Naming convention:
 *    --- All public symbols are prefixed `fhsm_` (function), `FHSM_` (macro),
 *        or `fhsm_*_t` (typedef).
 *    --- All return codes use the `fhsm_rv_t` enum below (no bare ints).
 *    --- Buffers are passed as (pointer, length) pairs; output length is
 *        always returned via an in-out length pointer (PKCS#11 convention).
 *
 *  Threading model:
 *    The module is reentrant. The single mutable global is the
 *    cryptographic-module state machine (`fhsm_module_state`), protected
 *    by a single global mutex declared in `fhsm_state.c`. All other state
 *    is per-session and lives on the caller's stack or in heap arenas
 *    allocated through `fhsm_secure_malloc`.
 *
 *  Memory model:
 *    Sensitive material (DEKs, PINs, private keys, session-key
 *    intermediate values, KAT plaintexts) MUST be allocated through
 *    `fhsm_secure_malloc` / `fhsm_secure_free` (OpenSSL secure heap
 *    `OPENSSL_secure_malloc`). Buffers freed through these wrappers are
 *    automatically zeroized before return to the allocator. See §3 of
 *    docs/FIPS_140_3.md ("Cryptographic Module Specification").
 * ========================================================================= */

#ifndef FHSM_COMMON_H
#define FHSM_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Version --- bumped manually on every cryptographic-module release.
 * The version is part of the certified TOE identity: any change here
 * invalidates the current FIPS 140-3 / CC certificate.
 * ----------------------------------------------------------------------- */
#define FHSM_VERSION_MAJOR   1
#define FHSM_VERSION_MINOR   1
#define FHSM_VERSION_PATCH   3
#define FHSM_VERSION_STRING  "1.1.3-FIPS"

/* SHA-256 of the entire signed binary --- declaration moved to
 * include/fhsm_integrity.h (the canonical location). Including
 * fhsm_integrity.h from any TU that needs the digest. */

/* ---------------------------------------------------------------------------
 * Return values --- all module functions return fhsm_rv_t (uint32_t). The
 * numeric values intentionally match PKCS#11 CKR_* so the façade layer
 * can pass them through to applications unchanged.
 *
 * Vendor-reserved codes (>= 0x80000000) are FreeHSM-specific extensions
 * per PKCS#11 §A.4. We use #define rather than an enum because C11
 * enumerator values are restricted to the int range.
 * ----------------------------------------------------------------------- */
typedef uint32_t fhsm_rv_t;

#define FHSM_RV_OK                          0x00000000u
#define FHSM_RV_CANCEL                      0x00000001u
#define FHSM_RV_HOST_MEMORY                 0x00000002u
#define FHSM_RV_SLOT_ID_INVALID             0x00000003u
#define FHSM_RV_GENERAL_ERROR               0x00000005u
#define FHSM_RV_FUNCTION_FAILED             0x00000006u
#define FHSM_RV_ARGUMENTS_BAD               0x00000007u
#define FHSM_RV_ATTRIBUTE_VALUE_INVALID     0x00000013u
#define FHSM_RV_DATA_INVALID                0x00000020u
#define FHSM_RV_ENCRYPTED_DATA_INVALID      0x00000040u
#define FHSM_RV_KEY_HANDLE_INVALID          0x00000060u
#define FHSM_RV_KEY_SIZE_RANGE              0x00000062u
#define FHSM_RV_KEY_TYPE_INCONSISTENT       0x00000063u
#define FHSM_RV_MECHANISM_INVALID           0x00000070u
#define FHSM_RV_OPERATION_ACTIVE            0x00000090u
#define FHSM_RV_OPERATION_NOT_INITIALIZED   0x00000091u
#define FHSM_RV_PIN_INCORRECT               0x000000A0u
#define FHSM_RV_PIN_LOCKED                  0x000000A4u
#define FHSM_RV_SESSION_CLOSED              0x000000B0u
#define FHSM_RV_SESSION_HANDLE_INVALID      0x000000B3u
#define FHSM_RV_SIGNATURE_INVALID           0x000000C0u
#define FHSM_RV_TOKEN_NOT_PRESENT           0x000000E0u
#define FHSM_RV_USER_NOT_LOGGED_IN          0x00000101u
#define FHSM_RV_CRYPTOKI_NOT_INITIALIZED    0x00000190u

/* Vendor-reserved extensions (FreeHSM). */
#define FHSM_RV_KAT_FAILED                  0x80000001u
#define FHSM_RV_INTEGRITY_FAILED            0x80000002u
#define FHSM_RV_FIPS_NOT_APPROVED           0x80000003u
#define FHSM_RV_PIN_THROTTLED               0x80000004u
#define FHSM_RV_TPM_UNAVAILABLE             0x80000005u
#define FHSM_RV_KMS_QUORUM_FAILED           0x80000006u
#define FHSM_RV_SECURE_HEAP_EXHAUSTED       0x80000007u
#define FHSM_RV_RNG_FAILURE                 0x80000008u

/* ---------------------------------------------------------------------------
 * Operator roles (PKCS#11 CKU_*). Defined here in fhsm_common.h because
 * both fhsm_audit.h and fhsm_token.h reference it.
 * ----------------------------------------------------------------------- */
typedef enum fhsm_role_e {
    FHSM_ROLE_NONE = 0,
    FHSM_ROLE_SO   = 1,
    FHSM_ROLE_USER = 2
} fhsm_role_t;

/* ---------------------------------------------------------------------------
 * Cryptographic-module state machine (FIPS 140-3 §7.4.2)
 *
 *      ┌────────────────┐  POST OK         ┌──────────────────┐
 *      │ POWER-OFF      │ ───────────────► │ INITIALIZED      │
 *      └────────────────┘                  └──────────────────┘
 *              │  POST FAIL                          │
 *              ▼                                     │ login OK
 *      ┌────────────────┐                            ▼
 *      │ ERROR (latched)│                  ┌──────────────────┐
 *      └────────────────┘                  │ AUTHENTICATED    │
 *                                          └──────────────────┘
 *
 * The module ENTERS the ERROR state on any KAT failure, integrity check
 * failure, or critical RNG failure. The only exit from ERROR is a full
 * process restart (operator-attended re-initialization). This is required
 * by FIPS 140-3 §7.10.5 for ISO/IEC 19790:2012 conformance.
 * ----------------------------------------------------------------------- */
typedef enum fhsm_module_state_e {
    FHSM_STATE_POWER_OFF      = 0,
    FHSM_STATE_INITIALIZING   = 1,  /* POST in progress */
    FHSM_STATE_INITIALIZED    = 2,  /* POST passed, no user authenticated */
    FHSM_STATE_AUTHENTICATED  = 3,  /* CO or USER authenticated */
    FHSM_STATE_ERROR          = 4   /* latched, requires restart */
} fhsm_module_state_t;

/* Read-only query of current state. Thread-safe. */
fhsm_module_state_t fhsm_state_get(void);

/* Transition --- internal only, exposed for the test harness. */
fhsm_rv_t fhsm_state_set(fhsm_module_state_t s);

/* Latch ERROR state. Idempotent. Called by any service that detects an
 * integrity / KAT / RNG fault. All subsequent service calls return
 * FHSM_RV_FUNCTION_FAILED until the module is restarted. */
void fhsm_state_latch_error(const char *reason);

/* ---------------------------------------------------------------------------
 * Secure heap allocator (FIPS 140-3 §7.9.5 zeroization)
 *
 *  Allocations go through OpenSSL's secure heap (OPENSSL_secure_malloc),
 *  which is a single mmap()-ed + mlock()-ed arena. CRYPTO_secure_clear_free
 *  zeroizes before return. This is the *only* allocator the cryptographic
 *  module is allowed to use for sensitive data. See docs/FIPS_140_3.md §5.
 *
 *  The arena size is configured at build time (default 256 KiB) and
 *  initialized in fhsm_secure_heap_init(). Subsequent allocations beyond
 *  the arena return NULL --- the caller MUST handle exhaustion gracefully.
 * ----------------------------------------------------------------------- */
#ifndef FHSM_SECURE_HEAP_BYTES
#define FHSM_SECURE_HEAP_BYTES   (256 * 1024)
#endif

#ifndef FHSM_SECURE_HEAP_MINSIZE
#define FHSM_SECURE_HEAP_MINSIZE 32  /* must be a power of 2 */
#endif

fhsm_rv_t  fhsm_secure_heap_init(void);
void      *fhsm_secure_malloc(size_t n);
void      *fhsm_secure_zalloc(size_t n);   /* zero-initialized */
void       fhsm_secure_free(void *p);
size_t     fhsm_secure_heap_used(void);
size_t     fhsm_secure_heap_total(void);

/* Force-zeroize a buffer NOT allocated through fhsm_secure_malloc
 * (e.g. a transient stack buffer). Compiler-barrier-protected so the
 * memset() cannot be elided as dead-store. */
void fhsm_zeroize(void *p, size_t n);

/* Constant-time compare. Used everywhere a length-mismatch or content-
 * mismatch on sensitive material is checked (HMAC tags, PINs, KAT
 * expected outputs). */
int fhsm_ct_memcmp(const void *a, const void *b, size_t n);

/* ---------------------------------------------------------------------------
 * Sized-buffer convenience type (passed by value, immutable view).
 * ----------------------------------------------------------------------- */
typedef struct fhsm_slice_s {
    const uint8_t *data;
    size_t         len;
} fhsm_slice_t;

#define FHSM_SLICE(p, n)  ((fhsm_slice_t){ (const uint8_t *)(p), (size_t)(n) })

/* ---------------------------------------------------------------------------
 * Build-time switches --- guarded so the evaluator can audit them at a
 * single point of the source tree.
 * ----------------------------------------------------------------------- */

/* When 1, only FIPS-approved algorithms are dispatchable through C_*. All
 * non-approved mechanisms return FHSM_RV_FIPS_NOT_APPROVED. Default in
 * shipping builds. Set to 0 only for interop tests against legacy systems.
 *
 * The setting is also queryable at runtime via fhsm_fips_mode(). */
#ifndef FHSM_FIPS_ONLY
#define FHSM_FIPS_ONLY 1
#endif

int fhsm_fips_mode(void);

/* When 1, the audit log is mandatory: every C_* entry point emits an
 * event line, and refusal to write to the log file is a fatal error
 * (the module enters ERROR state). Default in shipping builds. */
#ifndef FHSM_AUDIT_MANDATORY
#define FHSM_AUDIT_MANDATORY 1
#endif


/* When 1, PIN throttling is enabled (exponential backoff after each
 * failed login). The base delay is FHSM_PIN_THROTTLE_BASE_MS. */
#ifndef FHSM_PIN_THROTTLE_BASE_MS
#define FHSM_PIN_THROTTLE_BASE_MS 500
#endif
#ifndef FHSM_PIN_THROTTLE_MAX_MS
#define FHSM_PIN_THROTTLE_MAX_MS  60000
#endif
#ifndef FHSM_PIN_MAX_FAILED
#define FHSM_PIN_MAX_FAILED       5
#endif

#ifdef __cplusplus
}
#endif

#endif /* FHSM_COMMON_H */
