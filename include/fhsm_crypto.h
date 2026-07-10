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
 * fhsm_crypto.h --- FIPS-approved cryptographic primitives.
 *
 *  All primitives are delegated to OpenSSL 3.x with the FIPS provider
 *  loaded. The wrappers below are the *only* path through which the
 *  cryptographic module performs primitive operations. This single-entry
 *  invariant is required by FIPS 140-3 §7.4.5 ("cryptographic module
 *  interface") and CC EAL4+ TSF specification.
 *
 *  Each wrapper:
 *    --- accepts only sized slices (no NUL-terminated strings)
 *    --- enforces the FIPS-only flag (FHSM_FIPS_ONLY)
 *    --- traces entry / exit / parameters (length only, never key
 *        material) to the audit log via fhsm_audit_event()
 *    --- zeroizes intermediate state before return
 *
 *  Approved algorithms (FIPS 140-3 / CAVP IUT):
 *    Symmetric          : AES-128/192/256 in GCM, CBC, KW, KWP
 *    Hash               : SHA-256, SHA-384, SHA-512, SHA3-256/384/512
 *    MAC                : HMAC-SHA-256/384/512, CMAC-AES-128/256
 *    Signature          : RSA-PSS-2048/3072/4096, ECDSA P-256/P-384/P-521,
 *                          EdDSA Ed25519/Ed448
 *    KEM/KAS            : ECDH P-256/P-384, X25519, X448
 *    PQ Signature       : ML-DSA-44/65/87 (FIPS 204), SLH-DSA-* (FIPS 205)
 *    PQ KEM             : ML-KEM-512/768/1024 (FIPS 203)
 *    KDF                : HKDF-SHA-256/384/512, PBKDF2-HMAC-SHA-256/512
 *    DRBG               : CTR_DRBG-AES-256 (NIST SP 800-90A)
 *
 *  Non-approved (rejected when FHSM_FIPS_ONLY = 1):
 *    MD5, SHA-1 (except inside HMAC for TLS legacy), DES, 3DES, RC4,
 *    AES-ECB with > 16 input bytes, RSA-PKCS1-v1.5 sig, DSA, raw RSA.
 *
 * ========================================================================= */

#ifndef FHSM_CRYPTO_H
#define FHSM_CRYPTO_H

#include "fhsm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Subsystem lifecycle. Called from fhsm_initialize() / fhsm_finalize().
 * fhsm_crypto_init() runs the algorithm-self-test (KAT) for every
 * approved primitive listed above before returning OK. On any KAT
 * failure the module enters ERROR state (fhsm_state_latch_error) and
 * this function returns FHSM_RV_KAT_FAILED.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_crypto_init(void);
void      fhsm_crypto_finalize(void);

/* ---------------------------------------------------------------------------
 * DRBG --- the single approved RNG. CTR_DRBG-AES-256 with NIST SP 800-90B
 * conformant entropy source (Linux getrandom(GRND_RANDOM) gated by the
 * kernel's pool initialization, or /dev/random on platforms without
 * getrandom). The DRBG is reseeded every 2^16 requests or every hour,
 * whichever comes first (SP 800-90A §9.5).
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_rng_bytes(uint8_t *out, size_t n);

/* Reseed on demand. Called from the audit log to inject application
 * personalization. Returns FHSM_RV_RNG_FAILURE on entropy source failure
 * (which also latches the module ERROR state). */
fhsm_rv_t fhsm_rng_reseed(fhsm_slice_t personalization);

/* ---------------------------------------------------------------------------
 * AES-256-GCM ---  authenticated encryption used by:
 *   - token store payload encryption (DEK as key)
 *   - audit log entry encryption (audit MAC key as key)
 *   - PIN wrap (PBKDF2-derived key as key)
 *   - C_Encrypt / C_Decrypt with mechanism CKM_AES_GCM
 *
 *  Tag length is fixed at 16 octets (128 bits). Smaller tag lengths are
 *  rejected (FIPS SP 800-38D §5.2.1.2). IV length is fixed at 12 octets;
 *  longer IVs require GHASH expansion which is forbidden in approved
 *  mode.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_aes_gcm_encrypt(fhsm_slice_t key,
                                fhsm_slice_t iv,
                                fhsm_slice_t aad,
                                fhsm_slice_t plaintext,
                                uint8_t      *ciphertext,
                                size_t       *ciphertext_len /* in/out */,
                                uint8_t       tag[16]);

fhsm_rv_t fhsm_aes_gcm_decrypt(fhsm_slice_t key,
                                fhsm_slice_t iv,
                                fhsm_slice_t aad,
                                fhsm_slice_t ciphertext,
                                const uint8_t tag[16],
                                uint8_t       *plaintext,
                                size_t        *plaintext_len /* in/out */);

/* ---------------------------------------------------------------------------
 * HMAC --- the only MAC available for audit-log chaining and PBKDF2.
 * Approved hash families : SHA-256, SHA-384, SHA-512.
 * ----------------------------------------------------------------------- */
typedef enum fhsm_hash_e {
    FHSM_HASH_SHA256 = 1,
    FHSM_HASH_SHA384 = 2,
    FHSM_HASH_SHA512 = 3,
    FHSM_HASH_SHA3_256 = 4,
    FHSM_HASH_SHA3_384 = 5,
    FHSM_HASH_SHA3_512 = 6,
    /* Non-FIPS legacy digests (interop / general-purpose profile only ;
     * rejected in the fips-strict operation path). */
    FHSM_HASH_SHA1 = 7,
    FHSM_HASH_MD5  = 8
} fhsm_hash_t;

size_t fhsm_hash_size(fhsm_hash_t h);

fhsm_rv_t fhsm_hash_oneshot(fhsm_hash_t alg,
                             fhsm_slice_t data,
                             uint8_t *out,
                             size_t *out_len);

fhsm_rv_t fhsm_hmac(fhsm_hash_t alg,
                     fhsm_slice_t key,
                     fhsm_slice_t data,
                     uint8_t      *mac,
                     size_t       *mac_len);

/* ---------------------------------------------------------------------------
 * PBKDF2 --- approved key derivation for password-based wrapping.
 * Minimum iteration count : 200_000 (NIST SP 800-132 + OWASP 2023).
 * Output length must be a multiple of the hash output length and at
 * most 64 octets (we never derive more than a single AES-256 key).
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_pbkdf2(fhsm_hash_t alg,
                       fhsm_slice_t password,
                       fhsm_slice_t salt,
                       uint32_t    iterations,
                       uint8_t     *out,
                       size_t       out_len);

/* ---------------------------------------------------------------------------
 * Power-on self-test report (Known Answer Test status).
 *
 *  After fhsm_crypto_init() succeeds, this returns a snapshot of every
 *  KAT result: which test ran, KAT vector identifier, pass/fail. The
 *  output is appended to the audit log as event "kat_report" and is
 *  also available to the operator via the test harness.
 *
 *  Used to satisfy FIPS 140-3 §7.10.2 (pre-operational self-test
 *  reporting) and CC EAL4+ ATE_FUN.1 (functional testing).
 * ----------------------------------------------------------------------- */
typedef struct fhsm_kat_result_s {
    const char *algorithm;     /* "AES-GCM-256", "HMAC-SHA-256", ... */
    const char *vector_id;     /* CAVP vector identifier */
    int         passed;        /* 1 if matched expected output, else 0 */
    uint32_t    duration_us;   /* execution time, for performance regression */
} fhsm_kat_result_t;

const fhsm_kat_result_t *fhsm_kat_results(size_t *count);

/* Run every CAVP-derived KAT vector and populate the report array.
 * Definition in kat/fhsm_kat_vectors.c. Declared in this public
 * header so both caller and definition site share the prototype
 * (gcc 14 -Wmissing-prototypes). */
fhsm_rv_t fhsm_kat_run_all(fhsm_kat_result_t *out, size_t cap,
                            size_t *count);

/* Run the published-CAVP-vector extension suite (AES-GCM TC13-16 +
 * HMAC-SHA-256 RFC4231 TC1/2/3/6). Definition in kat/cavp_extended.c.
 * Appends results to `out` starting at index *count_io and advances
 * the cursor. Called by fhsm_kat_run_all after its smoke vectors. */
fhsm_rv_t fhsm_kat_cavp_extended(fhsm_kat_result_t *out, size_t cap,
                                   size_t *count_io);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_CRYPTO_H */
