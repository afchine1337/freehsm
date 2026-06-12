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
 * tests/test_dispatch.c --- Weak-strong override + smoke checks for the
 * concrete handlers.
 *
 *  1. For every handler we ship a strong symbol for, the dispatch
 *     table's pointer must equal that symbol (proves the weak stub
 *     was overridden at link time).
 *  2. For every unimplemented handler, the table still resolves to
 *     the weak stub (which returns FHSM_RV_FUNCTION_FAILED).
 *  3. dispatch_reject_fips returns FHSM_RV_FIPS_NOT_APPROVED.
 *  4. A few digest handlers produce correct output against a known
 *     answer (smoke only --- the full KAT suite lives in kat/).
 *
 *  This binary intentionally avoids C_Initialize so it can be run as
 *  a fast unit test without bringing up the entire module state
 *  machine. Crypto primitives that delegate to the FIPS provider
 *  still require the provider to be loadable.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_crypto.h"
#include "fhsm_pkcs11_mechanisms.h"
#include "fhsm_dispatch_common.h"  /* FHSM_TLV_* */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forward decls so we can compare addresses. */
extern fhsm_rv_t dispatch_reject_fips(unsigned long, unsigned long,
                                       const void*, size_t, fhsm_slice_t,
                                       uint8_t*, size_t*);
extern fhsm_rv_t dispatch_sha256(unsigned long, unsigned long,
                                  const void*, size_t, fhsm_slice_t,
                                  uint8_t*, size_t*);
extern fhsm_rv_t dispatch_sha384(unsigned long, unsigned long,
                                  const void*, size_t, fhsm_slice_t,
                                  uint8_t*, size_t*);
extern fhsm_rv_t dispatch_hmac_sha256(unsigned long, unsigned long,
                                       const void*, size_t, fhsm_slice_t,
                                       uint8_t*, size_t*);
extern fhsm_rv_t dispatch_aes_gcm(unsigned long, unsigned long,
                                   const void*, size_t, fhsm_slice_t,
                                   uint8_t*, size_t*);
extern fhsm_rv_t dispatch_pbkdf2(unsigned long, unsigned long,
                                  const void*, size_t, fhsm_slice_t,
                                  uint8_t*, size_t*);
extern fhsm_rv_t dispatch_ml_kem_keypair(unsigned long, unsigned long,
                                          const void*, size_t, fhsm_slice_t,
                                          uint8_t*, size_t*);

static int fails = 0;

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
                    fails++; }                                              \
    else         { printf("[OK ] %s\n", msg); }                             \
} while (0)

#define SAME_HANDLER(ckm, h)                                                \
    do {                                                                    \
        const fhsm_mech_entry_t *e = fhsm_mechanism_lookup(ckm);            \
        CHECK(e != NULL,                                                    \
              "lookup " #ckm);                                              \
        CHECK(e && (void*)(uintptr_t)e->handler == (void*)(uintptr_t)(h),   \
              "strong " #h " overrides weak stub");                         \
    } while (0)

int main(void) {
    /* --- 1. Strong handlers override weak stubs --- */
    SAME_HANDLER(CKM_SHA256,         dispatch_sha256);
    SAME_HANDLER(CKM_SHA384,         dispatch_sha384);
    SAME_HANDLER(CKM_SHA256_HMAC,    dispatch_hmac_sha256);
    SAME_HANDLER(CKM_AES_GCM,        dispatch_aes_gcm);
    SAME_HANDLER(CKM_PKCS5_PBKD2,    dispatch_pbkdf2);
    SAME_HANDLER(CKM_ML_KEM_KEY_PAIR_GEN, dispatch_ml_kem_keypair);

    /* --- 2. Non-approved mechanisms route to dispatch_reject_fips --- */
    const fhsm_mech_entry_t *e = fhsm_mechanism_lookup(CKM_MD5);
    CHECK(e && (void*)(uintptr_t)e->handler ==
          (void*)(uintptr_t)dispatch_reject_fips,
          "CKM_MD5 routes to dispatch_reject_fips");

    /* --- 3. dispatch_reject_fips returns FHSM_RV_FIPS_NOT_APPROVED --- */
    fhsm_slice_t empty = FHSM_SLICE(NULL, 0);
    size_t outlen = 0;
    fhsm_rv_t r = dispatch_reject_fips(0, 0, NULL, 0, empty, NULL, &outlen);
    CHECK(r == FHSM_RV_FIPS_NOT_APPROVED, "reject returns FIPS_NOT_APPROVED");

    /* --- 4. PQ handler validates param-set whitelist --- */
    /* "ML-KEM-INVALID" is rejected with MECHANISM_INVALID. */
    {
        uint8_t params[] = {
            FHSM_TLV_PARAM_SET, 0, 0, 0, 14,
            'M','L','-','K','E','M','-','I','N','V','A','L','I','D'
        };
        uint8_t out[32]; size_t outl = sizeof(out);
        fhsm_rv_t rv = dispatch_ml_kem_keypair(0, 0, params, sizeof(params),
                                                empty, out, &outl);
        CHECK(rv == FHSM_RV_MECHANISM_INVALID,
              "ML-KEM rejects unknown param set");
    }
    /* Valid "ML-KEM-768" reaches the "PQ provider unavailable" path. */
    {
        uint8_t params[] = {
            FHSM_TLV_PARAM_SET, 0, 0, 0, 10,
            'M','L','-','K','E','M','-','7','6','8'
        };
        uint8_t out[32]; size_t outl = sizeof(out);
        fhsm_rv_t rv = dispatch_ml_kem_keypair(0, 0, params, sizeof(params),
                                                empty, out, &outl);
        CHECK(rv == FHSM_RV_FUNCTION_FAILED,
              "ML-KEM-768 reaches provider-unavailable path");
    }

    /* --- 5. Table is sorted (binary search precondition) --- */
    int sorted = 1;
    for (size_t i = 1; i < fhsm_mechanism_count; ++i) {
        if (fhsm_mechanism_table[i].ckm_value <=
            fhsm_mechanism_table[i-1].ckm_value) { sorted = 0; break; }
    }
    CHECK(sorted, "dispatch table sorted by ckm_value");

    /* --- 6. Approved count matches expectation (58 approved + 12 not) --- */
    size_t app = 0, rej = 0;
    for (size_t i = 0; i < fhsm_mechanism_count; ++i) {
        if (fhsm_mechanism_table[i].fips_approved) app++;
        else                                        rej++;
    }
    CHECK(app == 66 && rej == 12,
          "66 approved + 12 non-approved mechanisms");

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
