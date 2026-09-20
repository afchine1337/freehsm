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
 * tests/test_smoke.c --- Smoke test for the libfreehsm.so.
 *
 *  1. C_Initialize triggers POST (KAT + integrity).
 *  2. Check the module state machine is INITIALIZED.
 *  3. Generate 32 random bytes via fhsm_rng_bytes.
 *  4. Encrypt/decrypt 1 KiB via AES-256-GCM.
 *  5. Verify a tampered tag is rejected.
 *  6. C_Finalize returns the module to POWER_OFF.
 *
 * Returns EXIT_SUCCESS if everything passes, EXIT_FAILURE otherwise.
 * In a real evaluation build, this binary is run by the lab during
 * ATE_FUN.1 ("functional testing").
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern unsigned long C_Initialize(void *);
extern unsigned long C_Finalize(void *);

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); return 1; } } while (0)

/* Overwrite a few kilobytes of dead stack below the current frame.
 *
 * fhsm_kat_result_t.vector_id must outlive the function that produced it
 * (see the LIFETIME note in fhsm_crypto.h). One producer formatted the
 * identifier into a local buffer, so every CAVP record pointed into
 * fhsm_kat_run_all's frame after it had returned. AddressSanitizer catches
 * that; an ordinary build reads the stale bytes, which are usually still
 * intact, and the test passes.
 *
 * So the check below reads the identifiers, scribbles over the region they
 * would live in if they were on the stack, and reads them again. A stable
 * string is one that was never there. This is not a proof -- nothing
 * portable is -- but it turns "passes because nothing has overwritten it
 * yet" into "passes because it is not stack memory", without needing a
 * sanitizer build.
 *
 * volatile so the compiler cannot decide the writes are unobservable. */
static void scribble_dead_stack(void) {
    volatile unsigned char pad[8192];
    for (size_t i = 0; i < sizeof(pad); ++i) pad[i] = (unsigned char)(0xA5u ^ i);
}

int main(void) {
    unsigned long rv;

    rv = C_Initialize(NULL);
    fprintf(stderr, "C_Initialize returned 0x%lx\n", rv); CHECK(rv == FHSM_RV_OK, "C_Initialize");
    CHECK(fhsm_state_get() == FHSM_STATE_INITIALIZED, "state after init");

    /* --- RNG smoke --- */
    uint8_t r[32];
    CHECK(fhsm_rng_bytes(r, sizeof(r)) == FHSM_RV_OK, "fhsm_rng_bytes");

    /* --- AES-GCM round-trip --- */
    uint8_t key[32], iv[12], pt[1024], ct[1024], dt[1024], tag[16];
    CHECK(fhsm_rng_bytes(key, sizeof(key)) == FHSM_RV_OK, "key");
    CHECK(fhsm_rng_bytes(iv,  sizeof(iv))  == FHSM_RV_OK, "iv");
    CHECK(fhsm_rng_bytes(pt,  sizeof(pt))  == FHSM_RV_OK, "pt");

    size_t ct_len = sizeof(ct);
    rv = fhsm_aes_gcm_encrypt(
            FHSM_SLICE(key, sizeof(key)),
            FHSM_SLICE(iv,  sizeof(iv)),
            FHSM_SLICE("aad", 3),
            FHSM_SLICE(pt,  sizeof(pt)),
            ct, &ct_len, tag);
    CHECK(rv == FHSM_RV_OK, "encrypt");

    size_t dt_len = sizeof(dt);
    rv = fhsm_aes_gcm_decrypt(
            FHSM_SLICE(key, sizeof(key)),
            FHSM_SLICE(iv,  sizeof(iv)),
            FHSM_SLICE("aad", 3),
            FHSM_SLICE(ct,  ct_len),
            tag, dt, &dt_len);
    CHECK(rv == FHSM_RV_OK, "decrypt");
    CHECK(dt_len == sizeof(pt), "decrypt len");
    CHECK(fhsm_ct_memcmp(dt, pt, dt_len) == 0, "decrypt match");

    /* --- Tampered tag must be rejected --- */
    tag[0] ^= 1;
    dt_len = sizeof(dt);
    rv = fhsm_aes_gcm_decrypt(
            FHSM_SLICE(key, sizeof(key)),
            FHSM_SLICE(iv,  sizeof(iv)),
            FHSM_SLICE("aad", 3),
            FHSM_SLICE(ct,  ct_len),
            tag, dt, &dt_len);
    CHECK(rv == FHSM_RV_ENCRYPTED_DATA_INVALID, "tamper rejected");

    /* --- KAT report --- */
    size_t kat_n = 0;
    const fhsm_kat_result_t *res = fhsm_kat_results(&kat_n);

    /* Identifier lifetime, checked before anything prints them. */
    CHECK(kat_n <= FHSM_KAT_MAX, "KAT count within report capacity");
    char snap[FHSM_KAT_MAX][64];
    for (size_t i = 0; i < kat_n; ++i) {
        CHECK(res[i].algorithm != NULL, "KAT algorithm not NULL");
        CHECK(res[i].vector_id != NULL, "KAT vector_id not NULL");
        snprintf(snap[i], sizeof(snap[i]), "%s", res[i].vector_id);
    }
    scribble_dead_stack();
    for (size_t i = 0; i < kat_n; ++i) {
        if (strcmp(snap[i], res[i].vector_id) != 0) {
            fprintf(stderr,
                    "FAIL: KAT vector_id %zu (%s) did not survive: now \"%s\"\n"
                    "      vector_id must outlive the record --- see the\n"
                    "      LIFETIME note in include/fhsm_crypto.h\n",
                    i, snap[i], res[i].vector_id);
            return 1;
        }
    }

    printf("[smoke] %zu KAT vectors:\n", kat_n);
    for (size_t i = 0; i < kat_n; ++i) {
        printf("        [%c] %-24s %-24s %4u us\n",
                res[i].passed ? '+' : '!',
                res[i].algorithm, res[i].vector_id,
                res[i].duration_us);
        CHECK(res[i].passed, "KAT");
    }

    rv = C_Finalize(NULL);
    CHECK(rv == FHSM_RV_OK, "C_Finalize");
    CHECK(fhsm_state_get() == FHSM_STATE_POWER_OFF, "state after finalize");

    puts("[smoke] OK");
    return 0;
}
