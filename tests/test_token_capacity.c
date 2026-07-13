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
 * test_token_capacity.c --- Regression test for the objects-blob loader
 * bound (#108, docs/TOKEN_STORE_FORMAT.md "Regression note").
 *
 *  v1.4.0 rejected any objects section with ct_len > 65536 at load
 *  time, while the writer produces up to 8 + 64 x 5620 = 359 688
 *  bytes. Tokens holding more than 11 objects persisted fine but
 *  became unreadable at the next login.
 *
 *  This test :
 *    1. Creates a fresh token in a temp dir, sets the USER PIN.
 *    2. Adds N_OBJECTS (> 11) small AES keys, then logs out + closes
 *       (forcing the blob through write_atomic).
 *    3. Reloads the token from disk, logs USER back in (which decrypts
 *       and parses the blob), and asserts every object is found.
 *    4. Repeats the reload check at FHSM_MAX_OBJECTS (64) to pin the
 *       upper bound.
 *
 *  Like test_smoke, this is an INTERNAL test linked against the
 *  library objects. It requires the OpenSSL provider used by
 *  fhsm_crypto to be loadable (same constraint as test_smoke).
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SO_PIN   "so-pin-test-12345"
#define USER_PIN "user-pin-test-12345"

/* First failing count under the v1.4.0 bug was 12 ; test well past it. */
#define N_OBJECTS 16
#define N_MAX     FHSM_MAX_OBJECTS   /* tracks fhsm_token.h (#125) */

static int fail(const char *msg, fhsm_rv_t rv) {
    fprintf(stderr, "FAIL: %s (rv=0x%08x)\n", msg, (unsigned)rv);
    return 1;
}

static int run_roundtrip(const char *path, uint32_t n_objects) {
    fhsm_token_t *t = NULL;
    fhsm_rv_t rv;

    unlink(path);

    /* --- create + provision ------------------------------------------- */
    rv = fhsm_token_init(path, SO_PIN, "cap-test", &t);
    if (rv != FHSM_RV_OK) return fail("token_init", rv);
    rv = fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN);
    if (rv != FHSM_RV_OK) return fail("SO login", rv);
    rv = fhsm_token_init_user_pin(t, USER_PIN);
    if (rv != FHSM_RV_OK) return fail("init_user_pin", rv);
    fhsm_token_logout(t);

    rv = fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN);
    if (rv != FHSM_RV_OK) return fail("USER login (fresh)", rv);

    uint8_t key[32];
    char label[32];
    for (uint32_t i = 0; i < n_objects; ++i) {
        memset(key, (int)(0xA0 + (i & 0x0F)), sizeof(key));
        snprintf(label, sizeof(label), "cap-key-%03u", i);
        uint32_t h = 0;
        rv = fhsm_token_object_add(t,
                                    0x00000004u /* CKO_SECRET_KEY */,
                                    0x0000001Fu /* CKK_AES */,
                                    label,
                                    key, sizeof(key),
                                    NULL, 0,
                                    0x01 /* CKA_PRIVATE */,
                                    &h);
        if (rv != FHSM_RV_OK) return fail("object_add", rv);
    }
    fhsm_token_logout(t);
    fhsm_token_close(t);
    t = NULL;

    /* --- reload from disk : this is where the v1.4.0 bug fired --------- */
    rv = fhsm_token_load(path, &t);
    if (rv != FHSM_RV_OK) return fail("token_load (reload)", rv);
    rv = fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN);
    if (rv != FHSM_RV_OK)
        return fail("USER login after reload --- objects blob rejected? "
                    "(v1.4.0 capacity regression)", rv);

    uint32_t handles[N_MAX];
    size_t count = 0;
    const uint32_t cls = 0x00000004u; /* CKO_SECRET_KEY */
    rv = fhsm_token_object_find(t, &cls, NULL, handles, N_MAX, &count);
    if (rv != FHSM_RV_OK) return fail("object_find after reload", rv);
    if (count != n_objects) {
        fprintf(stderr, "FAIL: expected %u objects after reload, found %zu\n",
                (unsigned)n_objects, count);
        return 1;
    }

    /* Spot-check one payload round-trips intact. */
    const uint8_t *val = NULL; size_t val_len = 0;
    uint32_t ocls = 0, okt = 0;
    rv = fhsm_token_object_get(t, handles[0], &val, &val_len, &ocls, &okt);
    if (rv != FHSM_RV_OK) return fail("object_get after reload", rv);
    if (val_len != 32) { fprintf(stderr, "FAIL: value_len %zu != 32\n", val_len); return 1; }

    fhsm_token_logout(t);
    fhsm_token_close(t);
    unlink(path);
    printf("  roundtrip %2u objects : OK\n", (unsigned)n_objects);
    return 0;
}

/* --- #110 : certificate-sized objects through the v2 blob ------------------
 * Stores 8 CKO_CERTIFICATE objects with 12 000-byte pseudo-DER values
 * (larger than the legacy v1 5 500-byte field --- exercising the v2
 * variable-record writer/parser), closes, reloads, and verifies one
 * payload byte-for-byte. */
#define CERT_LEN 12000
#define N_CERTS  8

static int run_cert_roundtrip(const char *path) {
    fhsm_token_t *t = NULL;
    fhsm_rv_t rv;
    unlink(path);

    rv = fhsm_token_init(path, SO_PIN, "cert-test", &t);
    if (rv != FHSM_RV_OK) return fail("token_init (cert)", rv);
    rv = fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN);
    if (rv != FHSM_RV_OK) return fail("SO login (cert)", rv);
    rv = fhsm_token_init_user_pin(t, USER_PIN);
    if (rv != FHSM_RV_OK) return fail("init_user_pin (cert)", rv);
    fhsm_token_logout(t);
    rv = fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN);
    if (rv != FHSM_RV_OK) return fail("USER login (cert)", rv);

    uint8_t *der = malloc(CERT_LEN);
    if (!der) return fail("malloc", FHSM_RV_HOST_MEMORY);
    char label[32];
    uint32_t first_handle = 0;
    for (uint32_t i = 0; i < N_CERTS; ++i) {
        for (size_t j = 0; j < CERT_LEN; ++j)
            der[j] = (uint8_t)(i * 31u + j * 7u);
        snprintf(label, sizeof(label), "cert-%03u", i);
        uint32_t h = 0;
        rv = fhsm_token_object_add(t,
                                    0x00000001u /* CKO_CERTIFICATE */,
                                    0x00000000u /* CKC_X_509 */,
                                    label, der, CERT_LEN,
                                    NULL, 0,
                                    0x02 /* CKA_EXTRACTABLE */, &h);
        if (rv != FHSM_RV_OK) { free(der); return fail("cert object_add", rv); }
        if (i == 0) first_handle = h;
    }
    fhsm_token_logout(t);
    fhsm_token_close(t);
    t = NULL;

    rv = fhsm_token_load(path, &t);
    if (rv != FHSM_RV_OK) { free(der); return fail("token_load (cert reload)", rv); }
    rv = fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN);
    if (rv != FHSM_RV_OK) { free(der); return fail("USER login after cert reload", rv); }

    const uint8_t *val = NULL; size_t val_len = 0;
    uint32_t ocls = 0, okt = 0;
    rv = fhsm_token_object_get(t, first_handle, &val, &val_len, &ocls, &okt);
    if (rv != FHSM_RV_OK) { free(der); return fail("cert object_get", rv); }
    if (val_len != CERT_LEN || ocls != 0x00000001u) {
        fprintf(stderr, "FAIL: cert len/class mismatch (len=%zu cls=0x%x)\n",
                val_len, (unsigned)ocls);
        free(der); return 1;
    }
    for (size_t j = 0; j < CERT_LEN; ++j)
        der[j] = (uint8_t)(j * 7u);
    if (memcmp(val, der, CERT_LEN) != 0) {
        fprintf(stderr, "FAIL: cert payload corrupted across reload\n");
        free(der); return 1;
    }
    free(der);
    fhsm_token_logout(t);
    fhsm_token_close(t);
    unlink(path);
    printf("  cert roundtrip %u x %u bytes : OK\n", N_CERTS, CERT_LEN);
    return 0;
}

/* --- #125 I1 : store-full must return CKR_DEVICE_MEMORY, not
 * CKR_HOST_MEMORY. Fill to FHSM_MAX_OBJECTS then assert the next add is
 * rejected with the token-storage code. */
#define FHSM_RV_DEVICE_MEMORY_ 0x00000131u
static int run_store_full(const char *path) {
    fhsm_token_t *t = NULL; fhsm_rv_t rv; unlink(path);
    rv = fhsm_token_init(path, SO_PIN, "full-test", &t);
    if (rv != FHSM_RV_OK) return fail("token_init (full)", rv);
    if ((rv = fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN))) return fail("SO login (full)", rv);
    if ((rv = fhsm_token_init_user_pin(t, USER_PIN)))     return fail("init_user_pin (full)", rv);
    fhsm_token_logout(t);
    if ((rv = fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN))) return fail("USER login (full)", rv);
    uint8_t key[32] = {0}; char label[32]; uint32_t h;
    for (uint32_t i = 0; i < N_MAX; ++i) {
        snprintf(label, sizeof(label), "full-%03u", i);
        rv = fhsm_token_object_add(t, 0x4u, 0x1Fu, label, key, sizeof key, NULL, 0, 0x1, &h);
        if (rv != FHSM_RV_OK) return fail("fill add", rv);
    }
    rv = fhsm_token_object_add(t, 0x4u, 0x1Fu, "overflow", key, sizeof key, NULL, 0, 0x1, &h);
    if (rv != FHSM_RV_DEVICE_MEMORY_) {
        fprintf(stderr, "FAIL: store-full add -> 0x%08x (want CKR_DEVICE_MEMORY 0x131)\n", (unsigned)rv);
        return 1;
    }
    fhsm_token_logout(t); fhsm_token_close(t); unlink(path);
    printf("  store-full -> CKR_DEVICE_MEMORY : OK\n");
    return 0;
}

int main(void) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/fhsm-capacity-%d.tok", (int)getpid());

    printf("test_token_capacity : objects-blob bounds (#108) + v2 records (#110)\n");
    if (run_roundtrip(path, N_OBJECTS)) return 1;  /* > 11 : the regression */
    if (run_roundtrip(path, N_MAX))     return 1;  /* upper bound (64)      */
    if (run_cert_roundtrip(path))       return 1;  /* v2 variable records   */
    if (run_store_full(path))           return 1;  /* #125 I1 : DEVICE_MEMORY */
    printf("test_token_capacity : PASS\n");
    return 0;
}
