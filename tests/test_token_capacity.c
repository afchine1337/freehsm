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
#define N_MAX     64   /* FHSM_MAX_OBJECTS --- keep in sync with fhsm_token.c */

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

int main(void) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/fhsm-capacity-%d.tok", (int)getpid());

    printf("test_token_capacity : objects-blob loader bound (#108)\n");
    if (run_roundtrip(path, N_OBJECTS)) return 1;  /* > 11 : the regression */
    if (run_roundtrip(path, N_MAX))     return 1;  /* upper bound (64)      */
    printf("test_token_capacity : PASS\n");
    return 0;
}
