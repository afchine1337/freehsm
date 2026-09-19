/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_encap_flags_store.c --- the second flags byte survives the file.
 *
 * CKA_ENCAPSULATE and CKA_DECAPSULATE are stored in the v3 record's byte 203,
 * which was a pad byte written zero and read by nobody until 2026-09-19. If
 * the serialiser and the parser disagree about it, a restriction holds for the
 * life of the process and vanishes with a restart -- a failure an operator
 * meets after a reboot and never during a test run.
 *
 * This lives at the token layer rather than behind PKCS#11 because that is
 * where a reload can be staged. tests/test_encap_flags.c tried first and
 * could not: closing a session reloads nothing, and C_Finalize followed by
 * C_Initialize leaves the token logged in, so the store is never parsed again.
 * test_throttle_reboot states the principle this file borrows -- "a reboot
 * cannot be staged inside a test, but it does not have to be: the file is the
 * whole interface between two boots".
 *
 * The other half of the compatibility claim is checked too: a record written
 * with byte 203 at zero -- every record this module wrote before today --
 * must load as unrestricted. The bits are negative for exactly that reason,
 * and a polarity mistake would restrict every existing key instead of none.
 * ======================================================================== */
#include "fhsm_common.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

int main(void) {
    char dir[] = "/tmp/fhsm-encapstore-XXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
    char path[512];
    snprintf(path, sizeof path, "%s/tok.tok", dir);

    printf("The second flags byte across a reload\n\n");

    fhsm_token_t *t = NULL;
    if (fhsm_token_init(path, SO_PIN, "encapstore", &t) != FHSM_RV_OK || !t) {
        fprintf(stderr, "fhsm_token_init\n"); return 2;
    }
    if (fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN, strlen(SO_PIN)) != FHSM_RV_OK) {
        fprintf(stderr, "SO login\n"); return 2;
    }
    if (fhsm_token_init_user_pin(t, USER_PIN) != FHSM_RV_OK) {
        fprintf(stderr, "init user pin\n"); return 2;
    }
    fhsm_token_logout(t);
    if (fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) != FHSM_RV_OK) {
        fprintf(stderr, "USER login\n"); return 2;
    }

    /* Two objects: one restricted, one left alone. The second is what catches
     * a polarity mistake -- a bug that sets bits would show on the first, a
     * bug that reads them inverted only on the second. */
    const uint8_t val[32] = { 1, 2, 3, 4 };
    uint32_t h_restricted = 0, h_plain = 0;
    if (fhsm_token_object_add(t, 3 /*CKO_PRIVATE_KEY*/, 0x49 /*CKK_ML_KEM*/,
                               "restricted", val, sizeof val, NULL, 0, 0,
                               &h_restricted) != FHSM_RV_OK
        || fhsm_token_object_add(t, 3, 0x49, "plain", val, sizeof val,
                                  NULL, 0, 0, &h_plain) != FHSM_RV_OK) {
        fprintf(stderr, "object_add\n"); return 2;
    }
    ok(fhsm_token_object_set_flags2(t, h_restricted,
                                     FHSM_OBJF2_NO_DECAPSULATE) == FHSM_RV_OK,
       "the restriction is recorded and the store written");

    uint8_t f2 = 0xFF;
    ok(fhsm_token_object_get_flags2(t, h_restricted, &f2) == FHSM_RV_OK
       && f2 == FHSM_OBJF2_NO_DECAPSULATE,
       "and reads back in the same session");
    f2 = 0xFF;
    ok(fhsm_token_object_get_flags2(t, h_plain, &f2) == FHSM_RV_OK && f2 == 0,
       "the untouched object carries no bits");

    /* The reload. Everything above is now only in the file. */
    fhsm_token_close(t);
    t = NULL;
    if (fhsm_token_load(path, &t) != FHSM_RV_OK || !t) {
        fprintf(stderr, "fhsm_token_load\n"); return 2;
    }
    if (fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) != FHSM_RV_OK) {
        fprintf(stderr, "USER login after reopen\n"); return 2;
    }

    f2 = 0xFF;
    ok(fhsm_token_object_get_flags2(t, h_restricted, &f2) == FHSM_RV_OK
       && f2 == FHSM_OBJF2_NO_DECAPSULATE,
       "the restriction survived the file");
    f2 = 0xFF;
    ok(fhsm_token_object_get_flags2(t, h_plain, &f2) == FHSM_RV_OK && f2 == 0,
       "and the other object came back unrestricted");

    /* The value must be intact too: byte 203 sits immediately before the
     * value in a v3 record, so an off-by-one in either direction would show
     * here rather than in the flags. */
    {
        const uint8_t *v = NULL; size_t vl = 0; uint32_t cl = 0, kt = 0;
        ok(fhsm_token_object_get(t, h_restricted, &v, &vl, &cl, &kt) == FHSM_RV_OK
           && vl == sizeof val && memcmp(v, val, sizeof val) == 0
           && cl == 3 && kt == 0x49,
           "the record around the byte is unharmed");
    }

    fhsm_token_close(t);
    unlink(path);
    rmdir(dir);
    printf("\n%s\n", g_fail ? "FAILURES" : "all good");
    return g_fail ? 1 : 0;
}
