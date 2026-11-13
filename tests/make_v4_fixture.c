/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * make_v4_fixture.c --- produce the v4 token file that tests/test_v4_fixture.c
 * loads under a v5 build.
 *
 * This program is NOT built by `make tests` and is not run in CI. It is
 * compiled inside a checkout of v2.7.0, the last release that writes v4, so
 * that the fixture is a file the old writer wrote. tests/make_v3_fixture.c
 * says why that matters: a v4 blob made by the v5 code would be checked
 * against the beliefs it was built from.
 *
 * Recipe, from the repository root:
 *
 *     git worktree add /tmp/fhsm-v4 v2.7.0
 *     cp tests/make_v4_fixture.c /tmp/fhsm-v4/tests/
 *     cd /tmp/fhsm-v4 && make generate PROFILE=all-mechanisms \
 *        && make PROFILE=all-mechanisms libfreehsm.so
 *     cc -std=c11 -D_GNU_SOURCE -Iinclude -Isrc/dispatch \
 *        -I/usr/local/ssl/include \
 *        -o /tmp/make_v4_fixture tests/make_v4_fixture.c \
 *        .obj/src/*.o .obj/src/dispatch/*.o .obj/src/gen/*.o .obj/kat/*.o \
 *        -L/usr/local/ssl/lib64 -L/usr/local/ssl/lib -lcrypto -ldl -pthread
 *     FHSM_INTEGRITY_ALLOW_UNSIGNED=1 OPENSSL_CONF=/dev/null \
 *        LD_LIBRARY_PATH=/usr/local/ssl/lib64:/usr/local/ssl/lib \
 *        /tmp/make_v4_fixture ~/Documents/dev/freehsm/tests/fixtures/token-v4.tok
 *     cd ~/Documents/dev/freehsm && git worktree remove --force /tmp/fhsm-v4
 *
 * The PINs are the ones every token-layer test uses; the fixture is a test
 * artefact holding no secret.
 * ======================================================================== */
#include "fhsm_common.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <string.h>

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s OUTPUT.tok\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];

    fhsm_token_t *t = NULL;
    if (fhsm_token_init(path, SO_PIN, "v4fixture", &t) != FHSM_RV_OK || !t) {
        fprintf(stderr, "fhsm_token_init\n"); return 2;
    }
    if (fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN, strlen(SO_PIN)) != FHSM_RV_OK
        || fhsm_token_init_user_pin(t, USER_PIN) != FHSM_RV_OK) {
        fprintf(stderr, "SO login / init PIN\n"); return 2;
    }
    fhsm_token_logout(t);
    if (fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) != FHSM_RV_OK) {
        fprintf(stderr, "USER login\n"); return 2;
    }

    /* Two secrets of different lengths, as in the v3 fixture and for the same
     * reason, and a public data object, so that the file has a public section
     * whose plaintext is v4. */
    static const uint8_t v16[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
    };
    static const uint8_t v32[32] = {
        0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87,
        0x78,0x69,0x5A,0x4B,0x3C,0x2D,0x1E,0x0F,
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    static const uint8_t pub[6] = { 'p','u','b','l','i','c' };
    static const uint8_t id16[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint32_t h16 = 0, h32 = 0, hp = 0;
    if (fhsm_token_object_add(t, 4 /*CKO_SECRET_KEY*/, 0x1F /*CKK_AES*/,
                              "sixteen", v16, sizeof v16,
                              id16, sizeof id16, FHSM_OBJF_LOCAL, &h16) != FHSM_RV_OK
        || fhsm_token_object_add(t, 4, 0x1F, "thirtytwo",
                                 v32, sizeof v32, NULL, 0, 0, &h32) != FHSM_RV_OK
        || fhsm_token_object_add(t, 0 /*CKO_DATA*/, 0, "pubdata",
                                 pub, sizeof pub, NULL, 0, 0, &hp) != FHSM_RV_OK) {
        fprintf(stderr, "object_add\n"); return 2;
    }

    /* The v4 policy block, on one object: the last field before the value in
     * a v4 record, and the last before the v5 block in a v5 one. */
    static const uint32_t mechs[2] = { 0x1082u /*CKM_AES_CBC*/, 0x1087u /*CKM_AES_GCM*/ };
    if (fhsm_token_object_set_allowed_mechs(t, h16, mechs, 2) != FHSM_RV_OK) {
        fprintf(stderr, "set_allowed_mechs\n"); return 2;
    }
    if (fhsm_token_object_set_flags2(t, h32, FHSM_OBJF2_NOT_COPYABLE) != FHSM_RV_OK) {
        fprintf(stderr, "set_flags2\n"); return 2;
    }
    {
        uint8_t f3 = 0;
        if (fhsm_token_object_get_flags3(t, hp, &f3) != FHSM_RV_OK
            || fhsm_token_object_set_flags3(t, hp, f3 | FHSM_OBJF3_DATA_PUBLIC) != FHSM_RV_OK) {
            fprintf(stderr, "set_flags3\n"); return 2;
        }
    }
    static const uint8_t app[5] = { 'f','h','s','m','4' };
    if (fhsm_token_object_set_meta(t, hp, NULL, 0, NULL, 0, app, sizeof app) != FHSM_RV_OK) {
        fprintf(stderr, "set_meta\n"); return 2;
    }

    fhsm_token_close(t);
    printf("wrote %s\n", path);
    printf("  \"sixteen\"    %zu-byte AES value, CKA_LOCAL, two allowed mechanisms\n", sizeof v16);
    printf("  \"thirtytwo\"  %zu-byte AES value, not copyable\n", sizeof v32);
    printf("  \"pubdata\"    %zu-byte public data object, CKA_APPLICATION \"fhsm4\"\n", sizeof pub);
    return 0;
}
