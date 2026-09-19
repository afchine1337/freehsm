/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * make_v3_fixture.c --- produce the v3 token file that tests/test_v3_fixture.c
 * loads under a v4 build.
 *
 * This program is NOT built by `make tests` and is not run in CI. It exists to
 * be compiled inside a checkout of the tree as it stood BEFORE the v4 record,
 * so that the fixture is a file the old writer actually wrote rather than one
 * this build produced while pretending to be older.
 *
 * That distinction is the whole point of the fixture. A v3 blob synthesised by
 * the v4 code would be checked against the same beliefs it was built from: if
 * an offset is wrong in the writer it would be wrong in the synthesiser too,
 * and the test would agree with itself. The only file that can contradict the
 * new reader is one the new code had no part in making.
 *
 * Recipe, from the repository root, while the v4 work is still uncommitted so
 * that HEAD is the last pre-v4 commit:
 *
 *     git worktree add /tmp/fhsm-v3 HEAD
 *     cp tests/make_v3_fixture.c /tmp/fhsm-v3/tests/
 *     cd /tmp/fhsm-v3 && make
 *     cc -std=c11 -D_GNU_SOURCE -Iinclude -Isrc/dispatch \
 *        -I/usr/local/ssl/include \
 *        -o /tmp/make_v3_fixture tests/make_v3_fixture.c \
 *        .obj/src/*.o .obj/src/dispatch/*.o .obj/src/gen/*.o .obj/kat/*.o \
 *        -L/usr/local/ssl/lib64 -L/usr/local/ssl/lib -lcrypto -ldl -pthread
 *     FHSM_INTEGRITY_ALLOW_UNSIGNED=1 OPENSSL_CONF=/dev/null \
 *        LD_LIBRARY_PATH=/usr/local/ssl/lib64:/usr/local/ssl/lib \
 *        /tmp/make_v3_fixture ~/Documents/dev/freehsm/tests/fixtures/token-v3.tok
 *     cd ~/Documents/dev/freehsm && git worktree remove /tmp/fhsm-v3
 *
 * The hardening and warning flags of the real build are deliberately absent
 * above: this program is compiled once, by hand, and the object files it links
 * against were already built by `make` with all of them.
 *
 * The PINs below are the ones every token-layer test uses; the fixture is a
 * test artefact holding no secret, and its PIN has to be known for the test to
 * open it at all.
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
    if (fhsm_token_init(path, SO_PIN, "v3fixture", &t) != FHSM_RV_OK || !t) {
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

    /* Two objects with different value lengths. The record is variable-sized
     * from v2 on, so two identical lengths would not catch an off-by-one in
     * the per-record advance -- the second record would start in the right
     * place by coincidence. */
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
    uint32_t h16 = 0, h32 = 0;
    static const uint8_t id16[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    if (fhsm_token_object_add(t, 4 /*CKO_SECRET_KEY*/, 0x1F /*CKK_AES*/,
                              "sixteen", v16, sizeof v16,
                              id16, sizeof id16, 0, &h16) != FHSM_RV_OK
        || fhsm_token_object_add(t, 4, 0x1F, "thirtytwo",
                                 v32, sizeof v32,
                                 NULL, 0, 0, &h32) != FHSM_RV_OK) {
        fprintf(stderr, "object_add\n"); return 2;
    }

    /* One object carries a flags2 bit. A v3 record stores it in byte 203, the
     * last byte before the value -- which under v4 is the last byte before the
     * policy block. If the v4 reader miscounts the block it will read byte 203
     * or the value as policy, and this bit is what says so. */
    if (fhsm_token_object_set_flags2(t, h32, FHSM_OBJF2_NOT_COPYABLE) != FHSM_RV_OK) {
        fprintf(stderr, "set_flags2\n"); return 2;
    }

    fhsm_token_close(t);
    printf("wrote %s\n", path);
    printf("  handle %u  label \"sixteen\"    %zu-byte value\n",
           h16, sizeof v16);
    printf("  handle %u  label \"thirtytwo\"  %zu-byte value, flags2=0x%02X\n",
           h32, sizeof v32, (unsigned)FHSM_OBJF2_NOT_COPYABLE);
    printf("\nThe handles above are what tests/test_v3_fixture.c expects.\n");
    return 0;
}
