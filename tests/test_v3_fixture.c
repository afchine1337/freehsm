/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_v3_fixture.c --- a token written before the v4 record still opens.
 *
 * This is the case that protects every key already on disk. Everything else in
 * the v4 work can be re-run; a key an operator stored last month cannot be
 * re-created, and a reader that mis-parses its record does not fail loudly --
 * it returns a value, and the value is wrong.
 *
 * The fixture is NOT generated here. tests/make_v3_fixture.c produced it
 * inside a checkout of the tree as it stood before v4, and the file is
 * committed. A v3 blob synthesised by the v4 code would be built from the same
 * beliefs the reader holds: an offset wrong in one would be wrong in the other
 * and the test would agree with itself. Only a file this build had no part in
 * making can contradict it -- the same argument test_encap_flags_store makes
 * about a reboot, one step further back.
 *
 * What a v3 record means, read by a v4 build: no policy. Not "empty policy",
 * which forbids everything -- absent, which forbids nothing. If the four
 * FHSM_OBJF2_HAS_* bits came back set, every key in every existing token would
 * become a key that permits nothing, on the next load, silently.
 * ======================================================================== */
#include "fhsm_common.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USER_PIN "userpin1234"
#define FIXTURE  "tests/fixtures/token-v3.tok"

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

/* The two objects tests/make_v3_fixture.c wrote. */
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

int main(void)
{
    printf("A v3 token file, read by a v4 build\n\n");

    /* The fixture is opened read-only in spirit but the store writes on some
     * paths, so work on a copy: a test that rewrites its own fixture passes
     * once and then tests the file it just wrote. */
    char dir[] = "/tmp/fhsm-v3fix-XXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
    char path[512];
    snprintf(path, sizeof path, "%s/tok.tok", dir);
    {
        FILE *in = fopen(FIXTURE, "rb");
        if (!in) {
            fprintf(stderr,
                    "cannot open %s -- run tests/make_v3_fixture.c in a\n"
                    "pre-v4 checkout first; see its header for the recipe.\n",
                    FIXTURE);
            return 2;
        }
        FILE *out = fopen(path, "wb");
        if (!out) { perror("fopen copy"); fclose(in); return 2; }
        char buf[4096]; size_t n;
        while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
            if (fwrite(buf, 1, n, out) != n) { perror("fwrite"); return 2; }
        }
        fclose(in);
        if (fclose(out) != 0) { perror("fclose"); return 2; }
    }

    fhsm_token_t *t = NULL;
    ok(fhsm_token_load(path, &t) == FHSM_RV_OK && t != NULL,
       "the v3 file loads");
    if (!t) { printf("\nFAILURES\n"); return 1; }
    ok(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN))
       == FHSM_RV_OK,
       "and the stored PIN still opens it");

    /* Find the objects by label rather than by a hard-coded handle: handles
     * are assigned by the writer and a fixture regenerated later could hand
     * them out differently. The labels are the fixture's contract. */
    uint32_t h16 = 0, h32 = 0;
    {
        uint32_t all[16];
        size_t n = 0;
        ok(fhsm_token_object_find(t, NULL, NULL, all, 16, &n) == FHSM_RV_OK
           && n == 2,
           "both objects are there");
        uint32_t one[4]; size_t k = 0;
        if (fhsm_token_object_find(t, NULL, "sixteen", one, 4, &k) == FHSM_RV_OK
            && k == 1) h16 = one[0];
        k = 0;
        if (fhsm_token_object_find(t, NULL, "thirtytwo", one, 4, &k) == FHSM_RV_OK
            && k == 1) h32 = one[0];
        ok(h16 != 0 && h32 != 0, "and both are found by their labels");
    }
    if (!h16 || !h32) { printf("\nFAILURES\n"); return 1; }

    /* The values. Two different lengths on purpose: a per-record advance that
     * is wrong by the size of the policy block would put the second record's
     * fields inside the first record's value, and two equal lengths could hide
     * that by landing somewhere plausible. */
    {
        const uint8_t *v = NULL; size_t vl = 0; uint32_t cl = 0, kt = 0;
        ok(fhsm_token_object_get(t, h16, &v, &vl, &cl, &kt) == FHSM_RV_OK
           && vl == sizeof v16 && memcmp(v, v16, sizeof v16) == 0,
           "the 16-byte value came back intact");
        ok(fhsm_token_object_get(t, h32, &v, &vl, &cl, &kt) == FHSM_RV_OK
           && vl == sizeof v32 && memcmp(v, v32, sizeof v32) == 0,
           "and so did the 32-byte one");
    }

    /* flags2 sits at byte 203, immediately before where the policy block now
     * begins. A v4 reader that starts the block one byte early reads this and
     * loses the bit; one that starts late reads a policy byte as a flag. */
    {
        uint8_t f2 = 0xFF;
        ok(fhsm_token_object_get_flags2(t, h32, &f2) == FHSM_RV_OK
           && f2 == FHSM_OBJF2_NOT_COPYABLE,
           "the v3 flags2 bit survived the format change");
        f2 = 0xFF;
        ok(fhsm_token_object_get_flags2(t, h16, &f2) == FHSM_RV_OK && f2 == 0,
           "and the object without one still has none");
    }

    /* The point of the whole file. */
    {
        uint8_t a = 0xFF, w = 0xFF, u = 0xFF, d = 0xFF;
        ok(fhsm_token_object_get_policy_counts(t, h16, &a, &w, &u, &d)
           == FHSM_RV_OK && a == 0 && w == 0 && u == 0 && d == 0,
           "a v3 object carries no policy entries");
        uint8_t f2 = 0xFF;
        ok(fhsm_token_object_get_flags2(t, h16, &f2) == FHSM_RV_OK
           && (f2 & (FHSM_OBJF2_HAS_ALLOWED_MECH | FHSM_OBJF2_HAS_WRAP_TMPL
                     | FHSM_OBJF2_HAS_UNWRAP_TMPL | FHSM_OBJF2_HAS_DERIVE_TMPL)) == 0,
           "and no policy is claimed to be present -- absent, not empty");
    }

    /* Re-writing migrates it. The file on disk becomes v4; the objects must
     * not change on the way through, and the second load is what says so. */
    {
        ok(fhsm_token_object_set_label(t, h16, "sixteen") == FHSM_RV_OK,
           "a write migrates the file to v4");
        fhsm_token_close(t);
        t = NULL;
        ok(fhsm_token_load(path, &t) == FHSM_RV_OK && t != NULL,
           "the migrated file loads again");
        if (!t) { printf("\nFAILURES\n"); return 1; }
        ok(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN))
           == FHSM_RV_OK,
           "with the same PIN");
        const uint8_t *v = NULL; size_t vl = 0; uint32_t cl = 0, kt = 0;
        ok(fhsm_token_object_get(t, h32, &v, &vl, &cl, &kt) == FHSM_RV_OK
           && vl == sizeof v32 && memcmp(v, v32, sizeof v32) == 0,
           "and the values crossed the migration unchanged");
        uint8_t f2 = 0xFF;
        ok(fhsm_token_object_get_flags2(t, h32, &f2) == FHSM_RV_OK
           && f2 == FHSM_OBJF2_NOT_COPYABLE,
           "flags2 too");
    }

    fhsm_token_close(t);
    unlink(path);
    rmdir(dir);
    printf("\n%s\n", g_fail ? "FAILURES" : "all good");
    return g_fail ? 1 : 0;
}
