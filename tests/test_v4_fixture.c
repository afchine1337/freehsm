/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_v4_fixture.c --- a token written by v2.7.0 still opens, and what the
 * v5 record adds survives a reload.
 *
 * The fixture is NOT generated here. tests/make_v4_fixture.c produced it in a
 * checkout of v2.7.0, and the file is committed: only a file this build had
 * no part in making can contradict its reader (tests/test_v3_fixture.c).
 *
 * What a v4 record means, read by a v5 build: no generation mechanism
 * recorded, and an empty CKA_OBJECT_ID. And everything it did hold, where it
 * was: the v5 reader is the v4 reader told a larger record, so a wrong size
 * would put the value, the last field, somewhere else.
 *
 * The second half is the v5 round trip at the store: the two new fields are
 * set, the token is closed and loaded, and they are read again.
 * ======================================================================== */
#include "fhsm_common.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USER_PIN "userpin1234"
#define FIXTURE  "tests/fixtures/token-v4.tok"

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

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

static uint32_t by_label(fhsm_token_t *t, const char *label) {
    uint32_t one[4]; size_t k = 0;
    if (fhsm_token_object_find(t, NULL, label, one, 4, &k) == FHSM_RV_OK && k == 1)
        return one[0];
    return 0;
}

int main(void)
{
    printf("A v4 token file, read by a v5 build\n\n");

    /* Work on a copy: the store writes, and a test that rewrites its own
     * fixture passes once and then tests the file it just wrote. */
    char dir[] = "/tmp/fhsm-v4fix-XXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
    char path[512];
    snprintf(path, sizeof path, "%s/tok.tok", dir);
    {
        FILE *in = fopen(FIXTURE, "rb");
        if (!in) {
            fprintf(stderr,
                    "cannot open %s -- run tests/make_v4_fixture.c in a\n"
                    "checkout of v2.7.0 first; see its header for the recipe.\n",
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
    ok(fhsm_token_load(path, &t) == FHSM_RV_OK && t != NULL, "the v4 file loads");
    if (!t) { printf("\nFAILURES\n"); return 1; }

    /* Before a login: the public section, whose plaintext is a v4 blob. */
    {
        uint32_t all[16]; size_t n = 0;
        ok(fhsm_token_object_find(t, NULL, NULL, all, 16, &n) == FHSM_RV_OK && n == 1,
           "before a login, its public section gives the one public object");
        uint32_t hp = by_label(t, "pubdata");
        const uint8_t *v = NULL; size_t vl = 0; uint32_t cl = 9, kt = 9;
        ok(hp != 0 && fhsm_token_object_get(t, hp, &v, &vl, &cl, &kt) == FHSM_RV_OK
           && cl == 0 && vl == sizeof pub && memcmp(v, pub, sizeof pub) == 0,
           "with its value");
    }

    ok(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) == FHSM_RV_OK,
       "the stored PIN opens it");
    uint32_t h16 = by_label(t, "sixteen"), h32 = by_label(t, "thirtytwo"),
             hp  = by_label(t, "pubdata");
    {
        uint32_t all[16]; size_t n = 0;
        ok(fhsm_token_object_find(t, NULL, NULL, all, 16, &n) == FHSM_RV_OK && n == 3
           && h16 && h32 && hp,
           "the three objects are there, found by their labels");
    }
    if (!h16 || !h32 || !hp) { printf("\nFAILURES\n"); return 1; }

    {
        const uint8_t *v = NULL; size_t vl = 0; uint32_t cl = 0, kt = 0;
        ok(fhsm_token_object_get(t, h16, &v, &vl, &cl, &kt) == FHSM_RV_OK
           && vl == sizeof v16 && memcmp(v, v16, sizeof v16) == 0 && cl == 4 && kt == 0x1F,
           "the 16-byte value came back intact");
        ok(fhsm_token_object_get(t, h32, &v, &vl, &cl, &kt) == FHSM_RV_OK
           && vl == sizeof v32 && memcmp(v, v32, sizeof v32) == 0,
           "and so did the 32-byte one");
    }
    /* The v4 policy block: the field the v5 block now follows. */
    {
        uint32_t m[8] = { 0 }; uint8_t n = 8;
        ok(fhsm_token_object_get_allowed_mechs(t, h16, m, &n) == FHSM_RV_OK
           && n == 2 && m[0] == 0x1082u && m[1] == 0x1087u,
           "the allowed mechanisms of the v4 record are the two written");
        uint8_t f = 0, f2 = 0xFF, f3 = 0;
        ok(fhsm_token_object_get_flags(t, h16, &f) == FHSM_RV_OK && (f & FHSM_OBJF_LOCAL),
           "CKA_LOCAL is still set on the key that had it");
        ok(fhsm_token_object_get_flags2(t, h32, &f2) == FHSM_RV_OK
           && (f2 & FHSM_OBJF2_NOT_COPYABLE),
           "the flags2 bit survived");
        ok(fhsm_token_object_get_flags3(t, hp, &f3) == FHSM_RV_OK
           && (f3 & FHSM_OBJF3_DATA_PUBLIC),
           "and the flags3 bit of the public data object");
        const uint8_t *a = NULL; size_t al = 0;
        ok(fhsm_token_object_get_meta(t, hp, FHSM_OBJ_META_APPLICATION, &a, &al) == FHSM_RV_OK
           && al == 5 && memcmp(a, "fhsm4", 5) == 0,
           "CKA_APPLICATION reads back");
    }

    /* The point of the file: what a v4 record says about the v5 fields. */
    {
        uint32_t km = 77; int set = 1;
        ok(fhsm_token_object_get_keygen_mech(t, h16, &km, &set) == FHSM_RV_OK && set == 0,
           "a v4 key has no generation mechanism recorded");
        const uint8_t *o = NULL; size_t ol = 9;
        ok(fhsm_token_object_get_meta(t, hp, FHSM_OBJ_META_OBJECT_ID, &o, &ol) == FHSM_RV_OK
           && ol == 0,
           "and a v4 data object an empty CKA_OBJECT_ID");
    }

    /* Set both, which writes the file as v5, and load it again. */
    static const uint8_t oid[5] = { 0x06, 0x03, 0x2A, 0x03, 0x04 };
    {
        ok(fhsm_token_object_set_object_id(t, hp, oid, sizeof oid) == FHSM_RV_OK,
           "CKA_OBJECT_ID is set; the write makes the file v5");
        /* Zero is CKM_RSA_PKCS_KEY_PAIR_GEN: the value that a field without a
         * presence byte could not tell from "not recorded". */
        ok(fhsm_token_object_set_keygen_mech(t, h32, 0u) == FHSM_RV_OK
           && fhsm_token_object_set_keygen_mech(t, h16, 0x1080u) == FHSM_RV_OK,
           "and two generation mechanisms, one of them zero");
        uint8_t big[FHSM_OBJ_OBJECT_ID_MAX + 1] = { 0 };
        ok(fhsm_token_object_set_object_id(t, hp, big, sizeof big)
           == FHSM_RV_ATTRIBUTE_VALUE_INVALID,
           "a CKA_OBJECT_ID longer than the field is refused, not cut");
        fhsm_token_close(t);
        t = NULL;
        ok(fhsm_token_load(path, &t) == FHSM_RV_OK && t != NULL,
           "the v5 file loads");
        if (!t) { printf("\nFAILURES\n"); return 1; }

        /* The public section is v5 now, and carries the object's new field. */
        const uint8_t *o = NULL; size_t ol = 0;
        ok(by_label(t, "pubdata") == hp
           && fhsm_token_object_get_meta(t, hp, FHSM_OBJ_META_OBJECT_ID, &o, &ol) == FHSM_RV_OK
           && ol == sizeof oid && memcmp(o, oid, sizeof oid) == 0,
           "before a login, the public object has its CKA_OBJECT_ID");

        ok(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) == FHSM_RV_OK,
           "with the same PIN");
        ok(fhsm_token_object_get_meta(t, hp, FHSM_OBJ_META_OBJECT_ID, &o, &ol) == FHSM_RV_OK
           && ol == sizeof oid && memcmp(o, oid, sizeof oid) == 0,
           "CKA_OBJECT_ID crossed the reload");
        uint32_t km = 77; int set = 0;
        ok(fhsm_token_object_get_keygen_mech(t, h32, &km, &set) == FHSM_RV_OK
           && set == 1 && km == 0u,
           "the mechanism zero is recorded as zero, not as absent");
        km = 77; set = 0;
        ok(fhsm_token_object_get_keygen_mech(t, h16, &km, &set) == FHSM_RV_OK
           && set == 1 && km == 0x1080u,
           "and the other one reads back");
        const uint8_t *v = NULL; size_t vl = 0; uint32_t cl = 0, kt = 0;
        ok(fhsm_token_object_get(t, h32, &v, &vl, &cl, &kt) == FHSM_RV_OK
           && vl == sizeof v32 && memcmp(v, v32, sizeof v32) == 0
           && fhsm_token_object_get(t, h16, &v, &vl, &cl, &kt) == FHSM_RV_OK
           && vl == sizeof v16 && memcmp(v, v16, sizeof v16) == 0,
           "the values crossed the migration unchanged");
        uint32_t m[8] = { 0 }; uint8_t n = 8;
        ok(fhsm_token_object_get_allowed_mechs(t, h16, m, &n) == FHSM_RV_OK
           && n == 2 && m[0] == 0x1082u && m[1] == 0x1087u,
           "and so did the allowed mechanisms");
    }

    fhsm_token_close(t);
    unlink(path);
    rmdir(dir);
    printf("\n%s\n", g_fail ? "FAILURES" : "all good");
    return g_fail ? 1 : 0;
}
