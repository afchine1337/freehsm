/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_conf.c --- config reader (#128).
 *
 *  The point of #128 is that a key ships in freehsm.conf if and only if code
 *  reads it. This test is what keeps that true: it asserts both keys are
 *  actually read, that a bad value falls back to the documented default
 *  rather than to something invented, and that key matching is exact -- the
 *  reader this replaced used a 4-byte prefix compare, so `modem = fips` was
 *  read as the mode.
 * ========================================================================= */
#include "fhsm_conf.h"
#include "fhsm_mode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
static const char *TMP = "/tmp/fhsm_test_conf.conf";

static void write_conf(const char *body) {
    FILE *f = fopen(TMP, "w");
    if (!f) { perror("fopen"); exit(2); }
    fputs(body, f);
    fclose(f);
    setenv("FHSM_CONF", TMP, 1);
    fhsm_mode_reset_cache();
}

static void ck(const char *what, long got, long want) {
    int ok = (got == want);
    printf("  %-46s got=%-9ld want=%-9ld %s\n", what, got, want, ok ? "OK" : "<<< FAIL");
    if (!ok) fails++;
}

int main(void) {
    const size_t DEF = (size_t)FHSM_SECURE_HEAP_BYTES;

    /* No file at all: both callers fall back to their documented defaults. */
    setenv("FHSM_CONF", "/nonexistent/freehsm.conf", 1);
    fhsm_mode_reset_cache();
    ck("absent file: heap = compiled default", (long)fhsm_conf_secure_heap_bytes(), (long)DEF);

    /* Both keys are read. This is the assertion #128 exists for. */
    write_conf("mode = strict\nsecure_heap_kb = 2048\n");
    ck("secure_heap_kb = 2048 is read", (long)fhsm_conf_secure_heap_bytes(), 2048L * 1024);
    ck("mode = strict is read", fhsm_mode_is_fips(), 1);

    write_conf("mode = permissive\nsecure_heap_kb = 512\n");
    ck("secure_heap_kb = 512 is read", (long)fhsm_conf_secure_heap_bytes(), 512L * 1024);
    ck("mode = permissive is read", fhsm_mode_is_fips(), 0);

    /* The former spellings, kept as a compatibility surface (#11). Each one
     * prints a note to stderr naming its replacement; what is asserted here
     * is that it still DECIDES the same way. An alias that warns correctly
     * and then returns the wrong mode would be worse than no alias: the
     * operator reads a note saying "taken as strict" and gets permissive.
     *
     * `default` is in the table as permissive. It is the odd one -- the other
     * four name a policy, `default` names a position in a list -- and it is
     * asserted here so that nobody removes it as meaningless. */
    write_conf("mode = fips\n");
    ck("alias: mode = fips still means strict", fhsm_mode_is_fips(), 1);
    write_conf("mode = legacy\n");
    ck("alias: mode = legacy still means permissive", fhsm_mode_is_fips(), 0);
    write_conf("mode = default\n");
    ck("alias: mode = default still means permissive", fhsm_mode_is_fips(), 0);

    /* The build profile's vocabulary reaching the runtime axis. Accepted,
     * warned about by name, and -- the point of the assertion -- mapped the
     * way a reader would expect rather than silently falling to the default. */
    write_conf("mode = fips-strict\n");
    ck("alias: mode = fips-strict maps to strict", fhsm_mode_is_fips(), 1);
    write_conf("mode = interop\n");
    ck("alias: mode = interop maps to permissive", fhsm_mode_is_fips(), 0);

    /* An unknown word is not a mode. It must not be taken as strict by
     * accident of table order, and must not be taken as strict by a prefix
     * match on "strict-ish" either: the fallback is the documented default. */
    write_conf("mode = stricter\n");
    ck("unknown word -> default (permissive)", fhsm_mode_is_fips(), 0);

    /* Exact key matching: the old prefix compare accepted this as `mode`. */
    write_conf("modem = fips\nsecure_heap_kbx = 4096\n");
    ck("`modem` does not match `mode`", fhsm_mode_is_fips(), 0);
    ck("`secure_heap_kbx` does not match", (long)fhsm_conf_secure_heap_bytes(), (long)DEF);

    /* Out of range and malformed values fall back rather than being clamped:
     * a clamped value is a setting the operator believes took effect. */
    write_conf("secure_heap_kb = 4\n");
    ck("below minimum -> default", (long)fhsm_conf_secure_heap_bytes(), (long)DEF);
    write_conf("secure_heap_kb = 999999999\n");
    ck("above maximum -> default", (long)fhsm_conf_secure_heap_bytes(), (long)DEF);
    write_conf("secure_heap_kb = 900abc\n");
    ck("trailing garbage -> default", (long)fhsm_conf_secure_heap_bytes(), (long)DEF);
    write_conf("secure_heap_kb =\n");
    ck("empty value -> default", (long)fhsm_conf_secure_heap_bytes(), (long)DEF);

    /* Power-of-two rounding. OpenSSL's arena asserts on anything else, so
     * `secure_heap_kb = 100` used to abort the process inside
     * CRYPTO_secure_malloc_init -- a config typo crashing an HSM. */
    write_conf("secure_heap_kb = 100\n");
    ck("100 KiB rounds up to 128 KiB (power of two)",
       (long)fhsm_conf_secure_heap_bytes(), 128L * 1024);
    write_conf("secure_heap_kb = 3000\n");
    ck("3000 KiB rounds up to 4096 KiB", (long)fhsm_conf_secure_heap_bytes(), 4096L * 1024);
    write_conf("secure_heap_kb = 2048\n");
    ck("an exact power of two is left alone", (long)fhsm_conf_secure_heap_bytes(), 2048L * 1024);

    /* Comments, section headers and inline comments must not confuse it. */
    write_conf("# a comment\n[module]\nsecure_heap_kb = 1024   # inline\nmode=strict\n");
    ck("comments/sections/inline value", (long)fhsm_conf_secure_heap_bytes(), 1024L * 1024);
    ck("mode=strict (no spaces) is read", fhsm_mode_is_fips(), 1);

    /* The environment still wins over the file. */
    write_conf("mode = legacy\n");
    setenv("FHSM_MODE", "fips", 1);
    fhsm_mode_reset_cache();
    ck("FHSM_MODE overrides the file", fhsm_mode_is_fips(), 1);
    unsetenv("FHSM_MODE");

    remove(TMP);
    printf("\ntest_conf : %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
