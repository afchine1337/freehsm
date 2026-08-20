/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * The PIN throttle must not survive a reboot as a month-long lockout.
 *
 * The token stores a failure counter and, until this test was written, an
 * absolute throttle deadline. The deadline lived in the CLOCK_MONOTONIC
 * domain, chosen deliberately so that `date -s` could not bypass the throttle
 * -- and correct for that. But CLOCK_MONOTONIC restarts at boot while the file
 * does not. A deadline written after thirty days of uptime was still thirty
 * days in the future when the next boot read it:
 *
 *     one wrong PIN            -> 0xa0
 *     throttle remaining       -> 455 ms
 *     after the reboot         -> 2574127916 ms  (29.8 days)
 *     correct PIN now          -> 0x80000004   (PIN_THROTTLED)
 *     cap the design intends   -> 60000 ms
 *
 * Fails closed, so not an opening -- but a correct PIN refused for a month,
 * reported as PIN_THROTTLED with nothing to explain it, on a token whose
 * operator did nothing but mistype once and reboot.
 *
 * The deadline was never independent state: it is a function of the failure
 * count, which is persisted. It is now derived on load and the two u64 fields
 * are written as zero.
 *
 * A reboot cannot be staged inside a test, but it does not have to be: the
 * file is the whole interface between two boots. Writing a large value into
 * the deadline field is exactly what a long-uptime boot leaves behind.
 */
#include "fhsm_common.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USER_PIN "userpin1234"
#define SO_PIN   "sopin1234"

/* Offsets from docs/TOKEN_STORE_FORMAT.md. */
#define OFF_THROTTLE_SO    301
#define OFF_THROTTLE_USER  309

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

static int poke_u64(const char *path, long off, unsigned long long v) {
    FILE *f = fopen(path, "r+b");
    if (!f) return 0;
    unsigned char le[8];
    for (int i = 0; i < 8; i++) le[i] = (unsigned char)((v >> (8 * i)) & 0xff);
    int good = fseek(f, off, SEEK_SET) == 0 && fwrite(le, 1, 8, f) == 8;
    fclose(f);
    return good;
}

static int peek_u64(const char *path, long off, unsigned long long *out) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    unsigned char le[8];
    int good = fseek(f, off, SEEK_SET) == 0 && fread(le, 1, 8, f) == 8;
    fclose(f);
    if (!good) return 0;
    unsigned long long v = 0;
    for (int i = 0; i < 8; i++) v |= (unsigned long long)le[i] << (8 * i);
    *out = v;
    return 1;
}

int main(void)
{
    const char *dir = getenv("FHSM_TOKENS_DIR");
    char path[512];
    snprintf(path, sizeof path, "%s/throttle.tok", dir ? dir : "/tmp");
    unlink(path);

    printf("The PIN throttle across a reboot\n\n");

    fhsm_token_t *t = NULL;
    if (fhsm_token_init(path, SO_PIN, "throttle", &t) != FHSM_RV_OK || !t) {
        printf("  cannot create a token at %s\n", path);
        return 2;
    }
    if (fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN, strlen(SO_PIN)) != FHSM_RV_OK
        || fhsm_token_init_user_pin(t, USER_PIN) != FHSM_RV_OK) {
        printf("  cannot set the user PIN\n");
        return 2;
    }
    fhsm_token_logout(t);

    /* One wrong PIN: failure count 1, so a 500 ms delay. */
    fhsm_rv_t rv = fhsm_token_login(t, FHSM_ROLE_USER, "wrongwrong", 10);
    ok(rv == FHSM_RV_PIN_INCORRECT, "a wrong PIN is refused");
    uint64_t rem = fhsm_token_throttle_remaining_ms(t, FHSM_ROLE_USER);
    ok(rem > 0 && rem <= FHSM_PIN_THROTTLE_MAX_MS,
       "the delay it earned is within the documented cap");
    fhsm_token_close(t);

    /* The file must not carry a monotonic deadline at all any more. A partial
     * revert -- deriving on load but still writing the timestamp -- would
     * leave the trap armed for the next reader. */
    unsigned long long stored = 1;
    ok(peek_u64(path, OFF_THROTTLE_USER, &stored) && stored == 0,
       "no deadline is written to the file");

    /* Now the reboot: the previous boot had been up thirty days. */
    ok(poke_u64(path, OFF_THROTTLE_USER, 30ull * 24 * 3600 * 1000)
       && poke_u64(path, OFF_THROTTLE_SO,   30ull * 24 * 3600 * 1000),
       "a long-uptime deadline is planted in the file");

    t = NULL;
    if (fhsm_token_load(path, &t) != FHSM_RV_OK || !t) {
        printf("  cannot reload %s\n", path);
        return 2;
    }
    rem = fhsm_token_throttle_remaining_ms(t, FHSM_ROLE_USER);
    printf("    (remaining after the reboot: %llu ms)\n", (unsigned long long)rem);

    /* THE regression. Before the fix this was 2.57e9 ms -- 29.8 days. */
    ok(rem <= FHSM_PIN_THROTTLE_MAX_MS,
       "the throttle after a reboot is still within the cap");

    /* And the other direction, so that simply clearing the deadline on load
     * would not pass: a restart must not be a way to skip the wait. */
    ok(rem > 0, "a restart does not clear a delay that was earned");

    /* It expires. Wait it out and the correct PIN works -- which is what makes
     * the two assertions above a throttle rather than a lock.
     *
     * The wait is bounded rather than `rem`: put the defect back and `rem` is
     * thirty days, and a test that sleeps for thirty days is a hang, not a
     * failure. Two seconds is longer than any delay this token can legitimately
     * owe at a failure count of one. */
    unsigned long long wait_ms = rem + 100;
    if (wait_ms > 2000) wait_ms = 2000;
    usleep((useconds_t)wait_ms * 1000);
    ok(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) == FHSM_RV_OK,
       "once the delay elapses the correct PIN is accepted");

    fhsm_token_close(t);
    unlink(path);
    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
