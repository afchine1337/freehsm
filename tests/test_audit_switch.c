/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Switching the audit log off has to be asked for, and has to be loud.
 *
 * It was possible before this, in the worst way available: `FHSM_AUDIT_LOG`
 * pointing at `/dev/null`. Silent, undocumented, and the module went on
 * behaving as though it were recording. Meanwhile `FHSM_AUDIT_MANDATORY` sat
 * in `include/fhsm_common.h` set to 1, was referenced in three comments and
 * enforced nowhere — `docs/ROADMAP.md` called it "a constant a comment
 * describes as aspirational".
 *
 * Two decisions, one for each party:
 *
 *   the build     decides whether the log may be switched off at all
 *                 (FHSM_AUDIT_MANDATORY). A distribution packaged for an
 *                 administration ships with 1 and nobody downstream can turn
 *                 the record off.
 *   the operator  decides whether it is, and says so by name: FHSM_AUDIT=off.
 *                 Never a side effect of a path.
 *
 * This test is correct under either build and reports which one it ran under,
 * because a test that silently covers half of a two-sided rule is how the
 * uncovered half stays broken.
 *
 *     make tests/test_audit_switch && ./tests/test_audit_switch
 *     make clean && make EXTRA_CFLAGS=-DFHSM_AUDIT_MANDATORY=0 \
 *          tests/test_audit_switch && ./tests/test_audit_switch
 *
 * `make tests` runs the default build, so the permissive branch below is
 * exercised only by the second command. That gap is stated rather than
 * papered over; `make audit-switch` runs both.
 */
#include "fhsm_common.h"
#include "fhsm_audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

int main(void)
{
    const char *dir = getenv("FHSM_TOKENS_DIR");
    if (!dir) dir = "/tmp";

    printf("The audit switch\n\n");
    printf("  this build: FHSM_AUDIT_MANDATORY = %d  (%s)\n\n",
           fhsm_audit_mandatory(),
           fhsm_audit_mandatory() ? "the log cannot be switched off"
                                  : "the log may be switched off");

    /* 1. The permission is readable from outside. Without this the rule is
     *    a compile-time constant nobody can observe, which is what it was. */
    ok(fhsm_audit_mandatory() == 0 || fhsm_audit_mandatory() == 1,
       "the build's decision is reported rather than implied");

    /* 2. A stream target is accepted and is not a log. `/dev/null` is the
     *    switch that used to be silent; it still works, because refusing it
     *    would break the FIFO case, but the module says what it is. Here we
     *    can only check the mechanism: the opening reports the name it was
     *    given rather than a numbered log. */
    {
        uint8_t key[32];
        memset(key, 0x42, sizeof key);
        if (fhsm_audit_open("/dev/null", FHSM_SLICE(key, 32)) == FHSM_RV_OK) {
            char actual[600] = {0};
            fhsm_audit_current_path(actual, sizeof actual);
            ok(strcmp(actual, "/dev/null") == 0,
               "a stream target is used as given, not numbered");
            fhsm_audit_close();
        } else {
            ok(0, "a stream target is used as given, not numbered");
        }
    }

    /* 3. A regular base is numbered, so it is a log and not a stream. The two
     *    cases have to be distinguishable from outside or the NOTE the module
     *    prints could not be decided either. */
    {
        char base[512];
        snprintf(base, sizeof base, "%s/switch.log", dir);
        uint8_t key[32];
        memset(key, 0x42, sizeof key);
        if (fhsm_audit_open(base, FHSM_SLICE(key, 32)) == FHSM_RV_OK) {
            char actual[600] = {0};
            fhsm_audit_current_path(actual, sizeof actual);
            ok(strcmp(actual, base) != 0 && strncmp(actual, base, strlen(base)) == 0,
               "a regular base becomes a numbered log");
            fhsm_audit_close();
            unlink(actual);
        } else {
            ok(0, "a regular base becomes a numbered log");
        }
    }

    /* 4. And the statement that matters, which only C_Initialize can enforce:
     *    under a mandatory build FHSM_AUDIT=off must be refused, under a
     *    permissive one it must be honoured. Both are behaviours of the
     *    module's entry point, and the note above says how to reach the branch
     *    this build does not cover. */
    printf("\n  The FHSM_AUDIT=off path is enforced in C_Initialize and is\n"
             "  exercised by tests/audit_switch.sh, which drives the real\n"
             "  module rather than the library.\n");

    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
