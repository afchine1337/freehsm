/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Does the audit chain actually detect tampering?
 *
 * Until now nothing could answer that. `fhsm_audit_verify` was a stub that
 * returned OK without reading its arguments, pointing at this very file, which
 * did not exist. `tools/freehsm-audit verify` had a real implementation, but it
 * computed a different HMAC from the module and started the chain from a
 * different head, so it could not have validated a single genuine line.
 *
 * Two independent verifiers is deliberate -- an auditor should be able to build
 * the tool without the module, and a check that shares code with the thing it
 * checks is a mirror. The price is drift, and drift is exactly what happened.
 * So this test runs BOTH against the same real log, and every mutation below is
 * put to both.
 *
 * The mutations are the four ways a log gets falsified: change a record, remove
 * one, insert one, cut the end off. A verifier that only recomputes each line's
 * own HMAC catches the first and none of the others, because in this format
 * every line authenticates itself.
 *
 * Three of the four are caught. The fourth -- truncation at the end -- is not,
 * and cannot be from the file alone: what remains is a shorter chain that
 * verifies perfectly. That case is asserted here as passing, on purpose, so the
 * limitation is stated by every run instead of being absent from the list. When
 * an external anchor exists the assertion inverts, and the test will say so.
 */
#include "fhsm_audit.h"
#include "fhsm_common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

static char g_dir[] = "/tmp/fhsm-audit-verify-XXXXXX";
static char g_log[512], g_keyp[512], g_keyhex[65];
static uint8_t g_key[32];

/* Produce a genuine log: several events through the real writer. */
static int make_log(void) {
    if (fhsm_audit_key_provision(g_dir, g_key, NULL) != FHSM_RV_OK) return 0;
    for (int i = 0; i < 32; i++) snprintf(g_keyhex + 2*i, 3, "%02x", g_key[i]);
    if (fhsm_audit_open(g_log, FHSM_SLICE(g_key, sizeof g_key)) != FHSM_RV_OK) return 0;
    /* g_log was a base name; the opening created base.NNNNNN so that every
     * chain has one author. Everything below reads, rewrites and verifies the
     * file on disk, so from here on g_log must be the file that exists. */
    fhsm_audit_current_path(g_log, sizeof g_log);

    if (fhsm_audit_event(FHSM_EV_MODULE_INIT, -1, -1, FHSM_ROLE_NONE,
                          FHSM_RV_OK, NULL) != FHSM_RV_OK) return 0;
    if (fhsm_audit_event(FHSM_EV_LOGIN_OK, 0, 1, FHSM_ROLE_USER,
                          FHSM_RV_OK, NULL) != FHSM_RV_OK) return 0;
    if (fhsm_audit_event(FHSM_EV_SIGN, 0, 1, FHSM_ROLE_USER,
                          FHSM_RV_OK, "alg", "mldsa65", NULL) != FHSM_RV_OK) return 0;
    if (fhsm_audit_event(FHSM_EV_LOGIN_FAIL, 0, 1, FHSM_ROLE_NONE,
                          FHSM_RV_PIN_INCORRECT, NULL) != FHSM_RV_OK) return 0;
    if (fhsm_audit_event(FHSM_EV_LOGOUT, 0, 1, FHSM_ROLE_USER,
                          FHSM_RV_OK, NULL) != FHSM_RV_OK) return 0;
    fhsm_audit_close();
    return 1;
}

static char **g_lines = NULL;
static size_t g_n = 0;

static int slurp_lines(void) {
    FILE *f = fopen(g_log, "r");
    if (!f) return 0;
    char buf[4096];
    g_n = 0;
    g_lines = malloc(64 * sizeof *g_lines);
    if (!g_lines) { fclose(f); return 0; }
    while (fgets(buf, sizeof buf, f) && g_n < 64) g_lines[g_n++] = strdup(buf);
    fclose(f);
    return g_n > 0;
}

/* Rewrite the log from the in-memory lines, with one mutation applied. */
typedef enum { MUT_NONE, MUT_ALTER, MUT_DELETE, MUT_INSERT, MUT_TRUNCATE } mut_t;

static void write_log(mut_t m, size_t at) {
    FILE *f = fopen(g_log, "w");
    if (!f) return;
    for (size_t i = 0; i < g_n; i++) {
        if (m == MUT_DELETE && i == at) continue;
        if (m == MUT_TRUNCATE && i >= at) break;
        if (m == MUT_INSERT && i == at) fputs(g_lines[i], f);   /* duplicated */
        if (m == MUT_ALTER && i == at) {
            /* Change one character of the payload, not of the HMAC: the point
             * is a record that says something else, not a corrupted digest. */
            char *copy = strdup(g_lines[i]);
            char *r = strstr(copy, "\"result\":\"OK\"");
            if (r) memcpy(r + 11, "KO", 2);
            fputs(copy, f);
            free(copy);
            continue;
        }
        fputs(g_lines[i], f);
    }
    fclose(f);
}

/* The standalone tool, run on the same file. Returns its exit status, or -1. */
static int run_tool(void) {
    if (access("./tools/freehsm-audit", X_OK) != 0) return -1;
    char cmd[1400];
    snprintf(cmd, sizeof cmd,
             "./tools/freehsm-audit verify %s %s >/dev/null 2>&1", g_log, g_keyhex);
    int r = system(cmd);
    return (r == -1) ? -1 : (r / 256);
}

static void case_mutation(const char *label, mut_t m, size_t at) {
    write_log(m, at);
    size_t bad = 0;
    fhsm_rv_t rv = fhsm_audit_verify(g_log, FHSM_SLICE(g_key, sizeof g_key), &bad);
    int lib_caught  = (rv != FHSM_RV_OK);
    int tool_status = run_tool();

    char msg[160];
    snprintf(msg, sizeof msg, "%s  (library)", label);
    ok(lib_caught, msg);
    if (lib_caught && bad) printf("      first line at fault: %zu\n", bad);

    if (tool_status >= 0) {
        snprintf(msg, sizeof msg, "%s  (freehsm-audit tool)", label);
        ok(tool_status != 0, msg);
    }
}

int main(void)
{
    printf("Audit log chain verification\n\n");

    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 2; }
    snprintf(g_log,  sizeof g_log,  "%s/audit.log", g_dir);
    snprintf(g_keyp, sizeof g_keyp, "%s/audit.key", g_dir);

    if (!make_log() || !slurp_lines()) {
        printf("  cannot produce a reference log\n");
        return 2;
    }
    printf("  reference log: %zu records\n\n", g_n);

    /* --- intact ---------------------------------------------------------- */
    size_t bad = 0;
    fhsm_rv_t rv = fhsm_audit_verify(g_log, FHSM_SLICE(g_key, sizeof g_key), &bad);
    ok(rv == FHSM_RV_OK, "an intact log is accepted  (library)");
    int t = run_tool();
    if (t >= 0) ok(t == 0, "an intact log is accepted  (freehsm-audit tool)");
    else printf("  (tool not built, cross-check skipped)\n");

    /* --- a wrong key must validate nothing ------------------------------- */
    {
        uint8_t wrong[32];
        memcpy(wrong, g_key, 32); wrong[0] ^= 0xFF;
        rv = fhsm_audit_verify(g_log, FHSM_SLICE(wrong, sizeof wrong), &bad);
        ok(rv != FHSM_RV_OK, "a wrong key is rejected at the first line");
    }
    printf("\n");

    /* --- the four falsifications ----------------------------------------- */
    case_mutation("an altered record is detected", MUT_ALTER, 2);
    printf("\n");
    case_mutation("a deleted record is detected", MUT_DELETE, 2);
    printf("\n");
    case_mutation("a duplicated record is detected", MUT_INSERT, 2);
    printf("\n");
    /* And the one that is NOT detected. It is here so the limitation stays
     * visible on every run: a log cut short at the end is a shorter chain
     * that verifies perfectly, and no check confined to the file can tell
     * the two apart -- it is the same file. The day an external anchor
     * exists this assertion has to invert, which is exactly what we want it
     * to signal. */
    write_log(MUT_TRUNCATE, g_n - 1);
    {
        size_t b = 0;
        fhsm_rv_t tr = fhsm_audit_verify(g_log, FHSM_SLICE(g_key, sizeof g_key), &b);
        ok(tr == FHSM_RV_OK,
           "a log truncated at the end passes -- known limit, not a defect");
        int ts = run_tool();
        if (ts >= 0)
            ok(ts == 0, "  the tool agrees, which proves the two are in step");
    }
    printf("\n");

    /* --- and it becomes valid again once restored ------------------------ */
    write_log(MUT_NONE, 0);
    rv = fhsm_audit_verify(g_log, FHSM_SLICE(g_key, sizeof g_key), &bad);
    ok(rv == FHSM_RV_OK, "restored, the log is accepted again");

    for (size_t i = 0; i < g_n; i++) free(g_lines[i]);
    free(g_lines);
    unlink(g_log); unlink(g_keyp); rmdir(g_dir);

    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
