/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Two processes must not share one audit log.
 *
 * A hash chain has exactly one author by construction. Nothing in the module
 * required that: two processes each opened the log, each resumed the chain from
 * the tail of the file, and from then on each believed itself the successor of
 * the same line. Their appends interleave and the chain is destroyed — not by
 * an attacker, by two ordinary clients.
 *
 *     lines written by two processes : 60 (expected 60)
 *     chain verifies                : NO
 *     first broken line             : 2
 *
 * Run one after the other, the same two processes produce a chain that
 * verifies. So it is the concurrency, not the resume.
 *
 * This is not a p11-kit problem, though that is where it was found: `p11-kit
 * server` forks a child per client, so it makes the situation systematic rather
 * than occasional. Two `fhsm-sign` invocations in a Monday-morning script do
 * the same thing.
 *
 * The fix is one log per opening, created with O_EXCL and a sequence number in
 * the name, so each file has a single author from line 1. This test asserts the
 * property that matters rather than the mechanism:
 *
 *   1. every audit file in the directory verifies on its own;
 *   2. the numbering has no hole — a deleted file is visible as a gap, which is
 *      what stops per-file logs from being a new way to erase history;
 *   3. no line was lost across the set.
 *
 * Under the old single-file behaviour, (1) fails. It is the same test on both
 * sides of the change, which is what makes it a regression test rather than a
 * description of the new code.
 */
#include "fhsm_common.h"
#include "fhsm_audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/wait.h>

#define PER_CHILD 30

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

static uint8_t g_key[32];

static void child(const char *base, const char *who)
{
    if (fhsm_audit_open(base, FHSM_SLICE(g_key, sizeof g_key)) != FHSM_RV_OK) {
        fprintf(stderr, "  %s: open failed\n", who);
        _exit(2);
    }
    for (int i = 0; i < PER_CHILD; i++)
        (void)fhsm_audit_event(FHSM_EV_LOGIN_OK, -1, -1, FHSM_ROLE_USER,
                                FHSM_RV_OK, "actor", who, NULL);
    fhsm_audit_close();
    _exit(0);
}

/* Every file in `dir` whose name is the base name, optionally followed by a
 * six-digit sequence. Returns the count; fills `seq` with the numbers seen. */
static int collect(const char *dir, const char *basename,
                   char paths[][512], unsigned long *seq, int cap)
{
    DIR *d = opendir(dir);
    if (!d) return 0;
    int n = 0;
    size_t blen = strlen(basename);
    struct dirent *e;
    while ((e = readdir(d)) && n < cap) {
        if (strncmp(e->d_name, basename, blen) != 0) continue;
        const char *rest = e->d_name + blen;
        unsigned long s = 0;
        if (*rest == '\0') {
            s = 0;                                  /* the un-numbered form */
        } else if (*rest == '.' && strlen(rest) == 7) {
            char *end = NULL;
            s = strtoul(rest + 1, &end, 10);
            if (!end || *end) continue;
        } else {
            continue;
        }
        snprintf(paths[n], 512, "%s/%s", dir, e->d_name);
        seq[n] = s;
        n++;
    }
    closedir(d);
    return n;
}

static int cmp_ul(const void *a, const void *b) {
    unsigned long x = *(const unsigned long *)a, y = *(const unsigned long *)b;
    return x < y ? -1 : x > y;
}

int main(void)
{
    const char *dir = getenv("FHSM_TOKENS_DIR");
    if (!dir) dir = "/tmp";
    char base[512];
    snprintf(base, sizeof base, "%s/multiproc.log", dir);

    printf("Two processes, one audit log\n\n");

    memset(g_key, 0x42, sizeof g_key);

    pid_t a = fork(); if (a == 0) child(base, "CN=child-A");
    pid_t b = fork(); if (b == 0) child(base, "CN=child-B");
    int st; waitpid(a, &st, 0); waitpid(b, &st, 0);

    static char paths[64][512];
    unsigned long seq[64];
    int n = collect(dir, "multiproc.log", paths, seq, 64);
    printf("    (%d audit file(s) produced)\n", n);
    ok(n >= 1, "the writers produced at least one audit file");

    /* 1. Each file is a chain with one author, so each must verify alone. */
    int all_ok = 1, lines = 0;
    for (int i = 0; i < n; i++) {
        size_t broken = 0;
        fhsm_rv_t rv = fhsm_audit_verify(paths[i], FHSM_SLICE(g_key, sizeof g_key),
                                          &broken);
        if (rv != FHSM_RV_OK) {
            all_ok = 0;
            printf("    (%s breaks at line %zu)\n", paths[i], broken);
        }
        FILE *f = fopen(paths[i], "r");
        if (f) { int c; while ((c = fgetc(f)) != EOF) if (c == '\n') lines++; fclose(f); }
    }
    ok(all_ok, "every audit file verifies on its own");

    /* 2. A gap in the numbering is how a deleted file becomes visible. Without
     *    it, per-file logs would be a new way to erase history silently. */
    qsort(seq, (size_t)n, sizeof seq[0], cmp_ul);
    int contiguous = 1;
    for (int i = 1; i < n; i++) if (seq[i] != seq[i-1] + 1) contiguous = 0;
    ok(contiguous, "the sequence numbers are contiguous");

    /* 3. And the set as a whole still holds every line. */
    printf("    (%d lines for %d events)\n", lines, 2 * PER_CHILD);
    ok(lines >= 2 * PER_CHILD, "no line was lost across the set");

    for (int i = 0; i < n; i++) unlink(paths[i]);
    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
