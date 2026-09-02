/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/bench_session_mem.c --- what a held session costs, and what runs out
 *                               first (#111).
 *
 *  #111 needs a number before it can choose a server model: how many clients
 *  can one process hold, and what is the wall it hits. "Memory per session"
 *  turns out to be the wrong question asked in the obvious way, which is why
 *  this measures rather than estimates.
 *
 *  Everything a session holds is in fixed tables, sized at compile time and
 *  reserved in .bss at load: the session table itself, and five operation
 *  tables indexed by session handle. So the marginal cost of an idle session
 *  is not a malloc -- it is whether a page of an already-reserved table gets
 *  touched. An untouched .bss page costs nothing resident and, after a fork,
 *  nothing per child either.
 *
 *  Three states, because they touch different amounts of that reservation:
 *
 *      open        a session handle, nothing more
 *      logged in   the same, plus a role; the token is shared, not copied
 *      operating   an active digest, which touches one ~5 KiB operation slot
 *
 *  Run several times before believing any of it. A 3.735 ms first run once
 *  went into a document as fact and was a cold-cache outlier; six more runs
 *  said 3.44-3.57. The lesson cost a correction.
 *
 *      make tests/bench_session_mem && ./tests/bench_session_mem
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "p11_util.h"

/* Resident set, in KiB, read from the kernel rather than from the allocator:
 * what we want to know is what is actually backed by physical pages, and
 * mallinfo cannot see a .bss table at all. */
static long rss_kb(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f) return -1;
    long total = 0, res = 0;
    if (fscanf(f, "%ld %ld", &total, &res) != 2) { fclose(f); return -1; }
    fclose(f);
    return res * (sysconf(_SC_PAGESIZE) / 1024);
}

int main(int argc, char **argv) {
    p11_progname = "bench_session_mem";
    const char *modpath = (argc > 1) ? argv[1] : "./libfreehsm.so";

    long base_load = rss_kb();
    load_module(modpath);
    if (p11.Initialize(NULL) != CKR_OK) {
        fprintf(stderr, "bench_session_mem: C_Initialize failed\n"); return 2; }
    long base_init = rss_kb();

    /* The one slot holding a token -- resolved, never assumed to be 0. */
    CK_SLOT_ID slot = p11_resolve_slot(-1, P11_SLOT_WITH_TOKEN);

    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) pin = "userpin1234";

    printf("What a held session costs\n\n");
    printf("  module                      %s\n", modpath);
    printf("  RSS after dlopen            %ld KiB\n", base_load);
    printf("  RSS after C_Initialize      %ld KiB   (+%ld)\n",
           base_init, base_init - base_load);
    printf("\n");

    enum { CAP = 4096 };
    static CK_SESSION_HANDLE s[CAP];
    int opened = 0;
    CK_RV last = CKR_OK;

    /* --- 1. open, and keep opening until the module says no ------------- */
    /* Sampled as it goes, not just measured at the end. A single before/after
     * pair gives a bytes-per-session average and no way to tell whether the
     * cost is per session at all: two builds gave 30510 and 14957 bytes with
     * the same code, which is not a per-session cost behaving differently but
     * a sign that the average was hiding the shape. Print the curve. */
    long before = rss_kb();
    long prev = before;
    printf("  sessions   RSS KiB   d(KiB)   d/session\n");
    for (; opened < CAP; opened++) {
        last = p11.OpenSession(slot, CKF_RW, NULL, NULL, &s[opened]);
        if (last != CKR_OK) break;
        if ((opened + 1) % 32 == 0) {
            long now = rss_kb();
            printf("  %8d   %7ld   %6ld   %8.0f B\n",
                   opened + 1, now, now - prev, (double)(now - prev) * 1024.0 / 32.0);
            prev = now;
        }
    }
    long after_open = rss_kb();
    printf("  sessions opened             %d, then 0x%lx\n",
           opened, (unsigned long)last);
    printf("  highest handle              %lu\n",
           opened ? (unsigned long)s[opened-1] : 0UL);
    printf("  RSS cost of all of them     %ld KiB", after_open - before);
    if (opened) printf("   (%.1f bytes/session)",
                       (double)(after_open - before) * 1024.0 / opened);
    printf("\n\n");

    /* --- 2. log every one of them in ----------------------------------- */
    /* PKCS#11 login state is per token per application, so this logs in once
     * and every other session observes it. The point is exactly that: it does
     * not cost anything per session, and a server cannot use one process to
     * keep two clients logged in as different roles. */
    long before_login = rss_kb();
    int logged = 0;
    for (int i = 0; i < opened; i++) {
        CK_RV rv = p11.Login(s[i], CKU_USER,
                                 (CK_BYTE*)(uintptr_t)pin, (CK_ULONG)strlen(pin));
        if (rv == CKR_OK || rv == 0x00000100UL /* USER_ALREADY_LOGGED_IN */) logged++;
    }
    long after_login = rss_kb();
    printf("  sessions logged in          %d\n", logged);
    printf("  RSS cost of logging in      %ld KiB\n\n", after_login - before_login);

    /* --- 3. give each one an active operation -------------------------- */
    /* This is the state that touches the reservation: an operation slot is
     * ~5 KiB of a table that already exists, so the cost appears as pages
     * becoming resident, not as allocation. */
    long before_op = rss_kb();
    int active = 0;
    CK_MECHANISM sha256 = { 0x00000250UL /* CKM_SHA256 */, NULL, 0 };
    for (int i = 0; i < opened; i++)
        if (p11.DigestInit(s[i], &sha256) == CKR_OK) active++;
    long after_op = rss_kb();
    printf("  sessions with an operation  %d\n", active);
    printf("  RSS cost of the operations  %ld KiB", after_op - before_op);
    if (active) printf("   (%.0f bytes/session)",
                       (double)(after_op - before_op) * 1024.0 / active);
    printf("\n\n");

    long total = rss_kb();
    printf("  RSS, everything held        %ld KiB\n", total);
    printf("  of which fixed at load      %ld KiB  (%.0f%%)\n",
           base_init, 100.0 * (double)base_init / (double)(total ? total : 1));

    for (int i = 0; i < opened; i++) (void)p11.CloseSession(s[i]);
    (void)p11.Finalize(NULL);
    return 0;
}
