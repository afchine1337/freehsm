/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/bench_fork_client.c --- what a process-per-client server costs (#111).
 *
 *  §2b of docs/REST_API_DESIGN.md settles the isolation question -- p11-kit
 *  remoting forks a child per connection, so each client is its own PKCS#11
 *  application and its own login -- and opens a capacity one it could not
 *  answer: what does each of those children cost.
 *
 *  Two costs, and the second is the one that is usually measured wrong.
 *
 *  TIME. A child is a new application, so it repeats C_Initialize -- which
 *  runs the integrity check and the power-on self-tests -- and C_Login, whose
 *  PBKDF2 is expensive on purpose. Both are per connection, not per process
 *  lifetime, so they set a ceiling on connections per second that has nothing
 *  to do with how fast the module signs.
 *
 *  MEMORY. Reported in PSS, not RSS. Resident set counts a shared page in full
 *  for every process mapping it, so summing RSS over N children counts one
 *  copy of libcrypto N times and answers a question nobody asked. Proportional
 *  set size divides each page by the number of processes sharing it, so the
 *  sum over the family is what the family actually occupies.
 *
 *  And two models, because they differ by exactly the thing COW provides:
 *
 *      fork        the child inherits the parent's pages copy-on-write, so
 *                  everything C_Initialize touched in the parent is shared
 *                  until written
 *      fork+exec   what p11-kit-remote actually does. exec replaces the
 *                  address space, so nothing but the file-backed libraries is
 *                  shared and every child pays the whole cost again
 *
 *      make tests/bench_fork_client && ./tests/bench_fork_client 16
 *      ./tests/bench_fork_client 16 --exec
 *
 *  Run several times. The first is always the slowest and is not the number.
 * ========================================================================= */
#include "p11_util.h"

#include <sys/wait.h>
#include <time.h>

static double ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

/* Proportional set size, in KiB. smaps_rollup exists since Linux 4.14; if it
 * is missing we say so rather than silently falling back to RSS, because RSS
 * would answer a different question while looking like an answer. */
static long pss_kb(pid_t pid) {
    char path[64];
    if (pid == 0) snprintf(path, sizeof path, "/proc/self/smaps_rollup");
    else          snprintf(path, sizeof path, "/proc/%ld/smaps_rollup", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256]; long v = -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "Pss: %ld kB", &v) == 1) break;
    fclose(f);
    return v;
}

struct report { double t_init, t_login, t_op; };

/* Where a child's memory actually is. PSS answers "how much", these answer
 * "why", which is the difference between reporting a measurement and telling
 * a story about one: fork and fork+exec differ by 2x and the explanation has
 * to come from the same file as the number. */
struct where { long pss, priv_dirty, shared_clean, shared_dirty; };
static void where_kb(pid_t pid, struct where *w) {
    char path[64];
    if (pid == 0) snprintf(path, sizeof path, "/proc/self/smaps_rollup");
    else          snprintf(path, sizeof path, "/proc/%ld/smaps_rollup", (long)pid);
    memset(w, 0, sizeof *w);
    FILE *f = fopen(path, "r"); if (!f) return;
    char line[256]; long v;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "Pss: %ld kB", &v) == 1)           w->pss = v;
        else if (sscanf(line, "Private_Dirty: %ld kB", &v) == 1) w->priv_dirty = v;
        else if (sscanf(line, "Shared_Clean: %ld kB", &v) == 1)  w->shared_clean = v;
        else if (sscanf(line, "Shared_Dirty: %ld kB", &v) == 1)  w->shared_dirty = v;
    }
    fclose(f);
}

/* One client's whole life, from an address space that has just been made.
 * Shared by the forked child and the exec'd one so that the two models differ only
 * in how the address space arrived. */
static int be_a_client(const char *modpath, const char *pin, struct report *r)
{
    double a = ms();
    CK_RV rv0 = p11.Initialize(NULL);
    if (rv0 != CKR_OK) {
        fprintf(stderr, "client: C_Initialize -> 0x%lx\n", (unsigned long)rv0);
        return 2; }
    double b = ms();

    CK_SLOT_ID slot = p11_resolve_slot(-1, P11_SLOT_WITH_TOKEN);
    CK_SESSION_HANDLE s = 0;
    CK_RV rvo = p11.OpenSession(slot, CKF_RW, NULL, NULL, &s);
    if (rvo != CKR_OK) {
        fprintf(stderr, "client: C_OpenSession -> 0x%lx\n", (unsigned long)rvo);
        return 2; }
    CK_RV rv = p11.Login(s, CKU_USER, (CK_BYTE*)(uintptr_t)pin, (CK_ULONG)strlen(pin));
    if (rv != CKR_OK && rv != 0x00000100UL) {
        fprintf(stderr, "client: C_Login -> 0x%lx\n", (unsigned long)rv);
        return 2; }
    double c = ms();

    CK_MECHANISM sha256 = { 0x00000250UL, NULL, 0 };
    CK_RV rvd = p11.DigestInit(s, &sha256);
    if (rvd != CKR_OK) {
        fprintf(stderr, "client: C_DigestInit -> 0x%lx\n", (unsigned long)rvd);
        return 2; }
    double d = ms();

    r->t_init = b - a; r->t_login = c - b; r->t_op = d - c;
    return 0;
}

int main(int argc, char **argv)
{
    p11_progname = "bench_fork_client";
    const char *modpath = getenv("FHSM_MODULE");
    if (!modpath || !*modpath) modpath = "./libfreehsm.so";
    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) pin = "userpin1234";

    /* --- the exec'd child: a fresh address space, told nothing else ------ */
    if (argc > 1 && !strcmp(argv[1], "--client")) {
        struct report r = {0,0,0};
        load_module(modpath);
        if (be_a_client(modpath, pin, &r) != 0) return 2;
        /* fd 3 is the pipe the parent left open across exec. */
        if (write(3, &r, sizeof r) != (ssize_t)sizeof r) return 2;
        struct where w; where_kb(0, &w);
        if (write(3, &w, sizeof w) != (ssize_t)sizeof w) return 2;
        char stop; (void)!read(4, &stop, 1);   /* hold until released */
        return 0;
    }

    int n = (argc > 1) ? atoi(argv[1]) : 8;
    int use_exec = 0;
    for (int i = 1; i < argc; i++) if (!strcmp(argv[i], "--exec")) use_exec = 1;
    if (n < 1 || n > 512) { fprintf(stderr, "1..512 clients\n"); return 2; }

    printf("What a process-per-client server costs  (%s, %d clients)\n\n",
           use_exec ? "fork+exec, the p11-kit model" : "fork, copy-on-write", n);

    /* The parent is the listener: module loaded and initialised before any
     * connection arrives. Whether that helps depends entirely on the model. */
    load_module(modpath);
    if (p11.Initialize(NULL) != CKR_OK) {
        fprintf(stderr, "bench_fork_client: C_Initialize failed\n"); return 2; }
    long parent_alone = pss_kb(0);
    if (parent_alone < 0) {
        fprintf(stderr, "bench_fork_client: /proc/self/smaps_rollup is not"
                        " readable -- PSS is the whole point, so stopping"
                        " rather than reporting RSS as though it answered.\n");
        return 2;
    }
    printf("  the listener alone, PSS        %ld KiB\n\n", parent_alone);

    pid_t kids[512]; int up[512][2], down[512][2];
    double t0 = ms();
    for (int i = 0; i < n; i++) {
        if (pipe(up[i]) || pipe(down[i])) { perror("pipe"); return 2; }
        pid_t k = fork();
        if (k < 0) { perror("fork"); return 2; }
        if (k == 0) {
            close(up[i][0]); close(down[i][1]);
            if (use_exec) {
                (void)dup2(up[i][1], 3); (void)dup2(down[i][0], 4);
                execl("/proc/self/exe", argv[0], "--client", (char*)NULL);
                _exit(3);
            }
            struct report r = {0,0,0};
            if (be_a_client(modpath, pin, &r) != 0) _exit(2);
            (void)!write(up[i][1], &r, sizeof r);
            struct where w; where_kb(0, &w);
            (void)!write(up[i][1], &w, sizeof w);
            char stop; (void)!read(down[i][0], &stop, 1);
            _exit(0);
        }
        kids[i] = k;
        close(up[i][1]); close(down[i][0]);
    }

    /* Collect while they are all still alive: PSS of a dead child is nothing,
     * and the question is what N of them occupy at once. */
    double ti = 0, tl = 0, to = 0; int ok_n = 0;
    long child_pss = 0, child_priv = 0, child_shclean = 0, child_shdirty = 0;
    for (int i = 0; i < n; i++) {
        struct report r; struct where w;
        if (read(up[i][0], &r, sizeof r) != (ssize_t)sizeof r) continue;
        if (read(up[i][0], &w, sizeof w) != (ssize_t)sizeof w) continue;
        ti += r.t_init; tl += r.t_login; to += r.t_op;
        child_pss += w.pss; child_priv += w.priv_dirty;
        child_shclean += w.shared_clean; child_shdirty += w.shared_dirty;
        ok_n++;
    }
    double t_all = ms() - t0;
    long parent_now = pss_kb(0);
    printf("  clients that came up           %d of %d\n", ok_n, n);
    if (ok_n == 0) { fprintf(stderr, "no client came up\n"); return 2; }

    printf("\n  Per client, mean of %d:\n", ok_n);
    printf("    C_Initialize                 %7.2f ms   (integrity check + KATs)\n", ti/ok_n);
    printf("    C_Login                      %7.2f ms   (PBKDF2, expensive on purpose)\n", tl/ok_n);
    printf("    first operation              %7.2f ms\n", to/ok_n);
    printf("    before the first request     %7.2f ms\n", (ti+tl+to)/ok_n);
    if (ok_n > 1)
        printf("    (inflated by contention: %d clients competing for the\n"
               "     machine's cores. Run with 1 client for the serial cost;\n"
               "     the rate that matters is the wall clock below.)\n", ok_n);
    printf("    connections/s, aggregate     %7.1f   (%d in %.1f ms)\n",
           (double)ok_n / (t_all / 1000.0), ok_n, t_all);

    printf("\n  Memory, PSS (shared pages divided, not counted twice):\n");
    printf("    listener, before forking     %7ld KiB\n", parent_alone);
    printf("    listener, after forking      %7ld KiB   (falls: its pages are\n"
           "                                              now shared, so its\n"
           "                                              proportional share\n"
           "                                              is smaller)\n", parent_now);
    printf("    %3d clients together         %7ld KiB\n", ok_n, child_pss);
    printf("    per client                   %7.0f KiB\n", (double)child_pss/ok_n);
    printf("    whole family                 %7ld KiB\n", parent_now + child_pss);
    printf("    vs one listener alone        %7.1fx\n",
           (double)(parent_now + child_pss) / (double)parent_alone);
    printf("\n  Where a client's memory is, mean per client:\n");
    printf("    private dirty                %7ld KiB   (its own, nobody else's)\n",
           child_priv / ok_n);
    printf("    shared clean                 %7ld KiB   (file-backed: the libraries)\n",
           child_shclean / ok_n);
    printf("    shared dirty                 %7ld KiB   (still copy-on-write)\n",
           child_shdirty / ok_n);


    for (int i = 0; i < n; i++) { (void)!write(down[i][1], "x", 1); close(down[i][1]); }
    for (int i = 0; i < n; i++) { int st; (void)waitpid(kids[i], &st, 0); }
    return 0;
}
