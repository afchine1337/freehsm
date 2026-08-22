/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/bench_fsync_floor.c --- what the storage costs, with none of our code
 *                               in the loop.
 *
 *  docs/AUDIT_DURABILITY.md publishes "2.5 to 3.3 ms per line" and the module
 *  at "3.44 - 3.57 ms". Those look like numbers about the audit log. They are
 *  almost entirely numbers about the disk: one 300-byte append and one
 *  fdatasync, with nothing of FreeHSM's involved, costs 3.25 ms on the same
 *  filesystem. The log's own overhead is the difference, and it is small.
 *
 *  Which matters because the disk under those figures is a virtual one. A
 *  barrier that takes milliseconds is rotational or network-backed latency; an
 *  NVMe device answers a flush in tens of microseconds, and an enterprise SSD
 *  with power-loss protection in fewer still. So the published figures are a
 *  floor for the machine they were taken on and pessimistic for the machine an
 *  authority would buy -- by how much is not something this file will guess.
 *  Run it there.
 *
 *      make tests/bench_fsync_floor
 *      ./tests/bench_fsync_floor /var/lib/freehsm        # where the log lives
 *
 *  It prints a distribution rather than a mean. A mean of 3.25 ms hides a
 *  minimum of 2.29 and a maximum of 76.4, and the tail is what an operator
 *  feels. It also refuses to let a no-op pass for a measurement: a barrier
 *  that returns in microseconds did not reach stable storage, which is what
 *  tmpfs does, and what once put "0.003 ms" in a document.
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/vfs.h>

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

static double ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}
static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x < y) ? -1 : (x > y);
}

/* Which filesystem, from /proc/mounts, so the output says where it was taken.
 * A durability number without its filesystem is not a measurement, it is an
 * anecdote. */
static void describe(const char *dir, char *out, size_t n)
{
    snprintf(out, n, "unknown");
    char real[4096];
    if (!realpath(dir, real)) return;
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return;
    char dev[128], mnt[256], type[32]; size_t best = 0;
    dev[0] = mnt[0] = type[0] = '\0';
    char line[8192];
    while (fgets(line, sizeof line, f)) {
        char d[256], m[4096], t[64];
        if (sscanf(line, "%255s %4095s %63s", d, m, t) != 3) continue;
        size_t L = strlen(m);
        if (strncmp(real, m, L) == 0 && (real[L] == '/' || real[L] == '\0' || L == 1)) {
            if (L >= best) { best = L;
                             snprintf(dev,  sizeof dev,  "%.127s", d);
                             snprintf(mnt,  sizeof mnt,  "%.255s", m);
                             snprintf(type, sizeof type, "%.31s",  t); }
        }
    }
    fclose(f);
    if (best) snprintf(out, n, "%s on %s (%s)", type, dev, mnt);
}

int main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : ".";
    int n = (argc > 2) ? atoi(argv[2]) : 300;
    if (n < 10 || n > 100000) { fprintf(stderr, "10..100000 samples\n"); return 2; }

    char where[512]; describe(dir, where, sizeof where);

    char path[4600];
    snprintf(path, sizeof path, "%s/.fsync_floor.%d", dir, (int)getpid());
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0600);
    if (fd < 0) { fprintf(stderr, "bench_fsync_floor: %s: %s\n", path, strerror(errno));
                  return 2; }

    /* 300 bytes: the audit line measured in docs/AUDIT_DURABILITY.md is 302. */
    char line[300]; memset(line, 'x', sizeof line); line[sizeof line - 1] = '\n';

    double *d = malloc((size_t)n * sizeof *d);
    if (!d) { close(fd); unlink(path); return 2; }

    for (int i = 0; i < n; i++) {
        double a = ms();
        if (write(fd, line, sizeof line) != (ssize_t)sizeof line) {
            fprintf(stderr, "write: %s\n", strerror(errno)); return 2; }
        if (fdatasync(fd) != 0) {
            fprintf(stderr, "fdatasync: %s\n", strerror(errno)); return 2; }
        d[i] = ms() - a;
    }
    close(fd); unlink(path);

    qsort(d, (size_t)n, sizeof *d, cmp);
    double sum = 0; for (int i = 0; i < n; i++) sum += d[i];
    double mean = sum / n, p50 = d[n/2];

    printf("One 300-byte append and one fdatasync, %d times\n\n", n);
    printf("  filesystem   %s\n", where);
    printf("  min          %8.3f ms\n", d[0]);
    printf("  p50          %8.3f ms\n", p50);
    printf("  p90          %8.3f ms\n", d[(n*9)/10]);
    printf("  p99          %8.3f ms\n", d[(n*99)/100]);
    printf("  max          %8.3f ms\n", d[n-1]);
    printf("  mean         %8.3f ms   -> %.0f lines/s\n", mean, 1000.0 / mean);

    /* The guard. A barrier this fast did not reach stable storage, and a
     * throughput taken here would be a number about nothing. Reported as a
     * failure rather than a footnote: "0.003 ms per line" once reached a
     * document and had to be corrected. */
    struct statfs sf;
    int is_tmpfs = (statfs(dir, &sf) == 0 && (unsigned long)sf.f_type == TMPFS_MAGIC);
    if (p50 < 0.100) {
        printf("\n  NOT A DURABILITY MEASUREMENT.\n");
        printf("  A barrier that returns in %.3f ms did not reach stable storage%s.\n",
               p50, is_tmpfs ? " -- this is tmpfs, where fdatasync is a no-op" : "");
        printf("  Point this at the filesystem the audit log will actually live on.\n");
        free(d);
        return 1;
    }

    printf("\n  This is the floor. FreeHSM's audit log costs this plus its own\n");
    printf("  formatting and HMAC; docs/AUDIT_DURABILITY.md compares the two.\n");
    free(d);
    return 0;
}
