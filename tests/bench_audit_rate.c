/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * What one audit line costs.
 *
 * Not a test — nothing here can fail. It exists because `docs/RATE_LIMIT.md`
 * rests on this number, and a number without the program that produced it is
 * an assertion.
 *
 * The question it answers: in the service of #111, a refused request is nearly
 * free for the client — one HTTP request, and in the service a comparison
 * decided before any PKCS#11 call. So what does it cost *us*? The answer is
 * the audit line, and the audit line is an fsync.
 *
 * It lives in tests/ rather than probes/rest/ deliberately. The probes are
 * standalone by design: they reach the module through dlopen, exactly as a
 * client would, and link nothing of ours. This measures something *inside* the
 * module rather than across its API, so it links `$(LIB_OBJ)` like
 * `bench_capacity.c` next door. It is not part of `make tests`.
 *
 *     make tests/bench_audit_rate
 *     FHSM_TOKENS_DIR=$(mktemp -d) LD_LIBRARY_PATH=. ./tests/bench_audit_rate
 *
 * Measured on 2 cores, OpenSSL 3.5.6, the same host as probes/rest/, over
 * seven runs of 300 events:
 *
 *     2.49 - 2.86 ms per line   ->  350 - 402 events/s
 *     302 bytes per line        ->  ~408 MB/hour, ~9.8 GB/day at saturation
 *
 * The very first run reported 3.735 ms and 268 events/s, and a conclusion was
 * nearly drawn from it -- that the log was a lower ceiling than the crypto.
 * Six further runs put it at 2.5-2.9 ms and the first was an outlier, almost
 * certainly a cold page cache right after a build. Hence the loop below is
 * worth running more than once, and hence this comment: one run of this
 * program is not a measurement.
 *
 * For comparison: a composite signature ALONE costs roughly 1 ms on this host.
 * The 3.3-4.3 ms in probes/rest/README.md is the signature plus its audit
 * line, which was not understood when that table was written -- C_Initialize
 * opens the log and C_Sign writes to it, so every probe figure already carried
 * a durable write.
 *
 * So the audit line costs more than the cryptography it records, and a
 * refusal -- which is nearly free to provoke -- costs us more than a signature
 * costs us. Re-running the probes with FHSM_AUDIT_LOG=/dev/null puts four-
 * thread throughput at 1359 sig/s against 247 with the log: the plateau that
 * looked like CPU saturation was this fsync. See the last section of
 * probes/rest/README.md.
 */
#include "fhsm_common.h"
#include "fhsm_audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>

/* Which filesystem the log landed on, because that is the entire measurement.
 * A run on tmpfs measures RAM: fdatasync returns without a barrier and reports
 * three microseconds a line, a thousand times faster than a disk. That is not
 * a fast disk, it is no durability at all -- and `mktemp -d` lands in /tmp,
 * which is tmpfs by default on current Debian. */
static const char *fs_name(const char *path, int *is_volatile)
{
    struct statfs sb;
    *is_volatile = 0;
    if (statfs(path, &sb) != 0) return "(unknown)";
    switch ((unsigned long)sb.f_type) {
    case 0x01021994UL: *is_volatile = 1; return "tmpfs";
    case 0x858458f6UL: *is_volatile = 1; return "ramfs";
    case 0xEF53UL:                       return "ext2/3/4";
    case 0x58465342UL:                   return "xfs";
    case 0x9123683EUL:                   return "btrfs";
    case 0x2FC12FC1UL:                   return "zfs";
    case 0x794c7630UL:                   return "overlayfs";
    case 0x65735546UL:                   return "fuse";
    default:                             return "(other)";
    }
}

static double ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1e3
         + (double)(b.tv_nsec - a.tv_nsec) / 1e6;
}

int main(int argc, char **argv)
{
    const int n = (argc > 1) ? atoi(argv[1]) : 300;
    const char *dir = getenv("FHSM_TOKENS_DIR");
    char path[512];
    snprintf(path, sizeof path, "%s/bench_audit.log", dir ? dir : "/tmp");
    remove(path);

    /* A fixed key: this measures the write path, not key provisioning. */
    uint8_t key[32];
    memset(key, 0x42, sizeof key);
    if (fhsm_audit_open(path, FHSM_SLICE(key, 32)) != FHSM_RV_OK) {
        printf("  cannot open %s\n", path);
        return 2;
    }

    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < n; i++)
        (void)fhsm_audit_event(FHSM_EV_LOGIN_FAIL, -1, -1, FHSM_ROLE_USER,
                                FHSM_RV_PIN_INCORRECT, "actor", "CN=bench", NULL);
    clock_gettime(CLOCK_MONOTONIC, &b);
    fhsm_audit_close();

    double total = ms(a, b);
    double per   = total / (double)n;

    struct stat st;
    double bytes_per_line = 0;
    if (stat(path, &st) == 0) bytes_per_line = (double)st.st_size / (double)(n + 1);

    int is_volatile = 0;
    const char *fs = fs_name(dir ? dir : "/tmp", &is_volatile);

    printf("audit log write cost\n\n");
    printf("  %d events            %8.2f ms total\n", n, total);
    printf("  per event            %8.3f ms\n", per);
    printf("  sustained rate       %8.0f events/s\n", 1000.0 / per);
    printf("  per line             %8.0f bytes\n", bytes_per_line);
    printf("  filesystem           %8s\n", fs);
    printf("  at saturation        %8.1f MB/hour, %.1f GB/day\n",
           (1000.0 / per) * bytes_per_line * 3600.0 / 1e6,
           (1000.0 / per) * bytes_per_line * 86400.0 / 1e9);
    printf("\n  Compare: a composite signature ALONE is roughly 1 ms. The\n"
             "  3.3-4.3 ms in probes/rest/README.md is the signature plus this\n"
             "  line. So the record costs more than the cryptography it records,\n"
             "  and a refusal -- nearly free to provoke -- costs more than a\n"
             "  signature costs us.\n");

    if (is_volatile || per < 0.1) {
        printf("\n"
          "  ==========================================================\n"
          "   THIS RUN MEASURED NOTHING.\n"
          "\n"
          "   %s%s\n"
          "\n"
          "   No physical medium answers a barrier in %.3f ms. fdatasync\n"
          "   returned without making anything durable, so the number above\n"
          "   describes memory, not storage -- and the audit log's whole\n"
          "   guarantee is absent for the same reason.\n"
          "\n"
          "   Point FHSM_TOKENS_DIR at the filesystem a deployment would\n"
          "   actually write to and run it again.\n"
          "  ==========================================================\n",
          is_volatile ? "The log is on " : "The log is on ",
          is_volatile ? fs : "a filesystem whose barrier costs nothing",
          per);
    }

    remove(path);
    return 0;
}
