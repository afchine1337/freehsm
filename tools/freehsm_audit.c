/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * freehsm-audit --- human-readable dump of FreeHSM C audit log.
 *
 *  Usage : freehsm-audit dump   <path.audit.log> [path...]
 *          freehsm-audit verify <path.audit.log> <audit_key_hex_64>
 *
 *  The audit format is one JSON-Lines record per line written by
 *  src/fhsm_audit.c. Each record carries HMAC-SHA-256(audit_key, line up to
 *  the "hmac" field) -- and that line already contains prev_hmac, so the
 *  chain is authenticated without the previous digest being fed in again.
 *
 *  This file used to describe, and compute, HMAC(key, prev_hmac ||
 *  line_minus_hmac) and to start the chain from 64 zero bytes. The module
 *  does neither. No line the module writes could ever have verified here,
 *  in two independent ways -- invisible while no log was ever written.
 *
 *  `dump` formats every event as a single human-readable row.
 *  `verify` walks the chain. Three checks per line, all required:
 *    - the recorded HMAC matches the line          (catches modification)
 *    - prev_hmac equals the previous line's hmac   (catches deletion,
 *      insertion, reordering -- each line self-authenticates, so removing
 *      one leaves the rest individually valid)
 *    - seq equals the line number                  (catches a middle record
 *      removed by a forger who renumbered)
 *
 *  Not caught, and not catchable from the file alone: truncation at the end.
 *  A log cut short is a shorter chain that verifies perfectly. See the note
 *  in src/fhsm_audit.c and docs/ROADMAP.md.
 *
 *  The first line's prev_hmac is HMAC(key, "FHSM-AUDIT-INIT|seq=0").
 *
 *  This tool deliberately does not link the module: an auditor should be
 *  able to build the verifier on its own, and a check that shares code with
 *  what it checks is a mirror. tests/test_audit_verify.c runs both against
 *  the same real log, which is what would have caught the drift above.
 *
 *  Build : cc tools/freehsm_audit.c -lcrypto -o freehsm-audit
 * ========================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#define LINE_MAX_LEN  4096

static int find_str(const char *line, const char *key, char *out, size_t cap) {
    char needle[64]; snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *p = strstr(line, needle);
    if (!p) return -1;
    p += strlen(needle);
    const char *e = strchr(p, '"');
    if (!e) return -1;
    size_t n = (size_t)(e - p);
    if (n + 1 > cap) n = cap - 1;
    memcpy(out, p, n); out[n] = '\0';
    return 0;
}

static int find_int(const char *line, const char *key, long long *out) {
    char needle[64]; snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(line, needle);
    if (!p) return -1;
    p += strlen(needle);
    char *end = NULL;
    long long v = strtoll(p, &end, 10);
    if (end == p) return -1;
    *out = v;
    return 0;
}

static int find_params(const char *line, char *out, size_t cap) {
    const char *p = strstr(line, "\"params\":");
    if (!p) return -1;
    p += strlen("\"params\":");
    if (*p != '{') return -1;
    int depth = 0;
    const char *start = p;
    while (*p) {
        if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
        p++;
    }
    size_t n = (size_t)(p - start);
    if (n + 1 > cap) n = cap - 1;
    memcpy(out, start, n); out[n] = '\0';
    return 0;
}

static void ts_to_iso(int64_t ns, char *out, size_t cap) {
    if (cap == 0) return;
    out[0] = '\0';
    time_t s = (time_t)(ns / 1000000000ll);
    struct tm tm; gmtime_r(&s, &tm);
    /* Clamp micro to [0, 999999] so gcc-14's format-truncation analysis
     * sees a bounded width. */
    long us_raw = (long)((ns % 1000000000ll) / 1000ll);
    if (us_raw < 0) us_raw = 0;
    if (us_raw > 999999) us_raw = 999999;
    snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ",
             (tm.tm_year + 1900) % 10000, (tm.tm_mon + 1) % 100,
             tm.tm_mday % 100, tm.tm_hour % 100, tm.tm_min % 100,
             tm.tm_sec % 100, us_raw);
}

static void rv_to_name(unsigned long rv, char *out, size_t cap) {
    switch (rv) {
        case 0x00000000UL: snprintf(out, cap, "CKR_OK");                       break;
        case 0x00000005UL: snprintf(out, cap, "CKR_GENERAL_ERROR");           break;
        case 0x00000006UL: snprintf(out, cap, "CKR_FUNCTION_FAILED");         break;
        case 0x00000007UL: snprintf(out, cap, "CKR_ARGUMENTS_BAD");           break;
        case 0x000000A0UL: snprintf(out, cap, "CKR_PIN_INCORRECT");            break;
        case 0x000000A4UL: snprintf(out, cap, "CKR_PIN_LOCKED");                break;
        case 0x00000101UL: snprintf(out, cap, "CKR_USER_NOT_LOGGED_IN");      break;
        case 0x000000E0UL: snprintf(out, cap, "CKR_TOKEN_NOT_PRESENT");        break;
        case 0x80000001UL: snprintf(out, cap, "FHSM_RV_KAT_FAILED");          break;
        case 0x80000002UL: snprintf(out, cap, "FHSM_RV_INTEGRITY_FAILED");    break;
        case 0x80000003UL: snprintf(out, cap, "FHSM_RV_FIPS_NOT_APPROVED");   break;
        case 0x80000004UL: snprintf(out, cap, "FHSM_RV_PIN_THROTTLED");       break;
        default:           snprintf(out, cap, "rv=0x%08lx", rv);              break;
    }
}

/* ---- dump ---------------------------------------------------------------- */

static int dump_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 1; }
    char line[LINE_MAX_LEN];
    int n_events = 0;
    printf("# %s\n", path);
    printf("# %-26s %-7s %-22s %-4s %-7s %-4s %-30s %s\n",
           "timestamp", "seq", "event", "slot", "session", "role", "result", "params");
    while (fgets(line, sizeof(line), f)) {
        long long seq = 0, ts = 0, slot = -1, session = -1, rv = 0;
        char event[64] = "", role[16] = "", result[8] = "";
        char params[1024] = "{}";
        find_int(line, "seq",     &seq);
        find_int(line, "ts",      &ts);
        find_int(line, "slot",    &slot);
        find_int(line, "session", &session);
        find_int(line, "rv",      &rv);
        find_str(line, "event",   event,  sizeof(event));
        find_str(line, "role",    role,   sizeof(role));
        find_str(line, "result",  result, sizeof(result));
        find_params(line, params, sizeof(params));
        char iso[40]; ts_to_iso((int64_t)ts, iso, sizeof(iso));
        char rvname[48]; rv_to_name((unsigned long)rv, rvname, sizeof(rvname));
        printf("  %-26s %-7lld %-22s %4lld %7lld %-4s %-30s %s\n",
               iso, seq, event, slot, session, role, rvname, params);
        n_events++;
    }
    fclose(f);
    printf("# total : %d events\n", n_events);
    return 0;
}

/* ---- verify -------------------------------------------------------------- */

static int hex2bin(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int b;
        if (sscanf(hex + 2*i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

/* Compute HMAC-SHA-256 via the OpenSSL 3.0+ EVP_MAC API (the legacy
 * HMAC_* family is deprecated since 3.0). Returns 0 on success. */
static int hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *part1, size_t l1,
                        const uint8_t *part2, size_t l2,
                        uint8_t out[32]) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) return -1;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) return -1;
    char digest_name[] = "SHA256";
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string("digest", digest_name, 0),
        OSSL_PARAM_construct_end()
    };
    if (EVP_MAC_init(ctx, key, key_len, params) != 1) {
        EVP_MAC_CTX_free(ctx); return -1;
    }
    if (l1 && EVP_MAC_update(ctx, part1, l1) != 1) {
        EVP_MAC_CTX_free(ctx); return -1;
    }
    if (l2 && EVP_MAC_update(ctx, part2, l2) != 1) {
        EVP_MAC_CTX_free(ctx); return -1;
    }
    size_t out_len = 32;
    int ok = EVP_MAC_final(ctx, out, &out_len, 32);
    EVP_MAC_CTX_free(ctx);
    return ok == 1 ? 0 : -1;
}

static int verify_file(const char *path, const char *key_hex) {
    uint8_t key[32];
    if (strlen(key_hex) != 64 || hex2bin(key_hex, key, 32) < 0) {
        fprintf(stderr, "verify: key must be 64 hex chars (32 bytes)\n");
        return 2;
    }
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 1; }

    /* Chain head, as src/fhsm_audit.c seeds it. */
    static const char INIT[] = "FHSM-AUDIT-INIT|seq=0";
    uint8_t expect_prev[32];
    if (hmac_sha256(key, 32, NULL, 0,
                     (const uint8_t*)INIT, sizeof INIT - 1, expect_prev) != 0) {
        fprintf(stderr, "verify: cannot compute the chain head\n");
        fclose(f); return 1;
    }

    char line[LINE_MAX_LEN];
    int n = 0, bad = 0;
    while (fgets(line, sizeof(line), f)) {
        n++;
        const char *h = strstr(line, "\"hmac\":\"");
        const char *p = strstr(line, "\"prev_hmac\":\"");
        const char *q = strstr(line, "\"seq\":");
        if (!h || !p || !q) {
            fprintf(stderr, "line %d : missing hmac, prev_hmac or seq field\n", n);
            bad++; continue;
        }
        size_t body_len = (size_t)(h - line);
        uint8_t recorded[32], prev_field[32];
        if (hex2bin(h + 8, recorded, 32) < 0 || hex2bin(p + 13, prev_field, 32) < 0) {
            fprintf(stderr, "line %d : malformed hmac hex\n", n); bad++; continue;
        }
        uint8_t mac[32];
        if (hmac_sha256(key, 32, NULL, 0,
                         (const uint8_t*)line, body_len, mac) != 0) {
            fprintf(stderr, "line %d : HMAC computation failed\n", n);
            bad++; continue;
        }
        if (CRYPTO_memcmp(mac, recorded, 32) != 0) {
            fprintf(stderr, "line %d : HMAC mismatch (record altered)\n", n);
            bad++;
        }
        if (CRYPTO_memcmp(prev_field, expect_prev, 32) != 0) {
            fprintf(stderr, "line %d : prev_hmac does not follow line %d"
                             " (record deleted, inserted or reordered)\n", n, n - 1);
            bad++;
        }
        if (strtoull(q + 6, NULL, 10) != (unsigned long long)n) {
            fprintf(stderr, "line %d : seq is not %d (records missing)\n", n, n);
            bad++;
        }
        memcpy(expect_prev, recorded, 32);
    }
    fclose(f);
    if (bad) {
        fprintf(stderr, "verify: %d/%d records FAILED\n", bad, n);
        return 1;
    }
    printf("verify: %d records OK, chain intact\n", n);
    return 0;
}

/* ---- main ---------------------------------------------------------------- */

static int usage(const char *prog) {
    fprintf(stderr, "Usage:\n"
                     "  %s dump   <path.audit.log> [path...]\n"
                     "  %s verify <path.audit.log> <audit_key_hex_64>\n"
                     "  %s verify <directory>         <audit_key_hex_64>\n"
                     "\n"
                     "  A directory verifies every base.NNNNNN log in it and\n"
                     "  reports holes in the numbering, which is how a removed\n"
                     "  log becomes visible.\n",
                     prog, prog, prog);
    return 2;
}

/* ---------------------------------------------------------------------------
 * Verifying a directory.
 *
 * A hash chain has one author, so each opening of the log creates its own file
 * `base.NNNNNN` -- see src/fhsm_audit.c. Reviewing a deployment therefore
 * means verifying a set, not a file.
 *
 * The numbering is what makes the set auditable. Each chain verifies on its
 * own, so deleting a whole file would remove a process's entire history while
 * everything left still checked out. A hole between 6 and 8 says a file is
 * gone. Deleting the highest-numbered ones leaves no hole -- the same
 * end-of-log truncation that a single file already permits, and recorded as
 * such rather than presented as new.
 * ------------------------------------------------------------------------- */
struct logfile { unsigned long seq; char path[512]; };

static int by_seq(const void *a, const void *b) {
    unsigned long x = ((const struct logfile*)a)->seq;
    unsigned long y = ((const struct logfile*)b)->seq;
    return x < y ? -1 : x > y;
}

static int verify_dir(const char *dir, const char *key_hex) {
    DIR *d = opendir(dir);
    if (!d) { perror(dir); return 1; }

    static struct logfile f[4096];
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) && n < (int)(sizeof f / sizeof f[0])) {
        const char *dot = strrchr(e->d_name, '.');
        if (!dot || strlen(dot) != 7) continue;
        char *end = NULL;
        unsigned long v = strtoul(dot + 1, &end, 10);
        if (!end || *end) continue;
        f[n].seq = v;
        snprintf(f[n].path, sizeof f[n].path, "%s/%s", dir, e->d_name);
        n++;
    }
    closedir(d);

    if (n == 0) {
        fprintf(stderr, "verify: no numbered audit file in %s\n", dir);
        return 1;
    }
    qsort(f, (size_t)n, sizeof f[0], by_seq);

    int rc = 0;
    for (int i = 0; i < n; i++) {
        printf("== %s\n", f[i].path);
        if (verify_file(f[i].path, key_hex) != 0) rc = 1;
        if (i && f[i].seq != f[i-1].seq + 1) {
            fflush(stdout);   /* so the hole appears where it happened */
            fprintf(stderr, "verify: MISSING log(s) between %06lu and %06lu"
                             " -- a file was removed\n", f[i-1].seq, f[i].seq);
            rc = 1;
        }
    }
    printf("\nverify: %d log(s), sequence %06lu..%06lu%s\n",
           n, f[0].seq, f[n-1].seq,
           rc ? "" : ", contiguous, every chain intact");
    if (f[0].seq != 1)
        printf("verify: note -- the sequence starts at %06lu, not 000001;"
                " earlier logs were archived or removed\n", f[0].seq);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage(argv[0]);
    if (strcmp(argv[1], "dump") == 0) {
        if (argc < 3) return usage(argv[0]);
        int rc = 0;
        for (int i = 2; i < argc; ++i) rc |= dump_file(argv[i]);
        return rc;
    }
    if (strcmp(argv[1], "verify") == 0) {
        if (argc != 4) return usage(argv[0]);
        struct stat sb;
        if (stat(argv[2], &sb) == 0 && S_ISDIR(sb.st_mode))
            return verify_dir(argv[2], argv[3]);
        return verify_file(argv[2], argv[3]);
    }
    return usage(argv[0]);
}
