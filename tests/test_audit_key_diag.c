/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_audit_key_diag.c --- a refused audit key says which refusal it was.
 *
 * fhsm_audit_key_provision has six failure exits and one return type, and
 * C_Initialize prints that return as a bare rv. @petrn met it on a directory
 * owned by another user (#11):
 *
 *     FATAL : cannot provision the audit key in /tmp/freehsm-wycheproof (rv=0x6)
 *
 * True, actionable by nobody, and indistinguishable from a TPM blob that will
 * not unseal. This checks the two cases an operator can actually meet on a
 * machine without a TPM, and the one case that must stay silent.
 *
 *   1. the directory cannot be written    -> names the path and strerror
 *   2. the key file is group/world readable -> says so, and says chmod 600
 *   3. no key file at all                 -> silent; this is first use
 *
 * Case 3 is the one worth guarding. A fresh install that printed a failure it
 * then recovered from would teach its operator that this channel is noise,
 * which costs more than the two messages above are worth.
 *
 * Runs as a subprocess per case so the module's one-shot C_Initialize does not
 * carry state between them, and reads what the child wrote to stderr.
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) fails++;
}

/* Run ourselves with FHSM_TOKENS_DIR set, capture stderr. */
static char *run_child(const char *dir, char *buf, size_t cap) {
    char cmd[1024];
    snprintf(cmd, sizeof cmd,
             "FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR='%s' "
             "OPENSSL_CONF=/dev/null ./tests/test_audit_key_diag --child 2>&1",
             dir);
    FILE *p = popen(cmd, "r");
    buf[0] = '\0';
    if (!p) return buf;
    size_t n = fread(buf, 1, cap - 1, p);
    buf[n] = '\0';
    pclose(p);
    return buf;
}

/* The child half: load the module and let C_Initialize try to provision. */
static int child(void) {
    unsigned long (*C_Initialize)(void *) = NULL;
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) return 2;
    *(void **)&C_Initialize = dlsym(h, "C_Initialize");
    if (!C_Initialize) return 2;
    (void)C_Initialize(NULL);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--child") == 0) return child();

    printf("test_audit_key_diag\n");
    char out[8192];

    /* --- 1. a directory that cannot be written ------------------------ */
    char ro[] = "/tmp/fhsm-diag-ro-XXXXXX";
    if (!mkdtemp(ro)) { fprintf(stderr, "mkdtemp\n"); return 2; }
    if (chmod(ro, 0500) != 0) { fprintf(stderr, "chmod\n"); return 2; }
    run_child(ro, out, sizeof out);
    ok(strstr(out, "audit key") != NULL,
       "an unwritable tokens directory produces an audit-key line");
    ok(strstr(out, ro) != NULL, "and names the path");
    ok(strstr(out, "Permission denied") != NULL,
       "and gives the system's reason rather than a bare rv");
    if (!strstr(out, "Permission denied"))
        printf("      got: %.300s\n", out);
    chmod(ro, 0700); rmdir(ro);

    /* --- 2. a key file others can read -------------------------------- */
    char loose[] = "/tmp/fhsm-diag-loose-XXXXXX";
    if (!mkdtemp(loose)) { fprintf(stderr, "mkdtemp\n"); return 2; }
    char kp[512];
    snprintf(kp, sizeof kp, "%s/audit.key", loose);
    FILE *k = fopen(kp, "wb");
    if (!k) { fprintf(stderr, "fopen\n"); return 2; }
    for (int i = 0; i < 32; ++i) fputc(i, k);
    fclose(k);
    chmod(kp, 0644);
    run_child(loose, out, sizeof out);
    ok(strstr(out, "readable by group") != NULL,
       "a group-readable key is refused, and says why");
    ok(strstr(out, "chmod 600") != NULL, "and says what to do about it");
    if (!strstr(out, "readable by group"))
        printf("      got: %.300s\n", out);
    unlink(kp); rmdir(loose);

    /* --- 3. first use says nothing ------------------------------------ */
    char fresh[] = "/tmp/fhsm-diag-fresh-XXXXXX";
    if (!mkdtemp(fresh)) { fprintf(stderr, "mkdtemp\n"); return 2; }
    run_child(fresh, out, sizeof out);
    ok(strstr(out, "audit key") == NULL,
       "a fresh store provisions in silence --- absence is not a failure");
    if (strstr(out, "audit key"))
        printf("      got: %.300s\n", out);
    char rm[600];
    snprintf(rm, sizeof rm, "rm -rf '%s'", fresh);
    if (system(rm) != 0) { /* best effort */ }

    if (fails) { fprintf(stderr, "test_audit_key_diag : %d FAIL\n", fails); return 1; }
    printf("test_audit_key_diag : PASS\n");
    return 0;
}
