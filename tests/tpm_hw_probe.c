/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/tpm_hw_probe.c --- one PKCS#11 action against a REAL TPM (#109).
 *
 *  tests/test_tpm.c drives the module against tests/tpm2-stub.sh, which does no
 *  cryptography. It proves our plumbing and nothing about the TPM. This program
 *  is the other half: a single action per invocation, against a real TPM 2.0,
 *  so a shell script can sequence the states that matter -- notably "the PCRs
 *  moved" and "the machine rebooted", neither of which fits inside one process.
 *
 *  Each run prints one line: RV=0x%08lx NAME. Exit code is 0 if the action
 *  produced the return value the caller said to expect, 1 otherwise, so the
 *  driving script can assert rather than eyeball.
 *
 *  Usage:
 *    tpm_hw_probe init          <path> <so-pin> <user-pin> <expected-rv>
 *    tpm_hw_probe login-so      <path> <so-pin> <expected-rv>
 *    tpm_hw_probe login-user    <path> <user-pin> <expected-rv>
 *
 *  <path> is the token FILE, not the directory: the module derives the sealed
 *  companion as {path}.tpm.
 * ========================================================================= */
#include "fhsm_common.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *rv_name(fhsm_rv_t rv) {
    switch (rv) {
        case FHSM_RV_OK:              return "CKR_OK";
        case FHSM_RV_DEVICE_ERROR:    return "CKR_DEVICE_ERROR  (TPM side failed; PIN counter untouched)";
        case FHSM_RV_PIN_INCORRECT:   return "CKR_PIN_INCORRECT";
        case FHSM_RV_PIN_LOCKED:      return "CKR_PIN_LOCKED";
        case FHSM_RV_PIN_THROTTLED:   return "CKR_PIN_THROTTLED";
        case FHSM_RV_TPM_UNAVAILABLE: return "FHSM_RV_TPM_UNAVAILABLE";
        case FHSM_RV_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
        default:                      return "(other)";
    }
}

static int finish(fhsm_rv_t got, unsigned long want) {
    printf("RV=0x%08lx  %s\n", (unsigned long)got, rv_name(got));
    if ((unsigned long)got == want) return 0;
    printf("   attendu 0x%08lx  --> ECHEC\n", want);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "usage: %s init       <token-path> <so-pin> <user-pin> <expected-rv>\n"
            "       %s login-so   <token-path> <so-pin> <expected-rv>\n"
            "       %s login-user <token-path> <user-pin> <expected-rv>\n",
            argv[0], argv[0], argv[0]);
        return 2;
    }
    const char *action = argv[1];
    const char *path   = argv[2];

    if (strcmp(action, "init") == 0) {
        if (argc != 6) { fprintf(stderr, "init: 4 arguments attendus\n"); return 2; }
        const char *so_pin = argv[3], *user_pin = argv[4];
        unsigned long want = strtoul(argv[5], NULL, 0);
        fhsm_token_t *t = NULL;
        fhsm_rv_t rv = fhsm_token_init(path, so_pin, "tpm-hw-validation", &t);
        if (rv == FHSM_RV_OK && t) {
            /* The SO must set the USER PIN before USER login is possible. */
            rv = fhsm_token_login(t, FHSM_ROLE_SO, so_pin, strlen(so_pin));
            if (rv == FHSM_RV_OK) rv = fhsm_token_init_user_pin(t, user_pin);
            fhsm_token_close(t);
        }
        return finish(rv, want);
    }

    if (strcmp(action, "login-so") == 0 || strcmp(action, "login-user") == 0) {
        if (argc != 5) { fprintf(stderr, "%s: 3 arguments attendus\n", action); return 2; }
        const char *pin = argv[3];
        unsigned long want = strtoul(argv[4], NULL, 0);
        fhsm_role_t role = (strcmp(action, "login-so") == 0) ? FHSM_ROLE_SO : FHSM_ROLE_USER;
        fhsm_token_t *t = NULL;
        fhsm_rv_t rv = fhsm_token_load(path, &t);
        if (rv != FHSM_RV_OK || !t) {
            printf("RV=0x%08lx  (chargement du token impossible)\n", (unsigned long)rv);
            return 1;
        }
        rv = fhsm_token_login(t, role, pin, strlen(pin));
        fhsm_token_close(t);
        return finish(rv, want);
    }

    fprintf(stderr, "action inconnue: %s\n", action);
    return 2;
}
