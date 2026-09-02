/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * probe_fips_loaded --- did C_Initialize actually load the FIPS provider?
 *
 * WHY THIS EXISTS
 *
 * scripts/run_fips_tests.sh asked the question the wrong way round on its
 * first run. It executed the suite and counted the tests that did *not* print
 * the module's "dev mode active" notice, and reported 21 of them as having
 * "passed with the provider loaded". Silence is not evidence. A test that
 * never reaches crypto_init_once prints nothing and was counted as a FIPS run.
 * The recurring error in this project, in a new place: an absence in the
 * output taken for an absence in the world -- and this time in the very
 * script written to stop making it.
 *
 * So this asks positively, and of the only configuration in which the
 * question is answerable: the shipped .so, opened by dlopen, which is the one
 * artefact `make integrity` signs. A test binary statically linked against
 * $(LIB_OBJ) carries the all-zero .fhsm_digest placeholder, so it can never
 * be signed, so it can never run without FHSM_INTEGRITY_ALLOW_UNSIGNED, so it
 * can never load the provider. That is a property of how it is built, not a
 * failure to report per run.
 *
 * Exit status is the answer: 0 loaded, 1 not loaded, 2 could not ask.
 * ========================================================================= */
#include <openssl/provider.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef unsigned long CK_RV;
typedef CK_RV (*init_fn)(void *);

int main(int argc, char **argv)
{
    const char *mod = (argc > 1) ? argv[1] : "./libfreehsm.so";

    /* Say this here rather than let it become a puzzling result later: in
     * this mode src/fhsm_crypto.c does not even attempt OSSL_PROVIDER_load,
     * so a "no" below would say nothing about the provider. */
    if (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED")) {
        puts("FHSM_INTEGRITY_ALLOW_UNSIGNED is set: the module skips the "
             "provider entirely, so the question cannot be answered");
        return 2;
    }

    void *h = dlopen(mod, RTLD_NOW);
    if (!h) { printf("dlopen(%s): %s\n", mod, dlerror()); return 2; }

    /* ISO C forbids the object-pointer-to-function-pointer cast and
     * -Wpedantic -Werror enforces it, so go through an object pointer the way
     * tests/test_op_state.c does. */
    init_fn c_init = NULL;
    *(void **)&c_init = dlsym(h, "C_Initialize");
    if (!c_init) { printf("no C_Initialize in %s\n", mod); return 2; }

    CK_RV rv = c_init(NULL);
    if (rv != 0) {
        /* 0x000001C0 is FHSM_RV_INTEGRITY_FAILED's CKR mapping in practice;
         * printing the raw value is more useful than guessing at it. */
        printf("C_Initialize failed (0x%lx) -- an unsigned module, or the "
               "provider refused to load\n", rv);
        dlclose(h);
        return 2;
    }

    /* The module loads the provider into the default library context, and
     * this process shares that context with it. */
    int loaded = OSSL_PROVIDER_available(NULL, "fips");
    printf("%s\n", loaded
           ? "fips provider available after C_Initialize"
           : "NO fips provider after C_Initialize");

    init_fn c_fini = NULL;
    *(void **)&c_fini = dlsym(h, "C_Finalize");
    if (c_fini) c_fini(NULL);
    return loaded ? 0 : 1;
}
