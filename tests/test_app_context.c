/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_app_context.c --- regression test: after C_Initialize, the application's
 * OpenSSL library context is unchanged.
 *
 *  Before the module ran in its own private OSSL_LIB_CTX, C_Initialize called
 *  OSSL_PROVIDER_load and EVP_default_properties_enable_fips directly on the
 *  calling thread's default context (NULL). This polluted the application's
 *  context by activating the FIPS provider and enabling fips=yes globally.
 *
 *  With the private context, every C_* call runs inside the module's private
 *  context and restores the caller's context upon return. This test verifies:
 *    1. OSSL_PROVIDER_available(NULL, "fips") is unchanged across C_Initialize.
 *    2. EVP_default_properties_is_fips_enabled(NULL) is unchanged across
 *       C_Initialize, whether the application had fips enabled or disabled.
 *    3. A second C_Initialize in the same process succeeds, reuses the loaded
 *       providers without error, and preserves
 *       the application's context.
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>

typedef unsigned long CK_RV;
typedef CK_RV (*c_initialize_fn)(void *);
typedef CK_RV (*c_finalize_fn)(void *);

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

int main(int argc, char **argv) {
    const char *mod = (argc > 1) ? argv[1] : "./libfreehsm.so";
    printf("test_app_context: application OpenSSL context isolation\n\n");

    void *h = dlopen(mod, RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        fprintf(stderr, "dlopen %s: %s\n", mod, dlerror());
        return 2;
    }

    c_initialize_fn c_init = NULL;
    c_finalize_fn   c_fini = NULL;
    *(void **)&c_init = dlsym(h, "C_Initialize");
    *(void **)&c_fini = dlsym(h, "C_Finalize");
    if (!c_init || !c_fini) {
        fprintf(stderr, "%s: missing C_Initialize or C_Finalize\n", mod);
        dlclose(h);
        return 2;
    }

    int prov_before = OSSL_PROVIDER_available(NULL, "fips");
    int fips_before = EVP_default_properties_is_fips_enabled(NULL);

    CK_RV rv = c_init(NULL);
    ok(rv == 0, "first C_Initialize succeeds");

    int prov_after = OSSL_PROVIDER_available(NULL, "fips");
    int fips_after = EVP_default_properties_is_fips_enabled(NULL);

    ok(prov_after == prov_before,
       "OSSL_PROVIDER_available(NULL, fips) unchanged after C_Initialize");
    ok(fips_after == fips_before,
       "EVP_default_properties_is_fips_enabled(NULL) unchanged after C_Initialize");

    rv = c_fini(NULL);
    ok(rv == 0, "C_Finalize succeeds");

    /* Second C_Initialize in the same process */
    rv = c_init(NULL);
    ok(rv == 0, "second C_Initialize in same process succeeds");

    ok(OSSL_PROVIDER_available(NULL, "fips") == prov_before,
       "OSSL_PROVIDER_available(NULL, fips) unchanged after second C_Initialize");
    ok(EVP_default_properties_is_fips_enabled(NULL) == fips_before,
       "EVP_default_properties_is_fips_enabled(NULL) unchanged after second C_Initialize");

    c_fini(NULL);

    /* 3. When the application explicitly sets fips=yes on its own context */
    EVP_default_properties_enable_fips(NULL, 1);
    prov_before = OSSL_PROVIDER_available(NULL, "fips");
    fips_before = EVP_default_properties_is_fips_enabled(NULL);

    rv = c_init(NULL);
    ok(rv == 0, "C_Initialize succeeds when application has fips property enabled");
    ok(OSSL_PROVIDER_available(NULL, "fips") == prov_before,
       "OSSL_PROVIDER_available(NULL, fips) unchanged with application fips=yes");
    ok(EVP_default_properties_is_fips_enabled(NULL) == fips_before,
       "EVP_default_properties_is_fips_enabled(NULL) remains enabled on application side");
    c_fini(NULL);

    /* 4. When the application explicitly sets fips=no on its own context */
    EVP_default_properties_enable_fips(NULL, 0);
    prov_before = OSSL_PROVIDER_available(NULL, "fips");
    fips_before = EVP_default_properties_is_fips_enabled(NULL);

    rv = c_init(NULL);
    ok(rv == 0, "C_Initialize succeeds when application has fips property disabled");
    ok(OSSL_PROVIDER_available(NULL, "fips") == prov_before,
       "OSSL_PROVIDER_available(NULL, fips) unchanged with application fips=no");
    ok(EVP_default_properties_is_fips_enabled(NULL) == fips_before,
       "EVP_default_properties_is_fips_enabled(NULL) remains disabled on application side");
    c_fini(NULL);

    dlclose(h);

    if (fails) {
        fprintf(stderr, "test_app_context : %d FAIL\n", fails);
        return 1;
    }
    printf("test_app_context : PASS\n");
    return 0;
}
