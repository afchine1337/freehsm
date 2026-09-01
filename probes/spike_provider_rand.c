/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * spike_provider_rand --- can a provider-supplied RAND become the source that
 *                         EVP_PKEY_Q_keygen draws from?
 *
 * WHY
 * ---
 * tests/probe_keygen_drbg.c shows that no key this module generates draws its
 * material from fhsm_drbg: RSA-2048, RSA-4096 and EC P-256 each draw exactly
 * 96 bytes, a fixed cost that cannot be key material. The proposed fix is a
 * private OSSL_LIB_CTX whose RAND is the module's DRBG. This asks whether that
 * fix exists before anyone writes it.
 *
 * WHAT IT ANSWERED (2026-09-01, default provider)
 * -----------------------------------------------
 *     RSA-2048   ok   provider RAND bytes: 31574
 *     RSA-4096   ok   provider RAND bytes: 77772
 *     EC P-256   ok   provider RAND bytes: 32
 *     ML-DSA-65  ok   provider RAND bytes: 32
 *
 * The counter tracks key size, which is what "it is being used" looks like.
 * Note the first attempt returned a deterministic ramp instead of random
 * bytes and RSA refused it -- prime generation rejecting a bad source is the
 * health check working, and it is why this returns real bytes now.
 *
 * WHAT IT HAS NOT ANSWERED
 * ------------------------
 * Whether the FIPS provider tolerates an external RAND for key generation.
 * The sandbox this was written in has no FIPS provider, so the question is
 * open, and the answer decides whether the property is reachable in the
 * fips-strict profile or has to be stated as unreachable there.
 *
 * TO ANSWER IT, on a machine whose OpenSSL has the FIPS provider:
 *
 *     cc -Wall -std=c11 -I$OPENSSL_PREFIX/include \
 *        -o /tmp/spike probes/spike_provider_rand.c \
 *        -L$OPENSSL_PREFIX/lib64 -lcrypto
 *     openssl list -providers                 # confirm fips is there at all
 *     SPIKE_PROVIDER=fips /tmp/spike
 *
 * Reading the result:
 *   - counts that track key size  -> the FIPS provider accepts it; the fix is
 *                                    reachable in fips-strict.
 *   - "would not load"            -> no FIPS provider on that machine; the
 *                                    question is still open, not answered no.
 *   - loads but keygen FAILs, or  -> the FIPS provider insists on its own
 *     counts stay at zero            DRBG. Then say so rather than work
 *                                    around it: docs/FIPS_140_3_SECURITY_
 *                                    TARGET.md delegates to that provider on
 *                                    purpose, and overriding its RAND would
 *                                    be undoing the delegation.
 * ========================================================================= */
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static unsigned long long g_drawn = 0;   /* stands in for fhsm_drbg's counter */

/* --- the RAND algorithm ------------------------------------------------- */
struct rctx { int dummy; };

static void *r_newctx(void *provctx, void *parent, const OSSL_DISPATCH *pd)
{ (void)provctx; (void)parent; (void)pd; return calloc(1, sizeof(struct rctx)); }
static void  r_freectx(void *ctx) { free(ctx); }
static int   r_instantiate(void *ctx, unsigned int s, int pr,
                            const unsigned char *pstr, size_t plen,
                            const OSSL_PARAM p[])
{ (void)ctx;(void)s;(void)pr;(void)pstr;(void)plen;(void)p; return 1; }
static int   r_uninstantiate(void *ctx) { (void)ctx; return 1; }
static int   r_generate(void *ctx, unsigned char *out, size_t outlen,
                         unsigned int strength, int pr,
                         const unsigned char *adin, size_t adlen)
{
    (void)ctx;(void)strength;(void)pr;(void)adin;(void)adlen;
    /* Real bytes now: a deterministic ramp is rejected by RSA prime
     * generation, which is the module's own health check working. In the
     * real thing this is fhsm_drbg_bytes(). */
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(out, 1, outlen, f) != outlen) { if (f) fclose(f); return 0; }
    fclose(f);
    g_drawn += outlen;
    return 1;
}
static int r_enable_locking(void *ctx) { (void)ctx; return 1; }
static int r_lock(void *ctx)   { (void)ctx; return 1; }
static void r_unlock(void *ctx){ (void)ctx; }
static const OSSL_PARAM *r_gettable(void *ctx, void *provctx)
{
    (void)ctx; (void)provctx;
    static const OSSL_PARAM t[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };
    return t;
}
static int r_get_params(void *ctx, OSSL_PARAM params[])
{
    (void)ctx;
    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE)))
        if (!OSSL_PARAM_set_int(p, EVP_RAND_STATE_READY)) return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH)))
        if (!OSSL_PARAM_set_uint(p, 256)) return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST)))
        if (!OSSL_PARAM_set_size_t(p, 1 << 20)) return 0;
    return 1;
}

static const OSSL_DISPATCH rand_fns[] = {
    { OSSL_FUNC_RAND_NEWCTX,        (void (*)(void))r_newctx },
    { OSSL_FUNC_RAND_FREECTX,       (void (*)(void))r_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE,   (void (*)(void))r_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))r_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE,      (void (*)(void))r_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,(void (*)(void))r_enable_locking },
    { OSSL_FUNC_RAND_LOCK,          (void (*)(void))r_lock },
    { OSSL_FUNC_RAND_UNLOCK,        (void (*)(void))r_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))r_gettable },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,(void (*)(void))r_get_params },
    { 0, NULL }
};
static const OSSL_ALGORITHM rands[] = {
    { "FHSM-DRBG", "provider=fhsm", rand_fns, "the module's DRBG" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM *p_query(void *provctx, int op, int *nocache)
{ (void)provctx; *nocache = 0; return op == OSSL_OP_RAND ? rands : NULL; }
static void p_teardown(void *provctx) { (void)provctx; }
static const OSSL_DISPATCH prov_fns[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))p_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN,        (void (*)(void))p_teardown },
    { 0, NULL }
};
static int prov_init(const OSSL_CORE_HANDLE *h, const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out, void **provctx)
{ (void)h; (void)in; *out = prov_fns; *provctx = NULL; return 1; }

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    if (!ctx) { puts("  OSSL_LIB_CTX_new failed"); return 2; }
    if (!OSSL_PROVIDER_add_builtin(ctx, "fhsm", prov_init)) {
        puts("  add_builtin failed"); return 2; }
    if (!OSSL_PROVIDER_load(ctx, "fhsm")) { puts("  provider load failed"); return 2; }
    const char *want = getenv("SPIKE_PROVIDER");
    if (!want) want = "default";
    if (!OSSL_PROVIDER_load(ctx, want)) {
        printf("  provider \"%s\" would not load\n", want); return 2; }
    printf("  provider under test: %s\n", want);
    if (!RAND_set_DRBG_type(ctx, "FHSM-DRBG", NULL, NULL, NULL)) {
        puts("  RAND_set_DRBG_type refused the provider RAND"); return 3; }

    struct { const char *name; const char *alg; size_t bits; } t[] = {
        { "RSA-2048",  "RSA", 2048 }, { "RSA-4096",  "RSA", 4096 },
        { "EC P-256",  "EC",  0 },    { "ML-DSA-65", NULL,  0 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        unsigned long long before = g_drawn;
        EVP_PKEY *k = NULL;
        if (t[i].alg && strcmp(t[i].alg, "RSA") == 0)
            k = EVP_PKEY_Q_keygen(ctx, NULL, "RSA", t[i].bits);
        else if (t[i].alg && strcmp(t[i].alg, "EC") == 0)
            k = EVP_PKEY_Q_keygen(ctx, NULL, "EC", "P-256");
        else
            k = EVP_PKEY_Q_keygen(ctx, NULL, "ML-DSA-65");
        printf("  %-10s %s   provider RAND bytes: %llu\n",
               t[i].name, k ? "ok  " : "FAIL", g_drawn - before);
        EVP_PKEY_free(k);
    }
    OSSL_LIB_CTX_free(ctx);
    return 0;
}
