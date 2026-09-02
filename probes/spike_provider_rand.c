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
 * WHAT IT ANSWERED, AGAINST THE FIPS PROVIDER (2026-09-01, Debian 13,
 * OpenSSL 3.5.6, fips provider active)
 * ---------------------------------------------------------------------
 *     control  RAND_bytes_ex(ctx): rc=1, drew 0 byte(s)
 *     r_generate entered 0 time(s), r_instantiate 0
 *     direct   EVP_RAND_generate: rc=1, entered 1 more time
 *     RSA-2048 / RSA-4096 / EC P-256 / ML-DSA-65 : 0 bytes each
 *
 * Read together: the DRBG is live and callable -- a direct generate on the
 * public RAND enters it and succeeds -- and neither RAND_bytes_ex nor key
 * generation reaches it while the FIPS provider is loaded. Under "default",
 * on the same code, both do.
 *
 *   So: a private OSSL_LIB_CTX with RAND_set_DRBG_type does NOT make FIPS
 *   key generation draw from the module's DRBG. That is measured.
 *
 *   WHY it diverges is not established, and this spike stops here rather than
 *   grow a sixth counter. It does not matter for the design decision -- the
 *   approach does not deliver the property either way -- and it does matter
 *   for what may be claimed, so nothing is claimed about the FIPS provider's
 *   internals.
 *
 * The conclusion drawn from it is in docs/ROADMAP.md: FIPS 140-3 puts the
 * DRBG inside the validated boundary, and per docs/FIPS_140_3_SECURITY_
 * TARGET.md the validated module here IS the OpenSSL FIPS provider. Keys it
 * generates coming from its own approved DRBG is the delegation working, not
 * a gap in it. Overriding that RAND would undo what #173 measured this
 * morning.
 *
 * FOUR THINGS THIS SPIKE GOT WRONG BEFORE IT GOT ANYTHING RIGHT
 * ------------------------------------------------------------
 * Recorded because each produced a confident wrong reading, and the shape is
 * the same every time: a measurement that cannot distinguish two situations
 * being used to choose between them.
 *
 *   1. OSSL_LIB_CTX_new() reads no configuration, so "fips" could not load at
 *      all on a host where it was properly installed. Reported as `provider
 *      "fips" would not load`, whose documented reading was "the question is
 *      still open". Fixed with OSSL_LIB_CTX_load_config, and the error stack
 *      is now printed instead of a bare verdict.
 *   2. A byte counter incremented only on success cannot separate "never
 *      called" from "called and refused". g_calls counts at entry.
 *   3. Naming the RAND via EVP_RAND_get0_provider reports the algorithm the
 *      context was fetched with, not a live instance: all three read
 *      "FHSM-DRBG from fhsm" while r_instantiate had been entered zero times.
 *      True, and the reading taken from it was not.
 *   4. The verdict line meant to stop misreadings contained one: it compared
 *      g_drawn against a mark taken before RAND_bytes_ex, by which point the
 *      direct call had also moved it, so it announced that RAND_bytes_ex had
 *      used our DRBG on a run whose control drew zero.
 *
 * TO RE-RUN, on a machine whose OpenSSL has the FIPS provider:
 *
 *     cc -Wall -std=c11 -o /tmp/spike probes/spike_provider_rand.c -lcrypto
 *     openssl list -providers                 # confirm fips is there at all
 *     SPIKE_PROVIDER=fips /tmp/spike
 *     SPIKE_PROVIDER=fips SPIKE_NO_FIPS_PROPS=1 /tmp/spike
 *
 * The second clears the fips default property, in case a host sets
 * `default_properties = fips=yes` and makes FHSM-DRBG unfetchable. On the
 * host above it changed nothing: the property was already fips=no.
 * ========================================================================= */
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static unsigned long long g_drawn = 0;   /* stands in for fhsm_drbg's counter */
static unsigned long long g_calls = 0;   /* entries into r_generate, success or not */
static size_t             g_last_req = 0;
static unsigned long long g_inst  = 0;   /* entries into r_instantiate */

/* --- the RAND algorithm ------------------------------------------------- */
struct rctx { int dummy; };

static void *r_newctx(void *provctx, void *parent, const OSSL_DISPATCH *pd)
{ (void)provctx; (void)parent; (void)pd; return calloc(1, sizeof(struct rctx)); }
static void  r_freectx(void *ctx) { free(ctx); }
static int   r_instantiate(void *ctx, unsigned int s, int pr,
                            const unsigned char *pstr, size_t plen,
                            const OSSL_PARAM p[])
{ (void)ctx;(void)s;(void)pr;(void)pstr;(void)plen;(void)p; g_inst++; return 1; }
static int   r_uninstantiate(void *ctx) { (void)ctx; return 1; }
static int   r_generate(void *ctx, unsigned char *out, size_t outlen,
                         unsigned int strength, int pr,
                         const unsigned char *adin, size_t adlen)
{
    (void)ctx;(void)strength;(void)pr;(void)adin;(void)adlen;
    /* Counted at entry, before anything can fail. g_drawn only moves on
     * success, so "0 bytes" conflated "never called" with "called and
     * refused" -- two situations with opposite meanings, and the run against
     * the FIPS provider is sitting exactly on that ambiguity: our DRBG is
     * reported installed as primary, public and private, RAND_bytes_ex
     * returns 1, and not a byte is counted. */
    g_calls++;
    g_last_req = outlen;
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

/* Name the RAND instead of inferring it from a counter.
 *
 * Three runs were spent reading "0 bytes drawn" as evidence about the FIPS
 * provider. It was evidence that something else served the request, and a
 * counter cannot say what. This asks the library which implementation is
 * installed and which provider supplies it, which is the question that was
 * actually being guessed at. */
static void say_rand(const char *which, EVP_RAND_CTX *r)
{
    if (!r) { printf("  %-8s (none)\n", which); return; }
    EVP_RAND *alg = EVP_RAND_CTX_get0_rand(r);
    const OSSL_PROVIDER *p = alg ? EVP_RAND_get0_provider(alg) : NULL;
    printf("  %-8s %s from provider \"%s\"\n", which,
           alg ? EVP_RAND_get0_name(alg) : "?",
           p ? OSSL_PROVIDER_get0_name(p) : "?");
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    if (!ctx) { puts("  OSSL_LIB_CTX_new failed"); return 2; }

    /* A context from OSSL_LIB_CTX_new() has read no configuration. That is
     * fine for "default", which needs none, and fatal for "fips", which needs
     * fipsmodule.cnf to supply the install-status MAC its self-test checks --
     * so OSSL_PROVIDER_load(ctx, "fips") fails on a machine where the
     * provider is perfectly well installed. The first run of this spike said
     * `provider "fips" would not load` on exactly such a machine, and the
     * header below reads that as "the question is still open". It was not
     * open; it was this line missing. Load the default config into the
     * private context first. */
    if (!OSSL_LIB_CTX_load_config(ctx, NULL)) {
        puts("  could not load the OpenSSL configuration into the private context");
        ERR_print_errors_fp(stderr);
        return 2;
    }

    if (!OSSL_PROVIDER_add_builtin(ctx, "fhsm", prov_init)) {
        puts("  add_builtin failed"); ERR_print_errors_fp(stderr); return 2; }
    if (!OSSL_PROVIDER_load(ctx, "fhsm")) {
        puts("  provider load failed"); ERR_print_errors_fp(stderr); return 2; }
    const char *want = getenv("SPIKE_PROVIDER");
    if (!want) want = "default";
    if (!OSSL_PROVIDER_load(ctx, want)) {
        /* Print the stack, not just the verdict. A bare "would not load"
         * cost a round trip and an almost-wrong conclusion. */
        printf("  provider \"%s\" would not load\n", want);
        ERR_print_errors_fp(stderr);
        return 2; }
    printf("  provider under test: %s\n", want);
    /* The default property query decides which providers a fetch can reach,
     * and loading the configuration above is what sets it. A distribution
     * that activates FIPS does so with `default_properties = fips=yes` in
     * openssl.cnf, and under that query "FHSM-DRBG" -- served by a provider
     * that advertises no such property -- is unfetchable. RAND_set_DRBG_type
     * still returns 1, the primary DRBG is still instantiated, and it is the
     * FIPS provider's. Every count then reads 0, which looks exactly like
     * "the FIPS provider ignores an external RAND" and is not that at all.
     *
     * So say what the query is, and offer to clear it. Two runs answer two
     * different questions:
     *
     *   as configured  -- what this module would get in this deployment
     *   props cleared  -- whether the FIPS provider itself refuses our RAND
     *
     * Only the second bears on the design question. The first bears on
     * whether the design would survive contact with a FIPS-activated host,
     * which is a separate and equally real thing to know. */
    printf("  default properties: fips=%s%s\n",
           EVP_default_properties_is_fips_enabled(ctx) ? "yes" : "no",
           getenv("SPIKE_NO_FIPS_PROPS") ? " (clearing it, as asked)" : "");
    if (getenv("SPIKE_NO_FIPS_PROPS")) {
        if (!EVP_default_properties_enable_fips(ctx, 0)) {
            puts("  could not clear the fips default property");
            ERR_print_errors_fp(stderr); return 2;
        }
    }

    if (!RAND_set_DRBG_type(ctx, "FHSM-DRBG", NULL, NULL, NULL)) {
        puts("  RAND_set_DRBG_type refused the provider RAND");
        ERR_print_errors_fp(stderr); return 3; }

    /* The control, without which a row of zeros below says nothing.
     *
     * Against the FIPS provider every keygen drew 0 bytes from this RAND, and
     * that has two readings: our RAND is the context's and keygen does not
     * use it, or our RAND was never installed and the run says nothing about
     * FIPS at all. Draw from the context directly. If this moves, the RAND is
     * installed and reachable, and a zero in the table is a fact about the
     * provider. If this is also zero, the zeros are a fact about this spike
     * and must not be read as a finding.
     *
     * The absence had to be made to mean something before it could be
     * evidence. */
    {
        unsigned char probe[32];
        unsigned long long before = g_drawn;
        unsigned long long calls0 = g_calls;
        int rc = RAND_bytes_ex(ctx, probe, sizeof probe, 0);
        unsigned long long ctl_calls = g_calls - calls0;
        printf("  control  RAND_bytes_ex(ctx): rc=%d, drew %llu byte(s)%s\n",
               rc, g_drawn - before,
               (g_drawn == before) ? "  <-- our RAND is NOT the context's"
                                   : "  <-- our RAND is installed");
        if (rc <= 0) ERR_print_errors_fp(stderr);

        printf("  r_generate entered %llu time(s), r_instantiate %llu, "
               "last request %zu byte(s)\n", g_calls, g_inst, g_last_req);

        /* And who did serve it. Careful with this: it names the algorithm the
         * EVP_RAND_CTX was fetched with, which is not the same as saying the
         * context is live. Against the FIPS provider all three read
         * "FHSM-DRBG from fhsm" while r_instantiate had been entered zero
         * times -- the line was true and the reading taken from it was not. */
        EVP_RAND_CTX *pub = RAND_get0_public(ctx);
        say_rand("primary", RAND_get0_primary(ctx));
        say_rand("public",  pub);
        say_rand("private", RAND_get0_private(ctx));

        /* The discriminating step, and the last one this spike gets.
         *
         * Go straight at the public DRBG rather than through RAND_bytes_ex.
         * Two outcomes, two different things to write down:
         *
         *   r_generate fires  -> our DRBG is live and usable, and
         *                        RAND_bytes_ex reached something else. The
         *                        finding is about how that call is routed
         *                        when the FIPS provider is loaded.
         *   it does not       -> our provider is not really wired in this
         *                        configuration. The finding is about this
         *                        spike, and says nothing about FIPS.
         *
         * State is printed alongside, because an uninstantiated context
         * explains a refusal without any of the above being true. */
        if (pub) {
            unsigned char direct[32];
            unsigned long long c0 = g_calls;
            int st = EVP_RAND_get_state(pub);
            int drc = EVP_RAND_generate(pub, direct, sizeof direct, 0, 0, NULL, 0);
            /* The verdict needs BOTH facts, and the first draft of this line
             * used only one: it printed "RAND_bytes_ex went elsewhere"
             * whenever the direct call fired, which is also what happens in
             * the control run where RAND_bytes_ex went straight through us.
             * A conclusion that fires in the case it is meant to exclude is
             * not a conclusion. `ours_live` is this call; `ctl_used_ours` is
             * whether the earlier one reached us. */
            int ours_live    = (g_calls > c0);
            /* `before` was taken before RAND_bytes_ex, and by this point
             * g_drawn has also been moved by the direct call five lines up.
             * Comparing against it therefore reports "the control used ours"
             * whenever the DIRECT call worked -- which is how this line came
             * to print "RAND_bytes_ex used it" on a run whose control drew
             * zero. One variable, two measurements, and the verdict written
             * to stop misreadings produced one. Use the control's own
             * observation instead: r_generate was entered c0 times by the
             * end of it, and the count printed above is the record. */
            int ctl_used_ours = (ctl_calls > 0);
            const char *verdict =
                  (ours_live &&  ctl_used_ours) ? "  <-- ours is live and RAND_bytes_ex used it"
                : (ours_live && !ctl_used_ours) ? "  <-- ours is live; RAND_bytes_ex went elsewhere"
                : (!ours_live && ctl_used_ours) ? "  <-- contradictory; do not conclude from this run"
                :                                 "  <-- ours is not wired here";
            printf("  direct   EVP_RAND_generate: rc=%d, state=%s, "
                   "r_generate entered %llu more time(s)%s\n",
                   drc,
                   st == EVP_RAND_STATE_READY      ? "READY"
                     : st == EVP_RAND_STATE_UNINITIALISED ? "UNINITIALISED"
                     : st == EVP_RAND_STATE_ERROR  ? "ERROR" : "?",
                   g_calls - c0, verdict);
            if (drc <= 0) ERR_print_errors_fp(stderr);
        }
    }

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
