/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_pkiops.c --- tools/pkiops without a window.
 *
 *  docs/fhsm-gui-plan.md stage 1 needs three things from pkiops the
 *  command-line tools never did: the slots to choose from, the keys a session
 *  sees, and a log of every PKCS#11 call for the exploration interface. This
 *  drives them against the module, so the interface is the only untested
 *  layer, and a thin one.
 *
 *  The check that matters most is the log's: it logs in with distinctive PINs
 *  and fails if either appears in any record. A call log that showed the PIN
 *  would be the one feature of the interface worse than not having it.
 *
 *  The composite key pair exists only in all-mechanisms builds; in the
 *  default profile that part reports itself skipped rather than failing.
 * ========================================================================= */
#include "pkiops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

#define SO_PIN   "So-Pin-4711"
#define USER_PIN "Us-Pin-8a2Q"
#define BAD_PIN  "Bad-Pin-x9"

/* Every record, kept as "C_Name args" so it can be searched. */
static char   g_rec[512][200];
static size_t g_n;
static int    g_negative_ms;

static void collect(const struct pkiops_call *c, void *ctx) {
    (void)ctx;
    if (c->ms < 0) g_negative_ms = 1;
    if (g_n < sizeof g_rec / sizeof g_rec[0])
        snprintf(g_rec[g_n++], sizeof g_rec[0], "%s %s", c->fn, c->args);
}

static int logged(const char *fn) {
    for (size_t i = 0; i < g_n; i++) if (!strncmp(g_rec[i], fn, strlen(fn))) return 1;
    return 0;
}

static int log_contains(const char *needle) {
    for (size_t i = 0; i < g_n; i++) if (strstr(g_rec[i], needle)) return 1;
    return 0;
}

int main(void) {
    struct p11_err e;
    printf("tools/pkiops without a window\n\n");

    pkiops_set_call_log(collect, NULL);
    if (pkiops_load("./libfreehsm.so", &e)) { fprintf(stderr, "load: %s", e.msg); return 2; }
    ok(logged("C_Initialize"), "a log set before loading records C_Initialize");

    struct pkiops_slot *sl = NULL; size_t ns = 0;
    ok(pkiops_slots(&sl, &ns, &e) == 0 && ns > 0, "pkiops_slots lists the module's slots");
    int any_token = 0;
    for (size_t i = 0; i < ns; i++) any_token |= sl[i].has_token;
    ok(!any_token, "  and on a fresh tokens directory none holds a token");
    pkiops_handle slot = ns ? sl[0].id : 0;
    free(sl);

    ok(pkiops_token_init(slot, (const uint8_t *)SO_PIN, strlen(SO_PIN),
                         (const uint8_t *)USER_PIN, strlen(USER_PIN), "pkiops", &e) == 0,
       "pkiops_token_init initialises the first slot");
    sl = NULL; ns = 0;
    ok(pkiops_slots(&sl, &ns, &e) == 0 && ns > 0 && sl[0].has_token
       && !strcmp(sl[0].label, "pkiops"),
       "  and pkiops_slots then reports it, under its label");
    free(sl);

    pkiops_handle s = 0;
    ok(pkiops_session_user(slot, (const uint8_t *)USER_PIN, strlen(USER_PIN), &s, &e) == 0,
       "pkiops_session_user logs in");

    struct pkiops_key *k = NULL; size_t nk = 0;
    ok(pkiops_keys(s, &k, &nk, &e) == 0 && nk == 0, "pkiops_keys finds nothing on a new token");
    free(k);

    pkiops_handle hp = 0, hk = 0;
    int kg = pkiops_keygen(s, "pk-test", &hp, &hk, &e);
    if (kg && strstr(e.msg, "0x70")) {
        printf("  %-66s %s\n", "composite key pair (all-mechanisms only)", "skipped");
    } else {
        ok(kg == 0, "pkiops_keygen makes a composite key pair");
        k = NULL; nk = 0;
        int pub = 0, priv = 0, named = 1;
        ok(pkiops_keys(s, &k, &nk, &e) == 0 && nk == 2, "  and pkiops_keys then finds two objects");
        for (size_t i = 0; i < nk; i++) {
            if (k[i].is_private) priv++; else pub++;
            if (strcmp(k[i].label, "pk-test")) named = 0;
        }
        ok(pub == 1 && priv == 1 && named, "  one public, one private, both under the label given");
        free(k);
        /* Only here: with no key on the token nothing reads an attribute,
         * and the first version of this test asserted it unconditionally --
         * it failed in the default profile, where the keygen is skipped. */
        ok(logged("C_GetAttributeValue") && log_contains("values not shown"),
           "attribute reads are logged by type, values not shown");
    }

    ok(logged("C_Login"), "the log records C_Login");
    ok(log_contains("PIN not shown"), "  and says the PIN is not shown");
    ok(!log_contains(USER_PIN) && !log_contains(SO_PIN),
       "  and neither PIN appears in any record");
    ok(!g_negative_ms, "every timing is non-negative");

    pkiops_session_close(s);

    /* Last, because a wrong PIN starts the module's throttle and would delay
     * every login after it. */
    pkiops_handle s2 = 0;
    int bad = pkiops_session_user(slot, (const uint8_t *)BAD_PIN, strlen(BAD_PIN), &s2, &e);
    ok(bad == 2 && strstr(e.msg, "C_Login failed") != NULL,
       "a wrong PIN is returned as an error, not an exit");
    ok(!log_contains(BAD_PIN), "  and is no more logged than the right one");

    pkiops_close();
    ok(logged("C_Finalize"), "pkiops_close finalises, and that is logged too");

    printf("\n%zu calls logged.\n", g_n);
    if (fails) { fprintf(stderr, "test_pkiops : %d FAIL\n", fails); return 1; }
    printf("test_pkiops : PASS\n");
    return 0;
}
