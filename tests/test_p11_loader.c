/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * The tools' module loader, and the ordering it depends on.
 *
 * PKCS#11 requires exactly one exported symbol, `C_GetFunctionList`. Everything
 * else is reached through the table it returns, whose field order is fixed by
 * v2.40 §C.6. Most modules export nothing else: p11-kit-client.so exports one
 * symbol, SoftHSM and smart-card drivers are the same.
 *
 * `load_module` used to dlsym each C_* by name and exit if one was missing, so
 * the four tools could drive our module and nothing else -- while the Makefile
 * claimed they "drive any module implementing the mechanism". They now read the
 * table.
 *
 * Which means the tools carry a second copy of the slot ordering, and a wrong
 * index calls the wrong function with no diagnostic at all. #61 was exactly
 * that: C_CancelFunction missing from the module's own table, shifting
 * everything after it.
 *
 * So this test compares the two: for every function the tools pull out of the
 * table, the pointer must equal the one `dlsym` returns for the same name from
 * the same module. A second copy of an ordering is safe only while something
 * compares them, and this is that something.
 */
#include "p11_util.h"

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-58s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

int main(int argc, char **argv)
{
    const char *mod = (argc > 1) ? argv[1] : "./libfreehsm.so";
    p11_progname = "test_p11_loader";

    printf("PKCS#11 module loader\n\n");

    /* The loader exits on failure, so reaching the next line is the first
     * assertion: our own module loads through C_GetFunctionList. */
    load_module(mod);
    ok(1, "the module loads through C_GetFunctionList");

    /* Now the ordering. dlsym gives the truth for a module that exports its
     * symbols; the table gives what the tools will actually call. */
    void *h = dlopen(mod, RTLD_NOW);
    if (!h) { printf("  cannot reopen %s\n", mod); return 2; }

    int checked = 0, missing = 0;
    #define SAME(f) do {                                                      \
        void *direct = dlsym(h, "C_" #f);                                     \
        if (!direct) { missing++; break; }                                    \
        checked++;                                                            \
        char msg[96];                                                         \
        snprintf(msg, sizeof msg, "  table slot for C_%s is C_%s", #f, #f);   \
        /* memcpy, not a cast: ISO C forbids converting a function pointer    \
         * to void*, and this file is built with -Wpedantic -Werror. */       \
        void *ours; memcpy(&ours, &p11.f, sizeof ours);                       \
        ok(direct == ours, msg);                                              \
    } while (0)

    SAME(Initialize);       SAME(Finalize);
    SAME(OpenSession);      SAME(CloseSession);
    SAME(Login);            SAME(GenerateKeyPair);
    SAME(FindObjectsInit);  SAME(FindObjects);   SAME(FindObjectsFinal);
    SAME(GetAttributeValue);
    SAME(SignInit);         SAME(Sign);
    SAME(SignUpdate);       SAME(SignFinal);
    SAME(VerifyInit);       SAME(VerifyUpdate);  SAME(VerifyFinal);
    SAME(InitToken);        SAME(InitPIN);
    SAME(GetTokenInfo);     SAME(GenerateRandom);
    SAME(GetSlotList);
    #undef SAME

    printf("\n  %d slots compared against dlsym", checked);
    if (missing) printf(", %d not exported directly (skipped)", missing);
    printf("\n");

    /* A module that exports its symbols is the only case where this comparison
     * is possible at all. If ours ever stops exporting them, the check goes
     * quiet rather than failing -- so say so instead of scoring it as a pass. */
    ok(checked >= 21, "  enough slots were comparable for the check to mean something");

    dlclose(h);
    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
