/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_secure_heap.c --- sensitive values live in the mlock'd arena (#127).
 *
 *  Three claims, each of which would otherwise be a comment nobody checks:
 *    1. a sensitive object's value is allocated in the secure heap;
 *    2. a non-sensitive one is not (certificates must not eat the arena);
 *    3. exhausting the arena returns CKR_DEVICE_MEMORY and never falls back
 *       to pageable memory.
 *
 *  (3) is the one that matters. A silent fallback would be a guarantee that
 *  holds until it quietly does not.
 * ========================================================================= */
#include "fhsm_token.h"
#include "fhsm_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails = 0;
static void ck(const char *what, int ok, const char *detail) {
    printf("  %-52s %s%s%s\n", what, ok ? "OK" : "<<< FAIL",
           detail && *detail ? "  " : "", detail ? detail : "");
    if (!ok) fails++;
}

int main(int argc, char **argv) {
    /* Second pass: re-exec ourselves against a deliberately tiny arena so the
     * exhaustion path is actually exercised. With the default 2 MiB the object
     * cap (FHSM_MAX_OBJECTS) binds first, so the first pass alone never proves
     * the branch this ticket is about. #128 made secure_heap_kb real, which is
     * what makes this test possible at all. */
    int tiny = (argc > 1 && strcmp(argv[1], "--tiny") == 0);
    if (!tiny) {
        FILE *cf = fopen("/tmp/fhsm_sh_tiny.conf", "w");
        if (cf) { fputs("secure_heap_kb = 64\n", cf); fclose(cf); }
    }

    char dir[] = "/tmp/fhsm_sh_XXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
    char path[512]; snprintf(path, sizeof(path), "%s/t.tok", dir);

    fhsm_token_t *t = NULL;
    if (fhsm_token_init(path, "87654321", "shtest", &t) != FHSM_RV_OK) {
        fprintf(stderr, "token_init failed\n"); return 2;
    }
    fhsm_rv_t lr;
    if ((lr = fhsm_token_login(t, FHSM_ROLE_SO, "87654321")) != FHSM_RV_OK) {
        fprintf(stderr, "SO login failed 0x%x\n", (unsigned)lr); return 2; }
    if ((lr = fhsm_token_init_user_pin(t, "12345678")) != FHSM_RV_OK) {
        fprintf(stderr, "init_user_pin failed 0x%x\n", (unsigned)lr); return 2; }
    if ((lr = fhsm_token_login(t, FHSM_ROLE_USER, "12345678")) != FHSM_RV_OK) {
        fprintf(stderr, "USER login failed 0x%x\n", (unsigned)lr); return 2; }

    static uint8_t payload[4096];
    memset(payload, 0xA5, sizeof(payload));

    /* 1. sensitive value -> arena usage grows by at least its size */
    size_t before = fhsm_secure_heap_used();
    uint32_t h1 = 0;
    fhsm_rv_t rv = fhsm_token_object_add(t, 4 /*CKO_SECRET_KEY*/, 0x1f,
                                             "sensitive", payload, sizeof(payload),
                                             NULL, 0, FHSM_OBJF_SENSITIVE, &h1);
    size_t after_sens = fhsm_secure_heap_used();
    char d[96];
    snprintf(d, sizeof d, "(+%zu o)", after_sens - before);
    ck("sensitive value allocated in the secure heap",
       rv == FHSM_RV_OK && after_sens >= before + sizeof(payload), d);

    /* 2. non-sensitive value -> arena usage does not grow by its size */
    size_t before_ns = fhsm_secure_heap_used();
    uint32_t h2 = 0;
    rv = fhsm_token_object_add(t, 1 /*CKO_CERTIFICATE*/, 0,
                                   "public", payload, sizeof(payload),
                                   NULL, 0, FHSM_OBJF_EXTRACTABLE, &h2);
    size_t after_ns = fhsm_secure_heap_used();
    snprintf(d, sizeof d, "(+%zu o)", after_ns - before_ns);
    ck("non-sensitive value stays out of the arena",
       rv == FHSM_RV_OK && (after_ns - before_ns) < sizeof(payload), d);

    /* 3. exhaustion is a hard failure, not a quiet downgrade. Fill the arena
     *    with sensitive objects until it refuses. */
    int made = 0; fhsm_rv_t last = FHSM_RV_OK;
    for (int i = 0; i < (int)FHSM_MAX_OBJECTS; ++i) {
        uint32_t hh = 0;
        char nm[32]; snprintf(nm, sizeof nm, "fill%03d", i);
        last = fhsm_token_object_add(t, 4, 0x1f, nm, payload, sizeof(payload),
                                         NULL, 0, FHSM_OBJF_SENSITIVE, &hh);
        if (last != FHSM_RV_OK) break;
        made++;
    }
    snprintf(d, sizeof d, "(%d objets, rv=0x%x, arene %zu/%zu o)",
             made, (unsigned)last, fhsm_secure_heap_used(), fhsm_secure_heap_total());
    if (tiny) {
        /* Small arena: the ceiling must be the arena, and it must say so. */
        ck("tiny arena exhaustion -> DEVICE_MEMORY", last == FHSM_RV_DEVICE_MEMORY, d);
        ck("tiny arena: refused before the object cap",
           made < (int)FHSM_MAX_OBJECTS - 2, "");
    } else {
        /* Default arena: the object cap binds first, which is the point of
         * sizing it at 2 MiB. Either ceiling is acceptable, silence is not. */
        ck("default arena: a ceiling is reported, not a silent downgrade",
           last != FHSM_RV_OK, d);
    }

    fhsm_token_close(t);
    remove(path); rmdir(dir);
    if (!tiny && fails == 0) {
        printf("  -- seconde passe, arene 64 KiB --\n");
        fflush(stdout);   /* execl remplace le processus : sinon la 1re passe est perdue */
        setenv("FHSM_CONF", "/tmp/fhsm_sh_tiny.conf", 1);
        execl(argv[0], argv[0], "--tiny", (char*)NULL);
        perror("execl");   /* si l'exec echoue, c'est un echec de test */
        return 2;
    }
    remove("/tmp/fhsm_sh_tiny.conf");
    printf("\ntest_secure_heap : %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
