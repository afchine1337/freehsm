/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_secure_heap_shared --- two copies of the module in one process.
 *
 *  The secure heap is libcrypto's, one per process. Until 2026-10-02 a second
 *  copy of the module -- another build loaded beside the first, as fhsm-gui
 *  does when it switches modules, or two FreeHSM modules under one p11-kit
 *  proxy -- failed its C_Initialize: CRYPTO_secure_malloc_init returns 0 when
 *  the arena already exists, and the module read that as "could not allocate
 *  it at all". src/fhsm_memory.c now adopts the existing arena once the kernel
 *  confirms it is locked.
 *
 *  Run with two paths to byte-identical copies of the module: different files,
 *  so the dynamic loader maps two instances with their own state, as it would
 *  two different builds. The checks:
 *    1. both C_Initialize return CKR_OK;
 *    2. the second locks nothing more (VmLck does not move): it adopted the
 *       arena rather than making a second one;
 *    3. both copies answer C_GetSlotList, so each is actually running.
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long ck_rv_t;
typedef ck_rv_t (*c_initialize_fn)(void *);
typedef ck_rv_t (*c_finalize_fn)(void *);
typedef ck_rv_t (*c_get_slot_list_fn)(unsigned char, unsigned long *, unsigned long *);

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static long vmlck_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "VmLck:", 6) == 0) { kb = strtol(line + 6, NULL, 10); break; }
    }
    fclose(f);
    return kb;
}

struct mod {
    void *h;
    c_initialize_fn init;
    c_finalize_fn fini;
    c_get_slot_list_fn slots;
};

static int open_mod(const char *path, struct mod *m) {
    m->h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!m->h) { fprintf(stderr, "dlopen %s: %s\n", path, dlerror()); return -1; }
    /* The pointer-to-pointer detour: -Wpedantic forbids the direct cast. */
    *(void **)&m->init  = dlsym(m->h, "C_Initialize");
    *(void **)&m->fini  = dlsym(m->h, "C_Finalize");
    *(void **)&m->slots = dlsym(m->h, "C_GetSlotList");
    if (!m->init || !m->fini || !m->slots) {
        fprintf(stderr, "%s: missing C_Initialize, C_Finalize or C_GetSlotList\n", path);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s MODULE COPY-OF-MODULE\n", argv[0]);
        return 2;
    }
    printf("two copies of the module in one process\n\n");

    struct mod a, b;
    if (open_mod(argv[1], &a) || open_mod(argv[2], &b)) return 2;
    ok(a.h != b.h, "the loader mapped two instances, not one");

    ck_rv_t ra = a.init(NULL);
    long after_a = vmlck_kb();
    ck_rv_t rb = b.init(NULL);
    long after_b = vmlck_kb();
    printf("  (VmLck: %ld kB after the first, %ld kB after the second)\n", after_a, after_b);

    ok(ra == 0, "the first copy initialises");
    ok(rb == 0, "the second copy initialises, on the arena the first made");
    ok(after_a >= 0 && after_b == after_a, "  and locks nothing more: one arena, adopted");

    unsigned long na = 0, nb = 0;
    ok(ra == 0 && a.slots(0, NULL, &na) == 0 && na > 0, "the first copy lists its slots");
    ok(rb == 0 && b.slots(0, NULL, &nb) == 0 && nb > 0, "the second copy lists its slots");

    if (rb == 0) b.fini(NULL);
    if (ra == 0) a.fini(NULL);

    if (fails) { fprintf(stderr, "test_secure_heap_shared : %d FAIL\n", fails); return 1; }
    printf("test_secure_heap_shared : PASS\n");
    return 0;
}
