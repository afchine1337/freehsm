/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * probe_secure_heap --- is the secure heap actually locked in memory?
 *
 * WHAT THIS ANSWERS
 *
 * src/fhsm_memory.c asks OpenSSL for an mlock()-ed arena and treats a return
 * of 1 as success. Its own comment says more than the code does:
 *
 *     "if mlock fails (rlimit too low), OpenSSL falls back to a regular mmap
 *      arena and OPENSSL_secure_malloc_initialized() returns 1 but
 *      secure-allocations are *not* swap-excluded. We re-check the result and
 *      reject the init in strict mode."
 *
 * There is no re-check. The function is twenty lines and does not contain one.
 * So a fallback to unlocked memory is indistinguishable, from inside the
 * module, from the locked arena the Security Target claims -- and the default
 * arena is 8 MiB while the default RLIMIT_MEMLOCK under systemd is also 8 MiB,
 * which is the worst possible place for that boundary to sit.
 *
 * This measures it rather than reasoning about it. VmLck in /proc/self/status
 * is the kernel's count of locked bytes for this process. If the arena is
 * locked, initialising the module moves it by roughly the arena size. If it
 * does not move, the arena is ordinary swappable memory.
 *
 * dlopen rather than a static link: a statically linked probe would carry its
 * own zeroed .fhsm_digest and would have to run with the integrity bypass,
 * which is how the FIPS provider went four years without being observed.
 * ======================================================================== */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long ck_rv_t;
typedef ck_rv_t (*c_initialize_fn)(void *);

static long vmlck_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "VmLck:", 6) == 0) {
            kb = strtol(line + 6, NULL, 10);
            break;
        }
    }
    fclose(f);
    return kb;
}

int main(int argc, char **argv) {
    const char *mod = (argc > 1) ? argv[1] : "./libfreehsm.so";

    long before = vmlck_kb();
    if (before < 0) {
        fprintf(stderr, "probe_secure_heap: no VmLck in /proc/self/status "
                        "-- this probe only means anything on Linux\n");
        return 2;
    }

    void *h = dlopen(mod, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    /* -Wpedantic -Werror forbids casting an object pointer to a function
     * pointer directly; the pointer-to-pointer detour is the portable form. */
    c_initialize_fn c_init;
    *(void **)&c_init = dlsym(h, "C_Initialize");
    if (!c_init) { fprintf(stderr, "dlsym C_Initialize: %s\n", dlerror()); return 2; }

    ck_rv_t rv = c_init(NULL);
    long after = vmlck_kb();

    printf("module            : %s\n", mod);
    printf("C_Initialize      : 0x%lx\n", (unsigned long)rv);
    printf("VmLck before      : %ld kB\n", before);
    printf("VmLck after       : %ld kB\n", after);
    printf("locked by init    : %ld kB\n", after - before);

    if (rv != 0) {
        printf("VERDICT           : inconclusive -- C_Initialize failed, so the\n");
        printf("                    heap may never have been reached.\n");
        return 2;
    }

    /* The arena is 8 MiB by default and configurable via secure_heap_kb.
     * Rather than hard-code a threshold that would silently rot when the
     * default changes, report the number and judge only the qualitative
     * question: did ANY substantial locking happen? */
    if (after - before >= 1024) {
        printf("VERDICT           : the arena is locked (%ld kB). Key material is\n",
               after - before);
        printf("                    swap-excluded, as the Security Target claims.\n");
        return 0;
    }

    printf("VERDICT           : NOT LOCKED. CRYPTO_secure_malloc_init returned\n");
    printf("                    success and the kernel locked nothing, so the\n");
    printf("                    arena is ordinary swappable memory. Sensitive\n");
    printf("                    key material can reach disk.\n");
    printf("                    Check:  ulimit -l   (bytes: %s)\n",
           getenv("FHSM_SECURE_HEAP_HINT") ? getenv("FHSM_SECURE_HEAP_HINT")
                                           : "default 8 MiB");
    return 1;
}
