/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_concurrency.c --- concurrent PKCS#11 use (#111-prep).
 *
 *  PKCS#11's model is one process per application, so nothing in the module
 *  has ever needed a lock. A REST front end inverts that: one process serves
 *  N clients, and g_op_*, g_slots, g_finds and the session table become
 *  shared mutable state.
 *
 *  This test is written to FAIL under `make TSAN=1` before that state is
 *  locked. A concurrency test that passes on the first run has proved nothing
 *  -- it has to be able to see the races it exists to catch.
 *
 *  Threads deliberately overlap on the paths that share state:
 *    - each opens and closes its own session (the session table, g_finds)
 *    - each runs digest and encrypt operations (the per-session op slots)
 *    - each enumerates objects (the find state)
 *  all against the same slot and the same token.
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } A;
typedef struct { CK_ULONG m; void *p; CK_ULONG l; } M;

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_OpenSession)(CK_ULONG,CK_ULONG,void*,void*,CK_ULONG*);
static CK_RV (*C_CloseSession)(CK_ULONG);
static CK_RV (*C_Login)(CK_ULONG,CK_ULONG,unsigned char*,CK_ULONG);
static CK_RV (*C_InitToken)(CK_ULONG,unsigned char*,CK_ULONG,unsigned char*);
static CK_RV (*C_InitPIN)(CK_ULONG,unsigned char*,CK_ULONG);
static CK_RV (*C_Logout)(CK_ULONG);
static CK_RV (*C_GenerateKey)(CK_ULONG,M*,A*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_DigestInit)(CK_ULONG,M*);
static CK_RV (*C_Digest)(CK_ULONG,unsigned char*,CK_ULONG,unsigned char*,CK_ULONG*);
static CK_RV (*C_EncryptInit)(CK_ULONG,M*,CK_ULONG);
static CK_RV (*C_Encrypt)(CK_ULONG,unsigned char*,CK_ULONG,unsigned char*,CK_ULONG*);
static CK_RV (*C_FindObjectsInit)(CK_ULONG,A*,CK_ULONG);
static CK_RV (*C_FindObjects)(CK_ULONG,CK_ULONG*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_ULONG);

#define NTHREADS 8
#define NLOOPS   40

static CK_ULONG g_key;
static int      g_errors;
static pthread_mutex_t g_err_mu = PTHREAD_MUTEX_INITIALIZER;

static void note_error(const char *what, CK_RV rv) {
    pthread_mutex_lock(&g_err_mu);
    if (g_errors < 8) fprintf(stderr, "    %s -> 0x%lx\n", what, rv);
    g_errors++;
    pthread_mutex_unlock(&g_err_mu);
}

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < NLOOPS; ++i) {
        CK_ULONG s = 0;
        CK_RV rv = C_OpenSession(0, 6, NULL, NULL, &s);
        if (rv != 0) { note_error("C_OpenSession", rv); continue; }

        /* Per-session digest op slot. */
        M sha = { 0x250, NULL, 0 };           /* CKM_SHA256 */
        unsigned char in[64], out[64];
        memset(in, 0x5A, sizeof in);
        CK_ULONG ol = sizeof out;
        if ((rv = C_DigestInit(s, &sha)) != 0) note_error("C_DigestInit", rv);
        else if ((rv = C_Digest(s, in, sizeof in, out, &ol)) != 0)
            note_error("C_Digest", rv);

        /* Per-session encrypt op slot, shared key object. */
        unsigned char iv[16]; memset(iv, 0x11, sizeof iv);
        M cbc = { 0x1082, iv, sizeof iv };    /* CKM_AES_CBC */
        unsigned char ct[128]; CK_ULONG cl = sizeof ct;
        if ((rv = C_EncryptInit(s, &cbc, g_key)) != 0) note_error("C_EncryptInit", rv);
        else if ((rv = C_Encrypt(s, in, 32, ct, &cl)) != 0)
            note_error("C_Encrypt", rv);

        /* Find state. */
        CK_ULONG hs[32], n = 0;
        if ((rv = C_FindObjectsInit(s, NULL, 0)) != 0) note_error("C_FindObjectsInit", rv);
        else {
            if ((rv = C_FindObjects(s, hs, 32, &n)) != 0) note_error("C_FindObjects", rv);
            C_FindObjectsFinal(s);
        }
        C_CloseSession(s);
    }
    return NULL;
}

/* Cold-start worker: races on the very first slot access.
 *
 * The barrier matters. Without it, pthread_create's own latency lets the first
 * thread finish the lazy initialisation before the others are running, and the
 * window closes untouched -- TSan reports only races it actually observes, so
 * a race that never overlaps in time looks exactly like no race at all. That
 * is also why this bug would survive production for years and then appear
 * under load. */
static pthread_barrier_t g_start;

static void *cold_worker(void *arg) {
    (void)arg;
    pthread_barrier_wait(&g_start);
    CK_ULONG s = 0;
    CK_RV rv = C_OpenSession(0, 6, NULL, NULL, &s);
    if (rv == 0) C_CloseSession(s);
    return NULL;
}

int main(int argc, char **argv) {
    int cold = (argc > 1 && strcmp(argv[1], "--cold") == 0);
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "%s\n", dlerror()); return 2; }
#define SYM(x) *(void**)&x = dlsym(h, #x)
    SYM(C_Initialize); SYM(C_OpenSession); SYM(C_CloseSession); SYM(C_Login);
    SYM(C_InitToken); SYM(C_InitPIN); SYM(C_Logout); SYM(C_GenerateKey);
    SYM(C_DigestInit); SYM(C_Digest); SYM(C_EncryptInit); SYM(C_Encrypt);
    SYM(C_FindObjectsInit); SYM(C_FindObjects); SYM(C_FindObjectsFinal);
#undef SYM

    C_Initialize(NULL);

    if (cold) {
        /* The token file already exists (pass 1 made it). Nothing here has
         * touched the slot table yet, so every thread below hits
         * fhsm_slot_table_init_once() and fhsm_slot_token() for the first
         * time, together. That is the window pass 1 cannot reach: by the time
         * its threads start, main has already loaded the token.
         *
         * Two lazy initialisations with no lock between them:
         *   fhsm_slot_table_init_once() guards on a plain flag, not pthread_once
         *   fhsm_slot_token() does test, load, assign */
        printf("  -- demarrage a froid : %d threads sur le premier acces --\n", NTHREADS);
        pthread_barrier_init(&g_start, NULL, NTHREADS);
        pthread_t ct[NTHREADS];
        for (int i = 0; i < NTHREADS; ++i) pthread_create(&ct[i], NULL, cold_worker, NULL);
        for (int i = 0; i < NTHREADS; ++i) pthread_join(ct[i], NULL);
        printf("  demarrage a froid termine\n");
        return 0;
    }

    unsigned char lab[32]; memset(lab, ' ', sizeof lab); memcpy(lab, "conc", 4);
    C_InitToken(0, (unsigned char*)"87654321", 8, lab);

    CK_ULONG s = 0;
    C_OpenSession(0, 6, NULL, NULL, &s);
    C_Login(s, 0, (unsigned char*)"87654321", 8);
    C_InitPIN(s, (unsigned char*)"12345678", 8);
    C_Logout(s);
    C_Login(s, 1, (unsigned char*)"12345678", 8);

    unsigned char t = 1, f = 0; CK_ULONG kl = 32;
    M kg = { 0x1080, NULL, 0 };
    A a[] = { {0x161,&kl,sizeof kl}, {0x001,&t,1}, {0x104,&t,1}, {0x162,&f,1} };
    CK_RV rv = C_GenerateKey(s, &kg, a, 4, &g_key);
    if (rv != 0) { fprintf(stderr, "setup key failed 0x%lx\n", rv); return 2; }

    printf("  %d threads x %d boucles, meme slot, meme token\n", NTHREADS, NLOOPS);
    pthread_t th[NTHREADS];
    for (int i = 0; i < NTHREADS; ++i) pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < NTHREADS; ++i) pthread_join(th[i], NULL);

    C_CloseSession(s);
    printf("  erreurs d'API : %d\n", g_errors);

    if (g_errors == 0) {
        fflush(stdout);
        execl(argv[0], argv[0], "--cold", (char*)NULL);
        perror("execl");
        return 2;
    }
    printf("\ntest_concurrency : %s\n", g_errors ? "FAIL" : "PASS");
    return g_errors ? 1 : 0;
}
