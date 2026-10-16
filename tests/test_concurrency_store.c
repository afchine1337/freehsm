/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_concurrency_store.c --- the token's shared state under
 * concurrent sessions (#111-prep, second half).
 *
 *  tests/test_concurrency proved that per-session state -- g_op_*, g_finds,
 *  the session table -- is partitioned by handle. It did not exercise what
 *  sessions on one token genuinely share: the object store, the login state,
 *  and the function tables. Every thread there only read objects. Here one
 *  thread mutates while the others read, which is what a REST front end
 *  serving N clients from one process will do.
 *
 *  Four passes, each a fresh process, each able to fail without TSan:
 *
 *   --tables  N threads released together into C_GetFunctionList and
 *             C_GetInterface. The tables were filled lazily behind a test on
 *             pfn[0], which is written first: a second caller could be handed
 *             a table whose other slots still said CKR_FUNCTION_NOT_SUPPORTED.
 *             Each thread snapshots what it was given and compares it with the
 *             final table.
 *
 *   --destroy one thread creates a session EC key pair and destroys it,
 *             alternately with C_DestroyObject and by closing its session;
 *             the others sign with whatever private key was last published. fhsm_token_object_get
 *             hands back a pointer to the value and drops the token mutex, so
 *             a destroy in between freed the key under a running C_Sign.
 *             Returns allowed: OK, or the handle being gone.
 *
 *   --attrs   one thread rewrites a key's CKA_LABEL between two values while
 *             another creates and destroys objects (the store compacts by
 *             moving its last entry into the hole); the readers check every
 *             label they get is one of the two, whole. get_label returned a
 *             pointer into the object array, copied after the mutex was
 *             released -- a torn label, or another object's label.
 *
 *   --login   one session logs out and in again in a loop while the others
 *             read session info and digest. Login state is the token's, and
 *             its accessors read it without the token mutex.
 *
 *  Run plain, it checks results. Run under `make TSAN=1`, it also reports
 *  every race it reaches; TSan's exit code (66) fails it.
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdatomic.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } A;
typedef struct { CK_ULONG m; void *p; CK_ULONG l; } M;
typedef struct { unsigned char major, minor; } V;
typedef struct { V version; void *pfn[100]; } FL;   /* large enough for 3.2 */
typedef struct { char *name; FL *list; CK_ULONG flags; } IFACE;

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_OpenSession)(CK_ULONG,CK_ULONG,void*,void*,CK_ULONG*);
static CK_RV (*C_CloseSession)(CK_ULONG);
static CK_RV (*C_Login)(CK_ULONG,CK_ULONG,unsigned char*,CK_ULONG);
static CK_RV (*C_Logout)(CK_ULONG);
static CK_RV (*C_InitToken)(CK_ULONG,unsigned char*,CK_ULONG,unsigned char*);
static CK_RV (*C_InitPIN)(CK_ULONG,unsigned char*,CK_ULONG);
static CK_RV (*C_GenerateKey)(CK_ULONG,M*,A*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_GenerateKeyPair)(CK_ULONG,M*,A*,CK_ULONG,A*,CK_ULONG,CK_ULONG*,CK_ULONG*);
static CK_RV (*C_SignInit)(CK_ULONG,M*,CK_ULONG);
static CK_RV (*C_Sign)(CK_ULONG,unsigned char*,CK_ULONG,unsigned char*,CK_ULONG*);
static CK_RV (*C_DestroyObject)(CK_ULONG,CK_ULONG);
static CK_RV (*C_EncryptInit)(CK_ULONG,M*,CK_ULONG);
static CK_RV (*C_Encrypt)(CK_ULONG,unsigned char*,CK_ULONG,unsigned char*,CK_ULONG*);
static CK_RV (*C_DigestInit)(CK_ULONG,M*);
static CK_RV (*C_Digest)(CK_ULONG,unsigned char*,CK_ULONG,unsigned char*,CK_ULONG*);
static CK_RV (*C_GetAttributeValue)(CK_ULONG,CK_ULONG,A*,CK_ULONG);
static CK_RV (*C_SetAttributeValue)(CK_ULONG,CK_ULONG,A*,CK_ULONG);
static CK_RV (*C_GetSessionInfo)(CK_ULONG,void*);
static CK_RV (*C_GetFunctionList)(FL**);
static CK_RV (*C_GetInterface)(unsigned char*,V*,IFACE**,CK_ULONG);

#define NTHREADS 8
#define NLOOPS   200

#define CKR_OK                    0x000UL
#define CKR_KEY_HANDLE_INVALID    0x060UL
#define CKR_OBJECT_HANDLE_INVALID 0x082UL
#define CKR_USER_NOT_LOGGED_IN    0x101UL
#define CKR_USER_ALREADY_LOGGED_IN 0x100UL

static int             g_errors;
static pthread_mutex_t g_err_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t g_start;
static atomic_int      g_stop;

static void note_error(const char *what, CK_RV rv) {
    pthread_mutex_lock(&g_err_mu);
    if (g_errors < 12) fprintf(stderr, "    %s -> 0x%lx\n", what, rv);
    g_errors++;
    pthread_mutex_unlock(&g_err_mu);
}

static const unsigned char USER_PIN[] = "12345678";
static const unsigned char SO_PIN[]   = "87654321";

/* A fresh token, user PIN set, and one RW session left logged in as USER.
 * Login state is the token's, so every other session sees it. */
static CK_ULONG setup_token(void) {
    unsigned char lab[32]; memset(lab, ' ', sizeof lab); memcpy(lab, "store", 5);
    C_InitToken(0, (unsigned char*)SO_PIN, 8, lab);
    CK_ULONG s = 0;
    C_OpenSession(0, 6, NULL, NULL, &s);
    C_Login(s, 0, (unsigned char*)SO_PIN, 8);
    C_InitPIN(s, (unsigned char*)USER_PIN, 8);
    C_Logout(s);
    CK_RV rv = C_Login(s, 1, (unsigned char*)USER_PIN, 8);
    if (rv != CKR_OK) { fprintf(stderr, "setup login 0x%lx\n", rv); exit(2); }
    return s;
}

static CK_RV gen_aes(CK_ULONG s, int token, const char *label, CK_ULONG *out) {
    unsigned char t = 1, f = 0, tok = token ? 1 : 0; CK_ULONG kl = 32;
    M kg = { 0x1080, NULL, 0 };                         /* CKM_AES_KEY_GEN */
    A a[] = { {0x161,&kl,sizeof kl}, {0x001,&tok,1}, {0x104,&t,1},
              {0x162,&f,1}, {0x003,(void*)label,(CK_ULONG)strlen(label)} };
    return C_GenerateKey(s, &kg, a, 5, out);
}

/* --- --tables ----------------------------------------------------------- */
static FL g_snap_v2[NTHREADS], g_snap_v3[NTHREADS];

static void *tables_worker(void *arg) {
    int i = (int)(long)arg;
    pthread_barrier_wait(&g_start);
    FL *l = NULL;
    /* 68 slots and no more: the v2.40 table is that long, and reading the
     * size of FL off its end is an overflow ASan reports. */
    if (C_GetFunctionList(&l) == CKR_OK && l)
        memcpy(g_snap_v2[i].pfn, l->pfn, 68 * sizeof(void*));
    IFACE *ifc = NULL;
    if (C_GetInterface(NULL, NULL, &ifc, 0) == CKR_OK && ifc && ifc->list)
        memcpy(g_snap_v3[i].pfn, ifc->list->pfn, 68 * sizeof(void*));
    return NULL;
}

static int pass_tables(void) {
    pthread_t th[NTHREADS];
    for (int i = 0; i < NTHREADS; ++i)
        pthread_create(&th[i], NULL, tables_worker, (void*)(long)i);
    for (int i = 0; i < NTHREADS; ++i) pthread_join(th[i], NULL);
    FL *l = NULL; C_GetFunctionList(&l);
    IFACE *ifc = NULL; C_GetInterface(NULL, NULL, &ifc, 0);
    /* Compare the first 68 slots: the v2.40 table's size, and present in
     * both. Anything a thread saw that differs from the settled table was a
     * half-built table. */
    for (int i = 0; i < NTHREADS; ++i) {
        if (memcmp(g_snap_v2[i].pfn, l->pfn, 68 * sizeof(void*)) != 0)
            note_error("C_GetFunctionList: half-built table", 0);
        if (memcmp(g_snap_v3[i].pfn, ifc->list->pfn, 68 * sizeof(void*)) != 0)
            note_error("C_GetInterface: half-built table", 0);
    }
    return 0;
}

/* --- --destroy ---------------------------------------------------------- */
/* An EC private key rather than an AES one: C_Sign parses the borrowed DER
 * value (d2i) on every call, which keeps the read window open long enough for
 * a destroy to land inside it. An AES key is copied into its cipher context in
 * a few instructions and the window almost never overlaps. */
static atomic_ulong g_pub_key;
static atomic_long  g_sig_ok;

static CK_RV gen_ec(CK_ULONG s, CK_ULONG *pub, CK_ULONG *priv) {
    static unsigned char p256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
    unsigned char t = 1, f = 0;
    M kg = { 0x1040, NULL, 0 };                         /* CKM_EC_KEY_PAIR_GEN */
    A pu[] = { {0x180,p256,sizeof p256}, {0x001,&f,1}, {0x10A,&t,1} };
    A pr[] = { {0x001,&f,1}, {0x108,&t,1}, {0x103,&t,1}, {0x162,&f,1} };
    return C_GenerateKeyPair(s, &kg, pu, 3, pr, 4, pub, priv);
}

static void *destroy_churner(void *arg) {
    (void)arg;
    pthread_barrier_wait(&g_start);
    for (int i = 0; i < NLOOPS && !atomic_load(&g_stop); ++i) {
        CK_ULONG s = 0, pub = 0, priv = 0;
        CK_RV rv = C_OpenSession(0, 6, NULL, NULL, &s);
        if (rv != CKR_OK) { note_error("churn C_OpenSession", rv); continue; }
        rv = gen_ec(s, &pub, &priv);
        if (rv != CKR_OK) { note_error("churn C_GenerateKeyPair", rv); C_CloseSession(s); continue; }
        atomic_store(&g_pub_key, priv);
        usleep(500);                      /* let the users pick it up */
        if (i & 1) {
            rv = C_DestroyObject(s, priv); /* explicit destroy */
            if (rv != CKR_OK) note_error("churn C_DestroyObject", rv);
        }
        C_CloseSession(s);                /* session-object teardown */
    }
    atomic_store(&g_stop, 1);
    return NULL;
}

static void *destroy_user(void *arg) {
    (void)arg;
    CK_ULONG s = 0;
    CK_RV rv = C_OpenSession(0, 6, NULL, NULL, &s);
    if (rv != CKR_OK) { note_error("user C_OpenSession", rv); return NULL; }
    pthread_barrier_wait(&g_start);
    unsigned char in[32], sig[128];
    memset(in, 0x5A, sizeof in);
    while (!atomic_load(&g_stop)) {
        CK_ULONG k = atomic_load(&g_pub_key);
        if (!k) continue;
        M ecdsa = { 0x1041, NULL, 0 };     /* CKM_ECDSA */
        CK_ULONG sl = sizeof sig;
        rv = C_SignInit(s, &ecdsa, k);
        if (rv == CKR_KEY_HANDLE_INVALID || rv == CKR_OBJECT_HANDLE_INVALID) continue;
        if (rv != CKR_OK) { note_error("user C_SignInit", rv); continue; }
        rv = C_Sign(s, in, sizeof in, sig, &sl);
        if (rv == CKR_OK) atomic_fetch_add(&g_sig_ok, 1);
        else if (rv != CKR_KEY_HANDLE_INVALID && rv != CKR_OBJECT_HANDLE_INVALID)
            note_error("user C_Sign", rv);
    }
    C_CloseSession(s);
    return NULL;
}

static int pass_destroy(void) {
    CK_ULONG s0 = setup_token();
    pthread_barrier_init(&g_start, NULL, NTHREADS);
    pthread_t th[NTHREADS];
    pthread_create(&th[0], NULL, destroy_churner, NULL);
    for (int i = 1; i < NTHREADS; ++i) pthread_create(&th[i], NULL, destroy_user, NULL);
    for (int i = 0; i < NTHREADS; ++i) pthread_join(th[i], NULL);
    C_CloseSession(s0);
    /* A run where no encryption overlapped a live key exercised nothing. */
    if (atomic_load(&g_sig_ok) == 0) note_error("no C_Sign succeeded", 0);
    fprintf(stderr, "    %ld signatures with keys being destroyed\n",
            (long)atomic_load(&g_sig_ok));
    return 0;
}

/* --- --attrs ------------------------------------------------------------ */
#define LBL_LEN 24
static const char LBL_A[LBL_LEN + 1] = "AAAAAAAAAAAAAAAAAAAAAAAA";
static const char LBL_B[LBL_LEN + 1] = "BBBBBBBBBBBBBBBBBBBBBBBB";
static CK_ULONG g_attr_key;

static void *attrs_setter(void *arg) {
    (void)arg;
    CK_ULONG s = 0;
    C_OpenSession(0, 6, NULL, NULL, &s);
    pthread_barrier_wait(&g_start);
    for (int i = 0; i < NLOOPS * 4 && !atomic_load(&g_stop); ++i) {
        A a = { 0x003, (void*)((i & 1) ? LBL_B : LBL_A), LBL_LEN };
        CK_RV rv = C_SetAttributeValue(s, g_attr_key, &a, 1);
        if (rv != CKR_OK) note_error("C_SetAttributeValue(CKA_LABEL)", rv);
    }
    atomic_store(&g_stop, 1);
    C_CloseSession(s);
    return NULL;
}

/* Creates objects and destroys the oldest, so the store keeps moving its last
 * entry into a hole -- sometimes over the slot that held g_attr_key. */
static void *attrs_compactor(void *arg) {
    (void)arg;
    CK_ULONG s = 0;
    C_OpenSession(0, 6, NULL, NULL, &s);
    pthread_barrier_wait(&g_start);
    CK_ULONG ring[4] = {0}; int n = 0;
    while (!atomic_load(&g_stop)) {
        CK_ULONG k = 0;
        CK_RV rv = gen_aes(s, 0, "CCCCCCCCCCCCCCCCCCCCCCCC", &k);
        if (rv != CKR_OK) { note_error("compactor C_GenerateKey", rv); break; }
        if (ring[n & 3]) C_DestroyObject(s, ring[n & 3]);
        ring[n & 3] = k; n++;
    }
    C_CloseSession(s);
    return NULL;
}

static void *attrs_reader(void *arg) {
    (void)arg;
    CK_ULONG s = 0;
    C_OpenSession(0, 6, NULL, NULL, &s);
    pthread_barrier_wait(&g_start);
    while (!atomic_load(&g_stop)) {
        char buf[64]; memset(buf, 0, sizeof buf);
        A a = { 0x003, buf, sizeof buf };
        CK_RV rv = C_GetAttributeValue(s, g_attr_key, &a, 1);
        if (rv != CKR_OK) { note_error("C_GetAttributeValue(CKA_LABEL)", rv); continue; }
        if (a.ulValueLen != LBL_LEN
            || (memcmp(buf, LBL_A, LBL_LEN) != 0 && memcmp(buf, LBL_B, LBL_LEN) != 0)) {
            pthread_mutex_lock(&g_err_mu);
            if (g_errors < 12)
                fprintf(stderr, "    torn or foreign label: \"%.*s\" (%lu)\n",
                        (int)(a.ulValueLen < 64 ? a.ulValueLen : 64), buf, a.ulValueLen);
            g_errors++;
            pthread_mutex_unlock(&g_err_mu);
        }
    }
    C_CloseSession(s);
    return NULL;
}

static int pass_attrs(void) {
    CK_ULONG s0 = setup_token();
    /* A session object, so set/destroy do not rewrite the token file on every
     * iteration -- the store and its mutex are the same either way. */
    CK_RV rv = gen_aes(s0, 0, LBL_A, &g_attr_key);
    if (rv != CKR_OK) { fprintf(stderr, "attrs key 0x%lx\n", rv); return 2; }
    pthread_barrier_init(&g_start, NULL, NTHREADS);
    pthread_t th[NTHREADS];
    pthread_create(&th[0], NULL, attrs_setter, NULL);
    pthread_create(&th[1], NULL, attrs_compactor, NULL);
    for (int i = 2; i < NTHREADS; ++i) pthread_create(&th[i], NULL, attrs_reader, NULL);
    for (int i = 0; i < NTHREADS; ++i) pthread_join(th[i], NULL);
    C_CloseSession(s0);
    return 0;
}

/* --- --login ------------------------------------------------------------ */
static void *login_flipper(void *arg) {
    CK_ULONG s = *(CK_ULONG*)arg;
    pthread_barrier_wait(&g_start);
    for (int i = 0; i < NLOOPS / 4; ++i) {
        CK_RV rv = C_Logout(s);
        if (rv != CKR_OK) note_error("C_Logout", rv);
        rv = C_Login(s, 1, (unsigned char*)USER_PIN, 8);
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) note_error("C_Login", rv);
    }
    atomic_store(&g_stop, 1);
    return NULL;
}

static void *login_reader(void *arg) {
    (void)arg;
    CK_ULONG s = 0;
    C_OpenSession(0, 6, NULL, NULL, &s);
    pthread_barrier_wait(&g_start);
    while (!atomic_load(&g_stop)) {
        struct { CK_ULONG slot, state, flags, err; } info;
        CK_RV rv = C_GetSessionInfo(s, &info);
        if (rv != CKR_OK) note_error("C_GetSessionInfo", rv);
        M sha = { 0x250, NULL, 0 };
        unsigned char in[16] = {0}, out[32]; CK_ULONG ol = sizeof out;
        if ((rv = C_DigestInit(s, &sha)) == CKR_OK) rv = C_Digest(s, in, sizeof in, out, &ol);
        if (rv != CKR_OK) note_error("C_Digest", rv);
    }
    C_CloseSession(s);
    return NULL;
}

static int pass_login(void) {
    CK_ULONG s0 = setup_token();
    pthread_barrier_init(&g_start, NULL, NTHREADS);
    pthread_t th[NTHREADS];
    pthread_create(&th[0], NULL, login_flipper, &s0);
    for (int i = 1; i < NTHREADS; ++i) pthread_create(&th[i], NULL, login_reader, NULL);
    for (int i = 0; i < NTHREADS; ++i) pthread_join(th[i], NULL);
    C_CloseSession(s0);
    return 0;
}

int main(int argc, char **argv) {
    static const char *passes[] = { "--tables", "--destroy", "--attrs", "--login" };
    const size_t npasses = sizeof passes / sizeof passes[0];

    /* No argument: run each pass in its own process, so each starts cold and
     * one pass's lazy initialisation cannot hide another's window. */
    if (argc < 2) {
        int failed = 0;
        for (size_t i = 0; i < npasses; ++i) {
            char cmd[4096];
            snprintf(cmd, sizeof cmd, "'%s' %s", argv[0], passes[i]);
            int st = system(cmd);
            printf("  %-10s %s\n", passes[i], st == 0 ? "ok" : "FAIL");
            if (st != 0) failed++;
        }
        printf("\ntest_concurrency_store : %s\n", failed ? "FAIL" : "PASS");
        return failed ? 1 : 0;
    }

    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "%s\n", dlerror()); return 2; }
#define SYM(x) *(void**)&x = dlsym(h, #x)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_OpenSession); SYM(C_CloseSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitToken); SYM(C_InitPIN);
    SYM(C_GenerateKey); SYM(C_DestroyObject); SYM(C_EncryptInit); SYM(C_Encrypt);
    SYM(C_DigestInit); SYM(C_Digest); SYM(C_GetAttributeValue);
    SYM(C_SetAttributeValue); SYM(C_GetSessionInfo); SYM(C_GetFunctionList);
    SYM(C_GetInterface); SYM(C_GenerateKeyPair); SYM(C_SignInit); SYM(C_Sign);
#undef SYM

    if (strcmp(argv[1], "--tables") == 0) {
        /* Before C_Initialize, as an application would: the function list is
         * the first thing it asks for. */
        pthread_barrier_init(&g_start, NULL, NTHREADS);
        pass_tables();
        return g_errors ? 1 : 0;
    }

    CK_RV rv = C_Initialize(NULL);
    if (rv != CKR_OK) { fprintf(stderr, "C_Initialize 0x%lx\n", rv); return 2; }

    if      (strcmp(argv[1], "--destroy") == 0) pass_destroy();
    else if (strcmp(argv[1], "--attrs")   == 0) { if (pass_attrs() == 2) return 2; }
    else if (strcmp(argv[1], "--login")   == 0) pass_login();
    else { fprintf(stderr, "unknown pass %s\n", argv[1]); return 2; }

    C_Finalize(NULL);
    if (g_errors) fprintf(stderr, "  %s : %d erreur(s)\n", argv[1], g_errors);
    return g_errors ? 1 : 0;
}
