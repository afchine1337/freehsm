/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_pkiops_objects.c --- listing and deleting objects through pkiops
 * (docs/fhsm-crypt-plan.md, stage 0).
 *
 *  Two key pairs and a certificate are put on a fresh token; the certificate
 *  through C_CreateObject on the same module instance, since nothing in
 *  pkiops stores one. Then:
 *
 *   (1) pkiops_objects lists each object once, under its class and label,
 *       certificates first, and the masks select what they name
 *   (2) the certificate carries the CKA_ID it was created with, in hex
 *   (3) pkiops_destroy removes exactly the handle it is given: the other
 *       objects, the other half of the same pair included, are untouched
 *   (4) a destroyed handle cannot be destroyed twice, and the second attempt
 *       is a refusal with a message, not a crash
 *   (5) the call log names C_DestroyObject and the object, as it does every
 *       other call
 * ========================================================================= */
#include "pkiops.h"

#include <dlfcn.h>
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

static char   g_rec[256][200];
static size_t g_n;
static void collect(const struct pkiops_call *c, void *ctx) {
    (void)ctx;
    if (g_n < sizeof g_rec / sizeof g_rec[0])
        snprintf(g_rec[g_n++], sizeof g_rec[0], "%s %s", c->fn, c->args);
}

static size_t count(const struct pkiops_object *v, size_t n, enum pkiops_obj_class c,
                    const char *label) {
    size_t k = 0;
    for (size_t i = 0; i < n; i++)
        if (v[i].cls == c && (!label || !strcmp(v[i].label, label))) k++;
    return k;
}

typedef unsigned long ULONG;
typedef struct { ULONG type; void *pValue; ULONG ulValueLen; } ATTR;

int main(void) {
    struct p11_err e;
    printf("pkiops: objects, listed and destroyed\n\n");

    pkiops_set_call_log(collect, NULL);
    if (pkiops_load("./libfreehsm.so", &e)) { fprintf(stderr, "load: %s", e.msg); return 2; }
    struct pkiops_slot *sl = NULL; size_t ns = 0;
    if (pkiops_slots(&sl, &ns, &e) || ns == 0) { fprintf(stderr, "slots: %s", e.msg); return 2; }
    pkiops_handle slot = sl[0].id;
    free(sl);
    if (pkiops_token_init(slot, (const uint8_t *)SO_PIN, strlen(SO_PIN),
                          (const uint8_t *)USER_PIN, strlen(USER_PIN), "objects", &e)) {
        fprintf(stderr, "token init: %s", e.msg); return 2;
    }
    pkiops_handle s = 0;
    if (pkiops_session_user(slot, (const uint8_t *)USER_PIN, strlen(USER_PIN), &s, &e)) {
        fprintf(stderr, "login: %s", e.msg); return 2;
    }

    struct pkiops_object *v = NULL; size_t n = 0;
    ok(pkiops_objects(s, PKIOPS_OBJS_ALL, &v, &n, &e) == 0 && n == 0,
       "a fresh token has no objects");
    free(v);

    pkiops_handle ap = 0, ak = 0, bp = 0, bk = 0;
    if (pkiops_keygen_alg(s, "pair-a", PKIOPS_ALG_ECDSA_P256, &ap, &ak, &e) ||
        pkiops_keygen_alg(s, "pair-b", PKIOPS_ALG_ED25519, &bp, &bk, &e)) {
        fprintf(stderr, "keygen: %s", e.msg); return 2;
    }

    /* A certificate object, labelled like its key, with a CKA_ID. Made through
     * C_CreateObject on the module pkiops loaded: dlopen of the same path
     * returns the same instance, so the session handle is valid here. */
    static uint8_t der[8192]; size_t dl = sizeof der;
    if (pkiops_root(s, "pair-a", "/CN=objects test", 1, 30, der, &dl, &e)) {
        fprintf(stderr, "root: %s", e.msg); return 2;
    }
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    ULONG (*C_CreateObject)(ULONG, ATTR *, ULONG, ULONG *) = NULL;
    if (h) *(void **)&C_CreateObject = dlsym(h, "C_CreateObject");
    if (!C_CreateObject) { fprintf(stderr, "C_CreateObject not found\n"); return 2; }
    ULONG cls = 1 /* CKO_CERTIFICATE */, ctype = 0 /* CKC_X_509 */;
    unsigned char tru = 1, id[3] = { 0xA1, 0xB2, 0xC3 };
    ATTR ct[] = {
        { 0x000, &cls, sizeof cls },               /* CKA_CLASS */
        { 0x080, &ctype, sizeof ctype },           /* CKA_CERTIFICATE_TYPE */
        { 0x001, &tru, 1 },                        /* CKA_TOKEN */
        { 0x003, (void *)"pair-a", 6 },            /* CKA_LABEL */
        { 0x102, id, sizeof id },                  /* CKA_ID */
        { 0x011, der, (ULONG)dl },                 /* CKA_VALUE */
    };
    ULONG cert = 0;
    ULONG crv = C_CreateObject((ULONG)s, ct, sizeof ct / sizeof ct[0], &cert);
    if (crv != 0) { fprintf(stderr, "C_CreateObject certificate: 0x%lx\n", crv); return 2; }

    v = NULL; n = 0;
    ok(pkiops_objects(s, PKIOPS_OBJS_ALL, &v, &n, &e) == 0 && n == 5,
       "(1) two key pairs and a certificate list as five objects");
    ok(n > 0 && v[0].cls == PKIOPS_OBJ_CERT, "(1) certificates come first");
    ok(count(v, n, PKIOPS_OBJ_CERT, "pair-a") == 1
       && count(v, n, PKIOPS_OBJ_PUBLIC, "pair-a") == 1
       && count(v, n, PKIOPS_OBJ_PRIVATE, "pair-a") == 1
       && count(v, n, PKIOPS_OBJ_PUBLIC, "pair-b") == 1
       && count(v, n, PKIOPS_OBJ_PRIVATE, "pair-b") == 1,
       "(1) each under its class and label");
    {
        int cert_id = 0, key_types = 1;
        for (size_t i = 0; i < n; i++) {
            if (v[i].cls == PKIOPS_OBJ_CERT)
                cert_id = !strcmp(v[i].id, "a1b2c3") && v[i].key_type == 0;
            else if (!strcmp(v[i].label, "pair-a")) key_types &= v[i].key_type == 0x03;  /* CKK_EC */
            else key_types &= v[i].key_type == 0x40;                                      /* CKK_EC_EDWARDS */
        }
        ok(cert_id, "(2) the certificate's CKA_ID reads back as a1b2c3");
        ok(key_types, "(1) the keys carry their CKA_KEY_TYPE");
    }
    free(v);

    v = NULL; n = 0;
    ok(pkiops_objects(s, PKIOPS_OBJS_CERTS, &v, &n, &e) == 0 && n == 1
       && v[0].cls == PKIOPS_OBJ_CERT, "(1) the certificate mask selects the certificate alone");
    free(v);
    v = NULL; n = 0;
    ok(pkiops_objects(s, PKIOPS_OBJS_KEYS, &v, &n, &e) == 0 && n == 4
       && count(v, n, PKIOPS_OBJ_CERT, NULL) == 0, "(1) the key mask selects the four keys");
    free(v);

    g_n = 0;
    ok(pkiops_destroy(s, ak, &e) == 0, "(3) pkiops_destroy removes pair-a's private key");
    {
        char want[64];
        snprintf(want, sizeof want, "C_DestroyObject session %lu, object %lu",
                 (unsigned long)s, (unsigned long)ak);
        int seen = 0;
        for (size_t i = 0; i < g_n; i++) seen |= !strcmp(g_rec[i], want);
        ok(seen, "(5) the call log records C_DestroyObject and the object");
    }
    v = NULL; n = 0;
    ok(pkiops_objects(s, PKIOPS_OBJS_ALL, &v, &n, &e) == 0 && n == 4
       && count(v, n, PKIOPS_OBJ_PRIVATE, "pair-a") == 0
       && count(v, n, PKIOPS_OBJ_PUBLIC, "pair-a") == 1
       && count(v, n, PKIOPS_OBJ_CERT, "pair-a") == 1
       && count(v, n, PKIOPS_OBJ_PRIVATE, "pair-b") == 1,
       "(3) everything else is still there, the public half of pair-a included");
    free(v);

    int again = pkiops_destroy(s, ak, &e);
    ok(again != 0 && strstr(e.msg, "C_DestroyObject failed") != NULL,
       "(4) destroying the same handle again is refused with a message");

    ok(pkiops_destroy(s, (pkiops_handle)cert, &e) == 0, "(3) the certificate is destroyed by its handle");
    v = NULL; n = 0;
    ok(pkiops_objects(s, PKIOPS_OBJS_CERTS, &v, &n, &e) == 0 && n == 0,
       "(3) and no certificate remains");
    free(v);

    pkiops_session_close(s);
    pkiops_close();
    printf("\n%s (%d failure%s)\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
