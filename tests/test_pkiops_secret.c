/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_pkiops_secret.c --- secret keys made through pkiops
 * (docs/fhsm-crypt-plan.md, stage 1).
 *
 *  For aes128, aes256 and hmac:
 *   (1) the key is on the token, listed as a secret key under its kind
 *   (2) its attributes say what pkiops_keygen_secret promises: token,
 *       private, sensitive, not extractable, and the usages of its kind
 *       and no other -- an AES key cannot sign, an HMAC key cannot encrypt
 *   (3) its value cannot be read: CKA_VALUE answers CKR_ATTRIBUTE_SENSITIVE
 *   (4) it works for what it is for: AES-ECB round trip on one block, an
 *       HMAC-SHA-256 that verifies and fails on altered data
 *   (5) pkiops_object_attrs describes it as a person would read it, and has
 *       no line for its value
 *  And the two name parsers send each other's names to the other tool.
 *
 *  The attributes are read through C_GetAttributeValue on the module pkiops
 *  loaded: dlopen of the same path returns the same instance.
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

typedef unsigned long ULONG;
typedef struct { ULONG type; void *pValue; ULONG ulValueLen; } ATTR;
typedef struct { ULONG mechanism; void *pParameter; ULONG ulParameterLen; } MECH;

static ULONG (*GetAttr)(ULONG, ULONG, ATTR *, ULONG);
static ULONG (*EncryptInit)(ULONG, MECH *, ULONG);
static ULONG (*Encrypt)(ULONG, unsigned char *, ULONG, unsigned char *, ULONG *);
static ULONG (*DecryptInit)(ULONG, MECH *, ULONG);
static ULONG (*Decrypt)(ULONG, unsigned char *, ULONG, unsigned char *, ULONG *);
static ULONG (*SignInit)(ULONG, MECH *, ULONG);
static ULONG (*Sign)(ULONG, unsigned char *, ULONG, unsigned char *, ULONG *);
static ULONG (*VerifyInit)(ULONG, MECH *, ULONG);
static ULONG (*Verify)(ULONG, unsigned char *, ULONG, unsigned char *, ULONG);

/* The value of the line called `name`, or NULL. */
static const char *attr(const struct pkiops_attr *a, size_t n, const char *name) {
    for (size_t i = 0; i < n; i++) if (!strcmp(a[i].name, name)) return a[i].value;
    return NULL;
}
static int is(const char *v, const char *want) { return v && !strcmp(v, want); }

/* A CK_BBOOL attribute: 1, 0, or -1 when it cannot be read. */
static int flag(ULONG s, ULONG h, ULONG type) {
    unsigned char v = 0xFF;
    ATTR a = { type, &v, 1 };
    return GetAttr(s, h, &a, 1) == 0 ? (v != 0) : -1;
}

int main(void) {
    struct p11_err e;
    printf("pkiops: secret keys\n\n");

    if (pkiops_load("./libfreehsm.so", &e)) { fprintf(stderr, "load: %s", e.msg); return 2; }
    struct pkiops_slot *sl = NULL; size_t ns = 0;
    if (pkiops_slots(&sl, &ns, &e) || ns == 0) { fprintf(stderr, "slots: %s", e.msg); return 2; }
    pkiops_handle slot = sl[0].id;
    free(sl);
    if (pkiops_token_init(slot, (const uint8_t *)SO_PIN, strlen(SO_PIN),
                          (const uint8_t *)USER_PIN, strlen(USER_PIN), "secret", &e)) {
        fprintf(stderr, "token init: %s", e.msg); return 2;
    }
    pkiops_handle s = 0;
    if (pkiops_session_user(slot, (const uint8_t *)USER_PIN, strlen(USER_PIN), &s, &e)) {
        fprintf(stderr, "login: %s", e.msg); return 2;
    }
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen\n"); return 2; }
    *(void **)&GetAttr     = dlsym(h, "C_GetAttributeValue");
    *(void **)&EncryptInit = dlsym(h, "C_EncryptInit");
    *(void **)&Encrypt     = dlsym(h, "C_Encrypt");
    *(void **)&DecryptInit = dlsym(h, "C_DecryptInit");
    *(void **)&Decrypt     = dlsym(h, "C_Decrypt");
    *(void **)&SignInit    = dlsym(h, "C_SignInit");
    *(void **)&Sign        = dlsym(h, "C_Sign");
    *(void **)&VerifyInit  = dlsym(h, "C_VerifyInit");
    *(void **)&Verify      = dlsym(h, "C_Verify");
    if (!GetAttr || !EncryptInit || !Encrypt || !DecryptInit || !Decrypt
        || !SignInit || !Sign || !VerifyInit || !Verify) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    static const char *LABEL[PKIOPS_SKEY_COUNT] = { "k-aes128", "k-aes256", "k-hmac" };
    pkiops_handle key[PKIOPS_SKEY_COUNT] = { 0 };
    char what[96];

    for (int k = 0; k < PKIOPS_SKEY_COUNT; k++) {
        const char *nm = pkiops_skey_name((enum pkiops_skey)k);
        printf("%s\n", nm);
        snprintf(what, sizeof what, "(1) pkiops_keygen_secret %s", nm);
        ok(pkiops_keygen_secret(s, LABEL[k], (enum pkiops_skey)k, &key[k], &e) == 0, what);
        ULONG o = (ULONG)key[k];
        int cipher = k != PKIOPS_SKEY_HMAC;
        ok(flag(s, o, 0x001) == 1 && flag(s, o, 0x002) == 1,
           "(2) on the token, and private");
        ok(flag(s, o, 0x103) == 1 && flag(s, o, 0x162) == 0,
           "(2) sensitive, and not extractable");
        ok(flag(s, o, 0x104) == cipher && flag(s, o, 0x105) == cipher
           && flag(s, o, 0x106) == cipher && flag(s, o, 0x107) == cipher,
           cipher ? "(2) encrypts, decrypts, wraps and unwraps"
                  : "(2) does not encrypt, decrypt, wrap or unwrap");
        ok(flag(s, o, 0x108) == !cipher && flag(s, o, 0x10A) == !cipher,
           cipher ? "(2) does not sign or verify" : "(2) signs and verifies");
        unsigned char v[64];
        ATTR a = { 0x011, v, sizeof v };
        ok(GetAttr(s, o, &a, 1) == 0x11UL, "(3) CKA_VALUE is refused: CKR_ATTRIBUTE_SENSITIVE");
    }

    struct pkiops_object *v = NULL; size_t n = 0;
    ok(pkiops_objects(s, PKIOPS_OBJS_KEYS, &v, &n, &e) == 0 && n == 3, "(1) three keys listed");
    int named = n == 3;
    for (size_t i = 0; i < n; i++) {
        int k = -1;
        for (int q = 0; q < PKIOPS_SKEY_COUNT; q++) if (!strcmp(v[i].label, LABEL[q])) k = q;
        named &= k >= 0 && v[i].cls == PKIOPS_OBJ_SECRET
              && !strcmp(v[i].alg, pkiops_skey_name((enum pkiops_skey)k));
    }
    ok(named, "(1) each a secret key, named by its kind");
    free(v);

    printf("use\n");
    for (int k = PKIOPS_SKEY_AES128; k <= PKIOPS_SKEY_AES256; k++) {
        unsigned char pt[16] = "sixteen bytes!!", ct[16], back[16];
        ULONG cl = sizeof ct, bl = sizeof back;
        MECH ecb = { 0x1081, NULL, 0 };                 /* CKM_AES_ECB */
        int r = EncryptInit(s, &ecb, key[k]) == 0 && Encrypt(s, pt, 16, ct, &cl) == 0
             && DecryptInit(s, &ecb, key[k]) == 0 && Decrypt(s, ct, cl, back, &bl) == 0
             && bl == 16 && !memcmp(pt, back, 16) && memcmp(pt, ct, 16) != 0;
        snprintf(what, sizeof what, "(4) %s: AES-ECB round trip", pkiops_skey_name((enum pkiops_skey)k));
        ok(r, what);
    }
    {
        unsigned char d[] = "message to authenticate", mac[64];
        ULONG ml = sizeof mac;
        MECH hm = { 0x251, NULL, 0 };                   /* CKM_SHA256_HMAC */
        int r = SignInit(s, &hm, key[PKIOPS_SKEY_HMAC]) == 0
             && Sign(s, d, sizeof d - 1, mac, &ml) == 0 && ml == 32
             && VerifyInit(s, &hm, key[PKIOPS_SKEY_HMAC]) == 0
             && Verify(s, d, sizeof d - 1, mac, ml) == 0;
        ok(r, "(4) hmac: HMAC-SHA-256 made and verified");
        d[0] ^= 1;
        ok(VerifyInit(s, &hm, key[PKIOPS_SKEY_HMAC]) == 0
           && Verify(s, d, sizeof d - 1, mac, ml) == 0xC0UL,
           "(4) hmac: altered data is CKR_SIGNATURE_INVALID");
        MECH ecb = { 0x1081, NULL, 0 };
        ok(EncryptInit(s, &ecb, key[PKIOPS_SKEY_HMAC]) != 0, "(2) hmac: the key cannot encrypt");
    }

    printf("attributes\n");
    {
        struct pkiops_attr *a = NULL; size_t na = 0;
        ok(pkiops_object_attrs(s, key[PKIOPS_SKEY_AES256], &a, &na, &e) == 0,
           "(5) pkiops_object_attrs reads the aes256 key");
        ok(is(attr(a, na, "class"), "secret key") && is(attr(a, na, "key type"), "AES")
           && is(attr(a, na, "size"), "256 bits") && is(attr(a, na, "label"), "k-aes256"),
           "(5) class, key type, size and label");
        ok(is(attr(a, na, "usage"), "encrypt, decrypt, wrap, unwrap"), "(5) usage");
        ok(is(attr(a, na, "sensitive"), "yes") && is(attr(a, na, "extractable"), "no")
           && is(attr(a, na, "on the token"), "yes") && is(attr(a, na, "private"), "yes"),
           "(5) protection and storage");
        ok(!attr(a, na, "value"), "(5) no line for the key's value");
        free(a);
        a = NULL; na = 0;
        ok(pkiops_object_attrs(s, key[PKIOPS_SKEY_HMAC], &a, &na, &e) == 0
           && is(attr(a, na, "key type"), "generic secret")
           && is(attr(a, na, "usage"), "sign, verify"),
           "(5) the hmac key: a generic secret that signs and verifies");
        free(a);
        a = NULL; na = 0;
        ok(pkiops_object_attrs(s, 999999, &a, &na, &e) != 0
           && strstr(e.msg, "does not answer"), "(5) a handle that does not exist is refused");
    }

    printf("names\n");
    enum pkiops_skey sk; enum pkiops_alg al;
    ok(pkiops_skey_parse("ecdsa-p256", &sk, &e) == 1 && strstr(e.msg, "fhsm-csr keygen"),
       "a signature algorithm given to fhsm-crypt names fhsm-csr");
    ok(pkiops_alg_parse("aes256", &al, &e) == 1 && strstr(e.msg, "fhsm-crypt keygen"),
       "a secret key given to fhsm-csr names fhsm-crypt");
    ok(pkiops_skey_parse("aes512", &sk, &e) == 1 && strstr(e.msg, "aes128, aes256, hmac"),
       "an unknown name lists the ones offered");

    pkiops_session_close(s);
    pkiops_close();
    printf("\n%s (%d failure%s)\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
