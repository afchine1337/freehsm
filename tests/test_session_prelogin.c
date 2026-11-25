/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_session_prelogin.c --- public session objects without a login (#45),
 * at the store.
 *
 * PKCS#11 v3.2 §5.6 gives a public session read/write access to public
 * session objects. The store refused every object before a login, because a
 * session object was made as a token object, in the encrypted file, and then
 * marked. fhsm_token_object_add_ex makes it in memory, as a session object
 * from the start.
 *
 * On a token holding a public key and a secret key, reloaded with no login:
 *   (A) a token object, and a private session object, are refused; a public
 *       secret key, a public private key and a public key made as session
 *       objects are accepted, found and read back, and the file is not
 *       touched;
 *   (C) they can be changed and destroyed, but not made private, and the
 *       token's own public key cannot be changed;
 *   (L) the first login keeps them, with their handles and values, beside the
 *       whole store; a token object made after it takes a fresh handle; the
 *       file written by the login holds none of their values;
 *   (O) a logout destroys a private session object and keeps a public one;
 *       a public one can be made again after it;
 *   (E) on a token with no object, a session object's handle is not reused
 *       by the store after the login;
 *   (S) closing the session destroys its objects and leaves the file as it
 *       was.
 * ========================================================================= */
#include "fhsm_common.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USER_PIN "userpin1234"
#define SO_PIN   "sopin1234"
#define CKO_PUBLIC_KEY_  2u
#define CKO_PRIVATE_KEY_ 3u
#define CKO_SECRET_KEY_  4u
#define CKK_EC_          3u
#define CKK_GENERIC_     0x10u
#define CKK_AES_         0x1fu
#define SESSION          7u
#define OTHER_SESSION    8u

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-70s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

static const uint8_t TOKEN_SECRET[32] = "token-secret-key-0123456789abcd";
static const uint8_t PUBKEY[24]       = "public-key-bytes-in-clr";
static const uint8_t S_SECRET[32]     = "session-secret-hkdf-input-01234";
static const uint8_t S_PRIVATE[32]    = "session-private-key-from-a-pem1";
static const uint8_t S_PUBLIC[24]     = "session-public-key-byte";

/* The whole file, for comparing before and after. */
static size_t file_read(const char *path, uint8_t *buf, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

static int file_contains(const char *path, const uint8_t *needle, size_t n) {
    static uint8_t buf[1 << 20];
    size_t len = file_read(path, buf, sizeof buf);
    for (size_t i = 0; i + n <= len; ++i)
        if (memcmp(buf + i, needle, n) == 0) return 1;
    return 0;
}

static size_t count(fhsm_token_t *t, fhsm_rv_t *rv) {
    size_t n = 99;
    *rv = fhsm_token_object_find(t, NULL, NULL, NULL, 0, &n);
    return n;
}

static int reads_back(fhsm_token_t *t, uint32_t h, uint32_t cls,
                      const uint8_t *val, size_t len) {
    const uint8_t *v = NULL; size_t vl = 0; uint32_t c = 0;
    return fhsm_token_object_get(t, h, &v, &vl, &c, NULL) == FHSM_RV_OK
        && c == cls && vl == len && memcmp(v, val, len) == 0;
}

static fhsm_rv_t add(fhsm_token_t *t, uint32_t cls, uint32_t kt, const char *label,
                     const uint8_t *v, size_t vl, uint8_t f3, uint32_t owner,
                     uint32_t *h) {
    return fhsm_token_object_add_ex(t, cls, kt, label, v, vl, NULL, 0,
                                    FHSM_OBJF_EXTRACTABLE, f3, owner, h);
}

static int setup(const char *path, int with_objects) {
    fhsm_token_t *t = NULL;
    unlink(path);
    if (fhsm_token_init(path, SO_PIN, "prelogin", &t) != FHSM_RV_OK || !t
        || fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN, strlen(SO_PIN)) != FHSM_RV_OK
        || fhsm_token_init_user_pin(t, USER_PIN) != FHSM_RV_OK) {
        printf("  cannot set up the token at %s\n", path);
        return -1;
    }
    fhsm_token_close(t); t = NULL;
    if (!with_objects) return 0;
    uint32_t h = 0;
    if (fhsm_token_load(path, &t) != FHSM_RV_OK
        || fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) != FHSM_RV_OK
        || fhsm_token_object_add(t, CKO_SECRET_KEY_, CKK_AES_, "token-secret",
                                 TOKEN_SECRET, sizeof TOKEN_SECRET, NULL, 0,
                                 FHSM_OBJF_SENSITIVE, &h) != FHSM_RV_OK
        || fhsm_token_object_add(t, CKO_PUBLIC_KEY_, CKK_EC_, "token-pub",
                                 PUBKEY, sizeof PUBKEY, NULL, 0,
                                 FHSM_OBJF_EXTRACTABLE, &h) != FHSM_RV_OK) {
        printf("  cannot create the token objects\n");
        return -1;
    }
    fhsm_token_close(t);
    return 0;
}

int main(void)
{
    const char *dir = getenv("FHSM_TOKENS_DIR");
    char path[512];
    snprintf(path, sizeof path, "%s/prelogin.tok", dir ? dir : ".");
    static uint8_t before[1 << 20], after[1 << 20];
    size_t nb, na;
    fhsm_rv_t rv;
    size_t n;

    printf("Public session objects without a login (#45)\n\n");
    if (setup(path, 1) != 0) return 2;

    fhsm_token_t *t = NULL;
    if (fhsm_token_load(path, &t) != FHSM_RV_OK) { printf("  cannot reload\n"); return 2; }
    n = count(t, &rv);
    ok(rv == FHSM_RV_OK && n == 1, "(A) before login, the view holds the token's public key");
    uint32_t h_tokpub = 0;
    fhsm_token_object_find(t, NULL, "token-pub", &h_tokpub, 1, &n);
    nb = file_read(path, before, sizeof before);

    uint32_t h = 0, hs = 0, hk = 0, hp = 0;
    ok(add(t, CKO_PUBLIC_KEY_, CKK_EC_, "x", S_PUBLIC, sizeof S_PUBLIC, 0, 0, &h)
           == FHSM_RV_USER_NOT_LOGGED_IN,
       "(A) a token object is refused");
    ok(add(t, CKO_SECRET_KEY_, CKK_GENERIC_, "x", S_SECRET, sizeof S_SECRET, 0, SESSION, &h)
           == FHSM_RV_USER_NOT_LOGGED_IN,
       "(A) a private secret key session object is refused");
    ok(add(t, CKO_PRIVATE_KEY_, CKK_EC_, "x", S_PRIVATE, sizeof S_PRIVATE, 0, SESSION, &h)
           == FHSM_RV_USER_NOT_LOGGED_IN,
       "(A) a private private-key session object is refused");
    ok(add(t, CKO_SECRET_KEY_, CKK_GENERIC_, "s-secret", S_SECRET, sizeof S_SECRET,
           FHSM_OBJF3_PUBLIC, SESSION, &hs) == FHSM_RV_OK,
       "(A) a public secret key session object is made");
    ok(add(t, CKO_PRIVATE_KEY_, CKK_EC_, "s-private", S_PRIVATE, sizeof S_PRIVATE,
           FHSM_OBJF3_PUBLIC, SESSION, &hk) == FHSM_RV_OK,
       "(A) a public private-key session object is made");
    ok(add(t, CKO_PUBLIC_KEY_, CKK_EC_, "s-public", S_PUBLIC, sizeof S_PUBLIC,
           0, SESSION, &hp) == FHSM_RV_OK,
       "(A) a public key session object is made");
    ok(hs != hk && hk != hp && hs != hp && hs != h_tokpub && hk != h_tokpub && hp != h_tokpub,
       "(A) four distinct handles");
    n = count(t, &rv);
    ok(rv == FHSM_RV_OK && n == 4, "(A) a search finds the token's public key and the three");
    ok(reads_back(t, hs, CKO_SECRET_KEY_, S_SECRET, sizeof S_SECRET)
       && reads_back(t, hk, CKO_PRIVATE_KEY_, S_PRIVATE, sizeof S_PRIVATE)
       && reads_back(t, hp, CKO_PUBLIC_KEY_, S_PUBLIC, sizeof S_PUBLIC),
       "(A) their values read back");
    na = file_read(path, after, sizeof after);
    ok(na == nb && memcmp(before, after, nb) == 0, "(A) the file is unchanged");

    /* (C) */
    ok(fhsm_token_object_set_label(t, hs, "renamed") == FHSM_RV_OK,
       "(C) a public session object is renamed");
    {
        const char *l = NULL; size_t ll = 0;
        ok(fhsm_token_object_get_label(t, hs, &l, &ll) == FHSM_RV_OK
           && ll == 7 && memcmp(l, "renamed", 7) == 0, "(C) and reads back renamed");
    }
    ok(fhsm_token_object_set_usage(t, hk, 0x81) == FHSM_RV_OK,
       "(C) its usage flags are set");
    ok(fhsm_token_object_set_flags3(t, hs, 0) == FHSM_RV_USER_NOT_LOGGED_IN,
       "(C) making it private is refused");
    {
        uint8_t f3 = 0;
        ok(fhsm_token_object_get_flags3(t, hs, &f3) == FHSM_RV_OK && (f3 & FHSM_OBJF3_PUBLIC),
           "(C) and it stays public");
    }
    ok(fhsm_token_object_set_label(t, h_tokpub, "renamed") == FHSM_RV_USER_NOT_LOGGED_IN,
       "(C) the token's public key cannot be changed");
    ok(fhsm_token_object_destroy(t, h_tokpub) == FHSM_RV_USER_NOT_LOGGED_IN,
       "(C) nor destroyed");
    ok(fhsm_token_object_set_label(t, 0x7fff0000u, "x") == FHSM_RV_USER_NOT_LOGGED_IN,
       "(C) an unknown handle answers CKR_USER_NOT_LOGGED_IN, as before");
    ok(fhsm_token_object_destroy(t, hp) == FHSM_RV_OK, "(C) the public key session object is destroyed");
    n = count(t, &rv);
    ok(rv == FHSM_RV_OK && n == 3, "(C) three objects left");
    na = file_read(path, after, sizeof after);
    ok(na == nb && memcmp(before, after, nb) == 0, "(C) the file is still unchanged");

    /* (L) */
    ok(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) == FHSM_RV_OK,
       "(L) the user logs in");
    n = count(t, &rv);
    ok(rv == FHSM_RV_OK && n == 4, "(L) the two token objects and the two session objects");
    ok(reads_back(t, hs, CKO_SECRET_KEY_, S_SECRET, sizeof S_SECRET)
       && reads_back(t, hk, CKO_PRIVATE_KEY_, S_PRIVATE, sizeof S_PRIVATE),
       "(L) the session objects keep their handles and values");
    ok(reads_back(t, h_tokpub, CKO_PUBLIC_KEY_, PUBKEY, sizeof PUBKEY),
       "(L) the token's public key keeps its handle");
    {
        int is_tok = 1;
        ok(fhsm_token_object_is_token(t, hs, &is_tok) == FHSM_RV_OK && !is_tok,
           "(L) and they are still session objects");
    }
    uint32_t hn = 0;
    ok(fhsm_token_object_add(t, CKO_PUBLIC_KEY_, CKK_EC_, "new", PUBKEY, sizeof PUBKEY,
                             NULL, 0, FHSM_OBJF_EXTRACTABLE, &hn) == FHSM_RV_OK
       && hn != hs && hn != hk && hn != h_tokpub,
       "(L) a token object made now takes a fresh handle");
    ok(!file_contains(path, S_SECRET, sizeof S_SECRET)
       && !file_contains(path, S_PRIVATE, sizeof S_PRIVATE),
       "(L) no session value is in the file");

    /* (O) */
    uint32_t hpriv = 0;
    ok(add(t, CKO_SECRET_KEY_, CKK_GENERIC_, "private", S_SECRET, sizeof S_SECRET,
           0, SESSION, &hpriv) == FHSM_RV_OK, "(O) a private session object is made, logged in");
    fhsm_token_logout(t);
    ok(fhsm_token_object_get(t, hpriv, NULL, NULL, NULL, NULL) == FHSM_RV_KEY_HANDLE_INVALID,
       "(O) the logout destroys it");
    ok(reads_back(t, hs, CKO_SECRET_KEY_, S_SECRET, sizeof S_SECRET)
       && reads_back(t, hk, CKO_PRIVATE_KEY_, S_PRIVATE, sizeof S_PRIVATE),
       "(O) and keeps the public ones, same handles");
    ok(add(t, CKO_SECRET_KEY_, CKK_GENERIC_, "again", S_SECRET, sizeof S_SECRET,
           FHSM_OBJF3_PUBLIC, OTHER_SESSION, &h) == FHSM_RV_OK
       && h != hs && h != hk && h != hn,
       "(O) a public one is made after the logout, with a fresh handle");

    /* (S) */
    nb = file_read(path, before, sizeof before);
    ok(fhsm_token_destroy_session_objects(t, SESSION) == FHSM_RV_OK
       && fhsm_token_object_get(t, hs, NULL, NULL, NULL, NULL) == FHSM_RV_KEY_HANDLE_INVALID
       && fhsm_token_object_get(t, hk, NULL, NULL, NULL, NULL) == FHSM_RV_KEY_HANDLE_INVALID
       && fhsm_token_object_get(t, h, NULL, NULL, NULL, NULL) == FHSM_RV_OK,
       "(S) closing a session destroys its objects, not another session's");
    na = file_read(path, after, sizeof after);
    ok(na == nb && memcmp(before, after, nb) == 0, "(S) the file is unchanged");
    fhsm_token_close(t); t = NULL;

    /* (E) A token with no object: the store starts its handles at 1 again
     * when it finds no blob. */
    if (setup(path, 0) != 0) return 2;
    if (fhsm_token_load(path, &t) != FHSM_RV_OK) { printf("  cannot reload\n"); return 2; }
    ok(add(t, CKO_SECRET_KEY_, CKK_GENERIC_, "early", S_SECRET, sizeof S_SECRET,
           FHSM_OBJF3_PUBLIC, SESSION, &hs) == FHSM_RV_OK,
       "(E) on an empty token, a public session object is made");
    ok(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) == FHSM_RV_OK
       && fhsm_token_object_add(t, CKO_PUBLIC_KEY_, CKK_EC_, "tok", PUBKEY, sizeof PUBKEY,
                                NULL, 0, FHSM_OBJF_EXTRACTABLE, &hn) == FHSM_RV_OK,
       "(E) after the login, a token object is made");
    ok(hn != hs && reads_back(t, hs, CKO_SECRET_KEY_, S_SECRET, sizeof S_SECRET)
       && reads_back(t, hn, CKO_PUBLIC_KEY_, PUBKEY, sizeof PUBKEY),
       "(E) with its own handle; the session object is intact");
    fhsm_token_close(t);

    unlink(path);
    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
