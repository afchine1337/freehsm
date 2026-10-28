/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Public objects before a login.
 *
 * PKCS#11 lets a public session find a token's public objects and read their
 * attributes. Up to 2.5.1 every object lived in the encrypted blob only, so
 * before a login the store was empty and a search answered
 * CKR_USER_NOT_LOGGED_IN. The token file now carries a public section after
 * the blob: the public keys and certificates, in clear, read at load time.
 * docs/TOKEN_STORE_FORMAT.md, "The public section".
 *
 * Checked from the file, in a new handle each time: what is visible before a
 * login and what is not, that no secret byte is written in clear, that the
 * view cannot be changed, that a login replaces it with the whole store, and
 * that a wrong PIN, which rewrites the file, keeps the section.
 */
#include "fhsm_common.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USER_PIN "userpin1234"
#define SO_PIN   "sopin1234"
#define CKO_CERTIFICATE_ 1u
#define CKO_PUBLIC_KEY_  2u
#define CKO_SECRET_KEY_  4u
#define CKK_EC_          3u
#define CKK_AES_         0x1fu
#define ALLOWED_MECH     0x1041u   /* CKM_ECDSA */
#define OTHER            0x1042u   /* CKM_ECDSA_SHA1 */
static const uint32_t ALLOWED = ALLOWED_MECH;

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

static const uint8_t SECRET[32] = {
    0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,
    0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,
};
static const uint8_t PUBKEY[24] = "public-key-bytes-in-clr";
static const uint8_t CERT[20]   = "certificate-der-xyz";

/* Does `needle` appear anywhere in the file? */
static int file_contains(const char *path, const uint8_t *needle, size_t n) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    static uint8_t buf[1 << 20];
    size_t len = fread(buf, 1, sizeof buf, f);
    fclose(f);
    for (size_t i = 0; i + n <= len; ++i)
        if (memcmp(buf + i, needle, n) == 0) return 1;
    return 0;
}

static size_t count(fhsm_token_t *t, const char *label, fhsm_rv_t *rv) {
    size_t n = 99;
    *rv = fhsm_token_object_find(t, NULL, label, NULL, 0, &n);
    return n;
}

int main(void)
{
    const char *dir = getenv("FHSM_TOKENS_DIR");
    char path[512];
    snprintf(path, sizeof path, "%s/public.tok", dir ? dir : ".");
    unlink(path);

    printf("Public objects before a login\n\n");

    /* A token that has never held an object: an empty view, not a refusal. */
    fhsm_token_t *t = NULL;
    if (fhsm_token_init(path, SO_PIN, "public", &t) != FHSM_RV_OK || !t
        || fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN, strlen(SO_PIN)) != FHSM_RV_OK
        || fhsm_token_init_user_pin(t, USER_PIN) != FHSM_RV_OK) {
        printf("  cannot set up the token at %s\n", path); return 2;
    }
    fhsm_token_close(t); t = NULL;
    fhsm_rv_t rv;
    if (fhsm_token_load(path, &t) != FHSM_RV_OK) { printf("  cannot reload\n"); return 2; }
    size_t n = count(t, NULL, &rv);
    ok(rv == FHSM_RV_OK && n == 0, "an empty token: a search before login finds nothing");

    /* One secret key, one public key, one certificate. */
    uint32_t h = 0, h_pub = 0;
    if (fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) != FHSM_RV_OK
        || fhsm_token_object_add(t, CKO_SECRET_KEY_, CKK_AES_, "secret", SECRET, sizeof SECRET,
                                 NULL, 0, FHSM_OBJF_SENSITIVE, &h) != FHSM_RV_OK
        || fhsm_token_object_add(t, CKO_PUBLIC_KEY_, CKK_EC_, "pub", PUBKEY, sizeof PUBKEY,
                                 (const uint8_t *)"k1", 2, FHSM_OBJF_EXTRACTABLE, &h_pub) != FHSM_RV_OK
        || fhsm_token_object_add(t, CKO_CERTIFICATE_, 0, "cert", CERT, sizeof CERT,
                                 (const uint8_t *)"k1", 2, FHSM_OBJF_EXTRACTABLE, &h) != FHSM_RV_OK
        || fhsm_token_object_set_allowed_mechs(t, h_pub, &ALLOWED, 1) != FHSM_RV_OK) {
        printf("  cannot create the objects\n"); return 2;
    }
    /* 2.5.1 answered "permitted" for any mechanism here. */
    fhsm_token_logout(t);
    ok(fhsm_token_object_mech_allowed(t, h_pub, OTHER) == FHSM_RV_MECHANISM_INVALID,
       "after a logout, CKA_ALLOWED_MECHANISMS still holds");
    fhsm_token_close(t); t = NULL;

    ok(!file_contains(path, SECRET, sizeof SECRET), "the secret key is nowhere in clear in the file");
    ok(file_contains(path, PUBKEY, sizeof PUBKEY), "the public key is in the public section");

    /* A new process, no login. */
    if (fhsm_token_load(path, &t) != FHSM_RV_OK) { printf("  cannot reload\n"); return 2; }
    n = count(t, NULL, &rv);
    ok(rv == FHSM_RV_OK && n == 2, "before login, a search finds the two public objects");
    n = count(t, "secret", &rv);
    ok(rv == FHSM_RV_OK && n == 0, "before login, the secret key is not found");
    {
        const uint8_t *v = NULL; size_t vl = 0; uint32_t cl = 0;
        ok(fhsm_token_object_get(t, h_pub, &v, &vl, &cl, NULL) == FHSM_RV_OK
           && cl == CKO_PUBLIC_KEY_ && vl == sizeof PUBKEY && memcmp(v, PUBKEY, vl) == 0,
           "before login, the public key reads back, same handle, same value");
    }
    ok(fhsm_token_object_mech_allowed(t, h_pub, ALLOWED_MECH) == FHSM_RV_OK
       && fhsm_token_object_mech_allowed(t, h_pub, OTHER) == FHSM_RV_MECHANISM_INVALID,
       "before login, the public key's CKA_ALLOWED_MECHANISMS holds");
    uint32_t h2 = 0;
    ok(fhsm_token_object_add(t, CKO_PUBLIC_KEY_, CKK_EC_, "late", PUBKEY, sizeof PUBKEY,
                             NULL, 0, 0, &h2) == FHSM_RV_USER_NOT_LOGGED_IN,
       "before login, adding an object is refused");
    ok(fhsm_token_object_set_label(t, h_pub, "renamed") == FHSM_RV_USER_NOT_LOGGED_IN,
       "before login, changing a public object is refused");
    ok(fhsm_token_object_destroy(t, h_pub) == FHSM_RV_USER_NOT_LOGGED_IN,
       "before login, destroying a public object is refused");

    /* The login replaces the view with the store. */
    ok(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) == FHSM_RV_OK,
       "the user logs in");
    n = count(t, NULL, &rv);
    ok(rv == FHSM_RV_OK && n == 3, "after login, all three objects");
    fhsm_token_close(t); t = NULL;

    /* A wrong PIN rewrites the file for its counter; the section stays. */
    if (fhsm_token_load(path, &t) != FHSM_RV_OK) { printf("  cannot reload\n"); return 2; }
    ok(fhsm_token_login(t, FHSM_ROLE_USER, "wrongwrong", 10) == FHSM_RV_PIN_INCORRECT,
       "a wrong PIN is refused");
    fhsm_token_close(t); t = NULL;
    if (fhsm_token_load(path, &t) != FHSM_RV_OK) { printf("  cannot reload\n"); return 2; }
    n = count(t, NULL, &rv);
    ok(rv == FHSM_RV_OK && n == 2, "after a wrong PIN, the two public objects are still found");

    /* Destroy the public objects: the section is rewritten, empty. */
    ok(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) == FHSM_RV_OK
       && fhsm_token_object_destroy(t, h_pub) == FHSM_RV_OK
       && fhsm_token_object_destroy(t, h) == FHSM_RV_OK,
       "the public key and the certificate are destroyed");
    fhsm_token_close(t); t = NULL;
    ok(!file_contains(path, PUBKEY, sizeof PUBKEY), "and are gone from the file");
    if (fhsm_token_load(path, &t) != FHSM_RV_OK) { printf("  cannot reload\n"); return 2; }
    n = count(t, NULL, &rv);
    ok(rv == FHSM_RV_OK && n == 0, "before login, a search now finds nothing");
    fhsm_token_close(t);

    unlink(path);
    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
