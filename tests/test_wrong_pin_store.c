/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * A wrong PIN must not touch the object store on disk.
 *
 * fhsm_token_login() persists the failure counter with write_atomic(). Up to
 * 2.5.0 that write re-encrypted the object blob whenever t->dek was non-NULL
 * and the objects were loaded, and dropped the blob otherwise; a wrong PIN
 * reached it with t->dek allocated but zeroized. Before the fix this test
 * failed three times:
 *
 *   1. after a logout the objects are still loaded, so the blob was
 *      rewritten under a DEK of 32 zero bytes -- readable by anyone, and no
 *      longer readable with the real DEK;
 *   2. in a fresh process the objects are not loaded yet, so the blob was
 *      dropped and the token emptied.
 *
 * Each case is checked from the file, by reloading the token in a new handle
 * and logging in with the correct PIN. docs/TOKEN_STORE_FORMAT.md, invariant
 * 6.
 */
#include "fhsm_common.h"
#include "fhsm_crypto.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USER_PIN "userpin1234"
#define SO_PIN   "sopin1234"
#define CKO_SECRET_KEY_ 4u
#define CKK_AES_        0x1fu
#define TOK_HDR_SZ      317   /* docs/TOKEN_STORE_FORMAT.md */

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

static const uint8_t KEY[32] = {
    0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,
    0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,0xe7,0x5e,0xc2,
};

/* Reload the file in a new handle, log in correctly and look for the key. */
static int store_intact(const char *path) {
    fhsm_token_t *t = NULL;
    if (fhsm_token_load(path, &t) != FHSM_RV_OK || !t) return 0;
    int good = 0;
    usleep(1100 * 1000);   /* one failure owes 500 ms; stay clear of it */
    if (fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) == FHSM_RV_OK) {
        uint32_t h[4]; size_t n = 0;
        if (fhsm_token_object_find(t, NULL, "kept", h, 4, &n) == FHSM_RV_OK && n == 1) {
            const uint8_t *v = NULL; size_t vl = 0;
            good = fhsm_token_object_get(t, h[0], &v, &vl, NULL, NULL) == FHSM_RV_OK
                && vl == sizeof(KEY) && memcmp(v, KEY, sizeof(KEY)) == 0;
        }
    }
    fhsm_token_close(t);
    return good;
}

/* Does the blob on disk open under a DEK of 32 zero bytes? */
static int opens_under_zero_dek(const char *path, const char *serial) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    uint8_t bh[16];
    int r = 0;
    if (fseek(f, TOK_HDR_SZ, SEEK_SET) == 0 && fread(bh, 1, 16, f) == 16) {
        uint32_t ct_len = (uint32_t)bh[0] | ((uint32_t)bh[1] << 8)
                        | ((uint32_t)bh[2] << 16) | ((uint32_t)bh[3] << 24);
        if (ct_len > 0 && ct_len < (1u << 24)) {
            uint8_t *ct = malloc(ct_len + 16), *pt = malloc(ct_len);
            if (ct && pt && fread(ct, 1, ct_len + 16, f) == ct_len + 16) {
                static const uint8_t zero[32];
                size_t pl = ct_len;
                r = fhsm_aes_gcm_decrypt(FHSM_SLICE(zero, 32), FHSM_SLICE(bh + 4, 12),
                                         FHSM_SLICE(serial, strlen(serial)),
                                         FHSM_SLICE(ct, ct_len), ct + ct_len,
                                         pt, &pl) == FHSM_RV_OK;
            }
            free(ct); free(pt);
        }
    }
    fclose(f);
    return r;
}

static fhsm_token_t *make_token(const char *path, char *serial, size_t serial_sz) {
    unlink(path);
    fhsm_token_t *t = NULL;
    uint32_t h = 0;
    if (fhsm_token_init(path, SO_PIN, "wrongpin", &t) != FHSM_RV_OK || !t
        || fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN, strlen(SO_PIN)) != FHSM_RV_OK
        || fhsm_token_init_user_pin(t, USER_PIN) != FHSM_RV_OK)
        return NULL;
    fhsm_token_logout(t);
    if (fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)) != FHSM_RV_OK
        || fhsm_token_object_add(t, CKO_SECRET_KEY_, CKK_AES_, "kept", KEY, sizeof(KEY),
                                 NULL, 0, FHSM_OBJF_SENSITIVE, &h) != FHSM_RV_OK)
        return NULL;
    snprintf(serial, serial_sz, "%s", fhsm_token_serial(t));
    return t;
}

int main(void)
{
    const char *dir = getenv("FHSM_TOKENS_DIR");
    char path[512], serial[64];
    snprintf(path, sizeof path, "%s/wrongpin.tok", dir ? dir : ".");

    printf("A wrong PIN and the object store\n\n");

    /* 1. Same process: log in, log out, mistype. */
    fhsm_token_t *t = make_token(path, serial, sizeof serial);
    if (!t) { printf("  cannot set up the token at %s\n", path); return 2; }
    ok(store_intact(path), "the key is in the store after it was created");
    fhsm_token_logout(t);
    ok(fhsm_token_login(t, FHSM_ROLE_USER, "wrongwrong", 10) == FHSM_RV_PIN_INCORRECT,
       "after a logout, a wrong PIN is refused");
    fhsm_token_close(t);
    ok(!opens_under_zero_dek(path, serial),
       "the store on disk does not open under a zero DEK");
    ok(store_intact(path), "the correct PIN still finds the key");

    /* 2. Fresh process: load, mistype first. */
    t = make_token(path, serial, sizeof serial);
    if (!t) { printf("  cannot set up the token at %s\n", path); return 2; }
    fhsm_token_close(t);
    t = NULL;
    if (fhsm_token_load(path, &t) != FHSM_RV_OK || !t) { printf("  cannot reload\n"); return 2; }
    ok(fhsm_token_login(t, FHSM_ROLE_USER, "wrongwrong", 10) == FHSM_RV_PIN_INCORRECT,
       "in a fresh process, a wrong PIN is refused");
    fhsm_token_close(t);
    ok(store_intact(path), "the correct PIN still finds the key");

    /* 3. After a logout the store cannot be changed: the DEK is gone, so a
     *    change could only live in memory and be lost. */
    t = make_token(path, serial, sizeof serial);
    if (!t) { printf("  cannot set up the token at %s\n", path); return 2; }
    fhsm_token_logout(t);
    uint32_t h2 = 0;
    ok(fhsm_token_object_add(t, CKO_SECRET_KEY_, CKK_AES_, "late", KEY, sizeof(KEY),
                             NULL, 0, FHSM_OBJF_SENSITIVE, &h2) == FHSM_RV_USER_NOT_LOGGED_IN,
       "after a logout, adding an object is refused");

    /* 4. A reinit destroys the objects, including the ones loaded in memory. */
    ok(fhsm_token_reinit(t, SO_PIN, "wrongpin") == FHSM_RV_OK, "the token is re-initialized");
    fhsm_token_close(t);
    t = NULL;
    size_t left = 99;
    if (fhsm_token_load(path, &t) == FHSM_RV_OK && t
        && fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN, strlen(SO_PIN)) == FHSM_RV_OK)
        (void)fhsm_token_object_find(t, NULL, NULL, NULL, 0, &left);
    fhsm_token_close(t);
    ok(left == 0, "after a reinit the token holds no object");

    unlink(path);
    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
