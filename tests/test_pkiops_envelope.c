/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_pkiops_envelope.c --- files encrypted for a token AES key
 * (docs/fhsm-crypt-plan.md, stage 2).
 *
 *   (1) round trip: a short file, an empty one, and 3 MiB of random bytes
 *       that cross the 64 KiB chunks unevenly; the key is found from the file
 *   (2) refusals that leave nothing behind: an existing output is not
 *       written over; a flipped content byte and a flipped tag byte do not
 *       authenticate (code 4), and no file -- final or temporary -- is left
 *   (3) a file made for a key that is not on the token: code 3, naming it
 *   (4) OpenSSL reads ours: CMS_decrypt with the key's bytes opens a file
 *       pkiops_encrypt_file made, for a key imported with known bytes
 *   (5) and we read OpenSSL's: an AuthEnvelopedData OpenSSL made the way
 *       `openssl cms -encrypt -secretkey` makes it -- CMS_encrypt_ex with
 *       CMS_PARTIAL, CMS_add0_recipient_key, CMS_final -- opens with
 *       pkiops_decrypt_file. (CMS_AuthEnvelopedData_create followed by
 *       CMS_final leaves the encrypted content out altogether, measured with
 *       OpenSSL 3.2 and 3.3; this test first used that and failed on it.)
 *
 *  (4) and (5) are the reason the structure is written by hand and not by
 *  OpenSSL's API, which needs the key-encryption key's bytes: they show the
 *  hand-written one is the standard one, read and written both ways.
 * ========================================================================= */
#include "pkiops.h"

#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/cms.h>
#include <openssl/rand.h>

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

#define SO_PIN   "So-Pin-4711"
#define USER_PIN "Us-Pin-8a2Q"

static char dir[256];

static void path(char *out, size_t cap, const char *name) { snprintf(out, cap, "%s/%s", dir, name); }

static int write_file(const char *p, const uint8_t *b, size_t n) {
    FILE *f = fopen(p, "wb");
    if (!f) return -1;
    int r = fwrite(b, 1, n, f) == n ? 0 : -1;
    fclose(f);
    return r;
}

static uint8_t *read_file(const char *p, size_t *n) {
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0) { fclose(f); return NULL; }
    uint8_t *b = malloc((size_t)st.st_size + 1);
    *n = b ? fread(b, 1, (size_t)st.st_size, f) : 0;
    fclose(f);
    return b;
}

static int same_file(const char *a, const char *b) {
    size_t na = 0, nb = 0;
    uint8_t *x = read_file(a, &na), *y = read_file(b, &nb);
    int r = x && y && na == nb && (na == 0 || !memcmp(x, y, na));
    free(x); free(y);
    return r;
}

/* Any file in the directory whose name begins with `prefix`: the output and
 * its temporaries share that prefix. */
static int any_with_prefix(const char *prefix) {
    DIR *d = opendir(dir);
    if (!d) return 1;
    struct dirent *de; int found = 0;
    while ((de = readdir(d)) != NULL)
        if (!strncmp(de->d_name, prefix, strlen(prefix))) found = 1;
    closedir(d);
    return found;
}

static void flip(const char *p, long from_end) {
    size_t n = 0;
    uint8_t *b = read_file(p, &n);
    if (b && n > (size_t)from_end) { b[n - (size_t)from_end] ^= 0x01; write_file(p, b, n); }
    free(b);
}

typedef unsigned long ULONG;
typedef struct { ULONG type; void *pValue; ULONG ulValueLen; } ATTR;

int main(void) {
    struct p11_err e;
    printf("pkiops: files encrypted for a token AES key\n\n");

    snprintf(dir, sizeof dir, "/tmp/fhsm-env-XXXXXX");
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }

    if (pkiops_load("./libfreehsm.so", &e)) { fprintf(stderr, "load: %s", e.msg); return 2; }
    struct pkiops_slot *sl = NULL; size_t ns = 0;
    if (pkiops_slots(&sl, &ns, &e) || ns == 0) { fprintf(stderr, "slots: %s", e.msg); return 2; }
    pkiops_handle slot = sl[0].id;
    free(sl);
    if (pkiops_token_init(slot, (const uint8_t *)SO_PIN, strlen(SO_PIN),
                          (const uint8_t *)USER_PIN, strlen(USER_PIN), "envelope", &e)) {
        fprintf(stderr, "token init: %s", e.msg); return 2;
    }
    pkiops_handle s = 0, k = 0;
    if (pkiops_session_user(slot, (const uint8_t *)USER_PIN, strlen(USER_PIN), &s, &e)
        || pkiops_keygen_secret(s, "file-key", PKIOPS_SKEY_AES256, &k, &e)) {
        fprintf(stderr, "setup: %s", e.msg); return 2;
    }

    char p_in[300], p_enc[300], p_out[300], used[65];

    printf("round trip\n");
    static const struct { const char *name; size_t len; } F[] = {
        { "short", 0 }, { "empty", 0 }, { "large", 3u * 1024 * 1024 + 4097 },
    };
    for (size_t i = 0; i < sizeof F / sizeof F[0]; i++) {
        size_t n = !strcmp(F[i].name, "short") ? 30 : F[i].len;
        uint8_t *b = malloc(n ? n : 1);
        if (!strcmp(F[i].name, "short")) memcpy(b, "a short file, thirty bytes...\n", 30);
        else if (n) RAND_bytes(b, (int)n);
        snprintf(p_in, sizeof p_in, "%s/%s", dir, F[i].name);
        snprintf(p_enc, sizeof p_enc, "%s/%s.p7m", dir, F[i].name);
        snprintf(p_out, sizeof p_out, "%s/%s.out", dir, F[i].name);
        write_file(p_in, b, n);
        free(b);
        used[0] = '\0';
        int r1 = pkiops_encrypt_file(s, "file-key", p_in, p_enc, &e);
        int r2 = r1 ? -1 : pkiops_decrypt_file(s, p_enc, p_out, used, sizeof used, &e);
        char what[96];
        snprintf(what, sizeof what, "(1) %s (%zu bytes): encrypted, decrypted, identical", F[i].name, n);
        ok(r1 == 0 && r2 == 0 && same_file(p_in, p_out), what);
        if (!strcmp(F[i].name, "short")) {
            ok(!strcmp(used, "file-key"), "(1) the key was found from the file");
            size_t en = 0; uint8_t *eb = read_file(p_enc, &en);
            ok(eb && en > 30 && !memmem(eb, en, "a short file", 12),
               "(1) the encrypted file does not contain the plaintext");
            free(eb);
        }
    }

    printf("refusals\n");
    path(p_in, sizeof p_in, "short"); path(p_enc, sizeof p_enc, "short.p7m"); path(p_out, sizeof p_out, "short.out");
    ok(pkiops_encrypt_file(s, "file-key", p_in, p_enc, &e) == 1 && strstr(e.msg, "exists"),
       "(2) encrypt will not write over an existing file");
    ok(pkiops_decrypt_file(s, p_enc, p_out, NULL, 0, &e) == 1 && strstr(e.msg, "exists"),
       "(2) nor will decrypt");
    {
        char a[300], b[300];
        path(a, sizeof a, "tampered.p7m");
        size_t n = 0; uint8_t *buf = read_file(p_enc, &n);
        write_file(a, buf, n);
        free(buf);
        flip(a, 18 + 5);                          /* a content byte, before the 18-byte tail */
        path(b, sizeof b, "tampered.out");
        int r = pkiops_decrypt_file(s, a, b, NULL, 0, &e);
        ok(r == 4 && strstr(e.msg, "does not authenticate"),
           "(2) a flipped content byte does not authenticate (code 4)");
        ok(!any_with_prefix("tampered.out"), "(2) and leaves no output, not even a temporary");
        unlink(a);
        path(a, sizeof a, "badtag.p7m");
        buf = read_file(p_enc, &n);
        write_file(a, buf, n);
        free(buf);
        flip(a, 1);                               /* the tag's last byte */
        path(b, sizeof b, "badtag.out");
        ok(pkiops_decrypt_file(s, a, b, NULL, 0, &e) == 4 && !any_with_prefix("badtag.out"),
           "(2) a flipped tag byte: code 4, nothing left");
    }

    printf("a key that is not here\n");
    {
        pkiops_handle k2 = 0;
        char a[300], b[300];
        path(a, sizeof a, "other.p7m"); path(b, sizeof b, "other.out");
        int r = pkiops_keygen_secret(s, "gone-key", PKIOPS_SKEY_AES128, &k2, &e)
             || pkiops_encrypt_file(s, "gone-key", p_in, a, &e)
             || pkiops_destroy(s, k2, &e);
        ok(r == 0, "(3) encrypted for gone-key (AES-128), then gone-key deleted");
        ok(pkiops_decrypt_file(s, a, b, NULL, 0, &e) == 3 && strstr(e.msg, "\"gone-key\""),
           "(3) decrypt: code 3, naming the key the file wants");
    }

    printf("OpenSSL, both ways\n");
    static const uint8_t KEK[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    {
        /* A token key with known bytes, so OpenSSL can be given the same. */
        void *h = dlopen("./libfreehsm.so", RTLD_NOW);
        ULONG (*C_CreateObject)(ULONG, ATTR *, ULONG, ULONG *) = NULL;
        if (h) *(void **)&C_CreateObject = dlsym(h, "C_CreateObject");
        ULONG cls = 4, kt = 0x1F, obj = 0;
        unsigned char yes = 1, no = 0;
        ATTR t[] = {
            { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt },
            { 0x011, (void *)KEK, sizeof KEK }, { 0x003, (void *)"known", 5 },
            { 0x001, &no, 1 }, { 0x103, &no, 1 }, { 0x162, &yes, 1 },
            { 0x104, &yes, 1 }, { 0x105, &yes, 1 },
        };
        ok(C_CreateObject && C_CreateObject((ULONG)s, t, sizeof t / sizeof t[0], &obj) == 0,
           "a token key \"known\" with known bytes");
    }
    {
        char a[300];
        path(a, sizeof a, "for-openssl.p7m");
        size_t n = 0; uint8_t *der = NULL;
        int r = pkiops_encrypt_file(s, "known", p_in, a, &e);
        if (!r) der = read_file(a, &n);
        const unsigned char *pp = der;
        CMS_ContentInfo *cms = der ? d2i_CMS_ContentInfo(NULL, &pp, (long)n) : NULL;
        BIO *mem = BIO_new(BIO_s_mem());
        int dec = cms && mem
               && CMS_decrypt_set1_key(cms, (unsigned char *)KEK, sizeof KEK,
                                       (const unsigned char *)"known", 5) == 1
               && CMS_decrypt(cms, NULL, NULL, NULL, mem, 0) == 1;
        char *plain = NULL; long pl = mem ? BIO_get_mem_data(mem, &plain) : 0;
        size_t sn = 0; uint8_t *src = read_file(p_in, &sn);
        ok(dec && src && pl == (long)sn && !memcmp(plain, src, sn),
           "(4) OpenSSL's CMS_decrypt opens our file with the key's bytes");
        free(src); BIO_free(mem); CMS_ContentInfo_free(cms); free(der);
    }
    {
        char a[300], b[300];
        path(a, sizeof a, "from-openssl.p7m"); path(b, sizeof b, "from-openssl.out");
        BIO *data = BIO_new_mem_buf("made by OpenSSL, read by pkiops\n", -1);
        CMS_ContentInfo *cms = data ? CMS_encrypt_ex(NULL, data, EVP_aes_256_gcm(),
                                                     CMS_BINARY | CMS_PARTIAL, NULL, NULL) : NULL;
        unsigned char *kc = OPENSSL_memdup(KEK, sizeof KEK), *ic = OPENSSL_memdup("known", 5);
        int made = cms && kc && ic
                && CMS_add0_recipient_key(cms, NID_id_aes256_wrap, kc, sizeof KEK, ic, 5,
                                          NULL, NULL, NULL) != NULL
                && CMS_final(cms, data, NULL, CMS_BINARY) == 1;
        unsigned char *der = NULL;
        int dl = made ? i2d_CMS_ContentInfo(cms, &der) : 0;
        ok(made && dl > 0 && write_file(a, der, (size_t)dl) == 0, "OpenSSL makes an AuthEnvelopedData for \"known\"");
        int r = pkiops_decrypt_file(s, a, b, used, sizeof used, &e);
        if (r) printf("      | %s", e.msg);
        size_t on = 0; uint8_t *outb = read_file(b, &on);
        ok(r == 0 && outb && on == 32 && !memcmp(outb, "made by OpenSSL, read by pkiops\n", 32)
           && !strcmp(used, "known"),
           "(5) pkiops_decrypt_file opens it with the token key");
        free(outb); OPENSSL_free(der); BIO_free(data); CMS_ContentInfo_free(cms);
    }

    pkiops_session_close(s);
    pkiops_close();
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    if (system(cmd) != 0) fprintf(stderr, "could not remove %s\n", dir);
    printf("\n%s (%d failure%s)\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
