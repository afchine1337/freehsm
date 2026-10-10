/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_pkiops_envelope_rsa.c --- files encrypted for an RSA key with
 * RSA-OAEP (docs/fhsm-crypt-plan.md, stage 3).
 *
 *   (1) an rsa-oaep pair: listed as rsa-oaep, refused as a signing key, and
 *       a file encrypted for it by label opens with its private half
 *   (2) for a certificate of that public key, with no token involved:
 *       named by subjectKeyIdentifier when the certificate has one, by
 *       issuer and serial number when it does not -- both open
 *   (3) OpenSSL, both ways, with an RSA key it generated and the token
 *       imported: CMS_decrypt opens our file, and pkiops_decrypt_file opens
 *       the one OpenSSL makes with OAEP, SHA-256 and MGF1-SHA-256 -- the
 *       same as `openssl cms -encrypt -keyopt rsa_padding_mode:oaep ...`
 *   (4) a file OpenSSL makes with its default, PKCS#1 v1.5 key transport,
 *       is refused by name, and leaves nothing behind
 * ========================================================================= */
#include "pkiops.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

#define SO_PIN   "So-Pin-4711"
#define USER_PIN "Us-Pin-8a2Q"
static const char MSG[] = "for the holder of an RSA key, and nobody else\n";

static char dir[256];
static void path(char *out, size_t cap, const char *name) { snprintf(out, cap, "%s/%s", dir, name); }

static int write_file(const char *p, const void *b, size_t n) {
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
static int holds_msg(const char *p) {
    size_t n = 0; uint8_t *b = read_file(p, &n);
    int r = b && n == sizeof MSG - 1 && !memcmp(b, MSG, n);
    free(b);
    return r;
}

typedef unsigned long ULONG;
typedef struct { ULONG type; void *pValue; ULONG ulValueLen; } ATTR;
static ULONG (*GetAttr)(ULONG, ULONG, ATTR *, ULONG);
static ULONG (*CreateObject)(ULONG, ATTR *, ULONG, ULONG *);

/* The token's RSA public key, as OpenSSL holds one. */
static EVP_PKEY *token_rsa(pkiops_handle s, pkiops_handle h) {
    uint8_t n[600], e[16];
    ATTR a[2] = { { 0x120, n, sizeof n }, { 0x122, e, sizeof e } };
    if (GetAttr(s, h, a, 2) != 0) return NULL;
    BIGNUM *bn = BN_bin2bn(n, (int)a[0].ulValueLen, NULL), *be = BN_bin2bn(e, (int)a[1].ulValueLen, NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, be);
    OSSL_PARAM *prm = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *k = NULL;
    if (EVP_PKEY_fromdata_init(c) == 1) EVP_PKEY_fromdata(c, &k, EVP_PKEY_PUBLIC_KEY, prm);
    EVP_PKEY_CTX_free(c); OSSL_PARAM_free(prm); OSSL_PARAM_BLD_free(bld); BN_free(bn); BN_free(be);
    return k;
}

/* A certificate for `subject_key`, signed by a throwaway EC key: what is
 * tested is the recipient, not the chain. */
static X509 *make_cert(EVP_PKEY *subject_key, int with_ski, long serial) {
    EVP_PKEY *signer = EVP_EC_gen("P-256");
    X509 *x = X509_new();
    X509_NAME *nm = X509_NAME_new();
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"rsa recipient", -1, -1, 0);
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_set_subject_name(x, nm);
    X509_set_issuer_name(x, nm);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_set_pubkey(x, subject_key);
    if (with_ski) {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    X509_sign(x, signer, EVP_sha256());
    X509_NAME_free(nm);
    EVP_PKEY_free(signer);
    return x;
}

static int write_cert(const char *p, X509 *x) {
    FILE *f = fopen(p, "w");
    if (!f) return -1;
    int r = PEM_write_X509(f, x) == 1 ? 0 : -1;
    fclose(f);
    return r;
}

/* Import an OpenSSL RSA private key into the token, for RSA-OAEP only. */
static int import_rsa(pkiops_handle s, EVP_PKEY *k, const char *label) {
    static const char *names[] = { OSSL_PKEY_PARAM_RSA_N, OSSL_PKEY_PARAM_RSA_E, OSSL_PKEY_PARAM_RSA_D,
        OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PKEY_PARAM_RSA_FACTOR2, OSSL_PKEY_PARAM_RSA_EXPONENT1,
        OSSL_PKEY_PARAM_RSA_EXPONENT2, OSSL_PKEY_PARAM_RSA_COEFFICIENT1 };
    static const ULONG types[] = { 0x120, 0x122, 0x123, 0x124, 0x125, 0x126, 0x127, 0x128 };
    uint8_t buf[8][600];
    ATTR t[16];
    ULONG n = 0, cls = 3, kt = 0, oaep = 0x9, obj = 0;
    unsigned char yes = 1, no = 0;
    t[n++] = (ATTR){ 0x000, &cls, sizeof cls };
    t[n++] = (ATTR){ 0x100, &kt, sizeof kt };
    t[n++] = (ATTR){ 0x003, (void *)label, strlen(label) };
    t[n++] = (ATTR){ 0x001, &no, 1 };
    t[n++] = (ATTR){ 0x105, &yes, 1 };
    t[n++] = (ATTR){ 0x40000600, &oaep, sizeof oaep };
    for (int i = 0; i < 8; i++) {
        BIGNUM *bn = NULL;
        if (EVP_PKEY_get_bn_param(k, names[i], &bn) != 1) return -1;
        int l = BN_bn2bin(bn, buf[i]);
        BN_free(bn);
        t[n++] = (ATTR){ types[i], buf[i], (ULONG)l };
    }
    return CreateObject(s, t, n, &obj) == 0 ? 0 : -1;
}

int main(void) {
    struct p11_err e;
    printf("pkiops: files encrypted for an RSA key, RSA-OAEP\n\n");
    snprintf(dir, sizeof dir, "/tmp/fhsm-envrsa-XXXXXX");
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }

    if (pkiops_load("./libfreehsm.so", &e)) { fprintf(stderr, "load: %s", e.msg); return 2; }
    struct pkiops_slot *sl = NULL; size_t ns = 0;
    if (pkiops_slots(&sl, &ns, &e) || ns == 0) { fprintf(stderr, "slots: %s", e.msg); return 2; }
    pkiops_handle slot = sl[0].id;
    free(sl);
    pkiops_handle s = 0;
    if (pkiops_token_init(slot, (const uint8_t *)SO_PIN, strlen(SO_PIN),
                          (const uint8_t *)USER_PIN, strlen(USER_PIN), "envrsa", &e)
        || pkiops_session_user(slot, (const uint8_t *)USER_PIN, strlen(USER_PIN), &s, &e)) {
        fprintf(stderr, "setup: %s", e.msg); return 2;
    }
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (h) { *(void **)&GetAttr = dlsym(h, "C_GetAttributeValue"); *(void **)&CreateObject = dlsym(h, "C_CreateObject"); }
    if (!GetAttr || !CreateObject) { fprintf(stderr, "symbols\n"); return 2; }

    char p_in[300], a[300], b[300], used[65];
    path(p_in, sizeof p_in, "plain");
    write_file(p_in, MSG, sizeof MSG - 1);

    printf("an rsa-oaep pair\n");
    pkiops_handle priv = 0, pub = 0;
    ok(pkiops_keygen_secret(s, "oaep", PKIOPS_SKEY_RSA_OAEP, &priv, &e) == 0, "(1) keygen rsa-oaep");
    {
        struct pkiops_object *v = NULL; size_t n = 0; int both = 0;
        if (pkiops_objects(s, PKIOPS_OBJS_KEYS, &v, &n, &e) == 0)
            for (size_t i = 0; i < n; i++)
                if (!strcmp(v[i].label, "oaep") && !strcmp(v[i].alg, "rsa-oaep")) {
                    both++;
                    if (v[i].cls == PKIOPS_OBJ_PUBLIC) pub = v[i].handle;
                }
        free(v);
        ok(both == 2 && pub, "(1) both halves listed as rsa-oaep");
        enum pkiops_alg al;
        ok(pkiops_key_alg(s, "oaep", &al, &e) == 3 && strstr(e.msg, "does not sign"),
           "(1) and refused as a signing key");
    }
    path(a, sizeof a, "by-label.p7m"); path(b, sizeof b, "by-label.out");
    ok(pkiops_encrypt_file(s, "oaep", p_in, a, &e) == 0
       && pkiops_decrypt_file(s, a, b, used, sizeof used, &e) == 0
       && holds_msg(b) && !strcmp(used, "oaep"),
       "(1) encrypted for \"oaep\" by label, opened by its private half");

    printf("for a certificate, no token\n");
    EVP_PKEY *tk = token_rsa(s, pub);
    for (int ski = 1; ski >= 0; ski--) {
        X509 *x = tk ? make_cert(tk, ski, 100 + ski) : NULL;
        char c[300];
        snprintf(c, sizeof c, "%s/cert-%d.pem", dir, ski);
        snprintf(a, sizeof a, "%s/cert-%d.p7m", dir, ski);
        snprintf(b, sizeof b, "%s/cert-%d.out", dir, ski);
        int r = x && write_cert(c, x) == 0 ? pkiops_encrypt_file_for_cert(c, p_in, a, &e) : -1;
        if (r) printf("      | %s", e.msg);
        int r2 = r ? -1 : pkiops_decrypt_file(s, a, b, used, sizeof used, &e);
        if (r2 > 0) printf("      | %s", e.msg);
        ok(r == 0 && r2 == 0 && holds_msg(b),
           ski ? "(2) named by subjectKeyIdentifier: opens"
               : "(2) no SKI in the certificate, named by issuer and serial: opens");
        X509_free(x);
    }
    EVP_PKEY_free(tk);

    printf("OpenSSL, both ways\n");
    EVP_PKEY *sw = EVP_RSA_gen(3072);
    X509 *sx = sw ? make_cert(sw, 0, 7) : NULL;
    char sc[300];
    path(sc, sizeof sc, "sw.pem");
    ok(sw && sx && write_cert(sc, sx) == 0 && import_rsa(s, sw, "imported") == 0,
       "an OpenSSL RSA key, imported into the token for OAEP");
    {
        path(a, sizeof a, "for-openssl.p7m");
        size_t n = 0; uint8_t *der = NULL;
        if (pkiops_encrypt_file_for_cert(sc, p_in, a, &e) == 0) der = read_file(a, &n);
        const unsigned char *pp = der;
        CMS_ContentInfo *cms = der ? d2i_CMS_ContentInfo(NULL, &pp, (long)n) : NULL;
        BIO *mem = BIO_new(BIO_s_mem());
        int dec = cms && mem && CMS_decrypt(cms, sw, sx, NULL, mem, 0) == 1;
        char *plain = NULL; long pl = mem ? BIO_get_mem_data(mem, &plain) : 0;
        ok(dec && pl == (long)(sizeof MSG - 1) && !memcmp(plain, MSG, sizeof MSG - 1),
           "(3) OpenSSL's CMS_decrypt opens our file with its private key");
        BIO_free(mem); CMS_ContentInfo_free(cms); free(der);
    }
    for (int oaep = 1; oaep >= 0; oaep--) {
        snprintf(a, sizeof a, "%s/from-openssl-%d.p7m", dir, oaep);
        snprintf(b, sizeof b, "%s/from-openssl-%d.out", dir, oaep);
        BIO *data = BIO_new_mem_buf(MSG, (int)sizeof MSG - 1);
        CMS_ContentInfo *cms = CMS_encrypt_ex(NULL, data, EVP_aes_256_gcm(),
                                              CMS_BINARY | CMS_PARTIAL, NULL, NULL);
        CMS_RecipientInfo *ri = cms ? CMS_add1_recipient_cert(cms, sx, CMS_KEY_PARAM) : NULL;
        EVP_PKEY_CTX *pc = ri ? CMS_RecipientInfo_get0_pkey_ctx(ri) : NULL;
        int made = pc != NULL;
        if (made && oaep)
            made = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_OAEP_PADDING) == 1
                && EVP_PKEY_CTX_set_rsa_oaep_md(pc, EVP_sha256()) == 1
                && EVP_PKEY_CTX_set_rsa_mgf1_md(pc, EVP_sha256()) == 1;
        made = made && CMS_final(cms, data, NULL, CMS_BINARY) == 1;
        unsigned char *der = NULL;
        int dl = made ? i2d_CMS_ContentInfo(cms, &der) : 0;
        made = made && dl > 0 && write_file(a, der, (size_t)dl) == 0;
        int r = made ? pkiops_decrypt_file(s, a, b, used, sizeof used, &e) : -1;
        if (oaep) {
            if (r > 0) printf("      | %s", e.msg);
            ok(made && r == 0 && holds_msg(b) && !strcmp(used, "imported"),
               "(3) pkiops_decrypt_file opens OpenSSL's RSA-OAEP SHA-256 file");
        } else {
            struct stat st;
            ok(made && r == 1 && strstr(e.msg, "PKCS#1 v1.5") && stat(b, &st) != 0,
               "(4) OpenSSL's default, PKCS#1 v1.5, is refused by name, nothing left");
        }
        OPENSSL_free(der); BIO_free(data); CMS_ContentInfo_free(cms);
    }
    X509_free(sx); EVP_PKEY_free(sw);

    pkiops_session_close(s);
    pkiops_close();
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    if (system(cmd) != 0) fprintf(stderr, "could not remove %s\n", dir);
    printf("\n%s (%d failure%s)\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
