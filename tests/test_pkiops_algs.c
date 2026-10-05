/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_pkiops_algs.c --- every algorithm through the token, checked by OpenSSL.
 *
 *  docs/classic-algorithms-plan.md stage 2. tools/pkiops generates a key pair
 *  for any of the algorithms and, from then on, reads the algorithm off the
 *  key. This drives every operation the tools perform with each one, through
 *  the module -- key pair, algorithm read back, request, root, raw signature
 *  streamed in pieces, CMS, issuance, CRL, OCSP -- and has OpenSSL check what
 *  comes out, which is what these algorithms are for.
 *
 *  What OpenSSL cannot check, the composite, is skipped there; the composite
 *  exists only in all-mechanisms builds and is skipped entirely elsewhere.
 * ========================================================================= */
#include "pkiops.h"

#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-66s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

#define SO_PIN   "So-Pin-4711"
#define USER_PIN "Us-Pin-8a2Q"

static const char DATA1[] = "the first part of the data, ";
static const char DATA2[] = "and the second.";

/* The signature over DATA1 || DATA2, checked by OpenSSL with `k`. */
static int openssl_verify(enum pkiops_alg a, EVP_PKEY *k,
                          const uint8_t *sig, size_t sl) {
    const char *md = a == PKIOPS_ALG_ECDSA_P384 ? "SHA384"
                   : (a == PKIOPS_ALG_ECDSA_P256 || a == PKIOPS_ALG_RSA_PSS
                      || a == PKIOPS_ALG_RSA_PKCS1) ? "SHA256" : NULL;
    char msg[128];
    snprintf(msg, sizeof msg, "%s%s", DATA1, DATA2);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int r = m && EVP_DigestVerifyInit_ex(m, &pc, md, NULL, NULL, k, NULL) == 1;
    if (r && a == PKIOPS_ALG_RSA_PSS)
        r = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1
         && EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, 32) == 1
         && EVP_PKEY_CTX_set_rsa_mgf1_md_name(pc, "SHA256", NULL) == 1;
    r = r && EVP_DigestVerify(m, sig, sl, (const uint8_t *)msg, strlen(msg)) == 1;
    EVP_MD_CTX_free(m);
    return r;
}

static int chains_to(const uint8_t *der, size_t n, X509 *root) {
    const uint8_t *p = der;
    X509 *x = d2i_X509(NULL, &p, (long)n);
    X509_STORE *st = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int r = x && st && ctx && X509_STORE_add_cert(st, root) == 1
         && X509_STORE_CTX_init(ctx, st, x, NULL) == 1
         && X509_verify_cert(ctx) == 1;
    X509_STORE_CTX_free(ctx); X509_STORE_free(st); X509_free(x);
    return r;
}

static uint8_t csr[PKIOPS_ALG_COUNT][16384];  static size_t csr_len[PKIOPS_ALG_COUNT];
static uint8_t root[PKIOPS_ALG_COUNT][16384]; static size_t root_len[PKIOPS_ALG_COUNT];
static X509   *rx[PKIOPS_ALG_COUNT];
static char    label[PKIOPS_ALG_COUNT][32];

int main(void) {
    struct p11_err e;
    printf("tools/pkiops, every algorithm, checked by OpenSSL\n");

    if (pkiops_load("./libfreehsm.so", &e)) { fprintf(stderr, "load: %s", e.msg); return 2; }
    struct pkiops_slot *sl = NULL; size_t ns = 0;
    if (pkiops_slots(&sl, &ns, &e) || !ns) { fprintf(stderr, "slots\n"); return 2; }
    pkiops_handle slot = sl[0].id;
    free(sl);
    if (pkiops_token_init(slot, (const uint8_t *)SO_PIN, strlen(SO_PIN),
                          (const uint8_t *)USER_PIN, strlen(USER_PIN), "algs", &e)) {
        fprintf(stderr, "init: %s", e.msg); return 2;
    }
    pkiops_handle s = 0;
    if (pkiops_session_user(slot, (const uint8_t *)USER_PIN, strlen(USER_PIN), &s, &e)) {
        fprintf(stderr, "login: %s", e.msg); return 2;
    }

    int have[PKIOPS_ALG_COUNT] = { 0 };
    for (int i = 0; i < PKIOPS_ALG_COUNT; i++) {
        enum pkiops_alg a = (enum pkiops_alg)i;
        const char *nm = pkiops_alg_name(a);
        printf("\n[%s]\n", nm);
        snprintf(label[i], sizeof label[i], "k-%s", nm);

        enum pkiops_alg back = PKIOPS_ALG_COUNT;
        ok(pkiops_alg_parse(nm, &back, &e) == 0 && back == a, "the name parses back to itself");

        pkiops_handle hp = 0, hk = 0;
        int kg = pkiops_keygen_alg(s, label[i], a, &hp, &hk, &e);
        if (kg && a == PKIOPS_ALG_COMPOSITE && strstr(e.msg, "0x70")) {
            printf("  %-66s %s\n", "composite (all-mechanisms only)", "skipped");
            continue;
        }
        ok(kg == 0, "key pair generated on the token");
        if (kg) { printf("      %s", e.msg); continue; }
        back = PKIOPS_ALG_COUNT;
        ok(pkiops_key_alg(s, label[i], &back, &e) == 0 && back == a,
           "and the algorithm is read back off the key");

        csr_len[i] = sizeof csr[i];
        int r = pkiops_csr(s, label[i], "/O=Simorgh Labs/CN=leaf", csr[i], &csr_len[i], &e);
        if (r == 0 && a != PKIOPS_ALG_COMPOSITE) {
            const uint8_t *p = csr[i];
            X509_REQ *q = d2i_X509_REQ(NULL, &p, (long)csr_len[i]);
            r = !(q && X509_REQ_verify(q, X509_REQ_get0_pubkey(q)) == 1);
            X509_REQ_free(q);
        }
        ok(r == 0, a == PKIOPS_ALG_COMPOSITE ? "request built"
                                             : "request built, and X509_REQ_verify accepts it");

        root_len[i] = sizeof root[i];
        r = pkiops_root(s, label[i], "/O=Simorgh Labs/CN=root", 1, 3650, root[i], &root_len[i], &e);
        const uint8_t *p = root[i];
        rx[i] = r == 0 ? d2i_X509(NULL, &p, (long)root_len[i]) : NULL;
        if (a != PKIOPS_ALG_COMPOSITE)
            ok(rx[i] && chains_to(root[i], root_len[i], rx[i]),
               "root built, and it verifies as its own trust anchor");
        else
            ok(rx[i] != NULL, "root built");
        have[i] = rx[i] != NULL;

        /* A raw signature, the data in two pieces. */
        uint8_t *sig = NULL; size_t sigl = 0;
        r = pkiops_sign_begin(s, label[i], &e)
         || pkiops_sign_update(s, (const uint8_t *)DATA1, strlen(DATA1), &e)
         || pkiops_sign_update(s, (const uint8_t *)DATA2, strlen(DATA2), &e)
         || pkiops_sign_end(s, &sig, &sigl, &e);
        ok(r == 0, "raw signature over data streamed in two pieces");
        if (r == 0) {
            int valid = -1;
            int v = pkiops_verify_begin(s, label[i], &e)
                 || pkiops_verify_update(s, (const uint8_t *)DATA1, strlen(DATA1), &e)
                 || pkiops_verify_update(s, (const uint8_t *)DATA2, strlen(DATA2), &e)
                 || pkiops_verify_end(s, sig, sigl, &valid, &e);
            ok(v == 0 && valid == 1, "  the module verifies it");
            valid = -1;
            v = pkiops_verify_begin(s, label[i], &e)
             || pkiops_verify_update(s, (const uint8_t *)DATA2, strlen(DATA2), &e)
             || pkiops_verify_end(s, sig, sigl, &valid, &e);
            ok(v == 0 && valid == 0, "  and says it does not match other data");
            if (a != PKIOPS_ALG_COMPOSITE && rx[i])
                ok(openssl_verify(a, X509_get0_pubkey(rx[i]), sig, sigl),
                   "  OpenSSL verifies it too (ECDSA as DER)");
        }
        free(sig);

        /* CMS. */
        if (rx[i]) {
            const char *dn = pkiops_alg_digest(a);
            struct pkiops_hash *h = pkiops_hash_begin(dn, &e);
            uint8_t dg[64]; size_t dl = 0;
            r = !h || pkiops_hash_update(h, (const uint8_t *)DATA1, strlen(DATA1), &e)
                   || pkiops_hash_update(h, (const uint8_t *)DATA2, strlen(DATA2), &e);
            if (h) r |= pkiops_hash_end(h, dg, &dl, &e);
            static uint8_t cms[32768]; size_t cl = sizeof cms;
            r = r || pkiops_cms_sign(s, label[i], root[i], root_len[i], dg, dl, cms, &cl, &e);
            ok(r == 0, "CMS built with the algorithm's own digest");
            if (r == 0) {
                const char *found = NULL;
                ok(pkiops_cms_digest(cms, cl, &found) == 0 && found && !strcmp(found, dn),
                   "  pkiops_cms_digest names it");
                int verdict = -2;
                ok(pkiops_cms_verify(cms, cl, dg, dl, &verdict, &e) == 0 && verdict == 1,
                   "  pkiops_cms_verify accepts it");
                if (a != PKIOPS_ALG_COMPOSITE) {
                    char msg[128];
                    snprintf(msg, sizeof msg, "%s%s", DATA1, DATA2);
                    const uint8_t *q = cms;
                    CMS_ContentInfo *ci = d2i_CMS_ContentInfo(NULL, &q, (long)cl);
                    BIO *dc = BIO_new_mem_buf(msg, (int)strlen(msg));
                    int cv = ci && dc && CMS_verify(ci, NULL, NULL, dc, NULL,
                                       CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) == 1;
                    BIO_free(dc); CMS_ContentInfo_free(ci);
                    ok(cv, "  OpenSSL's CMS_verify accepts it, against the data");
                }
            }
        }
    }

    printf("\n[a CA of each algorithm issues, revokes, answers]\n");
    for (int i = 0; i < PKIOPS_ALG_COUNT; i++) {
        if (!have[i]) continue;
        int j = i;
        do { j = (j + 1) % PKIOPS_ALG_COUNT; } while (!have[j]);
        char what[112];

        static uint8_t leaf[16384]; size_t ll = sizeof leaf;
        int pop = -1;
        int r = pkiops_issue(s, label[i], root[i], root_len[i], csr[j], csr_len[j],
                             NULL, "DNS:leaf.example", NULL, 0, FHSM_CERT_END_ENTITY, 365,
                             leaf, &ll, &pop, &e);
        snprintf(what, sizeof what, "%s CA issues for a %s key",
                 pkiops_alg_name((enum pkiops_alg)i), pkiops_alg_name((enum pkiops_alg)j));
        int issued = r == 0 && pop == 1;
        if (issued && i != PKIOPS_ALG_COMPOSITE) {
            if (j != PKIOPS_ALG_COMPOSITE) {
                issued = chains_to(leaf, ll, rx[i]);
            } else {
                /* A composite subject key: X509_verify_cert also judges the
                 * leaf's own key, its security level among other things, and
                 * cannot load a composite one. The question here is the CA's
                 * signature, which OpenSSL can check -- as test_pki_classic
                 * does for the same case. */
                const uint8_t *q = leaf;
                X509 *x = d2i_X509(NULL, &q, (long)ll);
                issued = x && X509_verify(x, X509_get0_pubkey(rx[i])) == 1;
                X509_free(x);
            }
        }
        ok(issued, what);
        if (!issued) continue;

        const uint8_t *p = leaf;
        X509 *lx = d2i_X509(NULL, &p, (long)ll);
        const ASN1_INTEGER *sn = lx ? X509_get0_serialNumber(lx) : NULL;
        if (!sn) { ok(0, "  the issued certificate parses"); X509_free(lx); continue; }
        fhsm_rev_entry_t en;
        memset(&en, 0, sizeof en);
        memcpy(en.serial, ASN1_STRING_get0_data(sn), (size_t)ASN1_STRING_length(sn));
        en.serial_len = (size_t)ASN1_STRING_length(sn);
        memcpy(en.date, "20261005120000Z", 16);
        en.reason = 1;
        fhsm_rev_db_t db = { 3, &en, 1, 1 };

        uint8_t *crl = NULL; size_t cl = 0;
        r = pkiops_crl(s, label[i], root[i], root_len[i], &db, 30, &crl, &cl, &e);
        int good = r == 0;
        if (good && i != PKIOPS_ALG_COMPOSITE) {
            const uint8_t *c = crl;
            X509_CRL *x = d2i_X509_CRL(NULL, &c, (long)cl);
            X509_REVOKED *hit = NULL;
            good = x && X509_CRL_verify(x, X509_get0_pubkey(rx[i])) == 1
                     && X509_CRL_get0_by_serial(x, &hit, (ASN1_INTEGER *)(uintptr_t)sn) == 1;
            X509_CRL_free(x);
        }
        ok(good, "  CRL signed, the serial listed");
        free(crl);

        OCSP_REQUEST *oreq = OCSP_REQUEST_new();
        OCSP_CERTID *id = OCSP_cert_to_id(NULL, lx, rx[i]);
        uint8_t *req = NULL; int reql = -1;
        if (oreq && id && OCSP_request_add0_id(oreq, OCSP_CERTID_dup(id)))
            reql = i2d_OCSP_REQUEST(oreq, &req);
        uint8_t *resp = NULL; size_t rl = 0;
        fhsm_ocsp_stats_t st;
        memset(&st, 0, sizeof st);
        r = reql > 0 ? pkiops_ocsp(s, label[i], req, (size_t)reql, root[i], root_len[i],
                                   root[i], root_len[i], &db, 7, "test",
                                   &resp, &rl, &st, &e) : -1;
        good = r == 0 && st.revoked == 1;
        if (good && i != PKIOPS_ALG_COMPOSITE) {
            const uint8_t *c = resp;
            OCSP_RESPONSE *or = d2i_OCSP_RESPONSE(NULL, &c, (long)rl);
            OCSP_BASICRESP *bs = or ? OCSP_response_get1_basic(or) : NULL;
            X509_STORE *store = X509_STORE_new();
            int status = -1, reason = -1;
            good = bs && store && X509_STORE_add_cert(store, rx[i]) == 1
                && OCSP_basic_verify(bs, NULL, store, 0) == 1
                && OCSP_resp_find_status(bs, id, &status, &reason, NULL, NULL, NULL) == 1
                && status == V_OCSP_CERTSTATUS_REVOKED;
            X509_STORE_free(store); OCSP_BASICRESP_free(bs); OCSP_RESPONSE_free(or);
        }
        ok(good, "  OCSP answers revoked, and the answer verifies");
        free(resp); OPENSSL_free(req);
        OCSP_CERTID_free(id); OCSP_REQUEST_free(oreq);
        X509_free(lx);
    }

    for (int i = 0; i < PKIOPS_ALG_COUNT; i++) X509_free(rx[i]);
    pkiops_session_close(s);
    pkiops_close();
    if (fails) { fprintf(stderr, "test_pkiops_algs : %d FAIL\n", fails); return 1; }
    printf("\ntest_pkiops_algs : PASS\n");
    return 0;
}
