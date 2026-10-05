/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * tests/test_pki_classic.c --- requests, roots and issuance for every signer.
 *
 *  docs/classic-algorithms-plan.md, stage 1a. include/fhsm_pki.h builds a
 *  request, a self-signed root and an issued certificate for any signer:
 *  ECDSA P-256 and P-384, RSA-PSS and PKCS#1 v1.5, Ed25519, ML-DSA-44/65/87.
 *  None of those is checked here by this project's own code. OpenSSL checks
 *  them -- X509_REQ_verify, X509_verify_cert -- which the composite cannot
 *  have until its RFC and its implementations exist, and which is the point
 *  of offering these algorithms at all.
 *
 *  The keys are software keys and the signer is a callback around
 *  EVP_DigestSign: the builders cannot tell, which is the property under
 *  test. For ECDSA the callback hands back r || s, as PKCS#11 does, through
 *  fhsm_pki_ecdsa_raw_to_der -- the path the tools will take.
 *
 *  Also checked:
 *    - each AlgorithmIdentifier constant against the one OpenSSL writes when
 *      it signs with that algorithm, byte for byte;
 *    - a forged request (one key, another's signature) refused;
 *    - mixed hierarchies both ways: an ECDSA CA certifying a composite key,
 *      a composite CA certifying an ECDSA key.
 * ========================================================================= */
#include "fhsm_pki.h"
#include "fhsm_revocation.h"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

static int fails = 0;
static void ck(const char *what, int ok) {
    printf("  %-62s %s\n", what, ok ? "OK" : "<<< FAIL");
    if (!ok) fails++;
}

static fhsm_rv_t t_rng(void *c, uint8_t *out, size_t n) {
    (void)c;
    return RAND_bytes(out, (int)n) == 1 ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

struct alg {
    const char *name;
    fhsm_pki_sigalg_t sig;
    const char *keytype, *keyparam;   /* for EVP_PKEY_Q_keygen */
    const char *md;                   /* NULL for Ed25519 and ML-DSA */
    int pss;
    size_t ecdsa_half;                /* r and s length, 0 if not ECDSA */
};

static const struct alg ALGS[] = {
    { "ecdsa-p256",  FHSM_PKI_SIG_ECDSA_SHA256,     "EC",  "P-256", "SHA256", 0, 32 },
    { "ecdsa-p384",  FHSM_PKI_SIG_ECDSA_SHA384,     "EC",  "P-384", "SHA384", 0, 48 },
    /* 2048 rather than the tools' 3072: the test is about encodings, and a
     * 3072-bit key generation costs seconds for nothing. */
    { "rsa-pss",     FHSM_PKI_SIG_RSA_PSS_SHA256,   "RSA", NULL,    "SHA256", 1, 0 },
    { "rsa-pkcs1",   FHSM_PKI_SIG_RSA_PKCS1_SHA256, "RSA", NULL,    "SHA256", 0, 0 },
    { "ed25519",     FHSM_PKI_SIG_ED25519,          "ED25519",   NULL, NULL, 0, 0 },
    { "ml-dsa-44",   FHSM_PKI_SIG_MLDSA44,          "ML-DSA-44", NULL, NULL, 0, 0 },
    { "ml-dsa-65",   FHSM_PKI_SIG_MLDSA65,          "ML-DSA-65", NULL, NULL, 0, 0 },
    { "ml-dsa-87",   FHSM_PKI_SIG_MLDSA87,          "ML-DSA-87", NULL, NULL, 0, 0 },
};
#define N_ALGS (sizeof ALGS / sizeof ALGS[0])

struct sw { EVP_PKEY *k; const struct alg *a; };

static int sign_init(EVP_MD_CTX *m, const struct sw *c) {
    EVP_PKEY_CTX *pc = NULL;
    if (EVP_DigestSignInit_ex(m, &pc, c->a->md, NULL, NULL, c->k, NULL) != 1) return 0;
    if (!c->a->pss) return 1;
    return EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1
        && EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, 32) == 1
        && EVP_PKEY_CTX_set_rsa_mgf1_md_name(pc, "SHA256", NULL) == 1;
}

/* The signer callback: what a token would do, in software. */
static fhsm_rv_t sw_sign(void *v, const uint8_t *tbs, size_t n, uint8_t *sig, size_t *sl) {
    const struct sw *c = v;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    static uint8_t buf[FHSM_PKI_SIG_MAX];
    size_t bl = sizeof buf;
    int ok = m && sign_init(m, c) && EVP_DigestSign(m, buf, &bl, tbs, n) == 1;
    EVP_MD_CTX_free(m);
    if (!ok) return FHSM_RV_FUNCTION_FAILED;
    if (c->a->ecdsa_half) {
        /* OpenSSL signs to DER; PKCS#11 returns r || s. Undo the one to get
         * the other, then convert back the way the tools will. */
        const uint8_t *p = buf;
        ECDSA_SIG *es = d2i_ECDSA_SIG(NULL, &p, (long)bl);
        uint8_t rs[2 * 66];
        size_t h = c->a->ecdsa_half;
        ok = es && BN_bn2binpad(ECDSA_SIG_get0_r(es), rs, (int)h) == (int)h
                && BN_bn2binpad(ECDSA_SIG_get0_s(es), rs + h, (int)h) == (int)h;
        ECDSA_SIG_free(es);
        if (!ok) return FHSM_RV_FUNCTION_FAILED;
        return fhsm_pki_ecdsa_raw_to_der(rs, 2 * h, sig, sl);
    }
    if (bl > *sl) return FHSM_RV_BUFFER_TOO_SMALL;
    memcpy(sig, buf, bl);
    *sl = bl;
    return FHSM_RV_OK;
}

static EVP_PKEY *keygen(const struct alg *a) {
    if (!strcmp(a->keytype, "RSA")) return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    if (a->keyparam) return EVP_PKEY_Q_keygen(NULL, NULL, a->keytype, a->keyparam);
    return EVP_PKEY_Q_keygen(NULL, NULL, a->keytype);
}

/* The AlgorithmIdentifier OpenSSL writes for this algorithm, signing a
 * request of its own -- the reference the constant is compared with. */
static int openssl_algid(const struct sw *c, uint8_t **der) {
    X509_REQ *r = X509_REQ_new();
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int n = -1;
    if (r && m && X509_REQ_set_pubkey(r, c->k) == 1 && sign_init(m, c)
        && X509_REQ_sign_ctx(r, m) > 0) {
        const X509_ALGOR *a = NULL;
        X509_REQ_get0_signature(r, NULL, &a);
        n = i2d_X509_ALGOR(a, der);
    }
    EVP_MD_CTX_free(m); X509_REQ_free(r);
    return n;
}

/* A signer for a composite software key, as test_composite_issue has. */
struct csctx { const uint8_t *p; size_t n; };
static fhsm_rv_t csign(void *v, const uint8_t *t, size_t tl, uint8_t *s, size_t *sl) {
    const struct csctx *c = v;
    return fhsm_composite_sign(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                               c->p, c->n, t, tl, NULL, 0, s, sl);
}

static int chains_to(const uint8_t *der, size_t n, X509 *root) {
    const uint8_t *p = der;
    X509 *x = d2i_X509(NULL, &p, (long)n);
    X509_STORE *st = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int ok = x && st && ctx && X509_STORE_add_cert(st, root) == 1
          && X509_STORE_CTX_init(ctx, st, x, NULL) == 1
          && X509_verify_cert(ctx) == 1;
    if (!ok && ctx) printf("      verify: %s\n",
        X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    X509_STORE_CTX_free(ctx); X509_STORE_free(st); X509_free(x);
    return ok;
}

static uint8_t spki[N_ALGS][8192];
static size_t  spki_len[N_ALGS];
static uint8_t csr[N_ALGS][16384];
static size_t  csr_len[N_ALGS];
static uint8_t root[N_ALGS][16384];
static size_t  root_len[N_ALGS];
static uint8_t leaf[N_ALGS][16384];   /* issued by CA i */
static size_t  leaf_len[N_ALGS];

int main(void) {
    printf("=== test_pki_classic : every signer, checked by OpenSSL ===\n");

    EVP_PKEY *k[N_ALGS] = { 0 };
    struct sw sw[N_ALGS];
    fhsm_pki_signer_t s[N_ALGS];
    X509 *rx[N_ALGS] = { 0 };

    for (size_t i = 0; i < N_ALGS; i++) {
        const struct alg *a = &ALGS[i];
        printf("\n[%s]\n", a->name);
        k[i] = keygen(a);
        ck("software key generated", k[i] != NULL);
        if (!k[i]) continue;
        sw[i].k = k[i]; sw[i].a = a;

        uint8_t *p = spki[i];
        int sl = i2d_PUBKEY(k[i], &p);
        spki_len[i] = sl > 0 ? (size_t)sl : 0;

        const uint8_t *ad = NULL; size_t adl = 0;
        ck("fhsm_pki_algid knows it", fhsm_pki_algid(a->sig, &ad, &adl) == FHSM_RV_OK);
        uint8_t *ref = NULL;
        int rl = openssl_algid(&sw[i], &ref);
        ck("the AlgorithmIdentifier is the one OpenSSL writes, byte for byte",
           rl > 0 && (size_t)rl == adl && ad && memcmp(ref, ad, adl) == 0);
        OPENSSL_free(ref);

        s[i] = (fhsm_pki_signer_t){ ad, adl, spki[i], spki_len[i], sw_sign, &sw[i] };

        csr_len[i] = sizeof csr[i];
        fhsm_rv_t rv = fhsm_pki_csr(&s[i], "/C=FR/O=Simorgh Labs/CN=leaf", csr[i], &csr_len[i]);
        int ok = rv == FHSM_RV_OK;
        if (ok) {
            const uint8_t *q = csr[i];
            X509_REQ *r = d2i_X509_REQ(NULL, &q, (long)csr_len[i]);
            ok = r && X509_REQ_verify(r, X509_REQ_get0_pubkey(r)) == 1;
            X509_REQ_free(r);
        }
        ck("request built, and X509_REQ_verify accepts it", ok);

        root_len[i] = sizeof root[i];
        rv = fhsm_pki_selfsigned(&s[i], "/C=FR/O=Simorgh Labs/CN=Root", 1, 3650,
                                 root[i], &root_len[i]);
        const uint8_t *q = root[i];
        rx[i] = rv == FHSM_RV_OK ? d2i_X509(NULL, &q, (long)root_len[i]) : NULL;
        ck("root built, and it verifies as its own trust anchor",
           rx[i] && chains_to(root[i], root_len[i], rx[i]));
    }

    printf("\n[issuance: each CA certifies the next algorithm's request]\n");
    for (size_t i = 0; i < N_ALGS; i++) {
        size_t j = (i + 1) % N_ALGS;
        if (!rx[i] || !k[j]) { ck("precondition", 0); continue; }
        leaf_len[i] = sizeof leaf[i];
        fhsm_rv_t rv = fhsm_pki_issue(&s[i], root[i], root_len[i], csr[j], csr_len[j],
                                      NULL, "DNS:leaf.example", NULL, 0,
                                      FHSM_CERT_END_ENTITY, 365, t_rng, NULL,
                                      leaf[i], &leaf_len[i]);
        char what[96];
        snprintf(what, sizeof what, "%s CA issues for %s, and the chain verifies",
                 ALGS[i].name, ALGS[j].name);
        ck(what, rv == FHSM_RV_OK && chains_to(leaf[i], leaf_len[i], rx[i]));
        if (rv != FHSM_RV_OK) leaf_len[i] = 0;
    }

    printf("\n[revocation: each CA revokes what it issued]\n");
    for (size_t i = 0; i < N_ALGS; i++) {
        if (!rx[i] || !leaf_len[i]) { ck("precondition", 0); continue; }
        char what[96];
        const uint8_t *q = leaf[i];
        X509 *lx = d2i_X509(NULL, &q, (long)leaf_len[i]);
        const ASN1_INTEGER *sn = lx ? X509_get0_serialNumber(lx) : NULL;
        if (!sn) { ck("issued certificate parses", 0); X509_free(lx); continue; }

        /* The CRL. */
        fhsm_composite_revoked_t rv1 = {
            ASN1_STRING_get0_data(sn), (size_t)ASN1_STRING_length(sn),
            (int64_t)time(NULL), 1 /* keyCompromise */ };
        static uint8_t crl[16384]; size_t cl = sizeof crl;
        fhsm_rv_t rv = fhsm_pki_crl(&s[i], root[i], root_len[i], &rv1, 1, 7, 30, crl, &cl);
        int ok = rv == FHSM_RV_OK;
        if (ok) {
            const uint8_t *c = crl;
            X509_CRL *x = d2i_X509_CRL(NULL, &c, (long)cl);
            X509_REVOKED *hit = NULL;
            ok = x && X509_CRL_verify(x, k[i]) == 1
                   && X509_CRL_get0_by_serial(x, &hit, sn) == 1;
            X509_CRL_free(x);
        }
        snprintf(what, sizeof what, "%s CRL: OpenSSL verifies it, the serial is listed",
                 ALGS[i].name);
        ck(what, ok);

        /* OCSP: a request built by OpenSSL, answered through the path fhsm-ca
         * and fhsm-service use, checked by OpenSSL. The CA answers for itself. */
        OCSP_REQUEST *oreq = OCSP_REQUEST_new();
        OCSP_CERTID *id = OCSP_cert_to_id(NULL, lx, rx[i]);
        uint8_t *req = NULL; int reql = -1;
        if (oreq && id && OCSP_request_add0_id(oreq, OCSP_CERTID_dup(id)))
            reql = i2d_OCSP_REQUEST(oreq, &req);
        fhsm_rev_entry_t e;
        memset(&e, 0, sizeof e);
        memcpy(e.serial, ASN1_STRING_get0_data(sn), (size_t)ASN1_STRING_length(sn));
        e.serial_len = (size_t)ASN1_STRING_length(sn);
        memcpy(e.date, "20261005120000Z", 16);
        e.reason = 1;
        fhsm_rev_db_t db = { 7, &e, 1, 1 };
        uint8_t *resp = NULL; size_t respl = 0;
        fhsm_ocsp_stats_t st;
        char err[FHSM_REV_ERR_MAX] = "";
        int orc = reql > 0
            ? fhsm_ocsp_answer_ex(req, (size_t)reql, root[i], root_len[i], root[i],
                                  root_len[i], &db, 7, "test", s[i].algid, s[i].algid_len,
                                  sw_sign, &sw[i], &resp, &respl, &st, err, sizeof err)
            : -1;
        ok = orc == FHSM_REV_OK && st.revoked == 1;
        if (ok) {
            const uint8_t *c = resp;
            OCSP_RESPONSE *or = d2i_OCSP_RESPONSE(NULL, &c, (long)respl);
            OCSP_BASICRESP *bs = or ? OCSP_response_get1_basic(or) : NULL;
            X509_STORE *store = X509_STORE_new();
            int status = -1, reason = -1;
            ok = bs && store && X509_STORE_add_cert(store, rx[i]) == 1
                 && OCSP_basic_verify(bs, NULL, store, 0) == 1
                 && OCSP_resp_find_status(bs, id, &status, &reason, NULL, NULL, NULL) == 1
                 && status == V_OCSP_CERTSTATUS_REVOKED;
            X509_STORE_free(store); OCSP_BASICRESP_free(bs); OCSP_RESPONSE_free(or);
        } else if (orc != FHSM_REV_OK) {
            printf("      %s", err);
        }
        snprintf(what, sizeof what, "%s OCSP: OpenSSL verifies it, and reads \"revoked\"",
                 ALGS[i].name);
        ck(what, ok);
        free(resp);
        OPENSSL_free(req);
        OCSP_CERTID_free(id); OCSP_REQUEST_free(oreq);
        X509_free(lx);
    }

    printf("\n[proof of possession]\n");
    {
        /* An Ed25519 key in the request, signed by the P-256 key: the applicant
         * does not hold the key it asks to have certified. */
        fhsm_pki_signer_t forged = s[0];
        forged.spki = spki[4]; forged.spki_len = spki_len[4];
        static uint8_t f[16384]; size_t fl = sizeof f;
        ck("a forged request is built (it is well-formed)",
           fhsm_pki_csr(&forged, "/CN=impostor", f, &fl) == FHSM_RV_OK);
        static uint8_t other[16384]; size_t ll = sizeof other;
        ck("and issuance refuses it (CKR_SIGNATURE_INVALID)",
           fhsm_pki_issue(&s[0], root[0], root_len[0], f, fl, NULL, NULL, NULL, 0,
                          FHSM_CERT_END_ENTITY, 365, t_rng, NULL, other, &ll)
           == FHSM_RV_SIGNATURE_INVALID);
    }

    printf("\n[mixed hierarchies, with the composite]\n");
    {
        static uint8_t cpriv[FHSM_COMPOSITE_PRIV_MAX], cpub[FHSM_COMPOSITE_PUB_MAX];
        size_t cpl = sizeof cpriv, cbl = sizeof cpub;
        const fhsm_composite_alg_t C = FHSM_COMPOSITE_MLDSA65_ED25519_SHA512;
        ck("composite key generated",
           fhsm_composite_keygen(C, cpriv, &cpl, cpub, &cbl) == FHSM_RV_OK);
        struct csctx cs = { cpriv, cpl };

        static uint8_t ccsr[16384]; size_t ccl = sizeof ccsr;
        ck("composite request built",
           fhsm_composite_csr(C, "/CN=composite leaf", cpub, cbl, csign, &cs, ccsr, &ccl)
           == FHSM_RV_OK);
        static uint8_t other[16384]; size_t ll = sizeof other;
        fhsm_rv_t rv = fhsm_pki_issue(&s[0], root[0], root_len[0], ccsr, ccl, NULL, NULL,
                                      NULL, 0, FHSM_CERT_END_ENTITY, 365, t_rng, NULL,
                                      other, &ll);
        int ok = rv == FHSM_RV_OK;
        if (ok) {
            /* OpenSSL cannot load the composite subject key, and does not need
             * to: the certificate's signature is the CA's, ECDSA. */
            const uint8_t *q = other;
            X509 *x = d2i_X509(NULL, &q, (long)ll);
            ok = x && X509_verify(x, k[0]) == 1;
            X509_free(x);
        }
        ck("an ECDSA CA certifies a composite key; OpenSSL checks its signature", ok);

        static uint8_t croot[16384]; size_t crl = sizeof croot;
        ck("composite root built",
           fhsm_composite_selfsigned(C, "/CN=composite root", 1, 3650, cpub, cbl,
                                     csign, &cs, croot, &crl) == FHSM_RV_OK);
        ll = sizeof other;
        rv = fhsm_composite_issue(C, croot, crl, csr[0], csr_len[0], NULL, NULL, NULL, 0,
                                  FHSM_CERT_END_ENTITY, 365, csign, &cs, t_rng, NULL,
                                  other, &ll);
        ok = rv == FHSM_RV_OK;
        if (ok) {
            const uint8_t *q = other;
            X509 *x = d2i_X509(NULL, &q, (long)ll);
            EVP_PKEY *pk = x ? X509_get0_pubkey(x) : NULL;
            ok = pk && EVP_PKEY_is_a(pk, "EC");
            X509_free(x);
        }
        ck("a composite CA certifies an ECDSA key, its proof checked by OpenSSL", ok);
    }

    for (size_t i = 0; i < N_ALGS; i++) { X509_free(rx[i]); EVP_PKEY_free(k[i]); }
    printf("\n%s\n", fails ? "test_pki_classic : FAIL" : "test_pki_classic : PASS");
    return fails ? 1 : 0;
}
