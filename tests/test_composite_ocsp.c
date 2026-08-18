/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Differential test: our OCSP encoder against OpenSSL's, byte for byte.
 *
 * The method is the one the CRL and CMS tests use. OpenSSL cannot sign with a
 * composite key, but it signs Ed25519 perfectly well, so the reference is
 * built on Ed25519 and the encoders are compared on the bytes they both can
 * produce. What is being checked is the DER assembly -- the part where a
 * misplaced tag produces something that parses and means something else.
 *
 * One difference from the CRL test, forced by OpenSSL's API surface:
 * i2d_re_X509_CRL_tbs is public, i2d_OCSP_RESPDATA is not -- OCSP_RESPDATA is
 * opaque, declared only in crypto/ocsp/ocsp_local.h. So tbsResponseData is
 * sliced out of the DER instead. It is the first inner TLV of
 * BasicOCSPResponse and therefore, by construction, exactly the bytes OpenSSL
 * signed. Nothing here depends on a private header or an unexported symbol.
 *
 * Reading the reference apart rather than trusting a second implementation of
 * it is the point: if this test built its own expected bytes, it would prove
 * only that the same author made the same assumption twice.
 */
#include "fhsm_composite.h"
#include "fhsm_common.h"

#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

static void show_diff(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
    printf("    lengths: reference %zu, ours %zu\n", na, nb);
    size_t n = na < nb ? na : nb;
    for (size_t i = 0; i < n; i++)
        if (a[i] != b[i]) {
            printf("    first difference at offset %zu: %02X vs %02X\n", i, a[i], b[i]);
            return;
        }
}

/* --- TLV reading, without depending on a private header ---------------- */
typedef struct { const uint8_t *tlv; size_t tlv_len; const uint8_t *val; size_t val_len; } tlv_t;

/* The i-th child of the content [p, p+n). Returns 0 if there are not enough. */
static int child(const uint8_t *p, size_t n, size_t idx, tlv_t *out) {
    const uint8_t *end = p + n;
    for (size_t i = 0; p < end; i++) {
        const uint8_t *start = p;
        long len; int tag, cls;
        int r = ASN1_get_object(&p, &len, &tag, &cls, (long)(end - start));
        if (r & 0x80) return 0;
        const uint8_t *val = p;
        p += len;
        if (i == idx) {
            out->tlv = start; out->tlv_len = (size_t)(p - start);
            out->val = val;   out->val_len = (size_t)len;
            return 1;
        }
    }
    return 0;
}

/* --- the OpenSSL reference ---------------------------------------------- */
typedef struct {
    X509 *ca, *leaf;
    EVP_PKEY *key;
    uint8_t *der; int der_len;          /* whole BasicOCSPResponse     */
    tlv_t tbs, rid, produced, responses, single;
} ref_t;

static void ref_free(ref_t *r) {
    X509_free(r->ca); X509_free(r->leaf); EVP_PKEY_free(r->key);
    OPENSSL_free(r->der);
    memset(r, 0, sizeof *r);
}

/* A small Ed25519 CA and a leaf, entirely in memory. */
static int make_pair(ref_t *r) {
    int good = 0;
    X509_NAME *nm = NULL;
    EVP_PKEY *lk = NULL;
    ASN1_INTEGER *sn = NULL;

    r->key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    lk     = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    r->ca   = X509_new();
    r->leaf = X509_new();
    if (!r->key || !lk || !r->ca || !r->leaf) goto out;

    nm = X509_NAME_new();
    if (!nm || X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                                          (const unsigned char *)"OCSP Ref CA",
                                          -1, -1, 0) != 1) goto out;

    sn = ASN1_INTEGER_new();
    if (!sn || ASN1_INTEGER_set(sn, 1) != 1) goto out;

    if (X509_set_version(r->ca, 2) != 1) goto out;
    if (X509_set_serialNumber(r->ca, sn) != 1) goto out;
    if (X509_set_subject_name(r->ca, nm) != 1) goto out;
    if (X509_set_issuer_name(r->ca, nm) != 1) goto out;
    if (!X509_gmtime_adj(X509_getm_notBefore(r->ca), 0)) goto out;
    if (!X509_gmtime_adj(X509_getm_notAfter(r->ca), 3650L * 86400)) goto out;
    if (X509_set_pubkey(r->ca, r->key) != 1) goto out;
    /* OCSP_cert_to_id hashes the issuer public key and needs the
     * subjectKeyIdentifier consistently absent or present; the minimum is
     * enough here, since the comparison is about our bytes. */
    if (X509_sign(r->ca, r->key, NULL) <= 0) goto out;

    if (ASN1_INTEGER_set(sn, 0x4711) != 1) goto out;
    if (X509_set_version(r->leaf, 2) != 1) goto out;
    if (X509_set_serialNumber(r->leaf, sn) != 1) goto out;
    if (X509_set_issuer_name(r->leaf, nm) != 1) goto out;
    if (X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                                   (const unsigned char *)"leaf", -1, -1, 0) != 1) goto out;
    if (X509_set_subject_name(r->leaf, nm) != 1) goto out;
    if (!X509_gmtime_adj(X509_getm_notBefore(r->leaf), 0)) goto out;
    if (!X509_gmtime_adj(X509_getm_notAfter(r->leaf), 365L * 86400)) goto out;
    if (X509_set_pubkey(r->leaf, lk) != 1) goto out;
    if (X509_sign(r->leaf, r->key, NULL) <= 0) goto out;
    good = 1;
out:
    X509_NAME_free(nm); EVP_PKEY_free(lk); ASN1_INTEGER_free(sn);
    return good;
}

/* status: V_OCSP_CERTSTATUS_*, reason: -1 for absent, with_next: nextUpdate */
static int ref_build(ref_t *r, int status, int reason, int with_next) {
    memset(r, 0, sizeof *r);
    int good = 0;
    OCSP_BASICRESP *bs = NULL;
    OCSP_CERTID *cid = NULL;
    ASN1_TIME *thisu = NULL, *nextu = NULL, *revt = NULL;

    if (!make_pair(r)) goto out;

    bs = OCSP_BASICRESP_new();
    if (!bs) goto out;

    /* SHA-256 on purpose: the CertID carries the hash the requester chose,
     * and nothing here forces SHA-1. */
    cid = OCSP_cert_to_id(EVP_sha256(), r->leaf, r->ca);
    if (!cid) goto out;

    thisu = ASN1_TIME_set(NULL, 1755000000);
    if (with_next) nextu = ASN1_TIME_set(NULL, 1755000000 + 7 * 86400);
    if (status == V_OCSP_CERTSTATUS_REVOKED) revt = ASN1_TIME_set(NULL, 1754000000);
    if (!thisu || (with_next && !nextu)) goto out;

    if (!OCSP_basic_add1_status(bs, cid, status, reason, revt, thisu, nextu)) goto out;
    cid = NULL;                              /* consumed */
    if (!OCSP_basic_add1_cert(bs, r->ca)) goto out;
    if (OCSP_basic_sign(bs, r->ca, r->key, NULL, NULL, 0) != 1) goto out;

    r->der_len = i2d_OCSP_BASICRESP(bs, &r->der);
    if (r->der_len <= 0) goto out;

    /* slicing: BasicOCSPResponse -> tbs, then the ResponseData fields */
    {
        const uint8_t *p = r->der; long l; int t, c;
        if (ASN1_get_object(&p, &l, &t, &c, r->der_len) & 0x80) goto out;
        if (!child(p, (size_t)l, 0, &r->tbs)) goto out;
        if (!child(r->tbs.val, r->tbs.val_len, 0, &r->rid)) goto out;
        if (!child(r->tbs.val, r->tbs.val_len, 1, &r->produced)) goto out;
        if (!child(r->tbs.val, r->tbs.val_len, 2, &r->responses)) goto out;
        if (!child(r->responses.val, r->responses.val_len, 0, &r->single)) goto out;
    }
    good = 1;
out:
    OCSP_CERTID_free(cid);
    ASN1_TIME_free(thisu); ASN1_TIME_free(nextu); ASN1_TIME_free(revt);
    OCSP_BASICRESP_free(bs);
    if (!good) ERR_print_errors_fp(stderr);
    return good;
}

/* --- les cas ------------------------------------------------------------ */

/* One SingleResponse, compared with OpenSSL's. The inner pieces -- CertID,
 * the times -- come from the reference: what is under test is the assembly,
 * not the ability to rebuild a CertID. */
static void case_single(const char *label, int status, int reason, int with_next)
{
    ref_t r;
    if (!ref_build(&r, status, reason, with_next)) { ok(0, label); return; }

    fhsm_composite_ocsp_single_t s;
    memset(&s, 0, sizeof s);
    s.reason = -1;

    tlv_t cid, st, thisu, nextu;
    int have_next = 0;
    if (!child(r.single.val, r.single.val_len, 0, &cid)
        || !child(r.single.val, r.single.val_len, 1, &st)
        || !child(r.single.val, r.single.val_len, 2, &thisu)) {
        ok(0, label); ref_free(&r); return;
    }
    have_next = child(r.single.val, r.single.val_len, 3, &nextu);

    s.cert_id = cid.tlv;  s.cert_id_len = cid.tlv_len;
    s.this_upd = thisu.tlv; s.this_upd_len = thisu.tlv_len;
    if (have_next) {
        /* nextUpdate is [0] EXPLICIT: pass the inner GeneralizedTime */
        tlv_t inner;
        if (child(nextu.val, nextu.val_len, 0, &inner)) {
            s.next_upd = inner.tlv; s.next_upd_len = inner.tlv_len;
        }
    }
    if (status == V_OCSP_CERTSTATUS_GOOD)    s.status = FHSM_OCSP_GOOD;
    if (status == V_OCSP_CERTSTATUS_UNKNOWN) s.status = FHSM_OCSP_UNKNOWN;
    if (status == V_OCSP_CERTSTATUS_REVOKED) {
        s.status = FHSM_OCSP_REVOKED;
        tlv_t rt;
        if (child(st.val, st.val_len, 0, &rt)) { s.revoked_at = rt.tlv; s.revoked_at_len = rt.tlv_len; }
        s.reason = reason;
    }

    uint8_t buf[1024]; size_t n = sizeof buf;
    fhsm_rv_t rv = fhsm_composite_ocsp_single(&s, buf, &n);
    int same = rv == FHSM_RV_OK && n == r.single.tlv_len
               && memcmp(buf, r.single.tlv, n) == 0;
    ok(same, label);
    if (!same) show_diff(r.single.tlv, r.single.tlv_len, buf, n);
    ref_free(&r);
}

/* The whole ResponseData. */
static void case_tbs(void)
{
    ref_t r;
    if (!ref_build(&r, V_OCSP_CERTSTATUS_GOOD, -1, 1)) {
        ok(0, "the ResponseData is identical to OpenSSL's"); return;
    }
    uint8_t buf[4096]; size_t n = sizeof buf;
    fhsm_rv_t rv = fhsm_composite_ocsp_tbs(r.rid.tlv, r.rid.tlv_len,
                                            r.produced.tlv, r.produced.tlv_len,
                                            r.responses.tlv, r.responses.tlv_len,
                                            NULL, 0, buf, &n);
    int same = rv == FHSM_RV_OK && n == r.tbs.tlv_len && memcmp(buf, r.tbs.tlv, n) == 0;
    ok(same, "the ResponseData is identical to OpenSSL's");
    if (!same) show_diff(r.tbs.tlv, r.tbs.tlv_len, buf, n);

    /* Proof the comparison can fail: one byte changed in the reference must
     * break it. Without this, a test comparing two empty buffers would pass
     * just as well. */
    if (same) {
        uint8_t *mut = OPENSSL_malloc(r.tbs.tlv_len);
        if (mut) {
            memcpy(mut, r.tbs.tlv, r.tbs.tlv_len);
            mut[r.tbs.tlv_len - 1] ^= 0x01;
            ok(memcmp(buf, mut, n) != 0,
               "and a single-byte mutation makes it fail");
            OPENSSL_free(mut);
        }
    }
    ref_free(&r);
}

/* Size query: the caller must be able to size the buffer without guessing. */
static void case_short_buffer(void)
{
    ref_t r;
    if (!ref_build(&r, V_OCSP_CERTSTATUS_GOOD, -1, 1)) {
        ok(0, "the size query returns the exact length"); return;
    }
    uint8_t probe[1]; size_t need = 0;
    fhsm_rv_t rv = fhsm_composite_ocsp_tbs(r.rid.tlv, r.rid.tlv_len,
                                            r.produced.tlv, r.produced.tlv_len,
                                            r.responses.tlv, r.responses.tlv_len,
                                            NULL, 0, probe, &need);
    ok(rv == FHSM_RV_BUFFER_TOO_SMALL && need == r.tbs.tlv_len,
       "the size query returns the exact length");
    ref_free(&r);
}

/* The refusals. Each one is a way of producing valid DER that says something
 * other than what the caller believes. */
static void case_args(void)
{
    uint8_t buf[512]; size_t n;
    const uint8_t seq[]  = { 0x30, 0x00 };
    const uint8_t gt[]   = { 0x18, 0x02, 0x30, 0x30 };
    const uint8_t a1[]   = { 0xA1, 0x00 };

    n = sizeof buf;
    ok(fhsm_composite_ocsp_tbs(NULL, 0, gt, sizeof gt, seq, sizeof seq,
                                NULL, 0, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "an absent responderID is refused");

    n = sizeof buf;
    ok(fhsm_composite_ocsp_tbs(seq, sizeof seq, gt, sizeof gt, seq, sizeof seq,
                                NULL, 0, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "a responderID that is neither [1] nor [2] is refused");

    n = sizeof buf;
    ok(fhsm_composite_ocsp_tbs(a1, sizeof a1, seq, sizeof seq, seq, sizeof seq,
                                NULL, 0, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "a producedAt that is not a GeneralizedTime is refused");

    n = sizeof buf;
    ok(fhsm_composite_ocsp_tbs(a1, sizeof a1, gt, sizeof gt, seq, sizeof seq,
                                seq, 0, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "an extensions pointer with no length is refused");

    fhsm_composite_ocsp_single_t s;
    memset(&s, 0, sizeof s);
    s.cert_id = seq; s.cert_id_len = sizeof seq;
    s.this_upd = gt; s.this_upd_len = sizeof gt;
    s.status = FHSM_OCSP_GOOD; s.reason = -1;

    s.revoked_at = gt; s.revoked_at_len = sizeof gt;
    n = sizeof buf;
    ok(fhsm_composite_ocsp_single(&s, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "a revocation date on a certificate reported good is refused");

    s.revoked_at = NULL; s.revoked_at_len = 0; s.reason = 1;
    n = sizeof buf;
    ok(fhsm_composite_ocsp_single(&s, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "a revocation reason without a revocation is refused");

    s.reason = -1; s.status = FHSM_OCSP_REVOKED;
    n = sizeof buf;
    ok(fhsm_composite_ocsp_single(&s, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "a revocation without a date is refused");
}

/* --- end to end, with a real composite key ------------------------------ */
typedef struct { fhsm_composite_alg_t alg; uint8_t *priv; size_t priv_len; } sctx_t;

static fhsm_rv_t local_sign(void *ctx, const uint8_t *tbs, size_t tbs_len,
                            uint8_t *sig, size_t *sig_len)
{
    sctx_t *s = ctx;
    return fhsm_composite_sign(s->alg, s->priv, s->priv_len,
                               tbs, tbs_len, NULL, 0, sig, sig_len);
}

static void case_end_to_end(void)
{
    ref_t r;
    if (!ref_build(&r, V_OCSP_CERTSTATUS_GOOD, -1, 1)) {
        ok(0, "a complete composite response is produced"); return;
    }

    static uint8_t priv[FHSM_COMPOSITE_PRIV_MAX], pub[FHSM_COMPOSITE_PUB_MAX];
    size_t pl = sizeof priv, ql = sizeof pub;
    fhsm_rv_t rv = fhsm_composite_keygen(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                          priv, &pl, pub, &ql);
    if (rv != FHSM_RV_OK) { ok(0, "a complete composite response is produced"); ref_free(&r); return; }

    sctx_t sc = { FHSM_COMPOSITE_MLDSA65_ED25519_SHA512, priv, pl };

    tlv_t cid, thisu;
    if (!child(r.single.val, r.single.val_len, 0, &cid)
        || !child(r.single.val, r.single.val_len, 2, &thisu)) {
        ok(0, "a complete composite response is produced"); ref_free(&r); return;
    }

    fhsm_composite_ocsp_single_t s;
    memset(&s, 0, sizeof s);
    s.cert_id = cid.tlv; s.cert_id_len = cid.tlv_len;
    s.this_upd = thisu.tlv; s.this_upd_len = thisu.tlv_len;
    s.status = FHSM_OCSP_GOOD; s.reason = -1;

    uint8_t *ca_der = NULL;
    int ca_n = i2d_X509(r.ca, &ca_der);
    if (ca_n <= 0) { ok(0, "a complete composite response is produced"); ref_free(&r); return; }

    static uint8_t out[16384]; size_t on = sizeof out;
    rv = fhsm_composite_ocsp(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                              ca_der, (size_t)ca_n,
                              r.produced.tlv, r.produced.tlv_len,
                              &s, 1, NULL, 0, local_sign, &sc, out, &on);
    ok(rv == FHSM_RV_OK, "a complete composite response is produced");

    if (rv == FHSM_RV_OK) {
        /* OpenSSL must be able to READ it even though it cannot verify it:
         * that is the difference between "a third party can inspect this"
         * and "a third party can do nothing with it". */
        const uint8_t *p = out;
        OCSP_BASICRESP *parsed = d2i_OCSP_BASICRESP(NULL, &p, (long)on);
        ok(parsed != NULL, "  and OpenSSL reads it despite the unknown algorithm");
        OCSP_BASICRESP_free(parsed);

        /* The signature must verify with our code, over the bytes as they
         * appear in the structure -- not as they were handed to the signer. */
        tlv_t tbs, sig;
        const uint8_t *q = out; long l; int t, c;
        if (!(ASN1_get_object(&q, &l, &t, &c, (long)on) & 0x80)
            && child(q, (size_t)l, 0, &tbs) && child(q, (size_t)l, 2, &sig)) {
            rv = fhsm_composite_verify(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                        pub, ql, tbs.tlv, tbs.tlv_len,
                                        NULL, 0, sig.val + 1, sig.val_len - 1);
            ok(rv == FHSM_RV_OK, "  and the signature covers the encoded ResponseData");
        } else {
            ok(0, "  and the signature covers the encoded ResponseData");
        }
    }
    OPENSSL_free(ca_der);
    ref_free(&r);
}

int main(void)
{
    printf("Composite OCSP -- differential comparison against OpenSSL\n\n");

    case_single("a 'good' SingleResponse with nextUpdate", V_OCSP_CERTSTATUS_GOOD, -1, 1);
    case_single("a 'good' SingleResponse without nextUpdate", V_OCSP_CERTSTATUS_GOOD, -1, 0);
    case_single("an 'unknown' SingleResponse", V_OCSP_CERTSTATUS_UNKNOWN, -1, 1);
    case_single("a 'revoked' SingleResponse with no reason", V_OCSP_CERTSTATUS_REVOKED, -1, 1);
    case_single("a 'revoked' SingleResponse, reason keyCompromise",
                V_OCSP_CERTSTATUS_REVOKED, OCSP_REVOKED_STATUS_KEYCOMPROMISE, 1);
    printf("\n");
    case_tbs();
    case_short_buffer();
    printf("\n");
    case_args();
    printf("\n");
    case_end_to_end();

    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
