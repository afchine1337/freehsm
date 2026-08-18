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
    printf("  %-62s %s\n", what, cond ? "OK" : "ECHEC");
    if (!cond) g_fail++;
}

static void show_diff(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
    printf("    longueurs : reference %zu, nous %zu\n", na, nb);
    size_t n = na < nb ? na : nb;
    for (size_t i = 0; i < n; i++)
        if (a[i] != b[i]) {
            printf("    premier ecart a l'offset %zu : %02X vs %02X\n", i, a[i], b[i]);
            return;
        }
}

/* --- lecture de TLV, sans dependre d'un en-tete prive ------------------- */
typedef struct { const uint8_t *tlv; size_t tlv_len; const uint8_t *val; size_t val_len; } tlv_t;

/* Le i-eme enfant du contenu [p, p+n). Renvoie 0 s'il n'y en a pas assez. */
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

/* --- la reference OpenSSL ----------------------------------------------- */
typedef struct {
    X509 *ca, *leaf;
    EVP_PKEY *key;
    uint8_t *der; int der_len;          /* BasicOCSPResponse complet   */
    tlv_t tbs, rid, produced, responses, single;
} ref_t;

static void ref_free(ref_t *r) {
    X509_free(r->ca); X509_free(r->leaf); EVP_PKEY_free(r->key);
    OPENSSL_free(r->der);
    memset(r, 0, sizeof *r);
}

/* Une petite AC Ed25519 et une feuille, entierement en memoire. */
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
    /* OCSP_cert_to_id hache la cle publique de l'emetteur ET a besoin du
     * subjectKeyIdentifier absent-ou-present de facon coherente ; on s'en
     * tient au strict necessaire, la comparaison porte sur nos octets. */
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

/* status : V_OCSP_CERTSTATUS_*, reason : -1 pour absent, with_next : nextUpdate */
static int ref_build(ref_t *r, int status, int reason, int with_next) {
    memset(r, 0, sizeof *r);
    int good = 0;
    OCSP_BASICRESP *bs = NULL;
    OCSP_CERTID *cid = NULL;
    ASN1_TIME *thisu = NULL, *nextu = NULL, *revt = NULL;

    if (!make_pair(r)) goto out;

    bs = OCSP_BASICRESP_new();
    if (!bs) goto out;

    /* SHA-256 volontairement : le CertID porte le hachage choisi par le
     * demandeur, et rien ici n'oblige a SHA-1. */
    cid = OCSP_cert_to_id(EVP_sha256(), r->leaf, r->ca);
    if (!cid) goto out;

    thisu = ASN1_TIME_set(NULL, 1755000000);
    if (with_next) nextu = ASN1_TIME_set(NULL, 1755000000 + 7 * 86400);
    if (status == V_OCSP_CERTSTATUS_REVOKED) revt = ASN1_TIME_set(NULL, 1754000000);
    if (!thisu || (with_next && !nextu)) goto out;

    if (!OCSP_basic_add1_status(bs, cid, status, reason, revt, thisu, nextu)) goto out;
    cid = NULL;                              /* consomme */
    if (!OCSP_basic_add1_cert(bs, r->ca)) goto out;
    if (OCSP_basic_sign(bs, r->ca, r->key, NULL, NULL, 0) != 1) goto out;

    r->der_len = i2d_OCSP_BASICRESP(bs, &r->der);
    if (r->der_len <= 0) goto out;

    /* decoupage : BasicOCSPResponse -> tbs, puis les champs de ResponseData */
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

/* Un SingleResponse, compare a celui d'OpenSSL. Les morceaux internes --
 * CertID, les temps -- viennent de la reference : ce qui est teste est
 * l'assemblage, pas la capacite a reconstruire un CertID. */
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
        /* nextUpdate est [0] EXPLICIT : on passe la GeneralizedTime interne */
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

/* Le ResponseData entier. */
static void case_tbs(void)
{
    ref_t r;
    if (!ref_build(&r, V_OCSP_CERTSTATUS_GOOD, -1, 1)) {
        ok(0, "le ResponseData est identique a celui d'OpenSSL"); return;
    }
    uint8_t buf[4096]; size_t n = sizeof buf;
    fhsm_rv_t rv = fhsm_composite_ocsp_tbs(r.rid.tlv, r.rid.tlv_len,
                                            r.produced.tlv, r.produced.tlv_len,
                                            r.responses.tlv, r.responses.tlv_len,
                                            NULL, 0, buf, &n);
    int same = rv == FHSM_RV_OK && n == r.tbs.tlv_len && memcmp(buf, r.tbs.tlv, n) == 0;
    ok(same, "le ResponseData est identique a celui d'OpenSSL");
    if (!same) show_diff(r.tbs.tlv, r.tbs.tlv_len, buf, n);

    /* La preuve que la comparaison peut echouer : un octet change dans la
     * reference doit faire tomber le test. Sans ca, un test qui compare deux
     * buffers vides passerait aussi. */
    if (same) {
        uint8_t *mut = OPENSSL_malloc(r.tbs.tlv_len);
        if (mut) {
            memcpy(mut, r.tbs.tlv, r.tbs.tlv_len);
            mut[r.tbs.tlv_len - 1] ^= 0x01;
            ok(memcmp(buf, mut, n) != 0,
               "et une mutation d'un seul octet la fait echouer");
            OPENSSL_free(mut);
        }
    }
    ref_free(&r);
}

/* Requete de taille : l'appelant doit pouvoir dimensionner sans deviner. */
static void case_short_buffer(void)
{
    ref_t r;
    if (!ref_build(&r, V_OCSP_CERTSTATUS_GOOD, -1, 1)) {
        ok(0, "la requete de taille renvoie la longueur exacte"); return;
    }
    uint8_t probe[1]; size_t need = 0;
    fhsm_rv_t rv = fhsm_composite_ocsp_tbs(r.rid.tlv, r.rid.tlv_len,
                                            r.produced.tlv, r.produced.tlv_len,
                                            r.responses.tlv, r.responses.tlv_len,
                                            NULL, 0, probe, &need);
    ok(rv == FHSM_RV_BUFFER_TOO_SMALL && need == r.tbs.tlv_len,
       "la requete de taille renvoie la longueur exacte");
    ref_free(&r);
}

/* Les refus. Chacun correspond a une facon d'obtenir du DER valide qui dit
 * autre chose que ce que l'appelant croit. */
static void case_args(void)
{
    uint8_t buf[512]; size_t n;
    const uint8_t seq[]  = { 0x30, 0x00 };
    const uint8_t gt[]   = { 0x18, 0x02, 0x30, 0x30 };
    const uint8_t a1[]   = { 0xA1, 0x00 };

    n = sizeof buf;
    ok(fhsm_composite_ocsp_tbs(NULL, 0, gt, sizeof gt, seq, sizeof seq,
                                NULL, 0, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "un responderID absent est refuse");

    n = sizeof buf;
    ok(fhsm_composite_ocsp_tbs(seq, sizeof seq, gt, sizeof gt, seq, sizeof seq,
                                NULL, 0, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "un responderID qui n'est ni [1] ni [2] est refuse");

    n = sizeof buf;
    ok(fhsm_composite_ocsp_tbs(a1, sizeof a1, seq, sizeof seq, seq, sizeof seq,
                                NULL, 0, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "un producedAt qui n'est pas une GeneralizedTime est refuse");

    n = sizeof buf;
    ok(fhsm_composite_ocsp_tbs(a1, sizeof a1, gt, sizeof gt, seq, sizeof seq,
                                seq, 0, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "un pointeur d'extensions sans longueur est refuse");

    fhsm_composite_ocsp_single_t s;
    memset(&s, 0, sizeof s);
    s.cert_id = seq; s.cert_id_len = sizeof seq;
    s.this_upd = gt; s.this_upd_len = sizeof gt;
    s.status = FHSM_OCSP_GOOD; s.reason = -1;

    s.revoked_at = gt; s.revoked_at_len = sizeof gt;
    n = sizeof buf;
    ok(fhsm_composite_ocsp_single(&s, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "une date de revocation sur un certificat declare bon est refusee");

    s.revoked_at = NULL; s.revoked_at_len = 0; s.reason = 1;
    n = sizeof buf;
    ok(fhsm_composite_ocsp_single(&s, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "un motif de revocation sans revocation est refuse");

    s.reason = -1; s.status = FHSM_OCSP_REVOKED;
    n = sizeof buf;
    ok(fhsm_composite_ocsp_single(&s, buf, &n) == FHSM_RV_ARGUMENTS_BAD,
       "une revocation sans date est refusee");
}

/* --- bout en bout, avec une vraie cle composite ------------------------- */
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
        ok(0, "une reponse composite complete est produite"); return;
    }

    static uint8_t priv[FHSM_COMPOSITE_PRIV_MAX], pub[FHSM_COMPOSITE_PUB_MAX];
    size_t pl = sizeof priv, ql = sizeof pub;
    fhsm_rv_t rv = fhsm_composite_keygen(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                          priv, &pl, pub, &ql);
    if (rv != FHSM_RV_OK) { ok(0, "une reponse composite complete est produite"); ref_free(&r); return; }

    sctx_t sc = { FHSM_COMPOSITE_MLDSA65_ED25519_SHA512, priv, pl };

    tlv_t cid, thisu;
    if (!child(r.single.val, r.single.val_len, 0, &cid)
        || !child(r.single.val, r.single.val_len, 2, &thisu)) {
        ok(0, "une reponse composite complete est produite"); ref_free(&r); return;
    }

    fhsm_composite_ocsp_single_t s;
    memset(&s, 0, sizeof s);
    s.cert_id = cid.tlv; s.cert_id_len = cid.tlv_len;
    s.this_upd = thisu.tlv; s.this_upd_len = thisu.tlv_len;
    s.status = FHSM_OCSP_GOOD; s.reason = -1;

    uint8_t *ca_der = NULL;
    int ca_n = i2d_X509(r.ca, &ca_der);
    if (ca_n <= 0) { ok(0, "une reponse composite complete est produite"); ref_free(&r); return; }

    static uint8_t out[16384]; size_t on = sizeof out;
    rv = fhsm_composite_ocsp(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                              ca_der, (size_t)ca_n,
                              r.produced.tlv, r.produced.tlv_len,
                              &s, 1, NULL, 0, local_sign, &sc, out, &on);
    ok(rv == FHSM_RV_OK, "une reponse composite complete est produite");

    if (rv == FHSM_RV_OK) {
        /* OpenSSL doit savoir la LIRE, meme sans savoir la verifier : c'est
         * la difference entre "un tiers peut l'inspecter" et "un tiers ne
         * peut rien en faire". */
        const uint8_t *p = out;
        OCSP_BASICRESP *parsed = d2i_OCSP_BASICRESP(NULL, &p, (long)on);
        ok(parsed != NULL, "  et OpenSSL la lit malgre l'algorithme inconnu");
        OCSP_BASICRESP_free(parsed);

        /* La signature doit verifier avec notre code, sur les octets tels
         * qu'ils apparaissent dans la structure -- pas tels qu'on les a
         * donnes au signeur. */
        tlv_t tbs, sig;
        const uint8_t *q = out; long l; int t, c;
        if (!(ASN1_get_object(&q, &l, &t, &c, (long)on) & 0x80)
            && child(q, (size_t)l, 0, &tbs) && child(q, (size_t)l, 2, &sig)) {
            rv = fhsm_composite_verify(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                        pub, ql, tbs.tlv, tbs.tlv_len,
                                        NULL, 0, sig.val + 1, sig.val_len - 1);
            ok(rv == FHSM_RV_OK, "  et la signature couvre bien le ResponseData encode");
        } else {
            ok(0, "  et la signature couvre bien le ResponseData encode");
        }
    }
    OPENSSL_free(ca_der);
    ref_free(&r);
}

int main(void)
{
    printf("OCSP composite -- comparaison differentielle contre OpenSSL\n\n");

    case_single("un SingleResponse 'good' avec nextUpdate", V_OCSP_CERTSTATUS_GOOD, -1, 1);
    case_single("un SingleResponse 'good' sans nextUpdate", V_OCSP_CERTSTATUS_GOOD, -1, 0);
    case_single("un SingleResponse 'unknown'", V_OCSP_CERTSTATUS_UNKNOWN, -1, 1);
    case_single("un SingleResponse 'revoked' sans motif", V_OCSP_CERTSTATUS_REVOKED, -1, 1);
    case_single("un SingleResponse 'revoked' avec motif keyCompromise",
                V_OCSP_CERTSTATUS_REVOKED, OCSP_REVOKED_STATUS_KEYCOMPROMISE, 1);
    printf("\n");
    case_tbs();
    case_short_buffer();
    printf("\n");
    case_args();
    printf("\n");
    case_end_to_end();

    printf("\n%s : %d echec(s)\n", g_fail ? "ECHEC" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
