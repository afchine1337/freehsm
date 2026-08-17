/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * The CMS SignerInfo and SignedData assemblers, against OpenSSL's own.
 *
 * Same obstacle as the revocation lists, one level deeper. OpenSSL builds the
 * SignedData envelope -- CMS_sign(CMS_PARTIAL) succeeds -- but CMS_add1_signer
 * refuses a composite certificate: X509_get_pubkey cannot load a key whose
 * OID has no provider, and the call fails with "private key does not match
 * certificate". Measured before any of this was written.
 *
 * The oracle: sign with OpenSSL over Ed25519, take the result apart, feed the
 * same parts back to the assemblers, and require the output to be identical
 * byte for byte.
 *
 * The one thing this file exists to catch above all others: RFC 5652 5.4 says
 * the signature is computed over the signed attributes in their SET OF form
 * (0x31) while the structure transmits them under [0] IMPLICIT (0xA0). Sign
 * one, send the other, and the result verifies nowhere.
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/cms.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include "fhsm_composite.h"

#define CALG FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
static uint8_t g_priv[FHSM_COMPOSITE_PRIV_MAX], g_pub[FHSM_COMPOSITE_PUB_MAX];
static size_t  g_priv_len = 0;

/* In production this is the PKCS#11 path; the seam exists so the private key
 * never has to leave the token. */
static fhsm_rv_t local_sign(void *c, const uint8_t *m, size_t n,
                             uint8_t *s, size_t *sl) {
    (void)c;
    return fhsm_composite_sign(CALG, g_priv, g_priv_len, m, n, NULL, 0, s, sl);
}

static int g_fail = 0;
static void ok(int c, const char *w) {
    printf("  [%s] %s\n", c ? "PASS" : "FAIL", w);
    if (!c) g_fail++;
}
static void show_diff(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
    size_t n = na < nb ? na : nb, i = 0;
    while (i < n && a[i] == b[i]) i++;
    printf("      lengths: reference %zu, assembled %zu\n", na, nb);
    if (i < n) printf("      first difference at offset %zu: %02X vs %02X\n", i, a[i], b[i]);
    size_t lo = i > 8 ? i - 8 : 0, hi = i + 12;
    printf("      reference "); for (size_t k = lo; k < hi && k < na; k++) printf("%02X ", a[k]);
    printf("\n      assembled "); for (size_t k = lo; k < hi && k < nb; k++) printf("%02X ", b[k]);
    printf("\n");
}

/* ---------------------------------------------------------------------------
 * A minimal DER reader. i2d_CMS_SignerInfo does not exist -- only
 * CMS_ContentInfo has ASN.1 functions -- so reaching the SignerInfo bytes
 * inside the reference means walking to them. Twenty lines, and it only has
 * to handle definite-length TLVs, which is all DER produces.
 * ------------------------------------------------------------------------- */
typedef struct { const uint8_t *p; size_t len; uint8_t tag; const uint8_t *val; size_t vlen; } tlv_t;

static int tlv_at(const uint8_t *p, size_t avail, tlv_t *t) {
    if (avail < 2) return 0;
    t->p = p; t->tag = p[0];
    size_t hl = 2, n = p[1];
    if (n & 0x80) {
        size_t k = n & 0x7F;
        if (k == 0 || k > 4 || avail < 2 + k) return 0;   /* no indefinite in DER */
        n = 0;
        for (size_t i = 0; i < k; i++) n = (n << 8) | p[2 + i];
        hl = 2 + k;
    }
    if (avail < hl + n) return 0;
    t->val = p + hl; t->vlen = n; t->len = hl + n;
    return 1;
}

/* Descend into a constructed TLV and return its i-th child. */
static int tlv_child(const tlv_t *parent, size_t idx, tlv_t *out) {
    const uint8_t *p = parent->val; size_t left = parent->vlen;
    for (size_t i = 0; ; i++) {
        tlv_t t;
        if (!left || !tlv_at(p, left, &t)) return 0;
        if (i == idx) { *out = t; return 1; }
        p += t.len; left -= t.len;
    }
}

/* ContentInfo -> [0] -> SignedData -> signerInfos (SET OF) -> first SignerInfo */
static int find_signerinfo(const uint8_t *der, size_t len, tlv_t *out) {
    tlv_t ci, c0, sd, sis;
    if (!tlv_at(der, len, &ci))            return 0;   /* ContentInfo SEQUENCE */
    if (!tlv_child(&ci, 1, &c0))           return 0;   /* [0] EXPLICIT         */
    if (!tlv_at(c0.val, c0.vlen, &sd))     return 0;   /* SignedData SEQUENCE  */
    /* Children: version, digestAlgorithms, encapContentInfo, then optional
     * [0] certs and [1] crls, then signerInfos. Walk to the trailing SET. */
    const uint8_t *p = sd.val; size_t left = sd.vlen; tlv_t t, last;
    int have = 0;
    while (left) {
        if (!tlv_at(p, left, &t)) return 0;
        last = t; have = 1;
        p += t.len; left -= t.len;
    }
    if (!have || last.tag != 0x31) return 0;           /* SET OF SignerInfo    */
    sis = last;
    return tlv_child(&sis, 0, out);
}

int main(void)
{
    printf("== CMS SignerInfo / SignedData vs OpenSSL ==\n");

    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    X509 *crt = X509_new();
    X509_NAME *nm = X509_NAME_new();
    ASN1_INTEGER *sn = ASN1_INTEGER_new();
    if (!key || !crt || !nm || !sn) { printf("  setup failed\n"); return 2; }
    X509_NAME_add_entry_by_txt(nm, "C",  MBSTRING_ASC, (const unsigned char*)"FR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "O",  MBSTRING_ASC, (const unsigned char*)"Simorgh Labs", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char*)"CMS Ref", -1, -1, 0);
    ASN1_INTEGER_set(sn, 0x4A3B2C1D);
    X509_set_version(crt, 2);
    X509_set_subject_name(crt, nm);
    X509_set_issuer_name(crt, nm);
    X509_set_serialNumber(crt, sn);
    X509_gmtime_adj(X509_getm_notBefore(crt), 0);
    X509_gmtime_adj(X509_getm_notAfter(crt), 365L * 86400);
    X509_set_pubkey(crt, key);
    if (X509_sign(crt, key, NULL) <= 0) { printf("  self-sign failed\n"); return 2; }

    static const unsigned char content[] = "hello cms";
    const size_t clen = sizeof content - 1;

    /* CMS_PARTIAL, then add the signer with an explicit digest: Ed25519 has
     * no default one in the CMS layer, and CMS_sign() alone fails with
     * "no default digest". */
    CMS_ContentInfo *cms = CMS_sign(NULL, NULL, NULL, NULL,
                                     CMS_PARTIAL | CMS_DETACHED | CMS_BINARY);
    ok(cms != NULL, "CMS_sign(CMS_PARTIAL) builds the envelope");
    if (!cms) { ERR_print_errors_fp(stderr); return 1; }

    CMS_SignerInfo *si = CMS_add1_signer(cms, crt, key, EVP_sha512(),
                                          CMS_PARTIAL | CMS_NOSMIMECAP);
    ok(si != NULL, "CMS_add1_signer accepts an Ed25519 certificate");
    if (!si) { ERR_print_errors_fp(stderr); return 1; }

    /* A first version of this test deleted signingTime here and asserted two
     * attributes remained. Both assertions failed, and the reason is worth
     * keeping: under CMS_PARTIAL, OpenSSL adds signingTime and messageDigest
     * inside CMS_final, not in CMS_add1_signer. At this point only
     * contentType exists, so there was nothing to delete and nothing to
     * count. The attribute set is therefore whatever CMS_final decides, and
     * that is fine -- the assembler carries what it is handed and asserts
     * nothing about how many attributes there are. */
    printf("      before CMS_final: %d signed attribute(s)\n",
           CMS_signed_get_attr_count(si));

    {
        BIO *in = BIO_new_mem_buf(content, (int)clen);
        int r = CMS_final(cms, in, NULL, CMS_DETACHED | CMS_BINARY);
        BIO_free(in);
        ok(r == 1, "CMS_final digests the content and signs the attributes");
        if (!r) { ERR_print_errors_fp(stderr); return 1; }
    }

    {
        int n = CMS_signed_get_attr_count(si);
        int st = CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1);
        int md = CMS_signed_get_attr_by_NID(si, NID_pkcs9_messageDigest, -1);
        printf("      after CMS_final: %d attributes"
               " (signingTime %s, messageDigest %s)\n",
               n, st >= 0 ? "present" : "absent", md >= 0 ? "present" : "absent");
        ok(md >= 0, "CMS_final added the messageDigest attribute");
    }

    uint8_t *ref = NULL;
    int ref_len = i2d_CMS_ContentInfo(cms, &ref);
    ok(ref_len > 0, "the reference CMS encodes");
    if (ref_len <= 0) return 1;

    /* ---- locate its SignerInfo ------------------------------------------ */
    tlv_t rsi;
    ok(find_signerinfo(ref, (size_t)ref_len, &rsi), "its SignerInfo can be located");
    if (!g_fail) printf("      SignerInfo at offset %zu, %zu bytes\n",
                        (size_t)(rsi.p - ref), rsi.len);

    /* ---- take the parts apart ------------------------------------------- */
    X509_NAME *iss = NULL; ASN1_INTEGER *ser = NULL;
    CMS_SignerInfo_get0_signer_id(si, NULL, &iss, &ser);
    X509_ALGOR *dig = NULL, *sga = NULL;
    CMS_SignerInfo_get0_algs(si, NULL, NULL, &dig, &sga);
    ASN1_OCTET_STRING *sv = CMS_SignerInfo_get0_signature(si);

    uint8_t *d_iss = NULL, *d_ser = NULL, *d_dig = NULL, *d_sga = NULL;
    int n_iss = i2d_X509_NAME(iss, &d_iss);
    int n_ser = i2d_ASN1_INTEGER(ser, &d_ser);
    int n_dig = i2d_X509_ALGOR(dig, &d_dig);
    int n_sga = i2d_X509_ALGOR(sga, &d_sga);
    ok(n_iss > 0 && n_ser > 0 && n_dig > 0 && n_sga > 0 && sv,
       "issuer, serial, both algorithms and the signature are reachable");

    /* The signed attributes, in the form that was signed. They sit in the
     * reference under [0] IMPLICIT; the SET OF form is the same bytes with
     * the identifier changed -- which is exactly the substitution the
     * assembler has to perform in the other direction. */
    static uint8_t attrs_set[4096]; size_t attrs_len = 0;
    {
        tlv_t a;
        int found = 0;
        for (size_t i = 0; tlv_child(&rsi, i, &a); i++)
            if (a.tag == 0xA0) { found = 1; break; }
        ok(found, "the signed attributes are present, under [0] IMPLICIT");
        if (found && a.len <= sizeof attrs_set) {
            memcpy(attrs_set, a.p, a.len);
            attrs_set[0] = 0x31;                      /* [0] -> SET OF */
            attrs_len = a.len;
        }
    }

    /* ---- the comparison -------------------------------------------------- */
    static uint8_t mine[8192]; size_t mine_len = sizeof mine;
    fhsm_rv_t rv = fhsm_composite_cms_signerinfo(
        d_iss, (size_t)n_iss, d_ser, (size_t)n_ser,
        d_dig, (size_t)n_dig, attrs_set, attrs_len,
        d_sga, (size_t)n_sga,
        ASN1_STRING_get0_data((const ASN1_STRING *)sv),
        (size_t)ASN1_STRING_length((const ASN1_STRING *)sv),
        mine, &mine_len);
    ok(rv == FHSM_RV_OK, "the assembler produces a SignerInfo");
    if (rv == FHSM_RV_OK) {
        int same = mine_len == rsi.len && memcmp(mine, rsi.p, mine_len) == 0;
        ok(same, "identical to OpenSSL's SignerInfo, byte for byte");
        if (!same) show_diff(rsi.p, rsi.len, mine, mine_len);
    }

    printf("\n== the retag, which is the whole point ==\n");
    {
        /* Attributes handed over already in [0] form must be refused: taking
         * both would mean signing one encoding and transmitting another, and
         * nothing downstream distinguishes the two. */
        static uint8_t bad[4096]; memcpy(bad, attrs_set, attrs_len); bad[0] = 0xA0;
        size_t n = sizeof mine;
        ok(fhsm_composite_cms_signerinfo(d_iss, (size_t)n_iss, d_ser, (size_t)n_ser,
                                          d_dig, (size_t)n_dig, bad, attrs_len,
                                          d_sga, (size_t)n_sga,
                                          ASN1_STRING_get0_data((const ASN1_STRING *)sv),
                                          (size_t)ASN1_STRING_length((const ASN1_STRING *)sv),
                                          mine, &n) == FHSM_RV_ARGUMENTS_BAD,
           "attributes passed in [0] form are refused, not accepted quietly");
        /* And the output really does carry 0xA0 where the input had 0x31. */
        size_t k = 0, hits = 0;
        for (k = 0; k + attrs_len <= mine_len; k++)
            if (mine[k] == 0xA0 && memcmp(mine + k + 1, attrs_set + 1, attrs_len - 1) == 0) hits++;
        ok(hits == 1, "the emitted SignerInfo carries them once, under [0]");
    }

    /* ---- the envelope ---------------------------------------------------
     * Same method one level out: take the reference's own digestAlgorithms
     * entry and certificate set, hand them to the wrapper, and require the
     * whole ContentInfo to come back identical. This is where the two
     * remaining retags live -- [0] IMPLICIT for the certificates, and [0]
     * EXPLICIT for the SignedData itself, which are different operations
     * that look alike in the ASN.1 and are easy to interchange. */
    printf("\n== the SignedData envelope ==\n");
    {
        tlv_t ci, c0, sd;
        int walked = tlv_at(ref, (size_t)ref_len, &ci)
                  && tlv_child(&ci, 1, &c0)
                  && tlv_at(c0.val, c0.vlen, &sd);
        ok(walked, "the reference SignedData can be reached");

        /* digestAlgorithms is child 1, a SET OF with one entry. */
        tlv_t das, da1;
        ok(walked && tlv_child(&sd, 1, &das) && das.tag == 0x31
                  && tlv_child(&das, 0, &da1),
           "its single digestAlgorithm is readable");

        /* certificates is the [0] IMPLICIT among the children. */
        static uint8_t certs_set[8192]; size_t certs_len = 0;
        {
            tlv_t t;
            for (size_t i = 0; tlv_child(&sd, i, &t); i++)
                if (t.tag == 0xA0 && t.len <= sizeof certs_set) {
                    memcpy(certs_set, t.p, t.len);
                    certs_set[0] = 0x31;              /* [0] -> SET OF */
                    certs_len = t.len;
                    break;
                }
            ok(certs_len > 0, "the embedded certificate set is readable");
        }

        static uint8_t whole[16384]; size_t whole_len = sizeof whole;
        fhsm_rv_t wr = fhsm_composite_cms_wrap(da1.p, da1.len,
                                                certs_set, certs_len,
                                                mine, mine_len,
                                                whole, &whole_len);
        ok(wr == FHSM_RV_OK, "the wrapper produces a ContentInfo");
        if (wr == FHSM_RV_OK) {
            int same = whole_len == (size_t)ref_len
                    && memcmp(whole, ref, whole_len) == 0;
            ok(same, "identical to OpenSSL's whole CMS, byte for byte");
            if (!same) show_diff(ref, (size_t)ref_len, whole, whole_len);
        }

        /* Certificates already in [0] form must be refused, same reasoning
         * as the attributes: accepting both would make the retag a guess. */
        static uint8_t bad[8192];
        if (certs_len) {
            memcpy(bad, certs_set, certs_len); bad[0] = 0xA0;
            size_t n = sizeof whole;
            ok(fhsm_composite_cms_wrap(da1.p, da1.len, bad, certs_len,
                                        mine, mine_len, whole, &n)
               == FHSM_RV_ARGUMENTS_BAD,
               "certificates passed in [0] form are refused");
        }

        /* And with no certificates at all: the field is optional, and its
         * absence must be an omission rather than an empty SET. */
        size_t n = sizeof whole;
        fhsm_rv_t nr = fhsm_composite_cms_wrap(da1.p, da1.len, NULL, 0,
                                                mine, mine_len, whole, &n);
        ok(nr == FHSM_RV_OK, "a ContentInfo without certificates is produced");
        if (nr == FHSM_RV_OK) {
            const uint8_t *q = whole;
            CMS_ContentInfo *p2 = d2i_CMS_ContentInfo(NULL, &q, (long)n);
            ok(p2 != NULL, "and OpenSSL parses it");
            if (p2) {
                STACK_OF(X509) *cs = CMS_get1_certs(p2);
                ok(cs == NULL || sk_X509_num(cs) == 0, "with no certificates in it");
                sk_X509_pop_free(cs, X509_free);
                CMS_ContentInfo_free(p2);
            }
        }
    }

    OPENSSL_free(d_iss); OPENSSL_free(d_ser); OPENSSL_free(d_dig); OPENSSL_free(d_sga);
    OPENSSL_free(ref);
    CMS_ContentInfo_free(cms);
    X509_free(crt); X509_NAME_free(nm); ASN1_INTEGER_free(sn); EVP_PKEY_free(key);

    /* ---- end to end: a real composite CMS ------------------------------
     * The assemblers are proven against OpenSSL's bytes. What remains is
     * whether the finished object is one a third party can read, and whether
     * the signature covers what a verifier recomputes -- which is not the
     * same as covering what we happened to hand the signer. */
    printf("\n== end to end: a composite CMS, read back by OpenSSL ==\n");
    {
        size_t cpl = sizeof g_priv, cbl = sizeof g_pub;
        ok(fhsm_composite_keygen(CALG, g_priv, &cpl, g_pub, &cbl) == FHSM_RV_OK,
           "composite key pair generated");
        g_priv_len = cpl;

        static uint8_t ccert[16384]; size_t ccl = sizeof ccert;
        ok(fhsm_composite_selfsigned(CALG, "/C=FR/O=Simorgh Labs/CN=CMS Signer",
                                      1, 365, g_pub, cbl, local_sign, NULL,
                                      ccert, &ccl) == FHSM_RV_OK,
           "self-signed composite signer certificate");

        uint8_t dg[64]; unsigned int dl = 0;
        {
            EVP_MD *m = EVP_MD_fetch(NULL, "SHA512", NULL);
            EVP_MD_CTX *c = EVP_MD_CTX_new();
            ok(m && c && EVP_DigestInit_ex(c, m, NULL) == 1
               && EVP_DigestUpdate(c, content, clen) == 1
               && EVP_DigestFinal_ex(c, dg, &dl) == 1 && dl == 64,
               "SHA-512 of the content computed by the caller");
            EVP_MD_CTX_free(c); EVP_MD_free(m);
        }

        static uint8_t p7[32768]; size_t p7l = sizeof p7;
        ok(fhsm_composite_cms(CALG, ccert, ccl, dg, 64, local_sign, NULL,
                               p7, &p7l) == FHSM_RV_OK,
           "a composite CMS is produced");
        printf("      %zu bytes\n", p7l);

        /* A digest of the wrong length is a caller who hashed with something
         * else; the messageDigest would then attest to nothing recomputable. */
        {
            size_t n = sizeof p7;
            ok(fhsm_composite_cms(CALG, ccert, ccl, dg, 32, local_sign, NULL,
                                   p7, &n) == FHSM_RV_ARGUMENTS_BAD,
               "a 32-byte digest is refused");
        }

        const uint8_t *q = p7;
        CMS_ContentInfo *mine_cms = d2i_CMS_ContentInfo(NULL, &q, (long)p7l);
        ok(mine_cms != NULL, "OpenSSL parses it");
        ok(mine_cms && (size_t)(q - p7) == p7l, "with no trailing bytes");
        if (!mine_cms) { ERR_print_errors_fp(stderr); goto e2e_done; }

        {
            STACK_OF(CMS_SignerInfo) *ss = CMS_get0_SignerInfos(mine_cms);
            ok(sk_CMS_SignerInfo_num(ss) == 1, "one SignerInfo");
            CMS_SignerInfo *s2 = sk_CMS_SignerInfo_value(ss, 0);
            X509_ALGOR *d2 = NULL, *s2a = NULL;
            CMS_SignerInfo_get0_algs(s2, NULL, NULL, &d2, &s2a);
            const ASN1_OBJECT *o = NULL; int pt = 0; const void *pv = NULL;
            X509_ALGOR_get0(&o, &pt, &pv, s2a);
            char b[128] = ""; OBJ_obj2txt(b, sizeof b, o, 1);
            ok(strcmp(b, FHSM_COMPOSITE_OID_MLDSA65_ED25519) == 0,
               "its signatureAlgorithm is the composite OID");
            ok(pt == V_ASN1_UNDEF, "parameters absent, as the draft requires");

            ok(CMS_signed_get_attr_by_NID(s2, NID_pkcs9_contentType, -1) >= 0,
               "contentType is among the signed attributes");
            int mdl = CMS_signed_get_attr_by_NID(s2, NID_pkcs9_messageDigest, -1);
            ok(mdl >= 0, "messageDigest too");
            if (mdl >= 0) {
                X509_ATTRIBUTE *at = CMS_signed_get_attr(s2, mdl);
                ASN1_TYPE *v = X509_ATTRIBUTE_get0_type(at, 0);
                ok(v && v->type == V_ASN1_OCTET_STRING
                   && ASN1_STRING_length(v->value.octet_string) == 64
                   && memcmp(ASN1_STRING_get0_data(v->value.octet_string), dg, 64) == 0,
                   "and it is exactly SHA-512 of the content");
            }
            STACK_OF(X509) *cs = CMS_get1_certs(mine_cms);
            ok(cs && sk_X509_num(cs) == 1, "the signer certificate is embedded");
            sk_X509_pop_free(cs, X509_free);
        }

        /* The check that matters. Re-encode what OpenSSL parsed, find the
         * signed attributes in that re-encoding, put them back in SET OF form,
         * and verify. If our assembly had been anything OpenSSL normalises
         * differently, the bytes a verifier recomputes would not be the bytes
         * we signed, and this is where that shows. */
        {
            uint8_t *re = NULL;
            int re_n = i2d_CMS_ContentInfo(mine_cms, &re);
            ok(re_n > 0, "OpenSSL re-encodes it");
            tlv_t si2, at;
            int found = 0;
            if (re_n > 0 && find_signerinfo(re, (size_t)re_n, &si2))
                for (size_t k = 0; tlv_child(&si2, k, &at); k++)
                    if (at.tag == 0xA0) { found = 1; break; }
            ok(found, "its signed attributes are locatable in the re-encoding");
            if (found) {
                static uint8_t signed_form[4096];
                memcpy(signed_form, at.p, at.len);
                signed_form[0] = 0x31;
                /* and the signature, from the same re-encoded structure */
                STACK_OF(CMS_SignerInfo) *ss = CMS_get0_SignerInfos(mine_cms);
                CMS_SignerInfo *s2 = sk_CMS_SignerInfo_value(ss, 0);
                ASN1_OCTET_STRING *sg = CMS_SignerInfo_get0_signature(s2);
                fhsm_rv_t vr = fhsm_composite_verify(
                    CALG, g_pub, cbl, signed_form, at.len, NULL, 0,
                    ASN1_STRING_get0_data((const ASN1_STRING *)sg),
                    (size_t)ASN1_STRING_length((const ASN1_STRING *)sg));
                ok(vr == FHSM_RV_OK,
                   "the composite signature verifies over the re-encoded attributes");

                signed_form[at.len / 2] ^= 0x01;
                vr = fhsm_composite_verify(
                    CALG, g_pub, cbl, signed_form, at.len, NULL, 0,
                    ASN1_STRING_get0_data((const ASN1_STRING *)sg),
                    (size_t)ASN1_STRING_length((const ASN1_STRING *)sg));
                ok(vr != FHSM_RV_OK, "one flipped byte breaks it");
            }
            OPENSSL_free(re);
        }
        /* ---- the verifier, which needs neither token nor key ------------ */
        printf("\n== verification from the file alone ==\n");
        ok(fhsm_composite_cms_verify(CALG, p7, p7l, dg, 64) == FHSM_RV_OK,
           "the CMS verifies against the content digest");

        {   /* A different digest means the data changed: that is a signature
             * failure, not a malformed file, and the two must not collapse. */
            uint8_t other[64]; memcpy(other, dg, 64); other[0] ^= 1;
            ok(fhsm_composite_cms_verify(CALG, p7, p7l, other, 64)
               == FHSM_RV_SIGNATURE_INVALID,
               "a different content digest is rejected as SIGNATURE_INVALID");
        }
        {   /* A byte flipped inside the signature. */
            static uint8_t t[32768]; memcpy(t, p7, p7l);
            t[p7l - 20] ^= 0x01;
            fhsm_rv_t r = fhsm_composite_cms_verify(CALG, t, p7l, dg, 64);
            ok(r != FHSM_RV_OK, "a tampered structure is refused");
        }
        {   /* Something that is not a CMS at all is an argument problem, not
             * a verification failure -- a script must be able to tell them
             * apart. */
            ok(fhsm_composite_cms_verify(CALG, (const uint8_t *)"not a cms", 9,
                                          dg, 64) == FHSM_RV_ARGUMENTS_BAD,
               "garbage is ARGUMENTS_BAD, not SIGNATURE_INVALID");
            ok(fhsm_composite_cms_verify(CALG, p7, p7l, dg, 32)
               == FHSM_RV_ARGUMENTS_BAD, "a wrong-length digest is refused");
        }

        CMS_ContentInfo_free(mine_cms);
e2e_done: ;
    }

    printf("\n%s\n", g_fail ? "FAILURES" : "all checks passed");
    return g_fail ? 1 : 0;
}
