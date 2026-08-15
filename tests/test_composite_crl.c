/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * The TBSCertList assembler, checked against OpenSSL's own encoder.
 *
 * Why this test exists in this shape.
 *
 * For a certificate, OpenSSL exposes X509_get0_tbs_sigalg, so the inner
 * AlgorithmIdentifier can be filled with a composite OID and i2d_re_X509_tbs
 * does the rest. For a CRL there is no such accessor: only the outer
 * algorithm is reachable, the inner one stays empty, and i2d_re_X509_CRL_tbs
 * fails with "illegal zero content". The TBSCertList therefore has to be
 * assembled by hand.
 *
 * Hand-assembled DER is exactly the kind of code that is wrong in ways that
 * look right. Reading it does not catch a length off by one -- that mistake
 * was already made once in this module, in ALGID_MLDSA65_ED25519. So the
 * assembler takes parts that OpenSSL has already encoded (the name, the
 * times, the revoked entries, the extensions) and only writes the envelopes.
 * That makes it a pure concatenation, and a pure concatenation can be
 * compared against the real thing.
 *
 * The oracle: build a CRL with OpenSSL on an algorithm it knows (Ed25519),
 * take its TBSCertList, then feed the same parts and the same Ed25519
 * AlgorithmIdentifier to the assembler. The two must be identical byte for
 * byte. Anything the assembler gets wrong -- a length, a tag, a field order,
 * an omitted OPTIONAL that should be present -- moves those bytes.
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "fhsm_composite.h"

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) g_fail++;
}

/* Dump two buffers around their first difference. A memcmp that just says
 * "differ" leaves nothing to act on. */
static void show_diff(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
    size_t n = na < nb ? na : nb, i = 0;
    while (i < n && a[i] == b[i]) i++;
    printf("      lengths: reference %zu, assembled %zu\n", na, nb);
    if (i < n) printf("      first difference at offset %zu: %02X vs %02X\n",
                       i, a[i], b[i]);
    size_t lo = i > 8 ? i - 8 : 0, hi = i + 12;
    printf("      reference "); for (size_t k = lo; k < hi && k < na; k++) printf("%02X ", a[k]);
    printf("\n      assembled "); for (size_t k = lo; k < hi && k < nb; k++) printf("%02X ", b[k]);
    printf("\n");
}

/* Encode a SEQUENCE OF from already-encoded members -- what the production
 * caller does too. */
static size_t wrap_seq(const uint8_t *content, size_t n, uint8_t *out) {
    uint8_t *c = out;
    *c++ = 0x30;
    if (n < 0x80) { *c++ = (uint8_t)n; }
    else if (n <= 0xFF) { *c++ = 0x81; *c++ = (uint8_t)n; }
    else if (n <= 0xFFFF) { *c++ = 0x82; *c++ = (uint8_t)(n >> 8); *c++ = (uint8_t)n; }
    else { *c++ = 0x83; *c++ = (uint8_t)(n >> 16);
           *c++ = (uint8_t)(n >> 8); *c++ = (uint8_t)n; }
    memcpy(c, content, n);
    return (size_t)(c - out) + n;
}

typedef struct {
    uint8_t *tbs;      int tbs_len;      /* what OpenSSL encoded            */
    uint8_t *issuer;   int issuer_len;
    uint8_t *this_u;   int this_u_len;
    uint8_t *next_u;   int next_u_len;
    uint8_t  revoked[2048]; size_t revoked_len;
    uint8_t  exts[1024];    size_t exts_len;
    uint8_t *algid;    int algid_len;    /* Ed25519 AlgorithmIdentifier     */
    X509_CRL *crl;
    EVP_PKEY *key;
} ref_t;

static void ref_free(ref_t *r) {
    OPENSSL_free(r->tbs); OPENSSL_free(r->issuer);
    OPENSSL_free(r->this_u); OPENSSL_free(r->next_u); OPENSSL_free(r->algid);
    X509_CRL_free(r->crl); EVP_PKEY_free(r->key);
    memset(r, 0, sizeof *r);
}

/* with_revoked / with_exts / with_next let the test cover the OPTIONAL fields
 * both ways: an OPTIONAL that is wrongly always emitted, or wrongly always
 * omitted, is the classic hand-assembly bug and it only shows up when both
 * are tried. */
static int ref_build(ref_t *r, int with_revoked, int with_exts, int with_next)
{
    memset(r, 0, sizeof *r);
    int rc = 0;
    X509_NAME *nm = NULL;
    ASN1_TIME *t1 = NULL, *t2 = NULL;

    r->key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    r->crl = X509_CRL_new();
    if (!r->key || !r->crl) goto out;

    /* v2 -- required as soon as extensions are present (RFC 5280 5.1.2.1). */
    if (X509_CRL_set_version(r->crl, 1) != 1) goto out;

    nm = X509_NAME_new();
    if (!nm
        || X509_NAME_add_entry_by_txt(nm, "C",  MBSTRING_ASC, (const unsigned char *)"FR", -1, -1, 0) != 1
        || X509_NAME_add_entry_by_txt(nm, "O",  MBSTRING_ASC, (const unsigned char *)"Simorgh Labs", -1, -1, 0) != 1
        || X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"FreeHSM Test Root", -1, -1, 0) != 1)
        goto out;
    if (X509_CRL_set_issuer_name(r->crl, nm) != 1) goto out;

    /* Fixed instants, so the test does not depend on when it runs. */
    t1 = ASN1_TIME_set(NULL, 1785000000L);
    if (!t1 || X509_CRL_set1_lastUpdate(r->crl, t1) != 1) goto out;
    if (with_next) {
        t2 = ASN1_TIME_set(NULL, 1785000000L + 30L * 86400L);
        if (!t2 || X509_CRL_set1_nextUpdate(r->crl, t2) != 1) goto out;
    }

    if (with_revoked) {
        static const long serials[] = { 0x4A3B2C1DL, 0x01L };
        uint8_t buf[2048]; size_t used = 0;
        for (size_t i = 0; i < sizeof serials / sizeof serials[0]; i++) {
            X509_REVOKED *rev = X509_REVOKED_new();
            ASN1_INTEGER *sn = ASN1_INTEGER_new();
            ASN1_TIME    *rd = ASN1_TIME_set(NULL, 1784000000L + (long)i * 3600L);
            int good = rev && sn && rd
                    && ASN1_INTEGER_set(sn, serials[i]) == 1
                    && X509_REVOKED_set_serialNumber(rev, sn) == 1
                    && X509_REVOKED_set_revocationDate(rev, rd) == 1;
            /* A reason code on the first entry only: crlEntryExtensions is
               itself OPTIONAL and must be exercised both ways. */
            if (good && i == 0) {
                ASN1_ENUMERATED *e = ASN1_ENUMERATED_new();
                X509_EXTENSION *x = NULL;
                good = e && ASN1_ENUMERATED_set(e, 1 /* keyCompromise */) == 1
                    && (x = X509V3_EXT_i2d(NID_crl_reason, 0, e)) != NULL
                    && X509_REVOKED_add_ext(rev, x, -1) == 1;
                X509_EXTENSION_free(x); ASN1_ENUMERATED_free(e);
            }
            if (good) {
                uint8_t *d = NULL;
                int n = i2d_X509_REVOKED(rev, &d);
                good = n > 0 && used + (size_t)n <= sizeof buf;
                if (good) { memcpy(buf + used, d, (size_t)n); used += (size_t)n; }
                OPENSSL_free(d);
            }
            if (good) good = X509_CRL_add0_revoked(r->crl, rev) == 1;
            else X509_REVOKED_free(rev);
            ASN1_INTEGER_free(sn); ASN1_TIME_free(rd);
            if (!good) goto out;
        }
        r->revoked_len = wrap_seq(buf, used, r->revoked);
    }

    if (with_exts) {
        uint8_t buf[1024]; size_t used = 0;
        uint8_t kid[20];
        for (int i = 0; i < 20; i++) kid[i] = (uint8_t)(0xA0 + i);

        AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
        ASN1_INTEGER *num = ASN1_INTEGER_new();
        X509_EXTENSION *e1 = NULL, *e2 = NULL;
        int good = akid && num
                && (akid->keyid = ASN1_OCTET_STRING_new()) != NULL
                && ASN1_OCTET_STRING_set(akid->keyid, kid, 20) == 1
                && (e1 = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid)) != NULL
                && ASN1_INTEGER_set(num, 4096) == 1
                && (e2 = X509V3_EXT_i2d(NID_crl_number, 0, num)) != NULL;
        X509_EXTENSION *both[2]; both[0] = e1; both[1] = e2;
        for (int i = 0; good && i < 2; i++) {
            uint8_t *d = NULL;
            int n = i2d_X509_EXTENSION(both[i], &d);
            good = n > 0 && used + (size_t)n <= sizeof buf;
            if (good) { memcpy(buf + used, d, (size_t)n); used += (size_t)n; }
            OPENSSL_free(d);
            if (good) good = X509_CRL_add_ext(r->crl, both[i], -1) == 1;
        }
        X509_EXTENSION_free(e1); X509_EXTENSION_free(e2);
        AUTHORITY_KEYID_free(akid); ASN1_INTEGER_free(num);
        if (!good) goto out;
        r->exts_len = wrap_seq(buf, used, r->exts);
    }

    if (X509_CRL_sign(r->crl, r->key, NULL) <= 0) goto out;

    r->tbs_len = i2d_re_X509_CRL_tbs(r->crl, &r->tbs);
    if (r->tbs_len <= 0) goto out;

    r->issuer_len = i2d_X509_NAME(X509_CRL_get_issuer(r->crl), &r->issuer);
    r->this_u_len = i2d_ASN1_TIME((ASN1_TIME *)X509_CRL_get0_lastUpdate(r->crl), &r->this_u);
    if (with_next)
        r->next_u_len = i2d_ASN1_TIME((ASN1_TIME *)X509_CRL_get0_nextUpdate(r->crl), &r->next_u);
    {
        const X509_ALGOR *a = NULL; const ASN1_BIT_STRING *s = NULL;
        X509_CRL_get0_signature(r->crl, &s, &a);
        r->algid_len = i2d_X509_ALGOR((X509_ALGOR *)a, &r->algid);
    }
    rc = r->issuer_len > 0 && r->this_u_len > 0 && r->algid_len > 0
         && (!with_next || r->next_u_len > 0);
out:
    X509_NAME_free(nm); ASN1_TIME_free(t1); ASN1_TIME_free(t2);
    if (!rc) ERR_print_errors_fp(stderr);
    return rc;
}

static void case_tbs(const char *label, int with_revoked, int with_exts, int with_next)
{
    ref_t r;
    if (!ref_build(&r, with_revoked, with_exts, with_next)) {
        printf("  [FAIL] %s: could not build the reference\n", label);
        g_fail++; return;
    }

    uint8_t mine[8192]; size_t mine_len = sizeof mine;
    fhsm_rv_t rv = fhsm_composite_crl_tbs(
        r.algid, (size_t)r.algid_len,
        r.issuer, (size_t)r.issuer_len,
        r.this_u, (size_t)r.this_u_len,
        with_next ? r.next_u : NULL, with_next ? (size_t)r.next_u_len : 0,
        with_revoked ? r.revoked : NULL, with_revoked ? r.revoked_len : 0,
        with_exts ? r.exts : NULL, with_exts ? r.exts_len : 0,
        mine, &mine_len);

    char msg[160];
    snprintf(msg, sizeof msg, "%s: assembler returns OK", label);
    ok(rv == FHSM_RV_OK, msg);
    if (rv != FHSM_RV_OK) { ref_free(&r); return; }

    int same = mine_len == (size_t)r.tbs_len
               && memcmp(mine, r.tbs, mine_len) == 0;
    snprintf(msg, sizeof msg, "%s: identical to OpenSSL's TBSCertList (%d bytes)",
             label, r.tbs_len);
    ok(same, msg);
    if (!same) show_diff(r.tbs, (size_t)r.tbs_len, mine, mine_len);

    ref_free(&r);
}

/* A short buffer must be reported as such, with the needed size, and must not
 * be written past. The canary catches an assembler that reports the right
 * size to the caller and overruns anyway. */
static void case_short_buffer(void)
{
    ref_t r;
    if (!ref_build(&r, 1, 1, 1)) { printf("  [FAIL] short buffer setup\n"); g_fail++; return; }

    uint8_t small[64];
    memset(small, 0xEE, sizeof small);
    size_t n = 8;
    fhsm_rv_t rv = fhsm_composite_crl_tbs(
        r.algid, (size_t)r.algid_len, r.issuer, (size_t)r.issuer_len,
        r.this_u, (size_t)r.this_u_len, r.next_u, (size_t)r.next_u_len,
        r.revoked, r.revoked_len, r.exts, r.exts_len, small, &n);

    ok(rv == FHSM_RV_BUFFER_TOO_SMALL, "short buffer: BUFFER_TOO_SMALL");
    ok(n == (size_t)r.tbs_len, "short buffer: reports the exact size needed");
    int untouched = 1;
    for (size_t i = 0; i < sizeof small; i++) if (small[i] != 0xEE) untouched = 0;
    ok(untouched, "short buffer: nothing written");
    ref_free(&r);
}

static void case_args(void)
{
    uint8_t out[64]; size_t n = sizeof out;
    uint8_t dummy[8]; memset(dummy, 0, sizeof dummy);
    dummy[0] = 0x30; dummy[1] = 0x02; dummy[2] = 0x05; dummy[3] = 0x00;
    ok(fhsm_composite_crl_tbs(NULL, 4, dummy, 4, dummy, 4, NULL, 0, NULL, 0,
                               NULL, 0, out, &n) == FHSM_RV_ARGUMENTS_BAD,
       "arguments: NULL algid refused");
    ok(fhsm_composite_crl_tbs(dummy, 4, dummy, 4, NULL, 0, NULL, 0, NULL, 0,
                               NULL, 0, out, &n) == FHSM_RV_ARGUMENTS_BAD,
       "arguments: missing thisUpdate refused");
    ok(fhsm_composite_crl_tbs(dummy, 4, dummy, 4, dummy, 4, NULL, 0, NULL, 0,
                               NULL, 0, NULL, &n) == FHSM_RV_ARGUMENTS_BAD,
       "arguments: NULL output refused");
}


/* ===========================================================================
 * End to end: a real composite CRL, and OpenSSL asked to read it back.
 *
 * The differential test above proves the assembler places bytes where OpenSSL
 * would. It says nothing about whether the finished, signed CRL is something
 * a third party can parse -- that is a different claim and needs a different
 * witness. The witness here is OpenSSL's own CRL parser, which knows nothing
 * about the composite OID and must still walk the structure.
 * ========================================================================= */

/* Signing callback: the composite key held in this process. In production
 * this is the PKCS#11 path, and the point of the callback seam is that the
 * private key never has to leave the token. */
typedef struct { const uint8_t *priv; size_t priv_len; } local_signer_t;

static fhsm_rv_t local_sign(void *ctx, const uint8_t *tbs, size_t tbs_len,
                             uint8_t *sig, size_t *sig_len)
{
    local_signer_t *s = ctx;
    return fhsm_composite_sign(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                s->priv, s->priv_len, tbs, tbs_len, NULL, 0,
                                sig, sig_len);
}

static void case_end_to_end(void)
{
    printf("\n== end to end: composite CRL read back by OpenSSL ==\n");

    static uint8_t priv[FHSM_COMPOSITE_PRIV_MAX], pub[FHSM_COMPOSITE_PUB_MAX];
    size_t priv_len = sizeof priv, pub_len = sizeof pub;
    fhsm_rv_t rv = fhsm_composite_keygen(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                          priv, &priv_len, pub, &pub_len);
    ok(rv == FHSM_RV_OK, "composite key pair generated");
    if (rv != FHSM_RV_OK) return;

    local_signer_t signer; signer.priv = priv; signer.priv_len = priv_len;

    /* A self-signed root to issue the list under. */
    static uint8_t root[16384]; size_t root_len = sizeof root;
    rv = fhsm_composite_selfsigned(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                    "/C=FR/O=Simorgh Labs/CN=FreeHSM CRL Test Root",
                                    1, 3650, pub, pub_len,
                                    local_sign, &signer, root, &root_len);
    ok(rv == FHSM_RV_OK, "self-signed composite root");
    if (rv != FHSM_RV_OK) return;

    /* Two revocations, one with a reason and one without. */
    static const uint8_t s1[] = { 0x4A, 0x3B, 0x2C, 0x1D };
    static const uint8_t s2[] = { 0xF0, 0x0D };      /* top bit set: the
                                                        encoder must add a
                                                        leading zero octet   */
    fhsm_composite_revoked_t list[2];
    list[0].serial = s1; list[0].serial_len = sizeof s1;
    list[0].date = 1784000000L; list[0].reason = 1;  /* keyCompromise */
    list[1].serial = s2; list[1].serial_len = sizeof s2;
    list[1].date = 1784500000L; list[1].reason = -1;

    static uint8_t crl[16384]; size_t crl_len = sizeof crl;
    rv = fhsm_composite_crl(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                             root, root_len, list, 2, 42, 30,
                             local_sign, &signer, crl, &crl_len);
    ok(rv == FHSM_RV_OK, "composite CRL produced");
    if (rv != FHSM_RV_OK) return;

    /* OpenSSL parses it. It cannot check the signature -- it has no composite
     * verifier -- but it must walk every field. */
    const uint8_t *p = crl;
    X509_CRL *parsed = d2i_X509_CRL(NULL, &p, (long)crl_len);
    ok(parsed != NULL, "OpenSSL parses the finished CRL");
    if (!parsed) { ERR_print_errors_fp(stderr); return; }
    ok((size_t)(p - crl) == crl_len, "no trailing bytes");

    ok(X509_CRL_get_version(parsed) == 1, "version is v2");

    /* The issuer must be the root's subject, compared as encodings rather
     * than as text: two different Names can print the same. */
    {
        const uint8_t *q = root;
        X509 *rc = d2i_X509(NULL, &q, (long)root_len);
        ok(rc && X509_NAME_cmp(X509_CRL_get_issuer(parsed),
                                X509_get_subject_name(rc)) == 0,
           "issuer is the root's subject");
        X509_free(rc);
    }

    /* Both algorithm identifiers are the composite OID, and they agree. A
     * verifier that finds them different is looking at a substitution. */
    {
        const X509_ALGOR *a = NULL; const ASN1_BIT_STRING *sg = NULL;
        X509_CRL_get0_signature(parsed, &sg, &a);
        const ASN1_OBJECT *o = NULL; int pt = 0; const void *pv = NULL;
        X509_ALGOR_get0(&o, &pt, &pv, a);
        char b[128] = ""; OBJ_obj2txt(b, sizeof b, o, 1);
        ok(strcmp(b, FHSM_COMPOSITE_OID_MLDSA65_ED25519) == 0,
           "outer AlgorithmIdentifier is the composite OID");
        ok(pt == V_ASN1_UNDEF, "algorithm parameters absent, as the draft requires");

        /* The inner one, located by searching the TBSCertList bytes for the
         * same twelve octets: there is no accessor, which is the whole
         * reason this code exists. */
        const uint8_t *aid = NULL; size_t aid_len = 0;
        fhsm_composite_algid(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512, &aid, &aid_len);
        int found = 0;
        for (size_t i = 0; i + aid_len <= crl_len; i++)
            if (memcmp(crl + i, aid, aid_len) == 0) found++;
        ok(found == 2, "the composite AlgorithmIdentifier appears twice (inner and outer)");
    }

    /* The revocation list itself. */
    {
        STACK_OF(X509_REVOKED) *st = X509_CRL_get_REVOKED(parsed);
        ok(sk_X509_REVOKED_num(st) == 2, "two entries in the list");
        if (sk_X509_REVOKED_num(st) == 2) {
            X509_REVOKED *e0 = sk_X509_REVOKED_value(st, 0);
            X509_REVOKED *e1 = sk_X509_REVOKED_value(st, 1);
            const ASN1_INTEGER *n0 = X509_REVOKED_get0_serialNumber(e0);
            const ASN1_INTEGER *n1 = X509_REVOKED_get0_serialNumber(e1);
            BIGNUM *b0 = ASN1_INTEGER_to_BN(n0, NULL);
            BIGNUM *b1 = ASN1_INTEGER_to_BN(n1, NULL);
            uint8_t got[8]; int g0 = BN_bn2bin(b0, got);
            ok(g0 == 4 && memcmp(got, s1, 4) == 0, "first serial round-trips");
            int g1 = BN_bn2bin(b1, got);
            /* 0xF00D has its top bit set. It must come back as 0xF00D, not as
             * a negative number and not with the padding octet still on. */
            ok(g1 == 2 && got[0] == 0xF0 && got[1] == 0x0D,
               "serial with the top bit set stays positive and unpadded");
            ok(BN_is_negative(b1) == 0, "and is not read as negative");
            BN_free(b0); BN_free(b1);

            ok(X509_REVOKED_get_ext_count(e0) == 1, "first entry carries its reason");
            ok(X509_REVOKED_get_ext_count(e1) == 0, "second entry carries none");
        }
    }

    /* crlNumber and authorityKeyIdentifier. */
    {
        int idx = X509_CRL_get_ext_by_NID(parsed, NID_crl_number, -1);
        ok(idx >= 0, "crlNumber present");
        if (idx >= 0) {
            ASN1_INTEGER *num = X509_CRL_get_ext_d2i(parsed, NID_crl_number, NULL, NULL);
            int64_t v = 0;
            ok(num && ASN1_INTEGER_get_int64(&v, num) == 1 && v == 42,
               "crlNumber is the value asked for");
            ASN1_INTEGER_free(num);
        }
        AUTHORITY_KEYID *ak = X509_CRL_get_ext_d2i(parsed, NID_authority_key_identifier,
                                                    NULL, NULL);
        ok(ak && ak->keyid, "authorityKeyIdentifier present");
        if (ak && ak->keyid) {
            const uint8_t *q = root;
            X509 *rc = d2i_X509(NULL, &q, (long)root_len);
            const ASN1_OCTET_STRING *skid = rc ? X509_get0_subject_key_id(rc) : NULL;
            ok(skid && ASN1_OCTET_STRING_cmp(ak->keyid, skid) == 0,
               "and matches the root's subjectKeyIdentifier byte for byte");
            X509_free(rc);
        }
        AUTHORITY_KEYID_free(ak);
    }

    /* nextUpdate must be after thisUpdate. A list valid for a negative span
     * is one every verifier treats as already expired. */
    ok(ASN1_TIME_compare(X509_CRL_get0_nextUpdate(parsed),
                          X509_CRL_get0_lastUpdate(parsed)) > 0,
       "nextUpdate is after thisUpdate");

    /* The signature really is over the TBSCertList, and really verifies.
     * OpenSSL cannot check it, so the composite verifier is asked directly
     * with the bytes OpenSSL re-encoded from what it parsed -- if the
     * assembler had produced a TBSCertList that re-encodes differently, this
     * is where it would show. */
    {
        uint8_t *re = NULL;
        int re_n = i2d_re_X509_CRL_tbs(parsed, &re);
        ok(re_n > 0, "OpenSSL re-encodes the parsed TBSCertList");
        if (re_n > 0) {
            const X509_ALGOR *a = NULL; const ASN1_BIT_STRING *sg = NULL;
            X509_CRL_get0_signature(parsed, &sg, &a);
            fhsm_rv_t vr = fhsm_composite_verify(
                FHSM_COMPOSITE_MLDSA65_ED25519_SHA512, pub, pub_len,
                re, (size_t)re_n, NULL, 0,
                ASN1_STRING_get0_data((const ASN1_STRING *)sg),
                (size_t)ASN1_STRING_length((const ASN1_STRING *)sg));
            ok(vr == FHSM_RV_OK, "composite signature verifies over the CRL");

            /* And a tampered list must not. Flipping one byte of a serial is
             * the attack this whole structure exists to prevent. */
            re[re_n / 2] ^= 0x01;
            vr = fhsm_composite_verify(
                FHSM_COMPOSITE_MLDSA65_ED25519_SHA512, pub, pub_len,
                re, (size_t)re_n, NULL, 0,
                ASN1_STRING_get0_data((const ASN1_STRING *)sg),
                (size_t)ASN1_STRING_length((const ASN1_STRING *)sg));
            ok(vr != FHSM_RV_OK, "a single flipped byte breaks it");
        }
        OPENSSL_free(re);
    }

    /* Write it out so the harness can hand it to the openssl(1) command. */
    {
        FILE *f = fopen("/tmp/fhsm_composite_test.crl", "wb");
        if (f) { fwrite(crl, 1, crl_len, f); fclose(f); }
        printf("      (written to /tmp/fhsm_composite_test.crl, %zu bytes)\n", crl_len);
    }

    X509_CRL_free(parsed);
}

/* A list long enough to need a three-octet DER length. A CA that has been
 * running for years gets here, and the two-octet ceiling would have silently
 * been the point where issuing a CRL started failing. */
static void case_large_list(void)
{
    printf("\n== a list past the 64 KiB length boundary ==\n");

    ref_t r;
    if (!ref_build(&r, 0, 1, 1)) { printf("  [FAIL] setup\n"); g_fail++; return; }

    /* Build the same long list twice: once through OpenSSL's encoder, once
     * through the assembler. 3000 entries puts the SEQUENCE well past 0xFFFF. */
    const int N = 3000;
    size_t cap = (size_t)N * 64 + 4096;
    uint8_t *members = malloc(cap), *seq = malloc(cap + 8);
    uint8_t *mine = malloc(cap + 8192);
    if (!members || !seq || !mine) { printf("  [FAIL] out of memory\n"); g_fail++; goto done; }

    size_t used = 0;
    for (int i = 0; i < N; i++) {
        X509_REVOKED *rev = X509_REVOKED_new();
        ASN1_INTEGER *sn = ASN1_INTEGER_new();
        ASN1_TIME *rd = ASN1_TIME_set(NULL, 1784000000L + i);
        uint8_t *d = NULL;
        int good = rev && sn && rd && ASN1_INTEGER_set(sn, 100000L + i) == 1
                && X509_REVOKED_set_serialNumber(rev, sn) == 1
                && X509_REVOKED_set_revocationDate(rev, rd) == 1;
        int n = good ? i2d_X509_REVOKED(rev, &d) : -1;
        if (n > 0 && used + (size_t)n <= cap) { memcpy(members + used, d, (size_t)n); used += (size_t)n; }
        else good = 0;
        OPENSSL_free(d);
        if (good) good = X509_CRL_add0_revoked(r.crl, rev) == 1;
        else X509_REVOKED_free(rev);
        ASN1_INTEGER_free(sn); ASN1_TIME_free(rd);
        if (!good) { printf("  [FAIL] building entry %d\n", i); g_fail++; goto done; }
    }
    size_t seq_n = wrap_seq(members, used, seq);
    ok(used > 0xFFFF, "the revoked SEQUENCE is past the two-octet length limit");

    /* Re-encode the reference now that the entries were added. */
    OPENSSL_free(r.tbs); r.tbs = NULL;
    r.tbs_len = i2d_re_X509_CRL_tbs(r.crl, &r.tbs);
    ok(r.tbs_len > 0, "OpenSSL encodes the long TBSCertList");

    if (r.tbs_len > 0) {
        size_t mine_len = cap + 8192;
        fhsm_rv_t rv = fhsm_composite_crl_tbs(
            r.algid, (size_t)r.algid_len, r.issuer, (size_t)r.issuer_len,
            r.this_u, (size_t)r.this_u_len, r.next_u, (size_t)r.next_u_len,
            seq, seq_n, r.exts, r.exts_len, mine, &mine_len);
        ok(rv == FHSM_RV_OK, "assembler handles it");
        int same = rv == FHSM_RV_OK && mine_len == (size_t)r.tbs_len
                   && memcmp(mine, r.tbs, mine_len) == 0;
        char msg[128];
        snprintf(msg, sizeof msg, "identical to OpenSSL (%d bytes, %d entries)",
                 r.tbs_len, N);
        ok(same, msg);
        if (!same && rv == FHSM_RV_OK)
            show_diff(r.tbs, (size_t)r.tbs_len, mine, mine_len);
    }
done:
    free(members); free(seq); free(mine);
    ref_free(&r);
}

int main(void)
{
    printf("== TBSCertList assembler vs OpenSSL ==\n");

    /* All combinations of the OPTIONAL fields, so neither a stray empty
     * SEQUENCE nor a missing one can hide. */
    case_tbs("full (revoked + extensions + nextUpdate)", 1, 1, 1);
    case_tbs("no revoked list",                          0, 1, 1);
    case_tbs("no crlExtensions",                         1, 0, 1);
    case_tbs("neither",                                  0, 0, 1);
    case_tbs("no nextUpdate",                            1, 1, 0);

    printf("\n== buffer and argument handling ==\n");
    case_short_buffer();
    case_args();

    case_large_list();
    case_end_to_end();

    printf("\n%s\n", g_fail ? "FAILURES" : "all checks passed");
    return g_fail ? 1 : 0;
}
