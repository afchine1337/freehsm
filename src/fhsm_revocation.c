/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm_revocation.c --- the revocation database and the OCSP responder body.
 *
 * Moved here from tools/fhsm_ca.c so that fhsm-ca and fhsm-service share one
 * implementation rather than two that agree today. See fhsm_revocation.h for
 * why, and for what had to change on the way (exit(), static buffers, the
 * eight-megabyte allocation per load).
 * ========================================================================= */
#include "fhsm_revocation.h"

#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Every failure path goes through this, so that "returned an error" and "said
 * why" cannot come apart -- they did once in this project, and the caller was
 * left printing a blank line. */
static int fail(char *err, size_t cap, int rc, const char *fmt, ...)
{
    if (err && cap) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, cap, fmt, ap);
        va_end(ap);
    }
    return rc;
}

/* ===========================================================================
 * Reasons
 * ========================================================================= */
static const struct { const char *name; int code; } REASONS[] = {
    { "unspecified",          0 }, { "keyCompromise",        1 },
    { "cACompromise",         2 }, { "affiliationChanged",   3 },
    { "superseded",           4 }, { "cessationOfOperation", 5 },
    { "certificateHold",      6 }, { "privilegeWithdrawn",   9 },
    { "aACompromise",        10 },
};

int fhsm_rev_reason_code(const char *name) {
    for (size_t i = 0; i < sizeof REASONS / sizeof REASONS[0]; i++)
        if (!strcmp(REASONS[i].name, name)) return REASONS[i].code;
    return -2;                                     /* -1 means "no reason" */
}

const char *fhsm_rev_reason_name(int code) {
    for (size_t i = 0; i < sizeof REASONS / sizeof REASONS[0]; i++)
        if (REASONS[i].code == code) return REASONS[i].name;
    return NULL;
}

const char *fhsm_rev_reason_list(void) {
    return "unspecified, keyCompromise, cACompromise, affiliationChanged, "
           "superseded, cessationOfOperation, certificateHold, "
           "privilegeWithdrawn, aACompromise";
}

/* ===========================================================================
 * Serials and dates
 * ========================================================================= */
int fhsm_rev_hex_to_bytes(const char *h, uint8_t *out, size_t cap, size_t *n) {
    size_t l = strlen(h);
    if (l == 0 || l % 2 || l / 2 > cap) return 0;
    for (size_t i = 0; i < l; i += 2) {
        int hi = -1, lo = -1;
        for (int k = 0; k < 16; k++) {
            if ("0123456789abcdef"[k] == h[i]   || "0123456789ABCDEF"[k] == h[i])   hi = k;
            if ("0123456789abcdef"[k] == h[i+1] || "0123456789ABCDEF"[k] == h[i+1]) lo = k;
        }
        if (hi < 0 || lo < 0) return 0;
        out[i/2] = (uint8_t)((hi << 4) | lo);
    }
    *n = l / 2;
    return 1;
}

int fhsm_rev_date_to_time(const char *s, int64_t *out) {
    if (strlen(s) != 15 || s[14] != 'Z') return 0;
    for (int i = 0; i < 14; i++) if (s[i] < '0' || s[i] > '9') return 0;
    struct tm t; memset(&t, 0, sizeof t);
    int v[6], f[6] = { 4, 2, 2, 2, 2, 2 }, p = 0;
    for (int i = 0; i < 6; i++) {
        v[i] = 0;
        for (int k = 0; k < f[i]; k++) v[i] = v[i] * 10 + (s[p++] - '0');
    }
    t.tm_year = v[0] - 1900; t.tm_mon = v[1] - 1; t.tm_mday = v[2];
    t.tm_hour = v[3]; t.tm_min = v[4]; t.tm_sec = v[5];
    time_t r = timegm(&t);
    if (r == (time_t)-1) return 0;
    *out = (int64_t)r;
    return 1;
}

int fhsm_rev_time_to_date(int64_t when, char out[16]) {
    time_t t = (time_t)when;
    struct tm g;
    char tmp[64];
    if (!gmtime_r(&t, &g)) return 0;
    int k = snprintf(tmp, sizeof tmp, "%04d%02d%02d%02d%02d%02dZ",
                     g.tm_year + 1900, g.tm_mon + 1, g.tm_mday,
                     g.tm_hour, g.tm_min, g.tm_sec);
    if (k != 15) return 0;
    memcpy(out, tmp, 16);
    return 1;
}

int fhsm_rev_serial_eq(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
    while (na > 1 && a[0] == 0) { a++; na--; }
    while (nb > 1 && b[0] == 0) { b++; nb--; }
    return na == nb && memcmp(a, b, na) == 0;
}

/* ===========================================================================
 * The database
 * ========================================================================= */

/* The whole file, or nothing. The wording is kept from the tool, where it was
 * the operator's only explanation of why a `crl` run stopped. */
static int db_bad(char *err, size_t cap, const char *path, size_t line,
                  const char *why)
{
    return fail(err, cap, FHSM_REV_EPARSE,
      "%s line %zu: %s\n"
      "  Nothing was read. A revocation database that is only partly\n"
      "  understood would produce a list missing revocations, which is a\n"
      "  signed statement that a revoked certificate is still valid.\n"
      "  Fix the line, or remove it deliberately.\n", path, line, why);
}

static int db_grow(fhsm_rev_db_t *d, char *err, size_t cap)
{
    if (d->n < d->cap) return FHSM_REV_OK;
    if (d->n >= FHSM_REV_MAX_ENTRIES)
        return fail(err, cap, FHSM_REV_EPARSE,
                    "too many entries (the limit is %d)\n", FHSM_REV_MAX_ENTRIES);
    size_t want = d->cap ? d->cap * 2 : 64;
    if (want > FHSM_REV_MAX_ENTRIES) want = FHSM_REV_MAX_ENTRIES;
    fhsm_rev_entry_t *p = realloc(d->e, want * sizeof *p);
    if (!p) return fail(err, cap, FHSM_REV_EIO, "out of memory\n");
    d->e = p; d->cap = want;
    return FHSM_REV_OK;
}

void fhsm_rev_db_free(fhsm_rev_db_t *d) {
    if (!d) return;
    free(d->e);
    d->e = NULL; d->n = 0; d->cap = 0; d->crl_number = 0;
}

int fhsm_rev_db_load(const char *path, fhsm_rev_db_t *d, char *err, size_t cap)
{
    memset(d, 0, sizeof *d);

    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return FHSM_REV_OK;   /* a first run */
        return fail(err, cap, FHSM_REV_EIO,
                    "cannot read %s: %s\n", path, strerror(errno));
    }

    char line[512]; size_t ln = 0; int seen_number = 0; int rc = FHSM_REV_OK;
    while (fgets(line, sizeof line, f)) {
        ln++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *nl = strpbrk(p, "\r\n"); if (nl) *nl = '\0';
        if (!*p || *p == '#') continue;

        if (!strncmp(p, "crlNumber", 9) && (p[9] == ' ' || p[9] == '\t')) {
            if (seen_number) { rc = db_bad(err, cap, path, ln, "crlNumber appears twice"); goto out; }
            char *end = NULL;
            unsigned long long v = strtoull(p + 10, &end, 10);
            if (!end || *end) { rc = db_bad(err, cap, path, ln, "crlNumber is not a number"); goto out; }
            d->crl_number = v; seen_number = 1;
            continue;
        }

        if (d->n >= FHSM_REV_MAX_ENTRIES) { rc = db_bad(err, cap, path, ln, "too many entries"); goto out; }
        if ((rc = db_grow(d, err, cap)) != FHSM_REV_OK) goto out;

        char sr[160], dt[64], rs[64];
        int got = sscanf(p, "%159s %63s %63s", sr, dt, rs);
        if (got < 2) { rc = db_bad(err, cap, path, ln, "expected: SERIAL DATE [REASON]"); goto out; }

        fhsm_rev_entry_t *e = &d->e[d->n];
        memset(e, 0, sizeof *e);
        if (!fhsm_rev_hex_to_bytes(sr, e->serial, sizeof e->serial, &e->serial_len)) {
            rc = db_bad(err, cap, path, ln, "serial is not an even number of hex digits"); goto out;
        }
        int64_t unused_t = 0;
        if (!fhsm_rev_date_to_time(dt, &unused_t)) {
            rc = db_bad(err, cap, path, ln, "date is not YYYYMMDDHHMMSSZ"); goto out;
        }
        memcpy(e->date, dt, 15); e->date[15] = '\0';   /* length checked above */
        if (got < 3 || !strcmp(rs, "-")) e->reason = -1;
        else {
            e->reason = fhsm_rev_reason_code(rs);
            if (e->reason == -2) { rc = db_bad(err, cap, path, ln, "unknown revocation reason"); goto out; }
        }
        d->n++;
    }
out:
    fclose(f);
    if (rc != FHSM_REV_OK) fhsm_rev_db_free(d);
    return rc;
}

int fhsm_rev_db_save(const char *path, const fhsm_rev_db_t *d, char *err, size_t cap)
{
    char tmp[1024];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp)
        return fail(err, cap, FHSM_REV_EIO, "path too long\n");

    FILE *f = fopen(tmp, "w");
    if (!f) return fail(err, cap, FHSM_REV_EIO,
                        "cannot write %s: %s\n", tmp, strerror(errno));

    fprintf(f, "# fhsm-ca revocation database v1\n"
               "# SERIAL(hex)  DATE(YYYYMMDDHHMMSSZ)  REASON  ('-' for none)\n");
    fprintf(f, "crlNumber %llu\n", d->crl_number);
    for (size_t i = 0; i < d->n; i++) {
        for (size_t k = 0; k < d->e[i].serial_len; k++)
            fprintf(f, "%02X", d->e[i].serial[k]);
        const char *rn = d->e[i].reason < 0 ? "-" : fhsm_rev_reason_name(d->e[i].reason);
        fprintf(f, " %s %s\n", d->e[i].date, rn ? rn : "-");
    }
    /* Reach the disk before the rename, so a crash cannot leave the new name
     * pointing at an empty file. */
    if (fflush(f) != 0 || fsync(fileno(f)) != 0 || fclose(f) != 0)
        return fail(err, cap, FHSM_REV_EIO,
                    "writing %s failed: %s\n", tmp, strerror(errno));
    if (rename(tmp, path) != 0)
        return fail(err, cap, FHSM_REV_EIO,
                    "cannot replace %s: %s\n", path, strerror(errno));
    return FHSM_REV_OK;
}

int fhsm_rev_db_add(fhsm_rev_db_t *d, const fhsm_rev_entry_t *e, char *err, size_t cap)
{
    int rc = db_grow(d, err, cap);
    if (rc != FHSM_REV_OK) return rc;
    d->e[d->n++] = *e;
    return FHSM_REV_OK;
}

const fhsm_rev_entry_t *fhsm_rev_db_find(const fhsm_rev_db_t *d,
                                          const uint8_t *serial, size_t n)
{
    for (size_t k = 0; k < d->n; k++)
        if (fhsm_rev_serial_eq(serial, n, d->e[k].serial, d->e[k].serial_len))
            return &d->e[k];
    return NULL;
}

/* ===========================================================================
 * OCSP
 * ========================================================================= */

int fhsm_ocsp_check_responder(const uint8_t *responder_der, size_t responder_len,
                              const uint8_t *ca_der, size_t ca_len,
                              const char *responder_path, const char *ca_path,
                              char *err, size_t cap)
{
    const char *rp = responder_path ? responder_path : "the responder certificate";
    const char *cp = ca_path        ? ca_path        : "the CA certificate";

    X509 *rc = NULL, *ca = NULL;
    { const uint8_t *p = responder_der; rc = d2i_X509(NULL, &p, (long)responder_len); }
    if (!rc)
        return fail(err, cap, FHSM_REV_EPARSE,
                    "%s does not parse as DER.\n", rp);
    { const uint8_t *p = ca_der; ca = d2i_X509(NULL, &p, (long)ca_len); }
    if (!ca) {
        X509_free(rc);
        return fail(err, cap, FHSM_REV_EPARSE, "%s is not a certificate.\n", cp);
    }

    /* 1. The EKU. Without it a verifier treats the answer as signed by
     *    something with no authority to answer, and refuses it. */
    EXTENDED_KEY_USAGE *eku = X509_get_ext_d2i(rc, NID_ext_key_usage, NULL, NULL);
    int has_ocsp = 0;
    for (int k = 0; eku && k < sk_ASN1_OBJECT_num(eku); k++)
        if (OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, k)) == NID_OCSP_sign) has_ocsp = 1;
    if (eku) EXTENDED_KEY_USAGE_free(eku);
    if (!has_ocsp) {
        int rv = fail(err, cap, FHSM_REV_EPARSE,
            "%s does not carry extendedKeyUsage OCSPSigning.\n"
            "  A verifier will refuse every response it signs, so signing them\n"
            "  would only produce answers nobody accepts. Issue the responder\n"
            "  with `fhsm-ca issue --profile ocsp-responder`.\n", rp);
        X509_free(rc); X509_free(ca);
        return rv;
    }

    /* 2. The same issuer. A delegate issued by some other CA has no authority
     *    over these certificates whatever its EKU says. */
    if (X509_NAME_cmp(X509_get_issuer_name(rc), X509_get_subject_name(ca)) != 0) {
        int rv = fail(err, cap, FHSM_REV_EPARSE,
            "%s was not issued by the CA in %s.\n"
            "  Its issuer name does not match that CA's subject, so a verifier\n"
            "  has no reason to accept it as speaking for this authority.\n",
            rp, cp);
        X509_free(rc); X509_free(ca);
        return rv;
    }

    X509_free(rc); X509_free(ca);
    return FHSM_REV_OK;
}

/* OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED,
 *                             responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }
 * Assembled here because OCSP_response_create needs an OCSP_BASICRESP, and we
 * have bytes rather than a structure OpenSSL could have built. */
static size_t wrap_response(const uint8_t *basic, size_t n, uint8_t *out, size_t cap)
{
    static const uint8_t OID_BASIC[] = {
        0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
    };
    uint8_t oct[8], rb[8], bytes_hdr[8], outer[8];
    size_t oct_n = 0, rb_n = 0, bytes_n = 0, outer_n = 0;

#define LEN(v, buf, nn) do {                                              \
        size_t _v = (v);                                                  \
        if (_v < 0x80) { (buf)[0] = (uint8_t)_v; (nn) = 1; }               \
        else if (_v <= 0xFF) { (buf)[0]=0x81; (buf)[1]=(uint8_t)_v; (nn)=2; } \
        else if (_v <= 0xFFFF) { (buf)[0]=0x82; (buf)[1]=(uint8_t)(_v>>8); \
                                 (buf)[2]=(uint8_t)_v; (nn)=3; }           \
        else { (buf)[0]=0x83; (buf)[1]=(uint8_t)(_v>>16);                  \
               (buf)[2]=(uint8_t)(_v>>8); (buf)[3]=(uint8_t)_v; (nn)=4; }  \
    } while (0)

    LEN(n, oct, oct_n);                                  /* OCTET STRING     */
    size_t oct_total = 1 + oct_n + n;
    size_t seq_content = sizeof OID_BASIC + oct_total;
    LEN(seq_content, rb, rb_n);                          /* ResponseBytes    */
    size_t rb_total = 1 + rb_n + seq_content;
    LEN(rb_total, bytes_hdr, bytes_n);                   /* [0] EXPLICIT     */
    size_t a0_total = 1 + bytes_n + rb_total;
    size_t content = 3 + a0_total;                       /* ENUMERATED 0     */
    LEN(content, outer, outer_n);
    size_t total = 1 + outer_n + content;
    if (cap < total) return 0;

    uint8_t *c = out;
    *c++ = 0x30; memcpy(c, outer, outer_n); c += outer_n;
    *c++ = 0x0A; *c++ = 0x01; *c++ = 0x00;               /* successful       */
    *c++ = 0xA0; memcpy(c, bytes_hdr, bytes_n); c += bytes_n;
    *c++ = 0x30; memcpy(c, rb, rb_n); c += rb_n;
    memcpy(c, OID_BASIC, sizeof OID_BASIC); c += sizeof OID_BASIC;
    *c++ = 0x04; memcpy(c, oct, oct_n); c += oct_n;
    memcpy(c, basic, n); c += n;
#undef LEN
    return (size_t)(c - out);
}

int fhsm_ocsp_answer(const uint8_t *reqder, size_t req_len,
                     const uint8_t *ca_der, size_t ca_len,
                     const uint8_t *responder_der, size_t responder_len,
                     const fhsm_rev_db_t *db, int days,
                     const char *req_label,
                     fhsm_composite_sign_cb sign, void *sign_ctx,
                     uint8_t **out, size_t *out_len,
                     fhsm_ocsp_stats_t *stats,
                     char *err, size_t cap)
{
    int rc = FHSM_REV_EIO;
    X509 *ca = NULL;
    OCSP_REQUEST *req = NULL;
    fhsm_composite_ocsp_single_t *singles = NULL;
    uint8_t **cid_der = NULL, **rev_der = NULL;
    uint8_t *d_now = NULL, *d_nxt = NULL, *exts = NULL;
    uint8_t *basic = NULL, *resp = NULL;
    ASN1_GENERALIZEDTIME *g_now = NULL, *g_nxt = NULL;
    int nreq = 0;

    *out = NULL; *out_len = 0;
    if (stats) memset(stats, 0, sizeof *stats);
    if (days <= 0) return fail(err, cap, FHSM_REV_EIO, "validity must be positive.\n");

    { const uint8_t *p = ca_der; ca = d2i_X509(NULL, &p, (long)ca_len); }
    if (!ca) return fail(err, cap, FHSM_REV_EPARSE, "the CA certificate does not parse.\n");

    { const uint8_t *p = reqder; req = d2i_OCSP_REQUEST(NULL, &p, (long)req_len); }
    const char *what = req_label ? req_label : "the request";
    if (!req) { rc = fail(err, cap, FHSM_REV_EPARSE, "%s is not an OCSP request.\n", what); goto done; }

    nreq = OCSP_request_onereq_count(req);
    if (nreq <= 0) { rc = fail(err, cap, FHSM_REV_EPARSE, "%s asks about nothing.\n", what); goto done; }

    /* Times. OCSP uses GeneralizedTime throughout -- ASN1_TIME_set would give
     * a UTCTime for any date before 2050, which is a different tag and a
     * response no client will parse. */
    time_t now = time(NULL);
    g_now = ASN1_GENERALIZEDTIME_set(NULL, now);
    g_nxt = ASN1_GENERALIZEDTIME_set(NULL, now + (time_t)days * 86400);
    int n_now = g_now ? i2d_ASN1_GENERALIZEDTIME(g_now, &d_now) : 0;
    int n_nxt = g_nxt ? i2d_ASN1_GENERALIZEDTIME(g_nxt, &d_nxt) : 0;
    if (n_now <= 0 || n_nxt <= 0) { rc = fail(err, cap, FHSM_REV_EIO, "cannot encode the time.\n"); goto done; }

    singles = calloc((size_t)nreq, sizeof *singles);
    cid_der = calloc((size_t)nreq, sizeof *cid_der);
    rev_der = calloc((size_t)nreq, sizeof *rev_der);
    if (!singles || !cid_der || !rev_der) { rc = fail(err, cap, FHSM_REV_EIO, "out of memory\n"); goto done; }

    size_t n_ours = 0, n_revoked = 0, n_unknown = 0;
    for (int i = 0; i < nreq; i++) {
        OCSP_ONEREQ  *one = OCSP_request_onereq_get0(req, i);
        OCSP_CERTID  *cid = OCSP_onereq_get0_id(one);
        ASN1_OCTET_STRING *nh = NULL, *kh = NULL;
        ASN1_INTEGER      *sn = NULL;
        ASN1_OBJECT       *md_oid = NULL;

        if (!OCSP_id_get0_info(&nh, &md_oid, &kh, &sn, cid)) {
            rc = fail(err, cap, FHSM_REV_EPARSE, "malformed CertID in the request.\n"); goto done;
        }
        int len = i2d_OCSP_CERTID(cid, &cid_der[i]);
        if (len <= 0) { rc = fail(err, cap, FHSM_REV_EIO, "cannot re-encode a CertID.\n"); goto done; }

        singles[i].cert_id     = cid_der[i];
        singles[i].cert_id_len = (size_t)len;
        singles[i].this_upd    = d_now; singles[i].this_upd_len = (size_t)n_now;
        singles[i].next_upd    = d_nxt; singles[i].next_upd_len = (size_t)n_nxt;
        singles[i].reason      = -1;
        singles[i].status      = FHSM_OCSP_UNKNOWN;

        /* Is this question even about our CA? Rebuild the CertID we would have
         * produced and compare. A responder that answered "good" for an issuer
         * it knows nothing about would be asserting something it cannot know --
         * unknown is the honest answer and the RFC's. */
        const EVP_MD *md = EVP_get_digestbyobj(md_oid);
        if (!md) { n_unknown++; continue; }
        OCSP_CERTID *mine = OCSP_cert_id_new(md, X509_get_subject_name(ca),
                                              X509_get0_pubkey_bitstr(ca), sn);
        int ours = mine && OCSP_id_issuer_cmp(mine, cid) == 0;
        OCSP_CERTID_free(mine);
        if (!ours) { n_unknown++; continue; }
        n_ours++;

        const uint8_t *sb = ASN1_STRING_get0_data(sn);
        size_t sl = (size_t)ASN1_STRING_length(sn);
        const fhsm_rev_entry_t *e = fhsm_rev_db_find(db, sb, sl);
        if (e) {
            int64_t t = 0;
            (void)fhsm_rev_date_to_time(e->date, &t);      /* validated at load */
            ASN1_GENERALIZEDTIME *gr = ASN1_GENERALIZEDTIME_set(NULL, (time_t)t);
            int nr = gr ? i2d_ASN1_GENERALIZEDTIME(gr, &rev_der[i]) : 0;
            ASN1_GENERALIZEDTIME_free(gr);
            if (nr <= 0) { rc = fail(err, cap, FHSM_REV_EIO, "cannot encode a revocation date.\n"); goto done; }
            singles[i].status         = FHSM_OCSP_REVOKED;
            singles[i].revoked_at     = rev_der[i];
            singles[i].revoked_at_len = (size_t)nr;
            singles[i].reason         = e->reason;
            n_revoked++;
        } else {
            singles[i].status = FHSM_OCSP_GOOD;
        }
    }

    /* The nonce, echoed. RFC 8954: without it a recorded response can be
     * replayed until its nextUpdate, which is precisely how a revoked
     * certificate keeps being accepted after revocation. It is copied, never
     * generated -- a nonce the responder chose proves nothing to the client
     * that did not choose it. */
    size_t exts_len = 0;
    {
        int idx = OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1);
        if (idx >= 0) {
            X509_EXTENSION *e = OCSP_REQUEST_get_ext(req, idx);
            uint8_t *one = NULL;
            int n = e ? i2d_X509_EXTENSION(e, &one) : 0;
            if (n > 0) {
                exts = malloc((size_t)n + 8);
                if (!exts) { OPENSSL_free(one); rc = fail(err, cap, FHSM_REV_EIO, "out of memory\n"); goto done; }
                uint8_t hdr[4]; size_t hn;
                if ((size_t)n < 0x80) { hdr[0] = (uint8_t)n; hn = 1; }
                else if (n <= 0xFF)   { hdr[0] = 0x81; hdr[1] = (uint8_t)n; hn = 2; }
                else                  { hdr[0] = 0x82; hdr[1] = (uint8_t)(n >> 8);
                                        hdr[2] = (uint8_t)n; hn = 3; }
                exts[0] = 0x30; memcpy(exts + 1, hdr, hn);
                memcpy(exts + 1 + hn, one, (size_t)n);
                exts_len = 1 + hn + (size_t)n;
            }
            OPENSSL_free(one);
        }
    }

    size_t bcap = 16384 + ca_len + responder_len + (size_t)nreq * 512 + exts_len;
    basic = malloc(bcap);
    if (!basic) { rc = fail(err, cap, FHSM_REV_EIO, "out of memory\n"); goto done; }
    size_t bn = bcap;
    fhsm_rv_t r = fhsm_composite_ocsp(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                       responder_der, responder_len,
                                       d_now, (size_t)n_now,
                                       singles, (size_t)nreq, exts, exts_len,
                                       sign, sign_ctx, basic, &bn);
    if (r != FHSM_RV_OK) {
        rc = fail(err, cap, FHSM_REV_EIO,
                  "building the OCSP response failed (0x%lX).\n", (unsigned long)r);
        goto done;
    }

    resp = malloc(bn + 64);
    if (!resp) { rc = fail(err, cap, FHSM_REV_EIO, "out of memory\n"); goto done; }
    size_t rn = wrap_response(basic, bn, resp, bn + 64);
    if (!rn) { rc = fail(err, cap, FHSM_REV_EIO, "cannot wrap the response.\n"); goto done; }

    *out = resp; *out_len = rn; resp = NULL;
    if (stats) {
        stats->asked        = (size_t)nreq;
        stats->ours         = n_ours;
        stats->revoked      = n_revoked;
        stats->unknown      = n_unknown;
        stats->nonce_echoed = exts_len != 0;
    }
    rc = FHSM_REV_OK;

done:
    if (cid_der) for (int i = 0; i < nreq; i++) OPENSSL_free(cid_der[i]);
    if (rev_der) for (int i = 0; i < nreq; i++) OPENSSL_free(rev_der[i]);
    free(cid_der); free(rev_der); free(singles); free(exts);
    free(basic); free(resp);
    OPENSSL_free(d_now); OPENSSL_free(d_nxt);
    ASN1_GENERALIZEDTIME_free(g_now); ASN1_GENERALIZEDTIME_free(g_nxt);
    OCSP_REQUEST_free(req); X509_free(ca);
    return rc;
}
