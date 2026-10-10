/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * tools/cms_env.c --- see tools/cms_env.h.
 *
 *  The structure, with the tags written here:
 *
 *  30 ContentInfo
 *     06 id-ct-authEnvelopedData            1.2.840.113549.1.9.16.1.23
 *     A0 [0] EXPLICIT
 *        30 AuthEnvelopedData
 *           02 version 0
 *           31 RecipientInfos
 *              A2 [2] KEKRecipientInfo
 *                 02 version 4
 *                 30 KEKIdentifier { 04 keyIdentifier }
 *                 30 AlgorithmIdentifier { 06 id-aesNNN-wrap }   (RFC 3565)
 *                 04 encryptedKey
 *           30 EncryptedContentInfo
 *              06 id-data                         1.2.840.113549.1.7.1
 *              30 AlgorithmIdentifier
 *                 06 id-aesNNN-GCM                (RFC 5084)
 *                 30 GCMParameters { 04 aes-nonce, 02 aes-ICVlen }
 *              80 [0] IMPLICIT encryptedContent   <- the content, streamed
 *           04 mac                                <- the tail
 * ========================================================================= */
#include "cms_env.h"

#include <stdlib.h>
#include <string.h>

/* id-ct-authEnvelopedData */
static const uint8_t OID_AUTH_ENV[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x17 };
/* id-data */
static const uint8_t OID_DATA[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
/* 2.16.840.1.101.3.4.1.x: aes, with the last arc naming mode and size. */
static const uint8_t OID_AES_PREFIX[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01 };

static uint8_t wrap_arc(int bits) { return bits == 128 ? 5 : bits == 192 ? 25 : bits == 256 ? 45 : 0; }
static uint8_t gcm_arc(int bits)  { return bits == 128 ? 6 : bits == 192 ? 26 : bits == 256 ? 46 : 0; }

/* --- writing ------------------------------------------------------------ */

static uint64_t len_bytes(uint64_t len) {
    if (len < 0x80) return 1;
    uint64_t n = 0;
    for (uint64_t v = len; v; v >>= 8) n++;
    return 1 + n;
}
/* The size of a whole TLV whose value is `len` bytes. */
static uint64_t tlv(uint64_t len) { return 1 + len_bytes(len) + len; }

static int put_tl(FILE *f, uint8_t tag, uint64_t len) {
    uint8_t b[10]; size_t n = 0;
    b[n++] = tag;
    if (len < 0x80) {
        b[n++] = (uint8_t)len;
    } else {
        uint8_t tmp[8]; size_t k = 0;
        for (uint64_t v = len; v; v >>= 8) tmp[k++] = (uint8_t)(v & 0xFF);
        b[n++] = (uint8_t)(0x80 | k);
        while (k) b[n++] = tmp[--k];
    }
    return fwrite(b, 1, n, f) == n ? 0 : -1;
}
static int put(FILE *f, const void *p, size_t n) { return fwrite(p, 1, n, f) == n ? 0 : -1; }
static int put_oid_aes(FILE *f, uint8_t arc) {
    return put_tl(f, 0x06, sizeof OID_AES_PREFIX + 1) || put(f, OID_AES_PREFIX, sizeof OID_AES_PREFIX)
        || put(f, &arc, 1);
}

/* RecipientInfos are small and built in memory, then handed to the head
 * writer whole: one writer for every kind of recipient. */
struct db { uint8_t *p; size_t n, cap; int bad; };

static void db_put(struct db *d, const void *v, size_t n) {
    if (d->bad) return;
    if (d->n + n > d->cap) {
        size_t c = d->cap ? d->cap * 2 : 256;
        while (c < d->n + n) c *= 2;
        uint8_t *q = realloc(d->p, c);
        if (!q) { d->bad = 1; return; }
        d->p = q; d->cap = c;
    }
    memcpy(d->p + d->n, v, n);
    d->n += n;
}
static void db_tl(struct db *d, uint8_t tag, uint64_t len) {
    uint8_t b[10]; size_t n = 0;
    b[n++] = tag;
    if (len < 0x80) {
        b[n++] = (uint8_t)len;
    } else {
        uint8_t tmp[8]; size_t k = 0;
        for (uint64_t v = len; v; v >>= 8) tmp[k++] = (uint8_t)(v & 0xFF);
        b[n++] = (uint8_t)(0x80 | k);
        while (k) b[n++] = tmp[--k];
    }
    db_put(d, b, n);
}
static uint8_t *db_done(struct db *d, size_t *len) {
    if (d->bad) { free(d->p); return NULL; }
    *len = d->n;
    return d->p;
}

uint8_t *cmsenv_kekri(const uint8_t *id, size_t id_len, int wrap_bits,
                      const uint8_t *ekey, size_t ekey_len, size_t *out_len) {
    if (!wrap_arc(wrap_bits)) return NULL;
    const uint64_t oid_aes = tlv(sizeof OID_AES_PREFIX + 1);
    uint64_t in = 3 + tlv(tlv(id_len)) + tlv(oid_aes) + tlv(ekey_len);
    static const uint8_t v4[] = { 0x02, 0x01, 0x04 };
    uint8_t arc = wrap_arc(wrap_bits);
    struct db d = { 0 };
    db_tl(&d, 0xA2, in); db_put(&d, v4, 3);
    db_tl(&d, 0x30, tlv(id_len)); db_tl(&d, 0x04, id_len); db_put(&d, id, id_len);
    db_tl(&d, 0x30, oid_aes);
    db_tl(&d, 0x06, sizeof OID_AES_PREFIX + 1); db_put(&d, OID_AES_PREFIX, sizeof OID_AES_PREFIX); db_put(&d, &arc, 1);
    db_tl(&d, 0x04, ekey_len); db_put(&d, ekey, ekey_len);
    return db_done(&d, out_len);
}

/* RSAES-OAEP with SHA-256 and MGF1-SHA-256, the empty label (RFC 4055 §4.1).
 * The SHA-256 AlgorithmIdentifiers carry no parameters, as RFC 4055 asks and
 * OpenSSL writes; NULL ones are accepted when read. */
static const uint8_t OID_RSAES_OAEP[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07 };
static const uint8_t OID_RSA_ENC[]    = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const uint8_t OID_MGF1[]       = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08 };
static const uint8_t OID_SHA256[]     = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };

static void db_sha256_alg(struct db *d) {
    db_tl(d, 0x30, tlv(sizeof OID_SHA256));
    db_tl(d, 0x06, sizeof OID_SHA256); db_put(d, OID_SHA256, sizeof OID_SHA256);
}

uint8_t *cmsenv_ktri_oaep(const uint8_t *ski, size_t ski_len,
                          const uint8_t *ias, size_t ias_len,
                          const uint8_t *ekey, size_t ekey_len, size_t *out_len) {
    if (!!ski == !!ias) return NULL;                /* exactly one identifier */
    const uint64_t sha = tlv(tlv(sizeof OID_SHA256));
    const uint64_t mgf_in = tlv(sizeof OID_MGF1) + sha;
    const uint64_t prm_in = tlv(sha) + tlv(tlv(mgf_in));
    const uint64_t alg_in = tlv(sizeof OID_RSAES_OAEP) + tlv(prm_in);
    const uint64_t rid = ski ? tlv(ski_len) : ias_len;
    const uint64_t in = 3 + rid + tlv(alg_in) + tlv(ekey_len);
    /* version 2 with a subjectKeyIdentifier, 0 with issuerAndSerialNumber */
    const uint8_t ver[] = { 0x02, 0x01, (uint8_t)(ski ? 2 : 0) };
    struct db d = { 0 };
    db_tl(&d, 0x30, in); db_put(&d, ver, 3);
    if (ski) { db_tl(&d, 0x80, ski_len); db_put(&d, ski, ski_len); }
    else     db_put(&d, ias, ias_len);
    db_tl(&d, 0x30, alg_in);
    db_tl(&d, 0x06, sizeof OID_RSAES_OAEP); db_put(&d, OID_RSAES_OAEP, sizeof OID_RSAES_OAEP);
    db_tl(&d, 0x30, prm_in);
    db_tl(&d, 0xA0, sha); db_sha256_alg(&d);
    db_tl(&d, 0xA1, tlv(mgf_in));
    db_tl(&d, 0x30, mgf_in);
    db_tl(&d, 0x06, sizeof OID_MGF1); db_put(&d, OID_MGF1, sizeof OID_MGF1);
    db_sha256_alg(&d);
    db_tl(&d, 0x04, ekey_len); db_put(&d, ekey, ekey_len);
    return db_done(&d, out_len);
}

int cmsenv_write_head(FILE *f, const uint8_t *ri, size_t ri_len, int gcm_bits,
                      const uint8_t *nonce, size_t nonce_len,
                      uint64_t content_len, size_t tag_len) {
    if (!ri || !gcm_arc(gcm_bits) || tag_len < 12 || tag_len > 16
        || nonce_len == 0 || nonce_len > 16) return -1;
    const uint64_t oid_aes = tlv(sizeof OID_AES_PREFIX + 1);

    /* Sizes, innermost first. */
    uint64_t set_in = ri_len;
    uint64_t gp_in  = tlv(nonce_len) + 3;                 /* nonce, INTEGER tag_len */
    uint64_t alg_in = oid_aes + tlv(gp_in);
    uint64_t eci_in = tlv(sizeof OID_DATA) + tlv(alg_in) + tlv(content_len);
    uint64_t aed_in = 3 + tlv(set_in) + tlv(eci_in) + tlv(tag_len);
    uint64_t ci_in  = tlv(sizeof OID_AUTH_ENV) + tlv(tlv(aed_in));

    static const uint8_t v0[] = { 0x02, 0x01, 0x00 };
    uint8_t icv[] = { 0x02, 0x01, (uint8_t)tag_len };
    return put_tl(f, 0x30, ci_in)
        || put_tl(f, 0x06, sizeof OID_AUTH_ENV) || put(f, OID_AUTH_ENV, sizeof OID_AUTH_ENV)
        || put_tl(f, 0xA0, tlv(aed_in))
        || put_tl(f, 0x30, aed_in) || put(f, v0, 3)
        || put_tl(f, 0x31, set_in) || put(f, ri, ri_len)
        || put_tl(f, 0x30, eci_in)
        || put_tl(f, 0x06, sizeof OID_DATA) || put(f, OID_DATA, sizeof OID_DATA)
        || put_tl(f, 0x30, alg_in) || put_oid_aes(f, gcm_arc(gcm_bits))
        || put_tl(f, 0x30, gp_in) || put_tl(f, 0x04, nonce_len) || put(f, nonce, nonce_len)
        || put(f, icv, 3)
        || put_tl(f, 0x80, content_len)
        ? -1 : 0;
}

int cmsenv_write_tail(FILE *f, const uint8_t *tag, size_t tag_len) {
    return put_tl(f, 0x04, tag_len) || put(f, tag, tag_len) ? -1 : 0;
}

/* --- reading ------------------------------------------------------------ */

struct rd { const uint8_t *p; size_t n, pos; };

/* One TL. Definite lengths only. `*len` may exceed what is left in the
 * buffer -- the encrypted content does -- and the caller decides whether
 * that is allowed. */
static int get_tl(struct rd *r, uint8_t *tag, uint64_t *len) {
    if (r->pos + 2 > r->n) return -1;
    *tag = r->p[r->pos++];
    if ((*tag & 0x1F) == 0x1F) return -1;          /* high tag numbers: none here */
    uint8_t b = r->p[r->pos++];
    if (b < 0x80) { *len = b; return 0; }
    size_t k = b & 0x7F;
    if (k == 0 || k > 8 || r->pos + k > r->n) return -1;   /* 0x80: indefinite */
    uint64_t v = 0;
    for (size_t i = 0; i < k; i++) v = (v << 8) | r->p[r->pos++];
    *len = v;
    return 0;
}

/* A TL that must have tag `want` and whose value fits in the buffer. */
static int expect(struct rd *r, uint8_t want, uint64_t *len) {
    uint8_t t;
    if (get_tl(r, &t, len) || t != want || *len > r->n - r->pos) return -1;
    return 0;
}

static int aes_oid_arc(const uint8_t *v, uint64_t len, uint8_t *arc) {
    if (len != sizeof OID_AES_PREFIX + 1 || memcmp(v, OID_AES_PREFIX, sizeof OID_AES_PREFIX)) return -1;
    *arc = v[sizeof OID_AES_PREFIX];
    return 0;
}

#define FAIL(msg) do { *why = (msg); return -1; } while (0)

static int parse_kek(struct rd *r, uint64_t len, struct cmsenv_head *h, const char **why) {
    size_t end = r->pos + (size_t)len;
    uint64_t l;
    if (expect(r, 0x02, &l) || l != 1 || r->p[r->pos] != 4) FAIL("a KEK recipient whose version is not 4");
    r->pos += 1;
    if (expect(r, 0x30, &l)) FAIL("a KEK recipient without a KEKIdentifier");
    size_t kid_end = r->pos + (size_t)l;
    uint64_t il;
    if (expect(r, 0x04, &il)) FAIL("a KEKIdentifier without a keyIdentifier");
    struct cmsenv_kek k = { r->p + r->pos, (size_t)il, 0, NULL, 0 };
    r->pos = kid_end;                               /* date and other: not used */
    if (expect(r, 0x30, &l)) FAIL("a KEK recipient without its wrap algorithm");
    size_t alg_end = r->pos + (size_t)l;
    uint64_t ol; uint8_t arc;
    if (expect(r, 0x06, &ol) || aes_oid_arc(r->p + r->pos, ol, &arc))
        FAIL("a KEK recipient whose key is not wrapped with AES key wrap");
    k.wrap_bits = arc == 5 ? 128 : arc == 25 ? 192 : arc == 45 ? 256 : 0;
    if (!k.wrap_bits) FAIL("a KEK recipient whose key is not wrapped with AES key wrap");
    r->pos = alg_end;
    if (expect(r, 0x04, &l)) FAIL("a KEK recipient without its encrypted key");
    k.ekey = r->p + r->pos; k.ekey_len = (size_t)l;
    r->pos = end;
    if (h->n_kek < CMSENV_KEK_MAX) h->kek[h->n_kek++] = k;
    return 0;
}

/* An AlgorithmIdentifier whose OID is `oid`, parameters absent or NULL. */
static int is_alg(struct rd *r, const uint8_t *oid, size_t oid_len) {
    uint64_t l, ol;
    if (expect(r, 0x30, &l)) return 0;
    size_t end = r->pos + (size_t)l;
    if (expect(r, 0x06, &ol) || ol != oid_len || memcmp(r->p + r->pos, oid, oid_len)) return 0;
    r->pos += (size_t)ol;
    if (r->pos < end && !(end - r->pos == 2 && r->p[r->pos] == 0x05 && r->p[r->pos + 1] == 0)) return 0;
    r->pos = end;
    return 1;
}

/* RSAES-OAEP-params: SHA-256, MGF1 with SHA-256, the empty label. Anything
 * else is named, not guessed at: SHA-1 is the default the structure falls
 * back to when the fields are left out. */
static const char *oaep_params(struct rd *r, size_t end) {
    int hash_ok = 0, mgf_ok = 0;
    uint64_t l;
    if (r->pos < end && r->p[r->pos] == 0xA0) {
        if (expect(r, 0xA0, &l)) return "malformed RSAES-OAEP parameters";
        size_t e0 = r->pos + (size_t)l;
        hash_ok = is_alg(r, OID_SHA256, sizeof OID_SHA256) && r->pos == e0;
        r->pos = e0;
    }
    if (r->pos < end && r->p[r->pos] == 0xA1) {
        if (expect(r, 0xA1, &l)) return "malformed RSAES-OAEP parameters";
        size_t e1 = r->pos + (size_t)l;
        uint64_t sl, ol;
        if (!expect(r, 0x30, &sl)) {
            size_t se = r->pos + (size_t)sl;
            if (!expect(r, 0x06, &ol) && ol == sizeof OID_MGF1 && !memcmp(r->p + r->pos, OID_MGF1, ol)) {
                r->pos += (size_t)ol;
                mgf_ok = is_alg(r, OID_SHA256, sizeof OID_SHA256) && r->pos == se;
            }
        }
        r->pos = e1;
    }
    if (r->pos < end) return "RSA-OAEP with a label, which this does not open";
    if (!hash_ok || !mgf_ok) return "RSA-OAEP with a hash other than SHA-256, which this does not open";
    return NULL;
}

static int parse_ktri(struct rd *r, uint64_t len, struct cmsenv_head *h, const char **why) {
    size_t end = r->pos + (size_t)len;
    struct cmsenv_ktri k;
    memset(&k, 0, sizeof k);
    uint64_t l;
    if (expect(r, 0x02, &l) || l != 1 || (r->p[r->pos] != 0 && r->p[r->pos] != 2))
        FAIL("a key-transport recipient whose version is neither 0 nor 2");
    r->pos += 1;
    if (r->pos < end && r->p[r->pos] == 0x80) {
        if (expect(r, 0x80, &l)) FAIL("a malformed subjectKeyIdentifier");
        k.ski = r->p + r->pos; k.ski_len = (size_t)l;
        r->pos += (size_t)l;
    } else {
        size_t at = r->pos;
        if (expect(r, 0x30, &l)) FAIL("a key-transport recipient that names no key");
        r->pos += (size_t)l;
        k.ias = r->p + at; k.ias_len = r->pos - at;
    }
    if (expect(r, 0x30, &l)) FAIL("a key-transport recipient without its algorithm");
    size_t alg_end = r->pos + (size_t)l;
    uint64_t ol;
    if (expect(r, 0x06, &ol)) FAIL("a key-transport recipient without its algorithm");
    const uint8_t *oid = r->p + r->pos;
    r->pos += (size_t)ol;
    if (ol == sizeof OID_RSAES_OAEP && !memcmp(oid, OID_RSAES_OAEP, ol)) {
        uint64_t pl;
        if (r->pos >= alg_end || expect(r, 0x30, &pl))
            k.refused = "RSA-OAEP with SHA-1, which this does not open";
        else
            k.refused = oaep_params(r, r->pos + (size_t)pl);
    } else if (ol == sizeof OID_RSA_ENC && !memcmp(oid, OID_RSA_ENC, ol)) {
        k.refused = "RSA PKCS#1 v1.5 key transport, which this does not open: it is the "
                    "padding Bleichenbacher's attack works on";
    } else {
        k.refused = "a key-transport algorithm this does not know";
    }
    r->pos = alg_end;
    if (expect(r, 0x04, &l)) FAIL("a key-transport recipient without its encrypted key");
    k.ekey = r->p + r->pos; k.ekey_len = (size_t)l;
    r->pos = end;
    if (h->n_ktri < CMSENV_KTRI_MAX) h->ktri[h->n_ktri++] = k;
    return 0;
}

int cmsenv_parse_head(const uint8_t *buf, size_t n, struct cmsenv_head *h, const char **why) {
    struct rd r = { buf, n, 0 };
    uint64_t l; uint8_t t;
    memset(h, 0, sizeof *h);

    if (get_tl(&r, &t, &l) || t != 0x30)
        FAIL("not a DER CMS structure (an indefinite-length BER file can be converted with "
             "openssl cms -cmsout -outform DER)");
    if (expect(&r, 0x06, &l) || l != sizeof OID_AUTH_ENV || memcmp(r.p + r.pos, OID_AUTH_ENV, l))
        FAIL("not CMS AuthEnvelopedData");
    r.pos += (size_t)l;
    if (get_tl(&r, &t, &l) || t != 0xA0) FAIL("AuthEnvelopedData without its content");
    if (get_tl(&r, &t, &l) || t != 0x30) FAIL("AuthEnvelopedData is not a SEQUENCE");
    if (expect(&r, 0x02, &l) || l != 1 || r.p[r.pos] != 0) FAIL("AuthEnvelopedData version is not 0");
    r.pos += 1;
    if (r.pos < n && r.p[r.pos] == 0xA0) {         /* originatorInfo: skipped */
        if (expect(&r, 0xA0, &l)) FAIL("a malformed originatorInfo");
        r.pos += (size_t)l;
    }
    if (expect(&r, 0x31, &l)) FAIL("no recipients");
    size_t set_end = r.pos + (size_t)l;
    while (r.pos < set_end) {
        if (get_tl(&r, &t, &l) || l > set_end - r.pos) FAIL("a malformed recipient");
        if (t == 0xA2) {
            if (parse_kek(&r, l, h, why)) return -1;
        } else if (t == 0x30) {
            if (parse_ktri(&r, l, h, why)) return -1;
        } else {
            h->n_other++;                           /* A1 kari, A3 pwri, A4 ori */
            r.pos += (size_t)l;
        }
    }
    /* EncryptedContentInfo holds the content itself, so its length runs past
     * the head: its tag is checked, its length is not held to the buffer.
     * Holding it there passed every file under 64 KiB and refused the rest. */
    if (get_tl(&r, &t, &l) || t != 0x30) FAIL("no EncryptedContentInfo");
    if (expect(&r, 0x06, &l) || l != sizeof OID_DATA || memcmp(r.p + r.pos, OID_DATA, l))
        FAIL("the encrypted content is not plain data");
    r.pos += (size_t)l;
    if (expect(&r, 0x30, &l)) FAIL("no content-encryption algorithm");
    size_t alg_end = r.pos + (size_t)l;
    uint8_t arc;
    if (expect(&r, 0x06, &l) || aes_oid_arc(r.p + r.pos, l, &arc)) FAIL("the content is not AES-GCM");
    h->gcm_bits = arc == 6 ? 128 : arc == 26 ? 192 : arc == 46 ? 256 : 0;
    if (!h->gcm_bits) FAIL("the content is not AES-GCM");
    r.pos += (size_t)l;
    if (expect(&r, 0x30, &l)) FAIL("AES-GCM without its parameters");
    size_t gp_end = r.pos + (size_t)l;
    if (expect(&r, 0x04, &l) || l == 0 || l > sizeof h->nonce) FAIL("an AES-GCM nonce this does not take");
    memcpy(h->nonce, r.p + r.pos, (size_t)l); h->nonce_len = (size_t)l;
    r.pos += (size_t)l;
    h->tag_len = 12;                                /* aes-ICVlen DEFAULT 12 */
    if (r.pos < gp_end) {
        if (expect(&r, 0x02, &l) || l != 1 || r.p[r.pos] < 12 || r.p[r.pos] > 16)
            FAIL("an AES-GCM tag length outside 12..16");
        h->tag_len = r.p[r.pos];
        r.pos += 1;
    }
    r.pos = alg_end;
    if (get_tl(&r, &t, &l)) FAIL("no encrypted content");
    if (t == 0xA0) FAIL("the encrypted content is in BER pieces; convert with openssl cms -cmsout -outform DER");
    if (t != 0x80) FAIL("no encrypted content");
    h->content_off = r.pos;
    h->content_len = l;
    if (h->n_kek == 0 && h->n_ktri == 0)
        FAIL(h->n_other ? "no recipient this tool opens: key agreement, password and other "
                          "recipients are not read" : "no recipients");
    return 0;
}

int cmsenv_parse_tail(const uint8_t *buf, size_t n, const struct cmsenv_head *h,
                      const uint8_t **tag, const char **why) {
    struct rd r = { buf, n, 0 };
    uint64_t l; uint8_t t;
    if (get_tl(&r, &t, &l)) FAIL("the file ends before its authentication tag");
    if (t == 0xA1) FAIL("authenticated attributes, which this does not read");
    if (t != 0x04 || l != h->tag_len || l > n - r.pos) FAIL("an authentication tag of the wrong length");
    *tag = r.p + r.pos;
    r.pos += (size_t)l;
    /* unauthAttrs [2] may follow; nothing else may. */
    if (r.pos < n && r.p[r.pos] != 0xA2) FAIL("bytes after the authentication tag");
    return 0;
}
