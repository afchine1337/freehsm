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

int cmsenv_write_head(FILE *f, const uint8_t *kek_id, size_t kek_id_len, int wrap_bits,
                      const uint8_t *ekey, size_t ekey_len, int gcm_bits,
                      const uint8_t *nonce, size_t nonce_len,
                      uint64_t content_len, size_t tag_len) {
    if (!wrap_arc(wrap_bits) || !gcm_arc(gcm_bits) || tag_len < 12 || tag_len > 16
        || nonce_len == 0 || nonce_len > 16) return -1;
    const uint64_t oid_aes = tlv(sizeof OID_AES_PREFIX + 1);

    /* Sizes, innermost first. */
    uint64_t kekid  = tlv(tlv(kek_id_len));
    uint64_t ri_in  = 3 + kekid + tlv(oid_aes) + tlv(ekey_len);
    uint64_t set_in = tlv(ri_in);
    uint64_t gp_in  = tlv(nonce_len) + 3;                 /* nonce, INTEGER tag_len */
    uint64_t alg_in = oid_aes + tlv(gp_in);
    uint64_t eci_in = tlv(sizeof OID_DATA) + tlv(alg_in) + tlv(content_len);
    uint64_t aed_in = 3 + tlv(set_in) + tlv(eci_in) + tlv(tag_len);
    uint64_t ci_in  = tlv(sizeof OID_AUTH_ENV) + tlv(tlv(aed_in));

    static const uint8_t v0[] = { 0x02, 0x01, 0x00 }, v4[] = { 0x02, 0x01, 0x04 };
    uint8_t icv[] = { 0x02, 0x01, (uint8_t)tag_len };
    return put_tl(f, 0x30, ci_in)
        || put_tl(f, 0x06, sizeof OID_AUTH_ENV) || put(f, OID_AUTH_ENV, sizeof OID_AUTH_ENV)
        || put_tl(f, 0xA0, tlv(aed_in))
        || put_tl(f, 0x30, aed_in) || put(f, v0, 3)
        || put_tl(f, 0x31, set_in)
        || put_tl(f, 0xA2, ri_in) || put(f, v4, 3)
        || put_tl(f, 0x30, tlv(kek_id_len)) || put_tl(f, 0x04, kek_id_len) || put(f, kek_id, kek_id_len)
        || put_tl(f, 0x30, oid_aes) || put_oid_aes(f, wrap_arc(wrap_bits))
        || put_tl(f, 0x04, ekey_len) || put(f, ekey, ekey_len)
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
        } else {
            h->n_other++;                           /* 30 ktri, A1 kari, A3 pwri, A4 ori */
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
    if (h->n_kek == 0)
        FAIL(h->n_other ? "no recipient this tool opens: only key-encryption-key recipients for now"
                        : "no recipients");
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
