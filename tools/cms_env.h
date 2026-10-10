/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * tools/cms_env.h --- CMS AuthEnvelopedData (RFC 5083), AES-GCM content
 * (RFC 5084), as fhsm-crypt writes and reads it (docs/fhsm-crypt-plan.md).
 *
 *  Why not OpenSSL's CMS API: a KEK recipient there is made and opened by
 *  handing OpenSSL the key-encryption key's bytes (CMS_add0_recipient_key,
 *  CMS_decrypt_set1_key), and a key held in a token never yields them. The
 *  public API neither takes a content key nor exposes a RecipientInfo's
 *  encryptedKey. Measured against OpenSSL 3.3 and 3.5 headers, 2026-10-10.
 *  So the structure is written and read here, and OpenSSL does what it is
 *  for: AES-GCM over the content, and -- in tests/test_pkiops_envelope.c --
 *  reading what this writes and writing what this reads.
 *
 *  Only what this project produces and what OpenSSL produces for the same
 *  case are read: definite-length DER, a primitive encryptedContent, no
 *  authenticated attributes. A file outside that is refused by name, never
 *  half-read.
 *
 *  The content is not held in memory. The head -- everything before the
 *  encrypted bytes -- is written with its exact lengths, the content follows
 *  in chunks, then the tail: the GCM tag. Reading is the same in reverse.
 * ========================================================================= */
#ifndef FHSM_TOOLS_CMS_ENV_H
#define FHSM_TOOLS_CMS_ENV_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* More than any head this writes or OpenSSL writes for a handful of
 * recipients; a head that does not fit is refused, not truncated. */
#define CMSENV_HEAD_MAX  65536u
#define CMSENV_KEK_MAX   8u
#define CMSENV_KTRI_MAX  8u

/* A key-encryption-key recipient (KEKRecipientInfo, RFC 5652 §6.2.3). */
struct cmsenv_kek {
    const uint8_t *id;   size_t id_len;     /* KEKIdentifier.keyIdentifier */
    int            wrap_bits;               /* 128, 192, 256: id-aesNNN-wrap */
    const uint8_t *ekey; size_t ekey_len;   /* the wrapped content key */
};

/* A key-transport recipient (KeyTransRecipientInfo, RFC 5652 §6.2.1). Only
 * RSAES-OAEP with SHA-256 and MGF1-SHA-256 is opened; any other is listed
 * with the reason in `refused`, so a caller can say why the file did not
 * open rather than that it did not. */
struct cmsenv_ktri {
    const uint8_t *ski;  size_t ski_len;    /* [0] subjectKeyIdentifier, or */
    const uint8_t *ias;  size_t ias_len;    /* issuerAndSerialNumber, whole TLV */
    const char    *refused;                 /* NULL when this tool can open it */
    const uint8_t *ekey; size_t ekey_len;
};

struct cmsenv_head {
    struct cmsenv_kek kek[CMSENV_KEK_MAX];
    size_t   n_kek;
    struct cmsenv_ktri ktri[CMSENV_KTRI_MAX];
    size_t   n_ktri;
    size_t   n_other;           /* recipients of other kinds, not read here */
    int      gcm_bits;          /* 128, 192 or 256 */
    uint8_t  nonce[16];
    size_t   nonce_len;
    size_t   tag_len;           /* aes-ICVlen; 12 when the file leaves it out */
    uint64_t content_off;       /* where the encrypted bytes start */
    uint64_t content_len;
};

/* One RecipientInfo, DER, malloc'd; NULL on a bad argument or no memory.
 * A key-encryption-key recipient, its key wrapped with AES key wrap: */
uint8_t *cmsenv_kekri(const uint8_t *id, size_t id_len, int wrap_bits,
                      const uint8_t *ekey, size_t ekey_len, size_t *out_len);
/* A key-transport recipient, RSAES-OAEP with SHA-256 and MGF1-SHA-256,
 * named by a subjectKeyIdentifier or by an issuerAndSerialNumber (its whole
 * DER) -- exactly one of the two. */
uint8_t *cmsenv_ktri_oaep(const uint8_t *ski, size_t ski_len,
                          const uint8_t *ias, size_t ias_len,
                          const uint8_t *ekey, size_t ekey_len, size_t *out_len);

/* Write everything before the encrypted content, for the recipient `ri`. The
 * content that follows must be exactly `content_len` bytes, and the tail
 * then carries a tag of `tag_len` bytes. 0 on success. */
int cmsenv_write_head(FILE *f, const uint8_t *ri, size_t ri_len, int gcm_bits,
                      const uint8_t *nonce, size_t nonce_len,
                      uint64_t content_len, size_t tag_len);

/* Write what follows the content: the tag. */
int cmsenv_write_tail(FILE *f, const uint8_t *tag, size_t tag_len);

/* Read the head from the first `n` bytes of a file. Pointers in `out` point
 * into `buf`. 0 on success; otherwise `*why` says what is wrong in a phrase
 * a person can act on. */
int cmsenv_parse_head(const uint8_t *buf, size_t n, struct cmsenv_head *out,
                      const char **why);

/* Read the tail -- the bytes after the content, to the end of the file --
 * and return the tag. */
int cmsenv_parse_tail(const uint8_t *buf, size_t n, const struct cmsenv_head *h,
                      const uint8_t **tag, const char **why);

#endif
