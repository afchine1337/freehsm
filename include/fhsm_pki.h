/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * fhsm_pki.h --- requests, certificates and the rest, for any signing key.
 *
 *  docs/classic-algorithms-plan.md, stage 1. The composite builders in
 *  fhsm_composite.h never needed to know much about the composite: OpenSSL
 *  encodes the names, times, extensions and envelopes, and the composite code
 *  supplied three things -- the signature AlgorithmIdentifier, the
 *  SubjectPublicKeyInfo, and the signature itself, through a callback. Here
 *  those three are the caller's, as a signer, and the builders take any.
 *
 *  The composite is one signer among others: fhsm_composite_csr and its
 *  siblings now build a composite signer and call these, and must produce
 *  the same bytes they always did (tests/test_composite_*,
 *  tests/pki_tools_characterize.sh).
 *
 *  What a signer does NOT carry is a key type. Nothing here inspects one: the
 *  AlgorithmIdentifier and the public key arrive encoded, and the callback
 *  returns the signature already in the form the structure carries -- for
 *  ECDSA a DER Ecdsa-Sig-Value, which fhsm_pki_ecdsa_raw_to_der makes from
 *  what PKCS#11 returns.
 *
 *  Implemented in src/fhsm_composite.c, beside the helpers both share.
 * ========================================================================= */
#ifndef FHSM_PKI_H
#define FHSM_PKI_H

#include "fhsm_composite.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest signature any signer below can produce: ML-DSA-87, 4627 bytes,
 * is the longest; a 4096-bit RSA key makes 512. */
#define FHSM_PKI_SIG_MAX 8192u

/* How far before its issuance a certificate's validity begins, in seconds.
 * A notBefore of exactly now is refused by every verifier whose clock is
 * behind the CA's, by even a second -- "certificate is not yet valid". Found
 * 2026-10-05 by tests/pki_tools_algs.sh, which saw a root rejected seconds
 * after it was made when the VM's clock stepped back. One hour, as Let's
 * Encrypt backdates; notAfter is still issuance plus the days asked for. */
#define FHSM_PKI_BACKDATE_SECONDS 3600L

typedef struct {
    const uint8_t *algid; size_t algid_len;   /* signatureAlgorithm, DER        */
    const uint8_t *spki;  size_t spki_len;    /* the signer's own public key,
                                               * DER SubjectPublicKeyInfo -- used
                                               * where the signer is also the
                                               * subject: a request, a root    */
    fhsm_composite_sign_cb sign; void *sign_ctx;
} fhsm_pki_signer_t;

/* The signature algorithms the tools offer, and their AlgorithmIdentifiers. */
typedef enum {
    FHSM_PKI_SIG_COMPOSITE_MLDSA65_ED25519 = 0,
    FHSM_PKI_SIG_ECDSA_SHA256,          /* ecdsa-with-SHA256                    */
    FHSM_PKI_SIG_ECDSA_SHA384,          /* ecdsa-with-SHA384                    */
    FHSM_PKI_SIG_RSA_PSS_SHA256,        /* RSASSA-PSS, SHA-256, MGF1-SHA-256, 32 */
    FHSM_PKI_SIG_RSA_PKCS1_SHA256,      /* sha256WithRSAEncryption              */
    FHSM_PKI_SIG_ED25519,               /* id-Ed25519                           */
    FHSM_PKI_SIG_MLDSA44,               /* id-ml-dsa-44                         */
    FHSM_PKI_SIG_MLDSA65,               /* id-ml-dsa-65                         */
    FHSM_PKI_SIG_MLDSA87                /* id-ml-dsa-87                         */
} fhsm_pki_sigalg_t;

/* The DER AlgorithmIdentifier for `a`, in static storage. */
fhsm_rv_t fhsm_pki_algid(fhsm_pki_sigalg_t a, const uint8_t **der, size_t *der_len);

/* PKCS#11 returns an ECDSA signature as r || s, each half the length of the
 * group order; X.509, CRLs, OCSP and CMS carry the DER Ecdsa-Sig-Value
 * (RFC 3279 2.2.3). `rs_len` must be even. */
fhsm_rv_t fhsm_pki_ecdsa_raw_to_der(const uint8_t *rs, size_t rs_len,
                                     uint8_t *out, size_t *out_len);

/* A PKCS#10 request, signed by `s`, for `s`'s own key. */
fhsm_rv_t fhsm_pki_csr(const fhsm_pki_signer_t *s, const char *subject,
                        uint8_t *out, size_t *out_len);

/* A self-signed v3 CA certificate for `s`'s own key. As
 * fhsm_composite_selfsigned: basicConstraints CA:TRUE and keyUsage
 * keyCertSign, cRLSign, both critical; subjectKeyIdentifier by RFC 5280
 * 4.2.1.2 method (1). */
fhsm_rv_t fhsm_pki_selfsigned(const fhsm_pki_signer_t *s, const char *subject,
                               long serial, int days,
                               uint8_t *out, size_t *out_len);

/* A certificate for the key in `csr`, issued by `s` under `ca_cert`. As
 * fhsm_composite_issue, with one difference: the request may carry any key
 * the signer's algorithm has nothing to do with -- an ECDSA CA can certify a
 * composite key and the reverse. Its proof of possession is checked by its
 * own algorithm, the composite verifier for a composite request and OpenSSL
 * for the rest, before anything is signed: FHSM_RV_SIGNATURE_INVALID if it
 * fails, FHSM_RV_MECHANISM_INVALID if no verifier knows the algorithm. */
fhsm_rv_t fhsm_pki_issue(const fhsm_pki_signer_t *s,
                          const uint8_t *ca_cert, size_t ca_cert_len,
                          const uint8_t *csr, size_t csr_len,
                          const char *subject_override,
                          const char *san,
                          const char *const *crl_urls, size_t n_crl_urls,
                          fhsm_cert_profile_t profile,
                          int days,
                          fhsm_composite_rng_cb rng, void *rng_ctx,
                          uint8_t *out, size_t *out_len);

/* A CRL signed by `s` for the CA in `ca_cert`: as fhsm_composite_crl, the
 * TBSCertList assembled from parts OpenSSL encodes, with the signer's
 * AlgorithmIdentifier inside and out. */
fhsm_rv_t fhsm_pki_crl(const fhsm_pki_signer_t *s,
                        const uint8_t *ca_cert, size_t ca_cert_len,
                        const fhsm_composite_revoked_t *revoked, size_t n_revoked,
                        uint64_t crl_number, int days,
                        uint8_t *out, size_t *out_len);

/* A BasicOCSPResponse signed by `s`: as fhsm_composite_ocsp, the responder
 * certificate carried in certs [0]. Most callers want fhsm_ocsp_answer_ex in
 * fhsm_revocation.h, which builds the whole OCSPResponse from a request. */
fhsm_rv_t fhsm_pki_ocsp(const fhsm_pki_signer_t *s,
                         const uint8_t *responder_cert, size_t responder_cert_len,
                         const uint8_t *produced_at, size_t produced_at_len,
                         const fhsm_composite_ocsp_single_t *singles, size_t n,
                         const uint8_t *exts, size_t exts_len,
                         uint8_t *out, size_t *out_len);

/* --- CMS ------------------------------------------------------------------
 *
 * A detached RFC 5652 SignedData over a digest the caller computed, carrying
 * the signer's certificate, as fhsm_composite_cms makes for the composite.
 *
 * `digest_name` names the digest -- "SHA256", "SHA384" or "SHA512" -- and it
 * must be the hash the signature algorithm itself uses, where it uses one: a
 * verifier hashes the signed attributes with the CMS digestAlgorithm, so
 * ecdsa-with-SHA256 needs SHA256. SHA-256 for P-256 and RSA, SHA-384 for
 * P-384, SHA-512 for Ed25519 (RFC 8419), ML-DSA and the composite. */
fhsm_rv_t fhsm_pki_cms(const fhsm_pki_signer_t *s, const char *digest_name,
                        const uint8_t *cert, size_t cert_len,
                        const uint8_t *digest, size_t digest_len,
                        uint8_t *out, size_t *out_len);

/* Which digest to compute over the data before checking `cms`: the name of
 * its digestAlgorithm, in static storage. So a caller can hash the data in
 * one pass without knowing in advance what signed it. */
fhsm_rv_t fhsm_pki_cms_digest(const uint8_t *cms, size_t cms_len, const char **name);

/* Check a detached CMS against the digest the caller computed with the
 * function fhsm_pki_cms_digest named. Needs no token and no key: the
 * signer's certificate is inside. A composite CMS goes to
 * fhsm_composite_cms_verify, unchanged; the others are checked here, over the
 * signed attributes as they appear when the structure is re-encoded.
 *
 * FHSM_RV_OK, FHSM_RV_SIGNATURE_INVALID for a signature or a digest that does
 * not match, FHSM_RV_ARGUMENTS_BAD for a structure this cannot read -- kept
 * apart as fhsm_composite_cms_verify keeps them: one means the data changed,
 * the other that the file is not what was expected. */
fhsm_rv_t fhsm_pki_cms_verify(const uint8_t *cms, size_t cms_len,
                               const uint8_t *digest, size_t digest_len);

#ifdef __cplusplus
}
#endif
#endif /* FHSM_PKI_H */
