/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_composite_csr.c --- PKCS#10 with a composite key (#112).
 *
 *  The criterion is external. A certification request exists to be sent to
 *  somebody else's CA, so the question is not whether we can read it back --
 *  our writer agreeing with our reader proves nothing, which is the lesson of
 *  the self-generated KATs that let the old hybrid sign the wrong thing for
 *  months. The question is whether OpenSSL's parser accepts it, recovers the
 *  subject and the key, and whether the signature verifies over exactly the
 *  bytes OpenSSL says are the to-be-signed part.
 *
 *  That last check is the one worth having. Verifying our own signature over
 *  our own idea of the TBS would pass even if we signed the wrong region.
 *  Re-deriving the TBS from the parsed request closes that.
 * ========================================================================= */
#include "fhsm_composite.h"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
static void ck(const char *what, int ok, const char *detail) {
    printf("  %-58s %s\n", what, ok ? "OK" : "<<< FAIL");
    if (detail && *detail) printf("      %s\n", detail);
    if (!ok) fails++;
}

/* The signing callback. Here it calls the library directly; fhsm-csr will pass
 * one that goes through C_Sign instead, which is the point of the indirection:
 * the CSR builder never sees a key. */
struct sctx { const uint8_t *priv; size_t priv_len; int calls; size_t tbs_seen; };

static fhsm_rv_t do_sign(void *vctx, const uint8_t *tbs, size_t tbs_len,
                          uint8_t *sig, size_t *sig_len) {
    struct sctx *c = vctx;
    c->calls++; c->tbs_seen = tbs_len;
    return fhsm_composite_sign(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                c->priv, c->priv_len, tbs, tbs_len,
                                NULL, 0, sig, sig_len);
}

int main(void) {
    printf("=== test_composite_csr : PKCS#10 with a composite key (#112) ===\n\n");

    static uint8_t priv[FHSM_COMPOSITE_PRIV_MAX], pub[FHSM_COMPOSITE_PUB_MAX];
    size_t pl = sizeof priv, ql = sizeof pub;
    if (fhsm_composite_keygen(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                               priv, &pl, pub, &ql) != FHSM_RV_OK) {
        ck("keygen (precondition)", 0, ""); return 2;
    }

    const char *subject = "/C=FR/O=Simorgh Labs/CN=composite.example";
    struct sctx sc = { priv, pl, 0, 0 };
    static uint8_t csr[16384]; size_t cl = sizeof csr;

    printf("[A] build\n");
    fhsm_rv_t rv = fhsm_composite_csr(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                       subject, pub, ql, do_sign, &sc, csr, &cl);
    char d[192];
    snprintf(d, sizeof d, "%zu bytes, sign callback called %d time(s) over %zu TBS bytes",
             cl, sc.calls, sc.tbs_seen);
    ck("fhsm_composite_csr succeeds", rv == FHSM_RV_OK, d);
    ck("the key was signed over exactly once", sc.calls == 1, "");
    if (rv != FHSM_RV_OK) { printf("\nFAIL\n"); return 1; }

    printf("\n[B] a third party parses it\n");
    const uint8_t *p = csr;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)cl);
    ck("OpenSSL's d2i_X509_REQ accepts it", req != NULL, "");
    if (!req) { printf("\nFAIL\n"); return 1; }

    char got[256] = "";
    X509_NAME_oneline(X509_REQ_get_subject_name(req), got, sizeof got);
    ck("the subject survives the round trip", strcmp(got, subject) == 0, got);

    ck("the version is v1 (INTEGER 0)", X509_REQ_get_version(req) == 0, "");

    /* The public key must come back as the composite, with the right OID and
     * absent parameters -- not as something OpenSSL guessed at. */
    X509_PUBKEY *xp = X509_REQ_get_X509_PUBKEY(req);
    const unsigned char *pk = NULL; int pklen = 0;
    X509_ALGOR *alg = NULL;
    ck("the SubjectPublicKeyInfo is present",
       xp && X509_PUBKEY_get0_param(NULL, &pk, &pklen, &alg, xp) == 1, "");
    if (xp && pk) {
        uint8_t raw[FHSM_COMPOSITE_RAW_PUB]; size_t rl = sizeof raw;
        fhsm_composite_raw_pub(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                pub, ql, raw, &rl);
        snprintf(d, sizeof d, "%d bytes", pklen);
        ck("it carries the 1984-byte composite key unchanged",
           pklen == (int)rl && memcmp(pk, raw, rl) == 0, d);
        const ASN1_OBJECT *o = NULL; int ptype = 0; const void *pval = NULL;
        X509_ALGOR_get0(&o, &ptype, &pval, alg);
        char buf[128] = ""; OBJ_obj2txt(buf, sizeof buf, o, 1);
        ck("under OID 1.3.6.1.5.5.7.6.48, parameters absent",
           strcmp(buf, FHSM_COMPOSITE_OID_MLDSA65_ED25519) == 0
           && ptype == V_ASN1_UNDEF, buf);
    }

    printf("\n[C] the signature covers what OpenSSL says it covers\n");
    printf("      verifying our signature over our own idea of the TBS would\n");
    printf("      pass even if we had signed the wrong region.\n");
    {
        const ASN1_BIT_STRING *sig = NULL;
        const X509_ALGOR *sa = NULL;
        X509_REQ_get0_signature(req, &sig, &sa);
        const ASN1_OBJECT *o = NULL; int pt = 0; const void *pv = NULL;
        X509_ALGOR_get0(&o, &pt, &pv, sa);
        char buf[128] = ""; OBJ_obj2txt(buf, sizeof buf, o, 1);
        ck("signatureAlgorithm is the composite OID, parameters absent",
           strcmp(buf, FHSM_COMPOSITE_OID_MLDSA65_ED25519) == 0
           && pt == V_ASN1_UNDEF, buf);

        /* Re-derive the TBS from the PARSED request, not from ours. */
        uint8_t *tbs = NULL;
        int tbs_len = i2d_re_X509_REQ_tbs(req, &tbs);
        snprintf(d, sizeof d, "%d bytes re-derived", tbs_len);
        ck("the to-be-signed part can be re-derived from the parse",
           tbs_len > 0, d);
        if (tbs_len > 0) {
            fhsm_rv_t vr = fhsm_composite_verify(
                               FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                               pub, ql, tbs, (size_t)tbs_len, NULL, 0,
                               ASN1_STRING_get0_data((const ASN1_STRING *)sig),
                               (size_t)ASN1_STRING_length((const ASN1_STRING *)sig));
            ck("the signature verifies over it", vr == FHSM_RV_OK, "");

            /* A negative control: the same signature must NOT verify over the
             * whole request. Without this, a verify that accepted anything
             * would pass the check above. */
            fhsm_rv_t nr = fhsm_composite_verify(
                               FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                               pub, ql, csr, cl, NULL, 0,
                               ASN1_STRING_get0_data((const ASN1_STRING *)sig),
                               (size_t)ASN1_STRING_length((const ASN1_STRING *)sig));
            ck("and does NOT verify over the whole request",
               nr == FHSM_RV_SIGNATURE_INVALID, "");
            OPENSSL_free(tbs);
        }
    }

    printf("\n[D] a malformed subject is refused, not silently truncated\n");
    size_t junk = sizeof csr;
    ck("a subject without a leading slash is rejected",
       fhsm_composite_csr(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                           "C=FR", pub, ql, do_sign, &sc, csr, &junk)
           == FHSM_RV_ARGUMENTS_BAD, "");
    junk = sizeof csr;
    ck("an empty attribute value is rejected",
       fhsm_composite_csr(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                           "/CN=", pub, ql, do_sign, &sc, csr, &junk)
           == FHSM_RV_ARGUMENTS_BAD, "");

    X509_REQ_free(req);

    printf("\n[E] a self-signed composite root\n");
    {
        static uint8_t cert[16384]; size_t xl = sizeof cert;
        struct sctx rc = { priv, pl, 0, 0 };
        fhsm_rv_t crv = fhsm_composite_selfsigned(
                            FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                            "/C=FR/O=Simorgh Labs/CN=Simorgh Composite Root",
                            1, 3650, pub, ql, do_sign, &rc, cert, &xl);
        snprintf(d, sizeof d, "%zu bytes, TBS %zu", xl, rc.tbs_seen);
        ck("fhsm_composite_selfsigned succeeds", crv == FHSM_RV_OK, d);

        if (crv == FHSM_RV_OK) {
            const uint8_t *q = cert;
            X509 *x = d2i_X509(NULL, &q, (long)xl);
            ck("OpenSSL's d2i_X509 accepts it", x != NULL, "");
            if (x) {
                ck("it is a v3 certificate", X509_get_version(x) == 2, "");
                char sub[256] = "", iss[256] = "";
                X509_NAME_oneline(X509_get_subject_name(x), sub, sizeof sub);
                X509_NAME_oneline(X509_get_issuer_name(x), iss, sizeof iss);
                ck("issuer and subject are the same name (self-signed)",
                   strcmp(sub, iss) == 0, sub);
                ck("it is marked as a CA",
                   (X509_get_extension_flags(x) & EXFLAG_CA) != 0, "");
                ck("keyUsage permits keyCertSign and cRLSign",
                   (X509_get_key_usage(x) & (KU_KEY_CERT_SIGN | KU_CRL_SIGN))
                       == (KU_KEY_CERT_SIGN | KU_CRL_SIGN), "");
                ck("a subjectKeyIdentifier is present",
                   X509_get0_subject_key_id(x) != NULL, "");

                /* RFC 5280 §4.1.1.2: the outer signatureAlgorithm MUST equal
                 * the signature field inside the TBS. Two separate fields,
                 * set by two separate calls -- so this is checked, not
                 * assumed. */
                const X509_ALGOR *inner = X509_get0_tbs_sigalg(x);
                const ASN1_BIT_STRING *s2 = NULL; const X509_ALGOR *outer = NULL;
                X509_get0_signature(&s2, &outer, x);
                ck("the two AlgorithmIdentifiers are equal (RFC 5280 4.1.1.2)",
                   inner && outer && X509_ALGOR_cmp(inner, outer) == 0, "");

                /* And the signature covers the TBS re-derived from the parse. */
                uint8_t *tbs2 = NULL;
                int tl2 = i2d_re_X509_tbs(x, &tbs2);
                if (tl2 > 0) {
                    fhsm_rv_t vr = fhsm_composite_verify(
                        FHSM_COMPOSITE_MLDSA65_ED25519_SHA512, pub, ql,
                        tbs2, (size_t)tl2, NULL, 0,
                        ASN1_STRING_get0_data((const ASN1_STRING *)s2),
                        (size_t)ASN1_STRING_length((const ASN1_STRING *)s2));
                    ck("the self-signature verifies over the re-derived TBS",
                       vr == FHSM_RV_OK, "");
                    OPENSSL_free(tbs2);
                }
                X509_free(x);
            }
        }

        size_t j = sizeof cert;
        ck("serial 0 is refused",
           fhsm_composite_selfsigned(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                "/CN=x", 0, 30, pub, ql, do_sign, &rc, cert, &j)
               == FHSM_RV_ARGUMENTS_BAD, "");
        j = sizeof cert;
        ck("a zero validity is refused",
           fhsm_composite_selfsigned(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                "/CN=x", 1, 0, pub, ql, do_sign, &rc, cert, &j)
               == FHSM_RV_ARGUMENTS_BAD, "");
    }

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
