/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_composite_issue.c --- issuing from somebody else's request (#112).
 *
 *  The check that matters is [C]: a request whose signature does not match the
 *  key it carries MUST be refused. That is the whole difference between a CA
 *  and a rubber stamp -- without it anyone could lift a public key out of an
 *  existing certificate and be issued a fresh one for a key they do not hold.
 *
 *  The test forges exactly that: a request built with one key and a signature
 *  made by another. It is constructed rather than described, because a
 *  proof-of-possession check nobody has ever seen fail is a check nobody knows
 *  is wired up.
 * ========================================================================= */
#include "fhsm_composite.h"

#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
static void ck(const char *what, int ok, const char *detail) {
    printf("  %-58s %s\n", what, ok ? "OK" : "<<< FAIL");
    if (detail && *detail) printf("      %s\n", detail);
    if (!ok) fails++;
}

struct sctx { const uint8_t *priv; size_t n; };
static fhsm_rv_t sg(void *v, const uint8_t *t, size_t tl, uint8_t *s, size_t *sl) {
    struct sctx *c = v;
    return fhsm_composite_sign(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                c->priv, c->n, t, tl, NULL, 0, s, sl);
}

#define ALG FHSM_COMPOSITE_MLDSA65_ED25519_SHA512

/* The test supplies its own randomness. Passing NULL is refused, which is the
 * point: a caller that forgets where serials come from should not silently get
 * whichever generator happened to be linked. */
static fhsm_rv_t t_rng(void *c, uint8_t *out, size_t n) {
    (void)c;
    return (RAND_bytes(out, (int)n) == 1) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

int main(void) {
    printf("=== test_composite_issue : issuing from a third-party request ===\n\n");

    /* Two independent key pairs: the CA, and an applicant. */
    static uint8_t capriv[FHSM_COMPOSITE_PRIV_MAX], capub[FHSM_COMPOSITE_PUB_MAX];
    static uint8_t eepriv[FHSM_COMPOSITE_PRIV_MAX], eepub[FHSM_COMPOSITE_PUB_MAX];
    size_t a = sizeof capriv, b = sizeof capub, c2 = sizeof eepriv, d2 = sizeof eepub;
    if (fhsm_composite_keygen(ALG, capriv, &a, capub, &b) != FHSM_RV_OK
        || fhsm_composite_keygen(ALG, eepriv, &c2, eepub, &d2) != FHSM_RV_OK) {
        ck("keygen (precondition)", 0, ""); return 2;
    }
    struct sctx ca_s = { capriv, a }, ee_s = { eepriv, c2 };
    char d[192];

    printf("[A] the CA's own root, and an applicant's request\n");
    static uint8_t cacert[16384]; size_t cl = sizeof cacert;
    fhsm_rv_t rv = fhsm_composite_selfsigned(ALG,
                       "/C=FR/O=Universite Exemple/CN=Exemple Root CA",
                       1, 3650, capub, b, sg, &ca_s, cacert, &cl);
    ck("root certificate built", rv == FHSM_RV_OK, "");

    static uint8_t csr[16384]; size_t rl = sizeof csr;
    rv = fhsm_composite_csr(ALG, "/C=FR/O=Universite Exemple/CN=web01.exemple.fr",
                             eepub, d2, sg, &ee_s, csr, &rl);
    ck("applicant's request built and self-signed", rv == FHSM_RV_OK, "");
    if (fails) { printf("\nFAIL\n"); return 1; }

    printf("\n[B] issuance\n");
    static uint8_t leaf[16384]; size_t ll = sizeof leaf;
    rv = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 365,
                               sg, &ca_s, t_rng, NULL, leaf, &ll);
    snprintf(d, sizeof d, "%zu bytes", ll);
    ck("a certificate is issued", rv == FHSM_RV_OK, d);
    if (rv != FHSM_RV_OK) { printf("\nFAIL\n"); return 1; }

    const uint8_t *p = leaf; X509 *x = d2i_X509(NULL, &p, (long)ll);
    ck("OpenSSL parses it", x != NULL, "");
    if (x) {
        char sub[256] = "", iss[256] = "";
        X509_NAME_oneline(X509_get_subject_name(x), sub, sizeof sub);
        X509_NAME_oneline(X509_get_issuer_name(x), iss, sizeof iss);
        ck("the subject comes from the request",
           strcmp(sub, "/C=FR/O=Universite Exemple/CN=web01.exemple.fr") == 0, sub);
        ck("the issuer is the CA", strstr(iss, "Exemple Root CA") != NULL, iss);
        ck("it is NOT a CA certificate",
           (X509_get_extension_flags(x) & EXFLAG_CA) == 0, "");
        ck("an authorityKeyIdentifier links it to the issuer",
           X509_get0_authority_key_id(x) != NULL, "");
        ck("a subjectKeyIdentifier is present",
           X509_get0_subject_key_id(x) != NULL, "");

        /* The serial must be unpredictable, not 1, 2, 3... */
        const ASN1_INTEGER *sn = X509_get0_serialNumber(x);
        snprintf(d, sizeof d, "%d octets", ASN1_STRING_length((const ASN1_STRING*)sn));
        ck("the serial is large and random, not sequential",
           ASN1_STRING_length((const ASN1_STRING*)sn) >= 16, d);

        /* It certifies the APPLICANT's key, not the CA's. */
        const unsigned char *pk = NULL; int pkl = 0;
        X509_PUBKEY_get0_param(NULL, &pk, &pkl, NULL, X509_get_X509_PUBKEY(x));
        uint8_t eeraw[FHSM_COMPOSITE_RAW_PUB]; size_t erl = sizeof eeraw;
        fhsm_composite_raw_pub(ALG, eepub, d2, eeraw, &erl);
        ck("it carries the APPLICANT's key, not the CA's",
           pkl == (int)erl && memcmp(pk, eeraw, erl) == 0, "");

        /* And the CA's signature over it verifies. */
        uint8_t *tbs = NULL; int tl = i2d_re_X509_tbs(x, &tbs);
        const ASN1_BIT_STRING *s2 = NULL; X509_get0_signature(&s2, NULL, x);
        if (tl > 0) {
            fhsm_rv_t vr = fhsm_composite_verify(ALG, capub, b, tbs, (size_t)tl,
                               NULL, 0,
                               ASN1_STRING_get0_data((const ASN1_STRING*)s2),
                               (size_t)ASN1_STRING_length((const ASN1_STRING*)s2));
            ck("the CA's signature verifies against the CA's key", vr == FHSM_RV_OK, "");
            OPENSSL_free(tbs);
        }
        X509_free(x);
    }

    printf("\n[C] proof of possession -- the check that makes this a CA\n");
    printf("      a forged request: one applicant's key, another's signature.\n");
    {
        /* Build a request for the applicant's key but signed by the CA's --
         * i.e. by someone who does not hold the key being certified. */
        static uint8_t forged[16384]; size_t fl = sizeof forged;
        fhsm_rv_t fr = fhsm_composite_csr(ALG, "/CN=impostor",
                                           eepub, d2,       /* applicant's key   */
                                           sg, &ca_s,       /* CA's signature    */
                                           forged, &fl);
        ck("the forged request was built (it is well-formed)", fr == FHSM_RV_OK, "");

        static uint8_t bad[16384]; size_t bl = sizeof bad;
        fhsm_rv_t ir = fhsm_composite_issue(ALG, cacert, cl, forged, fl, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 365,
                                             sg, &ca_s, t_rng, NULL, bad, &bl);
        ck("issuance REFUSES it (CKR_SIGNATURE_INVALID)",
           ir == FHSM_RV_SIGNATURE_INVALID,
           ir == FHSM_RV_OK ? "it was issued -- proof of possession is not enforced"
                            : "");

        /* And a request whose bytes were altered after signing. */
        static uint8_t tampered[16384];
        memcpy(tampered, csr, rl);
        /* flip a byte inside the subject region, well before the signature */
        tampered[40] ^= 0x01;
        bl = sizeof bad;
        fhsm_rv_t tr = fhsm_composite_issue(ALG, cacert, cl, tampered, rl, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 365,
                                             sg, &ca_s, t_rng, NULL, bad, &bl);
        ck("a request altered after signing is refused", tr != FHSM_RV_OK, "");
    }

    printf("\n[D] operator override and argument handling\n");
    {
        static uint8_t o[16384]; size_t ol = sizeof o;
        rv = fhsm_composite_issue(ALG, cacert, cl, csr, rl,
                                   "/C=FR/O=Universite Exemple/CN=imposed.example",
                                   NULL, NULL, 0, FHSM_CERT_END_ENTITY, 365, sg, &ca_s, t_rng, NULL, o, &ol);
        ck("--subject replaces the requested subject", rv == FHSM_RV_OK, "");
        if (rv == FHSM_RV_OK) {
            const uint8_t *q = o; X509 *y = d2i_X509(NULL, &q, (long)ol);
            char s3[256] = ""; if (y) X509_NAME_oneline(X509_get_subject_name(y), s3, sizeof s3);
            ck("and the imposed subject is what appears",
               y && strstr(s3, "imposed.example") != NULL, s3);
            X509_free(y);
        }
        ol = sizeof o;
        ck("a zero validity is refused",
           fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0, sg, &ca_s, t_rng, NULL, o, &ol)
               == FHSM_RV_ARGUMENTS_BAD, "");
        ol = sizeof o;
        ck("garbage in place of a request is refused",
           fhsm_composite_issue(ALG, cacert, cl, (const uint8_t*)"not a csr", 9,
                                 NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 365, sg, &ca_s, t_rng, NULL, o, &ol)
               == FHSM_RV_ARGUMENTS_BAD, "");
    }

    printf("\n[E] subjectAltName, from the operator and not from the request\n");
    {
        static uint8_t o[16384]; size_t ol = sizeof o;
        rv = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL,
                 "DNS:web01.exemple.fr,DNS:www.exemple.fr,IP:10.0.0.7,email:ca@exemple.fr",
                 NULL, 0, FHSM_CERT_END_ENTITY, 365, sg, &ca_s, t_rng, NULL, o, &ol);
        ck("a certificate with four alternative names is issued",
           rv == FHSM_RV_OK, "");
        if (rv == FHSM_RV_OK) {
            const uint8_t *q = o; X509 *y = d2i_X509(NULL, &q, (long)ol);
            GENERAL_NAMES *gs = y ? X509_get_ext_d2i(y, NID_subject_alt_name,
                                                      NULL, NULL) : NULL;
            snprintf(d, sizeof d, "%d names", gs ? sk_GENERAL_NAME_num(gs) : -1);
            ck("OpenSSL reads back all four", gs && sk_GENERAL_NAME_num(gs) == 4, d);
            if (gs) {
                int dns = 0, ip = 0, mail = 0;
                for (int i = 0; i < sk_GENERAL_NAME_num(gs); ++i) {
                    int t = 0; GENERAL_NAME_get0_value(sk_GENERAL_NAME_value(gs,i), &t);
                    if (t == GEN_DNS) dns++;
                    else if (t == GEN_IPADD) ip++;
                    else if (t == GEN_EMAIL) mail++;
                }
                snprintf(d, sizeof d, "DNS=%d IP=%d email=%d", dns, ip, mail);
                ck("the types survive: two DNS, one IP, one email",
                   dns == 2 && ip == 1 && mail == 1, d);
                GENERAL_NAMES_free(gs);
            }
            X509_free(y);
        }

        /* A private address is accepted on purpose: this is not a public CA,
         * and 10.0.0.0/8 is the intended use. Proven above by IP:10.0.0.7
         * being one of the four. */

        /* Anything malformed is REFUSED, not dropped. A name silently missing
         * from a certificate is a name the operator believes is covered. */
        struct { const char *san; const char *why; } bad[] = {
            { "web01.exemple.fr",        "no type prefix" },
            { "DNS:",                    "empty value" },
            { "IP:not.an.address",       "malformed address" },
            { "OTHER:x",                 "unsupported type" },
            { "DNS:a,,DNS:b",            "empty element" },
            { "",                        "empty list" },
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
            ol = sizeof o;
            fhsm_rv_t br = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL,
                                                 bad[i].san, NULL, 0, FHSM_CERT_END_ENTITY, 365, sg, &ca_s, t_rng, NULL, o, &ol);
            snprintf(d, sizeof d, "\"%s\" -- %s", bad[i].san, bad[i].why);
            ck("refused rather than silently dropped", br != FHSM_RV_OK, d);
        }
    }

    printf("\n[F] cRLDistributionPoints -- where the revocation list lives\n");
    {
        static uint8_t o[16384]; size_t ol = sizeof o;
        const char *urls[] = {
            "http://crl.exemple.fr/ca.crl",
            "ldap://ldap.exemple.fr/cn=CRL1,ou=CA,o=Exemple"
                "?certificateRevocationList;binary",
        };

        rv = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL, NULL,
                                   urls, 2, FHSM_CERT_END_ENTITY, 365, sg, &ca_s, t_rng, NULL, o, &ol);
        ck("a certificate carrying two distribution URIs is issued",
           rv == FHSM_RV_OK, "");

        if (rv == FHSM_RV_OK) {
            const uint8_t *q = o; X509 *y = d2i_X509(NULL, &q, (long)ol);
            CRL_DIST_POINTS *cdp = y ? X509_get_ext_d2i(y,
                       NID_crl_distribution_points, NULL, NULL) : NULL;

            /* One DistributionPoint, not two. Several names inside one point
             * are several ways to the same list (RFC 5280 4.2.1.13); two
             * points would assert two different lists. */
            snprintf(d, sizeof d, "%d point(s)", cdp ? sk_DIST_POINT_num(cdp) : -1);
            ck("OpenSSL reads back exactly one DistributionPoint",
               cdp && sk_DIST_POINT_num(cdp) == 1, d);

            if (cdp && sk_DIST_POINT_num(cdp) == 1) {
                DIST_POINT *dp = sk_DIST_POINT_value(cdp, 0);
                ck("it is a fullName", dp->distpoint && dp->distpoint->type == 0, "");

                GENERAL_NAMES *gs = dp->distpoint ? dp->distpoint->name.fullname : NULL;
                snprintf(d, sizeof d, "%d name(s)", gs ? sk_GENERAL_NAME_num(gs) : -1);
                ck("both URIs are inside it", gs && sk_GENERAL_NAME_num(gs) == 2, d);

                if (gs && sk_GENERAL_NAME_num(gs) == 2) {
                    int all_uri = 1, order_kept = 1;
                    for (int i = 0; i < 2; ++i) {
                        int t = 0;
                        ASN1_IA5STRING *s5 =
                            GENERAL_NAME_get0_value(sk_GENERAL_NAME_value(gs,i), &t);
                        if (t != GEN_URI) { all_uri = 0; continue; }
                        if (strcmp((const char *)ASN1_STRING_get0_data(s5), urls[i]))
                            order_kept = 0;
                    }
                    ck("both are uniformResourceIdentifier", all_uri, "");
                    /* Order matters: a client walks the points in the order
                     * they appear, so the operator's order is the fallback
                     * order they intended. */
                    ck("and in the order the operator gave them", order_kept, "");
                }

                /* Non-critical per 4.2.1.13: a client that cannot read the
                 * extension must still be able to use the certificate. */
                int loc = X509_get_ext_by_NID(y, NID_crl_distribution_points, -1);
                ck("the extension is not critical",
                   loc >= 0 && X509_EXTENSION_get_critical(X509_get_ext(y, loc)) == 0, "");
            }
            if (cdp) CRL_DIST_POINTS_free(cdp);
            X509_free(y);
        }

        /* Refusals. Same rule as subjectAltName: a URI that is not understood
         * stops the issuance. A distribution point that silently lost its only
         * reachable URI points at a list nobody can fetch, and nothing about
         * the certificate looks wrong. */
        struct { const char *url; const char *why; } bad[] = {
            { "https://crl.exemple.fr/ca.crl",
              "https -- fetching a CRL over TLS can require a CRL" },
            { "ldap://ldap.exemple.fr/cn=CRL1,ou=CA,o=Exemple",
              "ldap without ?attribute -- names an entry, not a list" },
            { "ftp://crl.exemple.fr/ca.crl",     "unsupported scheme" },
            { "http://",                          "scheme only" },
            { "crl.exemple.fr/ca.crl",            "no scheme" },
            { "http://crl.exemple.fr/\xc3\xa9.crl",
              "non-ASCII -- IA5String cannot hold it" },
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
            const char *one[] = { bad[i].url };
            ol = sizeof o;
            fhsm_rv_t br = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL, NULL,
                                                 one, 1, FHSM_CERT_END_ENTITY, 365, sg, &ca_s, t_rng, NULL, o, &ol);
            snprintf(d, sizeof d, "%s", bad[i].why);
            ck("refused", br == FHSM_RV_ARGUMENTS_BAD, d);
        }

        /* A NULL in the middle must not be walked past: the count is what the
         * caller promised, and a hole in the array is a caller bug, not a
         * reason to issue a shorter list than asked for. */
        {
            const char *holed[] = { "http://crl.exemple.fr/ca.crl", NULL };
            ol = sizeof o;
            fhsm_rv_t br = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL, NULL,
                                                 holed, 2, FHSM_CERT_END_ENTITY, 365, sg, &ca_s, t_rng, NULL, o, &ol);
            ck("refused", br == FHSM_RV_ARGUMENTS_BAD, "a NULL entry inside the array");
        }

        /* No URLs at all is not an error -- the extension is optional, and
         * every certificate issued before this feature existed has none. */
        {
            ol = sizeof o;
            fhsm_rv_t br = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL, NULL,
                                                 NULL, 0, FHSM_CERT_END_ENTITY, 365, sg, &ca_s, t_rng, NULL, o, &ol);
            ck("omitting the extension entirely is still valid",
               br == FHSM_RV_OK, "no --crl-url given");
            if (br == FHSM_RV_OK) {
                const uint8_t *q = o; X509 *y = d2i_X509(NULL, &q, (long)ol);
                ck("and then the certificate carries no distribution point",
                   y && X509_get_ext_by_NID(y, NID_crl_distribution_points, -1) < 0, "");
                X509_free(y);
            }
        }
    }

    /* ---- the delegated OCSP responder profile (RFC 6960 4.2.2.2) --------
     *
     * A delegated responder signs OCSP answers on the CA's behalf so the CA
     * key can stay offline. A verifier accepts that only because the CA said
     * so, and it said so with extendedKeyUsage OCSPSigning. Without the EKU
     * the certificate is an ordinary end entity and every answer it signs is
     * refused -- which is why this is checked rather than assumed.
     */
    {
        printf("\n  the delegated OCSP responder profile\n");

        uint8_t r[8192]; size_t rl2 = sizeof r;
        fhsm_rv_t rr = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL, NULL,
                                             NULL, 0, FHSM_CERT_OCSP_RESPONDER,
                                             30, sg, &ca_s, t_rng, NULL, r, &rl2);
        ck("a responder certificate is issued", rr == FHSM_RV_OK, "");

        if (rr == FHSM_RV_OK) {
            const uint8_t *q = r; X509 *y = d2i_X509(NULL, &q, (long)rl2);
            ck("and parses", y != NULL, "");

            /* The EKU, and only OCSPSigning in it. A responder certificate
             * that also claimed serverAuth would be a web certificate that
             * can vouch for revocation, which is not a thing to hand out. */
            EXTENDED_KEY_USAGE *eku = y ? X509_get_ext_d2i(y, NID_ext_key_usage,
                                                            NULL, NULL) : NULL;
            int n_eku = eku ? sk_ASN1_OBJECT_num(eku) : -1;
            int only_ocsp = (n_eku == 1) &&
                OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, 0)) == NID_OCSP_sign;
            ck("carries extendedKeyUsage OCSPSigning", only_ocsp,
               n_eku == 1 ? "" : "and nothing else");
            if (eku) EXTENDED_KEY_USAGE_free(eku);

            /* ocsp-nocheck, whose value is DER NULL. It is what stops a
             * verifier asking the responder about the responder. */
            int idx = y ? X509_get_ext_by_NID(y, NID_id_pkix_OCSP_noCheck, -1) : -1;
            ck("carries id-pkix-ocsp-nocheck", idx >= 0, "");
            if (idx >= 0) {
                X509_EXTENSION *e = X509_get_ext(y, idx);
                ASN1_OCTET_STRING *v = X509_EXTENSION_get_data(e);
                ck("  whose value is DER NULL",
                   v && ASN1_STRING_length(v) == 2
                     && ASN1_STRING_get0_data(v)[0] == 0x05
                     && ASN1_STRING_get0_data(v)[1] == 0x00, "05 00");
                ck("  and which is not critical",
                   X509_EXTENSION_get_critical(e) == 0,
                   "RFC 6960 4.2.2.2.1 leaves it non-critical");
            }
            X509_free(y);
        }

        /* The mutation. Without this the two assertions above would pass
         * against a build that set the extensions on every certificate, and
         * the profile would be doing nothing. */
        {
            uint8_t e2[8192]; size_t el2 = sizeof e2;
            fhsm_rv_t er = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL, NULL,
                                                 NULL, 0, FHSM_CERT_END_ENTITY,
                                                 30, sg, &ca_s, t_rng, NULL, e2, &el2);
            const uint8_t *q = e2; X509 *y = er == FHSM_RV_OK
                                    ? d2i_X509(NULL, &q, (long)el2) : NULL;
            ck("an end entity carries neither",
               y && X509_get_ext_by_NID(y, NID_ext_key_usage, -1) < 0
                 && X509_get_ext_by_NID(y, NID_id_pkix_OCSP_noCheck, -1) < 0,
               "so the profile is what puts them there");
            X509_free(y);
        }
    }

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
