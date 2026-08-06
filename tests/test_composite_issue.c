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
    rv = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL, NULL, 365,
                               sg, &ca_s, leaf, &ll);
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
        fhsm_rv_t ir = fhsm_composite_issue(ALG, cacert, cl, forged, fl, NULL, NULL, 365,
                                             sg, &ca_s, bad, &bl);
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
        fhsm_rv_t tr = fhsm_composite_issue(ALG, cacert, cl, tampered, rl, NULL, NULL, 365,
                                             sg, &ca_s, bad, &bl);
        ck("a request altered after signing is refused", tr != FHSM_RV_OK, "");
    }

    printf("\n[D] operator override and argument handling\n");
    {
        static uint8_t o[16384]; size_t ol = sizeof o;
        rv = fhsm_composite_issue(ALG, cacert, cl, csr, rl,
                                   "/C=FR/O=Universite Exemple/CN=imposed.example",
                                   NULL, 365, sg, &ca_s, o, &ol);
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
           fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL, NULL, 0, sg, &ca_s, o, &ol)
               == FHSM_RV_ARGUMENTS_BAD, "");
        ol = sizeof o;
        ck("garbage in place of a request is refused",
           fhsm_composite_issue(ALG, cacert, cl, (const uint8_t*)"not a csr", 9,
                                 NULL, NULL, 365, sg, &ca_s, o, &ol)
               == FHSM_RV_ARGUMENTS_BAD, "");
    }

    printf("\n[E] subjectAltName, from the operator and not from the request\n");
    {
        static uint8_t o[16384]; size_t ol = sizeof o;
        rv = fhsm_composite_issue(ALG, cacert, cl, csr, rl, NULL,
                 "DNS:web01.exemple.fr,DNS:www.exemple.fr,IP:10.0.0.7,email:ca@exemple.fr",
                 365, sg, &ca_s, o, &ol);
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
                                                 bad[i].san, 365, sg, &ca_s, o, &ol);
            snprintf(d, sizeof d, "\"%s\" -- %s", bad[i].san, bad[i].why);
            ck("refused rather than silently dropped", br != FHSM_RV_OK, d);
        }
    }

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
