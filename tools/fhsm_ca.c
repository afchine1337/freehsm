/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm-ca --- issue certificates from a certification request, signing with a
 *             composite post-quantum key held in a PKCS#11 module (#112).
 *
 *  Usage :
 *    fhsm-ca issue  --label NAME --ca-cert FILE --csr FILE
 *                   [--subject DN] [--days N] [--out FILE] [--pem]
 *    fhsm-ca revoke --db FILE --serial HEX [--reason NAME]
 *    fhsm-ca crl    --label NAME --ca-cert FILE --db FILE
 *                   [--days N] [--out FILE] [--pem]
 *
 *  Separate from fhsm-csr on purpose. That tool makes requests and its own
 *  root; this one signs for other people, which is a different authority and
 *  in most deployments a different operator. A single binary called fhsm-csr
 *  that also issued certificates would carry a name that lies about what it
 *  does, and this project has spent enough time removing those.
 *
 *  The proof of possession on the incoming request is verified before anything
 *  is signed -- see fhsm_composite_issue. Extensions requested by the
 *  applicant are ignored; the CA sets its own.
 * ========================================================================= */
#include "p11_util.h"
#include "fhsm_revocation.h"

#include <openssl/pem.h>
#include <openssl/ocsp.h>

#include <errno.h>
#include <time.h>
#include <unistd.h>

static uint8_t *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "fhsm-ca: cannot read %s\n", path); exit(2); }
    static uint8_t buf[262144];
    *n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (*n == 0) { fprintf(stderr, "fhsm-ca: %s is empty\n", path); exit(2); }
    /* Accept PEM as well as DER: an operator who received a PEM request should
     * not have to convert it first, and guessing wrong is cheap to detect. */
    if (*n > 11 && memcmp(buf, "-----BEGIN ", 11) == 0) {
        BIO *b = BIO_new_mem_buf(buf, (int)*n);
        char *nm = NULL, *hdr = NULL; unsigned char *data = NULL; long dl = 0;
        if (b && PEM_read_bio(b, &nm, &hdr, &data, &dl) == 1 && dl > 0
            && (size_t)dl <= sizeof buf) {
            memcpy(buf, data, (size_t)dl); *n = (size_t)dl;
        } else {
            fprintf(stderr, "fhsm-ca: %s looks like PEM but did not parse\n", path);
            exit(2);
        }
        OPENSSL_free(nm); OPENSSL_free(hdr); OPENSSL_free(data); BIO_free(b);
    }
    return buf;
}


/* ===========================================================================
 * The revocation database, and the OCSP responder, live in the library now:
 * include/fhsm_revocation.h, src/fhsm_revocation.c. They were here, reached
 * only by this tool, until fhsm-service had to answer the same question on a
 * socket. Two implementations of "is this serial revoked" agree on the day
 * they are written; the one that drifts answers `good` for a certificate the
 * CA revoked, which is the single wrong answer OCSP exists to prevent.
 *
 * What stays here is what belongs to a command-line tool: the messages, the
 * exit codes, and the decision to stop. The library returns a status and a
 * diagnostic; these two wrappers print it and exit, so this tool behaves
 * exactly as before, while the service can refuse one request without ending.
 * ========================================================================= */
static void db_load(const char *path, fhsm_rev_db_t *d) {
    char err[FHSM_REV_ERR_MAX] = "";
    int rc = fhsm_rev_db_load(path, d, err, sizeof err);
    if (rc != FHSM_REV_OK) { fprintf(stderr, "fhsm-ca: %s", err); exit(rc); }
}

static void db_save(const char *path, const fhsm_rev_db_t *d) {
    char err[FHSM_REV_ERR_MAX] = "";
    int rc = fhsm_rev_db_save(path, d, err, sizeof err);
    if (rc != FHSM_REV_OK) { fprintf(stderr, "fhsm-ca: %s", err); exit(rc); }
}


static void usage(void) {
    fprintf(stderr,
      "fhsm-ca --- issue and revoke certificates with a composite PQ key\n\n"
      "  fhsm-ca issue  --label NAME --ca-cert FILE --csr FILE\n"
      "                 [--profile end-entity|ocsp-responder]\n"
      "                 [--subject DN] [--san LIST] [--crl-url URL]...\n"
      "                 [--days N] [--out FILE] [--pem]\n"
      "  fhsm-ca revoke --db FILE --serial HEX [--reason NAME] [--date WHEN]\n"
      "  fhsm-ca crl    --label NAME --ca-cert FILE --db FILE\n"
      "                 [--days N] [--out FILE] [--pem]\n"
      "  fhsm-ca ocsp-respond --label NAME --ca-cert FILE --db FILE --req FILE\n"
      "                 [--responder-cert FILE] [--days N] [--out FILE]\n\n"
      "  --label NAME    label of the CA key inside the module\n"
      "  --ca-cert FILE  the CA's own certificate (DER or PEM)\n"
      "  --csr FILE      the request to sign (DER or PEM)\n"
      "  --db FILE       the revocation database (created on first revoke)\n"
      "  --serial HEX    serial to revoke, as it appears in the certificate\n"
      "  --reason NAME   unspecified, keyCompromise, cACompromise,\n"
      "                  affiliationChanged, superseded, cessationOfOperation,\n"
      "                  certificateHold, privilegeWithdrawn, aACompromise\n"
      "  --date WHEN     revocation date, YYYYMMDDHHMMSSZ (default: now)\n"
      "  --subject DN    replace the requested subject entirely\n"
      "  --san LIST      DNS:/IP:/email:/URI: entries, comma separated\n"
      "  --crl-url URL   where this certificate's revocation list is published.\n"
      "                  Repeat for several; they all describe the same list.\n"
      "                  http://... or ldap://...?attribute . https is refused:\n"
      "                  fetching a CRL over TLS can require a CRL, and the list\n"
      "                  is signed, so the transport protects nothing.\n"
      "  --req FILE      an OCSP request in DER (ocsp-respond)\n"
      "  --responder-cert FILE\n"
      "                  sign the response as a delegated responder rather\n"
      "                  than as the CA (RFC 6960 4.2.2.2). --label then names\n"
      "                  the delegate's key. Refused unless the certificate\n"
      "                  carries extendedKeyUsage OCSPSigning and was issued by\n"
      "                  the CA in --ca-cert.\n"
      "  --days N        validity in days (issue: 365, crl: 30, ocsp: 7)\n"
      "  --profile P     end-entity (default), or ocsp-responder for a\n"
      "                  delegated responder: extendedKeyUsage OCSPSigning\n"
      "                  plus id-pkix-ocsp-nocheck (RFC 6960 4.2.2.2). Such a\n"
      "                  certificate cannot be revoked in any way a verifier\n"
      "                  will notice, so issue it short.\n"
      "  --module PATH   PKCS#11 module (default ./libfreehsm-fips.so)\n"
      "  --slot N        slot to address. Default: the one slot holding a token.\n"
      "  --out FILE      output file (default stdout)\n"
      "  --pem           PEM instead of DER\n\n"
      "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n"
      "  is visible in ps to every user on the machine.\n\n"
      "  `revoke` only records the revocation; it does not need the key and\n"
      "  produces nothing signed. `crl` is what signs, and it advances the\n"
      "  database's crlNumber as it goes -- so a list that has been issued is\n"
      "  never issued again under the same number.\n\n"
      "  `ocsp-respond` answers one request from the same database, as a file.\n"
      "  It echoes the client's nonce when there is one, and answers unknown --\n"
      "  not good -- for any certificate whose issuer is not this CA.\n");
    exit(1);
}

static int cmd_issue(int argc, char **argv) {
    const char *module = "./libfreehsm-fips.so", *label = NULL;
    const char *cacert_p = NULL, *csr_p = NULL, *subject = NULL, *out = NULL;
    const char *san = NULL;
    /* Repeatable rather than comma-separated like --san: an LDAP URI carries
     * commas inside its DN (ldap://h/cn=CRL,ou=CA,o=Example?attr), so a comma
     * cannot separate these without an escaping rule nobody would remember. */
    const char *crl_urls[8];
    size_t      n_crl_urls = 0;
    int pem = 0, days = 365, days_given = 0; long slot = -1;
    fhsm_cert_profile_t profile = FHSM_CERT_END_ENTITY;

    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module")  && i+1<argc) module   = argv[++i];
        else if (!strcmp(argv[i],"--label")   && i+1<argc) label    = argv[++i];
        else if (!strcmp(argv[i],"--ca-cert") && i+1<argc) cacert_p = argv[++i];
        else if (!strcmp(argv[i],"--csr")     && i+1<argc) csr_p    = argv[++i];
        else if (!strcmp(argv[i],"--subject") && i+1<argc) subject  = argv[++i];
        else if (!strcmp(argv[i],"--san")     && i+1<argc) san      = argv[++i];
        else if (!strcmp(argv[i],"--crl-url") && i+1<argc) {
            if (n_crl_urls == sizeof crl_urls / sizeof *crl_urls) {
                fprintf(stderr, "fhsm-ca: at most %zu --crl-url entries\n",
                        sizeof crl_urls / sizeof *crl_urls);
                return 1;
            }
            crl_urls[n_crl_urls++] = argv[++i];
        }
        else if (!strcmp(argv[i],"--out")     && i+1<argc) out      = argv[++i];
        else if (!strcmp(argv[i],"--slot")    && i+1<argc) slot     = p11_slot_arg(argv[++i]);
        else if (!strcmp(argv[i],"--days")    && i+1<argc) days     = atoi(argv[++i]), days_given = 1;
        else if (!strcmp(argv[i],"--profile") && i+1<argc) {
            const char *v = argv[++i];
            if      (!strcmp(v, "end-entity"))     profile = FHSM_CERT_END_ENTITY;
            else if (!strcmp(v, "ocsp-responder")) profile = FHSM_CERT_OCSP_RESPONDER;
            else {
                fprintf(stderr, "fhsm-ca: --profile %s is not a profile.\n"
                                "  end-entity      the default\n"
                                "  ocsp-responder  a delegated OCSP responder\n", v);
                return 1;
            }
        }
        else if (!strcmp(argv[i],"--pem")) pem = 1;
        else if (!strncmp(argv[i],"--pin",5)) {
            fprintf(stderr, "fhsm-ca: --pin is not accepted. Set FHSM_PIN instead:\n"
                            "  an argument is visible in ps to every user on this machine.\n");
            return 1;
        }
        else usage();
    }
    if (!label || !cacert_p || !csr_p) usage();

    /* A delegated responder carries ocsp-nocheck, which tells a verifier not
     * to ask about its revocation status. So it cannot be revoked in any way
     * a verifier will notice, and a short validity is the only control left.
     * The default makes that choice for an operator who did not think about
     * it; an operator who did can say --days and is only warned. */
    if (profile == FHSM_CERT_OCSP_RESPONDER && !days_given) days = 30;
    if (profile == FHSM_CERT_OCSP_RESPONDER && days > 90) {
        fprintf(stderr,
            "fhsm-ca: NOTE -- %d days for a delegated responder.\n"
            "  It carries id-pkix-ocsp-nocheck, so revoking it is not something\n"
            "  a verifier will observe: for the whole of that period, whoever\n"
            "  holds the key can answer for this CA. Short validity is the only\n"
            "  control that remains. Issuing anyway.\n", days);
    }

    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) { fprintf(stderr, "fhsm-ca: FHSM_PIN is not set.\n"); return 1; }

    static uint8_t cabuf[262144]; size_t calen = 0;
    { size_t n = 0; uint8_t *t = slurp(cacert_p, &n);
      memcpy(cabuf, t, n); calen = n; }
    size_t csrlen = 0; uint8_t *csrbuf = slurp(csr_p, &csrlen);

    load_module(module);
    CK_RV rv = p11.Initialize(NULL);
    if (rv != CKR_OK) die("C_Initialize", rv);
    CK_SESSION_HANDLE s = 0;
    rv = p11.OpenSession(p11_resolve_slot(slot, P11_SLOT_WITH_TOKEN),
                          CKF_RW, NULL, NULL, &s);
    if (rv != CKR_OK) die("C_OpenSession", rv);
    rv = p11.Login(s, CKU_USER, (CK_BYTE*)(uintptr_t)pin, (CK_ULONG)strlen(pin));
    if (rv != CKR_OK) die("C_Login", rv);

    CK_OBJECT_HANDLE hpriv = find_one(s, CKO_PRIVATE_KEY, label);
    struct signer sg = { s, hpriv };

    static uint8_t der[32768]; size_t n = sizeof der;
    fhsm_rv_t r = fhsm_composite_issue(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                        cabuf, calen, csrbuf, csrlen,
                                        subject, san, crl_urls, n_crl_urls, profile,
                                        days, p11_sign, &sg, p11_rng, &s,
                                        der, &n);
    if (r == FHSM_RV_SIGNATURE_INVALID) {
        fprintf(stderr,
          "fhsm-ca: the request's signature does not match the key it carries.\n"
          "  Nothing was issued. Either the request was altered after signing,\n"
          "  or whoever produced it does not hold the private key it asks to\n"
          "  have certified.\n");
        return 4;
    }
    if (r != FHSM_RV_OK) die("issuing the certificate", (CK_RV)r);

    FILE *f = out ? fopen(out, "wb") : stdout;
    if (!f) { perror("fhsm-ca: open"); return 2; }
    if (pem) {
        BIO *b = BIO_new_fp(f, BIO_NOCLOSE);
        PEM_write_bio(b, "CERTIFICATE", "", der, (long)n);
        BIO_free(b);
    } else if (fwrite(der, 1, n, f) != n) { perror("fhsm-ca: write"); return 2; }
    if (out) fclose(f);

    p11.CloseSession(s);
    p11.Finalize(NULL);
    return 0;
}

/* ---------------------------------------------------------------------------
 * revoke --- record a revocation. No key, no signature, nothing to unlock.
 *
 * Deliberately separate from `crl`. Revoking is urgent and may happen at three
 * in the morning by whoever noticed; issuing a list is a signing operation
 * that needs the token and its PIN. Tying them together would mean either
 * that a revocation cannot be recorded without the key present, or that the
 * key has to be available to a more casual operation than it should be.
 * ------------------------------------------------------------------------- */
static int cmd_revoke(int argc, char **argv) {
    const char *db_p = NULL, *serial = NULL, *reason = NULL, *when = NULL;
    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--db")     && i+1<argc) db_p   = argv[++i];
        else if (!strcmp(argv[i],"--serial") && i+1<argc) serial = argv[++i];
        else if (!strcmp(argv[i],"--reason") && i+1<argc) reason = argv[++i];
        else if (!strcmp(argv[i],"--date")   && i+1<argc) when   = argv[++i];
        else usage();
    }
    if (!db_p || !serial) usage();

    fhsm_rev_entry_t e; memset(&e, 0, sizeof e);
    if (!fhsm_rev_hex_to_bytes(serial, e.serial, sizeof e.serial, &e.serial_len)) {
        fprintf(stderr, "fhsm-ca: --serial must be an even number of hex digits,\n"
                        "  exactly as the certificate carries it. openssl x509\n"
                        "  -noout -serial prints it in that form.\n");
        return 2;
    }
    e.reason = -1;
    if (reason) {
        e.reason = fhsm_rev_reason_code(reason);
        if (e.reason == -2) {
            fprintf(stderr, "fhsm-ca: unknown reason \"%s\".\n"
                            "  Accepted: ", reason);
            fprintf(stderr, "%s", fhsm_rev_reason_list());
            fprintf(stderr, ".\n  removeFromCRL is not accepted: it belongs to delta CRLs,\n"
                            "  which this tool does not produce.\n");
            return 2;
        }
    }
    if (when) {
        int64_t t = 0;
        if (!fhsm_rev_date_to_time(when, &t)) {
            fprintf(stderr, "fhsm-ca: --date must be YYYYMMDDHHMMSSZ, in UTC.\n");
            return 2;
        }
        memcpy(e.date, when, 15); e.date[15] = '\0';   /* length checked above */
    } else {
        if (!fhsm_rev_time_to_date((int64_t)time(NULL), e.date)) {
            fprintf(stderr, "fhsm-ca: unrepresentable date\n"); return 2;
        }
    }

    fhsm_rev_db_t d;
    db_load(db_p, &d);

    /* Already there? Say so and change nothing. Re-revoking would either
     * duplicate the entry in every future CRL or silently move its date,
     * and the date is what tells a verifier when to stop trusting
     * signatures made with that certificate.
     *
     * This compares the way the responder compares -- ignoring leading zeros
     * on both sides. It used to compare byte for byte, and the difference was
     * invisible while the two comparisons lived in different functions: this
     * one accepted `004A3B2C1D` as new when `4A3B2C1D` was already recorded,
     * put both in the database, and listed the same certificate twice in
     * every CRL after that. Putting the two side by side in one file is what
     * made it visible. */
    {
        const fhsm_rev_entry_t *had = fhsm_rev_db_find(&d, e.serial, e.serial_len);
        if (had) {
            fprintf(stderr, "fhsm-ca: serial %s is already revoked, on %s.\n"
                            "  The database was left unchanged. Remove the line\n"
                            "  by hand if the date or reason must be corrected.\n",
                    serial, had->date);
            fhsm_rev_db_free(&d);
            return 5;
        }
    }

    {
        char err[FHSM_REV_ERR_MAX] = "";
        int rc = fhsm_rev_db_add(&d, &e, err, sizeof err);
        if (rc != FHSM_REV_OK) { fprintf(stderr, "fhsm-ca: %s", err); return rc; }
    }
    db_save(db_p, &d);
    fprintf(stderr, "fhsm-ca: recorded. %zu revoked in total.\n"
                    "  Nothing is signed yet -- run `fhsm-ca crl` to publish a\n"
                    "  list that says so.\n", d.n);
    fhsm_rev_db_free(&d);
    return 0;
}

/* ---------------------------------------------------------------------------
 * crl --- sign and emit the revocation list.
 * ------------------------------------------------------------------------- */
static int cmd_crl(int argc, char **argv) {
    const char *module = "./libfreehsm-fips.so", *label = NULL;
    const char *cacert_p = NULL, *db_p = NULL, *out = NULL;
    int pem = 0, days = 30; long slot = -1;

    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module")  && i+1<argc) module   = argv[++i];
        else if (!strcmp(argv[i],"--label")   && i+1<argc) label    = argv[++i];
        else if (!strcmp(argv[i],"--ca-cert") && i+1<argc) cacert_p = argv[++i];
        else if (!strcmp(argv[i],"--db")      && i+1<argc) db_p     = argv[++i];
        else if (!strcmp(argv[i],"--out")     && i+1<argc) out      = argv[++i];
        else if (!strcmp(argv[i],"--slot")    && i+1<argc) slot     = p11_slot_arg(argv[++i]);
        else if (!strcmp(argv[i],"--days")    && i+1<argc) days     = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--pem")) pem = 1;
        else if (!strncmp(argv[i],"--pin",5)) {
            fprintf(stderr, "fhsm-ca: --pin is not accepted. Set FHSM_PIN instead:\n"
                            "  an argument is visible in ps to every user on this machine.\n");
            return 1;
        }
        else usage();
    }
    if (!label || !cacert_p || !db_p) usage();
    if (days <= 0) { fprintf(stderr, "fhsm-ca: --days must be positive.\n"); return 2; }

    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) { fprintf(stderr, "fhsm-ca: FHSM_PIN is not set.\n"); return 1; }

    static uint8_t cabuf[262144]; size_t calen = 0;
    { size_t n = 0; uint8_t *t = slurp(cacert_p, &n);
      memcpy(cabuf, t, n); calen = n; }

    fhsm_rev_db_t d;
    db_load(db_p, &d);

    fhsm_composite_revoked_t *list = NULL;
    if (d.n) {
        list = calloc(d.n, sizeof *list);
        if (!list) { fprintf(stderr, "fhsm-ca: out of memory\n"); return 2; }
        for (size_t i = 0; i < d.n; i++) {
            int64_t t = 0;
            (void)fhsm_rev_date_to_time(d.e[i].date, &t);  /* validated at load */
            list[i].serial     = d.e[i].serial;
            list[i].serial_len = d.e[i].serial_len;
            list[i].date       = t;
            list[i].reason     = d.e[i].reason;
        }
    }

    /* The number advances before the list is signed, and the database is
     * written before the CRL leaves this process. If signing then fails, a
     * number has been consumed and nothing published -- a gap, which is
     * harmless. The reverse order would publish two different lists under one
     * number, which is not. */
    d.crl_number++;

    load_module(module);
    CK_RV rv = p11.Initialize(NULL);
    if (rv != CKR_OK) die("C_Initialize", rv);
    CK_SESSION_HANDLE s = 0;
    rv = p11.OpenSession(p11_resolve_slot(slot, P11_SLOT_WITH_TOKEN),
                          CKF_RW, NULL, NULL, &s);
    if (rv != CKR_OK) die("C_OpenSession", rv);
    rv = p11.Login(s, CKU_USER, (CK_BYTE*)(uintptr_t)pin, (CK_ULONG)strlen(pin));
    if (rv != CKR_OK) die("C_Login", rv);

    CK_OBJECT_HANDLE hpriv = find_one(s, CKO_PRIVATE_KEY, label);
    struct signer sg = { s, hpriv };

    size_t cap = 8192 + d.n * 80;
    uint8_t *der = malloc(cap);
    if (!der) { fprintf(stderr, "fhsm-ca: out of memory\n"); return 2; }
    size_t n = cap;
    fhsm_rv_t r = fhsm_composite_crl(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                      cabuf, calen, list, d.n,
                                      d.crl_number, days, p11_sign, &sg, der, &n);
    if (r != FHSM_RV_OK) die("building the revocation list", (CK_RV)r);

    db_save(db_p, &d);

    FILE *f = out ? fopen(out, "wb") : stdout;
    if (!f) { perror("fhsm-ca: open"); return 2; }
    if (pem) {
        BIO *b = BIO_new_fp(f, BIO_NOCLOSE);
        PEM_write_bio(b, "X509 CRL", "", der, (long)n);
        BIO_free(b);
    } else if (fwrite(der, 1, n, f) != n) { perror("fhsm-ca: write"); return 2; }
    if (out) fclose(f);

    fprintf(stderr, "fhsm-ca: CRL number %llu, %zu revoked, valid %d days.\n",
            d.crl_number, d.n, days);

    free(der); free(list); fhsm_rev_db_free(&d);
    p11.CloseSession(s);
    p11.Finalize(NULL);
    return 0;
}

/* ===========================================================================
 * ocsp-respond --- answer one OCSP request from the revocation database.
 *
 * File in, file out. No socket, no daemon: a responder that listens is a
 * network service with its own concurrency, its own key lifetime and its own
 * denial-of-service surface, and none of that is cryptography. This produces
 * the signed object; publishing it is the operator's business, and a static
 * file served over HTTP is a legitimate way to do it.
 *
 * The parsing, the lookup and the assembly are in the library -- see
 * fhsm_ocsp_answer(), and the note there on why a responder computes SHA-1.
 * fhsm-service answers on a socket from the same code. What remains here is
 * the command line, the token, and the file.
 * ========================================================================= */
static int cmd_ocsp_respond(int argc, char **argv) {
    const char *module = "./libfreehsm-fips.so", *label = NULL;
    const char *cacert_p = NULL, *db_p = NULL, *req_p = NULL, *out = NULL;
    const char *rcert_p = NULL;
    long slot = -1; int days = 7;

    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module")  && i+1<argc) module   = argv[++i];
        else if (!strcmp(argv[i],"--label")   && i+1<argc) label    = argv[++i];
        else if (!strcmp(argv[i],"--ca-cert") && i+1<argc) cacert_p = argv[++i];
        else if (!strcmp(argv[i],"--db")      && i+1<argc) db_p     = argv[++i];
        else if (!strcmp(argv[i],"--req")     && i+1<argc) req_p    = argv[++i];
        else if (!strcmp(argv[i],"--responder-cert") && i+1<argc) rcert_p = argv[++i];
        else if (!strcmp(argv[i],"--out")     && i+1<argc) out      = argv[++i];
        else if (!strcmp(argv[i],"--slot")    && i+1<argc) slot     = p11_slot_arg(argv[++i]);
        else if (!strcmp(argv[i],"--days")    && i+1<argc) days     = atoi(argv[++i]);
        else if (!strncmp(argv[i],"--pin",5)) {
            fprintf(stderr, "fhsm-ca: --pin is not accepted. Set FHSM_PIN instead:\n"
                            "  an argument is visible in ps to every user on this machine.\n");
            return 1;
        }
        else usage();
    }
    if (!label || !cacert_p || !db_p || !req_p) usage();
    if (days <= 0) { fprintf(stderr, "fhsm-ca: --days must be positive.\n"); return 2; }

    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) { fprintf(stderr, "fhsm-ca: FHSM_PIN is not set.\n"); return 1; }

    static uint8_t cabuf[262144]; size_t calen = 0;
    { size_t n = 0; uint8_t *t = slurp(cacert_p, &n);
      memcpy(cabuf, t, n); calen = n; }

    /* Checked here rather than inside the delegation check below, because that
     * check compares against this certificate's subject name: a --ca-cert that
     * did not parse reached X509_get_subject_name(NULL) before anything tested
     * it. Without --responder-cert the tool printed this line; with it, the
     * same bad file was a segfault. The recurring shape again -- a check wired
     * to some of the paths that reach a state and not the rest. */
    { const uint8_t *p = cabuf; X509 *t = d2i_X509(NULL, &p, (long)calen);
      if (!t) { fprintf(stderr, "fhsm-ca: --ca-cert is not a certificate.\n"); return 2; }
      X509_free(t); }

    /* ---- who signs this answer -------------------------------------------
     * By default the CA answers for itself: one certificate, one identity. A
     * delegated responder (RFC 6960 4.2.2.2) lets the CA key stay offline
     * while something else answers, and a verifier accepts that only because
     * the CA issued the delegate with extendedKeyUsage OCSPSigning. Both
     * checks are about what a verifier will do with the answer; producing
     * responses nobody accepts is a failure an operator otherwise discovers in
     * production. */
    static uint8_t rbuf[262144]; size_t rlen = 0;
    const uint8_t *responder_der = cabuf; size_t responder_len = calen;
    if (rcert_p) {
        size_t n = 0; uint8_t *t = slurp(rcert_p, &n);
        if (n > sizeof rbuf) { fprintf(stderr, "fhsm-ca: responder certificate too large.\n"); return 2; }
        memcpy(rbuf, t, n); rlen = n;

        char err[FHSM_REV_ERR_MAX] = "";
        int rc = fhsm_ocsp_check_responder(rbuf, rlen, cabuf, calen,
                                           rcert_p, cacert_p, err, sizeof err);
        if (rc != FHSM_REV_OK) { fprintf(stderr, "fhsm-ca: %s", err); return rc; }

        responder_der = rbuf; responder_len = rlen;
    }

    size_t reqn = 0; uint8_t *reqbuf = slurp(req_p, &reqn);
    static uint8_t reqcopy[262144];
    memcpy(reqcopy, reqbuf, reqn);      /* slurp's buffer is reused below */

    fhsm_rev_db_t d;
    db_load(db_p, &d);

    load_module(module);
    CK_RV rv = p11.Initialize(NULL);
    if (rv != CKR_OK) die("C_Initialize", rv);
    CK_SESSION_HANDLE s = 0;
    rv = p11.OpenSession(p11_resolve_slot(slot, P11_SLOT_WITH_TOKEN),
                          CKF_RW, NULL, NULL, &s);
    if (rv != CKR_OK) die("C_OpenSession", rv);
    rv = p11.Login(s, CKU_USER, (CK_BYTE*)(uintptr_t)pin, (CK_ULONG)strlen(pin));
    if (rv != CKR_OK) die("C_Login", rv);

    CK_OBJECT_HANDLE hpriv = find_one(s, CKO_PRIVATE_KEY, label);
    struct signer sg = { s, hpriv };

    uint8_t *resp = NULL; size_t rn = 0;
    fhsm_ocsp_stats_t st;
    char err[FHSM_REV_ERR_MAX] = "";
    int rc = fhsm_ocsp_answer(reqcopy, reqn, cabuf, calen,
                              responder_der, responder_len, &d, days, req_p,
                              p11_sign, &sg, &resp, &rn, &st, err, sizeof err);
    if (rc != FHSM_REV_OK) {
        fprintf(stderr, "fhsm-ca: %s", err);
        fhsm_rev_db_free(&d);
        p11.CloseSession(s); p11.Finalize(NULL);
        return rc;
    }

    FILE *f = out ? fopen(out, "wb") : stdout;
    if (!f) { perror("fhsm-ca: open"); return 2; }
    if (fwrite(resp, 1, rn, f) != rn) { perror("fhsm-ca: write"); return 2; }
    if (out) fclose(f);

    fprintf(stderr, "fhsm-ca: %zu asked, %zu ours (%zu revoked), %zu unknown,"
                    " valid %d days%s.\n",
            st.asked, st.ours, st.revoked, st.unknown, days,
            st.nonce_echoed ? ", nonce echoed" : ", no nonce");

    free(resp);
    fhsm_rev_db_free(&d);
    p11.CloseSession(s);
    p11.Finalize(NULL);
    return 0;
}

int main(int argc, char **argv) {
    p11_progname = "fhsm-ca";
    if (argc < 2) usage();
    if (!strcmp(argv[1], "issue"))  return cmd_issue(argc, argv);
    if (!strcmp(argv[1], "revoke")) return cmd_revoke(argc, argv);
    if (!strcmp(argv[1], "crl"))    return cmd_crl(argc, argv);
    if (!strcmp(argv[1], "ocsp-respond")) return cmd_ocsp_respond(argc, argv);
    usage();
    return 1;
}

