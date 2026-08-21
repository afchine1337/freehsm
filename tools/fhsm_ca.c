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
 * The revocation database.
 *
 * Serials here are random, so the CA is otherwise stateless: nothing needs to
 * be remembered between issuances. A CRL breaks that. It needs the list of
 * serials that have been revoked, and it needs a number that only ever goes
 * up, because a verifier holding a newer list must be able to tell that an
 * older one is older. Without that number, replaying last month's list hides
 * every revocation since.
 *
 * The format is one line per entry, in a file the operator can read, diff,
 * grep and put under version control:
 *
 *     # fhsm-ca revocation database v1
 *     crlNumber 7
 *     4A3B2C1D 20260714033320Z keyCompromise
 *     F00D     20260719222640Z -
 *
 * The number lives in the same file as the entries on purpose. Two files can
 * be backed up, copied or restored separately, and a number that goes
 * backwards relative to its list is exactly the failure it exists to prevent.
 *
 * Anything malformed makes the whole file a refusal, never a partial read.
 * A database half-parsed produces a CRL that is missing revocations, and a
 * CRL that is missing revocations is worse than no CRL at all: it is a signed
 * assurance that a compromised certificate is still good. Skipping a line we
 * do not understand would be the quiet version of that.
 *
 * There is no locking. This is a single-operator tool for small authorities;
 * two people running `revoke` at the same moment is a situation it does not
 * handle, and saying so is more useful than a lock that would only narrow the
 * window. Writes go to a temporary file and are renamed into place, so an
 * interrupted run leaves the previous database intact rather than a truncated
 * one.
 * ========================================================================= */

#define DB_MAX_ENTRIES 100000

/* RFC 5280 5.3.1. Code 7 is not assigned; 8 (removeFromCRL) belongs to delta
 * CRLs, which this tool does not produce, so neither is accepted. */
static const struct { const char *name; int code; } REASONS[] = {
    { "unspecified",          0 }, { "keyCompromise",        1 },
    { "cACompromise",         2 }, { "affiliationChanged",   3 },
    { "superseded",           4 }, { "cessationOfOperation", 5 },
    { "certificateHold",      6 }, { "privilegeWithdrawn",   9 },
    { "aACompromise",        10 },
};

static int reason_code(const char *name) {
    for (size_t i = 0; i < sizeof REASONS / sizeof REASONS[0]; i++)
        if (!strcmp(REASONS[i].name, name)) return REASONS[i].code;
    return -2;                                    /* -1 means "no reason"   */
}
static const char *reason_name(int code) {
    for (size_t i = 0; i < sizeof REASONS / sizeof REASONS[0]; i++)
        if (REASONS[i].code == code) return REASONS[i].name;
    return NULL;
}

struct db_entry {
    uint8_t serial[64];
    size_t  serial_len;
    char    date[16];      /* YYYYMMDDHHMMSSZ */
    int     reason;        /* -1 for none */
};

struct db {
    unsigned long long crl_number;
    struct db_entry   *e;
    size_t             n;
};

/* Hex to bytes. An odd number of digits is refused rather than padded: it is
 * ambiguous which end the missing nibble belongs to, and guessing produces a
 * serial that does not match any certificate. */
static int hex_to_bytes(const char *h, uint8_t *out, size_t cap, size_t *n) {
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

/* "YYYYMMDDHHMMSSZ" to seconds since the epoch, UTC. */
static int date_to_time(const char *s, int64_t *out) {
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

static void time_to_date(int64_t when, char out[16]) {
    time_t t = (time_t)when;
    struct tm g;
    char tmp[64];
    gmtime_r(&t, &g);
    int k = snprintf(tmp, sizeof tmp, "%04d%02d%02d%02d%02d%02dZ",
                     g.tm_year + 1900, g.tm_mon + 1, g.tm_mday,
                     g.tm_hour, g.tm_min, g.tm_sec);
    /* A year past 9999 would not fit the fifteen-character form. It cannot
     * happen from time(NULL), but the buffer must not be the thing that
     * decides that. */
    if (k != 15) { fprintf(stderr, "fhsm-ca: unrepresentable date\n"); exit(2); }
    memcpy(out, tmp, 16);
}

static void db_bad(const char *path, size_t line, const char *why) {
    fprintf(stderr,
      "fhsm-ca: %s line %zu: %s\n"
      "  Nothing was read. A revocation database that is only partly\n"
      "  understood would produce a list missing revocations, which is a\n"
      "  signed statement that a revoked certificate is still valid.\n"
      "  Fix the line, or remove it deliberately.\n", path, line, why);
    exit(3);
}

/* Load, or start empty if the file does not exist yet. A file that exists but
 * cannot be read is an error: it is more likely a permissions or path mistake
 * than a first run, and treating it as a first run loses every revocation. */
static void db_load(const char *path, struct db *d) {
    d->crl_number = 0; d->n = 0;
    d->e = calloc(DB_MAX_ENTRIES, sizeof *d->e);
    if (!d->e) { fprintf(stderr, "fhsm-ca: out of memory\n"); exit(2); }

    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return;
        fprintf(stderr, "fhsm-ca: cannot read %s: %s\n", path, strerror(errno));
        exit(2);
    }
    char line[512]; size_t ln = 0; int seen_number = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *nl = strpbrk(p, "\r\n"); if (nl) *nl = '\0';
        if (!*p || *p == '#') continue;

        if (!strncmp(p, "crlNumber", 9) && (p[9] == ' ' || p[9] == '\t')) {
            if (seen_number) db_bad(path, ln, "crlNumber appears twice");
            char *end = NULL;
            unsigned long long v = strtoull(p + 10, &end, 10);
            if (!end || *end) db_bad(path, ln, "crlNumber is not a number");
            d->crl_number = v; seen_number = 1;
            continue;
        }

        if (d->n >= DB_MAX_ENTRIES) db_bad(path, ln, "too many entries");
        char sr[160], dt[64], rs[64];
        int got = sscanf(p, "%159s %63s %63s", sr, dt, rs);
        if (got < 2) db_bad(path, ln, "expected: SERIAL DATE [REASON]");

        struct db_entry *e = &d->e[d->n];
        if (!hex_to_bytes(sr, e->serial, sizeof e->serial, &e->serial_len))
            db_bad(path, ln, "serial is not an even number of hex digits");
        int64_t unused_t = 0;
        if (!date_to_time(dt, &unused_t))
            db_bad(path, ln, "date is not YYYYMMDDHHMMSSZ");
        memcpy(e->date, dt, 15); e->date[15] = '\0';   /* length checked above */
        if (got < 3 || !strcmp(rs, "-")) e->reason = -1;
        else {
            e->reason = reason_code(rs);
            if (e->reason == -2) db_bad(path, ln, "unknown revocation reason");
        }
        d->n++;
    }
    fclose(f);
}

/* Temporary file then rename: an interrupted write leaves the old database
 * whole rather than a truncated one. */
static void db_save(const char *path, const struct db *d) {
    char tmp[1024];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        fprintf(stderr, "fhsm-ca: path too long\n"); exit(2);
    }
    FILE *f = fopen(tmp, "w");
    if (!f) { fprintf(stderr, "fhsm-ca: cannot write %s: %s\n", tmp, strerror(errno)); exit(2); }
    fprintf(f, "# fhsm-ca revocation database v1\n"
               "# SERIAL(hex)  DATE(YYYYMMDDHHMMSSZ)  REASON  ('-' for none)\n");
    fprintf(f, "crlNumber %llu\n", d->crl_number);
    for (size_t i = 0; i < d->n; i++) {
        for (size_t k = 0; k < d->e[i].serial_len; k++)
            fprintf(f, "%02X", d->e[i].serial[k]);
        const char *rn = d->e[i].reason < 0 ? "-" : reason_name(d->e[i].reason);
        fprintf(f, " %s %s\n", d->e[i].date, rn ? rn : "-");
    }
    /* Reach the disk before the rename, so a crash cannot leave the new name
     * pointing at an empty file. */
    if (fflush(f) != 0 || fsync(fileno(f)) != 0 || fclose(f) != 0) {
        fprintf(stderr, "fhsm-ca: writing %s failed: %s\n", tmp, strerror(errno));
        exit(2);
    }
    if (rename(tmp, path) != 0) {
        fprintf(stderr, "fhsm-ca: cannot replace %s: %s\n", path, strerror(errno));
        exit(2);
    }
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

    struct db_entry e; memset(&e, 0, sizeof e);
    if (!hex_to_bytes(serial, e.serial, sizeof e.serial, &e.serial_len)) {
        fprintf(stderr, "fhsm-ca: --serial must be an even number of hex digits,\n"
                        "  exactly as the certificate carries it. openssl x509\n"
                        "  -noout -serial prints it in that form.\n");
        return 2;
    }
    e.reason = -1;
    if (reason) {
        e.reason = reason_code(reason);
        if (e.reason == -2) {
            fprintf(stderr, "fhsm-ca: unknown reason \"%s\".\n"
                            "  Accepted: ", reason);
            for (size_t k = 0; k < sizeof REASONS / sizeof REASONS[0]; k++)
                fprintf(stderr, "%s%s", k ? ", " : "", REASONS[k].name);
            fprintf(stderr, ".\n  removeFromCRL is not accepted: it belongs to delta CRLs,\n"
                            "  which this tool does not produce.\n");
            return 2;
        }
    }
    if (when) {
        int64_t t = 0;
        if (!date_to_time(when, &t)) {
            fprintf(stderr, "fhsm-ca: --date must be YYYYMMDDHHMMSSZ, in UTC.\n");
            return 2;
        }
        memcpy(e.date, when, 15); e.date[15] = '\0';   /* length checked above */
    } else {
        time_to_date((int64_t)time(NULL), e.date);
    }

    struct db d;
    db_load(db_p, &d);

    /* Already there? Say so and change nothing. Re-revoking would either
     * duplicate the entry in every future CRL or silently move its date,
     * and the date is what tells a verifier when to stop trusting
     * signatures made with that certificate. */
    for (size_t k = 0; k < d.n; k++)
        if (d.e[k].serial_len == e.serial_len
            && memcmp(d.e[k].serial, e.serial, e.serial_len) == 0) {
            fprintf(stderr, "fhsm-ca: serial %s is already revoked, on %s.\n"
                            "  The database was left unchanged. Remove the line\n"
                            "  by hand if the date or reason must be corrected.\n",
                    serial, d.e[k].date);
            free(d.e);
            return 5;
        }

    d.e[d.n++] = e;
    db_save(db_p, &d);
    fprintf(stderr, "fhsm-ca: recorded. %zu revoked in total.\n"
                    "  Nothing is signed yet -- run `fhsm-ca crl` to publish a\n"
                    "  list that says so.\n", d.n);
    free(d.e);
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

    struct db d;
    db_load(db_p, &d);

    fhsm_composite_revoked_t *list = NULL;
    if (d.n) {
        list = calloc(d.n, sizeof *list);
        if (!list) { fprintf(stderr, "fhsm-ca: out of memory\n"); return 2; }
        for (size_t i = 0; i < d.n; i++) {
            int64_t t = 0;
            (void)date_to_time(d.e[i].date, &t);   /* validated at load */
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

    free(der); free(list); free(d.e);
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
 * --- On computing SHA-1 here ------------------------------------------------
 *
 * The CertID in the request carries hashes of the issuer name and issuer
 * public key under an algorithm the *client* chose, and OpenSSL's own client
 * still chooses SHA-1. To know which certificate is being asked about, the
 * responder has to recompute those hashes with that same algorithm.
 *
 * So this tool computes SHA-1 when a client asks in SHA-1. That is not a
 * signature: SP 800-131A withdraws SHA-1 for signature generation, not for
 * identification, and a CertID identifies. It proves nothing about the
 * certificate and is not relied on for anything -- the answer's integrity
 * comes from the composite signature over the whole response.
 *
 * It also stays out of the module: this is OpenSSL's SHA-1, in the tool. The
 * fips-strict profile is not asked to provide it, and does not.
 * ========================================================================= */

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

/* Compare a request serial against a database entry, ignoring leading zeros
 * on both sides: DER adds one to keep a top-bit-set magnitude positive, and
 * the operator typing the serial in hex will not have. */
static int serial_eq(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
    while (na > 1 && a[0] == 0) { a++; na--; }
    while (nb > 1 && b[0] == 0) { b++; nb--; }
    return na == nb && memcmp(a, b, na) == 0;
}

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

    X509 *ca = NULL;
    { const uint8_t *p = cabuf; ca = d2i_X509(NULL, &p, (long)calen); }
    /* Checked here rather than after the block below, because that block
     * compares against this certificate's subject name: a --ca-cert that did
     * not parse reached X509_get_subject_name(NULL) before anything tested it.
     * Without --responder-cert the tool printed this line; with it, the same
     * bad file was a segfault. The recurring shape again -- a check wired to
     * some of the paths that reach a state and not the rest. */
    if (!ca) { fprintf(stderr, "fhsm-ca: --ca-cert is not a certificate.\n"); return 2; }

    /* ---- who signs this answer -------------------------------------------
     *
     * By default the CA answers for itself: one certificate, one identity.
     * A delegated responder (RFC 6960 4.2.2.2) lets the CA key stay offline
     * while something else answers, and a verifier accepts that only because
     * the CA issued the delegate with extendedKeyUsage OCSPSigning.
     *
     * So both checks below are about what a verifier will do with the answer.
     * Producing responses nobody accepts is a failure an operator discovers in
     * production, and this is the desk where it can be caught instead.
     */
    static uint8_t rbuf[262144]; size_t rlen = 0;
    const uint8_t *responder_der = cabuf; size_t responder_len = calen;
    X509 *rc = NULL;
    if (rcert_p) {
        size_t n = 0; uint8_t *t = slurp(rcert_p, &n);
        if (n > sizeof rbuf) { fprintf(stderr, "fhsm-ca: responder certificate too large.\n"); return 2; }
        memcpy(rbuf, t, n); rlen = n;
        const uint8_t *p = rbuf; rc = d2i_X509(NULL, &p, (long)rlen);
        if (!rc) { fprintf(stderr, "fhsm-ca: --responder-cert does not parse as DER.\n"); return 2; }

        /* 1. The EKU. Without it a verifier treats the answer as signed by
         *    something with no authority to answer, and refuses it. */
        EXTENDED_KEY_USAGE *eku = X509_get_ext_d2i(rc, NID_ext_key_usage, NULL, NULL);
        int has_ocsp = 0;
        for (int k = 0; eku && k < sk_ASN1_OBJECT_num(eku); k++)
            if (OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, k)) == NID_OCSP_sign) has_ocsp = 1;
        if (eku) EXTENDED_KEY_USAGE_free(eku);
        if (!has_ocsp) {
            fprintf(stderr,
                "fhsm-ca: %s does not carry extendedKeyUsage OCSPSigning.\n"
                "  A verifier will refuse every response it signs, so signing them\n"
                "  would only produce answers nobody accepts. Issue the responder\n"
                "  with `fhsm-ca issue --profile ocsp-responder`.\n", rcert_p);
            return 2;
        }

        /* 2. The same issuer. A delegate issued by some other CA has no
         *    authority over these certificates whatever its EKU says.
         *
         *    This compares names, and a name is not a signature. Verifying
         *    that this CA really issued the delegate would mean checking a
         *    composite signature, which nothing off the shelf can do -- the
         *    same limit recorded for CSRs and CRLs. So this catches the
         *    ordinary mistake (the wrong file) and not a forgery, and says so
         *    rather than implying more. */
        if (X509_NAME_cmp(X509_get_issuer_name(rc), X509_get_subject_name(ca)) != 0) {
            fprintf(stderr,
                "fhsm-ca: %s was not issued by the CA in %s.\n"
                "  Its issuer name does not match that CA's subject, so a verifier\n"
                "  has no reason to accept it as speaking for this authority.\n",
                rcert_p, cacert_p);
            return 2;
        }

        responder_der = rbuf; responder_len = rlen;
    }

    OCSP_REQUEST *req = NULL;
    { size_t n = 0; uint8_t *t = slurp(req_p, &n);
      const uint8_t *p = t; req = d2i_OCSP_REQUEST(NULL, &p, (long)n); }
    if (!req) { fprintf(stderr, "fhsm-ca: --req is not an OCSP request.\n"); return 2; }

    int nreq = OCSP_request_onereq_count(req);
    if (nreq <= 0) { fprintf(stderr, "fhsm-ca: the request asks about nothing.\n"); return 2; }

    struct db d;
    db_load(db_p, &d);

    /* Times. OCSP uses GeneralizedTime throughout -- ASN1_TIME_set would give
     * a UTCTime for any date before 2050, which is a different tag and a
     * response no client will parse. */
    time_t now = time(NULL);
    ASN1_GENERALIZEDTIME *g_now = ASN1_GENERALIZEDTIME_set(NULL, now);
    ASN1_GENERALIZEDTIME *g_nxt = ASN1_GENERALIZEDTIME_set(NULL, now + (time_t)days * 86400);
    uint8_t *d_now = NULL, *d_nxt = NULL;
    int n_now = i2d_ASN1_GENERALIZEDTIME(g_now, &d_now);
    int n_nxt = i2d_ASN1_GENERALIZEDTIME(g_nxt, &d_nxt);
    if (n_now <= 0 || n_nxt <= 0) { fprintf(stderr, "fhsm-ca: cannot encode the time.\n"); return 2; }

    fhsm_composite_ocsp_single_t *singles = calloc((size_t)nreq, sizeof *singles);
    uint8_t **cid_der = calloc((size_t)nreq, sizeof *cid_der);
    uint8_t **rev_der = calloc((size_t)nreq, sizeof *rev_der);
    if (!singles || !cid_der || !rev_der) { fprintf(stderr, "fhsm-ca: out of memory\n"); return 2; }

    size_t n_ours = 0, n_revoked = 0, n_unknown = 0;
    for (int i = 0; i < nreq; i++) {
        OCSP_ONEREQ  *one = OCSP_request_onereq_get0(req, i);
        OCSP_CERTID  *cid = OCSP_onereq_get0_id(one);
        ASN1_OCTET_STRING *nh = NULL, *kh = NULL;
        ASN1_INTEGER      *sn = NULL;
        ASN1_OBJECT       *md_oid = NULL;

        if (!OCSP_id_get0_info(&nh, &md_oid, &kh, &sn, cid)) {
            fprintf(stderr, "fhsm-ca: malformed CertID in the request.\n"); return 2;
        }
        int len = i2d_OCSP_CERTID(cid, &cid_der[i]);
        if (len <= 0) { fprintf(stderr, "fhsm-ca: cannot re-encode a CertID.\n"); return 2; }

        singles[i].cert_id     = cid_der[i];
        singles[i].cert_id_len = (size_t)len;
        singles[i].this_upd    = d_now; singles[i].this_upd_len = (size_t)n_now;
        singles[i].next_upd    = d_nxt; singles[i].next_upd_len = (size_t)n_nxt;
        singles[i].reason      = -1;
        singles[i].status      = FHSM_OCSP_UNKNOWN;

        /* Is this question even about our CA? Rebuild the CertID we would
         * have produced and compare. A responder that answered "good" for an
         * issuer it knows nothing about would be asserting something it
         * cannot know -- unknown is the honest answer and the RFC's. */
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
        for (size_t k = 0; k < d.n; k++) {
            if (!serial_eq(sb, sl, d.e[k].serial, d.e[k].serial_len)) continue;
            int64_t t = 0;
            (void)date_to_time(d.e[k].date, &t);          /* validated at load */
            ASN1_GENERALIZEDTIME *gr = ASN1_GENERALIZEDTIME_set(NULL, (time_t)t);
            int nr = gr ? i2d_ASN1_GENERALIZEDTIME(gr, &rev_der[i]) : 0;
            ASN1_GENERALIZEDTIME_free(gr);
            if (nr <= 0) { fprintf(stderr, "fhsm-ca: cannot encode a revocation date.\n"); return 2; }
            singles[i].status         = FHSM_OCSP_REVOKED;
            singles[i].revoked_at     = rev_der[i];
            singles[i].revoked_at_len = (size_t)nr;
            singles[i].reason         = d.e[k].reason;
            n_revoked++;
            break;
        }
        if (singles[i].status == FHSM_OCSP_UNKNOWN) singles[i].status = FHSM_OCSP_GOOD;
    }

    /* The nonce, echoed. RFC 8954: without it a recorded response can be
     * replayed until its nextUpdate, which is precisely how a revoked
     * certificate keeps being accepted after revocation. It is copied, never
     * generated -- a nonce the responder chose proves nothing to the client
     * that did not choose it. */
    uint8_t *exts = NULL; size_t exts_len = 0;
    {
        int idx = OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1);
        if (idx >= 0) {
            X509_EXTENSION *e = OCSP_REQUEST_get_ext(req, idx);
            uint8_t *one = NULL;
            int n = e ? i2d_X509_EXTENSION(e, &one) : 0;
            if (n > 0) {
                exts = malloc((size_t)n + 8);
                if (!exts) { fprintf(stderr, "fhsm-ca: out of memory\n"); return 2; }
                uint8_t hdr[4]; size_t hn;
                if ((size_t)n < 0x80)      { hdr[0] = (uint8_t)n; hn = 1; }
                else if (n <= 0xFF)        { hdr[0] = 0x81; hdr[1] = (uint8_t)n; hn = 2; }
                else                       { hdr[0] = 0x82; hdr[1] = (uint8_t)(n >> 8);
                                             hdr[2] = (uint8_t)n; hn = 3; }
                exts[0] = 0x30; memcpy(exts + 1, hdr, hn);
                memcpy(exts + 1 + hn, one, (size_t)n);
                exts_len = 1 + hn + (size_t)n;
            }
            OPENSSL_free(one);
        }
    }

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

    size_t cap = 16384 + calen + rlen + (size_t)nreq * 512 + exts_len;
    uint8_t *basic = malloc(cap);
    if (!basic) { fprintf(stderr, "fhsm-ca: out of memory\n"); return 2; }
    size_t bn = cap;
    fhsm_rv_t r = fhsm_composite_ocsp(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                       responder_der, responder_len, d_now, (size_t)n_now,
                                       singles, (size_t)nreq, exts, exts_len,
                                       p11_sign, &sg, basic, &bn);
    if (r != FHSM_RV_OK) die("building the OCSP response", (CK_RV)r);

    uint8_t *resp = malloc(bn + 64);
    if (!resp) { fprintf(stderr, "fhsm-ca: out of memory\n"); return 2; }
    size_t rn = wrap_response(basic, bn, resp, bn + 64);
    if (!rn) { fprintf(stderr, "fhsm-ca: cannot wrap the response.\n"); return 2; }

    FILE *f = out ? fopen(out, "wb") : stdout;
    if (!f) { perror("fhsm-ca: open"); return 2; }
    if (fwrite(resp, 1, rn, f) != rn) { perror("fhsm-ca: write"); return 2; }
    if (out) fclose(f);

    fprintf(stderr, "fhsm-ca: %d asked, %zu ours (%zu revoked), %zu unknown,"
                    " valid %d days%s.\n",
            nreq, n_ours, n_revoked, n_unknown, days,
            exts_len ? ", nonce echoed" : ", no nonce");

    for (int i = 0; i < nreq; i++) { OPENSSL_free(cid_der[i]); OPENSSL_free(rev_der[i]); }
    free(cid_der); free(rev_der); free(singles); free(exts);
    free(basic); free(resp); free(d.e);
    OPENSSL_free(d_now); OPENSSL_free(d_nxt);
    ASN1_GENERALIZEDTIME_free(g_now); ASN1_GENERALIZEDTIME_free(g_nxt);
    OCSP_REQUEST_free(req); X509_free(ca);
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

