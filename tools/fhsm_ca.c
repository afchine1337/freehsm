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
      "                 [--subject DN] [--san LIST] [--crl-url URL]...\n"
      "                 [--days N] [--out FILE] [--pem]\n"
      "  fhsm-ca revoke --db FILE --serial HEX [--reason NAME] [--date WHEN]\n"
      "  fhsm-ca crl    --label NAME --ca-cert FILE --db FILE\n"
      "                 [--days N] [--out FILE] [--pem]\n\n"
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
      "  --days N        validity in days (issue: 365, crl: 30)\n"
      "  --module PATH   PKCS#11 module (default ./libfreehsm-fips.so)\n"
      "  --slot N        slot index (default 0)\n"
      "  --out FILE      output file (default stdout)\n"
      "  --pem           PEM instead of DER\n\n"
      "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n"
      "  is visible in ps to every user on the machine.\n\n"
      "  `revoke` only records the revocation; it does not need the key and\n"
      "  produces nothing signed. `crl` is what signs, and it advances the\n"
      "  database's crlNumber as it goes -- so a list that has been issued is\n"
      "  never issued again under the same number.\n");
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
    int pem = 0, slot = 0, days = 365;

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
        else if (!strcmp(argv[i],"--slot")    && i+1<argc) slot     = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--days")    && i+1<argc) days     = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--pem")) pem = 1;
        else if (!strncmp(argv[i],"--pin",5)) {
            fprintf(stderr, "fhsm-ca: --pin is not accepted. Set FHSM_PIN instead:\n"
                            "  an argument is visible in ps to every user on this machine.\n");
            return 1;
        }
        else usage();
    }
    if (!label || !cacert_p || !csr_p) usage();

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
    rv = p11.OpenSession((CK_SLOT_ID)slot, CKF_RW, NULL, NULL, &s);
    if (rv != CKR_OK) die("C_OpenSession", rv);
    rv = p11.Login(s, CKU_USER, (CK_BYTE*)(uintptr_t)pin, (CK_ULONG)strlen(pin));
    if (rv != CKR_OK) die("C_Login", rv);

    CK_OBJECT_HANDLE hpriv = find_one(s, CKO_PRIVATE_KEY, label);
    struct signer sg = { s, hpriv };

    static uint8_t der[32768]; size_t n = sizeof der;
    fhsm_rv_t r = fhsm_composite_issue(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                        cabuf, calen, csrbuf, csrlen,
                                        subject, san, crl_urls, n_crl_urls,
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
    int pem = 0, slot = 0, days = 30;

    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module")  && i+1<argc) module   = argv[++i];
        else if (!strcmp(argv[i],"--label")   && i+1<argc) label    = argv[++i];
        else if (!strcmp(argv[i],"--ca-cert") && i+1<argc) cacert_p = argv[++i];
        else if (!strcmp(argv[i],"--db")      && i+1<argc) db_p     = argv[++i];
        else if (!strcmp(argv[i],"--out")     && i+1<argc) out      = argv[++i];
        else if (!strcmp(argv[i],"--slot")    && i+1<argc) slot     = atoi(argv[++i]);
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
    rv = p11.OpenSession((CK_SLOT_ID)slot, CKF_RW, NULL, NULL, &s);
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

int main(int argc, char **argv) {
    p11_progname = "fhsm-ca";
    if (argc < 2) usage();
    if (!strcmp(argv[1], "issue"))  return cmd_issue(argc, argv);
    if (!strcmp(argv[1], "revoke")) return cmd_revoke(argc, argv);
    if (!strcmp(argv[1], "crl"))    return cmd_crl(argc, argv);
    usage();
    return 1;
}

