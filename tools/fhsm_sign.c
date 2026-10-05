/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * fhsm-sign --- detached signatures over arbitrary data, with a composite
 *               post-quantum key held in a PKCS#11 module (#123).
 *
 *  Usage :
 *    fhsm-sign sign   --label NAME [--in FILE] [--out FILE]
 *    fhsm-sign verify --label NAME --sig FILE [--in FILE]
 *
 *  Detached and raw: the output is the signature bytes and nothing else. No
 *  container, no header, no algorithm identifier. That is a deliberate first
 *  step and it has a consequence worth stating rather than discovering: the
 *  file does not say which key or which algorithm produced it, so whoever
 *  verifies has to be told. CMS/PKCS#7, which carries that metadata, is the
 *  next layer and not this one.
 *
 *  The data is streamed. C_SignUpdate feeds the module in blocks and the
 *  message is never held whole, so an image larger than memory signs fine --
 *  and the 2 GiB ceiling C_Sign imposes on a single call does not apply.
 *  What is signed is identical to what the one-shot path signs; the module's
 *  tests cross-verify signatures made each way, because a streamed signature
 *  that only verified through the streamed path would be a private
 *  construction wearing a standard OID.
 *
 *  The work is in tools/pkiops.c, which the planned graphical interface calls
 *  too (docs/fhsm-gui-plan.md). What stays here is the command line and the
 *  files: reading the data, the signature and the certificate, and writing
 *  what is produced.
 * ========================================================================= */
#include "pkiops.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>

#define CHUNK (1u << 20)          /* 1 MiB : large enough that the syscall and
                                     PKCS#11 crossing cost nothing measurable,
                                     small enough to sign from a pipe without
                                     buffering the whole stream. */


static const char *prog = "fhsm-sign";

static void fail(const struct p11_err *e) {
    fprintf(stderr, "%s: %s", prog, e->msg);
    exit(e->code);
}

static void usage(void) {
    fprintf(stderr,
      "fhsm-sign --- detached signatures with a key held in a PKCS#11 module\n\n"
      "  fhsm-sign sign       --label NAME [--in FILE] [--out FILE]\n"
      "  fhsm-sign verify     --label NAME --sig FILE [--in FILE]\n"
      "  fhsm-sign cms        --label NAME --cert FILE [--in FILE] [--out FILE]\n"
      "  fhsm-sign cms-verify --cms FILE [--in FILE]\n\n"
      "  --label NAME    label of the key inside the module. sign uses the\n"
      "                  private key of that label, verify the public one, each\n"
      "                  with the algorithm the key was generated for.\n"
      "  --in FILE       data to sign or check (default: standard input)\n"
      "  --out FILE      where to write the signature (default: standard output)\n"
      "  --sig FILE      the signature to check\n"
      "  --cert FILE     the signer's certificate (DER or PEM), for cms\n"
      "  --cms FILE      the CMS structure to check\n"
      "  --module PATH   PKCS#11 module (default ./libfreehsm.so)\n"
      "  --slot N        slot to address. Default: the one slot holding a token.\n\n"
      "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n"
      "  is visible in ps to every user on the machine.\n\n"
      "  The signature is raw and detached -- the bytes, nothing around them.\n"
      "  It does not record which key or algorithm made it, so a verifier has\n"
      "  to be told. That is what cms, below, carries.\n"
      "  An ECDSA signature is written as DER, which openssl dgst -verify reads.\n\n"
      "  Input is streamed: this tool never holds it. The module may -- FreeHSM\n"
      "  hashes a composite signature's input as it arrives, and holds the\n"
      "  input of the other algorithms until the end. cms is never bounded:\n"
      "  only a digest reaches the module.\n\n"
      "  cms produces a detached RFC 5652 SignedData with signed attributes,\n"
      "  carrying the signer's certificate. Unlike the raw form it records\n"
      "  which key and which algorithm made it -- so cms-verify needs neither\n"
      "  the token nor a label, only the file and the data.\n\n"
      "  Exit codes: 0 success. 1 usage or FHSM_PIN unset. 2 module or I/O\n"
      "  failure. 3 no such key, or more than one with that label.\n"
      "  4 the signature does not match -- and only that.\n");
    exit(1);
}


/* Open the input, or standard input for "-" / absent. */
static FILE *open_in(const char *path) {
    if (!path || !strcmp(path, "-")) return stdin;
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "fhsm-sign: cannot read %s: %s\n", path, strerror(errno)); exit(2); }
    return f;
}

/* Feed the whole stream to the module in blocks. Used by both subcommands,
 * so sign and verify cannot disagree about what they consumed -- a difference
 * there would show up as a signature that never validates, with nothing in
 * either message to say why. */
static void stream_into(FILE *in, pkiops_handle s, int verifying) {
    static uint8_t buf[CHUNK];
    struct p11_err e;
    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, in);
        if (n && (verifying ? pkiops_verify_update(s, buf, n, &e)
                            : pkiops_sign_update(s, buf, n, &e)))
            fail(&e);
        if (n < sizeof buf) {
            if (ferror(in)) { fprintf(stderr, "fhsm-sign: read failed: %s\n", strerror(errno)); exit(2); }
            break;                       /* short read means end of file */
        }
    }
}

/* Open a session and log in. Shared so the two subcommands cannot drift on
 * the PIN policy. */
static pkiops_handle open_session(const char *module, long slot) {
    struct p11_err e;
    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) { fprintf(stderr, "fhsm-sign: FHSM_PIN is not set.\n"); exit(1); }
    pkiops_handle sid = 0, s = 0;
    if (pkiops_open(module, slot, PKIOPS_SLOT_WITH_TOKEN, &sid, &e)) fail(&e);
    if (pkiops_session_user(sid, (const uint8_t *)pin, strlen(pin), &s, &e)) fail(&e);
    return s;
}

static void close_session(pkiops_handle s) {
    pkiops_session_close(s);
    pkiops_close();
}

struct opts { const char *module, *label, *in, *out, *sig, *cert, *cms; long slot; };

static struct opts parse(int argc, char **argv) {
    struct opts o;
    struct p11_err e;
    o.module = "./libfreehsm.so";
    o.label = o.in = o.out = o.sig = o.cert = o.cms = NULL;
    o.slot = -1;
    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module") && i+1<argc) o.module = argv[++i];
        else if (!strcmp(argv[i],"--label")  && i+1<argc) o.label  = argv[++i];
        else if (!strcmp(argv[i],"--in")     && i+1<argc) o.in     = argv[++i];
        else if (!strcmp(argv[i],"--out")    && i+1<argc) o.out    = argv[++i];
        else if (!strcmp(argv[i],"--sig")    && i+1<argc) o.sig    = argv[++i];
        else if (!strcmp(argv[i],"--cert")   && i+1<argc) o.cert   = argv[++i];
        else if (!strcmp(argv[i],"--cms")    && i+1<argc) o.cms    = argv[++i];
        else if (!strcmp(argv[i],"--slot")   && i+1<argc) {
            if (pkiops_parse_slot(argv[++i], &o.slot, &e)) fail(&e);
        }
        else if (!strncmp(argv[i],"--pin",5)) {
            fprintf(stderr, "fhsm-sign: --pin is not accepted. Set FHSM_PIN instead:\n"
                            "  an argument is visible in ps to every user on this machine.\n");
            exit(1);
        }
        else usage();
    }
    return o;
}

static int cmd_sign(int argc, char **argv) {
    struct p11_err e;
    struct opts o = parse(argc, argv);
    if (!o.label) usage();
    FILE *in = open_in(o.in);

    pkiops_handle s = open_session(o.module, o.slot);
    if (pkiops_sign_begin(s, o.label, &e)) fail(&e);

    stream_into(in, s, 0);
    if (in != stdin) fclose(in);

    uint8_t *sig = NULL; size_t slen = 0;
    if (pkiops_sign_end(s, &sig, &slen, &e)) fail(&e);

    FILE *out = o.out ? fopen(o.out, "wb") : stdout;
    if (!out) { fprintf(stderr, "fhsm-sign: cannot write %s: %s\n", o.out, strerror(errno)); return 2; }
    if (fwrite(sig, 1, slen, out) != slen) { perror("fhsm-sign: write"); return 2; }
    if (o.out) { if (fclose(out) != 0) { perror("fhsm-sign: close"); return 2; } }
    else fflush(out);

    fprintf(stderr, "fhsm-sign: %lu-byte detached signature.\n", (unsigned long)slen);
    free(sig);
    close_session(s);
    return 0;
}

static int cmd_verify(int argc, char **argv) {
    struct p11_err e;
    struct opts o = parse(argc, argv);
    if (!o.label || !o.sig) usage();

    /* Read the signature first: a missing or unreadable one should fail before
     * the operator is asked for anything and before a stream is consumed. */
    FILE *sf = fopen(o.sig, "rb");
    if (!sf) { fprintf(stderr, "fhsm-sign: cannot read %s: %s\n", o.sig, strerror(errno)); exit(2); }
    static uint8_t sig[65536];
    size_t slen = fread(sig, 1, sizeof sig, sf);
    int overflow = !feof(sf) && !ferror(sf);
    if (ferror(sf)) { fprintf(stderr, "fhsm-sign: reading %s failed\n", o.sig); exit(2); }
    fclose(sf);
    if (slen == 0) { fprintf(stderr, "fhsm-sign: %s is empty\n", o.sig); exit(2); }
    if (overflow)  { fprintf(stderr, "fhsm-sign: %s is larger than any signature "
                                     "this tool produces\n", o.sig); exit(2); }

    FILE *in = open_in(o.in);
    pkiops_handle s = open_session(o.module, o.slot);
    if (pkiops_verify_begin(s, o.label, &e)) fail(&e);

    stream_into(in, s, 1);
    if (in != stdin) fclose(in);

    int valid = 0;
    int rc = pkiops_verify_end(s, sig, slen, &valid, &e);
    close_session(s);
    if (rc) fail(&e);

    /* A bad signature is not a tool failure, and it gets its own exit code so
     * a script can tell "did not verify" from "could not run". */
    if (!valid) {
        fprintf(stderr, "fhsm-sign: the signature does not match this data "
                        "under key \"%s\".\n", o.label);
        return 4;
    }
    fprintf(stderr, "fhsm-sign: signature verified.\n");
    return 0;
}


/* Read a whole file, accepting PEM as well as DER. Used for certificates and
 * CMS structures, which are small; the data being signed is never read this
 * way. */
static uint8_t *slurp_der(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "fhsm-sign: cannot read %s: %s\n", path, strerror(errno)); exit(2); }
    static uint8_t buf[262144];
    *n = fread(buf, 1, sizeof buf, f);
    int over = !feof(f) && !ferror(f);
    if (ferror(f)) { fprintf(stderr, "fhsm-sign: reading %s failed\n", path); exit(2); }
    fclose(f);
    if (*n == 0)  { fprintf(stderr, "fhsm-sign: %s is empty\n", path); exit(2); }
    if (over)     { fprintf(stderr, "fhsm-sign: %s is too large\n", path); exit(2); }
    if (*n > 11 && memcmp(buf, "-----BEGIN ", 11) == 0) {
        BIO *b = BIO_new_mem_buf(buf, (int)*n);
        char *nm = NULL, *hdr = NULL; unsigned char *d = NULL; long dl = 0;
        if (b && PEM_read_bio(b, &nm, &hdr, &d, &dl) == 1 && dl > 0
            && (size_t)dl <= sizeof buf) { memcpy(buf, d, (size_t)dl); *n = (size_t)dl; }
        else { fprintf(stderr, "fhsm-sign: %s looks like PEM but did not parse\n", path); exit(2); }
        OPENSSL_free(nm); OPENSSL_free(hdr); OPENSSL_free(d); BIO_free(b);
    }
    return buf;
}

/* The digests of a stream: SHA-256, SHA-384 and SHA-512, all three in the one
 * pass. The only thing that has to see the data: with signed attributes the
 * signature covers the attributes, so a file of any size costs exactly one
 * pass and nothing is held. Three, because which one a CMS uses depends on
 * the key that signs it or on the structure being checked, and the data is
 * read -- possibly from a pipe -- before either is known. */
static const char *const DIGESTS[3] = { "SHA256", "SHA384", "SHA512" };
struct digests { uint8_t d[3][64]; size_t len[3]; };

static void digest_stream(FILE *in, struct digests *out) {
    struct p11_err e;
    struct pkiops_hash *h[3];
    for (int k = 0; k < 3; k++)
        if (!(h[k] = pkiops_hash_begin(DIGESTS[k], &e))) fail(&e);
    static uint8_t buf[CHUNK];
    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, in);
        for (int k = 0; n && k < 3; k++)
            if (pkiops_hash_update(h[k], buf, n, &e)) fail(&e);
        if (n < sizeof buf) {
            if (ferror(in)) { fprintf(stderr, "fhsm-sign: read failed: %s\n", strerror(errno)); exit(2); }
            break;
        }
    }
    for (int k = 0; k < 3; k++)
        if (pkiops_hash_end(h[k], out->d[k], &out->len[k], &e)) fail(&e);
}

/* The one of the three that `name` names; SHA-512 for anything else. */
static int pick(const char *name) {
    for (int k = 0; k < 3; k++) if (name && !strcmp(name, DIGESTS[k])) return k;
    return 2;
}

static int cmd_cms(int argc, char **argv) {
    struct p11_err e;
    struct opts o = parse(argc, argv);
    if (!o.label || !o.cert) usage();

    size_t certlen = 0;
    uint8_t *certbuf = slurp_der(o.cert, &certlen);
    static uint8_t cert[262144];
    memcpy(cert, certbuf, certlen);

    FILE *in = open_in(o.in);
    struct digests dg;
    digest_stream(in, &dg);
    if (in != stdin) fclose(in);

    pkiops_handle s = open_session(o.module, o.slot);
    /* The digest the key's algorithm signs with. */
    enum pkiops_alg alg;
    if (pkiops_key_alg(s, o.label, &alg, &e)) fail(&e);
    int k = pick(pkiops_alg_digest(alg));
    static uint8_t der[262144]; size_t n = sizeof der;
    if (pkiops_cms_sign(s, o.label, cert, certlen, dg.d[k], dg.len[k], der, &n, &e)) fail(&e);

    FILE *out = o.out ? fopen(o.out, "wb") : stdout;
    if (!out) { fprintf(stderr, "fhsm-sign: cannot write %s: %s\n", o.out, strerror(errno)); return 2; }
    if (fwrite(der, 1, n, out) != n) { perror("fhsm-sign: write"); return 2; }
    if (o.out) { if (fclose(out) != 0) { perror("fhsm-sign: close"); return 2; } }
    else fflush(out);

    fprintf(stderr, "fhsm-sign: %zu-byte detached CMS SignedData.\n", n);
    close_session(s);
    return 0;
}

static int cmd_cms_verify(int argc, char **argv) {
    struct p11_err e;
    struct opts o = parse(argc, argv);
    if (!o.cms) usage();

    size_t cmslen = 0;
    uint8_t *cmsbuf = slurp_der(o.cms, &cmslen);
    static uint8_t cms[262144];
    memcpy(cms, cmsbuf, cmslen);

    FILE *in = open_in(o.in);
    struct digests dg;
    digest_stream(in, &dg);
    if (in != stdin) fclose(in);

    /* No module, no token, no PIN. The signer's certificate travels inside
     * the structure, which is what CMS is for -- and the structure names the
     * digest. One it cannot name falls through to the verdict below. */
    const char *dname = NULL;
    if (pkiops_cms_digest(cms, cmslen, &dname)) dname = NULL;
    int k = pick(dname);
    int verdict = 0;
    if (pkiops_cms_verify(cms, cmslen, dg.d[k], dg.len[k], &verdict, &e)) fail(&e);
    if (verdict == 0) {
        fprintf(stderr, "fhsm-sign: the CMS does not match this data.\n");
        return 4;
    }
    if (verdict < 0) {
        fprintf(stderr, "fhsm-sign: %s is not a CMS this tool can read.\n"
                        "  That is a different problem from a signature that does\n"
                        "  not match, and exits 2 rather than 4.\n", o.cms);
        return 2;
    }
    fprintf(stderr, "fhsm-sign: CMS verified.\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) usage();
    if (!strcmp(argv[1], "sign"))   return cmd_sign(argc, argv);
    if (!strcmp(argv[1], "verify")) return cmd_verify(argc, argv);
    if (!strcmp(argv[1], "cms"))        return cmd_cms(argc, argv);
    if (!strcmp(argv[1], "cms-verify")) return cmd_cms_verify(argc, argv);
    usage();
    return 1;
}
