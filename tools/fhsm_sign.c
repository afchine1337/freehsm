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
 * ========================================================================= */
#include "p11_util.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define CHUNK (1u << 20)          /* 1 MiB : large enough that the syscall and
                                     PKCS#11 crossing cost nothing measurable,
                                     small enough to sign from a pipe without
                                     buffering the whole stream. */

static void usage(void) {
    fprintf(stderr,
      "fhsm-sign --- detached signatures with a composite PQ key via PKCS#11\n\n"
      "  fhsm-sign sign       --label NAME [--in FILE] [--out FILE]\n"
      "  fhsm-sign verify     --label NAME --sig FILE [--in FILE]\n"
      "  fhsm-sign cms        --label NAME --cert FILE [--in FILE] [--out FILE]\n"
      "  fhsm-sign cms-verify --cms FILE [--in FILE]\n\n"
      "  --label NAME    label of the key inside the module. sign uses the\n"
      "                  private key of that label, verify the public one.\n"
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
      "  to be told. That is what CMS would carry, and CMS is not this tool.\n\n"
      "  Input is streamed, so size is not bounded by memory.\n\n"
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
static void stream_into(FILE *in, CK_SESSION_HANDLE s, int verifying) {
    static CK_BYTE buf[CHUNK];
    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, in);
        if (n) {
            CK_RV rv = verifying ? p11.VerifyUpdate(s, buf, (CK_ULONG)n)
                                 : p11.SignUpdate(s, buf, (CK_ULONG)n);
            if (rv != CKR_OK) die(verifying ? "C_VerifyUpdate" : "C_SignUpdate", rv);
        }
        if (n < sizeof buf) {
            if (ferror(in)) { fprintf(stderr, "fhsm-sign: read failed: %s\n", strerror(errno)); exit(2); }
            break;                       /* short read means end of file */
        }
    }
}

/* Open a session and log in. Shared so the two subcommands cannot drift on
 * the PIN policy. */
static CK_SESSION_HANDLE open_session(const char *module, long slot) {
    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) { fprintf(stderr, "fhsm-sign: FHSM_PIN is not set.\n"); exit(1); }
    load_module(module);
    CK_RV rv = p11.Initialize(NULL);
    if (rv != CKR_OK) die("C_Initialize", rv);
    CK_SESSION_HANDLE s = 0;
    rv = p11.OpenSession(p11_resolve_slot(slot, P11_SLOT_WITH_TOKEN),
                          CKF_RW, NULL, NULL, &s);
    if (rv != CKR_OK) die("C_OpenSession", rv);
    rv = p11.Login(s, CKU_USER, (CK_BYTE*)(uintptr_t)pin, (CK_ULONG)strlen(pin));
    if (rv != CKR_OK) die("C_Login", rv);
    return s;
}

struct opts { const char *module, *label, *in, *out, *sig, *cert, *cms; long slot; };

static struct opts parse(int argc, char **argv) {
    struct opts o;
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
        else if (!strcmp(argv[i],"--slot")   && i+1<argc) o.slot   = p11_slot_arg(argv[++i]);
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
    struct opts o = parse(argc, argv);
    if (!o.label) usage();
    FILE *in = open_in(o.in);

    CK_SESSION_HANDLE s = open_session(o.module, o.slot);
    CK_OBJECT_HANDLE hpriv = find_one(s, CKO_PRIVATE_KEY, o.label);

    CK_MECHANISM m = { CKM_COMPOSITE_MLDSA65_ED25519, NULL, 0 };
    CK_RV rv = p11.SignInit(s, &m, hpriv);
    if (rv != CKR_OK) die("C_SignInit", rv);

    stream_into(in, s, 0);
    if (in != stdin) fclose(in);

    /* Ask the module for the length rather than assuming it: the size is a
     * property of the mechanism, and hard-coding one here is how the RSA
     * query ended up wrong once already. */
    CK_ULONG need = 0;
    rv = p11.SignFinal(s, NULL, &need);
    if (rv != CKR_OK) die("C_SignFinal (size query)", rv);
    CK_BYTE *sig = malloc(need);
    if (!sig) { fprintf(stderr, "fhsm-sign: out of memory\n"); return 2; }
    CK_ULONG slen = need;
    rv = p11.SignFinal(s, sig, &slen);
    if (rv != CKR_OK) die("C_SignFinal", rv);

    FILE *out = o.out ? fopen(o.out, "wb") : stdout;
    if (!out) { fprintf(stderr, "fhsm-sign: cannot write %s: %s\n", o.out, strerror(errno)); return 2; }
    if (fwrite(sig, 1, slen, out) != slen) { perror("fhsm-sign: write"); return 2; }
    if (o.out) { if (fclose(out) != 0) { perror("fhsm-sign: close"); return 2; } }
    else fflush(out);

    fprintf(stderr, "fhsm-sign: %lu-byte detached signature.\n", (unsigned long)slen);
    free(sig);
    p11.CloseSession(s); p11.Finalize(NULL);
    return 0;
}

static int cmd_verify(int argc, char **argv) {
    struct opts o = parse(argc, argv);
    if (!o.label || !o.sig) usage();

    /* Read the signature first: a missing or unreadable one should fail before
     * the operator is asked for anything and before a stream is consumed. */
    FILE *sf = fopen(o.sig, "rb");
    if (!sf) { fprintf(stderr, "fhsm-sign: cannot read %s: %s\n", o.sig, strerror(errno)); exit(2); }
    static CK_BYTE sig[65536];
    size_t slen = fread(sig, 1, sizeof sig, sf);
    int overflow = !feof(sf) && !ferror(sf);
    if (ferror(sf)) { fprintf(stderr, "fhsm-sign: reading %s failed\n", o.sig); exit(2); }
    fclose(sf);
    if (slen == 0) { fprintf(stderr, "fhsm-sign: %s is empty\n", o.sig); exit(2); }
    if (overflow)  { fprintf(stderr, "fhsm-sign: %s is larger than any signature "
                                     "this tool produces\n", o.sig); exit(2); }

    FILE *in = open_in(o.in);
    CK_SESSION_HANDLE s = open_session(o.module, o.slot);
    CK_OBJECT_HANDLE hpub = find_one(s, CKO_PUBLIC_KEY, o.label);

    CK_MECHANISM m = { CKM_COMPOSITE_MLDSA65_ED25519, NULL, 0 };
    CK_RV rv = p11.VerifyInit(s, &m, hpub);
    if (rv != CKR_OK) die("C_VerifyInit", rv);

    stream_into(in, s, 1);
    if (in != stdin) fclose(in);

    rv = p11.VerifyFinal(s, sig, (CK_ULONG)slen);
    p11.CloseSession(s); p11.Finalize(NULL);

    /* A bad signature is not a tool failure, and it gets its own exit code so
     * a script can tell "did not verify" from "could not run". */
    if (rv == CKR_SIGNATURE_INVALID) {
        fprintf(stderr, "fhsm-sign: the signature does not match this data "
                        "under key \"%s\".\n", o.label);
        return 4;
    }
    if (rv != CKR_OK) die("C_VerifyFinal", rv);
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

/* SHA-512 of a stream. The only thing that has to see the data: with signed
 * attributes the signature covers the attributes, so a file of any size costs
 * exactly one pass and nothing is held. */
static void digest_stream(FILE *in, uint8_t out[64]) {
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA512", NULL);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!md || !c) { fprintf(stderr, "fhsm-sign: digest init failed\n"); exit(2); }
    if (EVP_DigestInit_ex(c, md, NULL) != 1) { fprintf(stderr, "fhsm-sign: digest init failed\n"); exit(2); }
    static uint8_t buf[CHUNK];
    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, in);
        if (n && EVP_DigestUpdate(c, buf, n) != 1) {
            fprintf(stderr, "fhsm-sign: digest failed\n"); exit(2);
        }
        if (n < sizeof buf) {
            if (ferror(in)) { fprintf(stderr, "fhsm-sign: read failed: %s\n", strerror(errno)); exit(2); }
            break;
        }
    }
    unsigned int l = 0;
    if (EVP_DigestFinal_ex(c, out, &l) != 1 || l != 64) {
        fprintf(stderr, "fhsm-sign: digest failed\n"); exit(2);
    }
    EVP_MD_CTX_free(c); EVP_MD_free(md);
}

static int cmd_cms(int argc, char **argv) {
    struct opts o = parse(argc, argv);
    if (!o.label || !o.cert) usage();

    size_t certlen = 0;
    uint8_t *certbuf = slurp_der(o.cert, &certlen);
    static uint8_t cert[262144];
    memcpy(cert, certbuf, certlen);

    FILE *in = open_in(o.in);
    uint8_t dg[64];
    digest_stream(in, dg);
    if (in != stdin) fclose(in);

    CK_SESSION_HANDLE s = open_session(o.module, o.slot);
    CK_OBJECT_HANDLE hpriv = find_one(s, CKO_PRIVATE_KEY, o.label);
    struct signer sg = { s, hpriv };

    static uint8_t der[262144]; size_t n = sizeof der;
    fhsm_rv_t r = fhsm_composite_cms(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                      cert, certlen, dg, sizeof dg,
                                      p11_sign, &sg, der, &n);
    if (r != FHSM_RV_OK) die("building the CMS", (CK_RV)r);

    FILE *out = o.out ? fopen(o.out, "wb") : stdout;
    if (!out) { fprintf(stderr, "fhsm-sign: cannot write %s: %s\n", o.out, strerror(errno)); return 2; }
    if (fwrite(der, 1, n, out) != n) { perror("fhsm-sign: write"); return 2; }
    if (o.out) { if (fclose(out) != 0) { perror("fhsm-sign: close"); return 2; } }
    else fflush(out);

    fprintf(stderr, "fhsm-sign: %zu-byte detached CMS SignedData.\n", n);
    p11.CloseSession(s); p11.Finalize(NULL);
    return 0;
}

static int cmd_cms_verify(int argc, char **argv) {
    struct opts o = parse(argc, argv);
    if (!o.cms) usage();

    size_t cmslen = 0;
    uint8_t *cmsbuf = slurp_der(o.cms, &cmslen);
    static uint8_t cms[262144];
    memcpy(cms, cmsbuf, cmslen);

    FILE *in = open_in(o.in);
    uint8_t dg[64];
    digest_stream(in, dg);
    if (in != stdin) fclose(in);

    /* No module, no token, no PIN. The signer's certificate travels inside
     * the structure, which is what CMS is for. */
    fhsm_rv_t r = fhsm_composite_cms_verify(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                             cms, cmslen, dg, sizeof dg);
    if (r == FHSM_RV_SIGNATURE_INVALID) {
        fprintf(stderr, "fhsm-sign: the CMS does not match this data.\n");
        return 4;
    }
    if (r == FHSM_RV_ARGUMENTS_BAD) {
        fprintf(stderr, "fhsm-sign: %s is not a composite CMS this tool can read.\n"
                        "  That is a different problem from a signature that does\n"
                        "  not match, and exits 2 rather than 4.\n", o.cms);
        return 2;
    }
    if (r != FHSM_RV_OK) die("verifying the CMS", (CK_RV)r);
    fprintf(stderr, "fhsm-sign: CMS verified.\n");
    return 0;
}

int main(int argc, char **argv) {
    p11_progname = "fhsm-sign";
    if (argc < 2) usage();
    if (!strcmp(argv[1], "sign"))   return cmd_sign(argc, argv);
    if (!strcmp(argv[1], "verify")) return cmd_verify(argc, argv);
    if (!strcmp(argv[1], "cms"))        return cmd_cms(argc, argv);
    if (!strcmp(argv[1], "cms-verify")) return cmd_cms_verify(argc, argv);
    usage();
    return 1;
}
