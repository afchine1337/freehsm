/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm-ca --- issue certificates from a certification request, signing with a
 *             composite post-quantum key held in a PKCS#11 module (#112).
 *
 *  Usage :
 *    fhsm-ca issue --label NAME --ca-cert FILE --csr FILE
 *                  [--subject DN] [--days N] [--out FILE] [--pem]
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

static void usage(void) {
    fprintf(stderr,
      "fhsm-ca --- issue certificates with a composite PQ key via PKCS#11\n\n"
      "  fhsm-ca issue --label NAME --ca-cert FILE --csr FILE\n"
      "                [--subject DN] [--days N] [--out FILE] [--pem]\n\n"
      "  --label NAME    label of the CA key inside the module\n"
      "  --ca-cert FILE  the CA's own certificate (DER or PEM)\n"
      "  --csr FILE      the request to sign (DER or PEM)\n"
      "  --subject DN    replace the requested subject entirely\n"
      "  --days N        validity in days (default 365)\n"
      "  --module PATH   PKCS#11 module (default ./libfreehsm-fips.so)\n"
      "  --slot N        slot index (default 0)\n"
      "  --out FILE      output file (default stdout)\n"
      "  --pem           PEM instead of DER\n\n"
      "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n"
      "  is visible in ps to every user on the machine.\n\n"
      "  The request's own signature is verified against the key it carries\n"
      "  before anything is issued. Extensions asked for by the applicant are\n"
      "  ignored; the CA sets basicConstraints CA:FALSE, keyUsage, and the two\n"
      "  key identifiers itself.\n");
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "issue") != 0) usage();
    const char *module = "./libfreehsm-fips.so", *label = NULL;
    const char *cacert_p = NULL, *csr_p = NULL, *subject = NULL, *out = NULL;
    int pem = 0, slot = 0, days = 365;

    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module")  && i+1<argc) module   = argv[++i];
        else if (!strcmp(argv[i],"--label")   && i+1<argc) label    = argv[++i];
        else if (!strcmp(argv[i],"--ca-cert") && i+1<argc) cacert_p = argv[++i];
        else if (!strcmp(argv[i],"--csr")     && i+1<argc) csr_p    = argv[++i];
        else if (!strcmp(argv[i],"--subject") && i+1<argc) subject  = argv[++i];
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
                                        subject, days, p11_sign, &sg, der, &n);
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
