/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm-csr --- certification requests and self-signed roots, with a composite
 *              post-quantum key held in a PKCS#11 module (#112).
 *
 *  Usage :
 *    fhsm-csr keygen --label NAME [--module PATH] [--slot N]
 *    fhsm-csr csr    --label NAME --subject DN [--out FILE] [--pem]
 *    fhsm-csr root   --label NAME --subject DN [--days N] [--serial N] ...
 *
 *  The PIN comes from the FHSM_PIN environment variable and from nowhere else.
 *  There is deliberately no --pin option: an argument is visible in `ps` to
 *  every user on the machine, and a tool that offers the convenient insecure
 *  option is a tool whose users take it.
 *
 *  The module is loaded at runtime and driven only through the PKCS#11
 *  interface, so this works against any PKCS#11 module that implements the
 *  composite mechanism -- not only against FreeHSM. That is the point: a
 *  university that already owns a hardware HSM should be able to use these
 *  tools with it. The composite DER encoding travels with the tool
 *  (src/fhsm_composite.o links standalone against libcrypto), the key stays
 *  wherever the module keeps it, and the private half is never seen here.
 * ========================================================================= */
#include "p11_util.h"

#include <openssl/pem.h>

static void emit(const uint8_t *der, size_t n, const char *path,
                  int pem, const char *pem_label) {
    FILE *f = path ? fopen(path, "wb") : stdout;
    if (!f) { perror("fhsm-csr: open"); exit(2); }
    if (pem) {
        BIO *b = BIO_new_fp(f, BIO_NOCLOSE);
        PEM_write_bio(b, pem_label, "", (unsigned char*)(uintptr_t)der, (long)n);
        BIO_free(b);
    } else {
        if (fwrite(der, 1, n, f) != n) { perror("fhsm-csr: write"); exit(2); }
    }
    if (path) fclose(f);
}

static void usage(void) {
    fprintf(stderr,
      "fhsm-csr --- composite PQ certification requests and roots via PKCS#11\n\n"
      "  fhsm-csr keygen --label NAME [--module PATH] [--slot N]\n"
      "  fhsm-csr csr    --label NAME --subject DN [--out FILE] [--pem] ...\n"
      "  fhsm-csr root   --label NAME --subject DN [--days N] [--serial N] ...\n\n"
      "  --module PATH   PKCS#11 module (default ./libfreehsm.so)\n"
      "  --slot N        slot to address. Default: the one slot holding a token.\n"
      "  --subject DN    e.g. \"/C=FR/O=Simorgh Labs/CN=example\"\n"
      "  --days N        validity in days for root (default 3650)\n"
      "  --serial N      certificate serial for root (default 1)\n"
      "  --out FILE      output file (default stdout)\n"
      "  --pem           PEM instead of DER\n\n"
      "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n"
      "  is visible in ps to every user on the machine.\n\n"
      "  Note: the composite algorithm is not yet implemented by general-purpose\n"
      "  tooling, so a request produced here can be parsed and transported but\n"
      "  not validated by anything off the shelf until the RFC publishes.\n");
    exit(1);
}

int main(int argc, char **argv) {
    p11_progname = "fhsm-csr";
    if (argc < 2) usage();
    const char *cmd = argv[1];
    const char *module = "./libfreehsm.so", *label = NULL, *subject = NULL;
    const char *out = NULL;
    int pem = 0, days = 3650; long serial = 1, slot = -1;

    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module")  && i+1<argc) module  = argv[++i];
        else if (!strcmp(argv[i],"--label")   && i+1<argc) label   = argv[++i];
        else if (!strcmp(argv[i],"--subject") && i+1<argc) subject = argv[++i];
        else if (!strcmp(argv[i],"--out")     && i+1<argc) out     = argv[++i];
        else if (!strcmp(argv[i],"--slot")    && i+1<argc) slot    = p11_slot_arg(argv[++i]);
        else if (!strcmp(argv[i],"--days")    && i+1<argc) days    = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--serial")  && i+1<argc) serial  = atol(argv[++i]);
        else if (!strcmp(argv[i],"--pem")) pem = 1;
        else if (!strcmp(argv[i],"--pin") || !strncmp(argv[i],"--pin=",6)) {
            fprintf(stderr, "fhsm-csr: --pin is not accepted. Set FHSM_PIN instead:\n"
                            "  an argument is visible in ps to every user on this machine.\n");
            return 1;
        }
        else usage();
    }
    if (!label) usage();
    if ((!strcmp(cmd,"csr") || !strcmp(cmd,"root")) && !subject) usage();

    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) {
        fprintf(stderr, "fhsm-csr: FHSM_PIN is not set.\n"); return 1;
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

    if (!strcmp(cmd, "keygen")) {
        CK_MECHANISM m = { CKM_COMPOSITE_MLDSA65_ED25519, NULL, 0 };
        CK_BYTE t = 1;
        CK_ATTRIBUTE pub_t[]  = { {CKA_LABEL,(void*)label,(CK_ULONG)strlen(label)},
                                   {CKA_TOKEN,&t,1} };
        CK_ATTRIBUTE priv_t[] = { {CKA_LABEL,(void*)label,(CK_ULONG)strlen(label)},
                                   {CKA_TOKEN,&t,1} };
        CK_OBJECT_HANDLE hp = 0, hk = 0;
        rv = p11.GenerateKeyPair(s, &m, pub_t, 2, priv_t, 2, &hp, &hk);
        if (rv != CKR_OK) die("C_GenerateKeyPair", rv);
        fprintf(stderr, "fhsm-csr: composite key pair \"%s\" created "
                        "(public %lu, private %lu)\n",
                label, (unsigned long)hp, (unsigned long)hk);
        goto done;
    }

    if (!strcmp(cmd,"csr") || !strcmp(cmd,"root")) {
        CK_OBJECT_HANDLE hpub  = find_one(s, CKO_PUBLIC_KEY,  label);
        CK_OBJECT_HANDLE hpriv = find_one(s, CKO_PRIVATE_KEY, label);

        static uint8_t pub[FHSM_COMPOSITE_PUB_MAX];
        CK_ATTRIBUTE g = { CKA_VALUE, pub, (CK_ULONG)sizeof pub };
        rv = p11.GetAttributeValue(s, hpub, &g, 1);
        if (rv != CKR_OK) die("C_GetAttributeValue(CKA_VALUE)", rv);

        struct signer sg = { s, hpriv };
        static uint8_t der[32768]; size_t n = sizeof der;
        fhsm_rv_t r;
        if (!strcmp(cmd,"csr"))
            r = fhsm_composite_csr(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                    subject, pub, (size_t)g.ulValueLen,
                                    p11_sign, &sg, der, &n);
        else
            r = fhsm_composite_selfsigned(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                           subject, serial, days,
                                           pub, (size_t)g.ulValueLen,
                                           p11_sign, &sg, der, &n);
        if (r != FHSM_RV_OK) die(!strcmp(cmd,"csr") ? "building the request"
                                                    : "building the certificate",
                                  (CK_RV)r);
        emit(der, n, out, pem,
             !strcmp(cmd,"csr") ? "CERTIFICATE REQUEST" : "CERTIFICATE");
        goto done;
    }

    usage();
done:
    p11.CloseSession(s);
    p11.Finalize(NULL);
    return 0;
}
