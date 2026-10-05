/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm-csr --- certification requests and self-signed roots, with a composite
 *              post-quantum key held in a PKCS#11 module (#112).
 *  Usage :
 *    fhsm-csr keygen --label NAME [--alg ALG] [--module PATH] [--slot N]
 *    fhsm-csr csr    --label NAME --subject DN [--out FILE] [--pem]
 *    fhsm-csr root   --label NAME --subject DN [--days N] [--serial N] ...
 *  The PIN comes from the FHSM_PIN environment variable and from nowhere else.
 *  There is deliberately no --pin option: an argument is visible in `ps` to
 *  every user on the machine, and a tool that offers the convenient insecure
 *  option is a tool whose users take it.
 *  The module is loaded at runtime and driven only through the PKCS#11
 *  interface, so this works against any PKCS#11 module that implements the
 *  composite mechanism -- not only against FreeHSM. That is the point: a
 *  university that already owns a hardware HSM should be able to use these
 *  tools with it. The composite DER encoding travels with the tool
 *  (src/fhsm_composite.o links standalone against libcrypto), the key stays
 *  wherever the module keeps it, and the private half is never seen here.
 *  The work is in tools/pkiops.c, which the planned graphical interface calls
 *  too (docs/fhsm-gui-plan.md). What stays here is the command line.
 * ========================================================================= */
#include "pkiops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>

static const char *prog = "fhsm-csr";

static void fail(const struct p11_err *e) {
    fprintf(stderr, "%s: %s", prog, e->msg);
    exit(e->code);
}

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
      "fhsm-csr --- certification requests and roots, with a key held in a PKCS#11 module\n\n"
      "  fhsm-csr keygen --label NAME [--alg ALG] [--module PATH] [--slot N]\n"
      "  fhsm-csr csr    --label NAME --subject DN [--out FILE] [--pem] ...\n"
      "  fhsm-csr root   --label NAME --subject DN [--days N] [--serial N] ...\n\n"
      "  --alg ALG       keygen only: composite (the default), ecdsa-p256,\n"
      "                  ecdsa-p384, rsa-pss, rsa-pkcs1, ed25519, ml-dsa-44,\n"
      "                  ml-dsa-65, ml-dsa-87. csr and root take no algorithm:\n"
      "                  they sign with the key's own.\n"
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
    struct p11_err e;
    if (argc < 2) usage();
    const char *cmd = argv[1];
    const char *module = "./libfreehsm.so", *label = NULL, *subject = NULL;
    const char *out = NULL, *alg_name = NULL;
    int pem = 0, days = 3650; long serial = 1, slot = -1;

    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module")  && i+1<argc) module  = argv[++i];
        else if (!strcmp(argv[i],"--label")   && i+1<argc) label   = argv[++i];
        else if (!strcmp(argv[i],"--subject") && i+1<argc) subject = argv[++i];
        else if (!strcmp(argv[i],"--alg")     && i+1<argc) alg_name = argv[++i];
        else if (!strcmp(argv[i],"--out")     && i+1<argc) out     = argv[++i];
        else if (!strcmp(argv[i],"--slot")    && i+1<argc) {
            if (pkiops_parse_slot(argv[++i], &slot, &e)) fail(&e);
        }
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

    /* The algorithm is chosen once, with the key, and read off it afterwards:
     * an --alg on csr or root could only agree with the key or contradict it. */
    enum pkiops_alg alg = PKIOPS_ALG_COMPOSITE;
    if (alg_name) {
        if (strcmp(cmd, "keygen") != 0) {
            fprintf(stderr, "fhsm-csr: --alg belongs to keygen. %s signs with the key's own\n"
                            "  algorithm, chosen when the key was generated.\n", cmd);
            return 1;
        }
        if (pkiops_alg_parse(alg_name, &alg, &e)) fail(&e);
    }

    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) {
        fprintf(stderr, "fhsm-csr: FHSM_PIN is not set.\n"); return 1;
    }

    pkiops_handle sid = 0, s = 0;
    if (pkiops_open(module, slot, PKIOPS_SLOT_WITH_TOKEN, &sid, &e)) fail(&e);
    if (pkiops_session_user(sid, (const uint8_t *)pin, strlen(pin), &s, &e)) fail(&e);

    if (!strcmp(cmd, "keygen")) {
        pkiops_handle hp = 0, hk = 0;
        if (pkiops_keygen_alg(s, label, alg, &hp, &hk, &e)) fail(&e);
        fprintf(stderr, "fhsm-csr: %s key pair \"%s\" created "
                        "(public %lu, private %lu)\n",
                pkiops_alg_name(alg), label, (unsigned long)hp, (unsigned long)hk);
        goto done;
    }

    if (!strcmp(cmd,"csr") || !strcmp(cmd,"root")) {
        static uint8_t der[32768]; size_t n = sizeof der;
        if (!strcmp(cmd,"csr")) {
            if (pkiops_csr(s, label, subject, der, &n, &e)) fail(&e);
        } else {
            if (pkiops_root(s, label, subject, serial, days, der, &n, &e)) fail(&e);
        }
        emit(der, n, out, pem,
             !strcmp(cmd,"csr") ? "CERTIFICATE REQUEST" : "CERTIFICATE");
        goto done;
    }

    usage();
done:
    pkiops_session_close(s);
    pkiops_close();
    return 0;
}
