/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm-crypt --- keys that do not sign, and the objects on the token.
 *  Usage :
 *    fhsm-crypt list   [--class key|cert|all] [--module PATH] [--slot N]
 *    fhsm-crypt keygen --label NAME --alg aes128|aes256|hmac
 *    fhsm-crypt show   --label NAME [--class key|cert|all]
 *    fhsm-crypt encrypt --key LABEL --in FILE --out FILE.p7m
 *    fhsm-crypt decrypt --in FILE.p7m --out FILE
 *    fhsm-crypt delete --label NAME [--class key|cert|all] [--yes]
 *  Files are encrypted as CMS AuthEnvelopedData (RFC 5083), AES-256-GCM,
 *  for an AES key on the token, and `openssl cms -decrypt` reads them given
 *  that key. Encryption for a public key comes in the later stages of
 *  docs/fhsm-crypt-plan.md; signature keys stay with fhsm-csr, and each tool
 *  names the other when given the other's algorithm.
 *
 *  The PIN comes from the FHSM_PIN environment variable and from nowhere else,
 *  as for every tool here: an argument is visible in `ps` to every user.
 *
 *  delete names every object it is about to destroy and, without --yes, stops
 *  there. That is the command line's confirmation: a script has to say yes in
 *  writing, and a person who typed the wrong label sees it before anything is
 *  gone. Nothing on a token comes back once destroyed.
 *  The work is in tools/pkiops.c, which fhsm-gui calls too.
 * ========================================================================= */
#include "pkiops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *prog = "fhsm-crypt";

static void fail(const struct p11_err *e) {
    fprintf(stderr, "%s: %s", prog, e->msg);
    exit(e->code);
}

static void usage(void) {
    fprintf(stderr,
      "fhsm-crypt --- keys that do not sign, and the objects on the token\n\n"
      "  fhsm-crypt list   [--class key|cert|all] [--module PATH] [--slot N]\n"
      "  fhsm-crypt keygen --label NAME --alg ALG ...\n"
      "  fhsm-crypt show   --label NAME [--class key|cert|all] ...\n"
      "  fhsm-crypt encrypt --key LABEL --in FILE --out FILE.p7m ...\n"
      "  fhsm-crypt decrypt --in FILE.p7m --out FILE ...\n"
      "  fhsm-crypt delete --label NAME [--class key|cert|all] [--yes] ...\n\n"
      "  --alg ALG       keygen: aes128, aes256 (encrypt and wrap) or hmac (a\n"
      "                  32-byte secret for HMAC). Sensitive, not extractable.\n"
      "                  Signature keys are made by fhsm-csr keygen.\n"
      "  --class C       which objects: key (public, private and secret keys),\n"
      "                  cert, or all (the default)\n"
      "  --label NAME    show, delete: every object of the class carrying this label\n"
      "  --yes           delete: destroy them. Without it, delete lists what it\n"
      "                  would destroy and stops.\n"
      "  --key LABEL     encrypt: the AES key on the token. decrypt finds the key\n"
      "                  itself, from the file.\n"
      "  --in, --out     encrypt, decrypt: the file read and the file written.\n"
      "                  An existing --out is never written over, and a file\n"
      "                  that does not authenticate leaves nothing behind.\n"
      "  --module PATH   PKCS#11 module (default ./libfreehsm.so)\n"
      "  --slot N        slot to address. Default: the one slot holding a token.\n\n"
      "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n"
      "  is visible in ps to every user on the machine.\n\n"
      "  Exit: 0 done, 1 usage or a file this does not read, 2 the module or the\n"
      "  file system, 3 no such key, 4 the file does not open with the key.\n");
    exit(1);
}

/* A key pair's algorithm comes from pkiops_keys, a secret key's from the
 * object itself; a certificate has none to show. */
static const char *alg_of_object(const struct pkiops_object *o,
                                 const struct pkiops_key *k, size_t nk) {
    if (o->alg[0]) return o->alg;
    for (size_t i = 0; i < nk; i++)
        if (k[i].handle == o->handle && k[i].alg[0]) return k[i].alg;
    return "-";
}

static void print_object(const struct pkiops_object *o, const char *alg) {
    printf("  %-11s  %6lu  %-32s  %-11s  %s\n", pkiops_obj_class_name(o->cls),
           (unsigned long)o->handle, o->label[0] ? o->label : "(no label)",
           alg, o->id[0] ? o->id : "-");
}

int main(int argc, char **argv) {
    struct p11_err e;
    if (argc < 2) usage();
    const char *cmd = argv[1];
    const char *module = "./libfreehsm.so", *label = NULL, *cls_name = "all";
    const char *alg_name = NULL, *key = NULL, *in = NULL, *out = NULL;
    long slot = -1;
    int yes = 0;

    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module") && i+1<argc) module   = argv[++i];
        else if (!strcmp(argv[i],"--label")  && i+1<argc) label    = argv[++i];
        else if (!strcmp(argv[i],"--class")  && i+1<argc) cls_name = argv[++i];
        else if (!strcmp(argv[i],"--alg")    && i+1<argc) alg_name = argv[++i];
        else if (!strcmp(argv[i],"--key")    && i+1<argc) key      = argv[++i];
        else if (!strcmp(argv[i],"--in")     && i+1<argc) in       = argv[++i];
        else if (!strcmp(argv[i],"--out")    && i+1<argc) out      = argv[++i];
        else if (!strcmp(argv[i],"--slot")   && i+1<argc) {
            if (pkiops_parse_slot(argv[++i], &slot, &e)) fail(&e);
        }
        else if (!strcmp(argv[i],"--yes")) yes = 1;
        else if (!strcmp(argv[i],"--pin") || !strncmp(argv[i],"--pin=",6)) {
            fprintf(stderr, "fhsm-crypt: --pin is not accepted. Set FHSM_PIN instead:\n"
                            "  an argument is visible in ps to every user on this machine.\n");
            return 1;
        }
        else usage();
    }

    unsigned classes;
    if      (!strcmp(cls_name, "all"))  classes = PKIOPS_OBJS_ALL;
    else if (!strcmp(cls_name, "key"))  classes = PKIOPS_OBJS_KEYS;
    else if (!strcmp(cls_name, "cert")) classes = PKIOPS_OBJS_CERTS;
    else {
        fprintf(stderr, "fhsm-crypt: --class takes key, cert or all, not \"%s\"\n", cls_name);
        return 1;
    }

    int is_list = !strcmp(cmd, "list"), is_delete = !strcmp(cmd, "delete");
    int is_keygen = !strcmp(cmd, "keygen"), is_show = !strcmp(cmd, "show");
    int is_enc = !strcmp(cmd, "encrypt"), is_dec = !strcmp(cmd, "decrypt");
    if (!is_list && !is_delete && !is_keygen && !is_show && !is_enc && !is_dec) usage();
    if ((is_enc || is_dec) && (!in || !out || label || yes)) usage();
    if (is_enc && !key) usage();
    if (!is_enc && key) usage();
    if (!is_enc && !is_dec && (in || out)) usage();
    if ((is_delete || is_keygen || is_show) && !label) usage();
    if (is_show && yes) usage();
    if (is_list && (label || yes)) usage();
    if (alg_name && !is_keygen) {
        fprintf(stderr, "fhsm-crypt: --alg belongs to keygen.\n"); return 1;
    }
    enum pkiops_skey skey = PKIOPS_SKEY_AES256;
    if (is_keygen) {
        if (!alg_name) {
            fprintf(stderr, "fhsm-crypt: keygen needs --alg: %s\n", pkiops_skey_list());
            return 1;
        }
        if (pkiops_skey_parse(alg_name, &skey, &e)) fail(&e);
    }

    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) {
        fprintf(stderr, "fhsm-crypt: FHSM_PIN is not set.\n"); return 1;
    }

    pkiops_handle sid = 0, s = 0;
    if (pkiops_open(module, slot, PKIOPS_SLOT_WITH_TOKEN, &sid, &e)) fail(&e);
    if (pkiops_session_user(sid, (const uint8_t *)pin, strlen(pin), &s, &e)) fail(&e);

    if (is_enc || is_dec) {
        char used[65] = "";
        int rc = is_enc ? pkiops_encrypt_file(s, key, in, out, &e)
                        : pkiops_decrypt_file(s, in, out, used, sizeof used, &e);
        if (rc) fprintf(stderr, "%s: %s", prog, e.msg);
        else if (is_enc) fprintf(stderr, "fhsm-crypt: %s encrypted for \"%s\" into %s\n", in, key, out);
        else             fprintf(stderr, "fhsm-crypt: %s decrypted with \"%s\" into %s\n", in, used, out);
        pkiops_session_close(s);
        pkiops_close();
        return rc;
    }

    if (is_keygen) {
        /* One label, one key: a second key under a label already in use is
         * the ambiguity every other operation then refuses to resolve. */
        struct pkiops_object *v = NULL; size_t n = 0;
        if (pkiops_objects(s, PKIOPS_OBJS_KEYS, &v, &n, &e)) fail(&e);
        for (size_t i = 0; i < n; i++)
            if (!strcmp(v[i].label, label)) {
                fprintf(stderr, "fhsm-crypt: a key labelled \"%s\" is already on the token\n", label);
                free(v);
                return 3;
            }
        free(v);
        pkiops_handle h = 0;
        if (pkiops_keygen_secret(s, label, skey, &h, &e)) fail(&e);
        fprintf(stderr, "fhsm-crypt: %s key \"%s\" created (object %lu)\n",
                pkiops_skey_name(skey), label, (unsigned long)h);
        pkiops_session_close(s);
        pkiops_close();
        return 0;
    }

    struct pkiops_object *v = NULL; size_t n = 0;
    if (pkiops_objects(s, classes, &v, &n, &e)) fail(&e);
    struct pkiops_key *k = NULL; size_t nk = 0;
    if (pkiops_keys(s, &k, &nk, &e)) fail(&e);

    int rc = 0;
    if (is_show) {
        size_t shown = 0;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(v[i].label, label) != 0) continue;
            struct pkiops_attr *a = NULL; size_t na = 0;
            if (pkiops_object_attrs(s, v[i].handle, &a, &na, &e)) {
                fprintf(stderr, "%s: %s", prog, e.msg);
                rc = e.code;
                continue;
            }
            printf("%s%s %lu\n", shown ? "\n" : "", pkiops_obj_class_name(v[i].cls),
                   (unsigned long)v[i].handle);
            for (size_t q = 0; q < na; q++) printf("  %-24s %s\n", a[q].name, a[q].value);
            free(a);
            shown++;
        }
        if (shown == 0 && rc == 0) {
            fprintf(stderr, "fhsm-crypt: nothing labelled \"%s\"\n", label);
            rc = 3;
        }
    } else if (is_list) {
        printf("  %-11s  %6s  %-32s  %-11s  %s\n", "class", "handle", "label", "algorithm", "CKA_ID");
        for (size_t i = 0; i < n; i++) print_object(&v[i], alg_of_object(&v[i], k, nk));
        printf("%zu object%s\n", n, n == 1 ? "" : "s");
    } else {
        size_t match = 0;
        for (size_t i = 0; i < n; i++)
            if (!strcmp(v[i].label, label)) match++;
        if (match == 0) {
            fprintf(stderr, "fhsm-crypt: no %s labelled \"%s\"\n",
                    classes == PKIOPS_OBJS_CERTS ? "certificate"
                    : classes == PKIOPS_OBJS_KEYS ? "key" : "object", label);
            rc = 3;
        } else if (!yes) {
            printf("would destroy %zu object%s labelled \"%s\":\n",
                   match, match == 1 ? "" : "s", label);
            for (size_t i = 0; i < n; i++)
                if (!strcmp(v[i].label, label)) print_object(&v[i], alg_of_object(&v[i], k, nk));
            fprintf(stderr, "fhsm-crypt: nothing destroyed. Add --yes to destroy %s;"
                            " it cannot be undone.\n", match == 1 ? "it" : "them");
            rc = 1;
        } else {
            for (size_t i = 0; i < n; i++) {
                if (strcmp(v[i].label, label) != 0) continue;
                if (pkiops_destroy(s, v[i].handle, &e)) {
                    /* Stop at the first refusal: what follows was named
                     * together with it, and a partial deletion is reported
                     * as one, not carried on past. */
                    fprintf(stderr, "%s: %s", prog, e.msg);
                    rc = e.code;
                    break;
                }
                fprintf(stderr, "fhsm-crypt: destroyed %s %lu \"%s\"\n",
                        pkiops_obj_class_name(v[i].cls), (unsigned long)v[i].handle, label);
            }
        }
    }
    free(v);
    free(k);
    pkiops_session_close(s);
    pkiops_close();
    return rc;
}
