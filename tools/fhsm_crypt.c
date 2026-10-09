/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm-crypt --- keys that do not sign, and the objects on the token.
 *  Usage :
 *    fhsm-crypt list   [--class key|cert|all] [--module PATH] [--slot N]
 *    fhsm-crypt delete --label NAME [--class key|cert|all] [--yes]
 *  Key generation for encryption, and file encryption, come in the later
 *  stages of docs/fhsm-crypt-plan.md; signature keys stay with fhsm-csr.
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
      "  fhsm-crypt delete --label NAME [--class key|cert|all] [--yes] ...\n\n"
      "  --class C       which objects: key (public, private and secret keys),\n"
      "                  cert, or all (the default)\n"
      "  --label NAME    delete: every object of the class carrying this label\n"
      "  --yes           delete: destroy them. Without it, delete lists what it\n"
      "                  would destroy and stops.\n"
      "  --module PATH   PKCS#11 module (default ./libfreehsm.so)\n"
      "  --slot N        slot to address. Default: the one slot holding a token.\n\n"
      "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n"
      "  is visible in ps to every user on the machine.\n");
    exit(1);
}

static void print_object(const struct pkiops_object *o) {
    printf("  %-11s  %6lu  %-32s  %s\n", pkiops_obj_class_name(o->cls),
           (unsigned long)o->handle, o->label[0] ? o->label : "(no label)",
           o->id[0] ? o->id : "-");
}

int main(int argc, char **argv) {
    struct p11_err e;
    if (argc < 2) usage();
    const char *cmd = argv[1];
    const char *module = "./libfreehsm.so", *label = NULL, *cls_name = "all";
    long slot = -1;
    int yes = 0;

    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module") && i+1<argc) module   = argv[++i];
        else if (!strcmp(argv[i],"--label")  && i+1<argc) label    = argv[++i];
        else if (!strcmp(argv[i],"--class")  && i+1<argc) cls_name = argv[++i];
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
    if (!is_list && !is_delete) usage();
    if (is_delete && !label) usage();
    if (is_list && (label || yes)) usage();

    const char *pin = getenv("FHSM_PIN");
    if (!pin || !*pin) {
        fprintf(stderr, "fhsm-crypt: FHSM_PIN is not set.\n"); return 1;
    }

    pkiops_handle sid = 0, s = 0;
    if (pkiops_open(module, slot, PKIOPS_SLOT_WITH_TOKEN, &sid, &e)) fail(&e);
    if (pkiops_session_user(sid, (const uint8_t *)pin, strlen(pin), &s, &e)) fail(&e);

    struct pkiops_object *v = NULL; size_t n = 0;
    if (pkiops_objects(s, classes, &v, &n, &e)) fail(&e);

    int rc = 0;
    if (is_list) {
        printf("  %-11s  %6s  %-32s  %s\n", "class", "handle", "label", "CKA_ID");
        for (size_t i = 0; i < n; i++) print_object(&v[i]);
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
                if (!strcmp(v[i].label, label)) print_object(&v[i]);
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
    pkiops_session_close(s);
    pkiops_close();
    return rc;
}
