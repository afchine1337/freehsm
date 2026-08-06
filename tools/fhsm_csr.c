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
#include "fhsm_composite.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK      0UL
#define CKF_RW      6UL
#define CKU_USER    1UL
#define CKA_CLASS   0x00000000UL
#define CKA_TOKEN   0x00000001UL
#define CKA_LABEL   0x00000003UL
#define CKA_VALUE   0x00000011UL
#define CKO_PUBLIC_KEY  2UL
#define CKO_PRIVATE_KEY 3UL
#define CKM_COMPOSITE_MLDSA65_ED25519 0x80004202UL

static struct {
    void *h;
    CK_RV (*Initialize)(void*);
    CK_RV (*Finalize)(void*);
    CK_RV (*OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                              CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
    CK_RV (*FindObjectsInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
    CK_RV (*FindObjects)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
    CK_RV (*FindObjectsFinal)(CK_SESSION_HANDLE);
    CK_RV (*GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
    CK_RV (*SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
} p11;

static void die(const char *what, CK_RV rv) {
    if (rv) fprintf(stderr, "fhsm-csr: %s failed (0x%lx)\n", what, (unsigned long)rv);
    else    fprintf(stderr, "fhsm-csr: %s\n", what);
    exit(2);
}

static void load_module(const char *path) {
    p11.h = dlopen(path, RTLD_NOW);
    if (!p11.h) { fprintf(stderr, "fhsm-csr: cannot load %s: %s\n", path, dlerror()); exit(2); }
    #define S(f,n) do { *(void**)&p11.f = dlsym(p11.h, n); \
        if (!p11.f) { fprintf(stderr,"fhsm-csr: %s missing from module\n", n); exit(2); } } while (0)
    S(Initialize,"C_Initialize"); S(Finalize,"C_Finalize");
    S(OpenSession,"C_OpenSession"); S(CloseSession,"C_CloseSession");
    S(Login,"C_Login"); S(GenerateKeyPair,"C_GenerateKeyPair");
    S(FindObjectsInit,"C_FindObjectsInit"); S(FindObjects,"C_FindObjects");
    S(FindObjectsFinal,"C_FindObjectsFinal");
    S(GetAttributeValue,"C_GetAttributeValue");
    S(SignInit,"C_SignInit"); S(Sign,"C_Sign");
    #undef S
}

/* Find exactly one object of a class carrying a label. "Exactly": two objects
 * with the same label is an ambiguity the operator has to resolve, and picking
 * the first would silently sign with a key they did not mean. */
static CK_OBJECT_HANDLE find_one(CK_SESSION_HANDLE s, CK_ULONG cls, const char *label) {
    CK_ULONG c = cls;
    CK_ATTRIBUTE t[] = { {CKA_CLASS,&c,sizeof c},
                          {CKA_LABEL,(void*)label,(CK_ULONG)strlen(label)} };
    if (p11.FindObjectsInit(s, t, 2) != CKR_OK) die("C_FindObjectsInit", 0);
    CK_OBJECT_HANDLE h[4]; CK_ULONG n = 0;
    CK_RV rv = p11.FindObjects(s, h, 4, &n);
    p11.FindObjectsFinal(s);
    if (rv != CKR_OK) die("C_FindObjects", rv);
    if (n == 0) { fprintf(stderr, "fhsm-csr: no %s key labelled \"%s\"\n",
                          cls == CKO_PUBLIC_KEY ? "public" : "private", label); exit(3); }
    if (n > 1)  { fprintf(stderr, "fhsm-csr: %lu keys labelled \"%s\" -- ambiguous, "
                          "refusing to guess\n", (unsigned long)n, label); exit(3); }
    return h[0];
}

/* The signing callback. This is the whole point of the seam: the CSR and
 * certificate builders never hold a key, they ask for a signature. */
struct signer { CK_SESSION_HANDLE s; CK_OBJECT_HANDLE priv; };

static fhsm_rv_t p11_sign(void *vctx, const uint8_t *tbs, size_t tbs_len,
                           uint8_t *sig, size_t *sig_len) {
    struct signer *g = vctx;
    CK_MECHANISM m = { CKM_COMPOSITE_MLDSA65_ED25519, NULL, 0 };
    CK_RV rv = p11.SignInit(g->s, &m, g->priv);
    if (rv != CKR_OK) return (fhsm_rv_t)rv;
    CK_ULONG n = (CK_ULONG)*sig_len;
    rv = p11.Sign(g->s, (CK_BYTE*)(uintptr_t)tbs, (CK_ULONG)tbs_len, sig, &n);
    if (rv != CKR_OK) return (fhsm_rv_t)rv;
    *sig_len = (size_t)n;
    return FHSM_RV_OK;
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
      "fhsm-csr --- composite PQ certification requests and roots via PKCS#11\n\n"
      "  fhsm-csr keygen --label NAME [--module PATH] [--slot N]\n"
      "  fhsm-csr csr    --label NAME --subject DN [--out FILE] [--pem] ...\n"
      "  fhsm-csr root   --label NAME --subject DN [--days N] [--serial N] ...\n\n"
      "  --module PATH   PKCS#11 module (default ./libfreehsm-fips.so)\n"
      "  --slot N        slot index (default 0)\n"
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
    if (argc < 2) usage();
    const char *cmd = argv[1];
    const char *module = "./libfreehsm-fips.so", *label = NULL, *subject = NULL;
    const char *out = NULL;
    int pem = 0, slot = 0, days = 3650; long serial = 1;

    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module")  && i+1<argc) module  = argv[++i];
        else if (!strcmp(argv[i],"--label")   && i+1<argc) label   = argv[++i];
        else if (!strcmp(argv[i],"--subject") && i+1<argc) subject = argv[++i];
        else if (!strcmp(argv[i],"--out")     && i+1<argc) out     = argv[++i];
        else if (!strcmp(argv[i],"--slot")    && i+1<argc) slot    = atoi(argv[++i]);
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
    rv = p11.OpenSession((CK_SLOT_ID)slot, CKF_RW, NULL, NULL, &s);
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
