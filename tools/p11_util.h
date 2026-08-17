/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tools/p11_util.h --- the PKCS#11 plumbing shared by fhsm-csr and fhsm-ca.
 *
 *  Header-only, and shared rather than copied. Two tools that load a module,
 *  find a key by label and sign through C_Sign should do it the same way; a
 *  second copy is a second place for the "exactly one key" rule to be relaxed
 *  or the PIN policy to be softened, and only one of them would get fixed.
 *
 *  The module is loaded at runtime and driven only through standard PKCS#11
 *  calls, so both tools work against any module implementing the mechanism.
 * ========================================================================= */
#ifndef FHSM_TOOLS_P11_UTIL_H
#define FHSM_TOOLS_P11_UTIL_H

#include "fhsm_composite.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Each tool uses a subset of what this header offers -- fhsm-sign never needs
 * the signing callback, fhsm-csr never needs the multipart entry points. With
 * -Werror that makes "defined but not used" a build failure for whichever tool
 * happens to use least. Marking the shared helpers is the honest fix; the
 * alternative is splitting the header per consumer, which is how two copies of
 * the "exactly one key" rule would appear. */
#if defined(__GNUC__) || defined(__clang__)
#  define P11_MAYBE_UNUSED __attribute__((unused))
#else
#  define P11_MAYBE_UNUSED
#endif

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK      0UL
#define CKR_SIGNATURE_INVALID 0x000000C0UL
#define CKF_RW      6UL
#define CKU_SO      0UL
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
    /* Multipart, for streaming a file too large to hold (#123). */
    CK_RV (*SignUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*SignFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
    CK_RV (*VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*VerifyUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*VerifyFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    /* Provisioning (fhsm-token). */
    CK_RV (*InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*GetTokenInfo)(CK_SLOT_ID,void*);
    CK_RV (*GenerateRandom)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
} p11;

/* Set by each tool before anything can fail. Extracting this header from
 * fhsm-csr left the name hard-coded, so fhsm-ca reported its errors as
 * "fhsm-csr:" -- a tool announcing itself under another tool's name sends the
 * operator to the wrong manual page. */
static const char *p11_progname = "fhsm";

P11_MAYBE_UNUSED static void die(const char *what, CK_RV rv) {
    if (rv) fprintf(stderr, "%s: %s failed (0x%lx)\n", p11_progname, what, (unsigned long)rv);
    else    fprintf(stderr, "%s: %s\n", p11_progname, what);
    exit(2);
}

P11_MAYBE_UNUSED static void load_module(const char *path) {
    p11.h = dlopen(path, RTLD_NOW);
    if (!p11.h) { fprintf(stderr, "%s: cannot load %s: %s\n", p11_progname, path, dlerror()); exit(2); }
    #define S(f,n) do { *(void**)&p11.f = dlsym(p11.h, n); \
        if (!p11.f) { fprintf(stderr,"%s: %s missing from module\n", p11_progname, n); exit(2); } } while (0)
    S(Initialize,"C_Initialize"); S(Finalize,"C_Finalize");
    S(OpenSession,"C_OpenSession"); S(CloseSession,"C_CloseSession");
    S(Login,"C_Login"); S(GenerateKeyPair,"C_GenerateKeyPair");
    S(FindObjectsInit,"C_FindObjectsInit"); S(FindObjects,"C_FindObjects");
    S(FindObjectsFinal,"C_FindObjectsFinal");
    S(GetAttributeValue,"C_GetAttributeValue");
    S(SignInit,"C_SignInit"); S(Sign,"C_Sign");
    S(SignUpdate,"C_SignUpdate"); S(SignFinal,"C_SignFinal");
    S(VerifyInit,"C_VerifyInit");
    S(VerifyUpdate,"C_VerifyUpdate"); S(VerifyFinal,"C_VerifyFinal");
    S(InitToken,"C_InitToken"); S(InitPIN,"C_InitPIN");
    S(GetTokenInfo,"C_GetTokenInfo");
    S(GenerateRandom,"C_GenerateRandom");
    #undef S
}

/* Find exactly one object of a class carrying a label. "Exactly": two objects
 * with the same label is an ambiguity the operator has to resolve, and picking
 * the first would silently sign with a key they did not mean. */
P11_MAYBE_UNUSED static CK_OBJECT_HANDLE find_one(CK_SESSION_HANDLE s, CK_ULONG cls, const char *label) {
    CK_ULONG c = cls;
    CK_ATTRIBUTE t[] = { {CKA_CLASS,&c,sizeof c},
                          {CKA_LABEL,(void*)label,(CK_ULONG)strlen(label)} };
    if (p11.FindObjectsInit(s, t, 2) != CKR_OK) die("C_FindObjectsInit", 0);
    CK_OBJECT_HANDLE h[4]; CK_ULONG n = 0;
    CK_RV rv = p11.FindObjects(s, h, 4, &n);
    p11.FindObjectsFinal(s);
    if (rv != CKR_OK) die("C_FindObjects", rv);
    if (n == 0) { fprintf(stderr, "%s: no %s key labelled \"%s\"\n", p11_progname,
                          cls == CKO_PUBLIC_KEY ? "public" : "private", label); exit(3); }
    if (n > 1)  { fprintf(stderr, "%s: %lu keys labelled \"%s\" -- ambiguous, "
                          "refusing to guess\n", p11_progname, (unsigned long)n, label); exit(3); }
    return h[0];
}

/* The signing callback. This is the whole point of the seam: the CSR and
 * certificate builders never hold a key, they ask for a signature. */
struct signer { CK_SESSION_HANDLE s; CK_OBJECT_HANDLE priv; };

P11_MAYBE_UNUSED static fhsm_rv_t p11_sign(void *vctx, const uint8_t *tbs, size_t tbs_len,
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


/* Randomness for the certificate builders, taken from the module rather than
 * from this process. C_GenerateRandom is the token's own DRBG -- the one with
 * the SP 800-90B health tests and the latching failure -- reached over the
 * standard API. A tool that generated serials itself would be using a second
 * generator that the module never inspected and the audit path never saw. */
P11_MAYBE_UNUSED
static fhsm_rv_t p11_rng(void *vctx, uint8_t *out, size_t n) {
    CK_SESSION_HANDLE *s = vctx;
    if (!s || !out) return FHSM_RV_ARGUMENTS_BAD;
    CK_RV rv = p11.GenerateRandom(*s, out, (CK_ULONG)n);
    return (rv == CKR_OK) ? FHSM_RV_OK : (fhsm_rv_t)rv;
}

#endif /* FHSM_TOOLS_P11_UTIL_H */
