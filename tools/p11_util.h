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
#include <errno.h>
#include <stdarg.h>
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
    CK_RV (*DigestInit)(CK_SESSION_HANDLE,CK_MECHANISM*);
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
    CK_RV (*GetSlotList)(unsigned char,CK_SLOT_ID*,CK_ULONG*);
    CK_RV (*GetMechanismList)(CK_SLOT_ID,CK_ULONG*,CK_ULONG*);
    CK_RV (*GetMechanismInfo)(CK_SLOT_ID,CK_ULONG,void*);
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

/* ---------------------------------------------------------------------------
 * Errors that are returned rather than ending the process.
 *
 * Every helper below used to print and exit, which is right for a command and
 * wrong for anything that must survive a refused PIN or a missing key -- the
 * planned graphical interface first of all (docs/fhsm-gui-plan.md, stage 0).
 * So each has a `_e` form that fills a p11_err and returns its code, and the
 * old name is now a thin wrapper that prints "<tool>: <msg>" and exits with
 * that code. The tools' messages and exit codes are unchanged, byte for byte;
 * tests/pki_tools_characterize.sh is how that is checked.
 *
 * `code` is the exit status a tool would use: 2 for the module or a PKCS#11
 * call, 3 for a slot or a key that is missing or ambiguous. `msg` holds the
 * whole message without the tool's name, final newline included, and may run
 * over several lines -- a slot list, for instance.
 * ------------------------------------------------------------------------- */
struct p11_err { int code; char msg[4096]; };

#if defined(__GNUC__) || defined(__clang__)
#  define P11_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#  define P11_PRINTF(a, b)
#endif

P11_MAYBE_UNUSED P11_PRINTF(3, 4)
static int p11_fail(struct p11_err *e, int code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->msg, sizeof e->msg, fmt, ap);
    va_end(ap);
    e->code = code;
    return code;
}

P11_MAYBE_UNUSED P11_PRINTF(2, 3)
static void p11_append(struct p11_err *e, const char *fmt, ...) {
    size_t n = strlen(e->msg);
    if (n >= sizeof e->msg - 1) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->msg + n, sizeof e->msg - n, fmt, ap);
    va_end(ap);
}

/* What the old helpers did on failure, in one place. */
P11_MAYBE_UNUSED static void p11_exit_on(const struct p11_err *e) {
    fprintf(stderr, "%s: %s", p11_progname, e->msg);
    exit(e->code);
}

/* ---------------------------------------------------------------------------
 * How a PKCS#11 module is actually loaded.
 *
 * This used to dlsym every C_* symbol by name and exit if one was missing.
 * That works against our own module, which exports 62 of them, and against
 * nothing else: the standard requires exactly ONE exported symbol,
 * `C_GetFunctionList`, and most modules export only that. p11-kit-client.so
 * exports one. So `fhsm-csr --module .../p11-kit-client.so` answered
 * "C_Initialize missing from module" -- while the Makefile claimed the tool
 * "drives any module implementing the mechanism, not only this one".
 *
 * The table's field order is fixed by PKCS#11 v2.40 §C.6, and getting an index
 * wrong calls the wrong function silently. This project has already been bitten
 * once (#61, C_CancelFunction missing, shifting everything after it). So the
 * indices below are not recounted here: they are the ones assigned in
 * src/fhsm_pkcs11.c, which were verified against OpenSC's pkcs11f.h, and
 * tests/test_p11_loader.c asserts that both agree, pointer by pointer, on
 * every build. A second copy of an ordering is safe only while something
 * compares them.
 * ------------------------------------------------------------------------- */
enum {                          /* PKCS#11 v2.40 §C.6 slot numbers */
    P11_SLOT_Initialize        = 0,
    P11_SLOT_Finalize          = 1,
    P11_SLOT_GetSlotList       = 4,
    P11_SLOT_GetMechanismList  = 7,
    P11_SLOT_GetMechanismInfo  = 8,
    P11_SLOT_InitToken         = 9,
    P11_SLOT_InitPIN           = 10,
    P11_SLOT_OpenSession       = 12,
    P11_SLOT_CloseSession      = 13,
    P11_SLOT_GetTokenInfo      = 6,
    P11_SLOT_Login             = 18,
    P11_SLOT_GetAttributeValue = 24,
    P11_SLOT_FindObjectsInit   = 26,
    P11_SLOT_FindObjects       = 27,
    P11_SLOT_FindObjectsFinal  = 28,
    P11_SLOT_DigestInit        = 37,
    P11_SLOT_SignInit          = 42,
    P11_SLOT_Sign              = 43,
    P11_SLOT_SignUpdate        = 44,
    P11_SLOT_SignFinal         = 45,
    P11_SLOT_VerifyInit        = 48,
    P11_SLOT_Verify            = 49,
    P11_SLOT_VerifyUpdate      = 50,
    P11_SLOT_VerifyFinal       = 51,
    P11_SLOT_GenerateKeyPair   = 59,
    P11_SLOT_GenerateRandom    = 64,
    P11_SLOT_COUNT             = 68      /* C_Initialize .. C_WaitForSlotEvent */
};

struct p11_function_list {
    unsigned char major, minor;
    void *pfn[P11_SLOT_COUNT];
};

P11_MAYBE_UNUSED static int p11_load_module_e(const char *path, struct p11_err *e) {
    p11.h = dlopen(path, RTLD_NOW);
    if (!p11.h) return p11_fail(e, 2, "cannot load %s: %s\n", path, dlerror());

    /* The conforming path first. */
    CK_RV (*getlist)(struct p11_function_list **) = NULL;
    *(void**)&getlist = dlsym(p11.h, "C_GetFunctionList");
    if (getlist) {
        struct p11_function_list *fl = NULL;
        CK_RV rv = getlist(&fl);
        if (rv != 0 || !fl)
            return p11_fail(e, 2, "C_GetFunctionList failed (0x%lx)\n", (unsigned long)rv);
        #define T(f,slot) do { \
            p11.f = (void*)0; \
            *(void**)&p11.f = fl->pfn[slot]; \
            if (!p11.f) return p11_fail(e, 2, "the module leaves C_%s unimplemented\n", #f); \
            } while (0)
        T(Initialize, P11_SLOT_Initialize);   T(Finalize, P11_SLOT_Finalize);
        T(OpenSession, P11_SLOT_OpenSession); T(CloseSession, P11_SLOT_CloseSession);
        T(Login, P11_SLOT_Login);             T(GenerateKeyPair, P11_SLOT_GenerateKeyPair);
        T(FindObjectsInit, P11_SLOT_FindObjectsInit);
        T(FindObjects, P11_SLOT_FindObjects);
        T(FindObjectsFinal, P11_SLOT_FindObjectsFinal);
        T(GetAttributeValue, P11_SLOT_GetAttributeValue);
        T(DigestInit, P11_SLOT_DigestInit);
        T(SignInit, P11_SLOT_SignInit);       T(Sign, P11_SLOT_Sign);
        T(SignUpdate, P11_SLOT_SignUpdate);   T(SignFinal, P11_SLOT_SignFinal);
        T(VerifyInit, P11_SLOT_VerifyInit);
        T(VerifyUpdate, P11_SLOT_VerifyUpdate);
        T(VerifyFinal, P11_SLOT_VerifyFinal);
        T(InitToken, P11_SLOT_InitToken);     T(InitPIN, P11_SLOT_InitPIN);
        T(GetTokenInfo, P11_SLOT_GetTokenInfo);
        T(GenerateRandom, P11_SLOT_GenerateRandom);
        T(GetSlotList, P11_SLOT_GetSlotList);
        T(GetMechanismList, P11_SLOT_GetMechanismList);
        T(GetMechanismInfo, P11_SLOT_GetMechanismInfo);
        #undef T
        return 0;
    }

    /* No C_GetFunctionList. Not conforming, but some modules and test doubles
     * export the functions directly, and refusing them buys nothing. */
    #define S(f,n) do { *(void**)&p11.f = dlsym(p11.h, n); \
        if (!p11.f) return p11_fail(e, 2, \
            "the module exports neither C_GetFunctionList nor %s\n", n); } while (0)
    S(Initialize,"C_Initialize"); S(Finalize,"C_Finalize");
    S(OpenSession,"C_OpenSession"); S(CloseSession,"C_CloseSession");
    S(Login,"C_Login"); S(GenerateKeyPair,"C_GenerateKeyPair");
    S(FindObjectsInit,"C_FindObjectsInit"); S(FindObjects,"C_FindObjects");
    S(FindObjectsFinal,"C_FindObjectsFinal");
    S(GetAttributeValue,"C_GetAttributeValue");
    S(DigestInit,"C_DigestInit");
    S(SignInit,"C_SignInit"); S(Sign,"C_Sign");
    S(SignUpdate,"C_SignUpdate"); S(SignFinal,"C_SignFinal");
    S(VerifyInit,"C_VerifyInit");
    S(VerifyUpdate,"C_VerifyUpdate"); S(VerifyFinal,"C_VerifyFinal");
    S(InitToken,"C_InitToken"); S(InitPIN,"C_InitPIN");
    S(GetTokenInfo,"C_GetTokenInfo");
    S(GenerateRandom,"C_GenerateRandom");
    S(GetSlotList,"C_GetSlotList");
    #undef S
    return 0;
}

P11_MAYBE_UNUSED static void load_module(const char *path) {
    struct p11_err e;
    if (p11_load_module_e(path, &e)) p11_exit_on(&e);
}

/* Find exactly one object of a class carrying a label. "Exactly": two objects
 * with the same label is an ambiguity the operator has to resolve, and picking
 * the first would silently sign with a key they did not mean. */
P11_MAYBE_UNUSED static int p11_find_one_e(CK_SESSION_HANDLE s, CK_ULONG cls, const char *label,
                                          CK_OBJECT_HANDLE *out, struct p11_err *e) {
    CK_ULONG c = cls;
    CK_ATTRIBUTE t[] = { {CKA_CLASS,&c,sizeof c},
                          {CKA_LABEL,(void*)label,(CK_ULONG)strlen(label)} };
    if (p11.FindObjectsInit(s, t, 2) != CKR_OK) return p11_fail(e, 2, "C_FindObjectsInit\n");
    CK_OBJECT_HANDLE h[4]; CK_ULONG n = 0;
    CK_RV rv = p11.FindObjects(s, h, 4, &n);
    p11.FindObjectsFinal(s);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_FindObjects failed (0x%lx)\n", (unsigned long)rv);
    if (n == 0) return p11_fail(e, 3, "no %s key labelled \"%s\"\n",
                                cls == CKO_PUBLIC_KEY ? "public" : "private", label);
    if (n > 1)  return p11_fail(e, 3, "%lu keys labelled \"%s\" -- ambiguous, "
                                "refusing to guess\n", (unsigned long)n, label);
    *out = h[0];
    return 0;
}

P11_MAYBE_UNUSED static CK_OBJECT_HANDLE find_one(CK_SESSION_HANDLE s, CK_ULONG cls, const char *label) {
    struct p11_err e;
    CK_OBJECT_HANDLE h = 0;
    if (p11_find_one_e(s, cls, label, &h, &e)) p11_exit_on(&e);
    return h;
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

/* ---------------------------------------------------------------------------
 * Which slot holds the token.
 *
 * `--slot` used to default to 0 and go straight to C_OpenSession. That is
 * right for our own module, whose slots are 0..FHSM_MAX_SLOTS-1, and wrong
 * everywhere else: a CK_SLOT_ID is an opaque identifier, not an index. Through
 * p11-kit, C_OpenSession answered CKR_SLOT_ID_INVALID for 0, 1, 2 and 3 --
 * there was no number the operator could have typed.
 *
 * So: enumerate. C_GetSlotList's two-call convention returns however many
 * there are, which is what a bound-free implementation needs -- four today,
 * eight tomorrow, whatever a smart-card reader or a remote module reports.
 *
 * Two enumerations, not one: tokenPresent=1 gives the slots that hold a token,
 * tokenPresent=0 gives every slot. Every rule below is a set operation on
 * those two, so nothing here needs C_GetTokenInfo to decide -- only to print.
 *
 *   --slot given : the value must appear in the full enumeration. If it does
 *                  not, say what does rather than pass it through to a bare
 *                  CKR_SLOT_ID_INVALID.
 *
 *   --slot absent : the default depends on what the tool is about to do, which
 *                   is why the intent is a parameter and not a boolean.
 *
 * P11_SLOT_WITH_TOKEN -- fhsm-csr, fhsm-ca, fhsm-sign. Exactly one token, or
 * refuse and list them with their labels. Refusing on ambiguity rather than
 * taking the first is deliberate: picking one of several tokens for the
 * operator means signing with a key they did not choose, and the mistake is
 * invisible until someone reads the certificate.
 *
 * P11_SLOT_FOR_INIT -- `fhsm-token init`, which addresses a slot precisely
 * because it has no token yet. Asking for tokenPresent there would hide every
 * slot the operator is allowed to initialise. The lowest EMPTY slot is chosen,
 * which is a guess -- but a guess whose worst case is initialising an empty
 * slot, and that destroys nothing. When every slot holds a token there is no
 * harmless choice left, so it refuses.
 *
 * P11_SLOT_ANY -- `fhsm-token info`, which is read-only and prints the slot it
 * read. One token -> that one; several -> refuse, because "info" on the wrong
 * token is how an operator concludes a key is missing; no token at all -> the
 * lowest slot, so that info can answer "not initialised" instead of failing.
 * ------------------------------------------------------------------------- */
enum p11_slot_intent {
    P11_SLOT_WITH_TOKEN,
    P11_SLOT_FOR_INIT,
    P11_SLOT_ANY
};
P11_MAYBE_UNUSED
static void p11_label_of(CK_SLOT_ID id, char out[33]) {
    /* CK_TOKEN_INFO opens with label[32], blank-padded, not NUL-terminated.
     * Reading the first 32 bytes needs no struct definition, which keeps a
     * third copy of the layout out of this header. */
    unsigned char ti[1024];
    memset(ti, 0, sizeof ti);
    memset(out, 0, 33);
    if (!p11.GetTokenInfo || p11.GetTokenInfo(id, ti) != CKR_OK) {
        snprintf(out, 33, "(unreadable)");
        return;
    }
    memcpy(out, ti, 32);
    for (int i = 31; i >= 0 && (out[i] == ' ' || out[i] == '\0'); i--) out[i] = '\0';
    if (!out[0]) snprintf(out, 33, "(no label)");
}

/* `--slot` used to go through atoi, which answers 0 for "abc", for "" and for
 * an overflowing number -- and 0 used to be the default, so a typo addressed
 * slot 0 silently. Now that a slot is chosen by enumeration, an unparseable
 * one has to be a refusal rather than a fallback. */
P11_MAYBE_UNUSED
static long p11_slot_arg(const char *s) {
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || !*s || *end || v < 0) {
        fprintf(stderr, "%s: --slot %s is not a slot identifier.\n", p11_progname, s);
        exit(1);
    }
    return v;
}

/* One enumeration. `*ids` is owned by the caller, and NULL when there are none. */
P11_MAYBE_UNUSED static int p11_enumerate_e(int token_present, CK_SLOT_ID **ids_out, CK_ULONG *out_n,
                           struct p11_err *e) {
    CK_ULONG n = 0;
    *ids_out = NULL;
    *out_n = 0;
    CK_RV rv = p11.GetSlotList((unsigned char)(token_present ? 1 : 0), NULL, &n);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_GetSlotList failed (0x%lx)\n", (unsigned long)rv);
    if (n == 0) return 0;
    CK_SLOT_ID *ids = calloc(n, sizeof *ids);
    if (!ids) return p11_fail(e, 2, "out of memory\n");
    rv = p11.GetSlotList((unsigned char)(token_present ? 1 : 0), ids, &n);
    /* n can only have shrunk between the two calls if a reader was removed;
     * trust the second answer, which is the one describing the buffer. */
    if (rv != CKR_OK) {
        free(ids);
        return p11_fail(e, 2, "C_GetSlotList failed (0x%lx)\n", (unsigned long)rv);
    }
    *ids_out = ids;
    *out_n = n;
    return 0;
}

/* The slot list printed beside a refusal, one "--slot N   label" per line. */
P11_MAYBE_UNUSED static void p11_append_slots(struct p11_err *e, const CK_SLOT_ID *ids, CK_ULONG n) {
    for (CK_ULONG i = 0; i < n; i++) {
        char lbl[33]; p11_label_of(ids[i], lbl);
        p11_append(e, "    --slot %lu   %s\n", (unsigned long)ids[i], lbl);
    }
}

/* `want` is the value of --slot, or -1 when the operator did not give one.
 * Every refusal names the slots there are, so the four tools and the
 * interface say the same thing; four copies of the same message is how they
 * drift. */
P11_MAYBE_UNUSED
static int p11_resolve_slot_e(long want, enum p11_slot_intent intent,
                              CK_SLOT_ID *out, struct p11_err *e) {
    CK_ULONG n_all = 0, n_tok = 0;
    CK_SLOT_ID *all = NULL, *tok = NULL;
    CK_SLOT_ID chosen = 0;
    int rc = 0;

    if ((rc = p11_enumerate_e(0, &all, &n_all, e)) != 0) goto done;
    if ((rc = p11_enumerate_e(1, &tok, &n_tok, e)) != 0) goto done;

    if (n_all == 0) {
        rc = p11_fail(e, 3, "the module reports no slot at all.\n");
        goto done;
    }

    /* --slot given: it must exist. Checked against the full list even for the
     * signing tools -- "slot 2 holds no token" is a better answer than "no
     * slot 2", and the operator learns which of the two mistakes they made. */
    if (want >= 0) {
        int exists = 0, has_token = 0;
        for (CK_ULONG i = 0; i < n_all; i++) if (all[i] == (CK_SLOT_ID)want) exists = 1;
        for (CK_ULONG i = 0; i < n_tok; i++) if (tok[i] == (CK_SLOT_ID)want) has_token = 1;
        if (!exists) {
            rc = p11_fail(e, 3, "no slot %ld on this module. Available:\n", want);
            p11_append_slots(e, all, n_all);
            goto done;
        }
        if (intent == P11_SLOT_WITH_TOKEN && !has_token) {
            rc = p11_fail(e, 3, "slot %ld holds no initialised token.\n"
                                "  `fhsm-token init --slot %ld` creates one.\n",
                          want, want);
            if (n_tok) {
                p11_append(e, "  Slots that do hold one:\n");
                p11_append_slots(e, tok, n_tok);
            }
            goto done;
        }
        chosen = (CK_SLOT_ID)want;
        goto done;
    }

    switch (intent) {
    case P11_SLOT_WITH_TOKEN:
        if (n_tok == 0) {
            rc = p11_fail(e, 3, "no slot on this module holds an initialised token.\n"
                                "  `fhsm-token init` creates one.\n");
            goto done;
        }
        if (n_tok > 1) {
            rc = p11_fail(e, 3, "%lu slots hold a token; name one with --slot:\n",
                          (unsigned long)n_tok);
            p11_append_slots(e, tok, n_tok);
            goto done;
        }
        chosen = tok[0];
        break;

    case P11_SLOT_FOR_INIT: {
        /* The lowest slot that holds nothing. */
        int found = 0;
        for (CK_ULONG i = 0; i < n_all && !found; i++) {
            int taken = 0;
            for (CK_ULONG k = 0; k < n_tok; k++) if (tok[k] == all[i]) taken = 1;
            if (!taken) { chosen = all[i]; found = 1; }
        }
        if (!found) {
            rc = p11_fail(e, 3, "every slot already holds a token, so there is no\n"
                                "  empty one to initialise. Name the slot to re-initialise\n"
                                "  with --slot, and note that doing so DESTROYS its keys:\n");
            p11_append_slots(e, all, n_all);
            goto done;
        }
        break;
    }

    case P11_SLOT_ANY:
        if (n_tok == 1) { chosen = tok[0]; break; }
        if (n_tok > 1) {
            rc = p11_fail(e, 3, "%lu slots hold a token; name one with --slot:\n",
                          (unsigned long)n_tok);
            p11_append_slots(e, tok, n_tok);
            goto done;
        }
        chosen = all[0];        /* none initialised: report on the first */
        break;
    }

done:
    free(all); free(tok);
    if (rc == 0) *out = chosen;
    return rc;
}

P11_MAYBE_UNUSED
static CK_SLOT_ID p11_resolve_slot(long want, enum p11_slot_intent intent) {
    struct p11_err e;
    CK_SLOT_ID sid = 0;
    if (p11_resolve_slot_e(want, intent, &sid, &e)) p11_exit_on(&e);
    return sid;
}

#endif /* FHSM_TOOLS_P11_UTIL_H */
