/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * tools/pkiops.c --- the operations of the PKI tools. See tools/pkiops.h.
 *
 *  The messages are the ones the tools printed before this file existed, word
 *  for word: tests/pki_tools_characterize.sh compares the tools' transcripts
 *  before and after, and the move is not done until they are identical.
 * ========================================================================= */
/* clock_gettime, for the call log's timings. Before any include. */
#define _POSIX_C_SOURCE 200809L

#include "pkiops.h"
#include "p11_util.h"

#include <openssl/evp.h>
#include <time.h>

/* --- the call log ----------------------------------------------------------
 *
 * Every function of the module's table is replaced, once loaded, by one that
 * calls the original and then reports the call. Installed on every load, for
 * the command-line tools too: with no callback set, a wrapper only calls
 * through, and keeping one path to the module is worth more than the cycles.
 *
 * What a summary may contain is decided here, function by function, and the
 * rule is the module's audit log's: handles, slots, mechanisms, attribute
 * TYPES and byte counts -- never a PIN, its length, or an attribute value.
 * tests/test_pkiops.c logs in with a distinctive PIN and checks that it
 * appears in no record.
 * ------------------------------------------------------------------------- */
static pkiops_call_cb g_log;
static void          *g_log_ctx;

void pkiops_set_call_log(pkiops_call_cb cb, void *ctx) { g_log = cb; g_log_ctx = ctx; }

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

P11_PRINTF(4, 5)
static void logcall(const char *fn, CK_RV rv, double t0, const char *fmt, ...) {
    if (!g_log) return;
    struct pkiops_call c;
    c.fn = fn;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c.args, sizeof c.args, fmt, ap);
    va_end(ap);
    c.rv = (unsigned long)rv;
    c.ms = now_ms() - t0;
    g_log(&c, g_log_ctx);
}

static const char *mech_name(CK_ULONG m, char buf[32]) {
    switch (m) {
    case CKM_COMPOSITE_MLDSA65_ED25519: return "CKM_COMPOSITE_MLDSA65_ED25519";
    case 0x0000UL: return "CKM_RSA_PKCS_KEY_PAIR_GEN";
    case 0x001CUL: return "CKM_ML_DSA_KEY_PAIR_GEN";
    case 0x001DUL: return "CKM_ML_DSA";
    case 0x0040UL: return "CKM_SHA256_RSA_PKCS";
    case 0x0043UL: return "CKM_SHA256_RSA_PKCS_PSS";
    case 0x1040UL: return "CKM_EC_KEY_PAIR_GEN";
    case 0x1044UL: return "CKM_ECDSA_SHA256";
    case 0x1045UL: return "CKM_ECDSA_SHA384";
    case 0x1055UL: return "CKM_EC_EDWARDS_KEY_PAIR_GEN";
    case 0x1057UL: return "CKM_EDDSA";
    default: break;
    }
    snprintf(buf, 32, "mechanism 0x%lx", (unsigned long)m);
    return buf;
}

static const char *user_name(CK_ULONG u) {
    return u == CKU_SO ? "CKU_SO" : u == CKU_USER ? "CKU_USER"
         : u == 2 ? "CKU_CONTEXT_SPECIFIC" : "user type ?";
}

/* "CKA_LABEL, CKA_VALUE" -- the types asked for or matched, never values. */
static void attr_types(char *out, size_t cap, const CK_ATTRIBUTE *t, CK_ULONG n) {
    size_t used = 0;
    out[0] = '\0';
    for (CK_ULONG i = 0; i < n && used < cap; i++) {
        const char *nm = t[i].type == CKA_CLASS ? "CKA_CLASS"
                       : t[i].type == CKA_TOKEN ? "CKA_TOKEN"
                       : t[i].type == CKA_LABEL ? "CKA_LABEL"
                       : t[i].type == CKA_VALUE ? "CKA_VALUE"
                       : t[i].type == 0x100UL   ? "CKA_KEY_TYPE"
                       : t[i].type == 0x103UL   ? "CKA_SENSITIVE"
                       : t[i].type == 0x108UL   ? "CKA_SIGN"
                       : t[i].type == 0x10AUL   ? "CKA_VERIFY"
                       : t[i].type == 0x120UL   ? "CKA_MODULUS"
                       : t[i].type == 0x121UL   ? "CKA_MODULUS_BITS"
                       : t[i].type == 0x122UL   ? "CKA_PUBLIC_EXPONENT"
                       : t[i].type == 0x180UL   ? "CKA_EC_PARAMS"
                       : t[i].type == 0x181UL   ? "CKA_EC_POINT"
                       : t[i].type == 0x61DUL   ? "CKA_PARAMETER_SET"
                       : t[i].type == 0x40000600UL ? "CKA_ALLOWED_MECHANISMS" : NULL;
        int w = nm ? snprintf(out + used, cap - used, "%s%s", i ? ", " : "", nm)
                   : snprintf(out + used, cap - used, "%s0x%lx", i ? ", " : "",
                              (unsigned long)t[i].type);
        if (w < 0) break;
        used += (size_t)w;
    }
}

static struct {
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
    CK_RV (*SignUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*SignFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
    CK_RV (*VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*VerifyUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*VerifyFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*GetTokenInfo)(CK_SLOT_ID,void*);
    CK_RV (*GenerateRandom)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*GetSlotList)(unsigned char,CK_SLOT_ID*,CK_ULONG*);
    CK_RV (*GetMechanismList)(CK_SLOT_ID,CK_ULONG*,CK_ULONG*);
    CK_RV (*GetMechanismInfo)(CK_SLOT_ID,CK_ULONG,void*);
} real;

static CK_RV w_Initialize(void *a) {
    double t = now_ms(); CK_RV rv = real.Initialize(a);
    logcall("C_Initialize", rv, t, "%s", "");
    return rv;
}
static CK_RV w_Finalize(void *a) {
    double t = now_ms(); CK_RV rv = real.Finalize(a);
    logcall("C_Finalize", rv, t, "%s", "");
    return rv;
}
static CK_RV w_OpenSession(CK_SLOT_ID sl, CK_FLAGS f, void *app, void *nfy, CK_SESSION_HANDLE *s) {
    double t = now_ms(); CK_RV rv = real.OpenSession(sl, f, app, nfy, s);
    logcall("C_OpenSession", rv, t, "slot %lu, flags 0x%lx -> session %lu",
            (unsigned long)sl, (unsigned long)f, rv == CKR_OK && s ? (unsigned long)*s : 0UL);
    return rv;
}
static CK_RV w_CloseSession(CK_SESSION_HANDLE s) {
    double t = now_ms(); CK_RV rv = real.CloseSession(s);
    logcall("C_CloseSession", rv, t, "session %lu", (unsigned long)s);
    return rv;
}
static CK_RV w_Login(CK_SESSION_HANDLE s, CK_ULONG u, CK_BYTE *pin, CK_ULONG n) {
    double t = now_ms(); CK_RV rv = real.Login(s, u, pin, n);
    logcall("C_Login", rv, t, "session %lu, %s, PIN not shown", (unsigned long)s, user_name(u));
    return rv;
}
static CK_RV w_GenerateKeyPair(CK_SESSION_HANDLE s, CK_MECHANISM *m,
                               CK_ATTRIBUTE *pt, CK_ULONG pn, CK_ATTRIBUTE *kt, CK_ULONG kn,
                               CK_OBJECT_HANDLE *hp, CK_OBJECT_HANDLE *hk) {
    double t = now_ms(); CK_RV rv = real.GenerateKeyPair(s, m, pt, pn, kt, kn, hp, hk);
    char mb[32];
    logcall("C_GenerateKeyPair", rv, t, "session %lu, %s -> public %lu, private %lu",
            (unsigned long)s, m ? mech_name(m->mechanism, mb) : "no mechanism",
            rv == CKR_OK && hp ? (unsigned long)*hp : 0UL,
            rv == CKR_OK && hk ? (unsigned long)*hk : 0UL);
    return rv;
}
static CK_RV w_FindObjectsInit(CK_SESSION_HANDLE s, CK_ATTRIBUTE *tp, CK_ULONG n) {
    double t = now_ms(); CK_RV rv = real.FindObjectsInit(s, tp, n);
    char ty[120]; attr_types(ty, sizeof ty, tp, n);
    logcall("C_FindObjectsInit", rv, t, "session %lu, matching %s", (unsigned long)s, n ? ty : "anything");
    return rv;
}
static CK_RV w_FindObjects(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE *h, CK_ULONG max, CK_ULONG *n) {
    double t = now_ms(); CK_RV rv = real.FindObjects(s, h, max, n);
    logcall("C_FindObjects", rv, t, "session %lu, up to %lu -> %lu found", (unsigned long)s,
            (unsigned long)max, rv == CKR_OK && n ? (unsigned long)*n : 0UL);
    return rv;
}
static CK_RV w_FindObjectsFinal(CK_SESSION_HANDLE s) {
    double t = now_ms(); CK_RV rv = real.FindObjectsFinal(s);
    logcall("C_FindObjectsFinal", rv, t, "session %lu", (unsigned long)s);
    return rv;
}
static CK_RV w_GetAttributeValue(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, CK_ATTRIBUTE *tp, CK_ULONG n) {
    double t = now_ms(); CK_RV rv = real.GetAttributeValue(s, o, tp, n);
    char ty[120]; attr_types(ty, sizeof ty, tp, n);
    logcall("C_GetAttributeValue", rv, t, "session %lu, object %lu, %s, values not shown",
            (unsigned long)s, (unsigned long)o, ty);
    return rv;
}
static CK_RV w_DigestInit(CK_SESSION_HANDLE s, CK_MECHANISM *m) {
    double t = now_ms(); CK_RV rv = real.DigestInit(s, m);
    char mb[32];
    logcall("C_DigestInit", rv, t, "session %lu, %s", (unsigned long)s,
            m ? mech_name(m->mechanism, mb) : "no mechanism");
    return rv;
}
static CK_RV w_SignInit(CK_SESSION_HANDLE s, CK_MECHANISM *m, CK_OBJECT_HANDLE k) {
    double t = now_ms(); CK_RV rv = real.SignInit(s, m, k);
    char mb[32];
    logcall("C_SignInit", rv, t, "session %lu, %s, key %lu", (unsigned long)s,
            m ? mech_name(m->mechanism, mb) : "no mechanism", (unsigned long)k);
    return rv;
}
static CK_RV w_Sign(CK_SESSION_HANDLE s, CK_BYTE *d, CK_ULONG dn, CK_BYTE *sig, CK_ULONG *sn) {
    double t = now_ms(); CK_RV rv = real.Sign(s, d, dn, sig, sn);
    logcall("C_Sign", rv, t, "session %lu, %lu bytes in -> %lu bytes%s", (unsigned long)s,
            (unsigned long)dn, sn ? (unsigned long)*sn : 0UL, sig ? "" : " (size query)");
    return rv;
}
static CK_RV w_SignUpdate(CK_SESSION_HANDLE s, CK_BYTE *d, CK_ULONG dn) {
    double t = now_ms(); CK_RV rv = real.SignUpdate(s, d, dn);
    logcall("C_SignUpdate", rv, t, "session %lu, %lu bytes", (unsigned long)s, (unsigned long)dn);
    return rv;
}
static CK_RV w_SignFinal(CK_SESSION_HANDLE s, CK_BYTE *sig, CK_ULONG *sn) {
    double t = now_ms(); CK_RV rv = real.SignFinal(s, sig, sn);
    logcall("C_SignFinal", rv, t, "session %lu -> %lu bytes%s", (unsigned long)s,
            sn ? (unsigned long)*sn : 0UL, sig ? "" : " (size query)");
    return rv;
}
static CK_RV w_VerifyInit(CK_SESSION_HANDLE s, CK_MECHANISM *m, CK_OBJECT_HANDLE k) {
    double t = now_ms(); CK_RV rv = real.VerifyInit(s, m, k);
    char mb[32];
    logcall("C_VerifyInit", rv, t, "session %lu, %s, key %lu", (unsigned long)s,
            m ? mech_name(m->mechanism, mb) : "no mechanism", (unsigned long)k);
    return rv;
}
static CK_RV w_VerifyUpdate(CK_SESSION_HANDLE s, CK_BYTE *d, CK_ULONG dn) {
    double t = now_ms(); CK_RV rv = real.VerifyUpdate(s, d, dn);
    logcall("C_VerifyUpdate", rv, t, "session %lu, %lu bytes", (unsigned long)s, (unsigned long)dn);
    return rv;
}
static CK_RV w_VerifyFinal(CK_SESSION_HANDLE s, CK_BYTE *sig, CK_ULONG sn) {
    double t = now_ms(); CK_RV rv = real.VerifyFinal(s, sig, sn);
    logcall("C_VerifyFinal", rv, t, "session %lu, %lu-byte signature", (unsigned long)s, (unsigned long)sn);
    return rv;
}
static CK_RV w_InitToken(CK_SLOT_ID sl, CK_BYTE *pin, CK_ULONG n, CK_BYTE *label) {
    double t = now_ms(); CK_RV rv = real.InitToken(sl, pin, n, label);
    logcall("C_InitToken", rv, t, "slot %lu, SO PIN not shown", (unsigned long)sl);
    return rv;
}
static CK_RV w_InitPIN(CK_SESSION_HANDLE s, CK_BYTE *pin, CK_ULONG n) {
    double t = now_ms(); CK_RV rv = real.InitPIN(s, pin, n);
    logcall("C_InitPIN", rv, t, "session %lu, PIN not shown", (unsigned long)s);
    return rv;
}
static CK_RV w_GetTokenInfo(CK_SLOT_ID sl, void *ti) {
    double t = now_ms(); CK_RV rv = real.GetTokenInfo(sl, ti);
    logcall("C_GetTokenInfo", rv, t, "slot %lu", (unsigned long)sl);
    return rv;
}
static CK_RV w_GenerateRandom(CK_SESSION_HANDLE s, CK_BYTE *out, CK_ULONG n) {
    double t = now_ms(); CK_RV rv = real.GenerateRandom(s, out, n);
    logcall("C_GenerateRandom", rv, t, "session %lu, %lu bytes, not shown", (unsigned long)s, (unsigned long)n);
    return rv;
}
static CK_RV w_GetSlotList(unsigned char present, CK_SLOT_ID *ids, CK_ULONG *n) {
    double t = now_ms(); CK_RV rv = real.GetSlotList(present, ids, n);
    logcall("C_GetSlotList", rv, t, "%s -> %lu%s", present ? "with a token" : "all slots",
            rv == CKR_OK && n ? (unsigned long)*n : 0UL, ids ? "" : " (count)");
    return rv;
}
static CK_RV w_GetMechanismList(CK_SLOT_ID sl, CK_ULONG *list, CK_ULONG *n) {
    double t = now_ms(); CK_RV rv = real.GetMechanismList(sl, list, n);
    logcall("C_GetMechanismList", rv, t, "slot %lu -> %lu%s", (unsigned long)sl,
            rv == CKR_OK && n ? (unsigned long)*n : 0UL, list ? "" : " (count)");
    return rv;
}
static CK_RV w_GetMechanismInfo(CK_SLOT_ID sl, CK_ULONG m, void *info) {
    double t = now_ms(); CK_RV rv = real.GetMechanismInfo(sl, m, info);
    char mb[32];
    logcall("C_GetMechanismInfo", rv, t, "slot %lu, %s", (unsigned long)sl, mech_name(m, mb));
    return rv;
}

/* Swap every function the module gave for its wrapper. A function the module
 * left unset (the non-conforming load path does not fetch the mechanism
 * queries) stays unset rather than becoming a wrapper around NULL. */
static void install_wrappers(void) {
    #define W(f) do { real.f = p11.f; if (p11.f) p11.f = w_##f; } while (0)
    W(Initialize); W(Finalize); W(OpenSession); W(CloseSession); W(Login);
    W(GenerateKeyPair); W(FindObjectsInit); W(FindObjects); W(FindObjectsFinal);
    W(GetAttributeValue); W(DigestInit); W(SignInit); W(Sign); W(SignUpdate);
    W(SignFinal); W(VerifyInit); W(VerifyUpdate); W(VerifyFinal); W(InitToken);
    W(InitPIN); W(GetTokenInfo); W(GenerateRandom); W(GetSlotList);
    W(GetMechanismList); W(GetMechanismInfo);
    #undef W
}

/* --- the module ----------------------------------------------------------- */

static int g_initialised;

int pkiops_load(const char *module, struct p11_err *e) {
    /* Whatever was loaded before is finalised and forgotten first, and a load
     * that fails part way leaves nothing behind: either way the next call
     * starts from an empty table. */
    pkiops_unload();
    if (p11_load_module_e(module, e)) { pkiops_unload(); return e->code; }
    install_wrappers();
    CK_RV rv = p11.Initialize(NULL);
    if (rv != CKR_OK) {
        pkiops_unload();
        return p11_fail(e, 2, "C_Initialize failed (0x%lx)\n", (unsigned long)rv);
    }
    g_initialised = 1;
    return 0;
}

int pkiops_open(const char *module, long want, enum pkiops_slot_intent intent,
                pkiops_handle *slot, struct p11_err *e) {
    if (pkiops_load(module, e)) return e->code;
    enum p11_slot_intent i = intent == PKIOPS_SLOT_FOR_INIT ? P11_SLOT_FOR_INIT
                           : intent == PKIOPS_SLOT_ANY      ? P11_SLOT_ANY
                           :                                  P11_SLOT_WITH_TOKEN;
    CK_SLOT_ID sid = 0;
    if (p11_resolve_slot_e(want, i, &sid, e)) { pkiops_close(); return e->code; }
    *slot = (pkiops_handle)sid;
    return 0;
}

void pkiops_close(void) {
    if (g_initialised) { p11.Finalize(NULL); g_initialised = 0; }
}

void pkiops_unload(void) {
    pkiops_close();
    /* Not dlclose'd -- see pkiops.h. Forgetting the table is what makes the
     * next pkiops_load start from nothing. */
    memset(&p11,  0, sizeof p11);
    memset(&real, 0, sizeof real);
}

int pkiops_parse_slot(const char *text, long *out, struct p11_err *e) {
    char *end = NULL;
    errno = 0;
    long v = strtol(text, &end, 10);
    if (errno || !*text || *end || v < 0)
        return p11_fail(e, 1, "--slot %s is not a slot identifier.\n", text);
    *out = v;
    return 0;
}

/* --- token state ---------------------------------------------------------- */

#define CKF_USER_PIN_INITIALIZED  0x00000008UL
#define CKF_TOKEN_INITIALIZED     0x00000400UL
#define CKF_USER_PIN_LOCKED       0x00040000UL
#define CKF_SO_PIN_LOCKED         0x00400000UL

/* CK_TOKEN_INFO, PKCS#11 v3.2 §C.6.3. Declared here rather than pulled from a
 * header so the operations stay usable against any module, not only this one. */
struct tok_info {
    unsigned char label[32], manufacturerID[32], model[16], serialNumber[16];
    CK_ULONG flags;
    CK_ULONG ulMaxSessionCount, ulSessionCount;
    CK_ULONG ulMaxRwSessionCount, ulRwSessionCount;
    CK_ULONG ulMaxPinLen, ulMinPinLen;
    CK_ULONG ulTotalPublicMemory, ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory, ulFreePrivateMemory;
    unsigned char hardwareVersion[2], firmwareVersion[2], utcTime[16];
};

/* PKCS#11 fixed-width fields are space-padded, not NUL-terminated. */
static void field(char *out, const unsigned char *f, size_t n) {
    while (n && (f[n-1] == ' ' || f[n-1] == '\0')) n--;
    memcpy(out, f, n);
    out[n] = '\0';
}

int pkiops_token_info(pkiops_handle slot, struct pkiops_token_info *out,
                      struct p11_err *e) {
    struct tok_info ti;
    memset(&ti, 0, sizeof ti);
    CK_RV rv = p11.GetTokenInfo((CK_SLOT_ID)slot, &ti);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_GetTokenInfo failed (0x%lx)\n", (unsigned long)rv);
    field(out->label,        ti.label,          sizeof ti.label);
    field(out->manufacturer, ti.manufacturerID, sizeof ti.manufacturerID);
    field(out->model,        ti.model,          sizeof ti.model);
    field(out->serial,       ti.serialNumber,   sizeof ti.serialNumber);
    out->initialised     = (ti.flags & CKF_TOKEN_INITIALIZED)    != 0;
    out->user_pin_set    = (ti.flags & CKF_USER_PIN_INITIALIZED) != 0;
    out->so_pin_locked   = (ti.flags & CKF_SO_PIN_LOCKED)        != 0;
    out->user_pin_locked = (ti.flags & CKF_USER_PIN_LOCKED)      != 0;
    out->min_pin = (unsigned long)ti.ulMinPinLen;
    out->max_pin = (unsigned long)ti.ulMaxPinLen;
    return 0;
}

int pkiops_token_init(pkiops_handle slot,
                      const uint8_t *so_pin, size_t so_len,
                      const uint8_t *user_pin, size_t user_len,
                      const char *label, struct p11_err *e) {
    /* PKCS#11 labels are space-padded to exactly 32 bytes, not NUL-terminated.
     * Passing a short C string here made C_InitToken read past the end once
     * already (see tests/test_attributes). */
    size_t ln = strlen(label);
    if (ln > 32) return p11_fail(e, 1, "the token label is at most 32 bytes\n");
    CK_BYTE lbl[32];
    memset(lbl, ' ', sizeof lbl);
    memcpy(lbl, label, ln);

    CK_RV rv = p11.InitToken((CK_SLOT_ID)slot, (CK_BYTE*)(uintptr_t)so_pin,
                             (CK_ULONG)so_len, lbl);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_InitToken failed (0x%lx)\n", (unsigned long)rv);

    CK_SESSION_HANDLE s = 0;
    rv = p11.OpenSession((CK_SLOT_ID)slot, CKF_RW, NULL, NULL, &s);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_OpenSession failed (0x%lx)\n", (unsigned long)rv);
    rv = p11.Login(s, CKU_SO, (CK_BYTE*)(uintptr_t)so_pin, (CK_ULONG)so_len);
    if (rv != CKR_OK) {
        p11.CloseSession(s);
        return p11_fail(e, 2, "C_Login (SO) failed (0x%lx)\n", (unsigned long)rv);
    }
    rv = p11.InitPIN(s, (CK_BYTE*)(uintptr_t)user_pin, (CK_ULONG)user_len);
    if (rv != CKR_OK) {
        p11.CloseSession(s);
        return p11_fail(e, 2, "C_InitPIN failed (0x%lx)\n", (unsigned long)rv);
    }
    p11.CloseSession(s);
    return 0;
}

/* --- sessions ------------------------------------------------------------- */

int pkiops_session_user(pkiops_handle slot, const uint8_t *pin, size_t pin_len,
                        pkiops_handle *session, struct p11_err *e) {
    CK_SESSION_HANDLE s = 0;
    CK_RV rv = p11.OpenSession((CK_SLOT_ID)slot, CKF_RW, NULL, NULL, &s);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_OpenSession failed (0x%lx)\n", (unsigned long)rv);
    rv = p11.Login(s, CKU_USER, (CK_BYTE*)(uintptr_t)pin, (CK_ULONG)pin_len);
    if (rv != CKR_OK) {
        p11.CloseSession(s);
        return p11_fail(e, 2, "C_Login failed (0x%lx)\n", (unsigned long)rv);
    }
    *session = (pkiops_handle)s;
    return 0;
}

void pkiops_session_close(pkiops_handle session) {
    p11.CloseSession((CK_SESSION_HANDLE)session);
}

/* --- algorithms ------------------------------------------------------------
 *
 * docs/classic-algorithms-plan.md stage 2. Chosen once, when the key pair is
 * generated; read off the key afterwards. The table is the one place that
 * ties a name the operator types to a key type, a signing mechanism, an X.509
 * algorithm and a CMS digest.
 * ------------------------------------------------------------------------- */
#include "fhsm_pki.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#define CKA_KEY_TYPE_           0x00000100UL
#define CKA_SENSITIVE_          0x00000103UL
#define CKA_SIGN_               0x00000108UL
#define CKA_VERIFY_             0x0000010AUL
#define CKA_MODULUS_            0x00000120UL
#define CKA_MODULUS_BITS_       0x00000121UL
#define CKA_PUBLIC_EXPONENT_    0x00000122UL
#define CKA_EC_PARAMS_          0x00000180UL
#define CKA_EC_POINT_           0x00000181UL
#define CKA_PARAMETER_SET_      0x0000061DUL
#define CKA_ALLOWED_MECHANISMS_ 0x40000600UL

#define CKK_RSA_        0x00000000UL
#define CKK_EC_         0x00000003UL
#define CKK_EC_EDWARDS_ 0x00000040UL
#define CKK_ML_DSA_     0x0000004AUL
#define CKK_COMPOSITE_  0x80004202UL

#define CKM_SHA256_     0x00000250UL
#define CKG_MGF1_SHA256_ 0x00000002UL

static const struct alginfo {
    const char       *name;
    fhsm_pki_sigalg_t sig;
    CK_ULONG          keytype;
    CK_ULONG          keygen;     /* key-pair generation mechanism */
    CK_ULONG          mech;       /* signing mechanism */
    const char       *digest;     /* the CMS digest */
    size_t            ecdsa_half; /* r and s length; 0 if not ECDSA */
} ALG[PKIOPS_ALG_COUNT] = {
    [PKIOPS_ALG_COMPOSITE]  = { "composite",  FHSM_PKI_SIG_COMPOSITE_MLDSA65_ED25519,
                                CKK_COMPOSITE_, CKM_COMPOSITE_MLDSA65_ED25519,
                                CKM_COMPOSITE_MLDSA65_ED25519, "SHA512", 0 },
    [PKIOPS_ALG_ECDSA_P256] = { "ecdsa-p256", FHSM_PKI_SIG_ECDSA_SHA256,
                                CKK_EC_, 0x1040UL, 0x1044UL, "SHA256", 32 },
    [PKIOPS_ALG_ECDSA_P384] = { "ecdsa-p384", FHSM_PKI_SIG_ECDSA_SHA384,
                                CKK_EC_, 0x1040UL, 0x1045UL, "SHA384", 48 },
    [PKIOPS_ALG_RSA_PSS]    = { "rsa-pss",    FHSM_PKI_SIG_RSA_PSS_SHA256,
                                CKK_RSA_, 0x0000UL, 0x0043UL, "SHA256", 0 },
    [PKIOPS_ALG_RSA_PKCS1]  = { "rsa-pkcs1",  FHSM_PKI_SIG_RSA_PKCS1_SHA256,
                                CKK_RSA_, 0x0000UL, 0x0040UL, "SHA256", 0 },
    [PKIOPS_ALG_ED25519]    = { "ed25519",    FHSM_PKI_SIG_ED25519,
                                CKK_EC_EDWARDS_, 0x1055UL, 0x1057UL, "SHA512", 0 },
    [PKIOPS_ALG_MLDSA44]    = { "ml-dsa-44",  FHSM_PKI_SIG_MLDSA44,
                                CKK_ML_DSA_, 0x001CUL, 0x001DUL, "SHA512", 0 },
    [PKIOPS_ALG_MLDSA65]    = { "ml-dsa-65",  FHSM_PKI_SIG_MLDSA65,
                                CKK_ML_DSA_, 0x001CUL, 0x001DUL, "SHA512", 0 },
    [PKIOPS_ALG_MLDSA87]    = { "ml-dsa-87",  FHSM_PKI_SIG_MLDSA87,
                                CKK_ML_DSA_, 0x001CUL, 0x001DUL, "SHA512", 0 },
};

/* The curve OIDs, as CKA_EC_PARAMS carries them. */
static const uint8_t OID_P256[]    = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t OID_P384[]    = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const uint8_t OID_ED25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };

const char *pkiops_alg_name(enum pkiops_alg a) {
    return (unsigned)a < PKIOPS_ALG_COUNT ? ALG[a].name : NULL;
}

const char *pkiops_alg_digest(enum pkiops_alg a) {
    return (unsigned)a < PKIOPS_ALG_COUNT ? ALG[a].digest : NULL;
}

const char *pkiops_alg_list(void) {
    return "composite, ecdsa-p256, ecdsa-p384, rsa-pss, rsa-pkcs1, ed25519, "
           "ml-dsa-44, ml-dsa-65, ml-dsa-87";
}

int pkiops_alg_parse(const char *name, enum pkiops_alg *out, struct p11_err *e) {
    for (unsigned i = 0; name && i < PKIOPS_ALG_COUNT; i++)
        if (!strcmp(name, ALG[i].name)) { *out = (enum pkiops_alg)i; return 0; }
    return p11_fail(e, 1, "\"%s\" is not an algorithm these tools offer.\n"
                          "  One of: %s\n", name ? name : "", pkiops_alg_list());
}

/* The CKM_SHA256_RSA_PKCS_PSS parameters fhsm_pki's AlgorithmIdentifier
 * names: SHA-256, MGF1 with SHA-256, a 32-byte salt. */
typedef struct { CK_ULONG hashAlg, mgf, sLen; } ck_pss_params;

static void alg_mechanism(enum pkiops_alg a, CK_MECHANISM *m, ck_pss_params *pss) {
    m->mechanism = ALG[a].mech;
    m->pParameter = NULL;
    m->ulParameterLen = 0;
    if (a == PKIOPS_ALG_RSA_PSS) {
        pss->hashAlg = CKM_SHA256_; pss->mgf = CKG_MGF1_SHA256_; pss->sLen = 32;
        m->pParameter = pss;
        m->ulParameterLen = sizeof *pss;
    }
}

/* One attribute, two calls: its length, then its value, in a malloc'd buffer
 * the caller frees. */
static int get_attr(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ULONG type,
                    uint8_t **val, size_t *len, struct p11_err *e) {
    CK_ATTRIBUTE a = { type, NULL, 0 };
    CK_RV rv = p11.GetAttributeValue(s, h, &a, 1);
    if (rv != CKR_OK || a.ulValueLen == (CK_ULONG)-1)
        return p11_fail(e, 2, "C_GetAttributeValue(0x%lx) failed (0x%lx)\n",
                        (unsigned long)type, (unsigned long)rv);
    uint8_t *b = malloc(a.ulValueLen ? (size_t)a.ulValueLen : 1);
    if (!b) return p11_fail(e, 2, "out of memory\n");
    a.pValue = b;
    rv = p11.GetAttributeValue(s, h, &a, 1);
    if (rv != CKR_OK) {
        free(b);
        return p11_fail(e, 2, "C_GetAttributeValue(0x%lx) failed (0x%lx)\n",
                        (unsigned long)type, (unsigned long)rv);
    }
    *val = b;
    *len = (size_t)a.ulValueLen;
    return 0;
}

static int get_ulong(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ULONG type,
                     CK_ULONG *out, struct p11_err *e) {
    CK_ATTRIBUTE a = { type, out, sizeof *out };
    CK_RV rv = p11.GetAttributeValue(s, h, &a, 1);
    if (rv != CKR_OK || a.ulValueLen != sizeof *out)
        return p11_fail(e, 2, "C_GetAttributeValue(0x%lx) failed (0x%lx)\n",
                        (unsigned long)type, (unsigned long)rv);
    return 0;
}

/* CKA_EC_POINT as a DER OCTET STRING -- what the specification says -- or as
 * the bare point, which modules in the field also return. Told apart by the
 * length the bare form must have, not by a leading 0x04: an uncompressed
 * point begins with 0x04 too, and its second byte can read as a length. */
static int point_of(const uint8_t *p, size_t n, size_t raw_len,
                    const uint8_t **out) {
    if (n == raw_len) { *out = p; return 1; }
    if (n >= 2 && p[0] == 0x04) {
        size_t hl = 2, l = p[1];
        if (l & 0x80) {
            size_t k = l & 0x7F;
            if (k == 0 || k > 2 || n < 2 + k) return 0;
            l = 0;
            for (size_t i = 0; i < k; i++) l = (l << 8) | p[2 + i];
            hl = 2 + k;
        }
        if (hl + l == n && l == raw_len) { *out = p + hl; return 1; }
    }
    return 0;
}

/* Which algorithm the key labelled `label` signs with, from `h` -- its
 * private half when signing, its public half when verifying -- and, where the
 * key type alone does not say, from its public half: the curve, the
 * parameter set. RSA's padding is the key's CKA_ALLOWED_MECHANISMS, set at
 * generation; a key without one, made elsewhere, signs with PSS. */
static int alg_of(CK_SESSION_HANDLE s, const char *label, CK_OBJECT_HANDLE h,
                  enum pkiops_alg *out, struct p11_err *e) {
    CK_ULONG kt = 0;
    if (get_ulong(s, h, CKA_KEY_TYPE_, &kt, e)) return e->code;
    if (kt == CKK_COMPOSITE_) { *out = PKIOPS_ALG_COMPOSITE; return 0; }

    if (kt == CKK_RSA_) {
        uint8_t *v = NULL; size_t n = 0;
        struct p11_err ignored;
        int pkcs1 = 0, pss = 0;
        if (get_attr(s, h, CKA_ALLOWED_MECHANISMS_, &v, &n, &ignored) == 0) {
            for (size_t i = 0; i + sizeof(CK_ULONG) <= n; i += sizeof(CK_ULONG)) {
                CK_ULONG m; memcpy(&m, v + i, sizeof m);
                if (m == ALG[PKIOPS_ALG_RSA_PKCS1].mech) pkcs1 = 1;
                if (m == ALG[PKIOPS_ALG_RSA_PSS].mech)   pss = 1;
            }
            free(v);
        }
        *out = pkcs1 && !pss ? PKIOPS_ALG_RSA_PKCS1 : PKIOPS_ALG_RSA_PSS;
        return 0;
    }

    CK_OBJECT_HANDLE hpub = 0;
    if (p11_find_one_e(s, CKO_PUBLIC_KEY, label, &hpub, e)) return e->code;
    uint8_t *v = NULL; size_t n = 0;
    int rc = 3;
    if (kt == CKK_EC_ || kt == CKK_EC_EDWARDS_) {
        if (get_attr(s, hpub, CKA_EC_PARAMS_, &v, &n, e)) return e->code;
        if (kt == CKK_EC_ && n == sizeof OID_P256 && !memcmp(v, OID_P256, n))
            { *out = PKIOPS_ALG_ECDSA_P256; rc = 0; }
        else if (kt == CKK_EC_ && n == sizeof OID_P384 && !memcmp(v, OID_P384, n))
            { *out = PKIOPS_ALG_ECDSA_P384; rc = 0; }
        else if (kt == CKK_EC_EDWARDS_
                 && ((n == sizeof OID_ED25519 && !memcmp(v, OID_ED25519, n))
                     || (n == 14 && !memcmp(v, "\x13\x0C" "edwards25519", 14))))
            { *out = PKIOPS_ALG_ED25519; rc = 0; }
    } else if (kt == CKK_ML_DSA_) {
        /* The parameter set, from the length of the raw public key -- what
         * every module returns as CKA_VALUE, whatever form it gives
         * CKA_PARAMETER_SET in. */
        if (get_attr(s, hpub, CKA_VALUE, &v, &n, e)) return e->code;
        if (n == 1312) { *out = PKIOPS_ALG_MLDSA44; rc = 0; }
        if (n == 1952) { *out = PKIOPS_ALG_MLDSA65; rc = 0; }
        if (n == 2592) { *out = PKIOPS_ALG_MLDSA87; rc = 0; }
    }
    free(v);
    if (rc)
        return p11_fail(e, 3, "the key \"%s\" is not one these tools sign with "
                              "(key type 0x%lx).\n  They sign with: %s\n",
                        label, (unsigned long)kt, pkiops_alg_list());
    return 0;
}

int pkiops_key_alg(pkiops_handle session, const char *label, enum pkiops_alg *out,
                   struct p11_err *e) {
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    CK_OBJECT_HANDLE h = 0;
    /* The public half: a session that is not logged in sees only that. */
    if (p11_find_one_e(s, CKO_PUBLIC_KEY, label, &h, e)) return e->code;
    return alg_of(s, label, h, out, e);
}

/* --- keys and requests ---------------------------------------------------- */

int pkiops_keygen(pkiops_handle session, const char *label,
                  pkiops_handle *pub, pkiops_handle *priv, struct p11_err *e) {
    return pkiops_keygen_alg(session, label, PKIOPS_ALG_COMPOSITE, pub, priv, e);
}

int pkiops_keygen_alg(pkiops_handle session, const char *label, enum pkiops_alg a,
                      pkiops_handle *pub, pkiops_handle *priv, struct p11_err *e) {
    if ((unsigned)a >= PKIOPS_ALG_COUNT) return p11_fail(e, 1, "no such algorithm\n");
    CK_MECHANISM m = { ALG[a].keygen, NULL, 0 };
    CK_BYTE t = 1;
    CK_ULONG lab = (CK_ULONG)strlen(label);
    /* The composite's templates are what they always were: label and token,
     * nothing else. The others say what the key is for, and RSA what it is
     * allowed to sign with -- which is also how the tools will know, later,
     * whether it is a PSS key or a PKCS#1 v1.5 one. */
    CK_ATTRIBUTE pub_t[6]  = { {CKA_LABEL,(void*)(uintptr_t)label,lab}, {CKA_TOKEN,&t,1} };
    CK_ATTRIBUTE priv_t[6] = { {CKA_LABEL,(void*)(uintptr_t)label,lab}, {CKA_TOKEN,&t,1} };
    CK_ULONG np = 2, nk = 2;
    CK_ULONG bits = 3072, pset = 0, allowed = ALG[a].mech;
    static const CK_BYTE f4[] = { 0x01, 0x00, 0x01 };
    if (a != PKIOPS_ALG_COMPOSITE) {
        pub_t[np++]  = (CK_ATTRIBUTE){ CKA_VERIFY_,    &t, 1 };
        priv_t[nk++] = (CK_ATTRIBUTE){ CKA_SIGN_,      &t, 1 };
        priv_t[nk++] = (CK_ATTRIBUTE){ CKA_SENSITIVE_, &t, 1 };
    }
    switch (a) {
    case PKIOPS_ALG_ECDSA_P256:
        pub_t[np++] = (CK_ATTRIBUTE){ CKA_EC_PARAMS_, (void*)(uintptr_t)OID_P256, sizeof OID_P256 };
        break;
    case PKIOPS_ALG_ECDSA_P384:
        pub_t[np++] = (CK_ATTRIBUTE){ CKA_EC_PARAMS_, (void*)(uintptr_t)OID_P384, sizeof OID_P384 };
        break;
    case PKIOPS_ALG_ED25519:
        pub_t[np++] = (CK_ATTRIBUTE){ CKA_EC_PARAMS_, (void*)(uintptr_t)OID_ED25519, sizeof OID_ED25519 };
        break;
    case PKIOPS_ALG_RSA_PSS:
    case PKIOPS_ALG_RSA_PKCS1:
        /* 3072 bits: SP 800-57 part 1's floor past 2030. */
        pub_t[np++]  = (CK_ATTRIBUTE){ CKA_MODULUS_BITS_, &bits, sizeof bits };
        pub_t[np++]  = (CK_ATTRIBUTE){ CKA_PUBLIC_EXPONENT_, (void*)(uintptr_t)f4, sizeof f4 };
        pub_t[np++]  = (CK_ATTRIBUTE){ CKA_ALLOWED_MECHANISMS_, &allowed, sizeof allowed };
        priv_t[nk++] = (CK_ATTRIBUTE){ CKA_ALLOWED_MECHANISMS_, &allowed, sizeof allowed };
        break;
    case PKIOPS_ALG_MLDSA44: pset = 1; break;       /* CKP_ML_DSA_44 */
    case PKIOPS_ALG_MLDSA65: pset = 2; break;       /* CKP_ML_DSA_65 */
    case PKIOPS_ALG_MLDSA87: pset = 3; break;       /* CKP_ML_DSA_87 */
    case PKIOPS_ALG_COMPOSITE:
    case PKIOPS_ALG_COUNT:
        break;
    }
    if (pset) pub_t[np++] = (CK_ATTRIBUTE){ CKA_PARAMETER_SET_, &pset, sizeof pset };

    CK_OBJECT_HANDLE hp = 0, hk = 0;
    CK_RV rv = p11.GenerateKeyPair((CK_SESSION_HANDLE)session, &m, pub_t, np, priv_t, nk, &hp, &hk);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_GenerateKeyPair failed (0x%lx)\n", (unsigned long)rv);
    *pub = (pkiops_handle)hp;
    *priv = (pkiops_handle)hk;
    return 0;
}

/* The public key as a SubjectPublicKeyInfo, built from the standard
 * attributes rather than from whatever a module returns as a public key's
 * CKA_VALUE -- which the specification leaves undefined for EC, RSA and
 * EdDSA keys, so a hardware module need not answer it. DER, malloc'd. */
static int spki_of(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE hpub, enum pkiops_alg a,
                   uint8_t **der, size_t *der_len, struct p11_err *e) {
    EVP_PKEY *k = NULL;
    uint8_t *v1 = NULL, *v2 = NULL; size_t n1 = 0, n2 = 0;
    int rc = 0;

    if (a == PKIOPS_ALG_COMPOSITE) {
        /* The module's own composite blob, as it has always been read. */
        static uint8_t blob[FHSM_COMPOSITE_PUB_MAX];
        CK_ATTRIBUTE g = { CKA_VALUE, blob, sizeof blob };
        CK_RV rv = p11.GetAttributeValue(s, hpub, &g, 1);
        if (rv != CKR_OK)
            return p11_fail(e, 2, "C_GetAttributeValue(CKA_VALUE) failed (0x%lx)\n", (unsigned long)rv);
        uint8_t *out = malloc(8192); size_t ol = 8192;
        if (!out) return p11_fail(e, 2, "out of memory\n");
        fhsm_rv_t r = fhsm_composite_spki(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                          blob, (size_t)g.ulValueLen, out, &ol);
        if (r != FHSM_RV_OK) { free(out); return p11_fail(e, 2, "the composite public key does not encode (0x%lx)\n", (unsigned long)r); }
        *der = out; *der_len = ol;
        return 0;
    }

    if (a == PKIOPS_ALG_ECDSA_P256 || a == PKIOPS_ALG_ECDSA_P384) {
        size_t raw = a == PKIOPS_ALG_ECDSA_P256 ? 65 : 97;
        const uint8_t *pt = NULL;
        if (get_attr(s, hpub, CKA_EC_POINT_, &v1, &n1, e)) return e->code;
        if (!point_of(v1, n1, raw, &pt)) { rc = p11_fail(e, 2, "CKA_EC_POINT is not an uncompressed point\n"); goto out; }
        OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
        OSSL_PARAM *pa = NULL;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        int ok = b && c
            && OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME,
                   a == PKIOPS_ALG_ECDSA_P256 ? "P-256" : "P-384", 0)
            && OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, pt, raw)
            && (pa = OSSL_PARAM_BLD_to_param(b)) != NULL
            && EVP_PKEY_fromdata_init(c) == 1
            && EVP_PKEY_fromdata(c, &k, EVP_PKEY_PUBLIC_KEY, pa) == 1;
        OSSL_PARAM_free(pa); OSSL_PARAM_BLD_free(b); EVP_PKEY_CTX_free(c);
        if (!ok) { rc = p11_fail(e, 2, "the EC public key does not load\n"); goto out; }
    } else if (a == PKIOPS_ALG_RSA_PSS || a == PKIOPS_ALG_RSA_PKCS1) {
        if (get_attr(s, hpub, CKA_MODULUS_, &v1, &n1, e)
            || get_attr(s, hpub, CKA_PUBLIC_EXPONENT_, &v2, &n2, e)) { rc = e->code; goto out; }
        BIGNUM *bn_n = BN_bin2bn(v1, (int)n1, NULL), *bn_e = BN_bin2bn(v2, (int)n2, NULL);
        OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
        OSSL_PARAM *pa = NULL;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        int ok = bn_n && bn_e && b && c
            && OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_RSA_N, bn_n)
            && OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_RSA_E, bn_e)
            && (pa = OSSL_PARAM_BLD_to_param(b)) != NULL
            && EVP_PKEY_fromdata_init(c) == 1
            && EVP_PKEY_fromdata(c, &k, EVP_PKEY_PUBLIC_KEY, pa) == 1;
        OSSL_PARAM_free(pa); OSSL_PARAM_BLD_free(b); EVP_PKEY_CTX_free(c);
        BN_free(bn_n); BN_free(bn_e);
        if (!ok) { rc = p11_fail(e, 2, "the RSA public key does not load\n"); goto out; }
    } else if (a == PKIOPS_ALG_ED25519) {
        const uint8_t *pt = NULL;
        if (get_attr(s, hpub, CKA_EC_POINT_, &v1, &n1, e)) return e->code;
        if (!point_of(v1, n1, 32, &pt)) { rc = p11_fail(e, 2, "CKA_EC_POINT is not an Ed25519 key\n"); goto out; }
        k = EVP_PKEY_new_raw_public_key_ex(NULL, "ED25519", NULL, pt, 32);
        if (!k) { rc = p11_fail(e, 2, "the Ed25519 public key does not load\n"); goto out; }
    } else {
        const char *nm = a == PKIOPS_ALG_MLDSA44 ? "ML-DSA-44"
                       : a == PKIOPS_ALG_MLDSA65 ? "ML-DSA-65" : "ML-DSA-87";
        if (get_attr(s, hpub, CKA_VALUE, &v1, &n1, e)) return e->code;
        k = EVP_PKEY_new_raw_public_key_ex(NULL, nm, NULL, v1, n1);
        if (!k) { rc = p11_fail(e, 2, "the ML-DSA public key does not load\n"); goto out; }
    }
    {
        uint8_t *d = NULL;
        int dl = i2d_PUBKEY(k, &d);
        if (dl <= 0) { rc = p11_fail(e, 2, "the public key does not encode\n"); goto out; }
        *der = malloc((size_t)dl);
        if (!*der) { OPENSSL_free(d); rc = p11_fail(e, 2, "out of memory\n"); goto out; }
        memcpy(*der, d, (size_t)dl);
        *der_len = (size_t)dl;
        OPENSSL_free(d);
    }
out:
    EVP_PKEY_free(k); free(v1); free(v2);
    return rc;
}

/* A signer that reaches the module, for any of the algorithms. */
struct tsigner { CK_SESSION_HANDLE s; CK_OBJECT_HANDLE priv; enum pkiops_alg alg; };

static fhsm_rv_t tok_sign(void *vctx, const uint8_t *tbs, size_t tbs_len,
                          uint8_t *sig, size_t *sig_len) {
    struct tsigner *g = vctx;
    if (g->alg == PKIOPS_ALG_COMPOSITE) {
        /* The composite's path, unchanged. */
        struct signer sg = { g->s, g->priv };
        return p11_sign(&sg, tbs, tbs_len, sig, sig_len);
    }
    CK_MECHANISM m; ck_pss_params pss;
    alg_mechanism(g->alg, &m, &pss);
    CK_RV rv = p11.SignInit(g->s, &m, g->priv);
    if (rv != CKR_OK) return (fhsm_rv_t)rv;
    static uint8_t raw[FHSM_PKI_SIG_MAX];
    CK_ULONG n = sizeof raw;
    rv = p11.Sign(g->s, (CK_BYTE*)(uintptr_t)tbs, (CK_ULONG)tbs_len, raw, &n);
    if (rv != CKR_OK) return (fhsm_rv_t)rv;
    /* PKCS#11 gives ECDSA as r || s; X.509 and CMS carry DER. */
    if (ALG[g->alg].ecdsa_half) return fhsm_pki_ecdsa_raw_to_der(raw, (size_t)n, sig, sig_len);
    if ((size_t)n > *sig_len) return FHSM_RV_BUFFER_TOO_SMALL;
    memcpy(sig, raw, (size_t)n);
    *sig_len = (size_t)n;
    return FHSM_RV_OK;
}

/* The key labelled `label`, ready to sign: its private half, its algorithm,
 * and the signer for fhsm_pki. With `want_spki`, its public key as well --
 * looked up first, as the request and root builders always did, so a missing
 * label is reported the same way. `*spki` is malloc'd. */
static int token_signer(CK_SESSION_HANDLE s, const char *label, int want_spki,
                        struct tsigner *ts, fhsm_pki_signer_t *ps,
                        uint8_t **spki, struct p11_err *e) {
    CK_OBJECT_HANDLE hpub = 0, hpriv = 0;
    if (want_spki && p11_find_one_e(s, CKO_PUBLIC_KEY, label, &hpub, e)) return e->code;
    if (p11_find_one_e(s, CKO_PRIVATE_KEY, label, &hpriv, e)) return e->code;
    enum pkiops_alg a;
    if (alg_of(s, label, hpriv, &a, e)) return e->code;
    const uint8_t *ad = NULL; size_t adl = 0;
    if (fhsm_pki_algid(ALG[a].sig, &ad, &adl) != FHSM_RV_OK)
        return p11_fail(e, 2, "no AlgorithmIdentifier for %s\n", ALG[a].name);
    ts->s = s; ts->priv = hpriv; ts->alg = a;
    *ps = (fhsm_pki_signer_t){ ad, adl, NULL, 0, tok_sign, ts };
    if (want_spki) {
        size_t sl = 0;
        if (spki_of(s, hpub, a, spki, &sl, e)) return e->code;
        ps->spki = *spki; ps->spki_len = sl;
    }
    return 0;
}

int pkiops_csr(pkiops_handle session, const char *label, const char *subject,
               uint8_t *der, size_t *der_len, struct p11_err *e) {
    struct tsigner ts; fhsm_pki_signer_t ps; uint8_t *spki = NULL;
    if (token_signer((CK_SESSION_HANDLE)session, label, 1, &ts, &ps, &spki, e)) {
        free(spki); return e->code;
    }
    fhsm_rv_t r = fhsm_pki_csr(&ps, subject, der, der_len);
    free(spki);
    if (r != FHSM_RV_OK)
        return p11_fail(e, 2, "building the request failed (0x%lx)\n", (unsigned long)r);
    return 0;
}

int pkiops_root(pkiops_handle session, const char *label, const char *subject,
                long serial, int days,
                uint8_t *der, size_t *der_len, struct p11_err *e) {
    struct tsigner ts; fhsm_pki_signer_t ps; uint8_t *spki = NULL;
    if (token_signer((CK_SESSION_HANDLE)session, label, 1, &ts, &ps, &spki, e)) {
        free(spki); return e->code;
    }
    fhsm_rv_t r = fhsm_pki_selfsigned(&ps, subject, serial, days, der, der_len);
    free(spki);
    if (r != FHSM_RV_OK)
        return p11_fail(e, 2, "building the certificate failed (0x%lx)\n", (unsigned long)r);
    return 0;
}

/* --- signing ---------------------------------------------------------------
 *
 * One operation at a time per process, as the module allows one per session:
 * the algorithm the current one began with is kept here, for the ECDSA
 * signature's conversion at the end. */
static enum pkiops_alg g_stream_alg;

int pkiops_sign_begin(pkiops_handle session, const char *label, struct p11_err *e) {
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    CK_OBJECT_HANDLE hpriv = 0;
    if (p11_find_one_e(s, CKO_PRIVATE_KEY, label, &hpriv, e)) return e->code;
    enum pkiops_alg a;
    if (alg_of(s, label, hpriv, &a, e)) return e->code;
    CK_MECHANISM m; ck_pss_params pss;
    alg_mechanism(a, &m, &pss);
    CK_RV rv = p11.SignInit(s, &m, hpriv);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_SignInit failed (0x%lx)\n", (unsigned long)rv);
    g_stream_alg = a;
    return 0;
}

int pkiops_sign_update(pkiops_handle session, const uint8_t *data, size_t len,
                       struct p11_err *e) {
    CK_RV rv = p11.SignUpdate((CK_SESSION_HANDLE)session, (CK_BYTE*)(uintptr_t)data, (CK_ULONG)len);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_SignUpdate failed (0x%lx)\n", (unsigned long)rv);
    return 0;
}

int pkiops_sign_end(pkiops_handle session, uint8_t **sig, size_t *sig_len,
                    struct p11_err *e) {
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    /* Ask the module for the length rather than assuming it: the size is a
     * property of the mechanism, and hard-coding one here is how the RSA
     * query ended up wrong once already. */
    CK_ULONG need = 0;
    CK_RV rv = p11.SignFinal(s, NULL, &need);
    if (rv != CKR_OK)
        return p11_fail(e, 2, "C_SignFinal (size query) failed (0x%lx)\n", (unsigned long)rv);
    CK_BYTE *buf = malloc(need);
    if (!buf) return p11_fail(e, 2, "out of memory\n");
    CK_ULONG n = need;
    rv = p11.SignFinal(s, buf, &n);
    if (rv != CKR_OK) {
        free(buf);
        return p11_fail(e, 2, "C_SignFinal failed (0x%lx)\n", (unsigned long)rv);
    }
    /* ECDSA is written as DER, so that `openssl dgst -verify` and anything
     * else reads it; the module gave r || s. */
    if (ALG[g_stream_alg].ecdsa_half) {
        size_t dl = 2 * (size_t)n + 16;
        uint8_t *d = malloc(dl);
        fhsm_rv_t r = d ? fhsm_pki_ecdsa_raw_to_der(buf, (size_t)n, d, &dl) : FHSM_RV_HOST_MEMORY;
        free(buf);
        if (r != FHSM_RV_OK) { free(d); return p11_fail(e, 2, "encoding the ECDSA signature failed (0x%lx)\n", (unsigned long)r); }
        *sig = d; *sig_len = dl;
        return 0;
    }
    *sig = buf;
    *sig_len = (size_t)n;
    return 0;
}

int pkiops_verify_begin(pkiops_handle session, const char *label, struct p11_err *e) {
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    CK_OBJECT_HANDLE hpub = 0;
    if (p11_find_one_e(s, CKO_PUBLIC_KEY, label, &hpub, e)) return e->code;
    enum pkiops_alg a;
    if (alg_of(s, label, hpub, &a, e)) return e->code;
    CK_MECHANISM m; ck_pss_params pss;
    alg_mechanism(a, &m, &pss);
    CK_RV rv = p11.VerifyInit(s, &m, hpub);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_VerifyInit failed (0x%lx)\n", (unsigned long)rv);
    g_stream_alg = a;
    return 0;
}

int pkiops_verify_update(pkiops_handle session, const uint8_t *data, size_t len,
                         struct p11_err *e) {
    CK_RV rv = p11.VerifyUpdate((CK_SESSION_HANDLE)session, (CK_BYTE*)(uintptr_t)data, (CK_ULONG)len);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_VerifyUpdate failed (0x%lx)\n", (unsigned long)rv);
    return 0;
}

/* An ECDSA signature in DER back to the r || s PKCS#11 wants. 0 if it is not
 * one -- which is a signature that does not match, not a failure to run. */
static int ecdsa_der_to_raw(const uint8_t *der, size_t n, size_t half, uint8_t *raw) {
    const uint8_t *p = der;
    ECDSA_SIG *es = d2i_ECDSA_SIG(NULL, &p, (long)n);
    int ok = es && p == der + n
          && BN_bn2binpad(ECDSA_SIG_get0_r(es), raw, (int)half) == (int)half
          && BN_bn2binpad(ECDSA_SIG_get0_s(es), raw + half, (int)half) == (int)half;
    ECDSA_SIG_free(es);
    return ok;
}

int pkiops_verify_end(pkiops_handle session, const uint8_t *sig, size_t sig_len,
                      int *valid, struct p11_err *e) {
    uint8_t raw[2 * 48];
    if (ALG[g_stream_alg].ecdsa_half) {
        size_t h = ALG[g_stream_alg].ecdsa_half;
        if (!ecdsa_der_to_raw(sig, sig_len, h, raw)) {
            /* Not an ECDSA signature at all. The operation is still ended:
             * the session outlives this call. */
            uint8_t zero[2 * 48] = { 0 };
            (void)p11.VerifyFinal((CK_SESSION_HANDLE)session, zero, (CK_ULONG)(2 * h));
            *valid = 0;
            return 0;
        }
        sig = raw;
        sig_len = 2 * h;
    }
    CK_RV rv = p11.VerifyFinal((CK_SESSION_HANDLE)session, (CK_BYTE*)(uintptr_t)sig, (CK_ULONG)sig_len);
    if (rv == CKR_SIGNATURE_INVALID) { *valid = 0; return 0; }
    if (rv != CKR_OK) return p11_fail(e, 2, "C_VerifyFinal failed (0x%lx)\n", (unsigned long)rv);
    *valid = 1;
    return 0;
}

/* --- CMS ------------------------------------------------------------------ */

struct pkiops_sha512 { EVP_MD *md; EVP_MD_CTX *c; };

/* SHA-512 of a stream. The only thing that has to see the data: with signed
 * attributes the signature covers the attributes, so a file of any size costs
 * exactly one pass and nothing is held. pkiops_sha512_end frees the state
 * whatever happened, so a caller that gives up after a failed update still
 * calls it. */
struct pkiops_sha512 *pkiops_sha512_begin(struct p11_err *e) {
    struct pkiops_sha512 *h = calloc(1, sizeof *h);
    if (h) { h->md = EVP_MD_fetch(NULL, "SHA512", NULL); h->c = EVP_MD_CTX_new(); }
    if (!h || !h->md || !h->c || EVP_DigestInit_ex(h->c, h->md, NULL) != 1) {
        if (h) { EVP_MD_CTX_free(h->c); EVP_MD_free(h->md); free(h); }
        p11_fail(e, 2, "digest init failed\n");
        return NULL;
    }
    return h;
}

int pkiops_sha512_update(struct pkiops_sha512 *h, const uint8_t *data, size_t len,
                         struct p11_err *e) {
    if (EVP_DigestUpdate(h->c, data, len) != 1) return p11_fail(e, 2, "digest failed\n");
    return 0;
}

int pkiops_sha512_end(struct pkiops_sha512 *h, uint8_t out[64], struct p11_err *e) {
    unsigned int l = 0;
    int ok = EVP_DigestFinal_ex(h->c, out, &l) == 1 && l == 64;
    EVP_MD_CTX_free(h->c); EVP_MD_free(h->md); free(h);
    return ok ? 0 : p11_fail(e, 2, "digest failed\n");
}

/* The same for any of the CMS digests. */
struct pkiops_hash { EVP_MD *md; EVP_MD_CTX *c; };

struct pkiops_hash *pkiops_hash_begin(const char *name, struct p11_err *e) {
    struct pkiops_hash *h = calloc(1, sizeof *h);
    if (h) { h->md = name ? EVP_MD_fetch(NULL, name, NULL) : NULL; h->c = EVP_MD_CTX_new(); }
    if (!h || !h->md || !h->c || EVP_DigestInit_ex(h->c, h->md, NULL) != 1) {
        if (h) { EVP_MD_CTX_free(h->c); EVP_MD_free(h->md); free(h); }
        p11_fail(e, 2, "digest init failed\n");
        return NULL;
    }
    return h;
}

int pkiops_hash_update(struct pkiops_hash *h, const uint8_t *data, size_t len,
                       struct p11_err *e) {
    if (EVP_DigestUpdate(h->c, data, len) != 1) return p11_fail(e, 2, "digest failed\n");
    return 0;
}

int pkiops_hash_end(struct pkiops_hash *h, uint8_t out[64], size_t *out_len,
                    struct p11_err *e) {
    unsigned int l = 0;
    int ok = EVP_DigestFinal_ex(h->c, out, &l) == 1;
    EVP_MD_CTX_free(h->c); EVP_MD_free(h->md); free(h);
    if (!ok) return p11_fail(e, 2, "digest failed\n");
    *out_len = l;
    return 0;
}

int pkiops_cms_sign(pkiops_handle session, const char *label,
                    const uint8_t *cert, size_t cert_len,
                    const uint8_t *digest, size_t digest_len,
                    uint8_t *der, size_t *der_len, struct p11_err *e) {
    struct tsigner ts; fhsm_pki_signer_t ps;
    if (token_signer((CK_SESSION_HANDLE)session, label, 0, &ts, &ps, NULL, e)) return e->code;
    fhsm_rv_t r = fhsm_pki_cms(&ps, ALG[ts.alg].digest, cert, cert_len, digest, digest_len,
                               der, der_len);
    if (r != FHSM_RV_OK)
        return p11_fail(e, 2, "building the CMS failed (0x%lx)\n", (unsigned long)r);
    return 0;
}

int pkiops_cms_digest(const uint8_t *cms, size_t cms_len, const char **name) {
    return fhsm_pki_cms_digest(cms, cms_len, name) == FHSM_RV_OK ? 0 : -1;
}

int pkiops_cms_verify(const uint8_t *cms, size_t cms_len,
                      const uint8_t *digest, size_t digest_len,
                      int *verdict, struct p11_err *e) {
    fhsm_rv_t r = fhsm_pki_cms_verify(cms, cms_len, digest, digest_len);
    if (r == FHSM_RV_OK)                { *verdict = 1;  return 0; }
    if (r == FHSM_RV_SIGNATURE_INVALID) { *verdict = 0;  return 0; }
    if (r == FHSM_RV_ARGUMENTS_BAD)     { *verdict = -1; return 0; }
    return p11_fail(e, 2, "verifying the CMS failed (0x%lx)\n", (unsigned long)r);
}

/* --- the certification authority ----------------------------------------- */

int pkiops_issue(pkiops_handle session, const char *label,
                 const uint8_t *ca, size_t ca_len,
                 const uint8_t *csr, size_t csr_len,
                 const char *subject, const char *san,
                 const char *const *crl_urls, size_t n_crl_urls,
                 fhsm_cert_profile_t profile, int days,
                 uint8_t *der, size_t *der_len, int *pop_valid,
                 struct p11_err *e) {
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    struct tsigner ts; fhsm_pki_signer_t ps;
    if (token_signer(s, label, 0, &ts, &ps, NULL, e)) return e->code;
    /* Serials come from the token's own DRBG through C_GenerateRandom -- see
     * p11_rng in tools/p11_util.h. */
    fhsm_rv_t r = fhsm_pki_issue(&ps, ca, ca_len, csr, csr_len,
                                 subject, san, crl_urls, n_crl_urls, profile,
                                 days, p11_rng, &s, der, der_len);
    if (r == FHSM_RV_SIGNATURE_INVALID) { *pop_valid = 0; return 0; }
    if (r != FHSM_RV_OK)
        return p11_fail(e, 2, "issuing the certificate failed (0x%lx)\n", (unsigned long)r);
    *pop_valid = 1;
    return 0;
}

int pkiops_crl(pkiops_handle session, const char *label,
               const uint8_t *ca, size_t ca_len, const fhsm_rev_db_t *db, int days,
               uint8_t **der, size_t *der_len, struct p11_err *e) {
    struct tsigner ts; fhsm_pki_signer_t ps;
    if (token_signer((CK_SESSION_HANDLE)session, label, 0, &ts, &ps, NULL, e)) return e->code;

    fhsm_composite_revoked_t *list = NULL;
    if (db->n) {
        list = calloc(db->n, sizeof *list);
        if (!list) return p11_fail(e, 2, "out of memory\n");
        for (size_t i = 0; i < db->n; i++) {
            int64_t t = 0;
            (void)fhsm_rev_date_to_time(db->e[i].date, &t);  /* validated at load */
            list[i].serial     = db->e[i].serial;
            list[i].serial_len = db->e[i].serial_len;
            list[i].date       = t;
            list[i].reason     = db->e[i].reason;
        }
    }

    size_t cap = 8192 + db->n * 80 + FHSM_PKI_SIG_MAX;
    uint8_t *buf = malloc(cap);
    if (!buf) { free(list); return p11_fail(e, 2, "out of memory\n"); }
    size_t n = cap;
    fhsm_rv_t r = fhsm_pki_crl(&ps, ca, ca_len, list, db->n,
                               db->crl_number, days, buf, &n);
    free(list);
    if (r != FHSM_RV_OK) {
        free(buf);
        return p11_fail(e, 2, "building the revocation list failed (0x%lx)\n", (unsigned long)r);
    }
    *der = buf;
    *der_len = n;
    return 0;
}

int pkiops_ocsp(pkiops_handle session, const char *label,
                const uint8_t *req, size_t req_len,
                const uint8_t *ca, size_t ca_len,
                const uint8_t *responder, size_t responder_len,
                const fhsm_rev_db_t *db, int days, const char *req_name,
                uint8_t **resp, size_t *resp_len, fhsm_ocsp_stats_t *stats,
                struct p11_err *e) {
    struct tsigner ts; fhsm_pki_signer_t ps;
    if (token_signer((CK_SESSION_HANDLE)session, label, 0, &ts, &ps, NULL, e)) return e->code;
    char err[FHSM_REV_ERR_MAX] = "";
    int rc = fhsm_ocsp_answer_ex(req, req_len, ca, ca_len, responder, responder_len,
                                 db, days, req_name, ps.algid, ps.algid_len,
                                 tok_sign, &ts, resp, resp_len, stats, err, sizeof err);
    if (rc != FHSM_REV_OK) return p11_fail(e, rc, "%s", err);
    return 0;
}

/* --- listing -------------------------------------------------------------- */

int pkiops_slots(struct pkiops_slot **out, size_t *n, struct p11_err *e) {
    CK_SLOT_ID *all = NULL, *tok = NULL;
    CK_ULONG n_all = 0, n_tok = 0;
    *out = NULL;
    *n = 0;
    if (p11_enumerate_e(0, &all, &n_all, e)) return e->code;
    if (p11_enumerate_e(1, &tok, &n_tok, e)) { free(all); return e->code; }
    struct pkiops_slot *v = n_all ? calloc(n_all, sizeof *v) : NULL;
    if (n_all && !v) { free(all); free(tok); return p11_fail(e, 2, "out of memory\n"); }
    for (CK_ULONG i = 0; i < n_all; i++) {
        v[i].id = (pkiops_handle)all[i];
        for (CK_ULONG k = 0; k < n_tok; k++) if (tok[k] == all[i]) v[i].has_token = 1;
        if (v[i].has_token) {
            struct tok_info ti;
            memset(&ti, 0, sizeof ti);
            if (p11.GetTokenInfo(all[i], &ti) == CKR_OK)
                field(v[i].label, ti.label, sizeof ti.label);
        }
    }
    free(all); free(tok);
    *out = v;
    *n = (size_t)n_all;
    return 0;
}

/* One class at a time, in batches; the module decides what a session may see
 * -- private keys only once logged in -- and this reports what it was shown. */
static int keys_of_class(CK_SESSION_HANDLE s, CK_ULONG cls,
                         struct pkiops_key **v, size_t *n, size_t *cap,
                         struct p11_err *e) {
    CK_ULONG c = cls;
    CK_ATTRIBUTE t = { CKA_CLASS, &c, sizeof c };
    CK_RV rv = p11.FindObjectsInit(s, &t, 1);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_FindObjectsInit failed (0x%lx)\n", (unsigned long)rv);
    for (;;) {
        CK_OBJECT_HANDLE h[16]; CK_ULONG got = 0;
        rv = p11.FindObjects(s, h, 16, &got);
        if (rv != CKR_OK) {
            p11.FindObjectsFinal(s);
            return p11_fail(e, 2, "C_FindObjects failed (0x%lx)\n", (unsigned long)rv);
        }
        for (CK_ULONG i = 0; i < got; i++) {
            if (*n == *cap) {
                size_t nc = *cap ? *cap * 2 : 16;
                struct pkiops_key *nv = realloc(*v, nc * sizeof *nv);
                if (!nv) { p11.FindObjectsFinal(s); return p11_fail(e, 2, "out of memory\n"); }
                *v = nv; *cap = nc;
            }
            struct pkiops_key *k = &(*v)[(*n)++];
            memset(k, 0, sizeof *k);
            k->handle = (pkiops_handle)h[i];
            k->is_private = (cls == CKO_PRIVATE_KEY);
            char lbl[256]; CK_ULONG kt = 0;
            CK_ATTRIBUTE a[2] = { { CKA_LABEL, lbl, sizeof lbl },
                                  { CKA_KEY_TYPE_, &kt, sizeof kt } };
            /* A key without a label, or one too long for the buffer, still
             * lists: the handle identifies it, the label only names it. */
            if (p11.GetAttributeValue(s, h[i], a, 2) == CKR_OK) {
                size_t ln = a[0].ulValueLen < sizeof k->label - 1 ? (size_t)a[0].ulValueLen
                                                                  : sizeof k->label - 1;
                memcpy(k->label, lbl, ln);
                k->label[ln] = '\0';
                k->key_type = (unsigned long)kt;
            }
        }
        if (got < 16) break;
    }
    p11.FindObjectsFinal(s);
    return 0;
}

int pkiops_keys(pkiops_handle session, struct pkiops_key **out, size_t *n,
                struct p11_err *e) {
    struct pkiops_key *v = NULL;
    size_t cnt = 0, cap = 0;
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    if (keys_of_class(s, CKO_PUBLIC_KEY,  &v, &cnt, &cap, e) ||
        keys_of_class(s, CKO_PRIVATE_KEY, &v, &cnt, &cap, e)) {
        free(v);
        return e->code;
    }
    /* Each key's algorithm, once the search is over: reading it may need a
     * search of its own -- the public half, for a curve or a parameter set --
     * and a session holds one at a time. A key it cannot name is listed
     * without one. */
    for (size_t i = 0; i < cnt; i++) {
        enum pkiops_alg a;
        struct p11_err ignored;
        if (v[i].label[0]
            && alg_of(s, v[i].label, (CK_OBJECT_HANDLE)v[i].handle, &a, &ignored) == 0)
            snprintf(v[i].alg, sizeof v[i].alg, "%s", ALG[a].name);
    }
    *out = v;
    *n = cnt;
    return 0;
}
