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

static const char *mech_name(CK_ULONG m, char buf[24]) {
    if (m == CKM_COMPOSITE_MLDSA65_ED25519) return "CKM_COMPOSITE_MLDSA65_ED25519";
    snprintf(buf, 24, "mechanism 0x%lx", (unsigned long)m);
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
                       : t[i].type == 0x100UL   ? "CKA_KEY_TYPE" : NULL;
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
    char mb[24];
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
    char mb[24];
    logcall("C_DigestInit", rv, t, "session %lu, %s", (unsigned long)s,
            m ? mech_name(m->mechanism, mb) : "no mechanism");
    return rv;
}
static CK_RV w_SignInit(CK_SESSION_HANDLE s, CK_MECHANISM *m, CK_OBJECT_HANDLE k) {
    double t = now_ms(); CK_RV rv = real.SignInit(s, m, k);
    char mb[24];
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
    char mb[24];
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
    char mb[24];
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
    if (p11_load_module_e(module, e)) return e->code;
    install_wrappers();
    CK_RV rv = p11.Initialize(NULL);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_Initialize failed (0x%lx)\n", (unsigned long)rv);
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

/* --- keys and requests ---------------------------------------------------- */

int pkiops_keygen(pkiops_handle session, const char *label,
                  pkiops_handle *pub, pkiops_handle *priv, struct p11_err *e) {
    CK_MECHANISM m = { CKM_COMPOSITE_MLDSA65_ED25519, NULL, 0 };
    CK_BYTE t = 1;
    CK_ATTRIBUTE pub_t[]  = { {CKA_LABEL,(void*)label,(CK_ULONG)strlen(label)},
                               {CKA_TOKEN,&t,1} };
    CK_ATTRIBUTE priv_t[] = { {CKA_LABEL,(void*)label,(CK_ULONG)strlen(label)},
                               {CKA_TOKEN,&t,1} };
    CK_OBJECT_HANDLE hp = 0, hk = 0;
    CK_RV rv = p11.GenerateKeyPair((CK_SESSION_HANDLE)session, &m, pub_t, 2, priv_t, 2, &hp, &hk);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_GenerateKeyPair failed (0x%lx)\n", (unsigned long)rv);
    *pub = (pkiops_handle)hp;
    *priv = (pkiops_handle)hk;
    return 0;
}

/* The key pair labelled `label`, its public value read back, and a signer
 * that signs through the module with its private half. */
static int key_and_signer(CK_SESSION_HANDLE s, const char *label,
                          uint8_t *pub, size_t *pub_len, struct signer *sg,
                          struct p11_err *e) {
    CK_OBJECT_HANDLE hpub = 0, hpriv = 0;
    if (p11_find_one_e(s, CKO_PUBLIC_KEY,  label, &hpub,  e)) return e->code;
    if (p11_find_one_e(s, CKO_PRIVATE_KEY, label, &hpriv, e)) return e->code;
    CK_ATTRIBUTE g = { CKA_VALUE, pub, (CK_ULONG)*pub_len };
    CK_RV rv = p11.GetAttributeValue(s, hpub, &g, 1);
    if (rv != CKR_OK)
        return p11_fail(e, 2, "C_GetAttributeValue(CKA_VALUE) failed (0x%lx)\n", (unsigned long)rv);
    *pub_len = (size_t)g.ulValueLen;
    sg->s = s;
    sg->priv = hpriv;
    return 0;
}

int pkiops_csr(pkiops_handle session, const char *label, const char *subject,
               uint8_t *der, size_t *der_len, struct p11_err *e) {
    static uint8_t pub[FHSM_COMPOSITE_PUB_MAX];
    size_t pub_len = sizeof pub;
    struct signer sg;
    if (key_and_signer((CK_SESSION_HANDLE)session, label, pub, &pub_len, &sg, e)) return e->code;
    fhsm_rv_t r = fhsm_composite_csr(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                     subject, pub, pub_len, p11_sign, &sg, der, der_len);
    if (r != FHSM_RV_OK)
        return p11_fail(e, 2, "building the request failed (0x%lx)\n", (unsigned long)r);
    return 0;
}

int pkiops_root(pkiops_handle session, const char *label, const char *subject,
                long serial, int days,
                uint8_t *der, size_t *der_len, struct p11_err *e) {
    static uint8_t pub[FHSM_COMPOSITE_PUB_MAX];
    size_t pub_len = sizeof pub;
    struct signer sg;
    if (key_and_signer((CK_SESSION_HANDLE)session, label, pub, &pub_len, &sg, e)) return e->code;
    fhsm_rv_t r = fhsm_composite_selfsigned(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                            subject, serial, days, pub, pub_len,
                                            p11_sign, &sg, der, der_len);
    if (r != FHSM_RV_OK)
        return p11_fail(e, 2, "building the certificate failed (0x%lx)\n", (unsigned long)r);
    return 0;
}

/* --- signing -------------------------------------------------------------- */

int pkiops_sign_begin(pkiops_handle session, const char *label, struct p11_err *e) {
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    CK_OBJECT_HANDLE hpriv = 0;
    if (p11_find_one_e(s, CKO_PRIVATE_KEY, label, &hpriv, e)) return e->code;
    CK_MECHANISM m = { CKM_COMPOSITE_MLDSA65_ED25519, NULL, 0 };
    CK_RV rv = p11.SignInit(s, &m, hpriv);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_SignInit failed (0x%lx)\n", (unsigned long)rv);
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
    *sig = buf;
    *sig_len = (size_t)n;
    return 0;
}

int pkiops_verify_begin(pkiops_handle session, const char *label, struct p11_err *e) {
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    CK_OBJECT_HANDLE hpub = 0;
    if (p11_find_one_e(s, CKO_PUBLIC_KEY, label, &hpub, e)) return e->code;
    CK_MECHANISM m = { CKM_COMPOSITE_MLDSA65_ED25519, NULL, 0 };
    CK_RV rv = p11.VerifyInit(s, &m, hpub);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_VerifyInit failed (0x%lx)\n", (unsigned long)rv);
    return 0;
}

int pkiops_verify_update(pkiops_handle session, const uint8_t *data, size_t len,
                         struct p11_err *e) {
    CK_RV rv = p11.VerifyUpdate((CK_SESSION_HANDLE)session, (CK_BYTE*)(uintptr_t)data, (CK_ULONG)len);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_VerifyUpdate failed (0x%lx)\n", (unsigned long)rv);
    return 0;
}

int pkiops_verify_end(pkiops_handle session, const uint8_t *sig, size_t sig_len,
                      int *valid, struct p11_err *e) {
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

int pkiops_cms_sign(pkiops_handle session, const char *label,
                    const uint8_t *cert, size_t cert_len, const uint8_t digest[64],
                    uint8_t *der, size_t *der_len, struct p11_err *e) {
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    CK_OBJECT_HANDLE hpriv = 0;
    if (p11_find_one_e(s, CKO_PRIVATE_KEY, label, &hpriv, e)) return e->code;
    struct signer sg = { s, hpriv };
    fhsm_rv_t r = fhsm_composite_cms(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                     cert, cert_len, digest, 64,
                                     p11_sign, &sg, der, der_len);
    if (r != FHSM_RV_OK)
        return p11_fail(e, 2, "building the CMS failed (0x%lx)\n", (unsigned long)r);
    return 0;
}

int pkiops_cms_verify(const uint8_t *cms, size_t cms_len, const uint8_t digest[64],
                      int *verdict, struct p11_err *e) {
    fhsm_rv_t r = fhsm_composite_cms_verify(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                            cms, cms_len, digest, 64);
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
    CK_OBJECT_HANDLE hpriv = 0;
    if (p11_find_one_e(s, CKO_PRIVATE_KEY, label, &hpriv, e)) return e->code;
    struct signer sg = { s, hpriv };
    /* Serials come from the token's own DRBG through C_GenerateRandom -- see
     * p11_rng in tools/p11_util.h. */
    fhsm_rv_t r = fhsm_composite_issue(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                       ca, ca_len, csr, csr_len,
                                       subject, san, crl_urls, n_crl_urls, profile,
                                       days, p11_sign, &sg, p11_rng, &s,
                                       der, der_len);
    if (r == FHSM_RV_SIGNATURE_INVALID) { *pop_valid = 0; return 0; }
    if (r != FHSM_RV_OK)
        return p11_fail(e, 2, "issuing the certificate failed (0x%lx)\n", (unsigned long)r);
    *pop_valid = 1;
    return 0;
}

int pkiops_crl(pkiops_handle session, const char *label,
               const uint8_t *ca, size_t ca_len, const fhsm_rev_db_t *db, int days,
               uint8_t **der, size_t *der_len, struct p11_err *e) {
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    CK_OBJECT_HANDLE hpriv = 0;
    if (p11_find_one_e(s, CKO_PRIVATE_KEY, label, &hpriv, e)) return e->code;
    struct signer sg = { s, hpriv };

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

    size_t cap = 8192 + db->n * 80;
    uint8_t *buf = malloc(cap);
    if (!buf) { free(list); return p11_fail(e, 2, "out of memory\n"); }
    size_t n = cap;
    fhsm_rv_t r = fhsm_composite_crl(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                     ca, ca_len, list, db->n,
                                     db->crl_number, days, p11_sign, &sg, buf, &n);
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
    CK_SESSION_HANDLE s = (CK_SESSION_HANDLE)session;
    CK_OBJECT_HANDLE hpriv = 0;
    if (p11_find_one_e(s, CKO_PRIVATE_KEY, label, &hpriv, e)) return e->code;
    struct signer sg = { s, hpriv };
    char err[FHSM_REV_ERR_MAX] = "";
    int rc = fhsm_ocsp_answer(req, req_len, ca, ca_len, responder, responder_len,
                              db, days, req_name, p11_sign, &sg,
                              resp, resp_len, stats, err, sizeof err);
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

#define CKA_KEY_TYPE_ 0x00000100UL

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
    *out = v;
    *n = cnt;
    return 0;
}
