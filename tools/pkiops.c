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
#include "pkiops.h"
#include "p11_util.h"

/* --- the module ----------------------------------------------------------- */

static int g_initialised;

int pkiops_open(const char *module, long want, enum pkiops_slot_intent intent,
                pkiops_handle *slot, struct p11_err *e) {
    if (p11_load_module_e(module, e)) return e->code;
    CK_RV rv = p11.Initialize(NULL);
    if (rv != CKR_OK) return p11_fail(e, 2, "C_Initialize failed (0x%lx)\n", (unsigned long)rv);
    g_initialised = 1;
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
