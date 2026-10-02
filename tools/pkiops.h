/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * tools/pkiops.h --- the operations of the PKI tools, as a library.
 *
 *  docs/fhsm-gui-plan.md, stage 0. What fhsm-token, fhsm-csr, fhsm-ca and
 *  fhsm-sign do, minus their command lines: each operation takes values,
 *  returns 0 or a p11_err code, and fills the p11_err with the reason. None
 *  prints, none exits, none reads the environment. The tools parse arguments
 *  and call these; the planned graphical interface calls the same ones.
 *
 *  Messages that speak the command line's language -- "FHSM_PIN is not set",
 *  "pass --force", "--label is at most 32 characters" -- stay in the tools.
 *  What is here returns the facts those messages are built from.
 *
 *  A PIN is passed as bytes and a length and is never kept: the caller owns
 *  it, and the caller zeroes it.
 *
 *  One module at a time, process-wide: pkiops_open loads it, pkiops_close
 *  finalises it, pkiops_unload forgets it so that another can be loaded. This
 *  file is the only one that includes tools/p11_util.h
 *  (see tools/p11_err.h for why).
 * ========================================================================= */
#ifndef FHSM_TOOLS_PKIOPS_H
#define FHSM_TOOLS_PKIOPS_H

#include "p11_err.h"
#include "fhsm_revocation.h"        /* the revocation database and OCSP types */

#include <stddef.h>
#include <stdint.h>

typedef unsigned long pkiops_handle;    /* CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE */

/* Which slot an operation wants when the caller names none. */
enum pkiops_slot_intent {
    PKIOPS_SLOT_WITH_TOKEN,     /* exactly one initialised token, or refuse */
    PKIOPS_SLOT_FOR_INIT,       /* the lowest empty slot */
    PKIOPS_SLOT_ANY             /* the one token, or the first slot if none */
};

/* --- the module ----------------------------------------------------------- */

/* Load the module and C_Initialize it. A module already loaded is unloaded
 * first (pkiops_unload); a load that fails leaves none loaded. */
int  pkiops_load(const char *module, struct p11_err *e);

/* pkiops_load, then resolve the slot: `want` is the slot the caller named, or
 * -1. What the command-line tools use; an interface lists the slots instead
 * and lets the operator choose. */
int  pkiops_open(const char *module, long want, enum pkiops_slot_intent intent,
                 pkiops_handle *slot, struct p11_err *e);
void pkiops_close(void);

/* pkiops_close, then forget the module, so that another -- or the same one
 * again -- can be loaded with pkiops_load. The library is not dlclose'd: a
 * PKCS#11 module, or the libcrypto under it, may have registered handlers to
 * run at process exit, and unmapping their code turns exit into a crash. The
 * mapping stays; nothing calls into it any more. */
void pkiops_unload(void);

/* Every slot the module reports, in a malloc'd array the caller frees. */
struct pkiops_slot {
    pkiops_handle id;
    int  has_token;
    char label[33];             /* the token's, trimmed; empty without one */
};
int pkiops_slots(struct pkiops_slot **out, size_t *n, struct p11_err *e);

/* --- the call log ----------------------------------------------------------
 *
 * Every PKCS#11 call pkiops makes, reported after it returns: the function,
 * a summary of its arguments, its CK_RV, and how long it took. For the
 * exploration interface, which shows the module at work.
 *
 * Never reported: a PIN, or its length, or any attribute value -- the same
 * rule as the module's audit log. A summary says which session, slot, object
 * and mechanism, and how many bytes went in; never which bytes.
 *
 * The callback runs on the thread that made the call. An interface that runs
 * pkiops on a worker thread must hand the record to its own thread before
 * touching a widget. NULL turns the log off. It may be set at any time; set
 * before pkiops_load, it records C_Initialize as well. */
struct pkiops_call {
    const char   *fn;           /* "C_Login" */
    char          args[160];    /* "session 3, CKU_USER, PIN not shown" */
    unsigned long rv;           /* CK_RV */
    double        ms;
};
typedef void (*pkiops_call_cb)(const struct pkiops_call *c, void *ctx);
void pkiops_set_call_log(pkiops_call_cb cb, void *ctx);

/* "--slot" as typed. Refuses what strtol would quietly turn into 0. */
int  pkiops_parse_slot(const char *text, long *out, struct p11_err *e);

/* --- token state ---------------------------------------------------------- */

struct pkiops_token_info {
    char label[33], manufacturer[33], model[17], serial[17];  /* trimmed */
    int  initialised, user_pin_set, so_pin_locked, user_pin_locked;
    unsigned long min_pin, max_pin;
};

int pkiops_token_info(pkiops_handle slot, struct pkiops_token_info *out,
                      struct p11_err *e);

/* C_InitToken, then C_InitPIN as the Security Officer. Destroys every object
 * on the token: whether to ask first is the caller's decision, and
 * pkiops_token_info says whether there is anything to destroy. `label` is at
 * most 32 bytes. */
int pkiops_token_init(pkiops_handle slot,
                      const uint8_t *so_pin, size_t so_len,
                      const uint8_t *user_pin, size_t user_len,
                      const char *label, struct p11_err *e);

/* --- sessions ------------------------------------------------------------- */

/* A read-write session on `slot`, logged in as the user. */
int  pkiops_session_user(pkiops_handle slot, const uint8_t *pin, size_t pin_len,
                         pkiops_handle *session, struct p11_err *e);
void pkiops_session_close(pkiops_handle session);

/* --- keys and requests ---------------------------------------------------- */

/* The key objects a session can see -- public ones always, private ones once
 * logged in -- in a malloc'd array the caller frees. */
struct pkiops_key {
    pkiops_handle handle;
    int           is_private;
    unsigned long key_type;     /* CKA_KEY_TYPE */
    char          label[65];    /* truncated if longer */
};
int pkiops_keys(pkiops_handle session, struct pkiops_key **out, size_t *n,
                struct p11_err *e);

/* A composite (ML-DSA-65 + Ed25519) key pair, both halves on the token. */
int pkiops_keygen(pkiops_handle session, const char *label,
                  pkiops_handle *pub, pkiops_handle *priv, struct p11_err *e);

/* A PKCS#10 request, or a self-signed root, signed by the key `label`. DER
 * goes into `der`; `*der_len` is its capacity on entry and the length on
 * return. */
int pkiops_csr(pkiops_handle session, const char *label, const char *subject,
               uint8_t *der, size_t *der_len, struct p11_err *e);
int pkiops_root(pkiops_handle session, const char *label, const char *subject,
                long serial, int days,
                uint8_t *der, size_t *der_len, struct p11_err *e);

/* --- signing ---------------------------------------------------------------
 *
 * Raw, detached composite signatures over data of any size: begin, feed the
 * data in as many pieces as it takes, end. Reading the data is the caller's
 * business -- a file, a pipe, a buffer -- so nothing here holds the message
 * whole, and the module sees the same bytes however they arrive.
 *
 * A verification that runs and finds the signature does not match is not an
 * error: pkiops_verify_end returns 0 and sets *valid to 0. Only a failure to
 * run returns a code, so a caller can tell "did not verify" from "could not
 * check". */
int pkiops_sign_begin(pkiops_handle session, const char *label, struct p11_err *e);
int pkiops_sign_update(pkiops_handle session, const uint8_t *data, size_t len,
                       struct p11_err *e);
/* The signature in a malloc'd buffer the caller frees. */
int pkiops_sign_end(pkiops_handle session, uint8_t **sig, size_t *sig_len,
                    struct p11_err *e);

int pkiops_verify_begin(pkiops_handle session, const char *label, struct p11_err *e);
int pkiops_verify_update(pkiops_handle session, const uint8_t *data, size_t len,
                         struct p11_err *e);
int pkiops_verify_end(pkiops_handle session, const uint8_t *sig, size_t sig_len,
                      int *valid, struct p11_err *e);

/* --- CMS -------------------------------------------------------------------
 *
 * A detached RFC 5652 SignedData over the SHA-512 of the data, carrying the
 * signer's certificate. The data is hashed by the caller -- pkiops_sha512_*
 * stream it -- so a file of any size costs one pass. */
struct pkiops_sha512;                    /* opaque */
struct pkiops_sha512 *pkiops_sha512_begin(struct p11_err *e);
int  pkiops_sha512_update(struct pkiops_sha512 *h, const uint8_t *data, size_t len,
                          struct p11_err *e);
int  pkiops_sha512_end(struct pkiops_sha512 *h, uint8_t out[64], struct p11_err *e);

int pkiops_cms_sign(pkiops_handle session, const char *label,
                    const uint8_t *cert, size_t cert_len, const uint8_t digest[64],
                    uint8_t *der, size_t *der_len, struct p11_err *e);

/* Needs no module and no PIN: the signer's certificate is inside. *verdict is
 * 1 when it verifies, 0 when it does not match the data, and -1 when the
 * structure is not a composite CMS this code can read. */
int pkiops_cms_verify(const uint8_t *cms, size_t cms_len, const uint8_t digest[64],
                      int *verdict, struct p11_err *e);

/* --- the certification authority -------------------------------------------
 *
 * The three CA operations that sign with the token. Recording a revocation
 * signs nothing and needs no module: it is fhsm_rev_db_* in
 * include/fhsm_revocation.h, which the tool and the interface call directly.
 */

/* Issue a certificate for `csr`, signed by the key `label` under the CA
 * certificate `ca`. The request's proof of possession is checked first: if
 * its signature does not match the key it carries, nothing is issued and
 * *pop_valid is 0 -- a verdict about the request, not a failure to run.
 * `subject` replaces the requested subject when not NULL; `san` and the CRL
 * URLs are as fhsm_composite_issue takes them. */
int pkiops_issue(pkiops_handle session, const char *label,
                 const uint8_t *ca, size_t ca_len,
                 const uint8_t *csr, size_t csr_len,
                 const char *subject, const char *san,
                 const char *const *crl_urls, size_t n_crl_urls,
                 fhsm_cert_profile_t profile, int days,
                 uint8_t *der, size_t *der_len, int *pop_valid,
                 struct p11_err *e);

/* A CRL listing every entry of `db`, numbered `db->crl_number` -- advancing
 * it, and saving the database before the list is published, is the caller's
 * job, because the order is what makes a number unique. The DER is in a
 * malloc'd buffer the caller frees. */
int pkiops_crl(pkiops_handle session, const char *label,
               const uint8_t *ca, size_t ca_len, const fhsm_rev_db_t *db, int days,
               uint8_t **der, size_t *der_len, struct p11_err *e);

/* Answer one OCSP request from `db`, signed by the key `label`. `responder` is
 * the certificate that answers -- the CA's own, or a delegate already checked
 * with fhsm_ocsp_check_responder. `req_name` names the request in messages.
 * The response is in a malloc'd buffer the caller frees. */
int pkiops_ocsp(pkiops_handle session, const char *label,
                const uint8_t *req, size_t req_len,
                const uint8_t *ca, size_t ca_len,
                const uint8_t *responder, size_t responder_len,
                const fhsm_rev_db_t *db, int days, const char *req_name,
                uint8_t **resp, size_t *resp_len, fhsm_ocsp_stats_t *stats,
                struct p11_err *e);

#endif /* FHSM_TOOLS_PKIOPS_H */
