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

/* --- algorithms ------------------------------------------------------------
 *
 * Chosen once, when a key pair is generated, and read off the key
 * afterwards: every operation below that signs finds the algorithm itself,
 * from the key's type, curve or parameter set -- and, for RSA, from the
 * CKA_ALLOWED_MECHANISMS keygen set, which says PSS or PKCS#1 v1.5. An RSA
 * key made elsewhere without that attribute signs with PSS. */
enum pkiops_alg {
    PKIOPS_ALG_COMPOSITE = 0,       /* ML-DSA-65 + Ed25519, as before      */
    PKIOPS_ALG_ECDSA_P256,
    PKIOPS_ALG_ECDSA_P384,
    PKIOPS_ALG_RSA_PSS,             /* RSA 3072, RSASSA-PSS with SHA-256    */
    PKIOPS_ALG_RSA_PKCS1,           /* RSA 3072, PKCS#1 v1.5 with SHA-256   */
    PKIOPS_ALG_ED25519,
    PKIOPS_ALG_MLDSA44,
    PKIOPS_ALG_MLDSA65,
    PKIOPS_ALG_MLDSA87,
    PKIOPS_ALG_COUNT
};

/* "ecdsa-p256" and the rest, as the tools take them; NULL out of range. */
const char *pkiops_alg_name(enum pkiops_alg a);
/* Every name, comma-separated, for a help text. */
const char *pkiops_alg_list(void);
/* The name as typed, or 1 (usage) naming the accepted ones. */
int pkiops_alg_parse(const char *name, enum pkiops_alg *out, struct p11_err *e);
/* The digest a CMS made with this algorithm uses: "SHA256", "SHA384" or
 * "SHA512" -- the signature's own hash where it has one. */
const char *pkiops_alg_digest(enum pkiops_alg a);

/* The algorithm of the key labelled `label`, from its public half. */
int pkiops_key_alg(pkiops_handle session, const char *label, enum pkiops_alg *out,
                   struct p11_err *e);

/* --- keys and requests ---------------------------------------------------- */

/* The key objects a session can see -- public ones always, private ones once
 * logged in -- in a malloc'd array the caller frees. */
struct pkiops_key {
    pkiops_handle handle;
    int           is_private;
    unsigned long key_type;     /* CKA_KEY_TYPE */
    char          label[65];    /* truncated if longer */
    char          alg[16];      /* pkiops_alg_name of its algorithm, or "" for
                                 * a key these tools do not sign with or whose
                                 * label is not unique */
};
int pkiops_keys(pkiops_handle session, struct pkiops_key **out, size_t *n,
                struct p11_err *e);

/* A composite (ML-DSA-65 + Ed25519) key pair, both halves on the token. */
int pkiops_keygen(pkiops_handle session, const char *label,
                  pkiops_handle *pub, pkiops_handle *priv, struct p11_err *e);

/* --- objects: listing and deletion (docs/fhsm-crypt-plan.md stage 0) ------- */

enum pkiops_obj_class {
    PKIOPS_OBJ_CERT = 0,
    PKIOPS_OBJ_PUBLIC,
    PKIOPS_OBJ_PRIVATE,
    PKIOPS_OBJ_SECRET,
    PKIOPS_OBJ_COUNT
};
/* Masks for pkiops_objects. */
#define PKIOPS_OBJS_CERTS (1u << PKIOPS_OBJ_CERT)
#define PKIOPS_OBJS_KEYS  ((1u << PKIOPS_OBJ_PUBLIC) | (1u << PKIOPS_OBJ_PRIVATE) | \
                           (1u << PKIOPS_OBJ_SECRET))
#define PKIOPS_OBJS_ALL   (PKIOPS_OBJS_CERTS | PKIOPS_OBJS_KEYS)

/* "certificate", "public key", "private key", "secret key"; NULL out of range. */
const char *pkiops_obj_class_name(enum pkiops_obj_class c);

struct pkiops_object {
    pkiops_handle         handle;
    enum pkiops_obj_class cls;
    unsigned long         key_type;   /* CKA_KEY_TYPE; 0 for a certificate */
    char                  label[65];  /* truncated if longer; "" if none */
    char                  id[41];     /* CKA_ID in hex, first 20 bytes; "" if none */
};
/* The objects of the classes in `classes` a session can see -- private and
 * secret keys only once logged in -- certificates first, in a malloc'd array
 * the caller frees. */
int pkiops_objects(pkiops_handle session, unsigned classes,
                   struct pkiops_object **out, size_t *n, struct p11_err *e);

/* Destroy one object. Cannot be undone: the caller asks first. Refused with a
 * message, not a crash, when the module has no C_DestroyObject. */
int pkiops_destroy(pkiops_handle session, pkiops_handle object, struct p11_err *e);

/* A key pair for `alg`, both halves on the token, the private one sensitive
 * and for signing only. RSA keys are 3072 bits. */
int pkiops_keygen_alg(pkiops_handle session, const char *label, enum pkiops_alg alg,
                      pkiops_handle *pub, pkiops_handle *priv, struct p11_err *e);

/* A PKCS#10 request, or a self-signed root, signed by the key `label` with
 * its own algorithm. DER goes into `der`; `*der_len` is its capacity on entry
 * and the length on return. The public key is built from the standard
 * attributes -- CKA_EC_PARAMS and CKA_EC_POINT, CKA_MODULUS and
 * CKA_PUBLIC_EXPONENT, an ML-DSA key's CKA_VALUE -- so any module that
 * answers them will do. */
int pkiops_csr(pkiops_handle session, const char *label, const char *subject,
               uint8_t *der, size_t *der_len, struct p11_err *e);
int pkiops_root(pkiops_handle session, const char *label, const char *subject,
                long serial, int days,
                uint8_t *der, size_t *der_len, struct p11_err *e);

/* --- signing ---------------------------------------------------------------
 *
 * Raw, detached signatures over data of any size, with the key's own
 * algorithm: begin, feed the data in as many pieces as it takes, end.
 * Reading the data is the caller's business -- a file, a pipe, a buffer -- so
 * nothing here holds the message whole, and the module sees the same bytes
 * however they arrive. (Ed25519 and pure ML-DSA are one-shot algorithms: a
 * module streams them only by holding the parts, as FreeHSM does.)
 *
 * An ECDSA signature is returned, and expected back, as DER -- what OpenSSL
 * and every other verifier reads -- though the module deals in r || s.
 *
 * One operation at a time per process.
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
 * A detached RFC 5652 SignedData over a digest of the data, carrying the
 * signer's certificate. The data is hashed by the caller -- pkiops_hash_*
 * stream it -- so a file of any size costs one pass. Which digest: to sign,
 * pkiops_alg_digest of the key's algorithm; to check, pkiops_cms_digest of
 * the structure. pkiops_sha512_* remain, for SHA-512 alone. */
struct pkiops_sha512;                    /* opaque */
struct pkiops_sha512 *pkiops_sha512_begin(struct p11_err *e);
int  pkiops_sha512_update(struct pkiops_sha512 *h, const uint8_t *data, size_t len,
                          struct p11_err *e);
int  pkiops_sha512_end(struct pkiops_sha512 *h, uint8_t out[64], struct p11_err *e);

struct pkiops_hash;                      /* opaque */
/* `name` is "SHA256", "SHA384" or "SHA512". */
struct pkiops_hash *pkiops_hash_begin(const char *name, struct p11_err *e);
int  pkiops_hash_update(struct pkiops_hash *h, const uint8_t *data, size_t len,
                        struct p11_err *e);
/* Frees `h` whatever happens. */
int  pkiops_hash_end(struct pkiops_hash *h, uint8_t out[64], size_t *out_len,
                     struct p11_err *e);

/* Signed with the key `label`'s algorithm; `digest` must be its
 * pkiops_alg_digest. */
int pkiops_cms_sign(pkiops_handle session, const char *label,
                    const uint8_t *cert, size_t cert_len,
                    const uint8_t *digest, size_t digest_len,
                    uint8_t *der, size_t *der_len, struct p11_err *e);

/* The digest to compute over the data before checking `cms`, in static
 * storage: 0, or -1 when the structure is not one this code can read. */
int pkiops_cms_digest(const uint8_t *cms, size_t cms_len, const char **name);

/* Needs no module and no PIN: the signer's certificate is inside. *verdict is
 * 1 when it verifies, 0 when it does not match the data, and -1 when the
 * structure is not a CMS this code can read. */
int pkiops_cms_verify(const uint8_t *cms, size_t cms_len,
                      const uint8_t *digest, size_t digest_len,
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
