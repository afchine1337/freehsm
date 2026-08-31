/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm_revocation --- the revocation database, and answering an OCSP request
 *                     from it (#111, #163).
 *
 * Why this file exists
 * --------------------
 * All of this was written inside tools/fhsm_ca.c, where it was reached only by
 * `fhsm-ca ocsp-respond`: a file in, a file out, one operator at a keyboard.
 * The service now has to answer the same question on a socket. Copying the
 * code would have given two implementations of "is this serial revoked" that
 * agree on the day they are written and drift afterwards -- and a responder
 * that has drifted answers `good` for a certificate the CA revoked, which is
 * the one wrong answer OCSP exists to prevent. ALC_DVS names that hazard for
 * the fuzz harnesses already; it would be worse here.
 *
 * So the tool and the service call the same functions. The tool keeps its
 * messages and its exit codes -- those are its interface, and tests assert on
 * them -- but it no longer owns the logic behind them.
 *
 * What changed in the move
 * ------------------------
 * Two things a command-line tool may do and a daemon may not:
 *
 *   1. exit().  A malformed database line ended the process. In a service that
 *      is a request that must be refused, not a reason to stop answering the
 *      others. Every function here returns a status and writes the diagnostic
 *      into a caller-supplied buffer; fhsm-ca prints it and exits, the service
 *      turns it into a status code and an audit line.
 *
 *   2. static buffers.  The tool's file reader parked bytes in a `static`
 *      array, which is fine for one operator and is a data race in a threaded
 *      service -- the same defect that gave fifteen of sixteen concurrent
 *      clients another client's signature earlier in #111. Nothing here holds
 *      state between calls.
 *
 * The database is also no longer allocated at full size on every load. The
 * tool could afford calloc(100000) once per run; a responder answering
 * requests cannot afford 8 MB per request. It grows instead, to the same cap.
 * ========================================================================= */
#ifndef FHSM_REVOCATION_H
#define FHSM_REVOCATION_H

#include "fhsm_common.h"
#include "fhsm_composite.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The cap is a refusal, not a truncation: a database larger than this is not
 * quietly half-read. See the note on partial reads below. */
#define FHSM_REV_MAX_ENTRIES 100000

/* Enough for the longest diagnostic below, which is a paragraph rather than a
 * line: the operator who sees it is being told why nothing was read. */
#define FHSM_REV_ERR_MAX     640

/* Status codes. These are fhsm-ca's exit codes, kept as they were so the tool
 * can return them unchanged:
 *   2  the caller got something wrong, or the machine did (unreadable file,
 *      out of memory, a path that does not fit)
 *   3  the database itself could not be understood                          */
#define FHSM_REV_OK      0
#define FHSM_REV_EIO     2
#define FHSM_REV_EPARSE  3

/* ---------------------------------------------------------------------------
 * Revocation reasons (RFC 5280 5.3.1).
 *
 * Code 7 is not assigned. Code 8 (removeFromCRL) belongs to delta CRLs, which
 * nothing here produces, so neither is accepted -- accepting a reason we
 * cannot honour would put it in a list that means something else.
 * ------------------------------------------------------------------------- */
int         fhsm_rev_reason_code(const char *name);   /* -2 unknown, -1 none */
const char *fhsm_rev_reason_name(int code);           /* NULL if unknown     */

/* The accepted names, comma-separated, for a caller printing its own help. */
const char *fhsm_rev_reason_list(void);

/* ---------------------------------------------------------------------------
 * Serials, dates.
 * ------------------------------------------------------------------------- */

/* Hex to bytes. An odd number of digits is refused rather than padded: it is
 * ambiguous which end the missing nibble belongs to, and guessing produces a
 * serial that matches no certificate. Returns 1 on success. */
int fhsm_rev_hex_to_bytes(const char *h, uint8_t *out, size_t cap, size_t *n);

/* "YYYYMMDDHHMMSSZ" to seconds since the epoch, UTC. Returns 1 on success. */
int fhsm_rev_date_to_time(const char *s, int64_t *out);

/* The reverse. Returns 1, or 0 for a year that will not fit the fifteen-
 * character form -- which time(NULL) cannot reach, but the buffer must not be
 * the thing that decides that. */
int fhsm_rev_time_to_date(int64_t when, char out[16]);

/* Compare two serials ignoring leading zeros on both sides: DER adds one to
 * keep a top-bit-set magnitude positive, and an operator typing the serial in
 * hex will not have. Returns 1 when they are the same number. */
int fhsm_rev_serial_eq(const uint8_t *a, size_t na, const uint8_t *b, size_t nb);

/* ---------------------------------------------------------------------------
 * The database.
 *
 * One line per entry, in a file the operator can read, diff, grep and put
 * under version control:
 *
 *     # fhsm-ca revocation database v1
 *     crlNumber 7
 *     4A3B2C1D 20260714033320Z keyCompromise
 *     F00D     20260719222640Z -
 *
 * crlNumber lives in the same file as the entries on purpose. Two files can be
 * backed up, copied or restored separately, and a number that goes backwards
 * relative to its list is exactly the failure it exists to prevent.
 *
 * Anything malformed makes the whole file a refusal, never a partial read. A
 * database half-parsed produces a list missing revocations, and a list missing
 * revocations is worse than none: it is a signed assurance that a compromised
 * certificate is still good. Skipping a line we do not understand would be the
 * quiet version of that.
 *
 * There is no locking. Writes go to a temporary file and are renamed into
 * place, so an interrupted write leaves the previous database whole; two
 * writers at the same moment is a situation this does not handle, and saying
 * so is more useful than a lock that would only narrow the window. The service
 * only ever reads.
 * ------------------------------------------------------------------------- */
typedef struct {
    uint8_t serial[64];
    size_t  serial_len;
    char    date[16];          /* YYYYMMDDHHMMSSZ, NUL-terminated */
    int     reason;            /* RFC 5280 code, or -1 for none   */
} fhsm_rev_entry_t;

typedef struct {
    unsigned long long crl_number;
    fhsm_rev_entry_t  *e;
    size_t             n;
    size_t             cap;    /* allocated, not used */
} fhsm_rev_db_t;

/* Load, or start empty if the file does not exist. A file that exists but
 * cannot be read is an error rather than a first run: it is more likely a
 * permissions or path mistake, and treating it as a first run loses every
 * revocation recorded so far.
 *
 * `err` receives the full diagnostic on failure -- the same text fhsm-ca used
 * to print, including the line number and the reason it matters. Pass NULL if
 * the caller has nowhere to put it. */
int fhsm_rev_db_load(const char *path, fhsm_rev_db_t *d,
                     char *err, size_t err_cap);

int fhsm_rev_db_save(const char *path, const fhsm_rev_db_t *d,
                     char *err, size_t err_cap);

/* Append, growing as needed. Returns FHSM_REV_EIO at the cap or out of
 * memory. The caller checks for an existing entry first: silently accepting a
 * second revocation of the same serial would either duplicate it in every
 * future list or move its date, and the date is what tells a verifier when to
 * stop trusting signatures made with that certificate. */
int fhsm_rev_db_add(fhsm_rev_db_t *d, const fhsm_rev_entry_t *e,
                    char *err, size_t err_cap);

/* The entry for this serial, or NULL. Leading-zero insensitive. */
const fhsm_rev_entry_t *fhsm_rev_db_find(const fhsm_rev_db_t *d,
                                          const uint8_t *serial, size_t n);

void fhsm_rev_db_free(fhsm_rev_db_t *d);

/* ---------------------------------------------------------------------------
 * Answering an OCSP request.
 *
 * On computing SHA-1 here
 * -----------------------
 * The CertID in a request carries hashes of the issuer name and issuer public
 * key under an algorithm the *client* chose, and OpenSSL's own client still
 * chooses SHA-1. To know which certificate is being asked about, a responder
 * has to recompute those hashes with that same algorithm.
 *
 * So this computes SHA-1 when a client asks in SHA-1. That is not a signature:
 * SP 800-131A withdraws SHA-1 for signature generation, not for
 * identification, and a CertID identifies. It proves nothing and is relied on
 * for nothing -- the answer's integrity comes from the composite signature
 * over the whole response.
 *
 * It also stays out of the module. This is OpenSSL's SHA-1, in code the module
 * does not link; the fips-strict profile is not asked to provide it, and does
 * not. That is why this file is not in LIB_SRC.
 * ------------------------------------------------------------------------- */
typedef struct {
    size_t asked;              /* CertIDs in the request              */
    size_t ours;               /* about a certificate this CA issued  */
    size_t revoked;
    size_t unknown;            /* another issuer, or an unknown hash  */
    int    nonce_echoed;
} fhsm_ocsp_stats_t;

/* Parse an OCSPRequest, answer every question in it from `db`, sign the
 * result, and produce a complete OCSPResponse -- responseStatus and all, not
 * just the BasicOCSPResponse that fhsm_composite_ocsp() returns.
 *
 * `responder_der` is the certificate that signs and whose name appears as the
 * responder: one certificate, one identity, no way for the two to disagree.
 * Pass the CA's own certificate when the CA answers for itself. Whether that
 * certificate is *allowed* to answer -- extendedKeyUsage OCSPSigning, issued
 * by this CA -- is checked by fhsm_ocsp_check_responder() below, separately,
 * because the caller may want to check it once at start rather than per
 * request.
 *
 * `req_label` names the request in diagnostics -- the file name for a tool
 * with a --req flag, NULL for a socket, where there is no name to give. The
 * same reason check_responder() takes paths: an error that says which input
 * was wrong saves the operator a guess, and the library does not know.
 *
 * `*out` is allocated here and belongs to the caller: the size depends on the
 * request, and every caller that guessed a cap for it guessed differently.
 *
 * Returns FHSM_REV_OK, or FHSM_REV_EPARSE for a request that is not one, or
 * FHSM_REV_EIO. On failure `*out` is NULL and `err` says why. */
int fhsm_ocsp_answer(const uint8_t *req, size_t req_len,
                     const uint8_t *ca_der, size_t ca_len,
                     const uint8_t *responder_der, size_t responder_len,
                     const fhsm_rev_db_t *db, int days,
                     const char *req_label,
                     fhsm_composite_sign_cb sign, void *sign_ctx,
                     uint8_t **out, size_t *out_len,
                     fhsm_ocsp_stats_t *stats,
                     char *err, size_t err_cap);

/* ---------------------------------------------------------------------------
 * The answers that are not answers.
 *
 * RFC 6960 4.2.1: an OCSPResponse whose responseStatus is anything but
 * successful(0) carries no responseBytes, and therefore no signature. That is
 * deliberate in the RFC and worth restating here, because it looks like a
 * gap: a responder that has not parsed the request has nothing to sign *for*,
 * and signing "your request was malformed" would let anyone who can reach the
 * socket obtain a signature over a chosen-ish object. The client is expected
 * to treat these as transport-level failures, not as statements about a
 * certificate -- and it can, because none of them says anything about one.
 *
 * Five bytes: SEQUENCE { ENUMERATED status }.
 *
 * Returns the length written, or 0 for a status this will not encode --
 * including successful(0), which without responseBytes is malformed, and is
 * the one mistake a caller reaching for this function is likely to make.
 * ------------------------------------------------------------------------- */
#define FHSM_OCSP_RESP_SUCCESSFUL  0
#define FHSM_OCSP_RESP_MALFORMED   1
#define FHSM_OCSP_RESP_INTERNAL    2
#define FHSM_OCSP_RESP_TRYLATER    3
/* 4 is not assigned. 5 sigRequired and 6 unauthorized exist; neither is
 * reachable from a responder that requires no signature on the request and
 * refuses nobody, so neither is offered until something can produce it. */

size_t fhsm_ocsp_status_response(int status, uint8_t out[5]);

/* Would a verifier accept answers signed by this certificate?
 *
 * Both checks are about what happens at the far end. Producing responses
 * nobody accepts is a failure an operator discovers in production, and this is
 * a desk where it can be caught instead.
 *
 * The issuer check compares names, and a name is not a signature. Verifying
 * that this CA really issued the delegate would mean checking a composite
 * signature, which nothing off the shelf can do -- the same limit recorded for
 * CSRs and CRLs. So it catches the ordinary mistake, the wrong file, and not a
 * forgery.
 *
 * Returns FHSM_REV_OK, or FHSM_REV_EPARSE with `err` naming what is missing
 * and how to get it. */
int fhsm_ocsp_check_responder(const uint8_t *responder_der, size_t responder_len,
                              const uint8_t *ca_der, size_t ca_len,
                              const char *responder_path, const char *ca_path,
                              char *err, size_t err_cap);

#ifdef __cplusplus
}
#endif
#endif /* FHSM_REVOCATION_H */
