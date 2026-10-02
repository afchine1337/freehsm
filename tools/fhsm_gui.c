/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * fhsm-gui --- a desktop interface over the PKI tools' operations.
 *
 *  docs/fhsm-gui-plan.md, stage 1: exploration. Load a PKCS#11 module, see its
 *  slots, log in, list the keys, generate a composite key pair -- and watch
 *  every PKCS#11 call that makes, as it happens, in the log on the right.
 *
 *  Stage 2, the Certificates tab: a certification request and a self-signed
 *  root (what fhsm-csr does), and issuing a certificate from a request (what
 *  fhsm-ca issue does), with the same defaults: a root for 3650 days, serial
 *  1; a certificate for 365 days, or 30 for a delegated OCSP responder.
 *  Inputs are read as DER or PEM; output is written as either.
 *
 *  Stage 3, the Revocation tab: what fhsm-ca revoke, crl and ocsp-respond do,
 *  on the same database file and in the same order. Recording a revocation
 *  signs nothing and needs no login; publishing a CRL and answering an OCSP
 *  request do. A new database is never written over an existing file.
 *
 *  Everything it does goes through tools/pkiops, the same operations the
 *  command-line tools call, so the window adds no second way of talking to
 *  the module. Every pkiops call runs on a worker thread, one at a time, so
 *  the window stays responsive through a 200,000-iteration PIN derivation; the
 *  call log is produced on that thread and handed to this one before it
 *  touches a widget.
 *
 *  The PIN. Typed into a GtkPasswordEntry, copied into a buffer this program
 *  owns, the entry cleared at once, and the buffer wiped with OPENSSL_cleanse
 *  as soon as C_Login has answered. That is weaker than the module's own
 *  handling, and said here rather than hidden: GTK may copy what is typed
 *  internally, and the password entry's own buffer is locked against swapping
 *  only if RLIMIT_MEMLOCK has room left. Once a FreeHSM module is loaded it
 *  usually has none -- the module's secure heap is sized to the whole default
 *  limit -- and GTK says "couldn't lock 16384 bytes of memory" and carries on
 *  with ordinary memory. What this program guarantees is narrower -- the PIN is
 *  never an argument, never in the environment, never written anywhere, never
 *  in the call log, and held no longer than the toolkit allows.
 *
 *  Logging out closes the session: since v2.3.0 the module logs the token out
 *  when its last session closes. Unloading closes the session if there is one,
 *  finalises the module and forgets it, so that another can be loaded.
 *
 *  Build: make gui (needs libgtk-4-dev; not part of `make all`).
 * ========================================================================= */
#include "pkiops.h"

#include <gtk/gtk.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* --- state -------------------------------------------------------------- */

static struct {
    GtkWidget *win;
    GtkWidget *module_entry, *load_btn, *unload_btn;
    GtkWidget *slots_box;
    GtkWidget *pin_entry, *login_btn, *logout_btn;
    GtkWidget *keys_box, *label_entry, *keygen_btn;
    GtkWidget *log_view, *status;

    /* The Certificates tab. */
    GtkWidget *cert_page, *key_drop, *pem_check;
    GtkStringList *key_labels;      /* the private keys' labels; owned by key_drop */
    GtkWidget *subject_entry, *serial_spin, *root_days_spin;
    GtkWidget *ca_btn, *csr_btn, *issue_subject_entry, *san_entry, *crl_view;
    GtkWidget *profile_drop, *issue_days_spin;
    char *ca_path, *csr_path;

    /* The Revocation tab. */
    GtkWidget *rv_db_box, *rv_revoke_box, *rv_sign_box;
    GtkWidget *db_btn, *db_info, *db_list;
    GtkWidget *serial_entry, *reason_drop, *date_entry;
    GtkWidget *rv_key_drop, *rv_ca_btn, *crl_days_spin, *crl_pem_check;
    GtkWidget *req_btn, *responder_btn, *ocsp_days_spin;
    char *db_path, *rv_ca_path, *req_path, *responder_path;

    int loaded, logged_in, busy;
    int closing;                    /* the widgets are going: touch none */
    struct pkiops_slot *slots;
    size_t n_slots;
    long selected;                  /* index into slots, or -1 */
    pkiops_handle session;
} A = { .selected = -1 };

/* --- the call log ------------------------------------------------------- */

static const char *rv_name(unsigned long rv) {
    switch (rv) {
    case 0x00000000UL: return "CKR_OK";
    case 0x00000005UL: return "CKR_GENERAL_ERROR";
    case 0x00000006UL: return "CKR_FUNCTION_FAILED";
    case 0x00000007UL: return "CKR_ARGUMENTS_BAD";
    case 0x00000070UL: return "CKR_MECHANISM_INVALID";
    case 0x00000082UL: return "CKR_OBJECT_HANDLE_INVALID";
    case 0x000000A0UL: return "CKR_PIN_INCORRECT";
    case 0x000000A4UL: return "CKR_PIN_LOCKED";
    case 0x000000B3UL: return "CKR_SESSION_HANDLE_INVALID";
    case 0x000000E0UL: return "CKR_TOKEN_NOT_PRESENT";
    case 0x00000100UL: return "CKR_USER_ALREADY_LOGGED_IN";
    case 0x00000101UL: return "CKR_USER_NOT_LOGGED_IN";
    case 0x00000104UL: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
    case 0x00000150UL: return "CKR_BUFFER_TOO_SMALL";
    case 0x00000190UL: return "CKR_CRYPTOKI_NOT_INITIALIZED";
    case 0x00000191UL: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
    case 0x80000004UL: return "vendor: PIN throttled";
    default:           return NULL;
    }
}

/* One record, copied off the worker thread. */
struct logline { char text[1024]; };   /* generous: a %.1f of a double is unbounded to the compiler */

static gboolean append_log(gpointer data) {
    struct logline *l = data;
    if (A.closing) { g_free(l); return G_SOURCE_REMOVE; }
    GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(A.log_view));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(b, &end);
    gtk_text_buffer_insert(b, &end, l->text, -1);
    gtk_text_buffer_get_end_iter(b, &end);
    GtkTextMark *m = gtk_text_buffer_create_mark(b, NULL, &end, FALSE);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(A.log_view), m);
    gtk_text_buffer_delete_mark(b, m);
    g_free(l);
    return G_SOURCE_REMOVE;
}

/* Called by pkiops on whichever thread made the call. Formats, then hands the
 * line to the main loop; no widget is touched here. */
static void on_call(const struct pkiops_call *c, void *ctx) {
    (void)ctx;
    struct logline *l = g_new(struct logline, 1);
    /* 48, not 16: the compiler cannot know the fields are two digits, and
     * -Wformat-truncation under -Werror is right to make it say so. */
    char when[48];
    GDateTime *now = g_date_time_new_now_local();
    snprintf(when, sizeof when, "%02d:%02d:%02d.%03d",
             g_date_time_get_hour(now), g_date_time_get_minute(now),
             g_date_time_get_second(now), g_date_time_get_microsecond(now) / 1000);
    g_date_time_unref(now);
    const char *nm = rv_name(c->rv);
    char rvs[48];
    if (nm) snprintf(rvs, sizeof rvs, "%s", nm);
    else    snprintf(rvs, sizeof rvs, "0x%lx", c->rv);
    snprintf(l->text, sizeof l->text, "%s  %-20s %s%s-> %s  (%.1f ms)\n",
             when, c->fn, c->args, c->args[0] ? "  " : "", rvs, c->ms);
    g_idle_add(append_log, l);
}

/* --- status line and sensitivity ---------------------------------------- */

static void status(const char *msg) {
    gtk_label_set_text(GTK_LABEL(A.status), msg ? msg : "");
}

/* A p11_err message ends with a newline and may run over several lines; the
 * status line shows it as it is, minus the last newline. */
static void status_err(const char *what, const struct p11_err *e) {
    char buf[4200];
    snprintf(buf, sizeof buf, "%s: %s", what, e->msg);
    size_t n = strlen(buf);
    if (n && buf[n-1] == '\n') buf[n-1] = '\0';
    status(buf);
}

static void update_sensitivity(void) {
    int has_token = A.selected >= 0 && (size_t)A.selected < A.n_slots
                 && A.slots[A.selected].has_token;
    gtk_widget_set_sensitive(A.load_btn,     !A.busy && !A.loaded);
    gtk_widget_set_sensitive(A.module_entry, !A.busy && !A.loaded);
    gtk_widget_set_sensitive(A.unload_btn,   !A.busy && A.loaded);
    gtk_widget_set_sensitive(A.slots_box,    !A.busy && A.loaded && !A.logged_in);
    gtk_widget_set_sensitive(A.pin_entry,    !A.busy && has_token && !A.logged_in);
    gtk_widget_set_sensitive(A.login_btn,    !A.busy && has_token && !A.logged_in);
    gtk_widget_set_sensitive(A.logout_btn,   !A.busy && A.logged_in);
    gtk_widget_set_sensitive(A.label_entry,  !A.busy && A.logged_in);
    gtk_widget_set_sensitive(A.keygen_btn,   !A.busy && A.logged_in);
    gtk_widget_set_sensitive(A.cert_page,    !A.busy && A.logged_in);
    gtk_widget_set_sensitive(A.rv_db_box,     !A.busy);
    gtk_widget_set_sensitive(A.rv_revoke_box, !A.busy && A.db_path);
    gtk_widget_set_sensitive(A.rv_sign_box,   !A.busy && A.db_path && A.logged_in);
}

static void clear_list(GtkWidget *box) {
    GtkWidget *c;
    while ((c = gtk_widget_get_first_child(box)) != NULL)
        gtk_list_box_remove(GTK_LIST_BOX(box), c);
}

static void list_add(GtkWidget *box, const char *text) {
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_widget_set_margin_start(l, 6);
    gtk_widget_set_margin_end(l, 6);
    gtk_list_box_append(GTK_LIST_BOX(box), l);
}

/* --- jobs on the worker thread ------------------------------------------ */

enum job_kind { J_LOAD, J_UNLOAD, J_SLOTS, J_LOGIN, J_KEYS, J_KEYGEN, J_LOGOUT,
                J_CSR, J_ROOT, J_ISSUE, J_DB_LOAD, J_REVOKE, J_CRL, J_OCSP };

struct job {
    enum job_kind kind;
    char *module, *label;
    pkiops_handle slot, session;
    uint8_t *pin; size_t pin_len;
    /* requests and issuance */
    char *subject, *san, *ca_path, *csr_path, *out_path;
    char **crl_urls;                /* NULL-terminated; NULL for none */
    int pem, days, profile;
    long serial;
    /* revocation */
    char *db_path, *serial_hex, *date, *req_path, *responder_path;
    int reason;                     /* RFC 5280 code, or -1 for none */
    /* results */
    int rc;
    struct p11_err e;
    struct pkiops_slot *slots; size_t n_slots;
    struct pkiops_key  *keys;  size_t n_keys;
    int pop_valid;
    size_t out_len;
    fhsm_rev_db_t db; int have_db;  /* the database as the job left it */
    int already; char already_date[16];
    fhsm_ocsp_stats_t stats;
};

static void job_free(gpointer p) {
    struct job *j = p;
    if (j->pin) { OPENSSL_cleanse(j->pin, j->pin_len); g_free(j->pin); }
    g_free(j->module);
    g_free(j->label);
    g_free(j->subject);
    g_free(j->san);
    g_free(j->ca_path);
    g_free(j->csr_path);
    g_free(j->out_path);
    g_strfreev(j->crl_urls);
    g_free(j->db_path);
    g_free(j->serial_hex);
    g_free(j->date);
    g_free(j->req_path);
    g_free(j->responder_path);
    if (j->have_db) fhsm_rev_db_free(&j->db);
    free(j->slots);
    free(j->keys);
    g_free(j);
}

/* --- files, on the worker thread ----------------------------------------- */

/* What the tools allow for a certificate or a request, and for what they
 * write: the same buffers fhsm-csr and fhsm-ca use. */
#define IN_MAX  262144
#define DER_MAX 32768

G_GNUC_PRINTF(3, 4)
static int err_set(struct p11_err *e, int code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->msg, sizeof e->msg, fmt, ap);
    va_end(ap);
    e->code = code;
    return code;
}

/* A certificate or a request, DER or PEM -- as fhsm-ca reads them: an
 * operator who received a PEM request should not have to convert it. The DER
 * is in a g_malloc'd buffer the caller frees. */
static int read_der(const char *path, uint8_t **out, size_t *n, struct p11_err *e) {
    gchar *buf = NULL; gsize len = 0; GError *ge = NULL;
    if (!g_file_get_contents(path, &buf, &len, &ge)) {
        err_set(e, 2, "cannot read %s: %s\n", path, ge->message);
        g_error_free(ge);
        return 2;
    }
    if (len == 0 || len > IN_MAX) {
        g_free(buf);
        return err_set(e, 2, "%s is %s\n", path, len ? "too large" : "empty");
    }
    if (len > 11 && memcmp(buf, "-----BEGIN ", 11) == 0) {
        BIO *b = BIO_new_mem_buf(buf, (int)len);
        char *nm = NULL, *hdr = NULL; unsigned char *data = NULL; long dl = 0;
        int ok = b && PEM_read_bio(b, &nm, &hdr, &data, &dl) == 1 && dl > 0;
        BIO_free(b);
        g_free(buf);
        if (ok) { *out = g_memdup2(data, (gsize)dl); *n = (size_t)dl; }
        OPENSSL_free(nm); OPENSSL_free(hdr); OPENSSL_free(data);
        return ok ? 0 : err_set(e, 2, "%s looks like PEM but did not parse\n", path);
    }
    *out = (uint8_t *)buf;
    *n = len;
    return 0;
}

static int write_out(const char *path, const uint8_t *der, size_t n, int pem,
                     const char *pem_label, struct p11_err *e) {
    FILE *f = fopen(path, "wb");
    if (!f) return err_set(e, 2, "cannot write %s: %s\n", path, g_strerror(errno));
    int bad;
    if (pem) {
        BIO *b = BIO_new_fp(f, BIO_NOCLOSE);
        bad = !b || PEM_write_bio(b, pem_label, "", der, (long)n) <= 0;
        BIO_free(b);
    } else {
        bad = fwrite(der, 1, n, f) != n;
    }
    if (fclose(f) != 0) bad = 1;
    return bad ? err_set(e, 2, "writing %s failed\n", path) : 0;
}

/* The revocation database, with the library's diagnostic as the message. */
static int db_load_e(const char *path, fhsm_rev_db_t *d, struct p11_err *e) {
    char err[FHSM_REV_ERR_MAX] = "";
    int rc = fhsm_rev_db_load(path, d, err, sizeof err);
    return rc == FHSM_REV_OK ? 0 : err_set(e, rc, "%s", err);
}

static int db_save_e(const char *path, const fhsm_rev_db_t *d, struct p11_err *e) {
    char err[FHSM_REV_ERR_MAX] = "";
    int rc = fhsm_rev_db_save(path, d, err, sizeof err);
    return rc == FHSM_REV_OK ? 0 : err_set(e, rc, "%s", err);
}

/* fhsm-ca revoke, minus the command line. */
static void run_revoke(struct job *j) {
    fhsm_rev_entry_t en;
    memset(&en, 0, sizeof en);
    if (!fhsm_rev_hex_to_bytes(j->serial_hex, en.serial, sizeof en.serial, &en.serial_len)) {
        j->rc = err_set(&j->e, 2,
            "the serial must be an even number of hex digits, exactly as the\n"
            "certificate carries it. openssl x509 -noout -serial prints it in that form.\n");
        return;
    }
    en.reason = j->reason;
    if (j->date) {
        int64_t t = 0;
        if (strlen(j->date) != 15 || !fhsm_rev_date_to_time(j->date, &t)) {
            j->rc = err_set(&j->e, 2, "the date must be YYYYMMDDHHMMSSZ, in UTC.\n");
            return;
        }
        memcpy(en.date, j->date, 15);
        en.date[15] = '\0';
    } else if (!fhsm_rev_time_to_date((int64_t)time(NULL), en.date)) {
        j->rc = err_set(&j->e, 2, "unrepresentable date\n");
        return;
    }

    if ((j->rc = db_load_e(j->db_path, &j->db, &j->e)) != 0) return;
    j->have_db = 1;
    /* Already there: say so and change nothing -- re-revoking would duplicate
     * the entry in every future list or move its date. */
    const fhsm_rev_entry_t *had = fhsm_rev_db_find(&j->db, en.serial, en.serial_len);
    if (had) {
        j->already = 1;
        memcpy(j->already_date, had->date, sizeof j->already_date);
        return;
    }
    char err[FHSM_REV_ERR_MAX] = "";
    int rc = fhsm_rev_db_add(&j->db, &en, err, sizeof err);
    if (rc != FHSM_REV_OK) { j->rc = err_set(&j->e, rc, "%s", err); return; }
    j->rc = db_save_e(j->db_path, &j->db, &j->e);
}

/* fhsm-ca crl, in its order: the number advances, the list is signed, the
 * database is saved, and only then is the list written. A failure after the
 * save leaves a number consumed and nothing published -- a gap, which is
 * harmless; the other order could publish two lists under one number. */
static void run_crl(struct job *j) {
    uint8_t *ca = NULL; size_t ca_len = 0;
    if ((j->rc = read_der(j->ca_path, &ca, &ca_len, &j->e)) != 0) return;
    if ((j->rc = db_load_e(j->db_path, &j->db, &j->e)) != 0) { g_free(ca); return; }
    j->have_db = 1;
    j->db.crl_number++;
    uint8_t *der = NULL; size_t n = 0;
    j->rc = pkiops_crl(j->session, j->label, ca, ca_len, &j->db, j->days, &der, &n, &j->e);
    g_free(ca);
    if (!j->rc) j->rc = db_save_e(j->db_path, &j->db, &j->e);
    if (!j->rc) j->rc = write_out(j->out_path, der, n, j->pem, "X509 CRL", &j->e);
    j->out_len = n;
    free(der);
}

/* fhsm-ca ocsp-respond: the CA answers, or a delegate it issued. */
static void run_ocsp(struct job *j) {
    uint8_t *ca = NULL, *rcert = NULL, *req = NULL;
    size_t ca_len = 0, rcert_len = 0, req_len = 0;
    j->rc = read_der(j->ca_path, &ca, &ca_len, &j->e);
    /* Parsed before the delegation check, which reads its subject: fhsm-ca
     * once reached X509_get_subject_name(NULL) that way. */
    if (!j->rc) {
        const unsigned char *p = ca;
        X509 *t = d2i_X509(NULL, &p, (long)ca_len);
        if (!t) j->rc = err_set(&j->e, 2, "the CA certificate is not a certificate.\n");
        X509_free(t);
    }
    if (!j->rc && j->responder_path) {
        j->rc = read_der(j->responder_path, &rcert, &rcert_len, &j->e);
        if (!j->rc) {
            char err[FHSM_REV_ERR_MAX] = "";
            int rc = fhsm_ocsp_check_responder(rcert, rcert_len, ca, ca_len,
                                               j->responder_path, j->ca_path,
                                               err, sizeof err);
            if (rc != FHSM_REV_OK) j->rc = err_set(&j->e, rc, "%s", err);
        }
    }
    if (!j->rc) j->rc = read_der(j->req_path, &req, &req_len, &j->e);
    if (!j->rc) { j->rc = db_load_e(j->db_path, &j->db, &j->e); j->have_db = !j->rc; }
    if (!j->rc) {
        uint8_t *resp = NULL; size_t rn = 0;
        j->rc = pkiops_ocsp(j->session, j->label, req, req_len, ca, ca_len,
                            rcert ? rcert : ca, rcert ? rcert_len : ca_len,
                            &j->db, j->days, j->req_path, &resp, &rn, &j->stats, &j->e);
        if (!j->rc) j->rc = write_out(j->out_path, resp, rn, 0, NULL, &j->e);
        free(resp);
    }
    g_free(ca);
    g_free(rcert);
    g_free(req);
}

static void run_job(GTask *task, gpointer src, gpointer data, GCancellable *c) {
    (void)task; (void)src; (void)c;
    struct job *j = data;
    switch (j->kind) {
    case J_LOAD:
        j->rc = pkiops_load(j->module, &j->e);
        if (!j->rc) j->rc = pkiops_slots(&j->slots, &j->n_slots, &j->e);
        break;
    case J_UNLOAD:
        if (j->session) pkiops_session_close(j->session);
        pkiops_unload();
        break;
    case J_SLOTS:
        j->rc = pkiops_slots(&j->slots, &j->n_slots, &j->e);
        break;
    case J_LOGIN:
        j->rc = pkiops_session_user(j->slot, j->pin, j->pin_len, &j->session, &j->e);
        /* Wiped as soon as the module has answered, not when the job is freed. */
        OPENSSL_cleanse(j->pin, j->pin_len);
        if (!j->rc) j->rc = pkiops_keys(j->session, &j->keys, &j->n_keys, &j->e);
        break;
    case J_KEYS:
        j->rc = pkiops_keys(j->session, &j->keys, &j->n_keys, &j->e);
        break;
    case J_KEYGEN: {
        pkiops_handle hp = 0, hk = 0;
        j->rc = pkiops_keygen(j->session, j->label, &hp, &hk, &j->e);
        if (!j->rc) j->rc = pkiops_keys(j->session, &j->keys, &j->n_keys, &j->e);
        break;
    }
    case J_LOGOUT:
        pkiops_session_close(j->session);
        j->rc = pkiops_slots(&j->slots, &j->n_slots, &j->e);
        break;
    case J_CSR:
    case J_ROOT: {
        size_t n = DER_MAX;
        uint8_t *der = g_malloc(n);
        j->rc = j->kind == J_CSR
              ? pkiops_csr(j->session, j->label, j->subject, der, &n, &j->e)
              : pkiops_root(j->session, j->label, j->subject, j->serial, j->days,
                            der, &n, &j->e);
        if (!j->rc)
            j->rc = write_out(j->out_path, der, n, j->pem,
                              j->kind == J_CSR ? "CERTIFICATE REQUEST" : "CERTIFICATE",
                              &j->e);
        j->out_len = n;
        g_free(der);
        break;
    }
    case J_ISSUE: {
        uint8_t *ca = NULL, *csr = NULL;
        size_t ca_len = 0, csr_len = 0;
        j->rc = read_der(j->ca_path, &ca, &ca_len, &j->e);
        if (!j->rc) j->rc = read_der(j->csr_path, &csr, &csr_len, &j->e);
        if (!j->rc) {
            size_t n = DER_MAX;
            uint8_t *der = g_malloc(n);
            size_t n_urls = j->crl_urls ? g_strv_length(j->crl_urls) : 0;
            j->rc = pkiops_issue(j->session, j->label, ca, ca_len, csr, csr_len,
                                 j->subject, j->san,
                                 (const char *const *)j->crl_urls, n_urls,
                                 (fhsm_cert_profile_t)j->profile, j->days,
                                 der, &n, &j->pop_valid, &j->e);
            /* A request that fails its proof of possession is a verdict, not
             * an error, and nothing is written for it. */
            if (!j->rc && j->pop_valid)
                j->rc = write_out(j->out_path, der, n, j->pem, "CERTIFICATE", &j->e);
            j->out_len = n;
            g_free(der);
        }
        g_free(ca);
        g_free(csr);
        break;
    }
    case J_DB_LOAD:
        j->rc = db_load_e(j->db_path, &j->db, &j->e);
        j->have_db = !j->rc;
        break;
    case J_REVOKE: run_revoke(j); break;
    case J_CRL:    run_crl(j);    break;
    case J_OCSP:   run_ocsp(j);   break;
    }
}

static void show_slots(struct job *j) {
    free(A.slots);
    A.slots = j->slots; A.n_slots = j->n_slots;
    j->slots = NULL;
    A.selected = -1;
    clear_list(A.slots_box);
    for (size_t i = 0; i < A.n_slots; i++) {
        char t[96];
        if (A.slots[i].has_token)
            snprintf(t, sizeof t, "slot %lu   \"%s\"", A.slots[i].id, A.slots[i].label);
        else
            snprintf(t, sizeof t, "slot %lu   (no token)", A.slots[i].id);
        list_add(A.slots_box, t);
    }
}

/* The database as a job left it: every entry, and the number the next CRL
 * will carry. */
static void show_db(struct job *j) {
    clear_list(A.db_list);
    for (size_t i = 0; i < j->db.n; i++) {
        const fhsm_rev_entry_t *en = &j->db.e[i];
        char hex[sizeof en->serial * 2 + 1];
        for (size_t k = 0; k < en->serial_len && k < sizeof en->serial; k++)
            snprintf(hex + 2 * k, 3, "%02X", en->serial[k]);
        hex[2 * (en->serial_len < sizeof en->serial ? en->serial_len : sizeof en->serial)] = '\0';
        const char *why = en->reason >= 0 ? fhsm_rev_reason_name(en->reason) : NULL;
        char t[256];
        snprintf(t, sizeof t, "%s   %s   %s", hex, en->date, why ? why : "-");
        list_add(A.db_list, t);
    }
    if (j->db.n == 0) list_add(A.db_list, "(nothing revoked)");
    char info[160];
    snprintf(info, sizeof info, "%zu revoked; the next CRL will be number %llu.",
             j->db.n, j->db.crl_number + 1);
    gtk_label_set_text(GTK_LABEL(A.db_info), info);
}

static void clear_key_labels(void) {
    gtk_string_list_splice(A.key_labels, 0,
                           g_list_model_get_n_items(G_LIST_MODEL(A.key_labels)), NULL);
}

static void show_keys(struct job *j) {
    /* The Certificates tab signs with a private key, named by its label. */
    clear_key_labels();
    for (size_t i = 0; i < j->n_keys; i++)
        if (j->keys[i].is_private && j->keys[i].label[0])
            gtk_string_list_append(A.key_labels, j->keys[i].label);
    clear_list(A.keys_box);
    for (size_t i = 0; i < j->n_keys; i++) {
        char t[128];
        snprintf(t, sizeof t, "%-7s  object %lu   \"%s\"",
                 j->keys[i].is_private ? "private" : "public",
                 j->keys[i].handle, j->keys[i].label);
        list_add(A.keys_box, t);
    }
    if (j->n_keys == 0) list_add(A.keys_box, "(no key on this token)");
}

static void job_done(GObject *src, GAsyncResult *res, gpointer ud) {
    (void)src; (void)ud;
    struct job *j = g_task_get_task_data(G_TASK(res));
    A.busy = 0;
    switch (j->kind) {
    case J_LOAD:
        if (j->rc) { status_err("Loading the module", &j->e); break; }
        A.loaded = 1;
        show_slots(j);
        status("Module loaded. Choose a slot holding a token, then log in.");
        break;
    case J_UNLOAD:
        A.loaded = 0;
        A.logged_in = 0;
        A.session = 0;
        free(A.slots);
        A.slots = NULL; A.n_slots = 0;
        A.selected = -1;
        clear_list(A.slots_box);
        clear_list(A.keys_box);
        clear_key_labels();
        status("Module unloaded. Load the same one or another.");
        break;
    case J_SLOTS:
        if (!j->rc) show_slots(j);
        break;
    case J_LOGIN:
        if (j->rc && !j->session) { status_err("Logging in", &j->e); break; }
        A.logged_in = 1;
        A.session = j->session;
        if (j->rc) status_err("Listing the keys", &j->e);
        else { show_keys(j); status("Logged in."); }
        break;
    case J_KEYS:
        if (j->rc) status_err("Listing the keys", &j->e);
        else show_keys(j);
        break;
    case J_KEYGEN:
        if (j->rc) {
            status_err("Generating the key pair", &j->e);
            if (strstr(j->e.msg, "0x70"))
                status("Generating the key pair: this module does not offer the composite "
                       "mechanism (CKR_MECHANISM_INVALID). It exists only in builds made "
                       "with PROFILE=all-mechanisms.");
        } else {
            show_keys(j);
            status("Key pair generated.");
        }
        break;
    case J_LOGOUT:
        A.logged_in = 0;
        A.session = 0;
        clear_list(A.keys_box);
        clear_key_labels();
        if (!j->rc) show_slots(j);
        status("Logged out: the session is closed.");
        break;
    case J_CSR:
    case J_ROOT:
    case J_ISSUE: {
        const char *what = j->kind == J_CSR  ? "Making the request"
                         : j->kind == J_ROOT ? "Making the root"
                         :                     "Issuing";
        if (j->rc) { status_err(what, &j->e); break; }
        if (j->kind == J_ISSUE && !j->pop_valid) {
            status("Issuing: the request's signature does not match the key it carries. "
                   "Nothing was issued. Either the request was altered after signing, or "
                   "whoever produced it does not hold the private key it asks to have "
                   "certified.");
            break;
        }
        char msg[1200];
        int w = snprintf(msg, sizeof msg, "%s written to %s (%zu bytes of DER, saved as %s).",
                         j->kind == J_CSR ? "Request" : "Certificate",
                         j->out_path, j->out_len, j->pem ? "PEM" : "DER");
        /* fhsm-ca's note, word for word in substance: a delegated responder
         * carries ocsp-nocheck, so its validity is the only control left. */
        if (w > 0 && (size_t)w < sizeof msg
            && j->kind == J_ISSUE && j->profile == FHSM_CERT_OCSP_RESPONDER && j->days > 90)
            snprintf(msg + w, sizeof msg - (size_t)w,
                     " NOTE: %d days for a delegated responder. It carries "
                     "id-pkix-ocsp-nocheck, so revoking it is not something a verifier "
                     "will observe; short validity is the only control that remains.",
                     j->days);
        status(msg);
        break;
    }
    case J_DB_LOAD:
        if (j->rc) {
            /* Not kept as the database: what cannot be read cannot be added to. */
            g_free(A.db_path);
            A.db_path = NULL;
            gtk_button_set_label(GTK_BUTTON(A.db_btn), "Open\xe2\x80\xa6");
            gtk_widget_set_tooltip_text(A.db_btn, NULL);
            clear_list(A.db_list);
            status_err("Reading the database", &j->e);
            break;
        }
        show_db(j);
        status(NULL);
        break;
    case J_REVOKE: {
        if (j->rc) { status_err("Recording the revocation", &j->e); break; }
        show_db(j);
        char msg[600];
        if (j->already)
            snprintf(msg, sizeof msg,
                     "Serial %s is already revoked, on %s. The database was left "
                     "unchanged. Remove the line by hand if the date or reason must "
                     "be corrected.", j->serial_hex, j->already_date);
        else
            snprintf(msg, sizeof msg,
                     "Recorded. %zu revoked in total. Nothing is signed yet: publish "
                     "a CRL to say so.", j->db.n);
        status(msg);
        break;
    }
    case J_CRL: {
        if (j->rc) { status_err("Signing the CRL", &j->e); break; }
        show_db(j);
        char msg[1200];
        snprintf(msg, sizeof msg, "CRL number %llu, %zu revoked, valid %d days, "
                 "written to %s.", j->db.crl_number, j->db.n, j->days, j->out_path);
        status(msg);
        break;
    }
    case J_OCSP: {
        if (j->rc) { status_err("Answering the OCSP request", &j->e); break; }
        char msg[1200];
        snprintf(msg, sizeof msg, "%zu asked, %zu ours (%zu revoked), %zu unknown, "
                 "valid %d days, %s. Response written to %s.",
                 j->stats.asked, j->stats.ours, j->stats.revoked, j->stats.unknown,
                 j->days, j->stats.nonce_echoed ? "nonce echoed" : "no nonce",
                 j->out_path);
        status(msg);
        break;
    }
    }
    update_sensitivity();
}

static void start(struct job *j) {
    /* Take the focus off any entry before it turns insensitive: an entry that
     * loses its sensitivity while focused never receives its focus-out, and
     * GTK warns about it on stderr. */
    gtk_window_set_focus(GTK_WINDOW(A.win), NULL);
    A.busy = 1;
    update_sensitivity();
    GTask *t = g_task_new(NULL, NULL, job_done, NULL);
    g_task_set_task_data(t, j, job_free);
    g_task_run_in_thread(t, run_job);
    g_object_unref(t);
}

/* --- actions ------------------------------------------------------------- */

static void on_load(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    const char *path = gtk_editable_get_text(GTK_EDITABLE(A.module_entry));
    if (!path || !*path) { status("Name a PKCS#11 module first."); return; }
    struct job *j = g_new0(struct job, 1);
    j->kind = J_LOAD;
    j->module = g_strdup(path);
    status("Loading...");
    start(j);
}

static void on_unload(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    struct job *j = g_new0(struct job, 1);
    j->kind = J_UNLOAD;
    j->session = A.logged_in ? A.session : 0;
    status("Unloading...");
    start(j);
}

static void on_slot_selected(GtkListBox *box, GtkListBoxRow *row, gpointer ud) {
    (void)box; (void)ud;
    if (A.closing) return;          /* the list empties itself as it is destroyed */
    A.selected = row ? gtk_list_box_row_get_index(row) : -1;
    if (A.selected >= 0 && (size_t)A.selected < A.n_slots && !A.slots[A.selected].has_token)
        status("This slot holds no token. Initialising one is fhsm-token init, for now.");
    else
        status(NULL);
    update_sensitivity();
}

static void on_login(GtkWidget *w, gpointer ud) {
    (void)w; (void)ud;
    if (A.busy || A.logged_in || A.selected < 0) return;
    const char *pin = gtk_editable_get_text(GTK_EDITABLE(A.pin_entry));
    size_t n = pin ? strlen(pin) : 0;
    if (n == 0) { status("Type the user PIN."); return; }
    struct job *j = g_new0(struct job, 1);
    j->kind = J_LOGIN;
    j->slot = A.slots[A.selected].id;
    j->pin = g_malloc(n);
    j->pin_len = n;
    memcpy(j->pin, pin, n);
    /* Cleared now, before the module is even asked. */
    gtk_editable_set_text(GTK_EDITABLE(A.pin_entry), "");
    status("Logging in...");
    start(j);
}

static void on_logout(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    struct job *j = g_new0(struct job, 1);
    j->kind = J_LOGOUT;
    j->session = A.session;
    start(j);
}

static void on_keygen(GtkWidget *w, gpointer ud) {
    (void)w; (void)ud;
    if (A.busy || !A.logged_in) return;
    const char *label = gtk_editable_get_text(GTK_EDITABLE(A.label_entry));
    if (!label || !*label) { status("Give the key pair a label."); return; }
    struct job *j = g_new0(struct job, 1);
    j->kind = J_KEYGEN;
    j->session = A.session;
    j->label = g_strdup(label);
    status("Generating a composite key pair...");
    start(j);
}

/* --- the Certificates tab ------------------------------------------------- */

static const char *chosen_key(GtkWidget *drop) {
    GtkStringObject *o = gtk_drop_down_get_selected_item(GTK_DROP_DOWN(drop));
    return o ? gtk_string_object_get_string(o) : NULL;
}

/* An entry's text, or NULL when it is empty: an optional field left blank. */
static char *text_or_null(GtkWidget *entry) {
    const char *t = gtk_editable_get_text(GTK_EDITABLE(entry));
    return t && *t ? g_strdup(t) : NULL;
}

/* The save dialog answered: run the job, or drop it if the operator
 * cancelled. */
static void on_saved(GObject *src, GAsyncResult *res, gpointer data) {
    struct job *j = data;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, NULL);
    char *path = f ? g_file_get_path(f) : NULL;
    if (f) g_object_unref(f);
    if (!path) { job_free(j); return; }
    if (A.closing || !A.logged_in) { g_free(path); job_free(j); return; }
    j->out_path = path;
    j->session = A.session;
    status(j->kind == J_CSR   ? "Signing the request..."
         : j->kind == J_ROOT  ? "Signing the root..."
         : j->kind == J_ISSUE ? "Checking the request, then issuing..."
         : j->kind == J_CRL   ? "Signing the CRL..."
         :                      "Answering the OCSP request...");
    start(j);
}

static void ask_where(struct job *j, const char *stem) {
    char name[64];
    snprintf(name, sizeof name, "%s.%s", stem, j->pem ? "pem" : "der");
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, "Save as");
    gtk_file_dialog_set_initial_name(d, name);
    gtk_file_dialog_save(d, GTK_WINDOW(A.win), NULL, on_saved, j);
    g_object_unref(d);
}

/* What every signing operation needs: a key, and the format. NULL, with the
 * reason in the status line, when there is no key to sign with. The format is
 * the Certificates tab's; the Revocation tab sets its own. */
static struct job *cert_job(enum job_kind kind, GtkWidget *key_drop) {
    if (A.busy || !A.logged_in) return NULL;
    const char *key = chosen_key(key_drop);
    if (!key) {
        status("No private key on this token to sign with. Generate a key pair first.");
        return NULL;
    }
    struct job *j = g_new0(struct job, 1);
    j->kind = kind;
    j->label = g_strdup(key);
    j->pem = gtk_check_button_get_active(GTK_CHECK_BUTTON(A.pem_check));
    return j;
}

static void on_csr(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    const char *subject = gtk_editable_get_text(GTK_EDITABLE(A.subject_entry));
    if (!subject || !*subject) { status("Give the request a subject."); return; }
    struct job *j = cert_job(J_CSR, A.key_drop);
    if (!j) return;
    j->subject = g_strdup(subject);
    ask_where(j, "request");
}

static void on_root(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    const char *subject = gtk_editable_get_text(GTK_EDITABLE(A.subject_entry));
    if (!subject || !*subject) { status("Give the root a subject."); return; }
    struct job *j = cert_job(J_ROOT, A.key_drop);
    if (!j) return;
    j->subject = g_strdup(subject);
    j->serial = (long)gtk_spin_button_get_value(GTK_SPIN_BUTTON(A.serial_spin));
    j->days = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.root_days_spin));
    ask_where(j, "root");
}

/* One URL per line; blank lines ignored. At most eight, as fhsm-ca allows. */
static char **crl_urls(int *too_many) {
    GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(A.crl_view));
    GtkTextIter s, e;
    gtk_text_buffer_get_bounds(b, &s, &e);
    char *all = gtk_text_buffer_get_text(b, &s, &e, FALSE);
    char **lines = g_strsplit(all, "\n", -1);
    g_free(all);
    GPtrArray *out = g_ptr_array_new();
    for (char **l = lines; *l; l++) {
        char *t = g_strstrip(*l);
        if (*t) g_ptr_array_add(out, g_strdup(t));
    }
    g_strfreev(lines);
    *too_many = out->len > 8;
    if (out->len == 0) { g_ptr_array_free(out, TRUE); return NULL; }
    g_ptr_array_add(out, NULL);
    return (char **)g_ptr_array_free(out, FALSE);
}

static void on_issue(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (!A.ca_path)  { status("Choose the CA's certificate."); return; }
    if (!A.csr_path) { status("Choose the request to sign."); return; }
    int too_many = 0;
    char **urls = crl_urls(&too_many);
    if (too_many) { g_strfreev(urls); status("At most 8 CRL URLs."); return; }
    struct job *j = cert_job(J_ISSUE, A.key_drop);
    if (!j) { g_strfreev(urls); return; }
    j->crl_urls = urls;
    j->ca_path = g_strdup(A.ca_path);
    j->csr_path = g_strdup(A.csr_path);
    j->subject = text_or_null(A.issue_subject_entry);
    j->san = text_or_null(A.san_entry);
    j->profile = gtk_drop_down_get_selected(GTK_DROP_DOWN(A.profile_drop)) == 1
               ? FHSM_CERT_OCSP_RESPONDER : FHSM_CERT_END_ENTITY;
    j->days = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.issue_days_spin));
    ask_where(j, "certificate");
}

/* A delegated responder defaults to 30 days, as in fhsm-ca; an end entity to
 * 365. Choosing the profile resets the days; the operator can change them. */
static void on_profile_changed(GObject *o, GParamSpec *ps, gpointer ud) {
    (void)o; (void)ps; (void)ud;
    int responder = gtk_drop_down_get_selected(GTK_DROP_DOWN(A.profile_drop)) == 1;
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(A.issue_days_spin), responder ? 30 : 365);
}

static void on_picked(GObject *src, GAsyncResult *res, gpointer data) {
    GtkWidget *btn = data;
    GFile *f = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, NULL);
    char *path = f ? g_file_get_path(f) : NULL;
    if (f) g_object_unref(f);
    if (!path || A.closing) { g_free(path); return; }
    /* Each file button carries the path it sets; see file_button. */
    char **slot = g_object_get_data(G_OBJECT(btn), "path-slot");
    g_free(*slot);
    *slot = path;
    char *base = g_path_get_basename(path);
    gtk_button_set_label(GTK_BUTTON(btn), base);
    g_free(base);
    gtk_widget_set_tooltip_text(btn, path);
}

static void on_pick(GtkButton *b, gpointer title) {
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, title);
    gtk_file_dialog_open(d, GTK_WINDOW(A.win), NULL, on_picked, b);
    g_object_unref(d);
}

/* --- the Revocation tab --------------------------------------------------- */

static void on_db_picked(GObject *src, GAsyncResult *res, gpointer data) {
    (void)data;
    GFile *f = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, NULL);
    char *path = f ? g_file_get_path(f) : NULL;
    if (f) g_object_unref(f);
    if (!path || A.closing || A.busy) { g_free(path); return; }
    g_free(A.db_path);
    A.db_path = path;
    char *base = g_path_get_basename(path);
    gtk_button_set_label(GTK_BUTTON(A.db_btn), base);
    g_free(base);
    gtk_widget_set_tooltip_text(A.db_btn, path);
    struct job *j = g_new0(struct job, 1);
    j->kind = J_DB_LOAD;
    j->db_path = g_strdup(path);
    start(j);
}

static void on_db_open(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, "The revocation database");
    gtk_file_dialog_open(d, GTK_WINDOW(A.win), NULL, on_db_picked, NULL);
    g_object_unref(d);
}

/* A new database is a name, not a file: like fhsm-ca, the file is created by
 * the first revocation. A name that already exists is refused rather than
 * emptied, whatever the save dialog said about replacing it -- an emptied
 * database signs a list that leaves out every revocation it held. */
static void on_db_named(GObject *src, GAsyncResult *res, gpointer data) {
    (void)data;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, NULL);
    char *path = f ? g_file_get_path(f) : NULL;
    if (f) g_object_unref(f);
    if (!path || A.closing || A.busy) { g_free(path); return; }
    if (g_file_test(path, G_FILE_TEST_EXISTS)) {
        char msg[1200];
        snprintf(msg, sizeof msg, "%s already exists, and was left as it is. Open it "
                 "instead: a new database is never written over an existing file.", path);
        status(msg);
        g_free(path);
        return;
    }
    g_free(A.db_path);
    A.db_path = path;
    char *base = g_path_get_basename(path);
    gtk_button_set_label(GTK_BUTTON(A.db_btn), base);
    g_free(base);
    gtk_widget_set_tooltip_text(A.db_btn, path);
    clear_list(A.db_list);
    list_add(A.db_list, "(nothing revoked)");
    gtk_label_set_text(GTK_LABEL(A.db_info),
                       "New: the file is created by the first revocation recorded.");
    status(NULL);
    update_sensitivity();
}

static void on_db_new(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, "A new revocation database");
    gtk_file_dialog_set_initial_name(d, "revocations.db");
    gtk_file_dialog_save(d, GTK_WINDOW(A.win), NULL, on_db_named, NULL);
    g_object_unref(d);
}

/* Index 0 is "no reason"; the rest are the names fhsm_rev_reason_code knows. */
static const char *const reasons[] = {
    "(no reason given)", "unspecified", "keyCompromise", "cACompromise",
    "affiliationChanged", "superseded", "cessationOfOperation",
    "certificateHold", "privilegeWithdrawn", "aACompromise", NULL
};

static void on_revoke_answered(GObject *src, GAsyncResult *res, gpointer data) {
    struct job *j = data;
    int choice = gtk_alert_dialog_choose_finish(GTK_ALERT_DIALOG(src), res, NULL);
    if (choice != 1 || A.closing || A.busy || !A.db_path) { job_free(j); return; }
    status("Recording the revocation...");
    start(j);
}

static void on_revoke(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (A.busy || !A.db_path) return;
    const char *serial = gtk_editable_get_text(GTK_EDITABLE(A.serial_entry));
    if (!serial || !*serial) { status("Type the serial to revoke, in hex."); return; }
    guint ri = gtk_drop_down_get_selected(GTK_DROP_DOWN(A.reason_drop));
    int reason = ri == 0 || ri >= G_N_ELEMENTS(reasons) - 1
               ? -1 : fhsm_rev_reason_code(reasons[ri]);
    if (reason == -2) { status("Unknown reason."); return; }

    struct job *j = g_new0(struct job, 1);
    j->kind = J_REVOKE;
    j->db_path = g_strdup(A.db_path);
    j->serial_hex = g_strdup(serial);
    j->reason = reason;
    j->date = text_or_null(A.date_entry);

    /* Revoking is not undone from here: the line has to be removed by hand.
     * The command line trusts its user; a window asks once. */
    GtkAlertDialog *d = gtk_alert_dialog_new("Revoke serial %s?", serial);
    gtk_alert_dialog_set_detail(d,
        "This records the revocation in the database. It is not undone from here: "
        "the line would have to be removed by hand. Nothing is signed until a CRL "
        "is published.");
    const char *const buttons[] = { "Cancel", "Revoke", NULL };
    gtk_alert_dialog_set_buttons(d, buttons);
    gtk_alert_dialog_set_cancel_button(d, 0);
    gtk_alert_dialog_set_default_button(d, 0);
    gtk_alert_dialog_choose(d, GTK_WINDOW(A.win), NULL, on_revoke_answered, j);
    g_object_unref(d);
}

static void on_crl(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (!A.rv_ca_path) { status("Choose the CA's certificate."); return; }
    struct job *j = cert_job(J_CRL, A.rv_key_drop);
    if (!j) return;
    j->pem = gtk_check_button_get_active(GTK_CHECK_BUTTON(A.crl_pem_check));
    j->ca_path = g_strdup(A.rv_ca_path);
    j->db_path = g_strdup(A.db_path);
    j->days = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.crl_days_spin));
    ask_where(j, "crl");
}

static void on_ocsp(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (!A.rv_ca_path) { status("Choose the CA's certificate."); return; }
    if (!A.req_path)   { status("Choose the OCSP request to answer."); return; }
    struct job *j = cert_job(J_OCSP, A.rv_key_drop);
    if (!j) return;
    j->pem = 0;                     /* an OCSP response is DER, as fhsm-ca writes it */
    j->ca_path = g_strdup(A.rv_ca_path);
    j->db_path = g_strdup(A.db_path);
    j->req_path = g_strdup(A.req_path);
    j->responder_path = A.responder_path ? g_strdup(A.responder_path) : NULL;
    j->days = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.ocsp_days_spin));
    ask_where(j, "response");
}

static void on_responder_clear(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    g_free(A.responder_path);
    A.responder_path = NULL;
    gtk_button_set_label(GTK_BUTTON(A.responder_btn), "None: the CA answers");
    gtk_widget_set_tooltip_text(A.responder_btn, NULL);
}

static void on_clear_log(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(A.log_view)), "", 0);
}

static gboolean on_close(GtkWindow *w, gpointer ud) {
    (void)w; (void)ud;
    if (A.busy) return TRUE;            /* let the running call finish first */
    /* From here the window is being destroyed. Its list boxes still emit
     * row-selected as they empty, and lines already queued for the log still
     * arrive: both must find the flag set and leave the widgets alone. The
     * log goes off first, so these last calls queue nothing. */
    A.closing = 1;
    pkiops_set_call_log(NULL, NULL);
    if (A.logged_in) pkiops_session_close(A.session);
    if (A.loaded) pkiops_unload();
    return FALSE;
}

/* --- the window ---------------------------------------------------------- */

static GtkWidget *heading(const char *text) {
    GtkWidget *l = gtk_label_new(NULL);
    char *m = g_markup_printf_escaped("<b>%s</b>", text);
    gtk_label_set_markup(GTK_LABEL(l), m);
    g_free(m);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_widget_set_margin_top(l, 8);
    return l;
}

static GtkWidget *scrolled(GtkWidget *child, int min_height) {
    GtkWidget *s = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(s), child);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(s), min_height);
    gtk_widget_set_vexpand(s, TRUE);
    return s;
}

/* A labelled row of a form. */
static void form_row(GtkWidget *grid, int r, const char *label, GtkWidget *w) {
    GtkWidget *l = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(l), 1.0f);
    gtk_grid_attach(GTK_GRID(grid), l, 0, r, 1, 1);
    gtk_widget_set_hexpand(w, TRUE);
    gtk_grid_attach(GTK_GRID(grid), w, 1, r, 1, 1);
}

static GtkWidget *form(void) {
    GtkWidget *g = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(g), 6);
    gtk_grid_set_column_spacing(GTK_GRID(g), 8);
    return g;
}

static GtkWidget *entry_with(const char *placeholder) {
    GtkWidget *e = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(e), placeholder);
    return e;
}

static GtkWidget *button_to(const char *text, GCallback cb, gpointer ud) {
    GtkWidget *b = gtk_button_new_with_label(text);
    g_signal_connect(b, "clicked", cb, ud);
    return b;
}

static GtkWidget *note_label(const char *text) {
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(l), TRUE);
    gtk_widget_add_css_class(l, "dim-label");
    return l;
}

/* A button that opens a file chooser and remembers the answer in *slot. */
static GtkWidget *file_button(const char *title, char **slot) {
    GtkWidget *b = button_to("Choose\xe2\x80\xa6", G_CALLBACK(on_pick), (gpointer)title);
    g_object_set_data(G_OBJECT(b), "path-slot", slot);
    return b;
}

/* Stage 2: requests, roots, issuance. */
static GtkWidget *cert_tab(void) {
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(page, 4);
    gtk_widget_set_margin_end(page, 8);

    GtkWidget *g = form();
    A.key_labels = gtk_string_list_new(NULL);
    A.key_drop = gtk_drop_down_new(G_LIST_MODEL(A.key_labels), NULL);
    form_row(g, 0, "Signing key", A.key_drop);
    A.pem_check = gtk_check_button_new_with_label("Write PEM (otherwise DER)");
    gtk_check_button_set_active(GTK_CHECK_BUTTON(A.pem_check), TRUE);
    form_row(g, 1, "Output", A.pem_check);
    gtk_box_append(GTK_BOX(page), g);

    gtk_box_append(GTK_BOX(page), heading("Request, or self-signed root"));
    g = form();
    A.subject_entry = entry_with("/C=FR/O=Simorgh Labs/CN=example");
    form_row(g, 0, "Subject", A.subject_entry);
    A.serial_spin = gtk_spin_button_new_with_range(1, 1e15, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(A.serial_spin), 1);
    form_row(g, 1, "Root serial", A.serial_spin);
    A.root_days_spin = gtk_spin_button_new_with_range(1, 36500, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(A.root_days_spin), 3650);
    form_row(g, 2, "Root days", A.root_days_spin);
    gtk_box_append(GTK_BOX(page), g);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Make request\xe2\x80\xa6", G_CALLBACK(on_csr), NULL));
    gtk_box_append(GTK_BOX(row), button_to("Make self-signed root\xe2\x80\xa6", G_CALLBACK(on_root), NULL));
    gtk_box_append(GTK_BOX(page), row);

    gtk_box_append(GTK_BOX(page), heading("Issue a certificate"));
    g = form();
    A.ca_btn = file_button("The CA's certificate", &A.ca_path);
    form_row(g, 0, "CA certificate", A.ca_btn);
    A.csr_btn = file_button("The request to sign", &A.csr_path);
    form_row(g, 1, "Request", A.csr_btn);
    A.issue_subject_entry = entry_with("as requested");
    form_row(g, 2, "Subject", A.issue_subject_entry);
    A.san_entry = entry_with("DNS:example.org,IP:192.0.2.1");
    form_row(g, 3, "SAN", A.san_entry);
    A.crl_view = gtk_text_view_new();
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(A.crl_view), TRUE);
    GtkWidget *crl_scroll = scrolled(A.crl_view, 52);
    gtk_widget_set_vexpand(crl_scroll, FALSE);
    gtk_widget_set_tooltip_text(crl_scroll,
        "Where this certificate's revocation list is published, one URL per line, "
        "at most 8. http://... or ldap://...?attribute; https is refused.");
    form_row(g, 4, "CRL URLs", crl_scroll);
    const char *const profiles[] = { "end-entity", "ocsp-responder (delegated)", NULL };
    A.profile_drop = gtk_drop_down_new_from_strings(profiles);
    g_signal_connect(A.profile_drop, "notify::selected", G_CALLBACK(on_profile_changed), NULL);
    form_row(g, 5, "Profile", A.profile_drop);
    A.issue_days_spin = gtk_spin_button_new_with_range(1, 36500, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(A.issue_days_spin), 365);
    form_row(g, 6, "Days", A.issue_days_spin);
    gtk_box_append(GTK_BOX(page), g);
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Issue\xe2\x80\xa6", G_CALLBACK(on_issue), NULL));
    gtk_box_append(GTK_BOX(page), row);
    gtk_box_append(GTK_BOX(page), note_label(
        "The request's proof of possession is checked before anything is signed. "
        "Extensions it asks for are ignored; the CA sets its own. The signing key "
        "above is the CA's."));

    A.cert_page = page;
    GtkWidget *s = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(s), page);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(s), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    return s;
}

/* Stage 3: the revocation database, CRLs, OCSP. */
static GtkWidget *revocation_tab(void) {
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(page, 4);
    gtk_widget_set_margin_end(page, 8);

    /* The database. */
    A.rv_db_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), gtk_label_new("Database"));
    A.db_btn = button_to("Open\xe2\x80\xa6", G_CALLBACK(on_db_open), NULL);
    gtk_widget_set_hexpand(A.db_btn, TRUE);
    gtk_box_append(GTK_BOX(row), A.db_btn);
    gtk_box_append(GTK_BOX(row), button_to("New\xe2\x80\xa6", G_CALLBACK(on_db_new), NULL));
    gtk_box_append(GTK_BOX(A.rv_db_box), row);
    A.db_list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(A.db_list), GTK_SELECTION_NONE);
    GtkWidget *db_scroll = scrolled(A.db_list, 110);
    gtk_widget_set_vexpand(db_scroll, FALSE);
    gtk_box_append(GTK_BOX(A.rv_db_box), db_scroll);
    A.db_info = note_label("Open a revocation database, or name a new one.");
    gtk_box_append(GTK_BOX(A.rv_db_box), A.db_info);
    gtk_box_append(GTK_BOX(page), A.rv_db_box);

    /* Recording a revocation: no key, no login. */
    A.rv_revoke_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(A.rv_revoke_box), heading("Revoke"));
    GtkWidget *g = form();
    A.serial_entry = entry_with("serial in hex, as the certificate carries it");
    form_row(g, 0, "Serial", A.serial_entry);
    A.reason_drop = gtk_drop_down_new_from_strings(reasons);
    form_row(g, 1, "Reason", A.reason_drop);
    A.date_entry = entry_with("now, or YYYYMMDDHHMMSSZ (UTC)");
    form_row(g, 2, "Date", A.date_entry);
    gtk_box_append(GTK_BOX(A.rv_revoke_box), g);
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Record revocation\xe2\x80\xa6", G_CALLBACK(on_revoke), NULL));
    gtk_box_append(GTK_BOX(A.rv_revoke_box), row);
    gtk_box_append(GTK_BOX(A.rv_revoke_box), note_label(
        "Recording signs nothing and needs no login. A CRL is what tells verifiers."));
    gtk_box_append(GTK_BOX(page), A.rv_revoke_box);

    /* What signs: the CRL and OCSP answers. */
    A.rv_sign_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(A.rv_sign_box), heading("Sign with the token"));
    g = form();
    /* The same list of private keys as the Certificates tab; the model is
     * shared, so the drop-down takes a reference of its own. */
    A.rv_key_drop = gtk_drop_down_new(G_LIST_MODEL(g_object_ref(A.key_labels)), NULL);
    form_row(g, 0, "Signing key", A.rv_key_drop);
    A.rv_ca_btn = file_button("The CA's certificate", &A.rv_ca_path);
    form_row(g, 1, "CA certificate", A.rv_ca_btn);
    gtk_box_append(GTK_BOX(A.rv_sign_box), g);

    gtk_box_append(GTK_BOX(A.rv_sign_box), heading("Publish a CRL"));
    g = form();
    A.crl_days_spin = gtk_spin_button_new_with_range(1, 3650, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(A.crl_days_spin), 30);
    form_row(g, 0, "Days", A.crl_days_spin);
    A.crl_pem_check = gtk_check_button_new_with_label("Write PEM (otherwise DER)");
    form_row(g, 1, "Output", A.crl_pem_check);
    gtk_box_append(GTK_BOX(A.rv_sign_box), g);
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Sign CRL\xe2\x80\xa6", G_CALLBACK(on_crl), NULL));
    gtk_box_append(GTK_BOX(A.rv_sign_box), row);
    gtk_box_append(GTK_BOX(A.rv_sign_box), note_label(
        "The number advances and the database is saved before the list is written, "
        "so no number is ever published twice."));

    gtk_box_append(GTK_BOX(A.rv_sign_box), heading("Answer an OCSP request"));
    g = form();
    A.req_btn = file_button("The OCSP request", &A.req_path);
    form_row(g, 0, "Request", A.req_btn);
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    A.responder_btn = file_button("The delegated responder's certificate", &A.responder_path);
    gtk_button_set_label(GTK_BUTTON(A.responder_btn), "None: the CA answers");
    gtk_widget_set_hexpand(A.responder_btn, TRUE);
    gtk_box_append(GTK_BOX(row), A.responder_btn);
    gtk_box_append(GTK_BOX(row), button_to("Clear", G_CALLBACK(on_responder_clear), NULL));
    form_row(g, 1, "Responder", row);
    A.ocsp_days_spin = gtk_spin_button_new_with_range(1, 365, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(A.ocsp_days_spin), 7);
    form_row(g, 2, "Days", A.ocsp_days_spin);
    gtk_box_append(GTK_BOX(A.rv_sign_box), g);
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Answer\xe2\x80\xa6", G_CALLBACK(on_ocsp), NULL));
    gtk_box_append(GTK_BOX(A.rv_sign_box), row);
    gtk_box_append(GTK_BOX(A.rv_sign_box), note_label(
        "A delegated responder must carry extendedKeyUsage OCSPSigning and be issued "
        "by this CA; the signing key is then the delegate's. Certificates of another "
        "issuer are answered unknown, not good."));
    gtk_box_append(GTK_BOX(page), A.rv_sign_box);

    GtkWidget *s = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(s), page);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(s), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    return s;
}

static void activate(GtkApplication *app, gpointer ud) {
    (void)ud;
    A.win = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(A.win), "fhsm-gui");
    gtk_window_set_default_size(GTK_WINDOW(A.win), 1100, 680);
    g_signal_connect(A.win, "close-request", G_CALLBACK(on_close), NULL);

    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(outer, 10);
    gtk_widget_set_margin_end(outer, 10);
    gtk_widget_set_margin_top(outer, 10);
    gtk_widget_set_margin_bottom(outer, 10);
    gtk_window_set_child(GTK_WINDOW(A.win), outer);

    /* The module. */
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), gtk_label_new("PKCS#11 module"));
    A.module_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(A.module_entry), "./libfreehsm.so");
    gtk_widget_set_hexpand(A.module_entry, TRUE);
    gtk_box_append(GTK_BOX(row), A.module_entry);
    A.load_btn = gtk_button_new_with_label("Load");
    g_signal_connect(A.load_btn, "clicked", G_CALLBACK(on_load), NULL);
    gtk_box_append(GTK_BOX(row), A.load_btn);
    A.unload_btn = gtk_button_new_with_label("Unload");
    gtk_widget_set_tooltip_text(A.unload_btn,
        "Closes the session, finalises the module and forgets it, so that another can be loaded.");
    g_signal_connect(A.unload_btn, "clicked", G_CALLBACK(on_unload), NULL);
    gtk_box_append(GTK_BOX(row), A.unload_btn);
    gtk_box_append(GTK_BOX(outer), row);

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_vexpand(paned, TRUE);
    gtk_box_append(GTK_BOX(outer), paned);

    /* Left: slots, login, keys. */
    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_end(left, 8);

    gtk_box_append(GTK_BOX(left), heading("Slots"));
    A.slots_box = gtk_list_box_new();
    g_signal_connect(A.slots_box, "row-selected", G_CALLBACK(on_slot_selected), NULL);
    gtk_box_append(GTK_BOX(left), scrolled(A.slots_box, 110));

    gtk_box_append(GTK_BOX(left), heading("Log in"));
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    A.pin_entry = gtk_password_entry_new();
    gtk_widget_set_hexpand(A.pin_entry, TRUE);
    g_signal_connect(A.pin_entry, "activate", G_CALLBACK(on_login), NULL);
    gtk_box_append(GTK_BOX(row), A.pin_entry);
    A.login_btn = gtk_button_new_with_label("Log in");
    g_signal_connect(A.login_btn, "clicked", G_CALLBACK(on_login), NULL);
    gtk_box_append(GTK_BOX(row), A.login_btn);
    A.logout_btn = gtk_button_new_with_label("Log out");
    gtk_widget_set_tooltip_text(A.logout_btn,
        "Closes the session; the module logs the token out when its last session closes.");
    g_signal_connect(A.logout_btn, "clicked", G_CALLBACK(on_logout), NULL);
    gtk_box_append(GTK_BOX(row), A.logout_btn);
    gtk_box_append(GTK_BOX(left), row);

    gtk_box_append(GTK_BOX(left), heading("Keys"));
    A.keys_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(A.keys_box), GTK_SELECTION_NONE);
    gtk_box_append(GTK_BOX(left), scrolled(A.keys_box, 160));
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    A.label_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(A.label_entry), "label for a new key pair");
    gtk_widget_set_hexpand(A.label_entry, TRUE);
    g_signal_connect(A.label_entry, "activate", G_CALLBACK(on_keygen), NULL);
    gtk_box_append(GTK_BOX(row), A.label_entry);
    A.keygen_btn = gtk_button_new_with_label("Generate composite key pair");
    g_signal_connect(A.keygen_btn, "clicked", G_CALLBACK(on_keygen), NULL);
    gtk_box_append(GTK_BOX(row), A.keygen_btn);
    gtk_box_append(GTK_BOX(left), row);

    GtkWidget *tabs = gtk_notebook_new();
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), left, gtk_label_new("Token"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), cert_tab(), gtk_label_new("Certificates"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), revocation_tab(), gtk_label_new("Revocation"));
    gtk_paned_set_start_child(GTK_PANED(paned), tabs);

    /* Right: the call log. */
    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(right, 8);
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *h = heading("PKCS#11 calls");
    gtk_widget_set_hexpand(h, TRUE);
    gtk_box_append(GTK_BOX(row), h);
    GtkWidget *clear = gtk_button_new_with_label("Clear");
    g_signal_connect(clear, "clicked", G_CALLBACK(on_clear_log), NULL);
    gtk_box_append(GTK_BOX(row), clear);
    gtk_box_append(GTK_BOX(right), row);
    A.log_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(A.log_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(A.log_view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(A.log_view), GTK_WRAP_WORD_CHAR);
    gtk_box_append(GTK_BOX(right), scrolled(A.log_view, 300));
    GtkWidget *note = gtk_label_new("PINs and attribute values are never shown here.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_widget_add_css_class(note, "dim-label");
    gtk_box_append(GTK_BOX(right), note);
    gtk_paned_set_end_child(GTK_PANED(paned), right);
    gtk_paned_set_position(GTK_PANED(paned), 540);

    /* Status. */
    A.status = gtk_label_new("Load a PKCS#11 module to begin.");
    gtk_label_set_xalign(GTK_LABEL(A.status), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(A.status), TRUE);
    gtk_label_set_selectable(GTK_LABEL(A.status), TRUE);
    gtk_box_append(GTK_BOX(outer), A.status);

    /* The log is on before the module is loaded, so C_Initialize shows. */
    pkiops_set_call_log(on_call, NULL);
    update_sensitivity();
    gtk_window_present(GTK_WINDOW(A.win));
}

int main(int argc, char **argv) {
    GtkApplication *app = gtk_application_new("com.chaharsou.FhsmGui",
                                              G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    int rc = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return rc;
}
