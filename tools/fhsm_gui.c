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
 *  Stage 4, the Signing tab: what fhsm-sign does. Raw detached signatures,
 *  streamed in 1 MiB blocks, and detached CMS over the SHA-512 of the data.
 *  Checking a CMS needs no login. A signature that does not match is a
 *  verdict, shown as one, and not an error.
 *
 *  Stage 5, operator mode, behind the switch at the top. The Certificates and
 *  Revocation tabs give way to three guided ones -- CA, Issue, Revoke -- that
 *  work for one CA set once, and refuse what the command line leaves to its
 *  user: re-initialising a token that holds one, a key label already on it, a certificate without CRL URLs,
 *  issuing while the published CRL is missing or expired. A revocation is
 *  published as soon as it is recorded, and the published CRL's expiry is
 *  re-read every minute. The refusals block; whoever needs the exception has
 *  exploration mode and the command-line tools, which are unchanged.
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
#include <openssl/bn.h>

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
    GtkWidget *init_box, *init_label, *init_so, *init_so2, *init_user, *init_user2;
    GtkWidget *keys_box, *label_entry, *keygen_btn, *keygen_alg, *delete_btn;
    GtkWidget *log_view, *status;
    /* What the object list shows, row for row: a row's index is its object's.
     * docs/fhsm-crypt-plan.md stage 0. */
    struct pkiops_object *objs;
    size_t n_objs;
    GtkWidget *attr_view;           /* the selected object's attributes */
    /* The slot whose token this window last listed, logged in, and found
     * empty -- or -1. Operator mode re-initialises only such a token. */
    long empty_slot;

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

    /* The Signing tab. */
    GtkWidget *sg_data_box, *sg_key_box, *sg_cmsv_btn;
    GtkWidget *sg_key_drop;
    char *sg_data_path, *sg_cert_path;

    /* Operator mode: the tabs it shows and hides, and the CA it works for. */
    int operator_mode;
    GtkWidget *page_certs, *page_revocation, *page_op_ca, *page_op_issue, *page_op_revoke;
    GtkWidget *op_key_drop, *op_ca_btn, *op_db_btn, *op_crl_btn, *op_urls_view;
    GtkWidget *op_crl_status, *op_issue_banner, *op_ca_signing_box;
    GtkWidget *op_new_label, *op_new_subject, *op_new_days, *op_new_alg;
    GtkWidget *op_csr_btn, *op_subject, *op_san, *op_profile, *op_days;
    GtkWidget *op_serial, *op_reason, *op_crl_days;
    char *op_ca_path, *op_db_path, *op_crl_path, *op_csr_path;

    int loaded, logged_in, busy;
    int closing;                    /* the widgets are going: touch none */
    struct pkiops_slot *slots;
    size_t n_slots;
    long selected;                  /* index into slots, or -1 */
    pkiops_handle session;
} A = { .selected = -1, .empty_slot = -1 };

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
    case 0x80000001UL: return "vendor: self-test (KAT) failed";
    case 0x80000002UL: return "vendor: integrity self-test failed";
    case 0x80000003UL: return "vendor: not approved in this mode";
    case 0x80000004UL: return "vendor: PIN throttled";
    case 0x80000007UL: return "vendor: secure heap exhausted";
    case 0x80000009UL: return "vendor: crypto provider unavailable";
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
    gtk_widget_set_sensitive(A.init_box,     !A.busy && A.loaded && !A.logged_in
                                             && A.selected >= 0);
    gtk_widget_set_sensitive(A.login_btn,    !A.busy && has_token && !A.logged_in);
    gtk_widget_set_sensitive(A.logout_btn,   !A.busy && A.logged_in);
    gtk_widget_set_sensitive(A.label_entry,  !A.busy && A.logged_in);
    gtk_widget_set_sensitive(A.keygen_btn,   !A.busy && A.logged_in);
    {
        GtkListBoxRow *r = gtk_list_box_get_selected_row(GTK_LIST_BOX(A.keys_box));
        int idx = r ? gtk_list_box_row_get_index(r) : -1;
        gtk_widget_set_sensitive(A.delete_btn, !A.busy && A.logged_in
                                               && idx >= 0 && (size_t)idx < A.n_objs);
    }
    gtk_widget_set_sensitive(A.cert_page,    !A.busy && A.logged_in);
    gtk_widget_set_sensitive(A.rv_db_box,     !A.busy);
    gtk_widget_set_sensitive(A.rv_revoke_box, !A.busy && A.db_path);
    gtk_widget_set_sensitive(A.rv_sign_box,   !A.busy && A.db_path && A.logged_in);
    gtk_widget_set_sensitive(A.sg_data_box,   !A.busy);
    gtk_widget_set_sensitive(A.sg_key_box,    !A.busy && A.sg_data_path && A.logged_in);
    gtk_widget_set_sensitive(A.sg_cmsv_btn,   !A.busy && A.sg_data_path);
    gtk_widget_set_sensitive(A.page_op_ca,    !A.busy);
    gtk_widget_set_sensitive(A.op_ca_signing_box, !A.busy && A.logged_in);
    gtk_widget_set_sensitive(A.page_op_issue, !A.busy && A.logged_in);
    gtk_widget_set_sensitive(A.page_op_revoke, !A.busy && A.logged_in);
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
                J_CSR, J_ROOT, J_ISSUE, J_DB_LOAD, J_REVOKE, J_CRL, J_OCSP,
                J_SIGN, J_VERIFY, J_CMS_SIGN, J_CMS_VERIFY,
                J_NEW_CA, J_REVOKE_PUBLISH, J_TOKEN_INIT, J_DELETE, J_ATTRS };

struct job {
    enum job_kind kind;
    char *module, *label;
    pkiops_handle slot, session;
    uint8_t *pin; size_t pin_len;
    uint8_t *so_pin; size_t so_pin_len;     /* J_TOKEN_INIT only */
    /* requests and issuance */
    char *subject, *san, *ca_path, *csr_path, *out_path;
    char **crl_urls;                /* NULL-terminated; NULL for none */
    int pem, days, profile;
    long serial;
    /* revocation */
    char *db_path, *serial_hex, *date, *req_path, *responder_path;
    int reason;                     /* RFC 5280 code, or -1 for none */
    /* signing: the data, and the signature, CMS or certificate read with it */
    char *data_path, *in_path, *cert_path;
    int operator_mode;              /* apply operator mode's refusals */
    int alg;                        /* enum pkiops_alg, for a key pair */
    int skey;                       /* enum pkiops_skey for a secret key, or -1 */
    /* results */
    int rc;
    struct p11_err e;
    struct pkiops_slot *slots; size_t n_slots;
    struct pkiops_key  *keys;  size_t n_keys;
    struct pkiops_object *objs; size_t n_objs;
    pkiops_handle *del; size_t n_del;   /* J_DELETE: what was ticked */
    size_t n_deleted;                   /* J_DELETE: how many went */
    pkiops_handle object;               /* J_ATTRS: the object described */
    struct pkiops_attr *attrs; size_t n_attrs;
    int pop_valid;
    size_t out_len;
    fhsm_rev_db_t db; int have_db;  /* the database as the job left it */
    int already; char already_date[16];
    fhsm_ocsp_stats_t stats;
    int verdict;                    /* 1 matches, 0 does not, -1 unreadable CMS */
};

static void job_free(gpointer p) {
    struct job *j = p;
    if (j->pin) { OPENSSL_cleanse(j->pin, j->pin_len); g_free(j->pin); }
    if (j->so_pin) { OPENSSL_cleanse(j->so_pin, j->so_pin_len); g_free(j->so_pin); }
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
    g_free(j->data_path);
    g_free(j->in_path);
    g_free(j->cert_path);
    if (j->have_db) fhsm_rev_db_free(&j->db);
    free(j->slots);
    free(j->keys);
    free(j->objs);
    g_free(j->del);
    free(j->attrs);
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

/* Written whole or not at all: g_file_set_contents writes a temporary file and
 * renames it into place. A published CRL is read by a web server while the
 * operator replaces it, and a reader must see the old list or the new one,
 * never half of either. */
static int write_out(const char *path, const uint8_t *der, size_t n, int pem,
                     const char *pem_label, struct p11_err *e) {
    const char *bytes = (const char *)der;
    gsize len = n;
    BIO *b = NULL;
    if (pem) {
        char *p = NULL;
        b = BIO_new(BIO_s_mem());
        if (!b || PEM_write_bio(b, pem_label, "", der, (long)n) <= 0) {
            BIO_free(b);
            return err_set(e, 2, "encoding %s as PEM failed\n", path);
        }
        long l = BIO_get_mem_data(b, &p);
        bytes = p;
        len = (gsize)l;
    }
    GError *ge = NULL;
    int ok = g_file_set_contents(path, bytes, (gssize)len, &ge);
    BIO_free(b);
    if (!ok) {
        err_set(e, 2, "cannot write %s: %s\n", path, ge->message);
        g_error_free(ge);
        return 2;
    }
    return 0;
}

/* Operator mode refuses a key label already on the token: two objects under
 * one label make every later "the key called X" ambiguous, and pkiops refuses
 * to sign with an ambiguous label -- after the second key exists. Checked on
 * the token itself, not on the list the window last showed. */
static int label_in_use(pkiops_handle s, const char *label, struct p11_err *e) {
    /* Every key, secret keys included: an AES key and a key pair under one
     * label are as ambiguous as two key pairs. */
    struct pkiops_object *k = NULL; size_t n = 0;
    int rc = pkiops_objects(s, PKIOPS_OBJS_KEYS, &k, &n, e);
    if (rc) return rc;
    int used = 0;
    for (size_t i = 0; i < n; i++) if (!strcmp(k[i].label, label)) used = 1;
    free(k);
    return used ? err_set(e, 3, "the label \"%s\" is already on this token. Operator "
                                "mode refuses a second key under it: every later use of "
                                "the label would be ambiguous.\n", label) : 0;
}

/* A certificate's serial in hex, as `openssl x509 -serial` prints it -- the
 * form an operator compares against. g_malloc'd, or NULL if it does not
 * parse. */
static char *cert_serial_hex(const uint8_t *der, size_t n) {
    const unsigned char *p = der;
    X509 *x = d2i_X509(NULL, &p, (long)n);
    if (!x) return NULL;
    BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get0_serialNumber(x), NULL);
    char *hex = bn ? BN_bn2hex(bn) : NULL;
    char *out = hex ? g_strdup(hex) : NULL;
    OPENSSL_free(hex);
    BN_free(bn);
    X509_free(x);
    return out;
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

/* fhsm-token init, minus the command line: the PIN lengths checked against
 * the bounds the token itself advertises, then C_InitToken and the user PIN.
 * Both PINs are wiped as soon as the module has answered. */
static void run_token_init(struct job *j) {
    struct pkiops_token_info ti;
    struct p11_err ignored;
    unsigned long lo = 4, hi = 64;
    if (pkiops_token_info(j->slot, &ti, &ignored) == 0 && ti.min_pin && ti.min_pin <= ti.max_pin) {
        lo = ti.min_pin;
        hi = ti.max_pin;
    }
    int bad_so   = j->so_pin_len < lo || j->so_pin_len > hi;
    int bad_user = j->pin_len    < lo || j->pin_len    > hi;
    const char *which = bad_so && bad_user ? "the SO PIN and the user PIN are"
                      : bad_so             ? "the SO PIN is"
                      : bad_user           ? "the user PIN is" : NULL;
    if (which)
        j->rc = err_set(&j->e, 1, "%s outside the token's accepted length (%lu..%lu "
                        "characters). Nothing was changed.\n", which, lo, hi);
    else
        j->rc = pkiops_token_init(j->slot, j->so_pin, j->so_pin_len, j->pin, j->pin_len,
                                  j->label, &j->e);
    OPENSSL_cleanse(j->so_pin, j->so_pin_len);
    OPENSSL_cleanse(j->pin, j->pin_len);
    if (!j->rc) j->rc = pkiops_slots(&j->slots, &j->n_slots, &j->e);
}

/* --- signing, on the worker thread -------------------------------------- */

#define CHUNK (1u << 20)        /* fhsm-sign's block: 1 MiB */

enum feed { FEED_SIGN, FEED_VERIFY, FEED_HASH };

/* The whole file, in blocks, to the module or to the hash -- one function for
 * all three, as in fhsm-sign, so signing and verifying cannot disagree about
 * what they consumed. Nothing holds the file whole. */
static int feed_file(const char *path, enum feed how, pkiops_handle s,
                     struct pkiops_hash *h, struct p11_err *e) {
    FILE *f = fopen(path, "rb");
    if (!f) return err_set(e, 2, "cannot read %s: %s\n", path, g_strerror(errno));
    uint8_t *buf = g_malloc(CHUNK);
    int rc = 0;
    for (;;) {
        size_t n = fread(buf, 1, CHUNK, f);
        if (n) {
            rc = how == FEED_SIGN   ? pkiops_sign_update(s, buf, n, e)
               : how == FEED_VERIFY ? pkiops_verify_update(s, buf, n, e)
               :                      pkiops_hash_update(h, buf, n, e);
            if (rc) break;
        }
        if (n < CHUNK) {
            if (ferror(f)) rc = err_set(e, 2, "reading %s failed\n", path);
            break;
        }
    }
    g_free(buf);
    fclose(f);
    return rc;
}

/* A file's digest under `name` -- SHA256, SHA384 or SHA512 -- for CMS. */
static int hash_file(const char *path, const char *name, uint8_t out[64], size_t *out_len,
                     struct p11_err *e) {
    struct pkiops_hash *h = pkiops_hash_begin(name, e);
    if (!h) return e->code ? e->code : 2;
    int rc = feed_file(path, FEED_HASH, 0, h, e);
    /* Ended either way: the context is freed by the end call. */
    struct p11_err ignored;
    int end = pkiops_hash_end(h, out, out_len, rc ? &ignored : e);
    return rc ? rc : end;
}

static void run_sign(struct job *j) {
    if ((j->rc = pkiops_sign_begin(j->session, j->label, &j->e)) != 0) return;
    j->rc = feed_file(j->data_path, FEED_SIGN, j->session, NULL, &j->e);
    /* The operation is ended even when reading failed: the session outlives
     * this job here, unlike in fhsm-sign, and an operation left active would
     * refuse the next C_SignInit. */
    uint8_t *sig = NULL; size_t n = 0;
    struct p11_err ignored;
    int end = pkiops_sign_end(j->session, &sig, &n, j->rc ? &ignored : &j->e);
    if (!j->rc) j->rc = end;
    if (!j->rc) j->rc = write_out(j->out_path, sig, n, 0, NULL, &j->e);
    j->out_len = n;
    free(sig);
}

static void run_verify(struct job *j) {
    /* The signature first: a missing or oversized one fails before any data
     * is read. 64 KiB, as in fhsm-sign: larger than any signature it makes. */
    gchar *sig = NULL; gsize n = 0; GError *ge = NULL;
    if (!g_file_get_contents(j->in_path, &sig, &n, &ge)) {
        j->rc = err_set(&j->e, 2, "cannot read %s: %s\n", j->in_path, ge->message);
        g_error_free(ge);
        return;
    }
    if (n == 0 || n > 65536) {
        j->rc = err_set(&j->e, 2, n ? "%s is larger than any signature this tool produces\n"
                                    : "%s is empty\n", j->in_path);
        g_free(sig);
        return;
    }
    if ((j->rc = pkiops_verify_begin(j->session, j->label, &j->e)) == 0) {
        j->rc = feed_file(j->data_path, FEED_VERIFY, j->session, NULL, &j->e);
        /* Ended either way, for the same reason as signing. */
        struct p11_err ignored;
        int end = pkiops_verify_end(j->session, (const uint8_t *)sig, n, &j->verdict,
                                    j->rc ? &ignored : &j->e);
        if (!j->rc) j->rc = end;
    }
    g_free(sig);
}

static void run_cms_sign(struct job *j) {
    uint8_t *cert = NULL; size_t cert_len = 0, n = 262144;
    uint8_t dg[64]; size_t dl = 0;
    /* The digest is the key's: its algorithm's own hash where it has one. */
    enum pkiops_alg a;
    if ((j->rc = pkiops_key_alg(j->session, j->label, &a, &j->e)) != 0) return;
    if ((j->rc = read_der(j->cert_path, &cert, &cert_len, &j->e)) != 0) return;
    if ((j->rc = hash_file(j->data_path, pkiops_alg_digest(a), dg, &dl, &j->e)) == 0) {
        uint8_t *der = g_malloc(n);
        j->rc = pkiops_cms_sign(j->session, j->label, cert, cert_len, dg, dl, der, &n, &j->e);
        if (!j->rc) j->rc = write_out(j->out_path, der, n, 0, NULL, &j->e);
        j->out_len = n;
        g_free(der);
    }
    g_free(cert);
}

/* No module, no PIN: the signer's certificate is inside the CMS. */
static void run_cms_verify(struct job *j) {
    uint8_t *cms = NULL; size_t cms_len = 0;
    uint8_t dg[64]; size_t dl = 0;
    if ((j->rc = read_der(j->in_path, &cms, &cms_len, &j->e)) != 0) return;
    /* The structure names its digest. One it cannot name is hashed with
     * SHA-512 and reaches the verdict "not a CMS this can read". */
    const char *dn = NULL;
    if (pkiops_cms_digest(cms, cms_len, &dn)) dn = "SHA512";
    if ((j->rc = hash_file(j->data_path, dn, dg, &dl, &j->e)) == 0)
        j->rc = pkiops_cms_verify(cms, cms_len, dg, dl, &j->verdict, &j->e);
    g_free(cms);
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

/* The keys, for the drop-downs that sign and their algorithms, and every
 * object, for the list on the Token tab. Read together wherever either was,
 * so the two cannot describe different moments of the token. */
static int list_objects(struct job *j, struct p11_err *e) {
    int rc = pkiops_keys(j->session, &j->keys, &j->n_keys, e);
    if (!rc) rc = pkiops_objects(j->session, PKIOPS_OBJS_ALL, &j->objs, &j->n_objs, e);
    return rc;
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
        if (!j->rc) j->rc = list_objects(j, &j->e);
        break;
    case J_KEYS:
        j->rc = list_objects(j, &j->e);
        break;
    case J_ATTRS:
        j->rc = pkiops_object_attrs(j->session, j->object, &j->attrs, &j->n_attrs, &j->e);
        break;
    case J_DELETE: {
        /* Stop at the first refusal: the rest was ticked together with it,
         * and the list read afterwards shows exactly what is left. */
        for (size_t i = 0; i < j->n_del; i++) {
            if ((j->rc = pkiops_destroy(j->session, j->del[i], &j->e)) != 0) break;
            j->n_deleted++;
        }
        struct p11_err ignored;
        if (list_objects(j, j->rc ? &ignored : &j->e) && !j->rc) j->rc = j->e.code;
        break;
    }
    case J_KEYGEN: {
        pkiops_handle hp = 0, hk = 0;
        if (j->operator_mode) j->rc = label_in_use(j->session, j->label, &j->e);
        if (!j->rc && j->skey >= 0)
            j->rc = pkiops_keygen_secret(j->session, j->label,
                                         (enum pkiops_skey)j->skey, &hk, &j->e);
        else if (!j->rc)
            j->rc = pkiops_keygen_alg(j->session, j->label,
                                      (enum pkiops_alg)j->alg, &hp, &hk, &j->e);
        if (!j->rc) j->rc = list_objects(j, &j->e);
        break;
    }
    case J_NEW_CA: {
        /* A key that is the CA's from birth: a label nothing else uses, the
         * pair, and the self-signed root, in that order. */
        pkiops_handle hp = 0, hk = 0;
        j->rc = label_in_use(j->session, j->label, &j->e);
        if (!j->rc) j->rc = pkiops_keygen_alg(j->session, j->label,
                                              (enum pkiops_alg)j->alg, &hp, &hk, &j->e);
        if (!j->rc) {
            size_t n = DER_MAX;
            uint8_t *der = g_malloc(n);
            j->rc = pkiops_root(j->session, j->label, j->subject, 1, j->days, der, &n, &j->e);
            if (!j->rc) j->rc = write_out(j->out_path, der, n, 1, "CERTIFICATE", &j->e);
            g_free(der);
        }
        struct p11_err ignored;
        if (list_objects(j, j->rc ? &ignored : &j->e) && !j->rc)
            j->rc = j->e.code;
        break;
    }
    case J_REVOKE_PUBLISH:
        /* Record, then publish at once: in operator mode a revocation is not
         * finished until a list says so. */
        run_revoke(j);
        if (j->rc || j->already) break;
        fhsm_rev_db_free(&j->db);
        j->have_db = 0;
        run_crl(j);
        break;
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
            /* Shown with the result: the serial is random, 160 bits, and it
             * is the number a revocation will ask for. */
            if (!j->rc && j->pop_valid) j->serial_hex = cert_serial_hex(der, n);
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
    case J_TOKEN_INIT: run_token_init(j); break;
    case J_SIGN:       run_sign(j);       break;
    case J_VERIFY:     run_verify(j);     break;
    case J_CMS_SIGN:   run_cms_sign(j);   break;
    case J_CMS_VERIFY: run_cms_verify(j); break;
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

/* --- operator mode: the published CRL ------------------------------------ */

enum crl_state { CRL_NONE, CRL_UNREADABLE, CRL_FRESH, CRL_DUE, CRL_EXPIRED };

/* What the CRL published at `path` says about itself, and a sentence saying
 * it. Due means less than a third of its validity is left: time to publish
 * the next one, while the current one still holds. Read on the main thread:
 * a CRL is small, and this runs once a minute. */
static enum crl_state crl_state_of(const char *path, char *text, size_t cap) {
    if (!path) { snprintf(text, cap, "No CRL location chosen."); return CRL_NONE; }
    gchar *buf = NULL; gsize len = 0;
    if (!g_file_get_contents(path, &buf, &len, NULL)) {
        snprintf(text, cap, "No CRL published at %s yet.", path);
        return CRL_NONE;
    }
    X509_CRL *crl = NULL;
    if (len > 11 && memcmp(buf, "-----BEGIN ", 11) == 0) {
        BIO *b = BIO_new_mem_buf(buf, (int)len);
        if (b) crl = PEM_read_bio_X509_CRL(b, NULL, NULL, NULL);
        BIO_free(b);
    } else {
        const unsigned char *p = (const unsigned char *)buf;
        crl = d2i_X509_CRL(NULL, &p, (long)len);
    }
    g_free(buf);
    const ASN1_TIME *this_up = crl ? X509_CRL_get0_lastUpdate(crl) : NULL;
    const ASN1_TIME *next_up = crl ? X509_CRL_get0_nextUpdate(crl) : NULL;
    int dd = 0, ds = 0, td = 0, ts = 0;
    struct tm next_tm;
    memset(&next_tm, 0, sizeof next_tm);
    if (!crl || !this_up || !next_up
        || !ASN1_TIME_diff(&dd, &ds, NULL, next_up)
        || !ASN1_TIME_diff(&td, &ts, this_up, next_up)
        || !ASN1_TIME_to_tm(next_up, &next_tm)) {
        X509_CRL_free(crl);
        snprintf(text, cap, "%s is not a CRL this interface can read, or has no "
                 "nextUpdate.", path);
        return CRL_UNREADABLE;
    }
    X509_CRL_free(crl);
    char when[32];
    strftime(when, sizeof when, "%Y-%m-%d %H:%M UTC", &next_tm);
    long long left = (long long)dd * 86400 + ds, total = (long long)td * 86400 + ts;
    if (left <= 0) {
        snprintf(text, cap, "The CRL at %s EXPIRED on %s. Verifiers now treat every "
                 "certificate pointing at it as unverifiable. Publish a new one.",
                 path, when);
        return CRL_EXPIRED;
    }
    char in[32];
    if (left >= 86400) snprintf(in, sizeof in, "%lld days", left / 86400);
    else               snprintf(in, sizeof in, "%lld hours", left / 3600);
    if (left * 3 < total) {
        snprintf(text, cap, "The CRL at %s expires on %s, in %s: less than a third of "
                 "its validity is left. Publish the next one now.", path, when, in);
        return CRL_DUE;
    }
    snprintf(text, cap, "The CRL at %s is valid until %s (%s).", path, when, in);
    return CRL_FRESH;
}

static void set_state_class(GtkWidget *w, enum crl_state s) {
    gtk_widget_remove_css_class(w, "error");
    gtk_widget_remove_css_class(w, "warning");
    gtk_widget_remove_css_class(w, "success");
    gtk_widget_add_css_class(w, s == CRL_FRESH ? "success"
                              : s == CRL_DUE   ? "warning" : "error");
}

static void refresh_crl_status(void) {
    if (A.closing || !A.op_crl_status) return;
    char text[1200];
    enum crl_state s = crl_state_of(A.op_crl_path, text, sizeof text);
    gtk_label_set_text(GTK_LABEL(A.op_crl_status), text);
    gtk_label_set_text(GTK_LABEL(A.op_issue_banner), text);
    set_state_class(A.op_crl_status, s);
    set_state_class(A.op_issue_banner, s);
}

static gboolean on_crl_tick(gpointer ud) {
    (void)ud;
    if (A.closing) return G_SOURCE_REMOVE;
    refresh_crl_status();
    return G_SOURCE_CONTINUE;
}

/* A file button's label is the file's name; the tooltip, its path. */
static void set_file_label(GtkWidget *btn, const char *path) {
    char *base = g_path_get_basename(path);
    gtk_button_set_label(GTK_BUTTON(btn), base);
    g_free(base);
    gtk_widget_set_tooltip_text(btn, path);
}

static void select_key(GtkWidget *drop, const char *label) {
    guint n = g_list_model_get_n_items(G_LIST_MODEL(A.key_labels));
    for (guint i = 0; i < n; i++)
        if (!strcmp(gtk_string_list_get_string(A.key_labels, i), label)) {
            gtk_drop_down_set_selected(GTK_DROP_DOWN(drop), i);
            return;
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

/* The object list and what it shows, emptied together. */
static void clear_objects(void) {
    clear_list(A.keys_box);
    gtk_label_set_text(GTK_LABEL(A.attr_view), "");
    free(A.objs);
    A.objs = NULL;
    A.n_objs = 0;
}

static void show_keys(struct job *j) {
    /* The Certificates tab signs with a private key, named by its label. */
    clear_key_labels();
    for (size_t i = 0; i < j->n_keys; i++)
        if (j->keys[i].is_private && j->keys[i].label[0])
            gtk_string_list_append(A.key_labels, j->keys[i].label);
    /* Every object, certificates first, each with the algorithm the signing
     * tabs know it by when it has one. The rows are the objects, in order, so
     * a selected row's index is the object to delete. */
    clear_objects();
    A.objs = j->objs; A.n_objs = j->n_objs;
    j->objs = NULL; j->n_objs = 0;
    for (size_t i = 0; i < A.n_objs; i++) {
        const struct pkiops_object *o = &A.objs[i];
        /* A secret key or an rsa-oaep key carries its own name; a signing
         * key's comes from pkiops_keys. */
        const char *alg = o->alg;
        for (size_t k = 0; !alg[0] && k < j->n_keys; k++)
            if (j->keys[k].handle == o->handle) alg = j->keys[k].alg;
        char t[200];
        snprintf(t, sizeof t, "%-11s  object %lu   \"%s\"   %s",
                 pkiops_obj_class_name(o->cls), o->handle, o->label, alg);
        list_add(A.keys_box, t);
    }
    /* Logged in, so the list is everything the token holds for this user:
     * an empty one is what operator mode needs to see before it will
     * re-initialise the token. */
    A.empty_slot = (A.n_objs == 0 && A.selected >= 0 && (size_t)A.selected < A.n_slots)
                 ? (long)A.slots[A.selected].id : -1;
    if (A.n_objs == 0) {
        list_add(A.keys_box, "(nothing on this token)");
        GtkListBoxRow *r = gtk_list_box_get_row_at_index(GTK_LIST_BOX(A.keys_box), 0);
        if (r) gtk_list_box_row_set_selectable(r, FALSE);
    }
}

static void job_done(GObject *src, GAsyncResult *res, gpointer ud) {
    (void)src; (void)ud;
    struct job *j = g_task_get_task_data(G_TASK(res));
    A.busy = 0;
    switch (j->kind) {
    case J_LOAD:
        if (j->rc) {
            status_err("Loading the module", &j->e);
            /* The module says which of its three integrity failures this is
             * on stderr, and they call for different things; the window only
             * has the code, so it points there instead of guessing. */
            if (strstr(j->e.msg, "0x80000002"))
                status("Loading the module: its integrity self-test refused to start "
                       "(0x80000002). The terminal that launched this window says why: "
                       "an unsigned build of your own wants `make integrity`; a digest "
                       "that does not match means the file changed after signing.");
            break;
        }
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
        clear_objects();
        clear_key_labels();
        A.empty_slot = -1;
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
            status_err(j->skey >= 0 ? "Generating the key" : "Generating the key pair", &j->e);
            if (strstr(j->e.msg, "0x70")) {
                char msg[400];
                snprintf(msg, sizeof msg, "Generating the key: this module does not "
                         "offer %s (CKR_MECHANISM_INVALID).%s",
                         j->skey >= 0 ? pkiops_skey_name((enum pkiops_skey)j->skey)
                                      : pkiops_alg_name((enum pkiops_alg)j->alg),
                         j->skey < 0 && j->alg == PKIOPS_ALG_COMPOSITE
                             ? " The composite exists only in builds made with "
                               "PROFILE=all-mechanisms." : "");
                status(msg);
            }
        } else {
            show_keys(j);
            status(j->skey == PKIOPS_SKEY_RSA_OAEP ? "Encryption key pair generated."
                   : j->skey >= 0 ? "Secret key generated." : "Key pair generated.");
        }
        break;
    case J_DELETE: {
        char msg[4400];
        if (j->rc) {
            char head[96];
            snprintf(head, sizeof head, "Deleting (%zu of %zu deleted before the refusal)",
                     j->n_deleted, j->n_del);
            snprintf(msg, sizeof msg, "%s: %s", head, j->e.msg);
            size_t n = strlen(msg);
            if (n && msg[n-1] == '\n') msg[n-1] = '\0';
            status(msg);
        }
        if (j->keys || j->objs) show_keys(j);
        if (!j->rc) {
            snprintf(msg, sizeof msg, "Deleted %zu object%s from the token.%s",
                     j->n_deleted, j->n_deleted == 1 ? "" : "s",
                     A.n_objs == 0 ? " The token is now empty: log out to re-initialise it."
                                   : "");
            status(msg);
        }
        break;
    }
    case J_ATTRS: {
        /* Shown only if that object is still the one selected: a click on
         * another row while this ran has its own job coming. */
        GtkListBoxRow *r = gtk_list_box_get_selected_row(GTK_LIST_BOX(A.keys_box));
        int idx = r ? gtk_list_box_row_get_index(r) : -1;
        if (idx < 0 || (size_t)idx >= A.n_objs || A.objs[idx].handle != j->object) break;
        if (j->rc) { gtk_label_set_text(GTK_LABEL(A.attr_view), j->e.msg); break; }
        GString *t = g_string_new(NULL);
        for (size_t i = 0; i < j->n_attrs; i++)
            g_string_append_printf(t, "%s%-24s %s", i ? "\n" : "",
                                   j->attrs[i].name, j->attrs[i].value);
        gtk_label_set_text(GTK_LABEL(A.attr_view), t->str);
        g_string_free(t, TRUE);
        break;
    }
    case J_LOGOUT:
        A.logged_in = 0;
        A.session = 0;
        clear_objects();
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
        int w = snprintf(msg, sizeof msg, "%s written to %s (%zu bytes of DER, saved as %s).%s%s",
                         j->kind == J_CSR ? "Request" : "Certificate",
                         j->out_path, j->out_len, j->pem ? "PEM" : "DER",
                         j->serial_hex ? " Serial: " : "",
                         j->serial_hex ? j->serial_hex : "");
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
    case J_SIGN:
    case J_CMS_SIGN: {
        if (j->rc) { status_err("Signing", &j->e); break; }
        char msg[1200];
        snprintf(msg, sizeof msg, "%zu-byte detached %s written to %s.", j->out_len,
                 j->kind == J_SIGN ? "signature" : "CMS SignedData", j->out_path);
        status(msg);
        break;
    }
    case J_VERIFY: {
        if (j->rc) { status_err("Verifying", &j->e); break; }
        char msg[400];
        /* A signature that does not match is a verdict, not a failure to run,
         * and the two are worded apart, as fhsm-sign's exit codes are. */
        snprintf(msg, sizeof msg, j->verdict
                 ? "VERIFIED: the signature matches this data under key \"%s\"."
                 : "NOT VERIFIED: the signature does not match this data under key \"%s\".",
                 j->label);
        status(msg);
        break;
    }
    case J_CMS_VERIFY:
        if (j->rc) { status_err("Checking the CMS", &j->e); break; }
        status(j->verdict > 0 ? "VERIFIED: the CMS matches this data."
             : j->verdict == 0 ? "NOT VERIFIED: the CMS does not match this data."
             : "This is not a composite CMS this interface can read. That is a "
               "different problem from a signature that does not match.");
        break;
    case J_TOKEN_INIT: {
        if (j->rc) { status_err("Initialising the token", &j->e); break; }
        show_slots(j);
        char msg[300];
        snprintf(msg, sizeof msg, "Slot %lu initialised as \"%s\", user PIN set. Next: "
                 "choose it, log in, and generate a key pair.", j->slot, j->label);
        status(msg);
        break;
    }
    case J_NEW_CA: {
        if (j->n_keys) show_keys(j);
        if (j->rc) { status_err("Creating the CA", &j->e); break; }
        /* The new CA becomes the context: its key and its certificate. */
        g_free(A.op_ca_path);
        A.op_ca_path = g_strdup(j->out_path);
        set_file_label(A.op_ca_btn, A.op_ca_path);
        select_key(A.op_key_drop, j->label);
        char msg[1200];
        snprintf(msg, sizeof msg, "CA \"%s\" created: key pair on the token, root "
                 "certificate in %s. Next: choose the database and where the CRL is "
                 "published, then publish the first CRL.", j->label, j->out_path);
        status(msg);
        break;
    }
    case J_REVOKE_PUBLISH: {
        if (j->rc) { status_err("Revoking and publishing", &j->e); refresh_crl_status(); break; }
        char msg[1200];
        if (j->already)
            snprintf(msg, sizeof msg, "Serial %s is already revoked, on %s. Nothing "
                     "changed, nothing published.", j->serial_hex, j->already_date);
        else
            snprintf(msg, sizeof msg, "Revoked, and published: CRL number %llu, %zu "
                     "revoked, valid %d days, at %s.", j->db.crl_number, j->db.n,
                     j->days, j->out_path);
        status(msg);
        refresh_crl_status();
        break;
    }
    }
    if (j->kind == J_CRL) refresh_crl_status();
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

/* What the status line says while a job runs. */
static const char *running_text(enum job_kind k) {
    switch (k) {
    case J_CSR:        return "Signing the request...";
    case J_ROOT:       return "Signing the root...";
    case J_ISSUE:      return "Checking the request, then issuing...";
    case J_CRL:        return "Signing the CRL...";
    case J_OCSP:       return "Answering the OCSP request...";
    case J_SIGN:       return "Signing: the data is streamed to the module...";
    case J_VERIFY:     return "Verifying: the data is streamed to the module...";
    case J_CMS_SIGN:   return "Hashing the data, then signing...";
    case J_CMS_VERIFY: return "Hashing the data, then checking the CMS...";
    case J_NEW_CA:     return "Creating the CA: key pair, then the root...";
    case J_TOKEN_INIT: return "Initialising the token: both PINs are derived, which takes a moment...";
    case J_DELETE:     return "Deleting from the token...";
    default:           return "Working...";
    }
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
        status("This slot holds no token. Initialise one below.");
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

static void clear_init_pins(void) {
    gtk_editable_set_text(GTK_EDITABLE(A.init_so), "");
    gtk_editable_set_text(GTK_EDITABLE(A.init_so2), "");
    gtk_editable_set_text(GTK_EDITABLE(A.init_user), "");
    gtk_editable_set_text(GTK_EDITABLE(A.init_user2), "");
}

static void on_init_answered(GObject *src, GAsyncResult *res, gpointer data) {
    struct job *j = data;
    int choice = gtk_alert_dialog_choose_finish(GTK_ALERT_DIALOG(src), res, NULL);
    if (choice != 1 || A.closing || A.busy || A.logged_in) { job_free(j); return; }
    status(running_text(J_TOKEN_INIT));
    start(j);
}

/* fhsm-token init. Each PIN is typed twice, as a window cannot be scrolled
 * back to check what was typed; all four fields are cleared as soon as they
 * are read, whatever happens next. Re-initialising a token that holds one
 * destroys every key on it: exploration mode asks, as `--force` does at the
 * command line, and operator mode refuses. */
static void on_init(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (A.busy || !A.loaded || A.logged_in || A.selected < 0
        || (size_t)A.selected >= A.n_slots) return;
    const struct pkiops_slot *sl = &A.slots[A.selected];
    const char *label = gtk_editable_get_text(GTK_EDITABLE(A.init_label));
    if (!label || !*label) label = "freehsm";       /* fhsm-token's default */
    if (strlen(label) > 32) {
        status("The token label is at most 32 characters (PKCS#11 pads it to exactly that).");
        return;
    }
    /* Operator mode re-initialises a token only once it has seen it empty:
     * listed while logged in, with nothing on it. Anything else could hold a
     * CA's key, and C_InitToken does not ask. */
    int seen_empty = sl->has_token && A.empty_slot == (long)sl->id;
    if (A.operator_mode && sl->has_token && !seen_empty) {
        clear_init_pins();
        status("Refused in operator mode: this token may hold keys, and re-initialising "
               "destroys every one. Log in, delete what is on it until the list is empty, "
               "log out, then re-initialise. Exploration mode asks instead of refusing.");
        return;
    }
    const char *so = gtk_editable_get_text(GTK_EDITABLE(A.init_so));
    const char *so2 = gtk_editable_get_text(GTK_EDITABLE(A.init_so2));
    const char *up = gtk_editable_get_text(GTK_EDITABLE(A.init_user));
    const char *up2 = gtk_editable_get_text(GTK_EDITABLE(A.init_user2));
    const char *wrong = !*so || !*up        ? "Type both PINs, each twice."
                      : strcmp(so, so2)     ? "The two entries of the SO PIN differ."
                      : strcmp(up, up2)     ? "The two entries of the user PIN differ."
                      :                       NULL;
    if (wrong) { clear_init_pins(); status(wrong); return; }

    struct job *j = g_new0(struct job, 1);
    j->kind = J_TOKEN_INIT;
    j->slot = sl->id;
    j->label = g_strdup(label);
    j->so_pin_len = strlen(so);
    j->so_pin = g_malloc(j->so_pin_len);
    memcpy(j->so_pin, so, j->so_pin_len);
    j->pin_len = strlen(up);
    j->pin = g_malloc(j->pin_len);
    memcpy(j->pin, up, j->pin_len);
    clear_init_pins();

    if (!sl->has_token) {
        status(running_text(J_TOKEN_INIT));
        start(j);
        return;
    }
    GtkAlertDialog *d = gtk_alert_dialog_new("Re-initialise slot %lu (\"%s\")?",
                                             sl->id, sl->label);
    gtk_alert_dialog_set_detail(d, seen_empty
        ? "This token was empty when this window last listed it. C_InitToken destroys "
          "whatever another program has put on it since. This is not undone."
        : "C_InitToken destroys every object on the token: every key, a CA's included. "
          "This is not undone.");
    const char *const buttons[] = { "Cancel", "Destroy and re-initialise", NULL };
    gtk_alert_dialog_set_buttons(d, buttons);
    gtk_alert_dialog_set_cancel_button(d, 0);
    gtk_alert_dialog_set_default_button(d, 0);
    gtk_alert_dialog_choose(d, GTK_WINDOW(A.win), NULL, on_init_answered, j);
    g_object_unref(d);
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
    j->operator_mode = A.operator_mode;
    /* One list: the signature algorithms, then the secret keys. */
    int sel = (int)gtk_drop_down_get_selected(GTK_DROP_DOWN(A.keygen_alg));
    j->alg = sel < PKIOPS_ALG_COUNT ? sel : -1;
    j->skey = sel < PKIOPS_ALG_COUNT ? -1 : sel - PKIOPS_ALG_COUNT;
    char msg[96];
    if (j->skey >= 0)
        snprintf(msg, sizeof msg, "Generating a %s secret key...",
                 pkiops_skey_name((enum pkiops_skey)j->skey));
    else
        snprintf(msg, sizeof msg, "Generating a %s key pair...",
                 pkiops_alg_name((enum pkiops_alg)j->alg));
    status(msg);
    start(j);
}

/* --- the Certificates tab ------------------------------------------------- */

static const char *chosen_key(GtkWidget *drop) {
    GtkStringObject *o = gtk_drop_down_get_selected_item(GTK_DROP_DOWN(drop));
    return o ? gtk_string_object_get_string(o) : NULL;
}

/* --- deleting objects (docs/fhsm-crypt-plan.md stage 0) ------------------ */

static void on_object_selected(GtkListBox *box, GtkListBoxRow *row, gpointer ud) {
    (void)box; (void)ud;
    if (A.closing) return;          /* the list empties itself as it is destroyed */
    update_sensitivity();
    int idx = row ? gtk_list_box_row_get_index(row) : -1;
    if (idx < 0 || (size_t)idx >= A.n_objs || !A.logged_in) {
        gtk_label_set_text(GTK_LABEL(A.attr_view), "");
        return;
    }
    if (A.busy) {                   /* one call into the module at a time */
        gtk_label_set_text(GTK_LABEL(A.attr_view), "Busy: select the row again in a moment.");
        return;
    }
    struct job *j = g_new0(struct job, 1);
    j->kind = J_ATTRS;
    j->session = A.session;
    j->object = A.objs[idx].handle;
    gtk_label_set_text(GTK_LABEL(A.attr_view), "Reading the attributes...");
    /* Not start(): that takes the focus off whatever has it, so that an entry
     * turning insensitive gets its focus-out -- and here what has the focus is
     * the list, whose arrow keys should keep moving through it. */
    A.busy = 1;
    update_sensitivity();
    GTask *t = g_task_new(NULL, NULL, job_done, NULL);
    g_task_set_task_data(t, j, job_free);
    g_task_run_in_thread(t, run_job);
    g_object_unref(t);
}

/* The confirmation: one tick box per object sharing the label, the clicked
 * one ticked, the others not. A private key, its public half and a
 * certificate usually go together, but which of them goes is the operator's
 * to say, and the window will not guess. */
struct del_ask {
    GtkWidget *win;
    GtkWidget **checks;
    pkiops_handle *handles;
    size_t n;
};

static void del_ask_free(gpointer p) {
    struct del_ask *d = p;
    g_free(d->checks);
    g_free(d->handles);
    g_free(d);
}

static void on_del_cancel(GtkButton *b, gpointer data) {
    (void)b;
    struct del_ask *d = data;
    gtk_window_destroy(GTK_WINDOW(d->win));
}

static void on_del_confirm(GtkButton *b, gpointer data) {
    (void)b;
    struct del_ask *d = data;
    pkiops_handle *pick = g_new(pkiops_handle, d->n ? d->n : 1);
    size_t n = 0;
    for (size_t i = 0; i < d->n; i++)
        if (gtk_check_button_get_active(GTK_CHECK_BUTTON(d->checks[i]))) pick[n++] = d->handles[i];
    gtk_window_destroy(GTK_WINDOW(d->win));      /* frees d */
    if (n == 0) { g_free(pick); status("Nothing ticked; nothing deleted."); return; }
    if (A.busy || !A.logged_in || A.closing) { g_free(pick); return; }
    struct job *j = g_new0(struct job, 1);
    j->kind = J_DELETE;
    j->session = A.session;
    j->operator_mode = A.operator_mode;
    j->del = pick;
    j->n_del = n;
    status(running_text(J_DELETE));
    start(j);
}

static void on_delete(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (A.busy || !A.logged_in) return;
    GtkListBoxRow *r = gtk_list_box_get_selected_row(GTK_LIST_BOX(A.keys_box));
    int idx = r ? gtk_list_box_row_get_index(r) : -1;
    if (idx < 0 || (size_t)idx >= A.n_objs) return;
    const struct pkiops_object *o = &A.objs[idx];

    /* Operator mode keeps the CA it works for: its key pair, and any
     * certificate on the token under the same label. No "delete anyway" --
     * exploration mode and fhsm-crypt remain for the exception, as for every
     * other refusal of this mode. */
    if (A.operator_mode && o->label[0]) {
        const char *ca = chosen_key(A.op_key_drop);
        if (ca && !strcmp(ca, o->label)) {
            char msg[200];
            snprintf(msg, sizeof msg, "Refused in operator mode: \"%s\" is the CA's key. "
                     "Leave operator mode to delete it.", o->label);
            status(msg);
            return;
        }
    }

    struct del_ask *d = g_new0(struct del_ask, 1);
    size_t cap = 0;
    for (size_t i = 0; i < A.n_objs; i++)
        if ((size_t)idx == i || (o->label[0] && !strcmp(A.objs[i].label, o->label))) cap++;
    d->checks = g_new0(GtkWidget *, cap);
    d->handles = g_new0(pkiops_handle, cap);

    d->win = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(d->win), "Delete from the token");
    gtk_window_set_transient_for(GTK_WINDOW(d->win), GTK_WINDOW(A.win));
    gtk_window_set_modal(GTK_WINDOW(d->win), TRUE);
    gtk_window_set_resizable(GTK_WINDOW(d->win), FALSE);
    g_object_set_data_full(G_OBJECT(d->win), "del-ask", d, del_ask_free);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(box, 16);
    gtk_widget_set_margin_end(box, 16);
    gtk_widget_set_margin_top(box, 16);
    gtk_widget_set_margin_bottom(box, 16);

    /* Escaped: a label is whatever its creator typed, markup included. */
    char *head = o->label[0]
        ? g_markup_printf_escaped("<b>Delete objects labelled \xe2\x80\x9c%s\xe2\x80\x9d?</b>", o->label)
        : g_markup_printf_escaped("<b>Delete object %lu?</b>", o->handle);
    GtkWidget *h = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(h), head);
    g_free(head);
    gtk_label_set_xalign(GTK_LABEL(h), 0.0f);
    gtk_box_append(GTK_BOX(box), h);
    GtkWidget *note = gtk_label_new(
        "Nothing deleted from a token comes back. Tick what to delete: the object "
        "you selected is ticked, the others sharing its label are not.");
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(note), 56);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_box_append(GTK_BOX(box), note);

    for (size_t i = 0; i < A.n_objs; i++) {
        if (!((size_t)idx == i || (o->label[0] && !strcmp(A.objs[i].label, o->label)))) continue;
        char t[160];
        snprintf(t, sizeof t, "%s, object %lu%s%s", pkiops_obj_class_name(A.objs[i].cls),
                 A.objs[i].handle, A.objs[i].id[0] ? ", CKA_ID " : "", A.objs[i].id);
        GtkWidget *c = gtk_check_button_new_with_label(t);
        gtk_check_button_set_active(GTK_CHECK_BUTTON(c), (size_t)idx == i);
        gtk_box_append(GTK_BOX(box), c);
        d->checks[d->n] = c;
        d->handles[d->n] = A.objs[i].handle;
        d->n++;
    }

    GtkWidget *buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_halign(buttons, GTK_ALIGN_END);
    gtk_widget_set_margin_top(buttons, 8);
    GtkWidget *cancel = gtk_button_new_with_label("Cancel");
    g_signal_connect(cancel, "clicked", G_CALLBACK(on_del_cancel), d);
    GtkWidget *go = gtk_button_new_with_label("Delete");
    gtk_widget_add_css_class(go, "destructive-action");
    g_signal_connect(go, "clicked", G_CALLBACK(on_del_confirm), d);
    gtk_box_append(GTK_BOX(buttons), cancel);
    gtk_box_append(GTK_BOX(buttons), go);
    gtk_box_append(GTK_BOX(box), buttons);

    gtk_window_set_child(GTK_WINDOW(d->win), box);
    gtk_window_set_default_widget(GTK_WINDOW(d->win), cancel);
    gtk_window_present(GTK_WINDOW(d->win));
    gtk_widget_grab_focus(cancel);
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
    status(running_text(j->kind));
    start(j);
}

static void ask_where_named(struct job *j, const char *name) {
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, "Save as");
    gtk_file_dialog_set_initial_name(d, name);
    gtk_file_dialog_save(d, GTK_WINDOW(A.win), NULL, on_saved, j);
    g_object_unref(d);
}

/* "stem.pem" or "stem.der", by the job's format. */
static void ask_where(struct job *j, const char *stem) {
    char name[64];
    snprintf(name, sizeof name, "%s.%s", stem, j->pem ? "pem" : "der");
    ask_where_named(j, name);
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
static char **crl_urls(GtkWidget *view, int *too_many) {
    GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
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
    char **urls = crl_urls(A.crl_view, &too_many);
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
static void on_profile_changed(GObject *o, GParamSpec *ps, gpointer days_spin) {
    (void)ps;
    int responder = gtk_drop_down_get_selected(GTK_DROP_DOWN(o)) == 1;
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(days_spin), responder ? 30 : 365);
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
    update_sensitivity();
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

/* "From certificate...": the serial read off the certificate file rather than
 * typed. Issued serials are 160 random bits; a hand-copied one is how a
 * revocation lands on a number no certificate carries. Read on the main
 * thread -- one small file, no module involved. */
static void on_serial_cert_picked(GObject *src, GAsyncResult *res, gpointer entry) {
    GFile *f = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, NULL);
    char *path = f ? g_file_get_path(f) : NULL;
    if (f) g_object_unref(f);
    if (!path || A.closing) { g_free(path); return; }
    uint8_t *der = NULL; size_t n = 0;
    struct p11_err e;
    char *hex = NULL;
    if (read_der(path, &der, &n, &e)) {
        status_err("Reading the certificate", &e);
    } else if (!(hex = cert_serial_hex(der, n))) {
        char msg[1200];
        snprintf(msg, sizeof msg, "%s is not a certificate.", path);
        status(msg);
    } else {
        gtk_editable_set_text(GTK_EDITABLE(entry), hex);
        status(NULL);
    }
    g_free(hex);
    g_free(der);
    g_free(path);
}

static void on_serial_from_cert(GtkButton *b, gpointer entry) {
    (void)b;
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, "The certificate to revoke");
    gtk_file_dialog_open(d, GTK_WINDOW(A.win), NULL, on_serial_cert_picked, entry);
    g_object_unref(d);
}

/* --- the Signing tab ------------------------------------------------------ */

/* "data.bin" + ".sig": the name the save dialog proposes. */
static char *named_after_data(const char *suffix) {
    char *base = g_path_get_basename(A.sg_data_path);
    char *name = g_strconcat(base, suffix, NULL);
    g_free(base);
    return name;
}

/* The file to check was chosen: run the job, or drop it. */
static void on_input_picked(GObject *src, GAsyncResult *res, gpointer data) {
    struct job *j = data;
    GFile *f = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, NULL);
    char *path = f ? g_file_get_path(f) : NULL;
    if (f) g_object_unref(f);
    if (!path || A.closing || A.busy || (j->kind == J_VERIFY && !A.logged_in)) {
        g_free(path);
        job_free(j);
        return;
    }
    j->in_path = path;
    j->session = A.session;
    status(running_text(j->kind));
    start(j);
}

static void ask_input(struct job *j, const char *title) {
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, title);
    gtk_file_dialog_open(d, GTK_WINDOW(A.win), NULL, on_input_picked, j);
    g_object_unref(d);
}

static void on_sign(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (!A.sg_data_path) { status("Choose the data first."); return; }
    struct job *j = cert_job(J_SIGN, A.sg_key_drop);
    if (!j) return;
    j->pem = 0;
    j->data_path = g_strdup(A.sg_data_path);
    char *name = named_after_data(".sig");
    ask_where_named(j, name);
    g_free(name);
}

static void on_verify(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (!A.sg_data_path) { status("Choose the data first."); return; }
    struct job *j = cert_job(J_VERIFY, A.sg_key_drop);
    if (!j) return;
    j->data_path = g_strdup(A.sg_data_path);
    ask_input(j, "The signature to check");
}

static void on_cms_sign(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (!A.sg_data_path) { status("Choose the data first."); return; }
    if (!A.sg_cert_path) { status("Choose the signer's certificate."); return; }
    struct job *j = cert_job(J_CMS_SIGN, A.sg_key_drop);
    if (!j) return;
    j->pem = 0;                     /* written as DER, as fhsm-sign writes it */
    j->data_path = g_strdup(A.sg_data_path);
    j->cert_path = g_strdup(A.sg_cert_path);
    char *name = named_after_data(".p7s");
    ask_where_named(j, name);
    g_free(name);
}

static void on_cms_verify(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (A.busy || !A.sg_data_path) return;
    struct job *j = g_new0(struct job, 1);
    j->kind = J_CMS_VERIFY;
    j->data_path = g_strdup(A.sg_data_path);
    ask_input(j, "The CMS to check");
}

/* --- operator mode ------------------------------------------------------- */

static void on_mode(GObject *o, GParamSpec *ps, gpointer ud) {
    (void)ps; (void)ud;
    int op = gtk_switch_get_active(GTK_SWITCH(o));
    A.operator_mode = op;
    gtk_widget_set_visible(A.page_certs, !op);
    gtk_widget_set_visible(A.page_revocation, !op);
    gtk_widget_set_visible(A.page_op_ca, op);
    gtk_widget_set_visible(A.page_op_issue, op);
    gtk_widget_set_visible(A.page_op_revoke, op);
    gtk_window_set_title(GTK_WINDOW(A.win), op ? "fhsm-gui \xe2\x80\x94 operator"
                                               : "fhsm-gui \xe2\x80\x94 exploration");
    refresh_crl_status();
    status(op ? "Operator mode: guided steps for one CA, and refusals where the "
                "command line trusts its user. The command-line tools are unchanged."
              : "Exploration mode: every operation, with the command line's defaults "
                "and none of operator mode's refusals.");
}

static void on_op_db_picked(GObject *src, GAsyncResult *res, gpointer data) {
    (void)data;
    GFile *f = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, NULL);
    char *path = f ? g_file_get_path(f) : NULL;
    if (f) g_object_unref(f);
    if (!path || A.closing) { g_free(path); return; }
    /* Read once now, so a database that cannot be read is refused here and
     * not at the first revocation. */
    fhsm_rev_db_t d;
    struct p11_err e;
    if (db_load_e(path, &d, &e)) { status_err("Reading the database", &e); g_free(path); return; }
    char msg[1200];
    snprintf(msg, sizeof msg, "Database %s: %zu revoked, last CRL number %llu.",
             path, d.n, d.crl_number);
    fhsm_rev_db_free(&d);
    g_free(A.op_db_path);
    A.op_db_path = path;
    set_file_label(A.op_db_btn, path);
    status(msg);
}

static void on_op_db_open(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, "The CA's revocation database");
    gtk_file_dialog_open(d, GTK_WINDOW(A.win), NULL, on_op_db_picked, NULL);
    g_object_unref(d);
}

/* As in the Revocation tab: a new database is a name, and a name that exists
 * is refused rather than emptied. */
static void on_op_db_named(GObject *src, GAsyncResult *res, gpointer data) {
    (void)data;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, NULL);
    char *path = f ? g_file_get_path(f) : NULL;
    if (f) g_object_unref(f);
    if (!path || A.closing) { g_free(path); return; }
    if (g_file_test(path, G_FILE_TEST_EXISTS)) {
        char msg[1200];
        snprintf(msg, sizeof msg, "%s already exists, and was left as it is. Open it "
                 "instead: a new database is never written over an existing file.", path);
        status(msg);
        g_free(path);
        return;
    }
    g_free(A.op_db_path);
    A.op_db_path = path;
    set_file_label(A.op_db_btn, path);
    status("New database: the file is created by the first revocation, or the first CRL.");
}

static void on_op_db_new(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, "A new revocation database");
    gtk_file_dialog_set_initial_name(d, "revocations.db");
    gtk_file_dialog_save(d, GTK_WINDOW(A.win), NULL, on_op_db_named, NULL);
    g_object_unref(d);
}

/* Where the CRL is published: the file a web server serves at the CRL URLs.
 * Choosing it writes nothing; publishing replaces it, atomically. */
static void on_op_crl_chosen(GObject *src, GAsyncResult *res, gpointer data) {
    (void)data;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, NULL);
    char *path = f ? g_file_get_path(f) : NULL;
    if (f) g_object_unref(f);
    if (!path || A.closing) { g_free(path); return; }
    g_free(A.op_crl_path);
    A.op_crl_path = path;
    set_file_label(A.op_crl_btn, path);
    refresh_crl_status();
}

static void on_op_crl_choose(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, "Where the CRL is published");
    gtk_file_dialog_set_initial_name(d, "ca.crl");
    gtk_file_dialog_save(d, GTK_WINDOW(A.win), NULL, on_op_crl_chosen, NULL);
    g_object_unref(d);
}

/* A job for the CA set on the CA tab: its key and certificate, and its
 * database when the job needs one. NULL, saying what is missing, otherwise. */
static struct job *op_job(enum job_kind kind, int need_db) {
    if (A.busy || !A.logged_in) return NULL;
    const char *key = chosen_key(A.op_key_drop);
    const char *missing = !key                     ? "the CA's key"
                        : !A.op_ca_path            ? "the CA's certificate"
                        : need_db && !A.op_db_path ? "the revocation database"
                        : !A.op_crl_path           ? "where the CRL is published"
                        :                            NULL;
    if (missing) {
        char msg[200];
        snprintf(msg, sizeof msg, "Set %s on the CA tab first.", missing);
        status(msg);
        return NULL;
    }
    struct job *j = g_new0(struct job, 1);
    j->kind = kind;
    j->operator_mode = 1;
    j->label = g_strdup(key);
    j->ca_path = g_strdup(A.op_ca_path);
    if (A.op_db_path) j->db_path = g_strdup(A.op_db_path);
    return j;
}

static void on_op_new_ca(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (A.busy || !A.logged_in) return;
    const char *label = gtk_editable_get_text(GTK_EDITABLE(A.op_new_label));
    const char *subject = gtk_editable_get_text(GTK_EDITABLE(A.op_new_subject));
    if (!label || !*label)     { status("Give the CA's key a label."); return; }
    if (!subject || !*subject) { status("Give the CA a subject."); return; }
    struct job *j = g_new0(struct job, 1);
    j->kind = J_NEW_CA;
    j->operator_mode = 1;
    j->label = g_strdup(label);
    j->subject = g_strdup(subject);
    j->days = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.op_new_days));
    j->alg = (int)gtk_drop_down_get_selected(GTK_DROP_DOWN(A.op_new_alg));
    j->pem = 1;
    char *name = g_strconcat(label, "-root.pem", NULL);
    ask_where_named(j, name);
    g_free(name);
}

static void on_op_issue(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    if (!A.op_csr_path) { status("Choose the request to sign."); return; }
    int too_many = 0;
    char **urls = crl_urls(A.op_urls_view, &too_many);
    /* The refusals. A certificate without a revocation pointer cannot be
     * revoked in any way a verifier notices; one whose pointer leads to no
     * list, or to an expired one, fails every verifier that checks. */
    if (!urls) {
        status("Refused: no CRL URL is set on the CA tab. A certificate without a "
               "revocation pointer cannot be revoked in any way a verifier will notice.");
        return;
    }
    if (too_many) { g_strfreev(urls); status("At most 8 CRL URLs."); return; }
    char crl_text[1200];
    enum crl_state cs = crl_state_of(A.op_crl_path, crl_text, sizeof crl_text);
    if (A.op_crl_path && cs != CRL_FRESH && cs != CRL_DUE) {
        char msg[1400];
        snprintf(msg, sizeof msg, "Refused: %s A certificate issued now would point at "
                 "a list verifiers cannot use. Publish a CRL on the Revoke tab first.",
                 crl_text);
        status(msg);
        g_strfreev(urls);
        return;
    }
    struct job *j = op_job(J_ISSUE, 0);
    if (!j) { g_strfreev(urls); return; }
    j->crl_urls = urls;
    j->csr_path = g_strdup(A.op_csr_path);
    j->subject = text_or_null(A.op_subject);
    j->san = text_or_null(A.op_san);
    j->profile = gtk_drop_down_get_selected(GTK_DROP_DOWN(A.op_profile)) == 1
               ? FHSM_CERT_OCSP_RESPONDER : FHSM_CERT_END_ENTITY;
    j->days = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.op_days));
    j->pem = 1;
    ask_where(j, "certificate");
}

static void on_op_revoke_answered(GObject *src, GAsyncResult *res, gpointer data) {
    struct job *j = data;
    int choice = gtk_alert_dialog_choose_finish(GTK_ALERT_DIALOG(src), res, NULL);
    if (choice != 1 || A.closing || A.busy || !A.logged_in) { job_free(j); return; }
    j->session = A.session;
    status("Recording the revocation, then publishing the CRL...");
    start(j);
}

static void on_op_revoke(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    const char *serial = gtk_editable_get_text(GTK_EDITABLE(A.op_serial));
    if (!serial || !*serial) { status("Type the serial to revoke, in hex."); return; }
    guint ri = gtk_drop_down_get_selected(GTK_DROP_DOWN(A.op_reason));
    int reason = ri == 0 || ri >= G_N_ELEMENTS(reasons) - 1
               ? -1 : fhsm_rev_reason_code(reasons[ri]);
    if (reason == -2) { status("Unknown reason."); return; }
    struct job *j = op_job(J_REVOKE_PUBLISH, 1);
    if (!j) return;
    j->serial_hex = g_strdup(serial);
    j->reason = reason;
    j->out_path = g_strdup(A.op_crl_path);
    j->pem = 0;                     /* a published CRL is served as DER */
    j->days = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.op_crl_days));

    GtkAlertDialog *d = gtk_alert_dialog_new("Revoke serial %s, and publish?", serial);
    gtk_alert_dialog_set_detail(d,
        "This records the revocation and publishes a new CRL at once, replacing the "
        "published file. The revocation is not undone from here.");
    const char *const buttons[] = { "Cancel", "Revoke and publish", NULL };
    gtk_alert_dialog_set_buttons(d, buttons);
    gtk_alert_dialog_set_cancel_button(d, 0);
    gtk_alert_dialog_set_default_button(d, 0);
    gtk_alert_dialog_choose(d, GTK_WINDOW(A.win), NULL, on_op_revoke_answered, j);
    g_object_unref(d);
}

/* Publishing again before the list expires is the routine that keeps every
 * certificate of this CA checkable. */
static void on_op_publish(GtkButton *b, gpointer ud) {
    (void)b; (void)ud;
    struct job *j = op_job(J_CRL, 1);
    if (!j) return;
    j->out_path = g_strdup(A.op_crl_path);
    j->pem = 0;
    j->session = A.session;
    j->days = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.op_crl_days));
    status(running_text(J_CRL));
    start(j);
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

/* A row whose field is taller than one line: the label at the top, level
 * with the field's first line, not centred on the whole height -- where it
 * read as belonging to the line below. */
static void form_row_top(GtkWidget *grid, int r, const char *label, GtkWidget *w) {
    GtkWidget *l = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(l), 1.0f);
    gtk_widget_set_valign(l, GTK_ALIGN_START);
    gtk_widget_set_margin_top(l, 6);
    gtk_grid_attach(GTK_GRID(grid), l, 0, r, 1, 1);
    gtk_widget_set_hexpand(w, TRUE);
    gtk_grid_attach(GTK_GRID(grid), w, 1, r, 1, 1);
}

/* A few lines of text to type, in a visible box: a GtkTextView has no border
 * of its own, and without one there is nothing to show where to click. */
static GtkWidget *text_box(GtkWidget **view, int lines, const char *tooltip) {
    *view = gtk_text_view_new();
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(*view), TRUE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(*view), 6);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(*view), 6);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(*view), 4);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(*view), 4);
    GtkWidget *s = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(s), *view);
    gtk_scrolled_window_set_has_frame(GTK_SCROLLED_WINDOW(s), TRUE);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(s), GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(s), 22 * lines);
    gtk_widget_set_vexpand(s, FALSE);
    gtk_widget_set_tooltip_text(s, tooltip);
    return s;
}

static GtkWidget *form(void) {
    GtkWidget *g = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(g), 6);
    gtk_grid_set_column_spacing(GTK_GRID(g), 8);
    return g;
}

/* Every algorithm the tools offer, by the name they take, the composite
 * first: what a key pair is generated for. */
static GtkWidget *alg_drop(void) {
    GtkStringList *l = gtk_string_list_new(NULL);
    for (int i = 0; i < PKIOPS_ALG_COUNT; i++)
        gtk_string_list_append(l, pkiops_alg_name((enum pkiops_alg)i));
    GtkWidget *d = gtk_drop_down_new(G_LIST_MODEL(l), NULL);
    gtk_widget_set_tooltip_text(d,
        "Chosen once: everything signed with the key afterwards uses its algorithm. "
        "The composite exists only in PROFILE=all-mechanisms builds.");
    return d;
}

/* The Token tab's: every signature algorithm, then the secret keys
 * fhsm-crypt makes. Operator mode's Create a new CA keeps alg_drop: a CA
 * signs. */
static GtkWidget *keygen_drop(void) {
    GtkStringList *l = gtk_string_list_new(NULL);
    for (int i = 0; i < PKIOPS_ALG_COUNT; i++)
        gtk_string_list_append(l, pkiops_alg_name((enum pkiops_alg)i));
    for (int i = 0; i < PKIOPS_SKEY_COUNT; i++)
        gtk_string_list_append(l, pkiops_skey_name((enum pkiops_skey)i));
    GtkWidget *d = gtk_drop_down_new(G_LIST_MODEL(l), NULL);
    gtk_widget_set_tooltip_text(d,
        "Signature key pairs first; their algorithm is used for everything signed "
        "with them, and the composite exists only in PROFILE=all-mechanisms builds. "
        "Then aes128 and aes256, which encrypt and wrap, hmac, a 32-byte secret "
        "for MACs, and rsa-oaep, an RSA 3072 pair that encrypts with OAEP and cannot "
        "sign: sensitive, and never leave the token.");
    return d;
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

/* A serial entry with its "From certificate..." button beside it. */
static GtkWidget *serial_row(GtkWidget *entry) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_box_append(GTK_BOX(row), entry);
    gtk_box_append(GTK_BOX(row), button_to("From certificate\xe2\x80\xa6",
                                           G_CALLBACK(on_serial_from_cert), entry));
    return row;
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
    GtkWidget *crl_box = text_box(&A.crl_view, 3,
        "Where this certificate's revocation list is published, one URL per line, "
        "at most 8. http://... or ldap://...?attribute; https is refused.");
    form_row_top(g, 4, "CRL URLs", crl_box);
    const char *const profiles[] = { "end-entity", "ocsp-responder (delegated)", NULL };
    A.profile_drop = gtk_drop_down_new_from_strings(profiles);
    form_row(g, 5, "Profile", A.profile_drop);
    A.issue_days_spin = gtk_spin_button_new_with_range(1, 36500, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(A.issue_days_spin), 365);
    form_row(g, 6, "Days", A.issue_days_spin);
    /* Connected once the spin button exists: it is the handler's data. */
    g_signal_connect(A.profile_drop, "notify::selected", G_CALLBACK(on_profile_changed),
                     A.issue_days_spin);
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
    form_row(g, 0, "Serial", serial_row(A.serial_entry));
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

/* Stage 4: detached signatures over files, raw and CMS. */
static GtkWidget *signing_tab(void) {
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(page, 4);
    gtk_widget_set_margin_end(page, 8);

    A.sg_data_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *g = form();
    form_row(g, 0, "Data", file_button("The data to sign or check", &A.sg_data_path));
    gtk_box_append(GTK_BOX(A.sg_data_box), g);
    gtk_box_append(GTK_BOX(A.sg_data_box), note_label(
        "Streamed in 1 MiB blocks and never held whole, so its size is not bounded "
        "by memory."));
    gtk_box_append(GTK_BOX(page), A.sg_data_box);

    /* Everything that needs the token. */
    A.sg_key_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    g = form();
    A.sg_key_drop = gtk_drop_down_new(G_LIST_MODEL(g_object_ref(A.key_labels)), NULL);
    form_row(g, 0, "Key", A.sg_key_drop);
    gtk_box_append(GTK_BOX(A.sg_key_box), g);

    gtk_box_append(GTK_BOX(A.sg_key_box), heading("Raw, detached"));
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Sign\xe2\x80\xa6", G_CALLBACK(on_sign), NULL));
    gtk_box_append(GTK_BOX(row), button_to("Verify\xe2\x80\xa6", G_CALLBACK(on_verify), NULL));
    gtk_box_append(GTK_BOX(A.sg_key_box), row);
    gtk_box_append(GTK_BOX(A.sg_key_box), note_label(
        "The signature is the bytes and nothing around them: it does not record which "
        "key or algorithm made it, so whoever verifies must be told. Signing uses the "
        "private key of this label, verifying the public one."));

    gtk_box_append(GTK_BOX(A.sg_key_box), heading("CMS (RFC 5652), detached"));
    g = form();
    form_row(g, 0, "Signer's certificate",
             file_button("The signer's certificate", &A.sg_cert_path));
    gtk_box_append(GTK_BOX(A.sg_key_box), g);
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Sign CMS\xe2\x80\xa6", G_CALLBACK(on_cms_sign), NULL));
    gtk_box_append(GTK_BOX(A.sg_key_box), row);
    gtk_box_append(GTK_BOX(page), A.sg_key_box);

    /* Checking a CMS needs neither the token nor a login. */
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    A.sg_cmsv_btn = button_to("Verify CMS\xe2\x80\xa6", G_CALLBACK(on_cms_verify), NULL);
    gtk_box_append(GTK_BOX(row), A.sg_cmsv_btn);
    gtk_box_append(GTK_BOX(page), row);
    gtk_box_append(GTK_BOX(page), note_label(
        "A CMS carries the signer's certificate and says which algorithm made it, so "
        "checking one needs only the file and the data: no token, no login."));

    GtkWidget *s = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(s), page);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(s), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    return s;
}

static GtkWidget *scrolled_page(GtkWidget *page) {
    GtkWidget *s = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(s), page);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(s), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    return s;
}

static GtkWidget *op_page(void) {
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(page, 4);
    gtk_widget_set_margin_end(page, 8);
    return page;
}

/* Stage 5, operator mode: the CA every other step works for. */
static GtkWidget *op_ca_tab(void) {
    GtkWidget *page = op_page();
    gtk_box_append(GTK_BOX(page), heading("This CA"));
    GtkWidget *g = form();
    A.op_key_drop = gtk_drop_down_new(G_LIST_MODEL(g_object_ref(A.key_labels)), NULL);
    form_row(g, 0, "CA key", A.op_key_drop);
    A.op_ca_btn = file_button("The CA's certificate", &A.op_ca_path);
    form_row(g, 1, "CA certificate", A.op_ca_btn);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    A.op_db_btn = button_to("Open\xe2\x80\xa6", G_CALLBACK(on_op_db_open), NULL);
    gtk_widget_set_hexpand(A.op_db_btn, TRUE);
    gtk_box_append(GTK_BOX(row), A.op_db_btn);
    gtk_box_append(GTK_BOX(row), button_to("New\xe2\x80\xa6", G_CALLBACK(on_op_db_new), NULL));
    form_row(g, 2, "Database", row);
    A.op_crl_btn = button_to("Choose\xe2\x80\xa6", G_CALLBACK(on_op_crl_choose), NULL);
    gtk_widget_set_tooltip_text(A.op_crl_btn,
        "The file a web server serves at the CRL URLs. Publishing replaces it.");
    form_row(g, 3, "Published CRL", A.op_crl_btn);
    GtkWidget *urls = text_box(&A.op_urls_view, 3,
        "Where that file is served, one URL per line, at most 8. Every certificate "
        "this CA issues carries them. http://... or ldap://...?attribute.");
    form_row_top(g, 4, "CRL URLs", urls);
    gtk_box_append(GTK_BOX(page), g);
    A.op_crl_status = note_label("No CRL location chosen.");
    gtk_widget_remove_css_class(A.op_crl_status, "dim-label");
    gtk_box_append(GTK_BOX(page), A.op_crl_status);

    A.op_ca_signing_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(A.op_ca_signing_box), heading("Create a new CA"));
    g = form();
    A.op_new_label = entry_with("label for the CA's key; one not already on the token");
    form_row(g, 0, "Key label", A.op_new_label);
    A.op_new_subject = entry_with("/C=FR/O=Simorgh Labs/CN=Example Root CA");
    form_row(g, 1, "Subject", A.op_new_subject);
    A.op_new_days = gtk_spin_button_new_with_range(1, 36500, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(A.op_new_days), 3650);
    form_row(g, 2, "Days", A.op_new_days);
    A.op_new_alg = alg_drop();
    form_row(g, 3, "Algorithm", A.op_new_alg);
    gtk_box_append(GTK_BOX(A.op_ca_signing_box), g);
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Create CA\xe2\x80\xa6", G_CALLBACK(on_op_new_ca), NULL));
    gtk_box_append(GTK_BOX(A.op_ca_signing_box), row);
    gtk_box_append(GTK_BOX(A.op_ca_signing_box), note_label(
        "Generates the key pair and the self-signed root, and makes them this CA. "
        "Then: a database, where the CRL is published, its URLs, and the first CRL "
        "from the Revoke tab -- issuing is refused until one exists."));
    gtk_box_append(GTK_BOX(page), A.op_ca_signing_box);
    return scrolled_page(page);
}

static GtkWidget *op_issue_tab(void) {
    GtkWidget *page = op_page();
    A.op_issue_banner = note_label("No CRL location chosen.");
    gtk_widget_remove_css_class(A.op_issue_banner, "dim-label");
    gtk_box_append(GTK_BOX(page), A.op_issue_banner);
    GtkWidget *g = form();
    A.op_csr_btn = file_button("The request to sign", &A.op_csr_path);
    form_row(g, 0, "Request", A.op_csr_btn);
    A.op_subject = entry_with("as requested");
    form_row(g, 1, "Subject", A.op_subject);
    A.op_san = entry_with("DNS:example.org,IP:192.0.2.1");
    form_row(g, 2, "SAN", A.op_san);
    const char *const profiles[] = { "end-entity", "ocsp-responder (delegated)", NULL };
    A.op_profile = gtk_drop_down_new_from_strings(profiles);
    form_row(g, 3, "Profile", A.op_profile);
    A.op_days = gtk_spin_button_new_with_range(1, 36500, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(A.op_days), 365);
    form_row(g, 4, "Days", A.op_days);
    g_signal_connect(A.op_profile, "notify::selected", G_CALLBACK(on_profile_changed), A.op_days);
    gtk_box_append(GTK_BOX(page), g);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Issue\xe2\x80\xa6", G_CALLBACK(on_op_issue), NULL));
    gtk_box_append(GTK_BOX(page), row);
    gtk_box_append(GTK_BOX(page), note_label(
        "Signed by the CA set on the CA tab, with its CRL URLs. Refused when there are "
        "no CRL URLs, or when the published CRL is missing or expired. The request's "
        "proof of possession is checked before anything is signed."));
    return scrolled_page(page);
}

static GtkWidget *op_revoke_tab(void) {
    GtkWidget *page = op_page();
    GtkWidget *g = form();
    A.op_serial = entry_with("serial in hex, as the certificate carries it");
    form_row(g, 0, "Serial", serial_row(A.op_serial));
    A.op_reason = gtk_drop_down_new_from_strings(reasons);
    form_row(g, 1, "Reason", A.op_reason);
    A.op_crl_days = gtk_spin_button_new_with_range(1, 3650, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(A.op_crl_days), 30);
    form_row(g, 2, "CRL days", A.op_crl_days);
    gtk_box_append(GTK_BOX(page), g);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Revoke and publish\xe2\x80\xa6", G_CALLBACK(on_op_revoke), NULL));
    gtk_box_append(GTK_BOX(row), button_to("Publish CRL now", G_CALLBACK(on_op_publish), NULL));
    gtk_box_append(GTK_BOX(page), row);
    gtk_box_append(GTK_BOX(page), note_label(
        "A revocation is published as soon as it is recorded. Publish again before "
        "the current list expires -- the CA tab says when -- or every certificate "
        "of this CA stops being checkable."));
    return scrolled_page(page);
}

static void activate(GtkApplication *app, gpointer ud) {
    (void)ud;
    A.win = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(A.win), "fhsm-gui \xe2\x80\x94 exploration");
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
    GtkWidget *mode_label = gtk_label_new("Operator mode");
    gtk_widget_set_margin_start(mode_label, 12);
    gtk_box_append(GTK_BOX(row), mode_label);
    GtkWidget *mode_switch = gtk_switch_new();
    gtk_widget_set_valign(mode_switch, GTK_ALIGN_CENTER);
    gtk_widget_set_tooltip_text(mode_switch,
        "Guided steps for one CA, and refusals where the command line trusts its user.");
    gtk_box_append(GTK_BOX(row), mode_switch);
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

    /* Initialising a token: folded away, as it is done once per token. */
    GtkWidget *init = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *ig = form();
    A.init_label = entry_with("freehsm");
    form_row(ig, 0, "Token label", A.init_label);
    A.init_so = gtk_password_entry_new();
    form_row(ig, 1, "SO PIN", A.init_so);
    A.init_so2 = gtk_password_entry_new();
    form_row(ig, 2, "SO PIN again", A.init_so2);
    A.init_user = gtk_password_entry_new();
    form_row(ig, 3, "User PIN", A.init_user);
    A.init_user2 = gtk_password_entry_new();
    form_row(ig, 4, "User PIN again", A.init_user2);
    gtk_box_append(GTK_BOX(init), ig);
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), button_to("Initialise\xe2\x80\xa6", G_CALLBACK(on_init), NULL));
    gtk_box_append(GTK_BOX(init), row);
    gtk_box_append(GTK_BOX(init), note_label(
        "For the slot chosen above. The Security Officer PIN can re-initialise the "
        "token and reset the user PIN; the user PIN is the one applications log in "
        "with. Re-initialising a token destroys every key on it."));
    A.init_box = gtk_expander_new("Initialise a token");
    gtk_expander_set_child(GTK_EXPANDER(A.init_box), init);
    gtk_box_append(GTK_BOX(left), A.init_box);

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

    gtk_box_append(GTK_BOX(left), heading("Keys and certificates"));
    A.keys_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(A.keys_box), GTK_SELECTION_SINGLE);
    g_signal_connect(A.keys_box, "row-selected", G_CALLBACK(on_object_selected), NULL);
    gtk_box_append(GTK_BOX(left), scrolled(A.keys_box, 160));
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    A.delete_btn = gtk_button_new_with_label("Delete\xe2\x80\xa6");
    gtk_widget_set_tooltip_text(A.delete_btn,
        "Delete the selected object, and any others sharing its label that you tick. "
        "Nothing deleted from a token comes back.");
    g_signal_connect(A.delete_btn, "clicked", G_CALLBACK(on_delete), NULL);
    gtk_widget_set_halign(A.delete_btn, GTK_ALIGN_END);
    gtk_widget_set_hexpand(A.delete_btn, TRUE);
    gtk_box_append(GTK_BOX(row), A.delete_btn);
    gtk_box_append(GTK_BOX(left), row);
    gtk_box_append(GTK_BOX(left), heading("Attributes of the selected object"));
    A.attr_view = gtk_label_new("");
    gtk_label_set_selectable(GTK_LABEL(A.attr_view), TRUE);
    gtk_label_set_xalign(GTK_LABEL(A.attr_view), 0.0f);
    gtk_label_set_yalign(GTK_LABEL(A.attr_view), 0.0f);
    gtk_widget_add_css_class(A.attr_view, "monospace");
    gtk_widget_set_margin_start(A.attr_view, 6);
    gtk_box_append(GTK_BOX(left), scrolled(A.attr_view, 140));
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    A.label_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(A.label_entry), "label for a new key");
    gtk_widget_set_hexpand(A.label_entry, TRUE);
    g_signal_connect(A.label_entry, "activate", G_CALLBACK(on_keygen), NULL);
    gtk_box_append(GTK_BOX(row), A.label_entry);
    A.keygen_alg = keygen_drop();
    gtk_box_append(GTK_BOX(row), A.keygen_alg);
    A.keygen_btn = gtk_button_new_with_label("Generate key");
    g_signal_connect(A.keygen_btn, "clicked", G_CALLBACK(on_keygen), NULL);
    gtk_box_append(GTK_BOX(row), A.keygen_btn);
    gtk_box_append(GTK_BOX(left), row);

    GtkWidget *tabs = gtk_notebook_new();
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), left, gtk_label_new("Token"));
    A.page_certs = cert_tab();       /* first: it creates the key list the others share */
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), A.page_certs, gtk_label_new("Certificates"));
    A.page_revocation = revocation_tab();
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), A.page_revocation, gtk_label_new("Revocation"));
    A.page_op_ca = op_ca_tab();
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), A.page_op_ca, gtk_label_new("CA"));
    A.page_op_issue = op_issue_tab();
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), A.page_op_issue, gtk_label_new("Issue"));
    A.page_op_revoke = op_revoke_tab();
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), A.page_op_revoke, gtk_label_new("Revoke"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), signing_tab(), gtk_label_new("Signing"));
    /* Exploration first; the switch swaps the middle tabs. */
    gtk_widget_set_visible(A.page_op_ca, FALSE);
    gtk_widget_set_visible(A.page_op_issue, FALSE);
    gtk_widget_set_visible(A.page_op_revoke, FALSE);
    g_signal_connect(mode_switch, "notify::active", G_CALLBACK(on_mode), NULL);
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
    /* The published CRL's state is re-read once a minute: an expiry nobody
     * looks at is the one this mode exists to catch. */
    g_timeout_add_seconds(60, on_crl_tick, NULL);
    update_sensitivity();
    gtk_window_present(GTK_WINDOW(A.win));
}

/* app.quit: Ctrl+Q, and how tests/gui_smoke.sh ends the program from outside
 * (`gapplication action com.chaharsou.FhsmGui quit`). It closes the window
 * the way its close button does, so it goes through on_close: refused while
 * a call is running, and the session and module closed otherwise. */
static void on_quit(GSimpleAction *a, GVariant *p, gpointer app) {
    (void)a; (void)p;
    if (A.win) gtk_window_close(GTK_WINDOW(A.win));
    else       g_application_quit(G_APPLICATION(app));   /* asked before the window exists */
}

int main(int argc, char **argv) {
    GtkApplication *app = gtk_application_new("com.chaharsou.FhsmGui",
                                              G_APPLICATION_DEFAULT_FLAGS);
    static const GActionEntry actions[] = {
        { .name = "quit", .activate = on_quit },
    };
    g_action_map_add_action_entries(G_ACTION_MAP(app), actions,
                                    G_N_ELEMENTS(actions), app);
    const char *const quit_accels[] = { "<Control>q", NULL };
    gtk_application_set_accels_for_action(app, "app.quit", quit_accels);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    int rc = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return rc;
}
