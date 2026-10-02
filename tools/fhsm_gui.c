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

enum job_kind { J_LOAD, J_UNLOAD, J_SLOTS, J_LOGIN, J_KEYS, J_KEYGEN, J_LOGOUT };

struct job {
    enum job_kind kind;
    char *module, *label;
    pkiops_handle slot, session;
    uint8_t *pin; size_t pin_len;
    /* results */
    int rc;
    struct p11_err e;
    struct pkiops_slot *slots; size_t n_slots;
    struct pkiops_key  *keys;  size_t n_keys;
};

static void job_free(gpointer p) {
    struct job *j = p;
    if (j->pin) { OPENSSL_cleanse(j->pin, j->pin_len); g_free(j->pin); }
    g_free(j->module);
    g_free(j->label);
    free(j->slots);
    free(j->keys);
    g_free(j);
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

static void show_keys(struct job *j) {
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
        if (!j->rc) show_slots(j);
        status("Logged out: the session is closed.");
        break;
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

    gtk_paned_set_start_child(GTK_PANED(paned), left);

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
    gtk_paned_set_position(GTK_PANED(paned), 470);

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
