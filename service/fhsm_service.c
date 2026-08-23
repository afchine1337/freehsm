/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm-service --- the guards, and nothing else yet (#111).
 *
 *  docs/REST_API_DESIGN.md decided the shape; this is its first slice, and it
 *  deliberately performs no cryptography at all. Every route that will one day
 *  sign answers 501 today. The point is to get the refusals right while they
 *  are still cheap to change, because refusals are the part of an API that
 *  ages worst when they are added late.
 *
 *  WHAT IT ENFORCES
 *
 *    the socket        A unix socket, not a localhost port. §1 of the ADR is
 *                      blunt about why: the identity header is trusted, so
 *                      the service must be able to refuse anything that did
 *                      not come from the proxy. Filesystem permissions decide
 *                      who may connect and SO_PEERCRED says who did. A TCP
 *                      port would let any local process assert any identity.
 *
 *    the peer          SO_PEERCRED, compared against --proxy-uid. There is no
 *                      default for that option and the service refuses to
 *                      start without it: a guard whose value was guessed is
 *                      not a guard.
 *
 *    the identity      One X-FHSM-Client-Subject header, non-empty. Missing is
 *                      refused; so is repeated, which is how header smuggling
 *                      gets an attacker's value read instead of the proxy's.
 *
 *    the request       Parsed strictly and refused liberally. This is the code
 *                      the ADR names as the largest thing it could ask a
 *                      reader to audit, so it accepts exactly what the proxy
 *                      sends: two methods, a bounded request line, bounded
 *                      headers, Content-Length only, and no chunked transfer.
 *                      Everything else is 400 and a closed connection.
 *
 *  WHY IT LINKS THE MODULE RATHER THAN dlopen()ING IT
 *
 *  The service is one process holding one login -- it IS the PKCS#11
 *  application, which is the pool design in the ADR. It also needs
 *  fhsm_audit_set_actor(), which is not part of PKCS#11 and is not exported
 *  from the shared object (-fvisibility=hidden). Linking the objects is both
 *  the honest shape and the only one that can attribute a log line.
 *
 *  NOT HERE YET, ON PURPOSE
 *
 *    the session pool, the throttle by identity (docs/RATE_LIMIT.md), the
 *    daemon PIN (docs/DAEMON_PIN.md), and every operation. Each arrives with
 *    its own measurement.
 *
 *      fhsm-service --socket /run/freehsm/p11.sock --proxy-uid 33
 * ========================================================================= */
#include "fhsm_common.h"
#include "fhsm_audit.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

extern unsigned long C_Initialize(void *);
extern unsigned long C_Finalize(void *);
extern unsigned long C_GetSlotList(unsigned char, unsigned long *, unsigned long *);
extern unsigned long C_GetTokenInfo(unsigned long, void *);
extern unsigned long C_OpenSession(unsigned long, unsigned long, void *, void *,
                                    unsigned long *);
extern unsigned long C_CloseSession(unsigned long);
extern unsigned long C_Login(unsigned long, unsigned long, unsigned char *,
                              unsigned long);

/* CK_TOKEN_INFO, PKCS#11 v3.2 C.6.3. Declared here for the same reason
 * tools/fhsm_token.c declares it: so this file depends on the interface and
 * not on our particular module's private headers. */
struct tok_info {
    unsigned char label[32], manufacturerID[32], model[16], serialNumber[16];
    unsigned long flags;
    unsigned long ulMaxSessionCount, ulSessionCount;
    unsigned long ulMaxRwSessionCount, ulRwSessionCount;
    unsigned long ulMaxPinLen, ulMinPinLen;
    unsigned long ulTotalPublicMemory, ulFreePublicMemory;
    unsigned long ulTotalPrivateMemory, ulFreePrivateMemory;
    unsigned char hardwareVersion[2], firmwareVersion[2], utcTime[16];
};
#define CKF_RW_SESSION_    0x00000002UL
#define CKF_SERIAL_SESSION 0x00000004UL
#define CKU_USER_          1UL

/* The header the proxy must set. Named for this project rather than borrowed
 * from nginx or Caddy: the value is trusted absolutely, so it should be
 * obvious in a configuration file that somebody chose to trust it. */
#define IDENT_HEADER "x-fhsm-client-subject"

/* Bounds. Every one of them exists to make the parser's worst case small and
 * stated, rather than large and discovered. */
#define MAX_HEADER_BYTES  8192   /* request line + headers, total */
#define MAX_REQUEST_LINE  1024
#define MAX_HEADERS         32
#define MAX_TARGET         256
#define MAX_BODY         65536

/* --------------------------------------------------------------------------
 * The session pool.
 *
 * "One session per concurrent request, never shared" (ADR). A session handle
 * is not thread-safe to share -- the module keeps per-handle operation state,
 * and two threads in the same handle would interleave into each other's
 * operation. So a worker takes one for the length of a request and gives it
 * back.
 *
 * Lazily grown to a cap: a service that opened its cap at start-up would pay
 * ~29 KiB of resident memory per session for sessions nobody asked for
 * (measured, docs/REST_API_DESIGN.md), and would fail to start on a token
 * whose cap is lower than ours. Grown under the same mutex that hands slots
 * out, which is the simple arrangement rather than the fast one: opening a
 * session is rare and short, and a second lock here would be a second thing
 * to get wrong.
 *
 * Never shrunk. A session that has been opened costs nothing further to keep,
 * and closing one under load only to reopen it is how a pool becomes a
 * source of latency instead of a cure for it.
 * ----------------------------------------------------------------------- */
#define POOL_MAX_LIMIT 127          /* the module's own cap, FHSM_MAX_SESSIONS-1 */

typedef struct {
    unsigned long handle;
    int           in_use;
} pool_slot_t;

static pthread_mutex_t g_pool_mu  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_pool_cv  = PTHREAD_COND_INITIALIZER;
static pool_slot_t     g_pool[POOL_MAX_LIMIT];
static int             g_pool_open = 0;    /* slots ever opened */
static int             g_pool_max  = 0;    /* configured ceiling */
static unsigned long   g_slot_id   = 0;

/* Borrow a session. Blocks while every open slot is busy and the pool is at
 * its ceiling -- which is the queue the ADR says does not exist yet, in its
 * smallest possible form: unbounded in depth and bounded only by the number
 * of worker threads. Making it a real queue with a depth is a later slice,
 * and docs/RATE_LIMIT.md is where its size will be argued. */
static int pool_acquire(unsigned long *out)
{
    pthread_mutex_lock(&g_pool_mu);
    for (;;) {
        for (int i = 0; i < g_pool_open; i++) {
            if (!g_pool[i].in_use) {
                g_pool[i].in_use = 1;
                *out = g_pool[i].handle;
                pthread_mutex_unlock(&g_pool_mu);
                return 0;
            }
        }
        if (g_pool_open < g_pool_max) {
            unsigned long h = 0;
            unsigned long rv = C_OpenSession(g_slot_id,
                                              CKF_SERIAL_SESSION | CKF_RW_SESSION_,
                                              NULL, NULL, &h);
            if (rv != 0) {
                /* Do not retry and do not grow again this time round: the
                 * module refused, and hammering it turns one failure into a
                 * loop. Wait for a slot to come back instead. */
                pthread_cond_wait(&g_pool_cv, &g_pool_mu);
                continue;
            }
            g_pool[g_pool_open].handle = h;
            g_pool[g_pool_open].in_use = 1;
            *out = h;
            g_pool_open++;
            pthread_mutex_unlock(&g_pool_mu);
            return 0;
        }
        pthread_cond_wait(&g_pool_cv, &g_pool_mu);
    }
}

static void pool_release(unsigned long h)
{
    pthread_mutex_lock(&g_pool_mu);
    for (int i = 0; i < g_pool_open; i++) {
        if (g_pool[i].handle == h) { g_pool[i].in_use = 0; break; }
    }
    pthread_cond_signal(&g_pool_cv);
    pthread_mutex_unlock(&g_pool_mu);
}

static void pool_close_all(void)
{
    pthread_mutex_lock(&g_pool_mu);
    for (int i = 0; i < g_pool_open; i++) (void)C_CloseSession(g_pool[i].handle);
    g_pool_open = 0;
    pthread_mutex_unlock(&g_pool_mu);
}

static volatile sig_atomic_t g_stop = 0;
static int g_stop_pipe[2] = { -1, -1 };

/* write() to a pipe is async-signal-safe; almost nothing else here would be.
 * The byte is what wakes every worker's poll() at once. */
static void on_signal(int s)
{
    (void)s;
    g_stop = 1;
    if (g_stop_pipe[1] >= 0) { char b = 1; (void)!write(g_stop_pipe[1], &b, 1); }
}

/* --------------------------------------------------------------------------
 * A refusal is a first-class outcome here, so it has a type. `reason` is a
 * short stable token, not a sentence: it goes in the audit line and somebody
 * will grep for it a year from now.
 * ----------------------------------------------------------------------- */
typedef struct {
    int         status;        /* HTTP status to send */
    const char *reason;        /* audit token, NULL when the request is fine */
} verdict_t;

static const verdict_t OK_VERDICT = { 200, NULL };

static void respond(int fd, int status, const char *text)
{
    const char *phrase = status == 200 ? "OK"
                       : status == 400 ? "Bad Request"
                       : status == 403 ? "Forbidden"
                       : status == 404 ? "Not Found"
                       : status == 413 ? "Payload Too Large"
                       : status == 501 ? "Not Implemented"
                       : status == 503 ? "Service Unavailable"
                       :                 "Error";
    char buf[512];
    int n = snprintf(buf, sizeof buf,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        status, phrase, strlen(text), text);
    if (n > 0 && (size_t)n < sizeof buf)
        (void)!write(fd, buf, (size_t)n);
}

/* Case-insensitive compare for a header name of known length. Header names
 * are ASCII by RFC 9110; tolower on anything else is not our problem because
 * the byte never got past the character check in read_request(). */
static int name_eq(const char *a, size_t alen, const char *lower)
{
    if (strlen(lower) != alen) return 0;
    for (size_t i = 0; i < alen; i++) {
        char c = a[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != lower[i]) return 0;
    }
    return 1;
}

/* --------------------------------------------------------------------------
 * The parser.
 *
 * It reads until CRLFCRLF or until MAX_HEADER_BYTES, whichever comes first,
 * and then walks what it read. It never grows a buffer, never allocates, and
 * has one loop per line. That is the whole design: an auditor should be able
 * to convince themselves it terminates by looking at it.
 * ----------------------------------------------------------------------- */
typedef struct {
    char   method[8];
    char   target[MAX_TARGET];
    char   subject[FHSM_AUDIT_ACTOR_MAX];
    int    have_subject;
    int    subject_repeated;
    long   content_length;
    int    saw_transfer_encoding;
} request_t;

static verdict_t read_request(int fd, request_t *r)
{
    memset(r, 0, sizeof *r);
    r->content_length = -1;

    static char buf[MAX_HEADER_BYTES + 1];
    size_t used = 0;
    const char *end = NULL;

    while (used < MAX_HEADER_BYTES) {
        ssize_t n = read(fd, buf + used, MAX_HEADER_BYTES - used);
        if (n < 0) {
            if (errno == EINTR) continue;
            return (verdict_t){ 400, "read_failed" };
        }
        if (n == 0) return (verdict_t){ 400, "closed_early" };
        used += (size_t)n;
        buf[used] = '\0';
        end = strstr(buf, "\r\n\r\n");
        if (end) break;
    }
    if (!end) return (verdict_t){ 400, "headers_too_large" };

    /* --- the request line ------------------------------------------------ */
    const char *p = buf;
    const char *eol = strstr(p, "\r\n");
    if (!eol || (size_t)(eol - p) > MAX_REQUEST_LINE)
        return (verdict_t){ 400, "request_line" };

    const char *sp1 = memchr(p, ' ', (size_t)(eol - p));
    if (!sp1) return (verdict_t){ 400, "request_line" };
    size_t mlen = (size_t)(sp1 - p);
    if (mlen == 0 || mlen >= sizeof r->method)
        return (verdict_t){ 400, "method" };
    memcpy(r->method, p, mlen);
    r->method[mlen] = '\0';
    if (strcmp(r->method, "GET") != 0 && strcmp(r->method, "POST") != 0)
        return (verdict_t){ 400, "method" };

    const char *tstart = sp1 + 1;
    const char *sp2 = memchr(tstart, ' ', (size_t)(eol - tstart));
    if (!sp2) return (verdict_t){ 400, "request_line" };
    size_t tlen = (size_t)(sp2 - tstart);
    if (tlen == 0 || tlen >= sizeof r->target || tstart[0] != '/')
        return (verdict_t){ 400, "target" };
    for (size_t i = 0; i < tlen; i++) {
        unsigned char c = (unsigned char)tstart[i];
        if (c < 0x21 || c > 0x7e) return (verdict_t){ 400, "target" };
    }
    memcpy(r->target, tstart, tlen);
    r->target[tlen] = '\0';

    /* One version, exactly. A service behind a proxy we configure has no
     * reason to negotiate. */
    if ((size_t)(eol - (sp2 + 1)) != 8 || memcmp(sp2 + 1, "HTTP/1.1", 8) != 0)
        return (verdict_t){ 400, "version" };

    /* --- the headers ----------------------------------------------------- */
    p = eol + 2;
    int count = 0;
    while (p < end) {
        eol = strstr(p, "\r\n");
        if (!eol) return (verdict_t){ 400, "header_line" };
        if (++count > MAX_HEADERS) return (verdict_t){ 400, "header_count" };

        const char *colon = memchr(p, ':', (size_t)(eol - p));
        if (!colon) return (verdict_t){ 400, "header_line" };
        size_t nlen = (size_t)(colon - p);
        if (nlen == 0 || nlen > 64) return (verdict_t){ 400, "header_name" };

        const char *v = colon + 1;
        while (v < eol && (*v == ' ' || *v == '\t')) v++;
        size_t vlen = (size_t)(eol - v);
        while (vlen && (v[vlen-1] == ' ' || v[vlen-1] == '\t')) vlen--;
        if (vlen > 256) return (verdict_t){ 400, "header_value" };

        for (size_t i = 0; i < vlen; i++) {
            unsigned char c = (unsigned char)v[i];
            if (c < 0x20 || c == 0x7f) return (verdict_t){ 400, "header_value" };
        }

        if (name_eq(p, nlen, IDENT_HEADER)) {
            /* Repeated is refused rather than resolved. Picking the first or
             * the last is a choice, and any choice here is one an attacker
             * can plan around. */
            if (r->have_subject) { r->subject_repeated = 1; }
            else if (vlen == 0 || vlen >= sizeof r->subject) {
                return (verdict_t){ 400, "subject_length" };
            } else {
                memcpy(r->subject, v, vlen);
                r->subject[vlen] = '\0';
                r->have_subject = 1;
            }
        } else if (name_eq(p, nlen, "content-length")) {
            if (r->content_length >= 0) return (verdict_t){ 400, "content_length" };
            if (vlen == 0 || vlen > 9) return (verdict_t){ 400, "content_length" };
            long cl = 0;
            for (size_t i = 0; i < vlen; i++) {
                if (v[i] < '0' || v[i] > '9') return (verdict_t){ 400, "content_length" };
                cl = cl * 10 + (v[i] - '0');
            }
            if (cl > MAX_BODY) return (verdict_t){ 413, "body_too_large" };
            r->content_length = cl;
        } else if (name_eq(p, nlen, "transfer-encoding")) {
            /* Not "handle chunked too". Refused: a body framed two ways is
             * how a proxy and a backend come to disagree about where one
             * request ends and the next begins. */
            r->saw_transfer_encoding = 1;
        }
        p = eol + 2;
    }

    if (r->saw_transfer_encoding) return (verdict_t){ 400, "transfer_encoding" };
    return OK_VERDICT;
}

/* --------------------------------------------------------------------------
 * One connection.
 * ----------------------------------------------------------------------- */
static void serve(int fd, uid_t proxy_uid)
{
    verdict_t v = OK_VERDICT;
    request_t r;
    memset(&r, 0, sizeof r);

    /* The peer first, before a single byte is read. Nothing this process does
     * on behalf of an unknown peer is safe, including parsing. */
    struct ucred cr;
    socklen_t crlen = sizeof cr;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &crlen) != 0) {
        v = (verdict_t){ 403, "peercred_unavailable" };
    } else if (cr.uid != proxy_uid) {
        v = (verdict_t){ 403, "peer_not_proxy" };
    } else {
        v = read_request(fd, &r);
    }

    /* The actor is set only once an identity has been established, so a
     * refusal before that point is logged with an empty actor -- which is the
     * truth: we do not know who it was, and writing a guess into an audit log
     * would be worse than the blank. */
    if (v.reason == NULL) {
        if (r.subject_repeated)   v = (verdict_t){ 400, "subject_repeated" };
        else if (!r.have_subject) v = (verdict_t){ 403, "no_identity" };
        else                      fhsm_audit_set_actor(r.subject);
    }

    if (v.reason == NULL) {
        if (strcmp(r.target, "/health") == 0 && strcmp(r.method, "GET") == 0) {
            (void)fhsm_audit_event(FHSM_EV_REQUEST_ACCEPTED, -1, -1,
                                    FHSM_ROLE_NONE, FHSM_RV_OK,
                                    "route", "/health", NULL);
            respond(fd, 200, "ok\n");
            fhsm_audit_set_actor(NULL);
            return;
        }
        if (strcmp(r.target, "/token") == 0 && strcmp(r.method, "GET") == 0) {
            /* The only route that touches the module. It exists so the pool
             * and the login are exercised by something: a pool nothing
             * borrows from is a pool whose growth path has never run. It
             * reads the token's own description, which is public -- no key
             * material, no operation, nothing that needs authorisation. */
            unsigned long sess = 0;
            struct tok_info ti;
            memset(&ti, 0, sizeof ti);
            if (pool_acquire(&sess) != 0) {
                v = (verdict_t){ 503, "pool_unavailable" };
            } else {
                unsigned long rv = C_GetTokenInfo(g_slot_id, &ti);
                pool_release(sess);
                if (rv != 0) {
                    v = (verdict_t){ 503, "token_unavailable" };
                } else {
                    char label[33], serial[17];
                    memcpy(label, ti.label, 32);  label[32]  = '\0';
                    memcpy(serial, ti.serialNumber, 16); serial[16] = '\0';
                    for (int i = 31; i >= 0 && label[i]  == ' '; i--) label[i]  = '\0';
                    for (int i = 15; i >= 0 && serial[i] == ' '; i--) serial[i] = '\0';
                    char body[128];
                    snprintf(body, sizeof body, "label=%s\nserial=%s\n", label, serial);
                    (void)fhsm_audit_event(FHSM_EV_REQUEST_ACCEPTED, (int)g_slot_id,
                                            (int)sess, FHSM_ROLE_USER, FHSM_RV_OK,
                                            "route", "/token", NULL);
                    respond(fd, 200, body);
                    fhsm_audit_set_actor(NULL);
                    return;
                }
            }
        }
        else if (strcmp(r.target, "/sign")         == 0 ||
            strcmp(r.target, "/verify")       == 0 ||
            strcmp(r.target, "/certificates") == 0 ||
            strcmp(r.target, "/ocsp")         == 0) {
            /* Named, refused, and audited as accepted: the request passed
             * every guard, and the only reason it does nothing is that the
             * operation is not written. Recording it as a refusal would make
             * the log lie about who was turned away. */
            (void)fhsm_audit_event(FHSM_EV_REQUEST_ACCEPTED, -1, -1,
                                    FHSM_ROLE_NONE, FHSM_RV_OK,
                                    "route", r.target, "state", "not_implemented",
                                    NULL);
            respond(fd, 501, "not implemented yet\n");
            fhsm_audit_set_actor(NULL);
            return;
        }
        v = (verdict_t){ 404, "unknown_route" };
    }

    (void)fhsm_audit_event(FHSM_EV_REQUEST_REFUSED, -1, -1,
                            FHSM_ROLE_NONE, FHSM_RV_FUNCTION_FAILED,
                            "reason", v.reason,
                            "route", r.target[0] ? r.target : "-",
                            NULL);
    respond(fd, v.status, "refused\n");
    fhsm_audit_set_actor(NULL);
}

/* --------------------------------------------------------------------------
 * The PIN, once, from a place a child process cannot inherit.
 *
 * docs/DAEMON_PIN.md decided this and also decided what to refuse, which is
 * the part worth having in the code rather than the document:
 *
 *   - no PIN in an argument (visible in ps) and none in an inherited
 *     environment variable, because systemd's own reason for credentials is
 *     that the environment is inherited by every child the daemon ever spawns;
 *   - one attempt, never a retry loop. The token locks after
 *     FHSM_PIN_MAX_FAILED consecutive failures, so a daemon restarting under
 *     systemd would spend those five in seconds and turn a misconfigured
 *     credential into a destroyed deployment;
 *   - never log the PIN, its length, or a hash of it.
 * ----------------------------------------------------------------------- */
static int login_once(unsigned long slot, const char *pin_file_override)
{
    char path[512];
    if (pin_file_override) {
        snprintf(path, sizeof path, "%s", pin_file_override);
    } else {
        const char *dir = getenv("CREDENTIALS_DIRECTORY");
        if (!dir || !*dir) {
            fprintf(stderr,
              "fhsm-service: no PIN source. Either run under systemd with\n"
              "  LoadCredentialEncrypted=fhsm-pin:... so that\n"
              "  $CREDENTIALS_DIRECTORY/fhsm-pin exists, or pass --pin-file PATH\n"
              "  for a test rig. There is no third option, and none that reads\n"
              "  the environment: see docs/DAEMON_PIN.md.\n");
            return -1;
        }
        snprintf(path, sizeof path, "%s/fhsm-pin", dir);
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "fhsm-service: cannot read the PIN from %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    unsigned char pin[128];
    ssize_t n = read(fd, pin, sizeof pin);
    close(fd);
    if (n <= 0) {
        fhsm_zeroize(pin, sizeof pin);
        fprintf(stderr, "fhsm-service: the PIN file is empty.\n");
        return -1;
    }
    /* A credential written by a shell usually ends in a newline, and a PIN is
     * a byte string: the trailing byte would be part of it. Trimmed here,
     * once, rather than by every operator who wonders why login fails. */
    while (n > 0 && (pin[n-1] == '\n' || pin[n-1] == '\r')) n--;

    unsigned long sess = 0;
    unsigned long rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION_,
                                      NULL, NULL, &sess);
    if (rv != 0) {
        fhsm_zeroize(pin, sizeof pin);
        fprintf(stderr, "fhsm-service: C_OpenSession failed (0x%lx)\n", rv);
        return -1;
    }
    rv = C_Login(sess, CKU_USER_, pin, (unsigned long)n);
    fhsm_zeroize(pin, sizeof pin);          /* before anything can fail below */

    if (rv != 0) {
        (void)C_CloseSession(sess);
        fprintf(stderr,
          "fhsm-service: C_Login failed (0x%lx). Not retrying: the token locks\n"
          "  after a handful of consecutive failures, and a restart loop would\n"
          "  spend them. Fix the credential and start again.\n", rv);
        return -1;
    }

    /* Login state is per token per application, so this one session's login
     * covers every session this process opens afterwards -- which is exactly
     * why the pool is not a security boundary (ADR) and why one process
     * cannot serve two clients as two different roles. The session is kept as
     * the pool's first slot rather than closed. */
    pthread_mutex_lock(&g_pool_mu);
    g_pool[0].handle = sess;
    g_pool[0].in_use = 0;
    g_pool_open = 1;
    pthread_mutex_unlock(&g_pool_mu);
    return 0;
}

/* --------------------------------------------------------------------------
 * Workers. Each takes a connection off the listening socket and serves it to
 * the end. accept() on one listening socket from several threads is safe on
 * Linux and needs no lock of ours.
 * ----------------------------------------------------------------------- */
typedef struct { int lfd; int stopfd; uid_t proxy_uid; } worker_arg_t;

/* Each worker waits on the listening socket AND on a stop pipe, rather than
 * blocking in accept().
 *
 * The obvious arrangement -- every thread in accept(), close the socket to
 * stop them -- does not work, and finding that out is what this comment is
 * for. A signal is delivered to one thread, so only that one leaves accept();
 * and closing the listening descriptor from another thread does not reliably
 * wake the rest on Linux. The process then never exits, a service manager
 * escalates to SIGKILL, and the stop is never recorded. A pipe every worker
 * is watching wakes all of them at once, and is portable. */
static void *worker(void *argp)
{
    worker_arg_t *a = argp;
    for (;;) {
        struct pollfd fds[2];
        fds[0].fd = a->lfd;    fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = a->stopfd; fds[1].events = POLLIN; fds[1].revents = 0;
        int n = poll(fds, 2, -1);
        if (n < 0) {
            if (errno == EINTR) { if (g_stop) break; continue; }
            break;
        }
        if (fds[1].revents) break;
        if (!(fds[0].revents & POLLIN)) continue;

        int cfd = accept(a->lfd, NULL, NULL);
        if (cfd < 0) {
            /* Another worker took it first: poll() reported the socket
             * readable to all of them and only one wins. Not an error. */
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            break;
        }
        serve(cfd, a->proxy_uid);
        close(cfd);
    }
    return NULL;
}

static void usage(void)
{
    fprintf(stderr,
      "fhsm-service --- the REST service's guards (#111), no operations yet\n\n"
      "  fhsm-service --socket PATH --proxy-uid N\n\n"
      "  --socket PATH    unix socket to listen on. Created with mode 0660;\n"
      "                   put the proxy in the group and nobody else.\n"
      "  --proxy-uid N    the uid the reverse proxy runs as. Required, with no\n"
      "                   default: SO_PEERCRED is the whole enforcement, and a\n"
      "                   guard whose value was guessed is not a guard.\n"
      "  --workers N      concurrent request handlers (default 4).\n"
      "  --pool-max N     ceiling on pooled sessions (default 32, module cap\n"
      "                   127). Grown lazily: an idle session still costs\n"
      "                   ~29 KiB resident, so they are opened on demand.\n"
      "  --pin-file PATH  read the token PIN from PATH instead of from\n"
      "                   $CREDENTIALS_DIRECTORY/fhsm-pin. For test rigs; a\n"
      "                   deployment uses LoadCredentialEncrypted=.\n\n"
      "  The token directory comes from FHSM_TOKENS_DIR, as everywhere else.\n"
      "  The PIN is never taken from an argument or an inherited environment\n"
      "  variable -- see docs/DAEMON_PIN.md for why the environment is as bad\n"
      "  as the command line here.\n\n"
      "  /token reads the token's public description and is the only route\n"
      "  that touches the module. /sign and friends answer 501.\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *sock_path = NULL, *pin_file = NULL;
    long proxy_uid = -1, workers = 4, pool_max = 32;

    for (int i = 1; i < argc; i++) {
        char *e = NULL;
        if (!strcmp(argv[i], "--socket") && i + 1 < argc) sock_path = argv[++i];
        else if (!strcmp(argv[i], "--pin-file") && i + 1 < argc) pin_file = argv[++i];
        else if (!strcmp(argv[i], "--proxy-uid") && i + 1 < argc) {
            proxy_uid = strtol(argv[++i], &e, 10);
            if (!e || *e || proxy_uid < 0) usage();
        } else if (!strcmp(argv[i], "--workers") && i + 1 < argc) {
            workers = strtol(argv[++i], &e, 10);
            if (!e || *e || workers < 1 || workers > 256) usage();
        } else if (!strcmp(argv[i], "--pool-max") && i + 1 < argc) {
            pool_max = strtol(argv[++i], &e, 10);
            if (!e || *e || pool_max < 1 || pool_max > POOL_MAX_LIMIT) usage();
        } else usage();
    }
    if (!sock_path || proxy_uid < 0) usage();
    if (pool_max < workers) {
        /* Refused rather than silently raised. A pool smaller than the worker
         * count means a worker that can never make progress on some request,
         * and quietly fixing the operator's arithmetic hides the fact that
         * they meant something we did not do. */
        fprintf(stderr, "fhsm-service: --pool-max (%ld) is below --workers (%ld).\n"
                        "  Every worker needs a session it can hold for the length\n"
                        "  of a request; with fewer sessions than workers one of\n"
                        "  them would block for as long as the service runs.\n",
                pool_max, workers);
        return 2;
    }
    g_pool_max = (int)pool_max;

    if (pipe(g_stop_pipe) != 0) { perror("fhsm-service: pipe"); return 1; }

    /* sigaction, not signal(): glibc's signal() installs the handler with
     * SA_RESTART, so accept() is restarted instead of returning EINTR and the
     * daemon never notices it was asked to stop. Found by a test that hung
     * waiting for the process to exit -- systemd would have reached the same
     * conclusion with SIGKILL, and the stop would never have been recorded. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                     /* deliberately NOT SA_RESTART */
    (void)sigaction(SIGINT,  &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);

    struct sigaction ign;
    memset(&ign, 0, sizeof ign);
    ign.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &ign, NULL);

    /* C_Initialize runs the self-tests and opens the audit log. The service
     * has nothing to say before the log can record it saying it. */
    unsigned long rv = C_Initialize(NULL);
    if (rv != FHSM_RV_OK) {
        fprintf(stderr, "fhsm-service: C_Initialize failed (0x%lx). Nothing is\n"
                        "  served without the module, and nothing is served\n"
                        "  without the audit log it opens.\n", rv);
        return 1;
    }

    /* One slot holding a token, resolved rather than assumed to be 0 -- the
     * lesson the tools learned against p11-kit. */
    {
        unsigned long slots[16], n = 16;
        if (C_GetSlotList(1, slots, &n) != 0 || n == 0) {
            fprintf(stderr, "fhsm-service: no slot holds a token. Run"
                            " `fhsm-token init` first.\n");
            return 1;
        }
        if (n > 1) {
            fprintf(stderr, "fhsm-service: %lu slots hold a token; this service"
                            " serves one.\n", n);
            return 1;
        }
        g_slot_id = slots[0];
    }

    if (login_once(g_slot_id, pin_file) != 0) return 1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof addr.sun_path) {
        fprintf(stderr, "fhsm-service: socket path is longer than %zu bytes.\n",
                sizeof addr.sun_path - 1);
        return 2;
    }
    memcpy(addr.sun_path, sock_path, strlen(sock_path));

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) { perror("fhsm-service: socket"); return 1; }

    (void)unlink(sock_path);
    mode_t old = umask(0117);           /* 0660 on the socket, nothing wider */
    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        perror("fhsm-service: bind"); umask(old); return 1;
    }
    umask(old);
    if (listen(lfd, 64) != 0) { perror("fhsm-service: listen"); return 1; }
    /* Non-blocking: several workers wake from the same poll() and only one
     * gets the connection. The losers must not block in accept(). */
    (void)fcntl(lfd, F_SETFL, fcntl(lfd, F_GETFL, 0) | O_NONBLOCK);

    (void)fhsm_audit_event(FHSM_EV_SERVICE_START, -1, -1,
                            FHSM_ROLE_NONE, FHSM_RV_OK,
                            "socket", sock_path, NULL);
    fprintf(stderr, "fhsm-service: listening on %s, uid %ld only,"
                    " %ld workers, pool ceiling %ld\n",
            sock_path, proxy_uid, workers, pool_max);

    /* One thread short of the requested count runs the accept loop here, so
     * that a signal lands on a thread that is in accept() and the process can
     * be told to stop. The workers are detached from that concern. */
    worker_arg_t warg = { lfd, g_stop_pipe[0], (uid_t)proxy_uid };
    pthread_t *tids = calloc((size_t)workers - 1, sizeof *tids);
    if (!tids && workers > 1) { fprintf(stderr, "fhsm-service: out of memory\n"); return 1; }
    for (long i = 0; i < workers - 1; i++) {
        if (pthread_create(&tids[i], NULL, worker, &warg) != 0) {
            fprintf(stderr, "fhsm-service: cannot start worker %ld\n", i);
            return 1;
        }
    }
    worker(&warg);                       /* this thread serves too */

    /* The stop pipe already woke them; joining is only waiting for the
     * request each was in the middle of. */
    for (long i = 0; i < workers - 1; i++) (void)pthread_join(tids[i], NULL);
    close(lfd);
    free(tids);

    pool_close_all();
    (void)fhsm_audit_event(FHSM_EV_SERVICE_STOP, -1, -1,
                            FHSM_ROLE_NONE, FHSM_RV_OK, NULL);
    (void)unlink(sock_path);
    (void)C_Finalize(NULL);
    fprintf(stderr, "fhsm-service: stopped\n");
    return 0;
}
