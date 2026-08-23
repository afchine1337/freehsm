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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

extern unsigned long C_Initialize(void *);
extern unsigned long C_Finalize(void *);

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

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

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
        if (strcmp(r.target, "/sign")         == 0 ||
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

static void usage(void)
{
    fprintf(stderr,
      "fhsm-service --- the REST service's guards (#111), no operations yet\n\n"
      "  fhsm-service --socket PATH --proxy-uid N\n\n"
      "  --socket PATH    unix socket to listen on. Created with mode 0660;\n"
      "                   put the proxy in the group and nobody else.\n"
      "  --proxy-uid N    the uid the reverse proxy runs as. Required, with no\n"
      "                   default: SO_PEERCRED is the whole enforcement, and a\n"
      "                   guard whose value was guessed is not a guard.\n\n"
      "  The token directory comes from FHSM_TOKENS_DIR, as everywhere else.\n"
      "  No route performs cryptography yet; /sign and friends answer 501.\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *sock_path = NULL;
    long proxy_uid = -1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--socket") && i + 1 < argc) sock_path = argv[++i];
        else if (!strcmp(argv[i], "--proxy-uid") && i + 1 < argc) {
            char *e = NULL;
            proxy_uid = strtol(argv[++i], &e, 10);
            if (!e || *e || proxy_uid < 0) usage();
        } else usage();
    }
    if (!sock_path || proxy_uid < 0) usage();

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

    (void)fhsm_audit_event(FHSM_EV_SERVICE_START, -1, -1,
                            FHSM_ROLE_NONE, FHSM_RV_OK,
                            "socket", sock_path, NULL);
    fprintf(stderr, "fhsm-service: listening on %s, accepting uid %ld only\n",
            sock_path, proxy_uid);

    while (!g_stop) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        serve(cfd, (uid_t)proxy_uid);
        close(cfd);
    }

    (void)fhsm_audit_event(FHSM_EV_SERVICE_STOP, -1, -1,
                            FHSM_ROLE_NONE, FHSM_RV_OK, NULL);
    close(lfd);
    (void)unlink(sock_path);
    (void)C_Finalize(NULL);
    fprintf(stderr, "fhsm-service: stopped\n");
    return 0;
}
