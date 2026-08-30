/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm-service --- the guards, and nothing else yet (#111).
 *
 *  docs/REST_API_DESIGN.md decided the shape. The guards came first and the
 *  cryptography after, because refusals are the part of an API that ages
 *  worst when they are added late. POST /sign is now real; /verify,
 *  /certificates and /ocsp still answer 501.
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
extern unsigned long C_FindObjectsInit(unsigned long, void *, unsigned long);
extern unsigned long C_FindObjects(unsigned long, unsigned long *, unsigned long,
                                    unsigned long *);
extern unsigned long C_FindObjectsFinal(unsigned long);
extern unsigned long C_SignInit(unsigned long, void *, unsigned long);
extern unsigned long C_Sign(unsigned long, unsigned char *, unsigned long,
                             unsigned char *, unsigned long *);

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
#define CKO_PRIVATE_KEY_   3UL
#define CKA_CLASS_         0UL
#define CKA_LABEL_         3UL
#define CKM_COMPOSITE_     0x80004202UL

/* The header the proxy must set. Named for this project rather than borrowed
 * from nginx or Caddy: the value is trusted absolutely, so it should be
 * obvious in a configuration file that somebody chose to trust it. */
#define IDENT_HEADER "x-fhsm-client-subject"
/* Which key to use. Not which mechanism: the API exposes operations, not
 * PKCS#11 (ADR §2), and a key knows how it signs. Letting a client choose
 * the mechanism would put the algorithm agility in the least trustworthy
 * place in the system. */
#define KEY_HEADER   "x-fhsm-key"

/* Bounds. Every one of them exists to make the parser's worst case small and
 * stated, rather than large and discovered. */
#define MAX_HEADER_BYTES  8192   /* request line + headers, total */
#define MAX_REQUEST_LINE  1024
#define MAX_HEADERS         32
#define MAX_TARGET         256
#define MAX_BODY         65536
#define MAX_KEY_LABEL       64   /* CKA_LABEL is 64 in the token store */

/* --------------------------------------------------------------------------
 * The authorisation policy: which certificate subject may use which key.
 *
 * A text file, one pair per line, subject and key label separated by a tab:
 *
 *     # fhsm-service authorisation policy v1
 *     # SUBJECT<TAB>KEY-LABEL
 *     CN=web01\ttls-web01
 *     CN=ocsp01\tocsp-responder
 *
 * A tab because a subject contains almost anything -- spaces, commas, equals
 * signs -- and a key label does not. Plain text for the same reasons the
 * revocation database is: readable, greppable, diffable, and something an
 * operator can put under version control and review in a merge request.
 *
 * Reloaded on SIGHUP rather than by watching the mtime. The operator decides
 * when a change takes effect, and a file being edited in place is never read
 * half-written. Replace it atomically and send the signal.
 *
 * A reload that fails keeps the previous policy. Neither of the two obvious
 * alternatives is acceptable: falling open would grant everything on a typo,
 * and falling closed would take the authority down for one. The failure is
 * loud and the old rules stand.
 * ----------------------------------------------------------------------- */
#define POLICY_MAX 512

typedef struct {
    char subject[FHSM_AUDIT_ACTOR_MAX];
    char key[MAX_KEY_LABEL];
} policy_rule_t;

static pthread_rwlock_t g_policy_rw = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t  g_reload_mu = PTHREAD_MUTEX_INITIALIZER;
static policy_rule_t    g_policy[POLICY_MAX];
static int              g_policy_n = 0;
static char             g_policy_path[512];
static volatile sig_atomic_t g_reload = 0;

/* Returns the number of rules loaded, or -1 leaving the current set alone. */
static int policy_load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    static policy_rule_t staging[POLICY_MAX];   /* guarded by g_policy_rw */
    int n = 0, lineno = 0, bad = 0;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        lineno++;
        size_t L = strlen(line);
        while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = '\0';
        if (L == 0 || line[0] == '#') continue;
        char *tab = strchr(line, '\t');
        if (!tab) {
            fprintf(stderr, "fhsm-service: %s:%d has no tab; a rule is"
                            " SUBJECT<TAB>KEY-LABEL\n", path, lineno);
            bad = 1; break;
        }
        *tab = '\0';
        const char *subj = line, *key = tab + 1;
        if (!*subj || !*key || strchr(key, '\t')) {
            fprintf(stderr, "fhsm-service: %s:%d is malformed\n", path, lineno);
            bad = 1; break;
        }
        size_t subj_len = strlen(subj), key_len = strlen(key);
        if (subj_len >= sizeof staging[0].subject ||
            key_len  >= sizeof staging[0].key) {
            fprintf(stderr, "fhsm-service: %s:%d is too long\n", path, lineno);
            bad = 1; break;
        }
        if (n >= POLICY_MAX) {
            fprintf(stderr, "fhsm-service: %s has more than %d rules\n",
                    path, POLICY_MAX);
            bad = 1; break;
        }
        /* memcpy, not snprintf: the bound was checked four lines up, and the
         * copy carries the length that was checked. At -O2 gcc followed that
         * reasoning; at the -O1 a TSAN build uses it did not, and warned about
         * a truncation the guard already prevents. Saying it with the length
         * is both clearer and provable at any optimisation level. */
        memcpy(staging[n].subject, subj, subj_len + 1);
        memcpy(staging[n].key,     key,  key_len  + 1);
        n++;
    }
    fclose(f);

    /* One malformed line refuses the whole file, exactly as the revocation
     * database does: a policy read only partly is a policy that grants less
     * than the operator wrote, and finding that out in production is worse
     * than refusing to load. */
    if (bad) return -1;

    pthread_rwlock_wrlock(&g_policy_rw);
    memcpy(g_policy, staging, sizeof g_policy);
    g_policy_n = n;
    pthread_rwlock_unlock(&g_policy_rw);
    return n;
}

/* SIGHUP asks for a reload; the reload happens on the next request.
 *
 * Not in the handler, because almost nothing is safe to call there. Not on a
 * dedicated descriptor either -- that would be a third thing in every worker's
 * poll() set for an event that happens twice a year. The consequence is worth
 * stating: on an idle service the new policy takes effect when the next
 * request arrives, which is exactly when it first matters. */
static void policy_reload_if_asked(void)
{
    if (!g_reload) return;
    pthread_mutex_lock(&g_reload_mu);
    if (g_reload) {
        g_reload = 0;
        int n = policy_load(g_policy_path);
        if (n < 0) {
            fprintf(stderr, "fhsm-service: reloading %s failed; the previous"
                            " policy is still in force.\n", g_policy_path);
        } else {
            fprintf(stderr, "fhsm-service: policy reloaded, %d rule(s)\n", n);
        }
    }
    pthread_mutex_unlock(&g_reload_mu);
}

static int policy_permits(const char *subject, const char *key)
{
    int ok = 0;
    pthread_rwlock_rdlock(&g_policy_rw);
    for (int i = 0; i < g_policy_n; i++) {
        if (strcmp(g_policy[i].subject, subject) == 0 &&
            strcmp(g_policy[i].key, key) == 0) { ok = 1; break; }
    }
    pthread_rwlock_unlock(&g_policy_rw);
    return ok;
}

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

/* --------------------------------------------------------------------------
 * Per-identity concurrency --- fairness, and the resource it actually guards
 *
 * docs/RATE_LIMIT.md says "the cap is on how much of the pool one identity may
 * hold". Measured against this service, that cap could never fire: main()
 * refuses to start when --pool-max < --workers, a worker serves one request at
 * a time, and every path releases its session, so the sessions held at once
 * are at most the worker count and the pool is never contended. Instrumenting
 * the wait and firing 32 concurrent signatures gave pool_waits = 0, in
 * workers=4/pool=8 and in workers=8/pool=8 alike.
 *
 * The starvation the document describes is real; it happens one layer down.
 * With four workers, one identity saturating the service took another
 * identity's median latency from 10.4 ms to 75.1 ms -- a factor of 7.2, with
 * zero pool contention. **The scarce resource is the worker thread.** So the
 * count is of requests in flight per identity, not of pooled sessions.
 *
 * THE CAP APPLIES ONLY WHILE SOMEBODY ELSE IS USING THE SERVICE. One identity
 * alone may use every worker; while another identity is also present, each is
 * held to workers-1, which leaves a worker the other can always take. A
 * service with a single client loses nothing, and nobody is refused while the
 * service is idle -- refusing a client on an idle authority would be a worse
 * failure than the one being prevented.
 *
 * "PRESENT" MEANS RECENTLY SEEN, NOT CURRENTLY IN FLIGHT, and the difference
 * is the whole control. The first version of this counted only identities with
 * a request in flight, which is circular and was measured to do nothing: a
 * starved client spends its time in the kernel's accept backlog, where this
 * process cannot see it. It is not in flight, so it caps nobody; it caps
 * nobody, so it never gets a worker. Against a saturating identity the cap
 * fired zero times and the starvation was unchanged.
 *
 * PRESENCE IS EARNED BY BEING SERVED, not by asking. An identity whose
 * requests are all refused -- an unauthorised key, an unknown subject -- does
 * not become present and does not tighten anyone else's cap. Found by the
 * existing test: an earlier "CN=attacker" probe, refused by the policy, had
 * marked itself present, which capped the legitimate client to workers-1 and
 * turned 12 of its 16 concurrent signatures into 429s. Left alone it would
 * also be an attack: one refused request every window, and the real client
 * loses a worker for as long as the attacker keeps it up.
 *
 * So an identity stays present for IDENT_WINDOW_S after its last *served*
 * request.
 * The clock is CLOCK_MONOTONIC: docs/RATE_LIMIT.md rejects it for the refusal
 * budget because it breaks across a reboot, which is exactly right there and
 * irrelevant here -- this table is in-process and does not outlive the
 * service, so there is no reboot for it to survive.
 *
 * A free entry always exists: the in_flight counts sum to at most the worker
 * count, the table is larger than the largest legal worker count, so at least
 * one entry is idle and can be taken -- the oldest, if none has expired.
 * ----------------------------------------------------------------------- */
#define IDENT_MAX      (POOL_MAX_LIMIT + 1)   /* > any legal --workers */
#define IDENT_WINDOW_S 30   /* how long an identity stays "present" */
/* How long an identity must go without a refusal before its burst is declared
 * over. Without it the burst flaps: a saturating client is refused, admitted,
 * refused again, and each swing writes two lines. Measured at zero cooldown,
 * 9865 refusals produced 786 audit lines -- far better than one per refusal
 * and still not the "handful" docs/RATE_LIMIT.md asks for. The burst is a
 * property of a period, not of a single request. */
#define BURST_COOLDOWN_S 5

typedef struct {
    char          subject[FHSM_AUDIT_ACTOR_MAX];
    int           in_flight;
    int           used;
    time_t        last_seen;         /* CLOCK_MONOTONIC seconds */
    int           limited;           /* inside a burst of refusals */
    unsigned long suppressed;        /* refusals counted, not written */
    time_t        limited_since;
    time_t        last_refusal;
} ident_t;

/* What the caller must write to the log, decided under the lock and written
 * outside it -- an audit write takes a durable barrier, and holding a mutex
 * across one would serialise every identity behind the slowest disk. */
typedef struct {
    int           log_refusal;   /* this refusal is the transition into limited */
    int           log_resume;    /* the burst just ended; close it */
    unsigned long suppressed;    /* how many were counted and not written */
    long          window_s;      /* how long the burst lasted */
} ident_note_t;

static time_t mono_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return ts.tv_sec;
}

static pthread_mutex_t g_ident_mu = PTHREAD_MUTEX_INITIALIZER;
static ident_t         g_ident[IDENT_MAX];
static int             g_workers  = 0;   /* set once, in main(), before threads */

/* 0 admitted and counted, -1 refused. Refusing does not count: a request that
 * was turned away never held a worker, and counting it would make the cap
 * tighten under its own refusals. */
static int ident_enter(const char *subject, ident_note_t *note)
{
    time_t now = mono_now();
    memset(note, 0, sizeof *note);
    pthread_mutex_lock(&g_ident_mu);

    int mine = -1, spare = -1, others = 0;
    time_t oldest = 0;
    for (int i = 0; i < IDENT_MAX; i++) {
        if (!g_ident[i].used) { if (spare < 0) spare = i; continue; }

        int present = g_ident[i].in_flight > 0 ||
                      (now - g_ident[i].last_seen) < IDENT_WINDOW_S;
        if (strcmp(g_ident[i].subject, subject) == 0) { mine = i; continue; }
        if (present) {
            others++;
        } else if (g_ident[i].in_flight == 0) {
            /* Expired and idle: reusable. Prefer the least recently seen, so a
             * burst of one-off identities does not evict an active client. */
            if (spare < 0 || g_ident[i].last_seen < oldest) {
                spare = i; oldest = g_ident[i].last_seen;
            }
        }
    }

    int cap = g_workers;
    if (others > 0 && cap > 1) cap = g_workers - 1;

    if (mine >= 0) {
        if (g_ident[mine].in_flight >= cap) {
            /* Refused, and last_seen is *not* touched: a client kept out must
             * not be able to hold its own presence open by being refused.
             *
             * The first refusal of a burst is written, because an identity
             * that starts being turned away is the event an operator needs.
             * The rest are counted. */
            if (!g_ident[mine].limited) {
                g_ident[mine].limited       = 1;
                g_ident[mine].limited_since = now;
                g_ident[mine].suppressed    = 0;
                note->log_refusal           = 1;
            } else {
                g_ident[mine].suppressed++;
            }
            g_ident[mine].last_refusal = now;
            pthread_mutex_unlock(&g_ident_mu);
            return -1;
        }
        if (g_ident[mine].limited &&
            (now - g_ident[mine].last_refusal) >= BURST_COOLDOWN_S) {
            /* Admitted, and quiet long enough that the burst is really over.
             * Not "admitted once": a client at its cap is admitted and refused
             * alternately, and closing on the first admission would write two
             * lines per swing. */
            note->log_resume  = 1;
            note->suppressed  = g_ident[mine].suppressed;
            note->window_s    = (long)(now - g_ident[mine].limited_since);
            g_ident[mine].limited    = 0;
            g_ident[mine].suppressed = 0;
        }
        g_ident[mine].in_flight++;
        /* last_seen is not touched here: admission is not service. It is set
         * by ident_leave(), and only for a request that was actually served. */
    } else {
        /* A brand-new identity is never refused: it holds nothing yet, and
         * turning away a client's first request because others are busy is the
         * starvation this exists to prevent, pointed the other way. */
        if (spare < 0) { pthread_mutex_unlock(&g_ident_mu); return 0; }
        snprintf(g_ident[spare].subject, sizeof g_ident[spare].subject,
                 "%s", subject);
        g_ident[spare].in_flight    = 1;
        g_ident[spare].last_seen    = 0;   /* not present until it is served */
        g_ident[spare].limited      = 0;
        g_ident[spare].suppressed   = 0;
        g_ident[spare].last_refusal = 0;
        g_ident[spare].used         = 1;
        pthread_mutex_unlock(&g_ident_mu);
        return 0;
    }
    pthread_mutex_unlock(&g_ident_mu);
    return 0;
}

/* A burst that never ended because the client stopped asking would otherwise
 * take its count to the grave. Called once, after the workers have joined. */
static void ident_flush_bursts(void)
{
    time_t now = mono_now();
    for (int i = 0; i < IDENT_MAX; i++) {
        if (!g_ident[i].used || !g_ident[i].limited) continue;
        char n[32], w[32];
        snprintf(n, sizeof n, "%lu", g_ident[i].suppressed);
        snprintf(w, sizeof w, "%ld", (long)(now - g_ident[i].limited_since));
        fhsm_audit_set_actor(g_ident[i].subject);
        (void)fhsm_audit_event(FHSM_EV_IDENTITY_RESUMED, -1, -1,
                                FHSM_ROLE_NONE, FHSM_RV_OK,
                                "suppressed", n, "window_s", w,
                                "ended", "shutdown", NULL);
        fhsm_audit_set_actor(NULL);
        g_ident[i].limited = 0;
    }
}

/* `served` is what earns presence. A request that was refused for any reason
 * decrements the in-flight count and nothing else. */
static void ident_leave(const char *subject, int served)
{
    time_t now = mono_now();
    pthread_mutex_lock(&g_ident_mu);
    for (int i = 0; i < IDENT_MAX; i++) {
        if (g_ident[i].used && g_ident[i].in_flight > 0 &&
            strcmp(g_ident[i].subject, subject) == 0) {
            g_ident[i].in_flight--;
            if (served) g_ident[i].last_seen = now;
            break;
        }
    }
    pthread_mutex_unlock(&g_ident_mu);
}

/* --------------------------------------------------------------------------
 * The refusal budget --- job 2 of docs/RATE_LIMIT.md
 *
 * An authorised client asking for keys it is not authorised for is mapping the
 * token, and repetition is how that is done. What counts here is exactly the
 * authorisation refusal -- a key the policy does not grant, a key that does
 * not exist, a subject the policy does not know, the three that /sign answers
 * identically. Not a malformed request, which says nothing about the token.
 * Not a request already refused by this budget or by the fairness cap, because
 * counting those would let the control tighten under its own refusals.
 *
 * PERSIST THE COUNT. DERIVE THE DELAY. The token bought that lesson: it once
 * stored throttle deadlines in the CLOCK_MONOTONIC domain, and a 500 ms delay
 * read back after a reboot became thirty days.
 *
 * Here it goes further -- **the count is the only thing on disk.** The decay
 * needs elapsed time, and there is no clock that can be persisted honestly:
 * CLOCK_MONOTONIC restarts at boot, CLOCK_REALTIME moves under `date -s`. So
 * nothing else is stored, and on load the decay clock simply starts again. A
 * restart *pauses* the decay; it never rewinds it. That direction is the one
 * that matters: RATE_LIMIT.md requires that a crash -- which an attacker may
 * be able to cause -- must not hand back a reset. The cost is that an honest
 * client's recovery is delayed by a restart, bounded by the decay it would
 * have earned meanwhile.
 *
 * WHEN IT IS WRITTEN. Not at shutdown: a crash is precisely the case this
 * exists for. Not on every refusal either, when the count is still inside the
 * free allowance, because losing a count that owes no delay costs nothing.
 * Written on each increment at or past the allowance -- and the write rate is
 * then bounded by the delay the count itself imposes, which is a pleasant
 * property rather than a coincidence: at a count of 8 the client is held for
 * 8 s, so it cannot force more than one write per 8 s.
 *
 * NEVER A PERMANENT LOCK. The delay escalates, is capped, and always expires.
 * Only the operator suspends an identity, by revoking its certificate.
 * ----------------------------------------------------------------------- */
#define BUDGET_MAX     256   /* identities remembered; > any realistic client set */
#define BUDGET_FREE      4   /* refusals that cost nothing -- a typo is not an attack */
#define BUDGET_DECAY_S 600   /* one refusal forgiven per ten quiet minutes */
#define BUDGET_CAP_S    60   /* the delay never exceeds this */

typedef struct {
    char     subject[FHSM_AUDIT_ACTOR_MAX];
    unsigned count;
    time_t   last;        /* monotonic; in-process only, never written */
    int      used;
    int      announced;   /* the crossing into "delayed" has been logged */
} budget_t;

static pthread_mutex_t g_budget_mu = PTHREAD_MUTEX_INITIALIZER;
static budget_t        g_budget[BUDGET_MAX];
static char            g_budget_path[512];

/* Escalating, capped, and zero inside the free allowance. Doubling from one
 * second: 5 -> 1 s, 6 -> 2, 7 -> 4, 8 -> 8, 9 -> 16, 10 -> 32, 11 -> 60. */
static long budget_delay_s(unsigned n)
{
    if (n <= BUDGET_FREE) return 0;
    unsigned k = n - BUDGET_FREE - 1;
    if (k >= 20) return BUDGET_CAP_S;
    long d = 1L << k;
    return d > BUDGET_CAP_S ? BUDGET_CAP_S : d;
}

/* Caller holds g_budget_mu. */
static unsigned budget_decayed(const budget_t *b, time_t now)
{
    if (b->count == 0) return 0;
    long quiet = (long)(now - b->last);
    if (quiet < 0) quiet = 0;
    unsigned forgiven = (unsigned)(quiet / BUDGET_DECAY_S);
    return forgiven >= b->count ? 0 : b->count - forgiven;
}

/* The whole table, rewritten. It is at most BUDGET_MAX short lines, and a
 * partial file would be worse than a slow one: temp, fsync, rename. */
static void budget_save_locked(void)
{
    if (g_budget_path[0] == '\0') return;
    char tmp[600];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp", g_budget_path);
    if (n < 0 || (size_t)n >= sizeof tmp) return;

    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "# fhsm-service refusal budget v1 -- count<TAB>subject\n");
    for (int i = 0; i < BUDGET_MAX; i++) {
        if (g_budget[i].used && g_budget[i].count > 0)
            fprintf(f, "%u\t%s\n", g_budget[i].count, g_budget[i].subject);
    }
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) { fclose(f); unlink(tmp); return; }
    fclose(f);
    if (rename(tmp, g_budget_path) != 0) unlink(tmp);
}

static void budget_load(const char *dir)
{
    if (!dir || !*dir) return;
    int n = snprintf(g_budget_path, sizeof g_budget_path, "%s/budget", dir);
    if (n < 0 || (size_t)n >= sizeof g_budget_path) { g_budget_path[0] = '\0'; return; }

    FILE *f = fopen(g_budget_path, "r");
    if (!f) return;                       /* no budget yet is not an error */
    time_t now = mono_now();
    char line[600];
    int slot = 0;
    while (fgets(line, sizeof line, f) && slot < BUDGET_MAX) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        char *subj = tab + 1;
        size_t L = strlen(subj);
        while (L && (subj[L-1] == '\n' || subj[L-1] == '\r')) subj[--L] = '\0';
        if (L == 0 || L >= sizeof g_budget[0].subject) continue;
        unsigned c = (unsigned)strtoul(line, NULL, 10);
        if (c == 0) continue;
        snprintf(g_budget[slot].subject, sizeof g_budget[slot].subject, "%s", subj);
        g_budget[slot].count = c;
        g_budget[slot].last  = now;   /* the decay clock starts now, not before */
        g_budget[slot].used  = 1;
        slot++;
    }
    fclose(f);
    if (slot > 0)
        fprintf(stderr, "fhsm-service: refusal budget restored for %d identity(ies)\n",
                slot);
}

/* Is this identity inside the interval its last refusal earned? Returns the
 * seconds remaining, or 0 to let the request through.
 *
 * THE DELAY IS AN INTERVAL BETWEEN ATTEMPTS, NOT A WINDOW OF REFUSAL. A window
 * would be a lock wearing a different word: at a count of 8 the client would
 * be shut out until the decay brought it back under the allowance, which is
 * forty minutes. What the document asks for is that the delay "escalates, is
 * capped, and always expires" -- so one attempt is admitted once the interval
 * has passed, and if that attempt is legitimate the client is simply served.
 *
 * A refusal produced *by this function* does not touch `last`. Otherwise every
 * retry would push the deadline forward and the client could never leave --
 * the control tightening under its own refusals, which is the same defect the
 * counting rule above avoids. */
static long budget_retry_after(const char *subject)
{
    time_t now = mono_now();
    long   wait = 0;
    pthread_mutex_lock(&g_budget_mu);
    for (int i = 0; i < BUDGET_MAX; i++) {
        if (!g_budget[i].used || strcmp(g_budget[i].subject, subject) != 0) continue;
        unsigned n = budget_decayed(&g_budget[i], now);
        long need = budget_delay_s(n);
        long since = (long)(now - g_budget[i].last);
        if (since < 0) since = 0;
        if (need > since) wait = need - since;
        break;
    }
    pthread_mutex_unlock(&g_budget_mu);
    return wait;
}

/* One authorisation refusal against this identity. Returns the count reached,
 * and sets *announce when this is the crossing out of the free allowance --
 * the event docs/RATE_LIMIT.md calls the budget's real product: not the
 * refusal, but the record that an identity started behaving differently. */
static unsigned budget_charge(const char *subject, int *announce)
{
    time_t now = mono_now();
    *announce = 0;
    pthread_mutex_lock(&g_budget_mu);

    int slot = -1, spare = -1;
    unsigned oldest = 0;
    for (int i = 0; i < BUDGET_MAX; i++) {
        if (!g_budget[i].used) { if (spare < 0) spare = i; continue; }
        if (strcmp(g_budget[i].subject, subject) == 0) { slot = i; break; }
        /* An entry decayed to nothing carries no information and is reusable.
         * Preferring the emptiest keeps a busy attacker from evicting the
         * record of a quieter one. */
        unsigned d = budget_decayed(&g_budget[i], now);
        if (d == 0 && (spare < 0 || d < oldest)) { spare = i; oldest = d; }
    }
    if (slot < 0) {
        if (spare < 0) { pthread_mutex_unlock(&g_budget_mu); return 0; }
        slot = spare;
        snprintf(g_budget[slot].subject, sizeof g_budget[slot].subject, "%s", subject);
        g_budget[slot].count     = 0;
        g_budget[slot].announced = 0;
        g_budget[slot].used      = 1;
    }

    unsigned before = budget_decayed(&g_budget[slot], now);
    g_budget[slot].count = before + 1;
    g_budget[slot].last  = now;

    if (g_budget[slot].count > BUDGET_FREE) {
        if (!g_budget[slot].announced) {
            g_budget[slot].announced = 1;
            *announce = 1;
        }
        /* Written here and not at shutdown: a crash is the case this exists
         * for. Not written below the allowance either, where losing the count
         * costs nothing -- and past it, the delay bounds how often a client
         * can force a write. */
        budget_save_locked();
    } else {
        g_budget[slot].announced = 0;
    }
    unsigned reached = g_budget[slot].count;
    pthread_mutex_unlock(&g_budget_mu);
    return reached;
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

static void on_hup(int s) { (void)s; g_reload = 1; }

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

/* Generated at build time from PROFILE. The service links the module's
 * objects statically, so it carries a profile of its own -- and a service
 * built fips-strict cannot sign with the composite mechanism whatever the
 * separately built tools around it can do. --profile exists so that a test
 * rig can ask the binary under test rather than infer from a sibling. */
extern const int fhsm_build_fips_strict;

static void respond_with(int fd, int status, const char *text,
                          const char *extra)
{
    const char *phrase = status == 200 ? "OK"
                       : status == 400 ? "Bad Request"
                       : status == 403 ? "Forbidden"
                       : status == 404 ? "Not Found"
                       : status == 405 ? "Method Not Allowed"
                       : status == 429 ? "Too Many Requests"
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
        "%s"
        "\r\n%s",
        status, phrase, strlen(text), extra ? extra : "", text);
    if (n > 0 && (size_t)n < sizeof buf)
        (void)!write(fd, buf, (size_t)n);
}

static void respond(int fd, int status, const char *text)
{
    respond_with(fd, status, text, NULL);
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
    char   key[MAX_KEY_LABEL];
    int    have_subject;
    int    subject_repeated;
    int    have_key;
    int    key_repeated;
    long   content_length;
    int    saw_transfer_encoding;

    /* The buffers live in the request, and the request lives on the worker's
     * stack. They used to be `static`, which was harmless while one thread
     * served one connection at a time and became a data race the moment
     * workers arrived -- every one of them parsing into the same array. Found
     * by reading, not by a sanitizer: ThreadSanitizer would have caught it,
     * but it could not serve a request in this environment, so nothing did.
     *
     * 8 KiB of headers plus 64 KiB of body against a default 8 MiB thread
     * stack. Bounded, and bounded by the same constants the parser enforces. */
    char   hdr[MAX_HEADER_BYTES + 1];
    size_t hdr_used;
    unsigned char body[MAX_BODY];
    size_t body_len;
} request_t;

static verdict_t read_request(int fd, request_t *r)
{
    memset(r, 0, sizeof *r);
    r->content_length = -1;

    char *buf = r->hdr;
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
        } else if (name_eq(p, nlen, KEY_HEADER)) {
            if (r->have_key) { r->key_repeated = 1; }
            else if (vlen == 0 || vlen >= sizeof r->key) {
                return (verdict_t){ 400, "key_length" };
            } else {
                memcpy(r->key, v, vlen);
                r->key[vlen] = '\0';
                r->have_key = 1;
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

    /* --- the body -------------------------------------------------------
     * Whatever arrived with the headers is already in hand; the rest is read
     * to exactly Content-Length and no further. A body longer than declared
     * belongs to no request we will answer, and one shorter means the client
     * went away mid-sentence. */
    r->hdr_used = used;
    if (r->content_length > 0) {
        const char *bstart = end + 4;
        size_t have = used - (size_t)(bstart - buf);
        if (have > (size_t)r->content_length) have = (size_t)r->content_length;
        memcpy(r->body, bstart, have);
        r->body_len = have;
        while (r->body_len < (size_t)r->content_length) {
            ssize_t n = read(fd, r->body + r->body_len,
                              (size_t)r->content_length - r->body_len);
            if (n < 0) {
                if (errno == EINTR) continue;
                return (verdict_t){ 400, "body_read" };
            }
            if (n == 0) return (verdict_t){ 400, "body_short" };
            r->body_len += (size_t)n;
        }
    }
    return OK_VERDICT;
}

/* --------------------------------------------------------------------------
 * POST /sign
 *
 *     X-FHSM-Client-Subject: <from the proxy>
 *     X-FHSM-Key: <label>
 *     Content-Length: <n>
 *     <n bytes to sign>
 *
 * 200 with the raw signature, or a refusal. No JSON in either direction: the
 * headers are already parsed strictly and boundedly, and a JSON parser in C
 * facing untrusted input is the single largest thing this project could ask a
 * reader to audit (ADR §1). The cost is that a client cannot send a structured
 * request, and nothing here needs one.
 *
 * The mechanism is not a parameter. The key knows how it signs, and letting a
 * caller choose would put algorithm agility in the least trustworthy place in
 * the system -- and would be PKCS#11 leaking through an API that exists not to
 * expose it (ADR §2).
 * ----------------------------------------------------------------------- */
static unsigned long find_key(unsigned long sess, const char *label)
{
    unsigned long cls = CKO_PRIVATE_KEY_;
    struct { unsigned long type; void *pValue; unsigned long len; } tmpl[2] = {
        { CKA_CLASS_, &cls, sizeof cls },
        { CKA_LABEL_, (void *)(uintptr_t)label, (unsigned long)strlen(label) }
    };
    unsigned long h = 0, n = 0;
    if (C_FindObjectsInit(sess, tmpl, 2) != 0) return 0;
    (void)C_FindObjects(sess, &h, 1, &n);
    (void)C_FindObjectsFinal(sess);
    return n ? h : 0;
}

static verdict_t do_sign(int fd, request_t *r)
{
    if (!r->have_key)   return (verdict_t){ 400, "no_key_header" };
    if (r->key_repeated) return (verdict_t){ 400, "key_repeated" };
    if (r->body_len == 0) return (verdict_t){ 400, "empty_body" };

    unsigned long sess = 0;
    if (pool_acquire(&sess) != 0) return (verdict_t){ 503, "pool_unavailable" };

    /* Both questions are asked before either is answered.
     *
     * docs/RATE_LIMIT.md requires that "you are not authorised for that key"
     * and "there is no such key" be the same answer, byte for byte and in the
     * same time -- otherwise the refusal budget is the only thing between an
     * attacker and a map of the token. Returning early on the policy check
     * would make an unauthorised request measurably faster than one naming a
     * key that does not exist, which is the map, one request at a time.
     *
     * So the key is looked up even when the policy has already said no, and
     * the two results are combined afterwards. It costs one object search on
     * a request that will be refused, against an audit line that already
     * costs milliseconds.
     *
     * Honest limit: this equalises the work, not the timing. A search that
     * finds nothing walks the whole store; one that finds a key stops early.
     * Constant-time object lookup is not something this service can impose on
     * the module, and claiming "in the same time" would be claiming more than
     * is true. */
    int permitted = policy_permits(r->subject, r->key);
    unsigned long key = find_key(sess, r->key);

    if (!permitted || key == 0) {
        pool_release(sess);
        return (verdict_t){ 403, "not_authorised" };
    }

    /* Automatic, not static. It was static, and sixteen concurrent
     * signatures then wrote into one 8 KB buffer at once -- found by
     * ThreadSanitizer under load, not by the test, because the only
     * signature the test verified was made before the concurrent burst.
     * This is the second buffer in this file to have been born static in a
     * single-threaded draft and left that way once workers arrived; the
     * first was the request parser. 8 KB on a thread stack is nothing. */
    unsigned char sig[8192];
    unsigned long siglen = sizeof sig;
    unsigned long mech_type = CKM_COMPOSITE_;
    struct { unsigned long mechanism; void *p; unsigned long len; } mech =
        { mech_type, NULL, 0 };

    unsigned long rv = C_SignInit(sess, &mech, key);
    if (rv == 0) rv = C_Sign(sess, r->body, (unsigned long)r->body_len, sig, &siglen);
    pool_release(sess);

    if (rv != 0) {
        (void)fhsm_audit_event(FHSM_EV_SIGN, (int)g_slot_id, (int)sess,
                                FHSM_ROLE_USER, FHSM_RV_FUNCTION_FAILED,
                                "key", r->key, NULL);
        return (verdict_t){ 500, "sign_failed" };
    }

    (void)fhsm_audit_event(FHSM_EV_SIGN, (int)g_slot_id, (int)sess,
                            FHSM_ROLE_USER, FHSM_RV_OK,
                            "key", r->key, NULL);

    char hdr[256];
    int n = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n\r\n", siglen);
    if (n > 0 && (size_t)n < sizeof hdr) {
        (void)!write(fd, hdr, (size_t)n);
        (void)!write(fd, sig, siglen);
    }
    return OK_VERDICT;
}

/* --------------------------------------------------------------------------
 * One connection.
 * ----------------------------------------------------------------------- */
static void serve(int fd, uid_t proxy_uid)
{
    verdict_t v = OK_VERDICT;
    request_t r;
    int       counted = 0;      /* this request holds a slot in g_ident */
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

    /* The budget first, before the fairness cap even counts this request as in
     * flight: an identity inside the interval its refusals earned should not
     * occupy a slot in either table. Rule 1 again -- decided before any audit
     * write, so the control's own record cannot become the flood. */
    long retry_after = 0;
    if (v.reason == NULL) {
        retry_after = budget_retry_after(r.subject);
        if (retry_after > 0)
            v = (verdict_t){ 429, "refusal_budget" };
    }

    /* Before the route, before the pool, and -- per docs/RATE_LIMIT.md rule 1
     * -- before any audit write: a control whose own record can be flooded is
     * a control that hands the attacker the log. Nothing has been done on this
     * request's behalf yet, so refusing here costs a worker one syscall. */
    ident_note_t note;
    memset(&note, 0, sizeof note);
    if (v.reason == NULL) {
        if (ident_enter(r.subject, &note) != 0)
            v = (verdict_t){ 429, "too_many_in_flight" };
        else
            counted = 1;
    }
    if (note.log_resume) {
        char n[32], w[32];
        snprintf(n, sizeof n, "%lu", note.suppressed);
        snprintf(w, sizeof w, "%ld", note.window_s);
        (void)fhsm_audit_event(FHSM_EV_IDENTITY_RESUMED, -1, -1,
                                FHSM_ROLE_NONE, FHSM_RV_OK,
                                "suppressed", n, "window_s", w, NULL);
    }

    if (v.reason == NULL) {
        if (strcmp(r.target, "/health") == 0 && strcmp(r.method, "GET") == 0) {
            (void)fhsm_audit_event(FHSM_EV_REQUEST_ACCEPTED, -1, -1,
                                    FHSM_ROLE_NONE, FHSM_RV_OK,
                                    "route", "/health", NULL);
            respond(fd, 200, "ok\n");
            goto done;
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
                    goto done;
                }
            }
        }
        else if (strcmp(r.target, "/sign") == 0 && strcmp(r.method, "POST") == 0) {
            v = do_sign(fd, &r);
            if (v.reason == NULL) goto done;
        }
        else if (strcmp(r.target, "/sign") == 0) {
            /* /sign exists and the method is wrong -- the guard above admits
             * GET and POST, so this is GET. It used to fall into the 501 list
             * below, which was true when the route was empty and became a lie
             * the moment it was written: "not implemented" for a route that
             * is. 404 would be a different lie, denying a route that exists.
             * 405 is the one answer that is neither. */
            v = (verdict_t){ 405, "wrong_method" };
        }
        else if (strcmp(r.target, "/verify")       == 0 ||
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
            goto done;
        }
        /* `else`, not a bare statement. It was unconditional, which was
         * correct only while every branch above ended in `return`: the moment
         * one of them produced a verdict and fell through -- /sign refusing an
         * unauthorised key -- its verdict was silently replaced by 404. Every
         * refusal the route made came out as "unknown route", which is both
         * the wrong status and a lie in the audit line. */
        else if (v.reason == NULL) v = (verdict_t){ 404, "unknown_route" };
    }

    /* An authorisation refusal, and only that one, is what the budget counts.
     * v.reason is compared rather than the status: 403 is also what a missing
     * identity and a non-proxy peer get, and neither says anything about the
     * token. Charged after the verdict and outside every lock, because the
     * announcement writes to the audit log. */
    if (v.reason != NULL && strcmp(v.reason, "not_authorised") == 0) {
        int announce = 0;
        unsigned n = budget_charge(r.subject, &announce);
        if (announce) {
            char cnt[32], del[32];
            snprintf(cnt, sizeof cnt, "%u", n);
            snprintf(del, sizeof del, "%ld", budget_delay_s(n));
            /* The budget's real product. A certificate stolen from a
             * legitimate client is not detectable by content -- every request
             * it makes is well-formed and authorised. What changes is the rate
             * and the shape, so the line saying an identity started behaving
             * differently is worth more than the refusal itself. */
            (void)fhsm_audit_event(FHSM_EV_IDENTITY_LIMITED, -1, -1,
                                    FHSM_ROLE_NONE, FHSM_RV_FUNCTION_FAILED,
                                    "refusals", cnt, "delay_s", del, NULL);
        }
    }

    /* Every refusal is written except the inside of a throttled burst, whose
     * first line was already written by ident_enter() and whose remainder is
     * counted for the identity_resumed line. This is the weakening
     * docs/RATE_LIMIT.md chooses deliberately: a log that can be flooded into
     * ERROR records nothing at all, which is strictly worse than a log that
     * records a burst as a burst. It is also what makes the cap do anything --
     * measured, a written refusal cost 48.8 ms, so a worker "reserved" for
     * another identity spent it writing refusals for the one being capped. */
    if (v.status != 429 || note.log_refusal) {
        (void)fhsm_audit_event(FHSM_EV_REQUEST_REFUSED, -1, -1,
                                FHSM_ROLE_NONE, FHSM_RV_FUNCTION_FAILED,
                                "reason", v.reason,
                                "route", r.target[0] ? r.target : "-",
                                NULL);
    }
    /* Retry-After, on both kinds of 429 and with different honesty. From the
     * budget it is the interval actually derived from the count. From the
     * fairness cap it is one second, because the header's unit is seconds and
     * the condition clears when a worker finishes a signature -- single-digit
     * milliseconds, so one is the smallest overstatement available.
     *
     * Known and accepted: the two are distinguishable by their value, so a
     * client can tell "you are being throttled for probing" from "the service
     * is busy". docs/RATE_LIMIT.md asks that the refusal not say why, and it
     * does not -- status and body are identical. Telling an attacker their
     * probing was noticed is a deterrent; telling them which key exists would
     * not be. */
    char ra[64];
    const char *extra = NULL;
    if (v.status == 429) {
        snprintf(ra, sizeof ra, "Retry-After: %ld\r\n",
                 retry_after > 0 ? retry_after : 1L);
        extra = ra;
    }
    respond_with(fd, v.status, "refused\n", extra);

    /* One exit, reached by every path, because the previous slice lost a
     * signature buffer to exactly this shape: per-request teardown repeated at
     * each return is teardown that will be forgotten at the next return added.
     * The `goto`s above exist to make this the only place it happens. */
done:
    if (counted) ident_leave(r.subject, v.reason == NULL);
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
        policy_reload_if_asked();
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
      "  --policy PATH    authorisation policy: SUBJECT<TAB>KEY-LABEL per\n"
      "                   line. Required. Reloaded on SIGHUP, taking effect\n"
      "                   on the next request; a failed reload keeps the\n"
      "                   rules already in force.\n"
      "  Fairness: while another identity has a request in flight, each is\n"
      "  held to --workers minus one, so a client cannot take every worker.\n"
      "  A single client is never capped, and the refusal is 429.\n\n"
      "  --profile        print the profile this binary was built with and\n"
      "                   exit. The service links the module statically, so\n"
      "                   the answer is about this binary and no other.\n\n"
      "  --pin-file PATH  read the token PIN from PATH instead of from\n"
      "                   $CREDENTIALS_DIRECTORY/fhsm-pin. For test rigs; a\n"
      "                   deployment uses LoadCredentialEncrypted=.\n\n"
      "  The token directory comes from FHSM_TOKENS_DIR, as everywhere else.\n"
      "  The PIN is never taken from an argument or an inherited environment\n"
      "  variable -- see docs/DAEMON_PIN.md for why the environment is as bad\n"
      "  as the command line here.\n\n"
      "  /token reads the token's public description; POST /sign signs a\n"
      "  request body with the key named by X-FHSM-Key, if the policy file\n"
      "  pairs it with the caller's subject. /verify, /certificates and\n"
      "  /ocsp answer 501.\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *sock_path = NULL, *pin_file = NULL, *policy_file = NULL;
    long proxy_uid = -1, workers = 4, pool_max = 32;

    for (int i = 1; i < argc; i++) {
        char *e = NULL;
        if (!strcmp(argv[i], "--profile")) {
            puts(fhsm_build_fips_strict ? "fips-strict" : "interop");
            return 0;
        }
        else if (!strcmp(argv[i], "--socket") && i + 1 < argc) sock_path = argv[++i];
        else if (!strcmp(argv[i], "--pin-file") && i + 1 < argc) pin_file = argv[++i];
        else if (!strcmp(argv[i], "--policy") && i + 1 < argc) policy_file = argv[++i];
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
    if (!sock_path || proxy_uid < 0 || !policy_file) usage();
    snprintf(g_policy_path, sizeof g_policy_path, "%s", policy_file);
    {
        int n = policy_load(g_policy_path);
        if (n < 0) {
            fprintf(stderr, "fhsm-service: cannot load the policy from %s.\n"
                            "  Refusing to start: with no policy nothing is\n"
                            "  authorised, and a service that answers every\n"
                            "  request with a refusal is worse than one that\n"
                            "  says why it will not run.\n", g_policy_path);
            return 1;
        }
        fprintf(stderr, "fhsm-service: policy loaded, %d rule(s)\n", n);
    }
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
    /* Set before any worker starts, read by every worker afterwards, never
     * written again -- so it needs no lock of its own. */
    g_workers  = (int)workers;

    /* The refusal budget, from the same directory as the token and the audit
     * log. Loaded before the socket exists, so no request can be served
     * against an empty budget that a crash was supposed to preserve. */
    budget_load(getenv("FHSM_TOKENS_DIR"));

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

    struct sigaction hup;
    memset(&hup, 0, sizeof hup);
    hup.sa_handler = on_hup;
    sigemptyset(&hup.sa_mask);
    hup.sa_flags = SA_RESTART;      /* HUP must not interrupt a request */
    (void)sigaction(SIGHUP, &hup, NULL);

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
    /* After the workers have joined, so no burst can still be growing. */
    ident_flush_bursts();

    (void)fhsm_audit_event(FHSM_EV_SERVICE_STOP, -1, -1,
                            FHSM_ROLE_NONE, FHSM_RV_OK, NULL);
    (void)unlink(sock_path);
    (void)C_Finalize(NULL);
    fprintf(stderr, "fhsm-service: stopped\n");
    return 0;
}
