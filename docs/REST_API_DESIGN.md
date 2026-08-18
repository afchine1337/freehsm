<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Simorgh Labs
-->
# Network access over REST — the decision (#111)

**Status: decided, not built.** Nothing in this document exists in code yet.
It records what was chosen, what was measured, and what the measurements forced
us to change our minds about.

---

## Why this document exists before any code

`docs/ROADMAP.md` calls #111 "the big architectural leap" and lists five
prerequisites. Four are now closed:

| | |
|---|---|
| Locking under concurrency | v1.6.0, proven under ThreadSanitizer |
| Private keys in the secure heap (#127) | shipped |
| State partitioned by session handle | measured, holds |
| **The audit log** | **written, chained, verifiable** |

The fifth — "audit gains an actor" — turned out to be worse than the ROADMAP
described. There was no log at all: `fhsm_audit_open()` was called from
nowhere, and forty-nine event sites returned success while writing nothing. A
network HSM that signs for N remote clients and keeps no record of who asked
cannot be deployed in a public body or a university, which is the mission
statement. So it was built first. It is now a column to fill rather than a log
to write.

---

## The three decisions

### 1. A reverse proxy terminates mTLS; the service listens locally

nginx or Caddy validates the client certificate against the operator's CA — the
one `fhsm-ca` already knows how to run. The service listens on a unix socket
and receives the client identity in a header.

FreeHSM therefore never parses TLS, and never parses HTTP that arrived from a
network. That matters more here than in most projects: the argument for this
module is that it can be audited, and an HTTP parser written in C and exposed
to the internet is the largest thing we could possibly ask a reader to audit.

**The price, stated plainly.** The service must refuse anything that did not
come from the proxy, because the identity header is trusted. A unix socket
makes that verifiable — filesystem permissions decide who can connect, and the
peer credentials are available via `SO_PEERCRED`. A localhost TCP port would
not: any local process could connect and assert any identity it liked. The
socket is not a convenience, it is the enforcement.

### 2. The API exposes operations, not PKCS#11

`POST /sign`, `/verify`, `/certificates`, `/ocsp`. One request carries
everything it needs; no `CK_SESSION_HANDLE` ever crosses the wire.

This was chosen to close ROADMAP point 2 — a session handle is a process-local
integer, and over the wire it becomes a capability that client A could present
to read client B's session.

**And it does not close it as completely as we thought.** See the measurement
below.

### 3. mTLS client certificates, not bearer tokens

The identity for audit and for throttling comes from the certificate subject.
No shared secret is stored server-side, and a client private key does not
travel. Coherent for a project that is a PKI.

---

## What the measurements changed

Five probes, `probes/rest/`, measured on 2 cores with OpenSSL 3.5.6. The
numbers and the programs are in that directory's README; three findings changed
a decision.

### A stateless API does not make the login stateless

```
session A : C_Login -> 0x0
session B : C_Login -> 0x100   (CKR_USER_ALREADY_LOGGED_IN)
session B : state=3            (logged in as USER)
```

PKCS#11 login state is per token **per application**, and one process is one
application. Session B is authenticated without having proved anything. This is
correct PKCS#11, and locally it is harmless: one process is one user.

In a daemon it means **the first client's login unlocks the token for every
request that follows, whoever sent it.** The PIN stops being a check after the
first request of the process's life.

So decision 2 removes handle leakage and nothing else. The consequence is not a
smaller design, it is a different one:

> **Authorisation lives in the service, keyed on the client certificate, and is
> decided before any PKCS#11 call. The token being logged in is an
> implementation detail and must never be read as an access check.**

That sentence is the most important line in this document.

### The session pool is mandatory, and is not a security boundary

| | per request |
|---|---|
| open, login, sign, close every time | 43.5 ms → **23 req/s** |
| session kept warm | 4.2 ms → **237 req/s** |

`C_Login` costs 31–39 ms every time: 200 000 PBKDF2 iterations, with no cached
shortcut, and a wrong PIN costs the same — no timing oracle. That is the right
behaviour for a login and the wrong cost for a per-request operation.

A factor of ten settles it. But given the finding above, holding sessions warm
changes nothing about who may do what. The pool is a performance structure and
will be documented as one, in the code and in the AGD.

### One session per concurrent request, never shared

```
4 threads on ONE session : 160 operations, 6 PKCS#11 errors
8 threads on ONE session : 320 operations, 2 PKCS#11 errors
```

Sharing a handle shares its operation slot. Intermittent, 1–4 %. Note what did
**not** happen: no signature of the wrong length, and no wrong signature. It
fails loudly, which is the operation-state guard from #32–#36 holding under
concurrency.

A shared-session run scored 350 sig/s — better than the pool. That number is
worthless: it measured a configuration that errors. It is recorded because it
was nearly reported as a result.

`probes/rest/05_session_race.c` becomes a real test when the service exists.

### Scaling

310 sig/s at 2 threads, 315 at 4, 294 at 8, on two cores. Signing is CPU-bound,
so past core count you buy latency and nothing else: median 5.6 ms at two
threads, 23.5 ms at eight. The pool should be sized to cores, not to clients,
and the queue in front of it is what absorbs the difference.

---

## What the service refuses

Refusals are the part of an API that ages well, so they are decided here.

* **A request with no client identity.** Not "anonymous read-only" — refused.
* **A connection whose peer credentials do not match the proxy's uid.**
* **Any request naming a key the certificate subject is not authorised for.**
  Authorisation is a decision, not the absence of a denial.
* **A request that would need the module in a state it is not in.** The ERROR
  latch is irreversible by design; a service must report that as unavailable,
  not retry around it.
* **Anything that would let a client choose the audit fields.** The actor comes
  from the certificate, never from the body.

---

## Still open

**The throttle by identity.** The token's own anti-brute-force throttle counts
failures per token, and after the first login of the process it protects
nothing at all. A per-identity throttle at the service becomes the only real
defence against guessing, and it needs to survive restart the way the token's
does.

**Where the token PIN comes from** for the daemon. It cannot be a request
parameter — that was the reason `--pin` does not exist on any of the four
tools. Options are an operator-entered secret at start, a TPM-sealed value, or
a systemd credential; none is chosen.

**The delegated OCSP responder** (RFC 6960 §4.2.2.2) and anything that listens
for OCSP, both of which were the parts of #112 that genuinely do wait for this
work.

**Memory per held session**, unmeasured. The 2-core figures are a floor, not a
capacity plan.

---

## See also

* `probes/rest/README.md` — the programs, the numbers, and how to rerun them.
* `docs/ROADMAP.md` — #111-prep, and the audit log's one uncloseable gap.
* `docs/AGD_OPE.md` §4.3–4.4 — the audit log and its chaining key.
