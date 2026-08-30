<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Simorgh Labs
-->
# Network access over REST — the decision (#111)

**Status: decided, and being built.** This document came first and still leads;
what it records is what was chosen, what was measured, and what the
measurements forced us to change our minds about -- several times, including
about claims made in this file.

`service/fhsm_service.c` now exists, in four slices: the guards with no
cryptography, then worker threads with a lazily grown session pool and a login
from a systemd credential, then `POST /sign`, then fairness between identities
and the refusal budget of `docs/RATE_LIMIT.md`. `POST /verify` follows, for the reason
`RELEASE_v2.0.0-beta.md` gives: nothing off the shelf verifies a composite
signature, so a verifier is either our tool on the module's own machine, or
this. What is *not* built is named at the end of this file rather than left to
be inferred.

Three things this document uncovered were built earlier, because they were
defects in the module rather than design of the service: `C_Login` honouring
`ulPinLen`, the audit log's durable barrier being shared between concurrent
writers, and one audit log per opening so that a chain has a single author.
Each is recorded below, next to the measurement that found it.

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

### 2b. And PKCS#11 over the network is a separate question, not this one

The objection that prompted this section: *most cryptographic applications
speak PKCS#11, not REST.* True, and an operations API does not serve them —
Apache, nginx, OpenSSL, a Java keystore and every smart-card-aware application
want a `.so` to load, not a URL.

Four things follow. The first was known; the rest were measured, and the last
two turned out not to be p11-kit questions at all but defects of ours that
p11-kit was simply the first thing to exercise.

**p11-kit already remotes PKCS#11 — the classical subset of it.**
`p11-kit server` publishes a module on a unix socket and `p11-kit-client.so` is
the provider an application loads; SSH forwards the socket. Writing our own
would mean an RPC protocol for 68 entry points in C, the opposite of the
argument that this module can be audited.

This paragraph used to end "nothing needs to be written for the transport",
which was written before anyone tried to sign through it. **Nothing
post-quantum crosses the socket.** Measured with
`probes/rest/07_kit_mechanisms` against p11-kit 0.24.0:

| | mechanisms |
|---|---|
| the module, directly | 72 |
| the same module through `p11-kit server` | **20** |

The 52 that vanish are every post-quantum one: `CKM_ML_DSA` (0x1c, 0x1d), the
standard SHA-3 family (0x2b0…), and our composite `0x80004202`. `C_SignInit`
with the composite answers `CKR_MECHANISM_INVALID` and **the module never sees
the call** — the server-side audit log records `login_ok` and nothing after it.
What survives is RSA, ECDSA, SHA-1/2, AES and HMAC.

It is not a defect of ours: `C_GetMechanismInfo` answers `CKR_OK` directly for
all six mechanisms probed, and `CKR_MECHANISM_INVALID` through the socket for
the four post-quantum ones. And it is not a bug of p11-kit's either.
`rpc-message.c` gates every call on

```c
bool p11_rpc_mechanism_is_supported (CK_MECHANISM_TYPE mech)
{
        if (mechanism_has_no_parameters (mech) ||
            mechanism_has_sane_parameters (mech))
```

— an allow-list, because a `CK_MECHANISM` parameter is a `void *` whose layout
depends on the mechanism and cannot be serialised generically. A mechanism
named in neither list cannot cross, **even one that takes no parameter at
all**, which is the case for ours. On upstream master the list names
`CKM_IBM_DILITHIUM`, `CKM_IBM_KYBER` and `CKM_IBM_SHA3_*` — vendor mechanisms
contributed by IBM — and no standard post-quantum mechanism whatever.

That last detail is the useful one: the list takes vendor mechanisms, so the
route exists. Adding `0x80004202` to `mechanism_has_no_parameters()` is a
handful of lines. `CKM_ML_DSA` with `CK_SIGN_ADDITIONAL_CONTEXT`, and ML-KEM,
would need a serialiser of the kind written for `CKM_IBM_KYBER`. Either way it
is a patch to p11-kit, not a setting.

**It does isolate the login, and the mechanism matters.** The worry was that a
`p11-kit server` is one process, therefore one PKCS#11 application, therefore
the first client to log in unlocks the token for everyone behind the socket.
Measured with `probes/rest/06_kit_isolation`, two client processes on one
socket:

```
[hold] slot 17, C_Login -> 0x0          (client A, logged in, holding)
[peek] slot 17, state = 2  RW_PUBLIC    (client B, never logged in)
[peek] private key "k1" is not visible
```

No leak. The reason is visible in `ps`: the server forks a `p11-kit-remote`
child per connection, so each client gets its own process and therefore its own
application-scoped login state.

Three consequences follow from *how* it isolates, and none is free.

**It costs a full start-up per client.** `C_Initialize` at 203–288 ms of KATs
and integrity check, plus a `C_Login` at 31–52 ms, because nothing is shared
between the children — `p11-kit-remote` is exec'd, so see the fork+exec column
of "What a process-per-client server costs" below for the same cost measured
directly. And the isolation is a property of p11-kit's process
model, not a promise in its documentation that we can rely on across versions;
the probe exists so the claim can be re-tested rather than assumed.

**It broke the audit chain, and that is now fixed.** Each child loads the
module, each module opened the same log, each resumed the chain from the tail
of the file — so two children writing at once each believed themselves the
successor of the same line. Sixty lines, broken at the second. The irony is
exact: the fork-per-client that makes p11-kit safe for login is what destroyed
the record. Fixed by giving each opening its own numbered log
(`docs/AUDIT_DURABILITY.md`), which is a defect of ours that p11-kit merely
made systematic — two `fhsm-sign` invocations in a script did it too.

**And it distributes the token PIN to every client.** This one cannot be
fixed, because it is the isolation. `06_kit_isolation` proved that a client
which does not log in sees nothing; so to be useful every client logs in, with
the PIN. p11-kit remoting does not distribute authorisations, it distributes
the token's secret — the opposite of `docs/DAEMON_PIN.md`, whose whole point is
that the operator never sees that value.

> **So p11-kit is a transport for one operator, for classical mechanisms, and
> not a multi-client service.** An administration workstation reaching its own
> HSM over SSH to do RSA or ECDSA work: yes, and nothing needs to be written
> for it. The same workstation signing with the composite key that is the
> reason this module exists: not today, and not without patching p11-kit. N
> clients of an authority, each holding the PIN that unlocks every key on the
> token: no, at any mechanism. That last distinction is what the REST service
> exists for; the first two are why it cannot simply be replaced by p11-kit.

Note also that the control matters here: run `06_kit_isolation peek` against
the module directly first. Two processes are two applications, so it must
report no leak. A peek that reports isolation over a socket without having
reported the opposite in `03_login_shared` has proved nothing.

**Our own tools could not drive a conforming module.** They dlsym'd each `C_*`
by name and exited when one was missing, so `--module .../p11-kit-client.so`
answered *"C_Initialize missing"* against a module that is entirely correct —
the standard requires exactly one exported symbol. The probes in
`probes/rest/` had the same defect and segfaulted rather than reporting it.
Both now load through `C_GetFunctionList` and enumerate slots with
`C_GetSlotList`. That is a precondition for measuring anything through
p11-kit, and it was found by asking the question, not by a test.

**And asking the question found a defect in the module itself.** Once the
tools could reach a remote module, `C_Login` refused the correct PIN through
p11-kit and accepted it locally. `C_Login` derived the key over
`strlen(pPin)`, ignoring `ulPinLen`: a read past the caller's buffer, which
also refuses any PIN not followed by a zero byte. Locally our own callers
passed `getenv()` pointers, terminated by accident. In the service this
document describes, it is a remote crash on attacker-chosen input. Fixed, with
`tests/test_pin_length.c`. Nothing in the design changed — but the design was
resting on a login path that no non-local client could have used.

### 3. mTLS client certificates, not bearer tokens

The identity for audit and for throttling comes from the certificate subject.
No shared secret is stored server-side, and a client private key does not
travel. Coherent for a project that is a PKI.

---

## What the measurements changed

Six probes, `probes/rest/`, measured on 2 cores with OpenSSL 3.5.6. The
numbers and the programs are in that directory's README; three findings changed
a decision, and the sixth probe is the p11-kit measurement in §2b.

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

### Scaling — and the conclusion that was wrong

This section used to read:

> 310 sig/s at 2 threads, 315 at 4, 294 at 8, on two cores. **Signing is
> CPU-bound**, so past core count you buy latency and nothing else. The pool
> should be sized to cores, not to clients.

It is not CPU-bound. That plateau was the audit log.

Every probe in `probes/rest/` runs against a module whose `C_Initialize` opens
the log, and `C_Sign` writes a line — 25 signatures, 25 `sign` events, counted.
So every number in this document already included a durable write, and none of
them said so. Re-run with `FHSM_AUDIT_LOG=/dev/null`, which formats the line
and computes the HMAC but does not make it durable:

| threads | with the log | on `/dev/null` |
|---|---|---|
| 1 | 199 sig/s | 558 sig/s |
| 2 | 267 sig/s | 859 sig/s |
| 4 | 247 sig/s | **1359 sig/s** |
| 8 | 242 sig/s | 1145 sig/s |

The flat line at ~250 was the `fsync` serialising the whole module. The
cryptography scales *past* core count on this host and reaches five times the
throughput. A single warm signature is 4.0–4.3 ms with the log and 0.9–1.4 ms
without it, so **the durable write is about 70 % of a request** and the
composite signature costs roughly 1 ms, not the 3.3–4.3 ms recorded in
`probes/rest/README.md`.

**What follows for the design.** "Size the pool to cores" was reasoning from a
CPU-bound premise that does not hold.

That open question is now closed and built — `docs/AUDIT_DURABILITY.md`. Every
event keeps a durable barrier before the operation returns, because losing a
delivered signature's record is the failure the log exists to prevent; but the
barrier is *shared* between concurrent writers, which costs nothing in
guarantee. With the log on a real file the module now does:

| threads | before | after |
|---|---|---|
| 1 | 199 sig/s | 222 sig/s |
| 2 | 267 sig/s | 324 sig/s |
| 4 | 247 sig/s | **493** sig/s |
| 8 | 242 sig/s | **674** sig/s |

So it scales past core count after all, and the pool is sized to neither cores
nor the log: it is sized to measurement, and the measurement now has to be
taken on the storage a deployment actually writes to.

The absolute numbers are from a 2-core VM and depend entirely on the storage
underneath; the ratio is the finding.

---

### What a held session costs, and what runs out first

Measured with `tests/bench_session_mem`, which loads the shipped `.so` through
`dlopen` and reads `/proc/self/statm` rather than the allocator — the state in
question is not on the heap and `mallinfo` cannot see it.

| | RSS |
|---|---|
| after `dlopen` | 1 404 KiB |
| after `C_Initialize` | 7 844 KiB |
| per session opened | **+29.3 KiB** |
| per session logged in | +0 |
| per session with an active digest | +0 |
| 127 sessions held, all logged in, all operating | 11 624 KiB |

Three of those numbers are worth more than the table.

**The fixed cost is mostly not ours.** A bare program that links libcrypto and
computes one SHA-256 through `EVP` goes from 3 080 to 6 120 KiB. So the ~6.4
MiB `C_Initialize` adds is dominated by OpenSSL provider initialisation and the
power-on self-tests; the secure heap accounts for about 150 KiB of it, and
`secure_heap_kb` between 64 and 8192 moves the total by that much and no more.

**A session holds almost nothing, and costs 29 KiB anyway.** The session table
entry is about 40 bytes. The 29 KiB is five operation slots of ~4 992 bytes,
which exist whether or not the session ever performs an operation: they are
reserved in `.bss` at load and become resident when `C_OpenSession` zeroes them
so a fresh handle cannot inherit a stale one. That is why an active digest then
costs nothing further — the page is already there. For a service holding idle
clients this is the wrong shape: ~24 KiB of per-session operation state that is
idle almost all the time. Restructuring it is not in this document, but sizing
a pool on the assumption that an idle session is cheap would be wrong by a
factor of about seven hundred.

**Logging in costs zero, and that is a constraint rather than good news.**
PKCS#11 login state is per token per application; the second session's
`C_Login` returns `CKR_USER_ALREADY_LOGGED_IN` and touches no per-session
state. One process cannot hold two clients authenticated as different roles —
which is §2b's isolation argument arriving from the other direction.

**The cap is `FHSM_MAX_SESSIONS - 1`, 127 by default**, then `CKR_HOST_MEMORY`.
It is a compile-time constant. Raising it is the obvious move for a service and
was, until this measurement, unsafe: see the CHANGELOG entry for the four
bounds that had to agree and did not. It is now one constant, checked by
`_Static_assert`, and `tests/test_session_cap.c` asserts that the last handle
the module is willing to issue can log in and work — the property no assertion
about array sizes can express.

Cost of the cap, if raised: ~24 KiB of reserved `.bss` per session. 128 costs
~3 MiB, 512 costs ~12.5 MiB, held whether the sessions are working or idle.

---

### What a process-per-client server costs

Measured with `tests/bench_fork_client`, on two cores. Before any of it could
be measured, a defect had to be fixed: **a child of an initialised parent could
not call `C_Initialize` at all** — it inherited the parent's `INITIALIZED`
state and `INITIALIZED -> INITIALIZING` is rightly not a legal transition, so
every child got `CKR_FUNCTION_FAILED`. The model this section costs out did not
work until this week.

**Latency, one client with nothing competing:**

| | fork | fork+exec |
|---|---|---|
| `C_Initialize` | 8.7–15.0 ms | most of the total |
| `C_Login` (PBKDF2) | 32.0–35.6 ms | 32–35 ms |
| before the first request | **41–47 ms** | **140–280 ms** |

**Connection rate, 16 clients at once:** ~60/s forked, ~10/s forked and
exec'd. Both plateau well below what the module can sign: 674 sig/s at eight
threads. **Connection setup, not cryptography, is the ceiling of this design.**

**Memory, in PSS** — proportional set size, so a page shared by seventeen
processes counts as a seventeenth in each, and summing over the family gives
what the family occupies. RSS would have counted one libcrypto seventeen times
and answered a question nobody asked.

| per client | fork | fork+exec |
|---|---|---|
| PSS | 4 251 KiB | 2 174 KiB |
| private dirty | 4 011 KiB | 1 868 KiB |
| shared clean (file-backed) | 2 952 KiB | 6 096 KiB |
| 16 clients + listener | 71 MiB | 37 MiB |

**The two models trade the same two resources in opposite directions**, and the
breakdown says why rather than leaving it to be guessed. A forked child
inherits an address space in which OpenSSL's providers are already built, so
its `C_Initialize` re-runs the self-tests and little else — six times faster.
It pays for that in private dirty pages: it inherits the parent's touched heap
copy-on-write and then writes over much of it, ending with 2.1× the private
memory of a child that started empty. An exec'd child builds everything from
nothing, which is slow, and shares twice as much file-backed memory with its
siblings, which is cheap.

**p11-kit remoting is the exec'd column.** `p11-kit-remote` is a separate
binary, so a deployment built on §2b's isolation gets ~10 connections/s and
~2 MiB per client, not the forked figures.

**What follows.** A process per client is affordable for a few dozen
long-lived clients and not for short-lived ones: at 41 ms of setup, a client
that connects to make one signature spends 97 % of its time not signing. If
the service ever needs to serve many brief clients, the pool of §"The session
pool is mandatory" is the design, and the isolation §2b requires has to come
from somewhere other than a process boundary — which is a real tension this
document should not pretend it has resolved.

`C_Login` is three quarters of the setup cost, and that is deliberate: the
PBKDF2 iteration count is a defence against an attacker with the token file.
It should not be lowered to make connections faster. A server that logs in
once and holds the session is the answer; a server that logs in per request is
paying a password-hashing cost per request on purpose.

---

## What the service refuses

Refusals are the part of an API that ages well, so they are decided here.

* **A request with no client identity.** Not "anonymous read-only" — refused.

  This still holds, and it is why there are now **two sockets rather than one
  rule with an exception**. An OCSP responder answers relying parties, and a
  relying party is anonymous by construction: a TLS client checking a
  certificate has no client certificate of its own. `/certificates` is the same
  — it is what an AIA `caIssuers` pointer resolves to. Demanding identity there
  would produce a responder nobody can query; carving an exception into this
  line would weaken a rule whose force came from having none.

  So `--public-socket` serves those, with no identity, no policy, no refusal
  budget, **its own workers** so anonymous traffic cannot starve the
  authenticated side, and **no audit line per request** — a durable barrier
  costs milliseconds and an OCSP responder answers as often as clients open
  connections, so one line per query would hand the flood to anyone who can
  reach it. What is recorded is that the listener exists, at start. Signing and
  verifying are simply absent from that surface, answering 404 rather than 403
  or 501: a route that answers anything invites a second look.

  The authenticated socket answers **404** for `/certificates` and `/ocsp`,
  not 501, and names the other listener in a `Link:` header. 501 would say
  "this route exists here and is unwritten", which stopped being true the
  moment they moved; 404 is what a route that is not on this socket is.

  The code both listeners reach is one implementation, in
  `src/fhsm_revocation.c`: the revocation database, the CertID matching and
  the response assembly, shared with `fhsm-ca` rather than mirrored. Two
  copies would agree on the day they were written, and the one that drifted
  would answer `good` for a certificate the CA revoked.
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

~~**The throttle by identity.**~~ **Decided** — `docs/RATE_LIMIT.md`, which
also corrects what was written here. There is nothing to guess: the client
presents a certificate, not a secret. The control has three other jobs, and the
measurement that shaped it is that **a refused request costs us nearly what a
signature costs us** — 2.5–2.9 ms and 302 bytes of audit line, against 3.3–4.3
ms of ML-DSA, ~10 GB/day at saturation. So the limit is enforced before the
audit write rather than after, and a refused identity produces a handful of
lines rather than one per request. It also says every throughput figure below
was taken with the log absent and is optimistic by roughly a factor of two. And "survive
restart the way the token's does" was itself a defect — see
`tests/test_throttle_reboot.c`. Persist the count, derive the delay.

~~**Where the token PIN comes from** for the daemon.~~ **Decided** —
`docs/DAEMON_PIN.md`. A machine-generated PIN (32 DRBG bytes, base64, 44
characters, never seen by the operator), read by default from a systemd
encrypted credential, zeroized as soon as `C_Login` returns. Our own
`fhsm_tpm_seal` was the obvious candidate and is not the default: it binds PCRs
0..7, so a kernel update would stop the service from starting. systemd's
credential encryption binds no PCRs by default, which is the whole difference.

~~**The delegated OCSP responder** (RFC 6960 §4.2.2.2)~~ **Built** — the
certificate profile and `ocsp-respond --responder-cert`, `docs/FHSM_CA.md`.
Anything that *listens* for OCSP still waits for this work.

~~**Memory per held session**, unmeasured.~~ **Measured** — see below.

~~**What a forked-per-client server costs at scale.**~~ **Measured** — see
above. Nothing in this document is now open that a measurement could close.

~~**Whether the pool's growth path works**, never exercised.~~ **Exercised.**
`/token` was too cheap to make two requests overlap; `/sign`, holding a session
for the 3–4 ms of an ML-DSA signature, is not. Sixteen concurrent signatures in
`tests/service_guards.sh` are served by **four distinct pooled sessions**, and
the test prints that number rather than asserting on it — whether the pool
grows depends on how the requests overlap, and an assertion would be demanding
a race resolve a particular way.

**What `/sign` equalises, and what it does not.** The three refusals — a key
the policy does not grant, a key that does not exist, a subject the policy does
not know — are one answer byte for byte, because the route asks both questions
before answering either. That equalises **the work, not the timing**: a search
that finds nothing walks the whole object store, one that finds a key stops
early. Constant-time object lookup is not something this service can impose on
the module, and `docs/RATE_LIMIT.md` is where the remaining exposure belongs.

~~**The service has never been run under load with TSAN.**~~ **Run — and it
found a real defect.** `make TSAN=1` plus `tests/service_guards.sh` under
`setarch -R`: four data races, all one cause. `do_sign()` held a `static`
signature buffer, so sixteen concurrent requests wrote into one 8 KB array and
**fifteen of the sixteen clients received a valid signature over another
client's message, with `200 OK`**. The suite was green throughout, because the
only signature it verified was made before the concurrent burst.

Two things follow, and they are the reason this is recorded here rather than
only in the changelog:

* **A sanitizer that serves zero requests proves nothing.** The earlier "TSAN
  clean" verdict in this document was true and empty. Concurrency defects need
  concurrency, and `/token` was too cheap to produce any.
* **An end-to-end test that verifies one signature proves one signature.** The
  assertion now gives each thread its own message and checks all sixteen.
  Restoring the `static` buffer fails fifteen of them, which is what an
  assertion earning its place looks like.

TSAN is clean under the same load once the buffer is automatic.

---

## See also

* `probes/rest/README.md` — the programs, the numbers, and how to rerun them.
* `docs/ROADMAP.md` — #111-prep, and the audit log's one uncloseable gap.
* `docs/AGD_OPE.md` §4.3–4.4 — the audit log and its chaining key.
