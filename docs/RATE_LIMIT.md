<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Simorgh Labs
-->
# Rate limiting by identity (#111)

**Status: decided, not built.** The second of the three items left open by
`docs/REST_API_DESIGN.md`.

---

## First, a correction

That document said:

> The token's own anti-brute-force throttle counts failures per token, and
> after the first login of the process it protects nothing at all. A
> per-identity throttle at the service becomes **the only real defence against
> guessing**, and it needs to survive restart the way the token's does.

The first sentence is right. The second is wrong, and the third rests on
something that turned out to be broken.

**There is nothing to guess.** The client authenticates with a certificate
validated by the proxy against the operator's CA. It presents no secret that
repetition could search: either it holds a private key or it does not. A
control modelled on the token's PIN throttle would be defending a door that
does not exist.

**And "the way the token's does" was a defect.** The token persisted its
throttle *deadline* in the `CLOCK_MONOTONIC` domain, so a reboot turned a
500 ms cooldown into a 29.8-day refusal of the correct PIN. Measured, fixed,
`tests/test_throttle_reboot.c`. What survives a restart correctly is the
**count**; the delay is derived from it. That is the rule this design inherits,
and it is the only thing it should inherit.

---

## What a refused request actually costs — measured

A refusal is nearly free for the client: one HTTP request, and in the service a
string comparison decided before any PKCS#11 call. So the question is what it
costs *us*. The answer is the audit log, and it is not small.

Measured by `tests/bench_audit_rate.c` on the same 2-core host as
`probes/rest/`, OpenSSL 3.5.6, seven runs of 300 events:

| | |
|---|---|
| One audit line, written and `fsync`ed | **2.49 – 2.86 ms** |
| Sustained rate | **350 – 402 events/s** |
| Line size | **302 bytes** |
| At saturation | **~408 MB/hour, ~9.8 GB/day** |
| A composite signature alone, for comparison | ~1 ms (see below) |

**A note on how that range was arrived at.** The first run reported 3.735 ms
and 268 events/s, and this section was originally written around it: the log is
a *lower* ceiling than the crypto, 268 against 310. Six further runs put the
cost at 2.5–2.9 ms and made the first an outlier — a cold page cache straight
after a build. The conclusion it supported was wrong and has been removed. One
run is not a measurement, and the same mistake produced the worthless 350 sig/s
shared-session figure in `probes/rest/README.md`.

Three things follow, and they invert the obvious design.

**A refusal costs us more than a signature costs us.** 2.5–2.9 ms of durable
write against roughly 1 ms of ML-DSA. There is no cheap "no": an attacker who
cannot obtain a single signature can make the service do *more* durable work
than one that can, for the price of an HTTP request.

**The audit line is most of the request, and this was measured badly twice
before it was measured properly.** The claim first written here — that the
numbers in `probes/rest/README.md` were taken with the log absent — is wrong.
The log is opened by `C_Initialize` and `C_Sign` writes a line; 25 signatures
produce 25 `sign` events, counted. Every probe figure already included a
durable write and none of them said so.

Re-running the probes with `FHSM_AUDIT_LOG=/dev/null`, which still formats the
line and computes the HMAC but does not make it durable:

| | with the log | on `/dev/null` |
|---|---|---|
| one warm signature | 4.0–4.3 ms | 0.9–1.4 ms |
| 1 thread | 199 sig/s | 558 sig/s |
| 2 threads | 267 sig/s | 859 sig/s |
| 4 threads | 247 sig/s | **1359 sig/s** |
| 8 threads | 242 sig/s | 1145 sig/s |

So the durable write is **about 70 % of a request**, the composite signature
costs roughly 1 ms rather than the 3.3–4.3 ms recorded in the probes README —
that figure was signature *plus* audit line — and the flat ~250 sig/s that
`docs/REST_API_DESIGN.md` read as CPU saturation was the `fsync` serialising
the module. Corrected there.

**Filling the disk is a way to stop the module.** The log latches `ERROR` when
a write fails, by design — an HSM that cannot record what it did must not keep
doing it. ~10 GB/day of refusal lines makes that latch reachable by anyone who
can be refused.

### Rule 1 — the limit is enforced *before* the audit write

The naive order is: receive, authorise, log the refusal, return. That makes the
control's own record the attack. The order is: receive, identify, **check the
budget**, and only then decide and log.

### Rule 2 — one line per refused request is a bug

Log the *first* refusal from an identity, and log the transition into the
limited state. Then count in memory and emit one summary line on the way out:
`identity_resumed` with the count and the window. A hundred thousand refusals
must produce a handful of lines, not a hundred thousand.

This is a real weakening of "every refusal is recorded", and it is chosen with
the reason stated rather than discovered later: a log that can be flooded into
`ERROR` records nothing at all, which is strictly worse than a log that records
a burst as a burst.

---

## The three jobs it actually has

### 1. Fairness, which is the common case and is not an attack

`probes/rest/04_concurrency` measured 310 sig/s at 2 threads, 315 at 4, 294 at
8 on two cores: signing is CPU-bound and saturates at core count. The pool is
therefore sized to cores, not to clients. One client issuing as many concurrent
requests as there are pooled sessions starves every other client.

The overwhelmingly likely cause is not malice but a retry loop in a client
someone deployed on a Friday. A per-identity concurrency cap is what keeps one
badly-behaved integration from taking the authority offline for everyone else.

### 2. A refusal budget, which is about enumeration and stolen certificates

An authorised client asking for keys it is not authorised for is mapping the
token. Repetition is how that is done, so a budget is the right shape of
control — but only if the answers do not differ:

> **"You are not authorised for that key" and "there is no such key" must be
> the same answer, byte for byte and in the same time.** Otherwise the budget
> is the only thing between an attacker and a map of the token, and budgets
> are meant to be a second line, not the first.

A certificate stolen from a legitimate client is not detectable by content —
every request it makes is well-formed and authorised. What changes is the
*rate* and the *shape*. So the budget's real product is not the refusal, it is
the audit event that says an identity started behaving differently.

### 3. Not anti-brute-force

Stated so that nobody re-derives it: there is no secret to guess. Any future
change that introduces one — a bearer token, a client-supplied PIN — invalidates
this document, and should be read as re-opening it rather than extending it.

---

## The state, and what survives a restart

* **Persist the count. Derive the delay.** The token's lesson, bought this
  week.
* The count **must** survive a restart. A service that restarts on crash would
  otherwise hand an attacker a reset for the price of a crash — and a crash is
  something they may be able to cause.
* The delay **must not** be persisted as an absolute deadline, in any clock
  domain. `CLOCK_MONOTONIC` breaks at reboot, as measured; `CLOCK_REALTIME`
  moves under `date -s`. Derived from the count, neither applies.
* The concurrency cap (job 1) is in-process and needs no persistence: after a
  restart the pool is empty, so there is nothing to be unfair about.

---

## Never a permanent lock

The token locks a role after five failures. That is right for a human PIN,
which carries perhaps twenty bits of entropy and where five tries is generous.

Applying it to a service identity would be a mistake of the same kind as
modelling the whole control on the PIN throttle. There is no entropy to
exhaust, so a lock buys nothing — and it takes an authority offline until an
operator intervenes, which is exactly the outcome a buggy client should not be
able to cause. The delay escalates, it is capped, and it always expires.

Only the operator suspends an identity, and they do it by revoking the
certificate, with a CRL and an OCSP responder that already exist.

---

## What identifies an identity

The **certificate subject**, for authorisation and for the budget. The
**SHA-256 fingerprint** goes in the audit line beside it.

Subject rather than fingerprint for the budget, because renewal is a routine
operator action and should not silently reset a budget or split one identity in
two. Fingerprint in the log, because when reading an incident afterwards the
question is which key was used, not which name was on it.

---

## What it returns

`429`, with `Retry-After` carrying the derived delay. No body that
distinguishes why — the same refusal for an exhausted budget, an unauthorised
key and a key that does not exist. The client learns when to come back and
nothing else.

---

## Not measured here

~~**The `fsync` policy.**~~ **Decided** — `docs/AUDIT_DURABILITY.md`. Keep a
durable barrier before every return, because losing a delivered signature's
record is the failure the log exists to prevent, while losing a record of an
undelivered one is harmless. Share the barrier instead of batching it: at eight
concurrent writers that is 1469 lines/s against 363, with 118 barriers instead
of 480 and the guarantee unchanged. The plateau was never the price of
durability, it was the price of not sharing. What follows below is what that
section said while it was open:

**The `fsync` policy — and it is now the largest open question in #111, not a
detail.** One `fsync` per event is what makes each line durable before the next
is written, and that is what makes the chain meaningful after a power loss. It
also costs a factor of five in throughput and turns the whole module into a
serialised writer: 247 sig/s against 1359 at four threads. Batching would buy
that back and weaken exactly the property the log exists for.

Nothing here decides it. What has changed is that it can no longer be deferred
as a tuning question: the pool size, the queue depth and the rate limit all
follow from it. It should be decided before any of the three are written, and
it needs a measurement on real deployment storage rather than a 2-core VM,
because the whole trade is the cost of one `fsync`.

**The queue in front of the pool.** It does not exist yet, and its depth is the
difference between a rate limit and a wait.

---

## See also

* `docs/REST_API_DESIGN.md` — the service, and the claim corrected above.
* `docs/DAEMON_PIN.md` — the first of the three open items.
* `tests/test_throttle_reboot.c` — where "persist the count, derive the delay"
  comes from.
* `probes/rest/README.md` — the concurrency and latency numbers.
