<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Simorgh Labs
-->
# Probes — what a network HSM would actually cost (#111)

Six throwaway programs, kept because their numbers decided the design and
because a number without the program that produced it is an assertion.

They are **not** part of `make all` or `make tests`: each needs a provisioned
token with a composite key, which the test suite does not have. Build and run
them by hand.

```bash
make -C probes/rest
export FHSM_TOKENS_DIR=$(mktemp -d) FHSM_SO_PIN=... FHSM_PIN=...
./tools/fhsm-token init  --module ./libfreehsm-fips.so --label t
./tools/fhsm-csr  keygen --module ./libfreehsm-fips.so --label k
probes/rest/01_latency ./libfreehsm-fips.so k
```

The composite mechanism is `interop`-only, so build the module with
`PROFILE=interop`.

Run each probe against a freshly provisioned token. `02_login_cost` ends by
offering a wrong PIN twice — on purpose, that is the measurement — and leaves
the token throttled, so a probe run after it in the same `FHSM_TOKENS_DIR`
measures the throttle instead of what it meant to.

## How the module is loaded

Through `C_GetFunctionList`, in `p11_probe.h`, and no longer by dlsym'ing each
`C_*` by name. Every probe here segfaulted against `p11-kit-client.so`, which
exports exactly one symbol — the only one PKCS#11 requires. The crash was in
the probe, calling a null pointer that `dlsym` had already declined to fill.

The four tools had the same defect and it was fixed first; these were left
behind, and the first attempt to run `03_login_shared` through a `p11-kit
server` found it. Which matters beyond the bug: these probes exist to measure
the module a REST service would sit on, and the question being measured is what
happens when the client and the token are *not* in the same process.

The slot is enumerated with `C_GetSlotList` for the same reason — slot 0 is a
guess that happens to be right for our module and wrong through p11-kit.
`FHSM_SLOT=N` overrides it when several tokens are present.

## What each one measures

| | Question |
|---|---|
| `01_latency` | What does one signature request cost, session opened per request versus kept warm? |
| `02_login_cost` | Does `C_Login` really run PBKDF2 every time, and does a wrong PIN cost the same? |
| `03_login_shared` | Does a second session inherit the first one's login? |
| `04_concurrency` | How does throughput and latency scale with concurrent signers? |
| `05_session_race` | Is sharing one session between threads safe? |
| `06_kit_isolation` | Does `p11-kit server` isolate two clients' login state? |

## The numbers, 2026-08-18

Intel Core Ultra 7 155H, **2 cores** allocated, OpenSSL 3.5.6, `sha_ni`
present, `PROFILE=interop`, composite `MLDSA65-Ed25519-SHA512`.

| | measured |
|---|---|
| `C_Initialize` | 203–288 ms, once per process (KATs + integrity) |
| `C_Login`, right PIN | 31–39 ms, **every time** — 200 000 PBKDF2 iterations |
| `C_Login`, wrong PIN | 33.5 ms — same cost, so no timing oracle |
| `C_Login`, 2nd wrong | 3.7 ms — the throttle refuses before the KDF |
| composite signature | 3.3–4.3 ms |
| fully stateless request | 43.5 ms → **23 req/s** |
| warm session, 1 thread | 4.2 ms → **237 req/s** |
| pool, 2 threads | 310 sig/s, median 5.6 ms, p95 9.6 ms |
| pool, 4 threads | 315 sig/s, median 11.4 ms, p95 21.5 ms |
| pool, 8 threads | 294 sig/s, median 23.5 ms, p95 52 ms |

Bare PBKDF2-HMAC-SHA-256, 200 000 iterations, measured separately on the same
host: **31.9 ms**. That is the figure that showed `C_Login` was doing the full
derivation rather than a cached shortcut.

## The three findings that changed the design

**1. A stateless API does not make the login stateless.** PKCS#11 login state
is per token *per application*, and one process is one application:

```
session A : C_Login -> 0x0
session B : C_Login -> 0x100   (CKR_USER_ALREADY_LOGGED_IN)
session B : state=3            (logged in as USER)
```

Session B is authenticated without having proved anything. Locally this is
correct and harmless. In a daemon serving N clients it means the first
client's login unlocks the token for every request that follows, whoever sent
it. Authorisation therefore cannot rest on the token being logged in; it has
to live in the service, keyed on the client certificate, above PKCS#11.

**2. The pool is mandatory, and is not a security boundary.** A factor of ten
between 23 and 237 requests per second settles the question. But given (1),
holding sessions warm changes nothing about who is allowed to do what — it is
a performance decision and must be documented as one.

**3. One session per concurrent request, never shared.** Sharing a handle
between threads shares its operation slot:

```
4 threads on ONE session : 160 operations, 6 PKCS#11 errors
8 threads on ONE session : 320 operations, 2 PKCS#11 errors
```

Intermittent, 1–4 %. Note what did *not* happen: no signature came out the
wrong length, and no wrong signature was produced. It fails loudly, with an
error, which is the operation-state guard from #32–#36 holding under
concurrency. A shared-session run scored 350 sig/s — better than the pool —
and that number is worthless, because it was measuring a configuration that
errors.

That last one is the reason these files are in the repository rather than in a
scratch directory. `05_session_race.c` should become a real test the day the
service exists; until then it is the evidence for a rule the service must
follow.

## What is not measured here

Memory per held session, behaviour past the point where the pool is smaller
than the number of concurrent clients, and anything at all about the network:
these all measure the module through `dlopen`, with no socket in sight. The
2-core figure is a floor, not a capacity plan.

## `06_kit_isolation`, and the defect it found

It answers §2b of the ADR: two client processes on one `p11-kit server` socket,
one logged in and holding, the other never logged in.

```bash
p11-kit server -f -n /tmp/fhsm.sock "pkcs11:" --provider $PWD/libfreehsm-fips.so &
export P11_KIT_SERVER_ADDRESS="unix:path=/tmp/fhsm.sock"
C=/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
probes/rest/06_kit_isolation $C hold 14 k1 &
sleep 5
probes/rest/06_kit_isolation $C peek k1
```

Run `peek` against the module **directly** first. Two processes are two
applications, so the answer there must be "no leak" — that is the control, and
without it a "no leak" over the socket means nothing.

The answer is that p11-kit isolates, because it forks a `p11-kit-remote` child
per connection. Visible in `ps`, not in its documentation.

Getting there took a fix in the module: `C_Login` derived the key over
`strlen(pPin)` and ignored `ulPinLen`, so it refused the correct PIN through
p11-kit — whose RPC does not terminate the buffer — and read past its end.
The first run of this probe reported "no leak" while nobody was logged in at
all. That number was as worthless as the 350 sig/s above, and for the same
reason: it measured a configuration that was failing.
