<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Reaching a FreeHSM token over a socket with p11-kit

`p11-kit server` publishes a PKCS#11 module on a unix socket;
`p11-kit-client.so` is the provider an application loads instead of the module.
SSH forwards the socket. Nothing has to be written for it, and it works with
FreeHSM.

**Read the next section before setting any of it up.** Two limits decide
whether this is the right tool, and neither is obvious from p11-kit's
documentation.

---

## Two limits, measured

### 1. No post-quantum mechanism crosses the socket

This is the one that surprises people, because it removes the reason FreeHSM
exists.

| | mechanisms advertised |
|---|---|
| the module, loaded directly | 72 |
| the same module through `p11-kit server` | **20** |

The 52 that disappear are every post-quantum mechanism: `CKM_ML_DSA`
(`0x1c`, `0x1d`), the standard SHA-3 family (`0x2b0`…) and the composite
`CKM_COMPOSITE_MLDSA65_ED25519` (`0x80004202`). What survives is RSA, ECDSA,
SHA-1, SHA-2, AES and HMAC.

Signing with the composite key through the socket fails:

```
$ fhsm-sign sign --module …/p11-kit-client.so --label k1 --in msg --out msg.sig
fhsm-sign: C_SignInit failed (0x70)          # CKR_MECHANISM_INVALID
```

and **the module never sees the call** — the server-side audit log records
`login_ok` and nothing after it.

It is not a FreeHSM defect. `C_GetMechanismInfo` answers `CKR_OK` for all six
mechanisms probed when the module is loaded directly, and
`CKR_MECHANISM_INVALID` through the socket for the four post-quantum ones. It
is a design decision upstream: `rpc-message.c` gates every call on

```c
bool p11_rpc_mechanism_is_supported (CK_MECHANISM_TYPE mech)
{
        if (mechanism_has_no_parameters (mech) ||
            mechanism_has_sane_parameters (mech))
```

an allow-list, because a `CK_MECHANISM` parameter is a `void *` whose layout
depends on the mechanism and cannot be serialised generically. A mechanism in
neither list cannot cross, **even one that takes no parameter**, which is the
case for ours. Upstream master names `CKM_IBM_DILITHIUM`, `CKM_IBM_KYBER` and
`CKM_IBM_SHA3_*` — vendor mechanisms contributed by IBM — and no standard
post-quantum mechanism at all.

**There is a patch.** `contrib/p11-kit/` carries a change that makes every
parameterless mechanism cross, including ours: a composite signature made
through the patched socket verifies against the module loaded directly, and
p11-kit's own suite still passes -- 44/44 on master; the 525 figure was 0.24.0,
where the patch had a bug that master's suite caught. **Submitted on
2026-08-22**: issue [#778](https://github.com/p11-glue/p11-kit/issues/778) and
PR [#779](https://github.com/p11-glue/p11-kit/issues/779). It is not upstream --
no maintainer has responded as of 2026-08-30 -- so read that directory before
relying on it.

Re-run the measurement rather than trusting this table, which was taken on
unpatched p11-kit 0.24.0:

```bash
probes/rest/07_kit_mechanisms ./libfreehsm.so \
    /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
```

### 2. Every client needs the token's PIN

`p11-kit server` forks a `p11-kit-remote` child per connection, so each client
is its own PKCS#11 application with its own login state. That is good news for
isolation — `probes/rest/06_kit_isolation` shows a client that has not logged
in sees nothing — and it is exactly why the PIN has to travel.

p11-kit remoting does not distribute *authorisations*. It distributes the
token's secret. Anyone who can use the socket usefully holds the value that
unlocks every key on the token, which is the opposite of
[`DAEMON_PIN.md`](DAEMON_PIN.md), whose whole point is that the operator never
sees it.

> **So: one operator reaching their own HSM, for classical mechanisms.** Not a
> multi-client service, and not the composite. `docs/REST_API_DESIGN.md` §2b
> is the reasoning; this page is the mechanics.

---

## Setting it up

The commands below were run against p11-kit 0.24.0 and FreeHSM built
`PROFILE=interop`.

### On the machine holding the token

```bash
export FHSM_TOKENS_DIR=/var/lib/freehsm            # where the token lives
p11-kit server -f -n /run/freehsm/p11.sock "pkcs11:" \
        --provider /usr/lib/freehsm/libfreehsm.so
```

`-f` keeps it in the foreground, which is what you want under a supervisor and
what you want while you are still finding out whether it works. Without `-f`
the command prints two shell assignments and detaches:

```
P11_KIT_SERVER_ADDRESS=unix:path=/run/freehsm/p11.sock; export P11_KIT_SERVER_ADDRESS;
P11_KIT_SERVER_PID=4711; export P11_KIT_SERVER_PID;
```

which are meant to be `eval`-ed.

**The server process needs `FHSM_TOKENS_DIR`, and the client does not.** The
module runs there. A client with the variable set and a server without it
reaches a server that has no token — the error is `no slot at all`, and it
points at the wrong machine.

### On the machine running the application

```bash
export P11_KIT_SERVER_ADDRESS="unix:path=/run/freehsm/p11.sock"
export FHSM_PIN=…                                  # yes, here; see limit 2
fhsm-token info --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
```

```
slot 17
  label          kit
  manufacturer   Simorgh Labs
  model          FreeHSM-C-v1
  initialised    yes
```

**Note the slot number.** p11-kit gives the token whatever id it likes — 17
here, not 0. Any tool that assumes slot 0 fails against a p11-kit socket while
working perfectly against the module; ours enumerate, and `FHSM_SLOT=N`
overrides when several tokens are present.

### Over SSH

The socket is an ordinary unix socket, so:

```bash
ssh -R /run/user/1000/p11.sock:/run/freehsm/p11.sock hsm-host
```

and on the far side `P11_KIT_SERVER_ADDRESS=unix:path=/run/user/1000/p11.sock`.
Nothing FreeHSM-specific happens here; if the forwarding works for any other
socket it works for this one.

---

## What the audit log does

Each `p11-kit-remote` child loads the module, and each opening gets its own
numbered log:

```
audit.log.000001    module_init, state_transition, module_finalize
audit.log.000002    module_init, state_transition, login_ok
```

That is deliberate. Several processes appending to one hash-chained log each
believed themselves the successor of the same line, and the chain broke at the
second entry — a defect of ours that p11-kit's fork-per-connection merely made
systematic. See [`AUDIT_DURABILITY.md`](AUDIT_DURABILITY.md).

The practical consequence: **a busy server produces many log files**, one per
connection, and `freehsm-audit verify` checks one chain at a time. Plan the
rotation and the verification around that rather than around a single file.

---

## Troubleshooting

**`C_SignInit failed (0x70)`** — `CKR_MECHANISM_INVALID`, and almost certainly
limit 1. Confirm with `probes/rest/07_kit_mechanisms`: if the mechanism is in
the module's list and not in the socket's, p11-kit dropped it and no
configuration will bring it back.

**`the module reports no slot at all`** — **two different faults produce this
one message**, and the client cannot tell them apart:

* the server is running and its token directory is empty — check
  `FHSM_TOKENS_DIR` **on the server**, not on the client;
* there is no server behind that socket path at all — a stale socket file
  outlives the process that made it, and `p11-kit-client.so` reports an empty
  slot list rather than a connection error.

Both were reproduced. Distinguish them on the server: if the process is gone,
it is the second. Checking the socket file proves nothing either way.

**`C_GetFunctionList failed (0x5)`** — `CKR_GENERAL_ERROR`, and the usual cause
is that `P11_KIT_SERVER_ADDRESS` holds a bare path. It must be the full form:

```bash
P11_KIT_SERVER_ADDRESS="unix:path=/run/freehsm/p11.sock"   # not /run/freehsm/p11.sock
```

**Everything works, slowly** — expected. A connection costs a full module
start-up: integrity check, power-on self-tests, and a `C_Login` whose PBKDF2 is
expensive on purpose. Measured at 140–280 ms before the first request, so
roughly ten connections a second on two cores. Hold the connection open rather
than reconnecting per operation. `docs/REST_API_DESIGN.md`, "What a
process-per-client server costs".

---

## See also

* [`REST_API_DESIGN.md`](REST_API_DESIGN.md) §2b — why p11-kit is not the
  answer to network access for an authority, and what is.
* [`DAEMON_PIN.md`](DAEMON_PIN.md) — how a PIN reaches a daemon without an
  operator seeing it, which is what limit 2 gives up.
* `probes/rest/06_kit_isolation`, `probes/rest/07_kit_mechanisms` — the two
  measurements this page rests on, written to be re-run.
