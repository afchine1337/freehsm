<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0

Draft text for an issue on https://github.com/p11-glue/p11-kit
Open this BEFORE the pull request. It asks nothing and asserts nothing that
cannot be checked from the source in five minutes.
-->

# Issue title

`p11-kit server` hides every post-quantum mechanism a module offers

# Issue body

## The short version

`p11_rpc_mechanism_is_supported()` is an allow-list of mechanism types, and it
has not kept up with PKCS#11. The effect is not a degraded transport; it is a
mechanism that is simply invisible to the client, with no diagnostic anywhere.

You can confirm the shape of this without running anything. In
`p11-kit/rpc-message.c`, `mechanism_has_no_parameters()` on current master
lists:

- `CKM_SHA224`, `CKM_SHA512_256` — standard digests
- `CKM_IBM_SHA3_224` … `CKM_IBM_SHA3_512`, `CKM_IBM_SHA3_*_HMAC`
- `CKM_IBM_DILITHIUM`, `CKM_IBM_KYBER`

and does not list `CKM_SHA3_224`, `CKM_SHA3_256`, `CKM_SHA3_384`,
`CKM_SHA3_512`, `CKM_ML_DSA`, `CKM_ML_KEM` or `CKM_SLH_DSA`.

So IBM's vendor SHA-3 crosses the socket and the standard SHA-3 does not.
SHA-3 has been in PKCS#11 since v3.0; ML-DSA, ML-KEM and SLH-DSA since v3.2.

The comment above the switch already says `/* This list is incomplete */`.
This is a report of what that incompleteness now costs, not a complaint that
it exists.

## What it looks like from a client

Measured with a PKCS#11 module that implements post-quantum signatures,
p11-kit 0.24.0 (Ubuntu jammy):

| | mechanisms reported by `C_GetMechanismList` |
|---|---|
| module loaded directly | 72 |
| same module through `p11-kit server` | **20** |

52 dropped. Among them every mechanism the module exists to provide.
`C_SignInit` with one of them returns `CKR_MECHANISM_INVALID`, and the module
never receives the call — confirmed from the server side, where the module's
audit log records the login and nothing after it.

Two properties of this that make it awkward to diagnose:

1. **`C_GetMechanismList` is filtered, so the mechanism is not merely
   unusable — it is invisible.** An application enumerating mechanisms to
   decide what it can do concludes, correctly as far as it can tell, that the
   token does not offer it.
2. **`C_GetMechanismInfo` also answers `CKR_MECHANISM_INVALID`**, through
   `IN_MECHANISM_TYPE`, even though that call carries a bare mechanism type
   and serialises no parameter at all.

## Why now rather than at any point in the last five years

Because of what is on the other side of the list. Until recently the missing
mechanisms were unusual ones. They are now the mechanisms that public bodies
and universities are being told to migrate to, and a module whose whole
purpose is post-quantum signing becomes an ordinary RSA token when reached
through `p11-kit server`.

## Reproducing it

Any module offering SHA-3 will show the digest half of it. For the
post-quantum half:

```bash
p11-kit server -f -n /tmp/p11.sock "pkcs11:" --provider /path/to/module.so &
export P11_KIT_SERVER_ADDRESS="unix:path=/tmp/p11.sock"
# count C_GetMechanismList through .../p11-kit-client.so, then against the
# module directly, and diff the two lists
```

A small probe that prints both lists and their difference is at
<https://github.com/…/freehsm> in `probes/rest/07_kit_mechanisms.c`
(Apache-2.0, no dependency on p11-kit); happy to reduce it to a self-contained
file here if that is more useful.

## What I am not asking for in this issue

A fix shape. I have one that works and passes your suite, and I would rather
agree on the problem first — in particular on whether filtering
`C_GetMechanismList` is still wanted, since that is the part that changes
behaviour for existing users.

I am glad to send whichever pieces you want, in whatever order.
