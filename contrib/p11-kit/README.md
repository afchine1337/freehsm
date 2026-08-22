<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# A patch to p11-kit, so post-quantum mechanisms cross the socket

Not FreeHSM code. This is a change to somebody else's project, kept here
because we need it, we measured the problem, and it is meant to go upstream.

## The problem

`p11-kit server` publishes a PKCS#11 module on a socket. Measured against
FreeHSM with `probes/rest/07_kit_mechanisms`:

```
  ./libfreehsm-fips.so                            72
  …/p11-kit-client.so                             20

  dropped by the second: 52
```

The 52 include `CKM_ML_DSA`, the standard SHA-3 family and our composite
`0x80004202` — every post-quantum mechanism the module exists to provide.
`C_SignInit` answers `CKR_MECHANISM_INVALID` and the module never sees the
call.

The cause is a deliberate allow-list in `p11-kit/rpc-message.c`:

```c
bool p11_rpc_mechanism_is_supported (CK_MECHANISM_TYPE mech)
{
        if (mechanism_has_no_parameters (mech) ||
            mechanism_has_sane_parameters (mech))
```

with the reason stated in `rpc-client.c`: mechanism parameters are a `void *`
whose layout depends on the mechanism, so an unknown one cannot be encoded.
The list is enumerated by hand and carries `/* This list is incomplete */`.

## What the patch changes

Three pieces, in increasing order of how much argument they need.

**1. Mechanisms that never take a parameter, added to the list.** The SHA-3
family and the three post-quantum key-pair generators. Safe by inspection:
their wire form is the empty byte array. Ubuntu's 0.24.0 lacks even the
constants, so the patch adds those too; upstream master already has them and
that hunk is unnecessary there.

**Deliberately not added: `CKM_ML_DSA`, `CKM_SLH_DSA`, the `CKM_HASH_*`
family.** They take an *optional* `CK_SIGN_ADDITIONAL_CONTEXT`. Listing them
as parameterless would encode a supplied context as absent, and the server
would return a signature made with an empty context — valid-looking and wrong.
**A wrong signature is worse than a refused one**, so they are carried by (2)
instead, which admits the call only when no context was supplied.

**2. A parameter-aware test, `p11_rpc_mechanism_call_is_supported()`.** The
allow-list answers a question about a *type*. Whether a *call* can be
serialised is a different question, and a better one: if the caller passed
`pParameter == NULL && ulParameterLen == 0`, the encoding is the empty byte
array whatever the mechanism is, and there is nothing left to misencode.

This carries every parameterless use of every mechanism p11-kit does not know,
vendor mechanisms included, while still refusing exactly what the allow-list
was built to refuse. Demonstrated both ways against FreeHSM:

```
  CKM_ML_DSA, no parameter      C_SignInit -> 0x0
  CKM_ML_DSA, WITH a parameter  C_SignInit -> 0x70
```

— refused at the proxy, while the module itself accepts it. That is the
boundary the change draws, and it is the honest one.

**3. `C_GetMechanismList` stops being filtered.** This is the piece worth
arguing about, and a maintainer may want it separately or behind an option.
The filter made sense while the decision could be taken from the type alone;
after (2) it cannot, because a mechanism this file has never heard of may be
perfectly usable. Filtering therefore hides working mechanisms — 52 of them in
the measurement above. A mechanism that is advertised and then fails at
`C_*Init` is ordinary PKCS#11; a mechanism the module advertises and the proxy
makes invisible is a lie about the token.

`IN_MECHANISM_TYPE` is relaxed for the same reason: it carries a bare type for
`C_GetMechanismInfo`, serialises no parameter, and had no cause to refuse.

## What it was tested against

* **p11-kit's own suite: 525 tests, 525 pass, 0 failures** (`make check`,
  0.24.0).
* Through the patched socket, all 72 mechanisms are reported, nothing dropped.
* A composite ML-DSA-65 + Ed25519 signature made through the socket **verifies
  against the module loaded directly**, and a corrupted copy of it is refused —
  so the verifier is not simply agreeing.
* The negative case above: an unknown mechanism with a parameter is still
  refused.

## What has not been done

* **The patch is against 0.24.0**, which is what Ubuntu jammy ships and what
  could be built and measured here. Upstream wants it against `master`, where
  the constants in hunk 1 already exist.
* **Not submitted.** No issue opened, no maintainer consulted. Piece (3)
  changes behaviour for every existing user and should be proposed as its own
  patch with its own reasoning.
* **No test added to p11-kit's suite.** A contribution should carry one — the
  natural shape is a mock module offering a vendor mechanism, asserted to cross
  without a parameter and be refused with one.

## Applying it

```bash
apt-get source p11-kit                 # or git clone upstream
cd p11-kit-0.24.0
patch -p1 < contrib/p11-kit/0001-carry-parameterless-mechanisms.patch
./configure --prefix=/opt/p11-kit-pq && make && make install
```

Ours is `probes/rest/07_kit_mechanisms`, which prints the before and after.
