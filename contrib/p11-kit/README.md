<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# A patch to p11-kit, so post-quantum mechanisms cross the socket

Not FreeHSM code. This is a change to somebody else's project, kept here
because we need it, we measured the problem, and it is meant to go upstream.

Two patch files, and only one of them is for submitting:

| | base | status |
|---|---|---|
| `0002-master-carry-parameterless-mechanisms.patch` | upstream `master`, `120050e` (0.26.5) | **the one to send.** 44/44 of p11-kit's meson suite, and 44/44 on unmodified master in the same build directory |
| `0001-carry-parameterless-mechanisms.patch` | 0.24.0 (Ubuntu jammy) | archive. Where the work was done and measured end to end |

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

On master it names `CKM_IBM_DILITHIUM`, `CKM_IBM_KYBER` and `CKM_IBM_SHA3_*`
— IBM's vendor mechanisms — and no standard post-quantum mechanism at all.
Standard `CKM_SHA3_256` is absent while `CKM_IBM_SHA3_256` is present, which is
checkable by reading one file.

## What the master patch changes

**Master has already done most of the work.** `p11_rpc_buffer_add_mechanism()`
encodes an absent parameter as a presence byte of `0`, and
`p11_rpc_buffer_get_mechanism()` reads that byte back for *any* mechanism,
known or not. The two halves are already symmetric. The only thing standing in
the way is an `assert (mechanism_has_sane_parameters (...))` between them.

So the patch is small:

1. **SHA-3 and the post-quantum key-pair generators** added to
   `mechanism_has_no_parameters()`. Safe by inspection: no parameter in any
   mode.

   **Deliberately not added: `CKM_ML_DSA`, `CKM_SLH_DSA`, the `CKM_HASH_*`
   family.** They take an *optional* `CK_SIGN_ADDITIONAL_CONTEXT`. Listing them
   would encode a supplied context as absent and return a signature computed
   over an empty context — well-formed, verifying against nothing the caller
   expects, and silent. **A wrong signature is worse than a refused call.**

2. **`p11_rpc_mechanism_call_is_supported()`** — asks whether a *call* can be
   serialised rather than whether a *type* is known. True when the caller
   supplied no parameter, whatever the mechanism. This is what carries vendor
   mechanisms, and it is strictly safer than enumerating a mechanism with an
   optional parameter: supply a context to `CKM_ML_DSA` and the call is
   refused rather than the context dropped.

3. **The encoder skips the assert for an unrecognised type** and writes the
   presence byte `0` — the path master already has. The decoder is not touched.

4. **`C_GetMechanismList` stops being trimmed**, and `IN_MECHANISM_TYPE` stops
   refusing. Separable, and the piece that needs its own argument: it changes
   what every existing user sees.

## What it was tested against

* **p11-kit's own meson suite on master: 44 tests, 44 pass, 0 failures.**
* Through the patched socket on 0.24.0, all 72 mechanisms are reported.
* A composite ML-DSA-65 + Ed25519 signature made through the socket **verifies
  against the module loaded directly**, and a corrupted copy is refused.
* An unknown mechanism *with* a parameter is still refused:
  `CKM_ML_DSA` no parameter → `CKR_OK`, with one → `CKR_MECHANISM_INVALID`,
  while the module itself accepts it.

## Two things this cost, worth recording

**The 0.24.0 patch had a real bug, and the 0.24.0 suite did not catch it.**
The first version tested `pParameter == NULL` *before* consulting
`mechanism_has_sane_parameters()`, so a mechanism with a registered serialiser
invoked with a NULL parameter was encoded one way and decoded another. The
stream desynchronised. It passed 0.24.0's `make check`, 525 of 525, and failed
master's `test-transport`, where fifty cases died inside `setup_mock_module()`.

The gap between the two suites is where the bug lived. The verification here
was done on 0.24.0 because that is what builds without autotools — and that
choice is exactly what let the bug through.

**On master the bug cannot occur.** Master encodes an absent parameter
explicitly, so there is no short cut to get wrong. The 0.24.0 patch is kept for
the record, not because anyone should apply it.

## What has not been done

* **Not submitted.** No issue opened, no maintainer consulted. See
  `UPSTREAM_ISSUE.md` and `UPSTREAM_PR.md`.
* **No test added to p11-kit's suite.** A contribution should carry one: a mock
  module offering a vendor mechanism, asserted to cross without a parameter and
  be refused with one.
* **Piece 4 should be proposed separately.** Pieces 1–3 stand on their own.

## Applying it

```bash
git clone https://github.com/p11-glue/p11-kit && cd p11-kit
git apply .../contrib/p11-kit/0002-master-carry-parameterless-mechanisms.patch
meson setup /tmp/build && meson compile -C /tmp/build && meson test -C /tmp/build
```

Build in a short path. A long build directory produced four unexplained
failures on Debian 13 that vanished under `/tmp` — unrelated to this patch, and
noted in case it bites someone else.

Ours is `probes/rest/07_kit_mechanisms`, which prints the before and after.
