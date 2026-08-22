<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0

Draft text for a pull request on https://github.com/p11-glue/p11-kit
Send it AFTER the issue. One commit; the last part can be split out on
request, and the text below says so.
-->

# PR title

rpc: carry mechanisms invoked without a parameter

# PR body

Follows #778.

The RPC layer decides what it can serialise from the mechanism **type**. This
changes it to decide from the **call**, which is a different and easier
question, and lets every parameterless invocation across — post-quantum
mechanisms and vendor mechanisms included — without loosening what the
allow-list was built to protect.

One commit, four parts. The last one changes behaviour for existing users and
I am happy to split it into its own commit, or drop it, on request; the first
three stand without it.

## The encoder already does the hard part

Worth saying first, because it makes the change smaller than it sounds.
`p11_rpc_buffer_add_mechanism()` already encodes an absent parameter as a
presence byte of `0`, and `p11_rpc_buffer_get_mechanism()` already reads that
byte back for *any* mechanism, recognised or not. The two halves are symmetric
today.

The only thing between them is `assert (mechanism_has_sane_parameters (...))`,
which aborts for a type the allow-list does not name — including one invoked
with no parameter, where the encoding would be that same presence byte. This
patch lets that case take the path that already exists. **The decoder is not
touched.**

## 1. Mechanisms that never take a parameter

`CKM_SHA3_224/256/384/512`, their `_HMAC` and `_KEY_GEN` forms, and
`CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_KEM_KEY_PAIR_GEN`,
`CKM_SLH_DSA_KEY_PAIR_GEN`, added to `mechanism_has_no_parameters()`.

Safe by inspection: none takes a parameter in any mode, so nothing is written
after the mechanism type and nothing is read back — exactly what every entry
already in that switch does.

**Deliberately not added: `CKM_ML_DSA`, `CKM_SLH_DSA`, and the `CKM_HASH_*`
family.** Those take an *optional* `CK_SIGN_ADDITIONAL_CONTEXT`. Listing them
as parameterless would encode a supplied context as absent, and the server
would return a signature computed over an empty context: well-formed, verifying
against nothing the caller expects, and silent. **A wrong signature is a worse
failure than a refused call.** Part 2 carries them instead.

I mention this because it is the trap in the obvious version of this patch, and
the reason it is not simply "add the new mechanisms to the list".

## 2. Decide from the call, not the type

```c
bool
p11_rpc_mechanism_call_is_supported (const CK_MECHANISM *mech)
{
        if (mech == NULL)
                return false;
        if (p11_rpc_mechanism_is_supported (mech->mechanism))
                return true;
        return mech->pParameter == NULL && mech->ulParameterLen == 0;
}
```

The allow-list exists because a `CK_MECHANISM` parameter is a `void *` whose
layout depends on the mechanism, so an unrecognised type cannot be encoded.
That reasoning does not reach a call which supplied no parameter: the encoding
is the presence byte the decoder already understands for every mechanism, and
there is nothing left to misencode.

`proto_write_mechanism()` uses it.

This is also strictly safer than enumerating a mechanism with an optional
parameter: with `CKM_ML_DSA` on the list of part 1, a context would be dropped;
with this test, the call is refused.

Demonstrated in both directions against a module implementing `CKM_ML_DSA`:

```
  CKM_ML_DSA, no parameter      C_SignInit -> CKR_OK
  CKM_ML_DSA, with a parameter  C_SignInit -> CKR_MECHANISM_INVALID
```

— refused at the proxy while the module itself accepts it. That is the
boundary this patch draws, and I think it is the right one.

## 3. The encoder stops asserting on an unrecognised type

Two lines: where `p11_rpc_buffer_add_mechanism()` currently asserts, a type
that is in neither list now writes the presence byte `0` and returns. It can
only have reached that point through part 2, which means the call carried no
parameter, which means that byte is the whole of it.

## 4. `C_GetMechanismList` stops being trimmed — the debatable part

`mechanism_list_purge()` removes mechanisms this file cannot serialise. That
was sound while the answer depended only on the type. After part 2 it no
longer does: a mechanism this file has never heard of may be entirely usable,
and trimming hides it.

Measured before the change: a module advertising 72 mechanisms reported 20
through the socket.

The trade is between two imperfect behaviours. Advertising a mechanism whose
parameterised form will fail at `C_*Init` is ordinary PKCS#11 — modules refuse
advertised mechanisms for key type, session state and policy reasons already.
Advertising nothing, for a mechanism the module does offer and the proxy can
carry, is a false statement about the token that the application has no way to
question.

`IN_MECHANISM_TYPE` is relaxed for a narrower reason: it carries a bare
mechanism type for `C_GetMechanismInfo`, serialises no parameter, and so had
nothing to protect.

**If you would rather keep the trimming, or make it conditional, say so and I
will split it out** — parts 1 to 3 stand on their own: `C_SignInit` would work
for a caller that knows the mechanism value, and enumeration would keep today's
behaviour.

## Testing

- `meson test` on this branch — **44 tests, 44 pass, 0 failures**, and the same
  44 pass on unmodified master in the same build directory. Base:
  `120050e` (Release 0.26.5), Debian 13, gcc.
- Through the patched socket, a module advertising 72 mechanisms reports 72.
- A composite ML-DSA-65 + Ed25519 signature produced through the socket
  **verifies against the same module loaded directly**, and a single flipped
  byte in it is rejected — so the verification is discriminating.
- The negative case above: unknown mechanism plus parameter is still refused.

## Notes

- The end-to-end measurements (72 mechanisms, the composite signature) were
  taken against 0.24.0, which is what the environment where this showed up
  could build. This branch is against master and its suite is green there.
- No test added to your suite yet. The natural shape is a mock module offering
  a vendor mechanism, asserted to cross without a parameter and be refused with
  one — I will write it in whatever style you prefer, and would rather match
  your conventions than guess.
