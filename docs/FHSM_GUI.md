<!--
Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# `fhsm-gui` — a desktop interface over the PKI tools

A GTK 4 window that does what `fhsm-token`, `fhsm-csr`, `fhsm-ca` and
`fhsm-sign` do, through the same operations (`tools/pkiops`), and shows every
PKCS#11 call it makes as it makes it.

It adds no second way of talking to the module. The command-line tools and the
window call the same functions; `tests/pki_tools_characterize.sh` checked,
byte for byte, that moving the tools onto those functions changed nothing they
print. The design and its stages are in [`fhsm-gui-plan.md`](fhsm-gui-plan.md).

---

## Building and running

```bash
sudo apt install libgtk-4-dev            # once
make PROFILE=all-mechanisms              # for the composite; the other algorithms need no profile
make PROFILE=all-mechanisms gui
FHSM_TOKENS_DIR=~/fhsm-tokens ./tools/fhsm-gui
```

`make gui` is not part of `make all`: the module and the command-line tools do
not depend on GTK, and a server needs neither.

The module is loaded from the path in the window (`./libfreehsm.so` by
default) and can be unloaded and another loaded without restarting. The
environment is the module's, as for any other application: `FHSM_TOKENS_DIR`
says where the tokens are, and a build of your own is unsigned until
`make integrity` signs it. If loading fails with `0x80000002`, the module's
integrity self-test refused to start; the terminal that launched the window
says which of its three reasons applies.

---

## Two modes

A switch at the top chooses between them. Both keep the **Token** and
**Signing** tabs.

**Exploration** (the default) offers every operation with the command line's
defaults, in two more tabs, **Certificates** and **Revocation**. It is for
learning the module and the PKI, and for the exception operator mode refuses.

**Operator** mode replaces those two tabs with three guided ones, **CA**,
**Issue** and **Revoke**, that work for one CA set once, and refuses what the
command line leaves to its user (see below).

---

## The tabs, and the commands they correspond to

| Tab | What it does | Command line |
|---|---|---|
| Token | slots, initialise a token, log in and out, keys and their algorithms, generate a key pair | `fhsm-token init`, `fhsm-csr keygen --alg` |
| Certificates | request, self-signed root, issue from a request | `fhsm-csr csr`, `fhsm-csr root`, `fhsm-ca issue` |
| Revocation | the revocation database, revoke, publish a CRL, answer an OCSP request | `fhsm-ca revoke`, `crl`, `ocsp-respond` |
| Signing | raw detached signatures and CMS, signed and checked | `fhsm-sign sign`, `verify`, `cms`, `cms-verify` |
| CA, Issue, Revoke | operator mode: the same operations, for one CA | (the same) |

**The algorithm is chosen where a key pair is generated** — the Token tab, and
Create a new CA in operator mode — from the list `fhsm-csr keygen --alg` takes:
the composite, ECDSA P-256 and P-384, RSA-PSS and PKCS#1 v1.5, Ed25519,
ML-DSA-44/65/87. Nothing else asks: every other operation signs with the
algorithm of the key it is given, and the key list shows each key's. The
composite exists only in `all-mechanisms` builds; the others work with the
default profile. CMS uses the key's own digest when it signs, and the one the
structure names when it checks.

The defaults are the tools': a root for 3650 days and serial 1, a certificate
for 365 days or 30 for a delegated OCSP responder, a CRL for 30 days, an OCSP
response for 7. Certificates and requests are read as DER or PEM; output is
written as either where the tools offer both. An issued certificate's serial is
shown with the result — it is 160 random bits, and the number a revocation will
ask for — and **From certificate…** reads it off the file instead of having it
copied by hand.

Recording a revocation needs no login, as with `fhsm-ca revoke`. Checking a CMS
needs neither the token nor a login: the signer's certificate is inside it.

---

## Operator mode

The **CA** tab sets, once: the CA's key, its certificate, its revocation
database, the file where its CRL is published, and the URLs at which that file
is served. **Create a new CA** generates the key pair and the self-signed root
and makes them the CA.

Refused, with no "continue anyway" — whoever needs the exception has
exploration mode and the command-line tools, which are unchanged:

- **Re-initialising a token that holds one.** It destroys every key on it.
- **A key label already on the token.** Two objects under one label make every
  later use of the label ambiguous, and the tools refuse to sign with an
  ambiguous label — after the second key exists. Checked on the token at the
  moment of generating, not on the list the window last showed.
- **A certificate without CRL URLs.** It could not be revoked in any way a
  verifier would notice.
- **Issuing while the published CRL is missing, unreadable or expired.** A
  certificate issued then would point at a list verifiers cannot use. So a new
  CA's first act after its root is to publish a CRL, empty if need be.

**Revoke and publish** records the revocation and publishes a new CRL at once:
in operator mode a revocation is not finished until a list says so.

The published CRL's `nextUpdate` is read from the file itself and re-read every
minute. Once less than a third of its validity is left, the CA and Issue tabs
say so; once it has passed, they say that, and issuing is refused until a new
list is published. Nothing about this is stored in the revocation database,
whose format `fhsm-ca` and `fhsm-service` share.

The CA set on the CA tab is not remembered between runs.

---

## The PIN

Typed into a password field, copied into a buffer the program owns, the field
cleared at once, and the buffer wiped (`OPENSSL_cleanse`) as soon as
`C_Login` has answered. The PIN is never an argument, never in the environment,
never written anywhere, and never in the call log.

That is weaker than the module's own handling, and said here rather than
discovered: GTK may copy what is typed internally, and the password field's
buffer is locked against swapping only if `RLIMIT_MEMLOCK` has room left.
Once a FreeHSM module is loaded it usually has none — its secure heap is sized
to the whole default limit — and GTK prints
`couldn't lock 16384 bytes of memory` and carries on with ordinary memory.

---

## The call log

The right-hand pane lists every PKCS#11 call: the function, a summary of its
arguments, the return value by name, and how long it took. It shows handles,
slots, mechanisms, attribute **types** and byte counts — never a PIN, its
length, or any attribute value. `tests/test_pkiops.c` logs in with distinctive
PINs and fails if either appears in any record.

---

## Where the window differs from the command line

- **Revoking asks for confirmation.** The command line trusts its user; a
  window asks once, because the revocation is not undone from there.
- **Re-initialising a token asks for confirmation** where `fhsm-token init`
  wants `--force`, and operator mode refuses it. Each PIN is typed twice, and
  all four fields are cleared as soon as they are read. The PIN lengths are
  checked against the token's own bounds, as the tool checks them.
- **A new revocation database is never written over an existing file**, even
  if the save dialog offered to replace it.
- **Every file is written to a temporary name and renamed into place**, so a
  web server reading the published CRL while it is replaced sees the old list
  or the new one, never part of either.
- **A signing or verification whose input fails part way is still ended**
  (`C_SignFinal`, `C_VerifyFinal`, result discarded). The session outlives the
  operation here, and one left active would refuse the next.
- **One module, one session at a time.** Unloading closes the session and
  finalises the module. The library is not `dlclose`'d: a module, or the
  libcrypto under it, may have registered handlers to run at process exit.
  A second FreeHSM build loaded afterwards shares that libcrypto's secure heap,
  which the module adopts once the kernel shows it locked.

---

## What it does not do

- **Verify a composite signature made outside FreeHSM's code.** As for the
  command-line tools, nothing off the shelf validates the composite algorithm
  yet; `openssl crl -text` and `openssl x509 -text` read the structures, and
  stop at the signature.
- **Run without a display.** It is a desktop tool. The operations are tested
  through `tests/test_pkiops.c` and the command-line tools; the window itself
  by `make gui-smoke` (`tests/gui_smoke.sh`), which starts it under a virtual
  display, closes it with `app.quit` — the action behind Ctrl+Q — and fails on
  any GTK or GLib CRITICAL or WARNING. CI runs it in the `gui-smoke` job.
