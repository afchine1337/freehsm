<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.5.1

A security release. A wrong PIN could re-encrypt the token's objects under a
key of zero bytes, or remove them from the token file; `C_InitToken`
re-initialized an existing token without its SO PIN; and after one wrong PIN
a command-line client could no longer log in with the right one. All three
are fixed, nothing is added.

**Upgrade.** The first two reach every published release since v1.1.0. The
upgrade is a drop-in replacement of the module; token files are read as
they are.

**Log in once after upgrading.** A token whose objects were re-encrypted
under the zero key is repaired at its next correct login. Copies of the
token file taken while it was in that state are not: `SECURITY.md` says
what to do about them.

Two security advisories accompany this release; `SECURITY.md` has both.

---

## A wrong PIN and the object store

### What was wrong

Each PIN attempt writes the token file, to persist the failure counter.
That write re-encrypted the object store when the DEK buffer existed and the
objects were loaded, and left the store out of the file otherwise. A wrong
PIN clears the DEK buffer but keeps it allocated.

So in a process that had already logged in -- a service that logs out and
back in, `p11-kit server` -- a wrong PIN re-encrypted the store under 32
zero bytes: the private and secret keys in the file then opened with a key
anyone has. And as the first attempt of a process -- `pkcs11-tool --login`
with a typing mistake -- the objects were not loaded yet, and the file was
rewritten without them: the token kept its PINs and lost its objects.

### What changed

The store is re-encrypted only while the DEK is known and the objects are
loaded; otherwise the encrypted store already on disk is copied unchanged.
Changing an object after a logout answers `CKR_USER_NOT_LOGGED_IN`, as it
did before the first login.

A store found under the zero key is decrypted at the next correct login and
re-encrypted under the token's DEK straight away. A store already removed
cannot be recovered from the token file; a backup taken before holds it.

`C_InitToken` on an initialized token also kept the objects it had loaded
in memory and wrote them into the new token at the next write. The store is
now emptied first.

### How it was found

Designing `C_FindObjectsInit` for public objects before login meant reading
how the store decides it may write. Its test for "the DEK is known" was
whether the buffer existed, not whether it held the key.

## `C_InitToken` and the SO PIN

PKCS#11 checks `pPin` against the current SO PIN when the token is already
initialized. FreeHSM did not: any PIN re-initialized the token and destroyed
its objects, without disclosing any. The SO PIN is now verified first, with
the failure counter and throttle of `C_Login`.

## After one wrong PIN

Since v2.0.0 the delay a failed attempt earns is re-imposed whenever the
token is loaded, so that restarting is not a way around it. A command-line
client loads the token and presents the PIN a few milliseconds later; it
met the delay every time, and the correct PIN came back
`FHSM_RV_PIN_THROTTLED` (`0x80000004`) in every new process.

A PIN attempt inside the delay -- `C_Login`, `C_InitToken`, the
`CKU_CONTEXT_SPECIFIC` re-authentication -- now waits until it has passed
(500 ms after one failure, doubling, 60 s at most), then examines the PIN.
One attempt per delay, as before, and a restart still does not skip it.
`C_InitToken` holds the module's exclusive lock while it waits.

## Measured

`tests/test_wrong_pin_store.c`, new: a wrong PIN after a logout, and as the
first attempt of a process, leaves a store that does not open under the
zero key and still holds the key with the correct PIN; a change after a
logout is refused; a re-initialized token holds no object. Three failures
on v2.5.0.

`tests/integration_pkcs11.sh`, through `pkcs11-tool`: the correct user PIN
in a new process after a wrong one; `C_InitToken` refused with a wrong SO
PIN, then accepted with the right one in a new process. 20 of 20; the
expectations it held on the module's identity strings, stale since they
changed, are updated.

`make tests` in `nist-approved-only`, green. The release commit is measured
by CI in both profiles.

## Verifying this release

    scripts/release.sh 2.5.1
