<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.6.0

Public objects before a login, and three attributes that can be changed.

A session that is not logged in now finds the token's public keys and
certificates and reads their attributes, as PKCS#11 provides; until now
`C_FindObjectsInit` answered `CKR_USER_NOT_LOGGED_IN`. `CKA_START_DATE`,
`CKA_END_DATE` and a data object's `CKA_APPLICATION` can be set after
creation. `C_InitToken` refuses to re-initialize a token while a session is
open on it.

**Check your error handling if an application re-initializes a token.**
`C_InitToken` with a session open on the slot was carried out and is now
`CKR_SESSION_EXISTS`. Close the sessions first.

Two low-severity fixes ride along: the unwrap buffer is cleared on every
exit (#27), and a public key's `CKA_ALLOWED_MECHANISMS` holds again after a
`C_Logout`, which 2.5.1 had broken.

There is no security advisory in this release.

---

## Public objects before a login

### What was wrong

Every object lived in the token file's encrypted blob, which only a login
can decrypt. Before a login the store was empty, and a search answered
`CKR_USER_NOT_LOGGED_IN` where PKCS#11 expects the public objects.

### What changed

The token file carries a public section after the blob: the public keys and
certificates, in clear, read when the token is loaded. Secret and private
keys, and anything flagged sensitive, stay in the blob only, and the reader
refuses a section holding anything else.

The blob remains the store. A login replaces the view with it; the view
itself cannot be changed; the section is written only by the write that
re-encrypts the blob, from the same store, and copied as it is by every
other write. A token with no public object carries an empty section, so
that a search before login finds nothing rather than refusing.

The section is not authenticated: before a login there is no key to do it
with. Whoever can write the token file could put objects in it, and could
equally replace the whole file. `docs/TOKEN_STORE_FORMAT.md`, "The public
section", has the format and the reasoning.

### Upgrading and downgrading

A token file written by an earlier version has no section. Before its first
login on 2.6.0 it answers as before, `CKR_USER_NOT_LOGGED_IN`; the login's
write adds the section. An earlier version reading a 2.6.0 file reads the
blob by its own length and ignores what follows, and drops the section at
its next write.

## Attributes that can be changed

`CKA_START_DATE` and `CKA_END_DATE` were stored and accepted at creation,
but `C_SetAttributeValue` answered `CKR_ATTRIBUTE_TYPE_INVALID`. They can now
be changed on keys and certificates, checked for shape as at creation and
cleared by an empty value. A data object's `CKA_APPLICATION` likewise, up to
64 bytes. The dates remain informational, as PKCS#11 says: stored, never
enforced.

## `C_InitToken` with a session open

PKCS#11 answers `CKR_SESSION_EXISTS`. The module re-initialized the token,
destroying its objects and resetting both PINs, under sessions that went on
holding handles and a login state that no longer existed. The refusal comes
before the SO PIN is examined, so it costs no attempt.

## Fixes

**The unwrap buffer (#27).** Three checks in `C_UnwrapKey` after a
successful decrypt -- a key type that does not fit the key's length, a
`CKA_VALUE_LEN` that does not match -- returned with the unwrapped key still
in a 4 KiB stack buffer. Every exit after the decrypt now goes through one
place that clears it. Reading the residue needed a separate memory
disclosure, a core dump or swap; the caller could already unwrap the blob.
Reported by AlexLaroche, with a harness that showed the bytes on the stack;
it shows none on 2.6.0.

**`CKA_ALLOWED_MECHANISMS` after a logout.** 2.5.1 made the store's
functions ask whether the DEK is live rather than whether its buffer exists.
Four of them only read -- the mechanism check and the three policy getters
-- and after a `C_Logout` the check answered "permitted" for any object. A
public key, the only kind a session that is not logged in can use, was then
usable with mechanisms its list excluded. Reading needs the store, not the
DEK, and now asks for that. 2.5.1 only.

## Measured

`make tests` in both profiles, green. New: `tests/test_public_objects.c`
(17), `tests/test_set_dates.c` (15), `tests/test_init_token_session.c` (5).

pkcs11-check 0.2.3 in CI, signed module: 5 011 tests and 2 failures in
`nist-approved-only`, 5 142 and 3 in `all-mechanisms`, all of them listed in
`tests/pkcs11_check_known_failures.txt`. The release commit is measured
again by CI.

That gate was red on the 2.5.1 commits, for a reason outside the module:
pytest 9.2.0, published on 2026-10-27, dropped an attribute that
pytest-benchmark reads, and the eight benchmark tests errored at setup
before reaching the module. No other test failed. The workflow now holds
pytest below 9.2.

## Credits

AlexLaroche reported #27 and wrote the harness that confirmed it and its
fix. The harness is Denis Mingulov's `pkcs11-check`.

## Verifying this release

    scripts/release.sh 2.6.0
