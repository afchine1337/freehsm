<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.3.1

A maintenance release for two defects: multipart digest worked for three of
the eleven digests the module accepts, and a key's value was given in clear
when the key was not extractable.

**Upgrade if an application hashes in parts** — `C_DigestInit`, then
`C_DigestUpdate` more than once — with SHA-224, SHA-512/224, SHA-512/256 or
any SHA-3 digest, or in `all-mechanisms` builds with SHA-1 or MD5. One-shot
`C_Digest` was never affected, and neither was multipart SHA-256, SHA-384 or
SHA-512.

**Check your templates if an application reads back a key it imported or
derived as non-sensitive.** Such a key now needs `CKA_EXTRACTABLE=TRUE` as
well for its value to be given; without it, the read answers
`CKR_ATTRIBUTE_SENSITIVE`. Keys generated on the token are sensitive by
default and are not affected.

There is no security advisory in this release.

---

## Multipart digest

### What was wrong

`C_DigestInit` accepts eleven digests. `C_DigestUpdate` and `C_DigestKey`
looked the OpenSSL digest up in a table of their own that held three. For
the other eight, the first Update answered `CKR_MECHANISM_INVALID`: an
application got a refusal, never a wrong digest.

The refusal then left the operation active, although PKCS#11 says an error in
`C_DigestUpdate` ends it, so the application's next `C_DigestInit` on that
session answered `CKR_OPERATION_ACTIVE` as well.

Behind that sat a third defect, which could give a wrong digest. When an
Update failed after an earlier Update had succeeded — a NULL buffer with a
non-zero length, or a length past 2 GiB — the operation ended but kept its
OpenSSL context. The next digest on the same session hashed into it: the
earlier data, under the earlier algorithm, returned with `CKR_OK`. It needed
a malformed call from the application first, and it stayed within that
application's own session.

### What changed

`C_DigestUpdate` and `C_DigestKey` use the table `C_DigestInit` checks
availability against, so the three can no longer disagree. Any error in
`C_DigestUpdate` ends the operation and releases its context, and
`C_DigestInit` releases a context left by an earlier operation.

### How it was found

pkcs11-check's `TestMultipartDigest` reported the `CKR_OPERATION_ACTIVE`
cases under both 0.2.1 and 0.2.3. They alternated with refused digests and
were first read as one test's session state reaching the next — the
harness question settled in mingulov/pkcs11-check#38. Confirming #38 against
the reports, before saying so upstream, meant reading each remaining case;
the skip reasons side by side showed the module refusing eight digests.

## A key's value

### What was wrong

PKCS#11 v3.2 does not reveal a private or secret key's `CKA_VALUE` when the
key is sensitive or when it is not extractable — the attribute tables'
footnote 7 — and `C_GetAttributeValue` then returns
`CKR_ATTRIBUTE_SENSITIVE`. The module checked `CKA_SENSITIVE` alone.

So a key derived or imported with `CKA_SENSITIVE=FALSE`, and nothing said
about `CKA_EXTRACTABLE`, whose default here is FALSE, gave its value to
`C_GetAttributeValue`, though `C_WrapKey` refused to let it out wrapped. Only
a session that could already see the key could ask, and only for a key whose
creator had declared it non-sensitive.

Where it did withhold a value, it returned `CKR_OK` with
`CK_UNAVAILABLE_INFORMATION` in the length: nothing was disclosed, but a
caller checking only the return code took the marker for a length.

Correcting that exposed a third defect, in `C_CreateObject`, which read
neither attribute from the template. A secret key was imported neither
sensitive nor extractable, whatever was asked: one imported with
`CKA_SENSITIVE=TRUE` kept a readable value, and one imported with
`CKA_EXTRACTABLE=TRUE` could not be wrapped. A private key was imported
sensitive and never extractable.

### What changed

A private or secret key's value is withheld when the key is sensitive or not
extractable, and the call returns `CKR_ATTRIBUTE_SENSITIVE`; other attributes
asked in the same call are still given. Public keys and certificates are
unchanged.

`C_CreateObject` keeps `CKA_SENSITIVE` and `CKA_EXTRACTABLE` as the template
states them. A private key stays sensitive whatever is asked, as before, and
both still default to FALSE.

### How it was found

On the `fhsm-crypt` branch, the first test in this tree to ask for a secret
key's value and check the return code.

## Measured

`tests/test_digest_multipart.c`, new: for every digest the build accepts,
multipart equals one-shot; an Update error ends the operation; and the next
operation carries nothing of the failed one. pkcs11-check 0.2.3, every
`TestMultipartDigest` and `TestMultiPartDigest` test against the signed
default-profile module: 30 passed, 0 xfail, where 0.2.3 had recorded sixteen
xfails on v2.3.0 — eight refusals and eight `CKR_OPERATION_ACTIVE` that
followed them.

`tests/test_sensitive_value.c`, new: a generated key's value is refused for
the size query and the read, with nothing written; an imported non-sensitive
key gives its value only when extractable; a value asked beside `CKA_LABEL`
leaves the label given; a public key's value is still given; an imported
key's `CKA_SENSITIVE` and `CKA_EXTRACTABLE` read back as the template set
them, and sensitive wins over extractable.

The static-analysis CI job is green again. `make lint` had flagged two
redundant assignments in the certificate builder since 2026-10-05; they are
removed, with no change in behaviour.

## Credits

The harness is Denis Mingulov's `pkcs11-check`.

## Verifying this release

    scripts/release.sh 2.3.1
