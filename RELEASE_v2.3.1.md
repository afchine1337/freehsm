<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.3.1

A maintenance release for one defect: multipart digest worked for three of
the eleven digests the module accepts.

**Upgrade if an application hashes in parts** — `C_DigestInit`, then
`C_DigestUpdate` more than once — with SHA-224, SHA-512/224, SHA-512/256 or
any SHA-3 digest, or in `all-mechanisms` builds with SHA-1 or MD5. One-shot
`C_Digest` was never affected, and neither was multipart SHA-256, SHA-384 or
SHA-512.

There is no security advisory in this release.

---

## What was wrong

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

## What changed

`C_DigestUpdate` and `C_DigestKey` use the table `C_DigestInit` checks
availability against, so the three can no longer disagree. Any error in
`C_DigestUpdate` ends the operation and releases its context, and
`C_DigestInit` releases a context left by an earlier operation.

## Measured

`tests/test_digest_multipart.c`, new: for every digest the build accepts,
multipart equals one-shot; an Update error ends the operation; and the next
operation carries nothing of the failed one. pkcs11-check 0.2.3, every
`TestMultipartDigest` and `TestMultiPartDigest` test against the signed
default-profile module: 30 passed, 0 xfail, where 0.2.3 had recorded sixteen
xfails on v2.3.0 — eight refusals and eight `CKR_OPERATION_ACTIVE` that
followed them.

The static-analysis CI job is green again. `make lint` had flagged two
redundant assignments in the certificate builder since 2026-10-05; they are
removed, with no change in behaviour.

## How it was found

pkcs11-check's `TestMultipartDigest` reported the `CKR_OPERATION_ACTIVE`
cases under both 0.2.1 and 0.2.3. They alternated with refused digests and
were first read as one test's session state reaching the next — the
harness question settled in mingulov/pkcs11-check#38. Confirming #38 against
the reports, before saying so upstream, meant reading each remaining case;
the skip reasons side by side showed the module refusing eight digests.

## Credits

The harness is Denis Mingulov's `pkcs11-check`.

## Verifying this release

    scripts/release.sh 2.3.1
