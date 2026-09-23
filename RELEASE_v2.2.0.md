<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.2.0

This release exists because a defect that refused too much was hiding a defect
that wrote too far.

`C_DecryptUpdate` rejected output buffers it should have accepted. Nothing was
ever overrun there and nothing crashed; the only visible effect was that
`pkcs11-check`'s probe gave up at its setup step. Behind that refusal sat
`C_DecryptFinal`, which had no output-size check at all and wrote up to fifteen
bytes past whatever the caller had declared — in every published release since
v1.1.0, through four full-corpus runs.

Correcting the refusal exposed the write within the hour.

**If you use multipart AES-CBC-PAD decryption, upgrade.** The security fix
touches two functions and is independent of everything else here.

---

## An out-of-bounds write in `C_DecryptFinal`

High · CWE-787 · affects every release from v1.1.0 through v2.1.0.

The function called `EVP_DecryptFinal_ex` straight into the caller's buffer and
reported the length afterwards:

```c
int out_len = 0;
int ok = EVP_DecryptFinal_ex(op->cipher_ctx, pLast, &out_len);
*pulLastLen = (CK_ULONG)out_len;
```

For `CKM_AES_CBC_PAD` the held-back block yields 0 to 15 bytes once padding is
removed, and all of them were written.

The part that makes this worse than an ordinary missing bound is the size
query. PKCS#11 §5.2 has the caller ask for the required length with a NULL
buffer, allocate, and call again. This function answered **`0`**. An
application following the pattern the specification prescribes allocated
nothing, called again, and had fifteen bytes written into it. An application
that guessed a generous buffer was safe.

It is also quieter than [GHSA-833h-crp9-f378](https://github.com/afchine1337/freehsm/security/advisories/GHSA-833h-crp9-f378),
last release's overflow. That one wrote past a stack buffer *inside* the
module, where `_FORTIFY_SOURCE` and the stack protector turned it into an
abort. This one writes into the **caller's** buffer — the module knows neither
its size nor where it lives, commonly the heap — so no compile-time protection
in our build sees it. Nothing aborts and nothing is logged.

The size query now answers the real bound, an undersized buffer is refused with
a length the caller can retry with, and the operation keeps its held-back block
for that retry. When the padding does not verify, the answer comes from a copy
of the cipher context rather than from calling the real `Final` with an
undersized buffer and trusting it not to write on failure.

Full write-up in `SECURITY.md`.

## The refusal that was standing in front of it

`C_DecryptUpdate` measured the caller's buffer against `ulEncLen` plus one
block. That is `C_EncryptUpdate`'s bound, and there it is real — a block cipher
fed 64 bytes with 12 already buffered emits 64 + 16. Decryption cannot reach
it: each ciphertext block yields one plaintext block, and padding only removes
bytes. So decrypting 64 bytes of AES-CBC-PAD answered "retry with 80", more
than the ciphertext itself, and no caller could act on that.

The length now comes from EVP, asked on a *copy* of the cipher context. It has
to be a copy: the answer decides whether to return `CKR_BUFFER_TOO_SMALL`,
after which §5.2 keeps the operation alive so the caller can retry with the
same ciphertext — a module that consumed it while measuring would decrypt those
bytes twice.

This is the third time in this release that the same shape appears: measuring
the caller's buffer against an upper bound instead of against what is actually
produced. `C_Decrypt` did it with RSA-OAEP, comparing a 37-byte buffer against
the 256-byte key size for a 29-byte plaintext. `C_SignFinal` would have done it
too.

## Multipart signing and verification, for the asymmetric mechanisms

`C_SignInit` accepts every signature mechanism, because `C_Sign` needs it to.
`C_SignUpdate` and `C_SignFinal` implemented HMAC and the composite mechanism
only, so `CKM_SHA256_RSA_PKCS` was accepted at Init and refused at Final with
`CKR_MECHANISM_INVALID`. Advertised, not operational. The same on the verify
side, where a comment had said so for months.

Both now accumulate the message and hand it to the same one-shot path the
single-call functions use, so the PSS parameters, the post-quantum context
string, the raw-versus-hashed split and the ECDSA DER-to-`r||s` conversion keep
one implementation each.

Streaming through `EVP_DigestSignUpdate` would avoid holding the message, and
was measured rather than assumed: `tests/probe_digestsign_stream.c` asks the
library, and Ed25519, Ed448, ML-DSA and SLH-DSA are one-shot on OpenSSL 3.5 —
by construction for the first two. Streaming would have covered three families
of seven while putting a second copy of those rules on the path that last
release's raw-ECDSA finding already broke once.

So the message is buffered, and the memory that costs is bounded and declared:
**16 MiB**, `CKR_DATA_LEN_RANGE` past it. Multipart exists so a caller need not
hold the message; a module that holds it anyway should say by how much.

## RSA private keys can be imported from their components

`C_CreateObject` accepted `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT` for a public
key and had no path for `CKA_PRIVATE_EXPONENT` and the CRT parameters, so
importing a private key returned `CKR_TEMPLATE_INCOMPLETE`. The key is now
rebuilt through `EVP_PKEY_fromdata`, which checks the components against each
other: a key that cannot sign is refused at import rather than at the first
`C_Sign`.

Multi-prime RSA remains unsupported, and correctly so — PKCS#11 has no
attributes for the additional primes.

## A self-test that read a dead stack frame

`fhsm_kat_result_t.vector_id` is read long after the function that wrote it has
returned: `fhsm_kat_results()` hands the array out, and the module prints the
identifier when a vector fails. Six of the seven recording sites pass a string
literal and satisfy that without anyone stating it. The seventh formatted
`CAVP-SHA256-Len<N>` into a local buffer, so every CAVP record — 57 of the 62
in a normal boot — pointed into a frame that had gone.

The first code to read it is the code that reports a failed self-test.

## Measured

Full corpus, against a **signed** module in the evaluated configuration with
the FIPS provider loaded — the first run made that way:

    55,202 passed · 2 failed · 0 crashed · xfail 14,299

against 54,339 / 11 / 0 / 15,263 on 2026-09-19. The two counts do not compare
directly and `docs/PKCS11_CHECK_FINDINGS.md` says why: every previous full run
went through the integrity bypass, so mechanisms the `fips-strict` profile
refuses became skips rather than failures here.

The two remaining failures are `test_registry_sign_missing_required_param`
`[EDDSA]` and its verify twin, an upstream disagreement in mingulov#23 rather
than a defect here.

`make asan` — AddressSanitizer and UBSan over the whole suite — is new, and
green. It is also the reason several things in this release exist: the first
complete run under it found four defects in an afternoon, in a build that had
been available for months and never taken to the end.

## Why minor and not patch

`C_SignFinal`, `C_VerifyFinal` and `C_CreateObject` each answer a request they
used to refuse. An application can observe that, which under semantic
versioning is a minor release — the same argument that made v2.1.0 minor rather
than a patch.

A security fix travelling in a minor release is an argument for the other
choice, since a patch is taken without deliberation. The security fix here
touches `C_DecryptFinal` and `C_DecryptUpdate` only and depends on nothing else
in this release, which is the honest way to have both.

## What this release does not do

Multipart signing buffers the message rather than streaming it, for the three
families that could stream. `CKM_AES_CMAC` and `CKM_AES_GMAC` remain one-shot
only and are still refused by `C_SignUpdate`. The optional IV parameter of
PKCS#11 §6.16.2 is still not honoured on the AES key-wrap paths (issue #14).
The two advertised hybrid mechanisms are still not operational (issue #17).

No FIPS or Common Criteria certification is held, sought, or planned.

## Credits

The harness is Denis Mingulov's `pkcs11-check`; its
`aes_cbc_pad_decrypt_final_buffer_too_small` probe found the overflow, and its
`test_sign_final_buffer_too_small_then_correct` found the multipart gap.
**petrn** reported the CCM AAD ceiling (#15), now closed, and resolved its
second group himself upstream.

`ACKNOWLEDGEMENTS.md` records who found what.

## Verifying this release

    scripts/release.sh 2.2.0
