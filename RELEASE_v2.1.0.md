<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.1.0

This release exists because someone pointed out that a command had never been
run.

`pkcs11-check` ships its harness and downloads the third-party vector sets
separately, with `pkcs11-check fetch-data`. Neither our script nor either CI
workflow ever called it. Every measurement this project has published since
July — the 517 failures of the first run, the 7,392 Wycheproof assertions, the
"zero crashes" of last week — was made against **4,014 vectors**. The corpus is
**111,739**.

petrn noticed the discrepancy from the other side: he was reporting 35 failures
and 3 crashes against v2.0.2 while we were reporting 2 and 0, and he asked, in
issue #10, what result to expect. The difference was not the module.

With the data present, the first run found four defects and one crash that no
previous run could reach.

---

## A stack buffer overflow in `C_UnwrapKey`

[GHSA-833h-crp9-f378](https://github.com/afchine1337/freehsm/security/advisories/GHSA-833h-crp9-f378)
· High · CWE-121 · affects every release through v2.0.3.

The function decrypted the wrapped blob into `uint8_t pt[256]` on the stack.
`EVP_DecryptUpdate` takes no output-capacity argument — the caller guarantees
the buffer — and `ulWrappedKeyLen` was never checked against it. AES-KW yields
`ulWrappedKeyLen - 8` bytes, so any blob over 264 bytes wrote past the end:

    *** stack smashing detected ***: terminated
    Aborted            (exit 134)

The canary caught it, which is why it appeared as an abort rather than as
corruption, and why the honest description in our binaries is denial of service
and not code execution. `_FORTIFY_SOURCE` and `-fstack-protector` are
compile-time choices rather than properties of the code, and issue #7
established that distributions do not all apply the same flags. A build without
them takes the write instead — on a blob that, by the very purpose of key
wrapping, arrives from somewhere else.

The same missing bound had a second symptom: nine Wycheproof vectors with
**forged blobs accepted**, producing key objects from data that should have been
refused. One defect, two faces.

A third thing surfaced beside it. `C_WrapKey` validates the wrapping-key size,
with a comment saying a bad size must not "silently fall through to the 256-bit
cipher name". `C_UnwrapKey` did exactly that — a 20-byte key selected
`AES-256-WRAP`. The fix had been applied to one of the two paths that reach the
same state.

`tests/test_unwrap_len.c` covers both directions, and exits 134 if the bound is
removed. The write-up is in `SECURITY.md`.

## RSA-PSS ignored the mask generation function you asked for

`op->pss_mgf` appeared three times in the entire tree: its declaration, its
reset, its assignment. Never once on the right-hand side of anything.

So OpenSSL applied its own default — MGF1 over the signature hash — and a caller
asking for SHA-256 with MGF1-SHA1, which PKCS#11 v3.2 permits and which
certificates in the wild use, had its signatures verified against the wrong mask
and **refused**. 267 Wycheproof vectors, every one of them a valid signature.

The OAEP path, two thousand lines away, has always called
`EVP_PKEY_CTX_set_rsa_mgf1_md`. One branch handled the parameter and the other
dropped it.

Four call sites of three inline calls each are now one helper. It returns a
status, so an unknown MGF is refused rather than ignored — ignoring it is the
fault being repaired. One of those four had been discarding the return value of
all three calls, so a parameter OpenSSL rejected became a verification against
whatever the context already held.

## Public keys were imported without being checked

`EVP_PKEY_fromdata` builds a key from the caller's bytes and does not verify
that the result is a point on the curve. For Ed25519 and Ed448 any string of the
right length was accepted; for EC, any coordinates. Nothing downstream
re-checks, so a key that entered the token was treated as valid by every
operation after it.

`EVP_PKEY_public_check` now runs at import on both paths.

The two did not land together, on purpose. The Ed fix went in with a comment
saying the EC branch was deliberately untouched: nothing measured said it was
wrong, and adding a check to a path carrying 15,057 passing ECDSA vectors on the
strength of symmetry is a good way to trade four failures for many more. It was
measured the next morning — no valid key is refused — and only then applied.

## AES key wrap had half a mechanism

PKCS#11 v3.2 §6.16.3:

> The mechanisms support only single-part operations, i.e. single part wrapping
> and unwrapping, **and single-part encryption and decryption**.

Only the wrapping half existed. The module was entirely self-consistent about
it — the dispatch table said `wrap`, `C_GetMechanismInfo` reported
`CKF_WRAP|CKF_UNWRAP_MECH`, `C_EncryptInit` returned `CKR_MECHANISM_INVALID` —
and consistently short of the specification.

The obstacle was in the model, not in a line of code: the generated table
carried **one** operation string per mechanism and could not express a mechanism
belonging to two families. It now accepts several, joined by `+`.

The consequence was concrete. NIST publishes ACVP AES-KW and AES-KWP vectors at
the byte level, and they drive `C_Encrypt` rather than `C_WrapKey`, because they
carry raw data and not key objects. **None of them could run against this
module.** They now do: 7,219 of 7,231, one hundred percent — a body of official
validation vectors this project could not reach at all, on a module that has
spent months demonstrating that its own KATs are self-consistent.

This is what makes the release 2.1.0 rather than 2.0.4: `C_GetMechanismInfo`
reports flags it did not report before, which is a capability added rather than
a defect repaired.

## Valid keys longer than 256 bytes are unwrapped again

Visible only once the overflow stopped hiding it: `tc10`, `tc52` and `tc107` are
**valid** vectors whose plaintext exceeds the old buffer. They used to abort the
process; bounding the length turned that into a clean refusal, which was better
and still wrong. The buffer is now 4 KiB and they are unwrapped.

## What this release does not do

**The optional IV parameter of §6.16.2** — 8 bytes for KW, 4 for KWP, or NULL
for the SP 800-38F default — is honoured on neither the new encrypt path nor the
wrap path, which has always passed NULL. A caller who supplies one is silently
given the default either way. Issue #14 stays open for it.

**The unwrap buffer is still on the stack, and still not zeroised.** Key
material belongs in `fhsm_secure_malloc`, which exists and is used elsewhere.
`C_UnwrapKey` has 28 return statements, about twenty of them after the buffer is
declared, and one missed path would leak plaintext key material — a worse defect
than the one repaired here. Both that and the zeroisation want the function
restructured around a single exit, which is not a change to make in the same
week as six others.

**`CKM_AES_KEY_WRAP_PKCS7`** remains unimplemented. `CKM_AES_KEY_WRAP_PAD`
remains unimplemented on purpose — the specification deprecates it in favour of
the other two.

## Also

* The bypass notice named neither its cause nor its remedy, and said "this
  build is not FIPS-conformant" where it meant "this run". It now names
  `FHSM_INTEGRITY_ALLOW_UNSIGNED`, says the binary is unchanged, and points at
  `FHSM_EVIDENCE=1`. Reported by petrn, who had configured OpenSSL correctly and
  was told otherwise by our own harness.
* The Wycheproof harness hard-coded `/tmp/freehsm-wycheproof` at mode 0700, so
  the first user to run it locked out every other user on the machine. Now a
  per-run directory, removed on exit. Also his.
* Every pkcs11-check run writes `provenance.txt`: harness version, OpenSSL
  version, module path and module SHA-256. A report that cannot state its own
  environment cannot be compared with another one later, and this cost an hour
  on 2026-09-07.
* The conformance report is generated on every run. The project had never
  produced it, which is why the four defects above were visible to petrn and not
  to us.

## Credits

Reported, diagnosed, or made possible by **petrn**: the `fetch-data` remark that
uncovered everything here, the bypass notice, the token directory, and the
analysis of the AES-KW encrypt path in issue #14. The harness itself is Denis
Mingulov's `pkcs11-check`.

`ACKNOWLEDGEMENTS.md` records who found what.

## Verifying this release

    scripts/release.sh 2.1.0
