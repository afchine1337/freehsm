<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Acknowledgements

FreeHSM is maintained by one person. Most of what has been fixed since v1.4.0
was found by people outside the project, and several of those things could not
have been found inside it: a distribution's compiler flags, a documented step
requiring a tool the maintainer does not have, a release tarball rather than a
checkout, the first fifteen minutes of a stranger's evening.

This file records who found what. It is not a courtesy list — the entries name
specific defects, because a vague thank-you is worth less than an accurate one.

---

## Denis Mingulov — [`pkcs11-check`](https://github.com/mingulov/pkcs11-check)

The largest external contribution to this project is a tool its author did not
write for us. `pkcs11-check` is a vendor-neutral behavioural harness of some
100 000 PKCS#11 assertions; running it against FreeHSM opened at **517 failures
and 7 crashes** on 2026-07-10 and drove the entire #125 campaign — SIGSEGV
guards, operation-state hygiene, session-object lifecycle, private-object access
control, mechanism advertisement, attribute coverage. `docs/PKCS11_CHECK_FINDINGS.md`
is a hundred pages long because of it.

Three findings went back the other way: a padding-oracle probe that fails one
run in three for statistical reasons, an output-length probe whose success
condition could never be met, and a `BufferError` at a typed `ctypes` boundary.
The v0.1.9 error-attribution fix closed three FreeHSM "failures" that were never
FreeHSM's.

## Simon Josefsson (`jas4711`)

Preparing Debian packages, and reporting what that exposed:

* **#7** — the build fails under his compiler on
  `snprintf(cipher_name, sizeof cipher_name, "AES-%zu-GCM", key_len * 8)`. The
  fix replaced both call sites with a lookup table and closed what the format
  string hid: neither caller validated `key_len`, so a 7-byte key produced
  `"AES-56-GCM"` and failed three layers down instead of answering
  `CKR_KEY_SIZE_RANGE`.
* **PR #9** — `LOCAL_CFLAGS` / `LOCAL_LDFLAGS`, appended after the project's own
  groups so a packager can add a distribution's hardening without being able to
  drop ours. Merged in v2.0.2, and it is what lets CI build under
  `dpkg-buildflags` instead of guessing.
* **#1** — "Normally PKCS#11 modules are usable as any user." They are, and this
  one is; AGD_PRE said otherwise by implication for months.
* **#2** — 32-bit build failures, which turned out to be correct rejections of
  code that is 64-bit by construction. Now documented as unsupported instead of
  discovered by a build.
* **#8** — an ELF binary committed to git. Already removed eleven days before he
  filed it, and nobody had told him.

## Petr (`petrn`)

Followed `AGD_PRE.md` as written, on a clean machine, repeatedly:

* **#4** — `make dist-verify` could not run. Four defects stacked behind one
  another; he found three of them, one per round trip, over two weeks. He then
  produced the **first independent verification of the reproducibility claim**
  (`docs/REPRODUCIBLE_BUILD.md` §8) — the row §7 has asked an evaluator for
  since the document was written, and which nobody, including the maintainer,
  had ever produced.
* **#5** — five failures in `tests/full_crypto_pkcs11.sh`. Four were real and
  are fixed; the fifth was an assertion that could never pass, comparing a raw
  `r‖s` signature against what OpenSSL wants in DER. He then isolated a
  genuine defect across three days and seven test cycles — RSA-2048 keygen
  failing through the module on OpenSSL 3.5.6 — with a clean single-variable
  attribution that none of the maintainer's four hypotheses achieved.
* **#6** — three Wycheproof RSA-PSS violations on v1.5.0.

## `fencepost-error`

**#3** — tried FreeHSM with their own PKCS#11 test code, hit
`C_Initialize` returning `0x80000002`, read the source, and correctly diagnosed
an unsigned module. They were right: **v1.4.0 was published without its
integrity digest** (`SECURITY.md`). The report also noted that an empty slot
before provisioning reads as a fault, which it does, and which the guide did not
say. Both are fixed in v2.0.2.

The workaround they found — `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` — starts the
module by turning its integrity check off. That a broken release pushed a user
to disable a security control is the most useful single thing anyone has told
this project.

---

## How this project treats reports

Learned the hard way, in the week of 2026-09-01, when three of eight open
issues turned out to be already fixed with nobody told, one had gone ten weeks
unanswered, and one was closed on a reporter while he was still testing.

* An issue closes when a **released** version carries the fix and the **reporter
  says so** — not when a commit does.
* When a release carries someone's fix, they are told, by name, in the issue.
* A fix that cannot be verified locally says so in the commit message, and is
  not claimed as verified.
* Reports are answered even when the answer is "already fixed, and we should
  have told you".
