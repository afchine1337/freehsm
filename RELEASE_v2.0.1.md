<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.0.1

A maintenance release one day after v2.0.0, and it exists because of three
people outside the project — a Debian maintainer, an operator following the
guide, and someone trying the module against their own test code.

**If you have v2.0.0, upgrade.** Not for the module — its cryptography is
unchanged — but because the test script v2.0.0 ships contains an assertion that
cannot pass, and anyone running it will conclude FreeHSM produces invalid ECDSA
signatures. It does not.

---

## Read this if you ran v2.0.0's test suite

`tests/full_crypto_pkcs11.sh` fed the raw `r‖s` signature that PKCS#11 returns
straight to `openssl pkeyutl -verify`, which expects DER
`SEQUENCE { INTEGER r, INTEGER s }`. Measured on one signature, both encodings:

    raw 64 bytes  ->  Signature Verification Failure
    DER 72 bytes  ->  Signature Verified Successfully

The assertion would have failed against any conforming PKCS#11 module,
including hardware. It was reported to us as a module defect and carried for six
weeks. RSA hid it: a PKCS#1 v1.5 signature is a bare octet string, so the RSA
case passed unconverted and made the failure look specific to the curve.

Two more defects in the same script, both invisible to anyone who had followed
`AGD_PRE`:

* **`FHSM_TOKENS_DIR` never reached the module.** Every call runs through
  `sudo -u freehsm`, and sudo scrubs the environment. The suite therefore ran
  against the compile-time default `/var/lib/freehsm/tokens` while printing
  `tokens_dir : /tmp/freehsm-full-XXXXXX` — a directory the module never
  opened, and never cleaned. On a machine where that default is root-owned, all
  twenty assertions fail at `C_Initialize`.
* **The `chown` meant to make the temporary directory usable** sent its error to
  `/dev/null` and had its exit status eaten by `|| true`.

## The module now says why it refuses to start

`C_Initialize` latched into ERROR and returned when the OpenSSL FIPS provider
would not load, printing nothing — while the two failures either side of it in
the same sequence, the audit key and the tokens directory, each name themselves
and say what to check. Forty minutes of diagnosis on a host whose
`fipsmodule.cnf` still held the MAC of the pre-upgrade `fips.so`; OpenSSL knew
exactly that and had put it on an error stack nobody printed.

Both provider branches now write to `stderr`, name `OPENSSL_CONF` as it stands,
point at AGD_PRE 3.3.1, and print OpenSSL's error stack.

**New vendor return code: `FHSM_RV_PROVIDER_UNAVAILABLE (0x80000009)`**,
returned from `C_Initialize` only. It replaces the generic
`CKR_FUNCTION_FAILED` on that path. The first attempt reused
`FHSM_RV_FIPS_NOT_APPROVED (0x80000003)`, which `AGD_OPE` documents as *"switch
to an approved mechanism"* — advice with no meaning when the module will not
initialise at all.

## Two behaviour changes worth knowing

* **AES-CMAC and GMAC reject unsupported key lengths** with
  `CKR_KEY_SIZE_RANGE` at the point the length is wrong. Previously a 7-byte key
  produced the cipher name `"AES-56-GCM"` and failed several layers down inside
  OpenSSL. Found because a Debian maintainer could not compile the `snprintf`
  that built that string.
* **`LOCAL_CFLAGS` / `LOCAL_LDFLAGS`** are honoured by the Makefile, appended
  after the project's own groups (PR #9, jas4711). A packager can raise `-O1`
  to `-O2` or add a distribution's hardening; nobody can silently drop
  `-Werror`, `-fstack-protector-strong` or the `-z relro,now,noexecstack`
  bundle. They do not reach the reproducible build.

## `make dist-verify` has never worked, and now might

`Dockerfile.build` mounted the source at `/src:ro` — deliberately, since a build
that measures a tree must not modify it — and its entrypoint ran
`cd /src && make clean`. `make clean` writes. The step `AGD_PRE` documents could
not complete for as long as the read-only mount has existed, and the first
person to run it found that out.

This also completes an explanation given too confidently two days ago:
`dist/refs/` was empty through six releases for **two** independent reasons, not
one. The reference file could not be committed (a `.gitignore` rule), *and* the
path meant to produce it could not run. Either alone would have been enough.

Fixed by building in a writable copy. The image tag moves
`freehsm-build:1.0.0` → `1.1.0`, because the script builds the image only when
absent and a cached one would have kept the old entrypoint.

**Not verified end to end.** That path needs Docker, which the maintainer's
machine does not have — the same absence that let it stand for nine months.

## Security note: v1.4.0 was published unsigned

Not a defect in this release, disclosed with it. `.fhsm_digest` in the published
v1.4.0 artefact is all zeros; v1.5.0 and v1.6.0 carry real digests. The release
workflow ran `make integrity || echo "WARN…"`, so a failed signing step wrote a
warning into a green log and published anyway. Every download of v1.4.0 returned
`FHSM_RV_INTEGRITY_FAILED (0x80000002)` from `C_Initialize`.

It fails closed, so an unsigned module is unusable rather than silently trusted.
What makes it worth a security section is the workaround two independent
reporters found on the same day: `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` starts the
module by **turning the integrity check off**. A broken release drove users to
disable a control in order to evaluate the product.

The cause was removed in v2.0.0 and described there as a hypothetical. It had
already happened, in two issues open at the time. Full account in `SECURITY.md`;
the v1.4.0 release page now carries a warning.

## Also

* **32-bit is unsupported and now says so.** `src/fhsm_integrity.c` reads
  `Elf64_*` unconditionally to locate `.fhsm_digest`, so the `-Wconversion`
  failures on i386 are correct rejections rather than sloppy casts. AGD_PRE's
  environment table states 64-bit only (x86_64 or aarch64).
* **AGD_PRE 3.3.1** — regenerate `fipsmodule.cnf` after every OpenSSL upgrade;
  `fipsinstall` must run under `sudo env OPENSSL_CONF=/dev/null` because it
  loads the module through the configuration it is meant to repair; and there
  must be exactly one `.include`.
* **`pkcs11-check` pinned to `0.1.9`** in both workflows. Unpinned, the harness
  measuring FreeHSM changed whenever PyPI did — and did: three findings closed
  between 0.1.8 and 0.1.9 with the module untouched, including one this project
  had recorded as *observed, not diagnosed*.
* **The module is unchanged cryptographically.** No mechanism, format or wire
  behaviour differs from v2.0.0 beyond the two rejections listed above.

## Verifying this release

    scripts/release.sh 2.0.1

The pre-flight refuses to declare the tree ready without a reproducibility
reference at `dist/refs/v2.0.1.sha256`, and the release workflow refuses to
publish a build that does not match it — or to publish at all without these
notes, which is itself new since v2.0.0 shipped without its strongest warning.
