<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.0.2

One day after v2.0.1, and for a plain reason: three people outside the project
are debugging FreeHSM against a released binary, and the fixes they need were
on `main`. A fix nobody can download is not a fix — v2.0.1 was closed as
"fixed" for a reporter who was running the release, and he was right to reopen
it.

The module's cryptography is unchanged from v2.0.0. Every mechanism, format and
wire behaviour is the same.

---

## The module now says why it refuses

Five conditions used to return a bare code and nothing else. An operator saw
`CKR_FUNCTION_FAILED` or `0x80000002` and had to read the source to get further
— two users did exactly that in June, and one of them then reached for
`FHSM_INTEGRITY_ALLOW_UNSIGNED`, which starts the module by **turning the
integrity check off**. A control that fails without explaining itself teaches
people to disable it. That is the cost being paid down here.

| condition | now |
|---|---|
| unsigned module | names `make integrity`, and says not to use the bypass on a downloaded binary |
| module altered after signing | says the binary changed since signing, and deliberately does **not** offer the bypass |
| no `.fhsm_digest` section | says it is not a FreeHSM module, with the `readelf` command to confirm |
| FIPS provider will not load | names `OPENSSL_CONF` as it stands, points at AGD_PRE 3.3.1, prints OpenSSL's error stack |
| `C_GenerateKeyPair` failing | prints the mechanism and OpenSSL's error stack |

The three integrity messages read differently on purpose: an unsigned build is
a missing step in your own workflow, a mismatched digest is a binary that
changed after it was signed, and telling someone to bypass the check in the
second case would be the very mistake that produced this release.

**New vendor return code `FHSM_RV_PROVIDER_UNAVAILABLE (0x80000009)`** (v2.0.1),
from `C_Initialize` only, documented in `AGD_OPE.md` in both languages.

## `make dist-verify` can run

The container mounts the source read-only, deliberately, and its entrypoint ran
`make clean` inside that mount — so this step could never complete. Fixed in
v2.0.1 by building in a writable copy; fixed here for the second obstacle
behind it, `/out` not being writable by the container's uid.

Both were found by an external user following AGD_PRE, one per round trip,
because nobody in the project can run this path: the maintainer's machine has
no Docker. It now runs on a GitHub runner
(`.github/workflows/dist-verify.yml`), which is where it should have been all
along.

The image tag moves `freehsm-build:1.0.0` → `1.1.0`; the script only builds the
image when absent, so a cached one would have kept the old entrypoint.

## The secure heap is measured, and it holds by nothing

`src/fhsm_memory.c` claimed in a comment to re-check that the arena was really
locked, and did not. OpenSSL falls back to ordinary swappable memory when
`mlock` fails and still reports success, so the fallback was invisible from
inside the module — while the Security Target claims key material is
swap-excluded.

`tests/probe_secure_heap` now reads `VmLck` across `C_Initialize`. Measured on
Debian 13: **the whole 8 MiB arena is locked**. The claim holds — and holds with
no margin at all, because the default arena is 8 MiB and systemd's default
`RLIMIT_MEMLOCK` is also 8 MiB. On a host with anything else locked, the
fallback happens silently.

Deliberately not made a hard failure: refusing to start whenever `mlock` falls
short would refuse on most default installations, which is not hardening. The
order is to lower the default arena below the common limit first, then make
locking verified and mandatory. Roadmap.

## Documentation, from two first-contact reports

* **The module does not require a dedicated user.** AGD_PRE created one and ran
  every subsequent command under it, so the only available reading was that it
  is required. It is not: any user who can read the `.so` and a tokens
  directory can use it, with `FHSM_TOKENS_DIR`. The `freehsm` user belongs to a
  shared `fhsm-service` deployment, which is the evaluated configuration and
  therefore what the guide assumes — a posture, not a requirement, and the
  section now says which is which.
* **An empty slot is not a fault.** `C_GetSlotList` reports no token until one
  has been created; "soft token" suggests permanence and the file does not
  exist yet. §4.2 says so at the point the reader sees it, instead of leaving
  them to conclude the module is broken between loading it and provisioning it.
* **32-bit is unsupported and says so** (v2.0.1): `src/fhsm_integrity.c` reads
  `Elf64_*` unconditionally, so the `-Wconversion` failures on i386 are correct
  rejections rather than sloppy casts.

## Verifying this release

    scripts/release.sh 2.0.2

The pre-flight refuses without a reproducibility reference at
`dist/refs/v2.0.2.sha256`, and the release workflow refuses to publish a build
that does not match it, or to publish at all without these notes.
