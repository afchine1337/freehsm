<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Simorgh Labs
-->
# What FreeHSM depends on

Written because `docs/OPENSSF_BEST_PRACTICES.md` cited this file for the
`external_dependencies` criterion while it did not exist — and cited `liboqs`,
which the module does not use.

Every line below is derived from the build rather than remembered: the linked
libraries from the `Makefile`, the packages from `Dockerfile.build` and
`Dockerfile.test`, the run-time helpers from the source that spawns them.

---

## Linked into the module

| Library | Why | Minimum |
|---|---|---|
| `libcrypto` (OpenSSL) | every primitive: AES, SHA-2/3, HMAC, RSA, ECDSA, Ed25519, **and ML-DSA, ML-KEM, SLH-DSA** | **3.5** |
| `libdl` | `dlopen` in the module loader test and the integrity self-check | libc |
| `libpthread` | the session locks, the audit barrier, and the service's workers | libc |

That is the whole list: `-lcrypto -ldl -lpthread`.

**OpenSSL 3.5 is not negotiable.** The post-quantum algorithms come from its
default provider — there is no `liboqs` and no `oqsprovider` in the build.
Built against 3.0 or 3.2, the module compiles and then fails its own boot KAT
at `ML-DSA-65-export-roundtrip`, because the algorithm does not exist to fetch.
That is not hypothetical: it is how a misconfigured `LD_LIBRARY_PATH` was
found, with the tests loading the system's 3.0.2 instead of the 3.5 the objects
were linked against.

`liboqs` and `oqsprovider` appear in `docs/POST_QUANTUM.md` as an **optional**
route for an operator running `mode = legacy` against older tooling. They are
not a dependency of this project, and nothing here links them.

---

## Needed at run time, if used

| Program | When | Package |
|---|---|---|
| `tpm2` (tpm2-tools) | only if the token's data-encryption key is sealed to a TPM. The module forks and execs the CLI rather than linking a TSS — see the note at the top of `src/fhsm_tpm.c` | `tpm2-tools` |
| `systemd` ≥ 250 | only for `fhsm-service` with the recommended PIN path: `LoadCredentialEncrypted=` arrived in v250 | `systemd` |

Both are optional and both fail visibly rather than silently. A broken TPM
reports a device fault and does **not** lock the token (#109). An older systemd
ignores `LoadCredentialEncrypted=` as an unknown key, so the daemon starts and
cannot find its PIN — which is why `docs/DEPLOYING_THE_SERVICE.md` names the
version.

---

## Needed to build

From `Dockerfile.build`: `build-essential`, `pkg-config`, `libssl-dev`
(3.5 headers), `python3` for the mechanism generator, `git`, `ca-certificates`.

`cmake` and `ninja-build` are there to build OpenSSL 3.5 from source where the
distribution does not ship it, not for FreeHSM itself, whose build is a
`Makefile`.

## Needed to test

From `Dockerfile.test`, on top of the build set: `opensc` and `pkcs11-tool` for
third-party interoperability checks, `gnutls-bin` for the same, `python3` for
the test drivers and the `pkcs11-check` campaign.

---

## What this project deliberately does not depend on

* **No liboqs, no oqsprovider.** See above.
* **No TLS library beyond libcrypto.** The module exposes no network interface;
  `fhsm-service` listens on a UNIX socket and a reverse proxy terminates TLS.
* **No JSON parser.** The audit log is written by hand and the service's
  `/sign` takes a raw body — a signature is bytes, and a decoder is a thing to
  get wrong.
* **No package manager for C dependencies.** Everything above is an `apt`
  package or is pinned in a Dockerfile, which is what
  `docs/REPRODUCIBLE_BUILD.md` needs to be true.
