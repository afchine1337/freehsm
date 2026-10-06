<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.3.0

The PKI tools stop being a composite-only proposition, and get a window.

Until now `fhsm-csr`, `fhsm-ca` and `fhsm-sign` signed with one algorithm, the
post-quantum composite ML-DSA-65 + Ed25519 — which exists only in
`all-mechanisms` builds and which nothing off the shelf can verify yet. They
now also make and use ECDSA, RSA, Ed25519 and pure ML-DSA keys, all approved in
the default profile, and everything made with those is ordinary PKIX that the
`openssl` command line checks. `fhsm-gui` puts the same operations in a desktop
window, with every PKCS#11 call shown as it is made.

The module itself carries corrections, most of them found by Denis Mingulov's
`pkcs11-check`, and several of them make it refuse what PKCS#11 says it must.
There is no security advisory in this release.

---

## Every algorithm in the PKI tools

`fhsm-csr keygen --alg` chooses, once:

| `--alg` | Key | X.509 signature algorithm |
|---|---|---|
| `composite` (default) | ML-DSA-65 + Ed25519 | id-MLDSA65-Ed25519-SHA512 |
| `ecdsa-p256`, `ecdsa-p384` | EC | ecdsa-with-SHA256 / SHA384 |
| `rsa-pss`, `rsa-pkcs1` | RSA 3072 | RSASSA-PSS (SHA-256) / sha256WithRSAEncryption |
| `ed25519` | Ed25519 | id-Ed25519 |
| `ml-dsa-44`, `-65`, `-87` | ML-DSA | id-ml-dsa-44/65/87 |

Every other command — requests, roots, issuance, CRLs, OCSP, raw signatures,
CMS — reads the algorithm off the key and takes no option for it. An RSA key
carries its padding in `CKA_ALLOWED_MECHANISMS`, which the module enforces.
Public keys are read from the standard attributes, so the tools work with any
PKCS#11 module that answers them.

**Hierarchies may mix.** A CA of one algorithm certifies a key of another; the
request's proof of possession is checked by the request's own algorithm.

**Checked by something else.** `tests/pki_tools_algs.sh` runs the tools with
each algorithm but the composite and hands every file to `openssl`: `req
-verify`, `verify`, `crl`, `ocsp`, `dgst` or `pkeyutl -verify`, `cms -verify`.
ECDSA raw signatures are written as DER for that reason.

**The composite's output is unchanged.** The request, certificate, CRL, OCSP
and CMS builders were made to take any signer (`include/fhsm_pki.h`); the
composite is one signer among them, and `tests/pki_tools_characterize.sh`
shows the tools' composite output identical before and after.

Certificates now begin their validity an hour before issuance. A `notBefore`
of exactly now was refused by any verifier whose clock was behind the CA's.

## `fhsm-gui`

A GTK 4 window over the same operations (`make gui`, not part of `make all`;
see `docs/FHSM_GUI.md`):

- **exploration** — every operation with the command line's defaults, and the
  PKCS#11 call log, which never shows a PIN, its length or an attribute value;
- **operator** — guided steps for one CA, refusing a key label already on the
  token, re-initialising a token that holds one, a certificate without CRL
  URLs, and issuing while the published CRL is missing or expired. The
  published CRL's expiry is re-read every minute, and every file the window
  writes is replaced atomically.

A module can be unloaded and another loaded without restarting. CI starts and
closes the window under a virtual display and fails on any GTK warning
(`make gui-smoke`).

## What the module now refuses

Each of these was accepted before and is refused now, as PKCS#11 v3.2 asks. A
conforming application sees no difference.

- `C_OpenSession` without `CKF_SERIAL_SESSION`.
- `C_Login` of one role while the other holds the token, an SO login with a
  read-only session open, and a read-only session while the SO is logged in.
- `C_Logout` with nobody logged in (`CKR_USER_NOT_LOGGED_IN`).
- RSA-OAEP without its parameter block is `CKR_MECHANISM_PARAM_INVALID`, not
  `CKR_ARGUMENTS_BAD`.
- In `all-mechanisms` builds: EC curves below the advertised 256 bits, and
  3DES with a `CKA_VALUE_LEN` other than 24.
- `CKA_VALUE_LEN` beyond 32 bits in `C_GenerateKey`: 2^32 + 16 was cut to 16
  and made a 16-byte AES key. It is now `CKR_KEY_SIZE_RANGE`.
- A `CK_EDDSA_PARAMS` block on an Ed25519 key, even an empty one. Its presence
  asks for Ed25519ctx, which this module does not implement; it was answered
  with a pure Ed25519 signature. Pure Ed25519, with no parameters, is
  unchanged, and so is Ed448.

Two calls that failed now work. `C_EncryptFinal` or `C_DecryptFinal` straight
after its Init, with no Update, is empty input rather than
`CKR_OPERATION_NOT_INITIALIZED`. And `CKM_ECDH1_DERIVE` no longer refuses the
one peer point in 256 whose X coordinate made a bare point look DER-wrapped.

Closing the last session now logs the token out, and `C_GetSessionInfo`
reports the token's login state rather than the session's.

## Offered only where it works

A signed module loads the OpenSSL FIPS provider, which has no X25519, X448,
MD5, brainpool or secp256k1. A signed `all-mechanisms` build advertised those
and failed when they were used. The module now asks the loaded providers:
what they cannot serve is not advertised, and a curve they cannot build is
refused as unsupported. Nothing changes in the default profile.

The two PQ/T hybrid mechanisms (#17), never operational, are no longer
advertised; `CKM_COMPOSITE_MLDSA65_ED25519` is the construction that replaced
them.

## Two copies of the module in one process

A second FreeHSM module in the same process — another build loaded beside the
first, as `fhsm-gui` does, or two under one p11-kit proxy — failed
`C_Initialize`, because libcrypto's secure heap is one per process. It now
adopts the existing arena, once the kernel shows it locked; an unlocked one is
still refused.

## Measured

Full corpus, signed module, FIPS provider loaded, no integrity bypass in the
environment, 2026-10-06:

| harness | profile | passed | failed |
|---|---|---|---|
| pkcs11-check 0.2.1 | nist-approved-only | 55 205 | 2 |
| pkcs11-check 0.2.1 | all-mechanisms | 55 655 | 4 |
| pkcs11-check 0.2.3 | nist-approved-only | 55 378 of 93 010 | 7 |
| pkcs11-check 0.2.3 | all-mechanisms | 55 832 of 93 141 | 7 |

Each run was diffed by node-id against the previous reference, and every
moved failure was read. Under 0.2.3, three failures were the module's — the
`CKA_VALUE_LEN` and Ed25519 items above — and were fixed the same day; a
targeted run confirmed them, and the `C_EncryptFinal` fix with them. The rest
are recorded in `tests/pkcs11_check_known_failures.txt`, each with its reason:
two async probes that never reach the module and a question on Ed448 without
parameters (mingulov/pkcs11-check#49), and RSA PKCS#1 v1.5 implicit rejection
scored as an oracle by one test (#37). CI now runs 0.2.3 and gates on that
list. `docs/PKCS11_CHECK_FINDINGS.md` has the detail.

The composite signs under the FIPS provider: a signed `all-mechanisms` build
passed `scripts/run_fips_tests.sh` 64 of 64 with the provider shown loaded,
every composite test included. CI now runs that suite on both profiles.

## Why minor and not patch

New capabilities an application can observe — the tools' algorithms, the
window — and calls answered differently than before, in the direction the
specification asks. Under semantic versioning that is a minor release, the
same argument as for v2.1.0 and v2.2.0. The two mechanisms withdrawn from the
list never worked, so no caller that worked loses anything.

## What this release does not do

Raw signatures with keys other than the composite are accumulated by the module
until `C_SignFinal`, so its memory bounds the file it can sign that way; `cms`
has no such limit. The window does not remember the CA set in operator mode
between runs. Composite signatures still cannot be verified by anything off
the shelf, until the RFC publishes and implementations follow.

No FIPS or Common Criteria certification is held, sought, or planned.

## Credits

The harness is Denis Mingulov's `pkcs11-check`. It found the login conflicts,
the missing `CKF_SERIAL_SESSION` check, the EC curve bound and the 3DES key
length. Its 0.2.3 release resolves #38 and most of #37, and found the
Ed25519, `CKA_VALUE_LEN` and `C_EncryptFinal` defects fixed here.
`ACKNOWLEDGEMENTS.md` records who found what.

## Verifying this release

    scripts/release.sh 2.3.0
