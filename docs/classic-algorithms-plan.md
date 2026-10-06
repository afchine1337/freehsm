<!--
Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Classical and pure ML-DSA keys in the PKI tools — plan

## What is being asked

`fhsm-csr`, `fhsm-ca`, `fhsm-sign` and `fhsm-gui` sign with one algorithm:
the composite ML-DSA-65 + Ed25519. Add, beside it:

| Name in the tools | Key | PKCS#11 signing mechanism | X.509 signature algorithm |
|---|---|---|---|
| `ecdsa-p256` | EC, P-256 | `CKM_ECDSA_SHA256` | ecdsa-with-SHA256 |
| `ecdsa-p384` | EC, P-384 | `CKM_ECDSA_SHA384` | ecdsa-with-SHA384 |
| `rsa-pss` | RSA 3072 | `CKM_SHA256_RSA_PKCS_PSS` | RSASSA-PSS, SHA-256, MGF1-SHA-256, salt 32 |
| `rsa-pkcs1` | RSA 3072 | `CKM_SHA256_RSA_PKCS` | sha256WithRSAEncryption |
| `ed25519` | EdDSA, Ed25519 | `CKM_EDDSA` | id-Ed25519 |
| `ml-dsa-44`, `-65`, `-87` | ML-DSA | `CKM_ML_DSA` | id-ml-dsa-44/65/87 |
| `composite` | as today | `CKM_COMPOSITE_MLDSA65_ED25519` | as today |

## Decisions taken

- **The algorithm is chosen once, at key generation** (`--alg`), and read off
  the key afterwards. `csr`, `root`, `issue`, `crl`, `ocsp-respond`, `sign`
  and `cms` take no algorithm option: they look at the key's type, curve or
  parameter set, and use the mechanism that goes with it. An option repeated
  on every command is an option that can disagree with the key.
- **RSA's padding is carried by the key.** An RSA key alone does not say PSS
  or PKCS#1 v1.5, so keygen sets `CKA_ALLOWED_MECHANISMS` to the one signing
  mechanism chosen; the tools read it back, and the module enforces it. An RSA
  key made elsewhere, without that attribute, is used with PSS.
- **`--alg` defaults to `composite`**, so every existing command line does
  what it did. `tests/pki_tools_characterize.sh` must stay IDENTICAL.
- **Hierarchies may mix.** A CA signs with its own algorithm whatever the
  request's key: an ECDSA CA can certify a composite key and the reverse. The
  proof of possession is checked by the request's algorithm — OpenSSL for the
  classical ones and ML-DSA, the composite verifier as now.

## Why this is mostly not new code

For requests, certificates, CRLs, OCSP responses and CMS, OpenSSL already
encodes everything — names, times, extensions, envelopes. The composite code
supplies three things: the AlgorithmIdentifier, the SubjectPublicKeyInfo, and
the signature, through a callback that reaches PKCS#11. Adding algorithms
means making those three depend on the algorithm, not writing new builders.

Two pieces of real work:

- **ECDSA signatures change shape.** PKCS#11 returns `r || s`; X.509, CRLs,
  OCSP and CMS carry DER `Ecdsa-Sig-Value`. Converted in the signing callback.
- **The SubjectPublicKeyInfo comes from the token.** For EC from `CKA_EC_PARAMS`
  and `CKA_EC_POINT`, for RSA from `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT`, for
  Ed25519 and ML-DSA from `CKA_EC_POINT` / `CKA_VALUE`, then encoded by OpenSSL.

## What it buys

- **The tools work with the default, approved profile.** Every algorithm above
  is approved in `nist-approved-only`; today the tools need `all-mechanisms`
  for anything at all, because the composite exists only there.
- **Everything they produce can be checked by something else.** OpenSSL
  verifies all of these algorithms, so the tests can run `openssl verify`,
  `openssl crl -verify`, `openssl ocsp -verify` and `openssl cms -verify` on
  the output — a validation the composite cannot have until the RFC and its
  implementations exist.

## Stages

Each ends green and committed; the composite's output is unchanged throughout.

0. **This plan.**
1. **The library.** An algorithm descriptor — AlgorithmIdentifier, public key
   to SubjectPublicKeyInfo, signature post-processing, CMS digest — and the
   builders (CSR, root, issue, CRL, OCSP, CMS) taking it in place of the
   composite enum. The composite becomes one descriptor among others; its
   tests and the characterization unchanged.
2. **`pkiops`.** `pkiops_keygen` with an algorithm; every signing operation
   finding the key's algorithm itself; raw signatures and CMS for each. The
   CMS digest follows the algorithm: SHA-256 for P-256 and RSA, SHA-384 for
   P-384, SHA-512 for Ed25519 (RFC 8419) and ML-DSA.
3. **The command-line tools.** `--alg` on `fhsm-csr keygen`; nothing else
   changes in their syntax. Their documentation.
4. **Tests.** Each algorithm end to end in the default profile — key,
   request, root, issued certificate, CRL, OCSP response, raw signature, CMS —
   and every artefact checked by OpenSSL. A mixed hierarchy. The FIPS-provider
   job then exercises all of it with the signed module.
5. **`fhsm-gui`.** An algorithm choice where a key is generated (Token tab,
   Create a new CA); the key list shows each key's algorithm. Nothing else:
   every other operation already works from the key.

## Settled along the way

- **The raw signature format for ECDSA: DER.** The module returns `r || s`,
  which `openssl dgst -verify` does not read; `fhsm-sign` writes DER and
  takes DER back, so the raw signature too can be checked by something else
  (`FHSM_SIGN.md`).
- **RSA size: 3072, with no option.** As SP 800-57 advises past 2030. A
  `--bits` can come when someone needs 4096.
- **Stage 4 was not a stage.** Each stage brought its own tests:
  `tests/test_pki_classic.c` (library, software keys, checked by OpenSSL),
  `tests/test_pkiops_algs.c` (through the module) and
  `tests/pki_tools_algs.sh` (the tools, checked by the `openssl` command line).
  The FIPS-provider CI job runs the first two against the signed module, in
  both profiles.
- **Certificates begin an hour before issuance.** `pki_tools_algs.sh` saw a
  root refused as not yet valid seconds after it was made, when a VM's clock
  stepped back; `FHSM_PKI_BACKDATE_SECONDS` in `fhsm_pki.h`.
- **Where FreeHSM holds the input.** It streams the composite by pre-hashing,
  and accumulates the parts of every other raw signature until `C_SignFinal`.
  `cms` is unaffected: only a digest reaches the module.

## Status

Stages 0 to 5 done, 2026-10-05.
