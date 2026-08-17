<!--
Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.0.0-beta

**The PKI and signing tools, and the composite post-quantum signatures under
them.**

Four command-line tools on top of a Composite ML-DSA implementation that
matches the draft's own Appendix D vectors byte for byte:

| Tool | What it does |
|---|---|
| `fhsm-token` | provisions a token: `init`, `info` |
| `fhsm-csr` | key pairs, PKCS#10 requests, self-signed roots |
| `fhsm-ca` | issues certificates, records revocations, publishes CRLs |
| `fhsm-sign` | detached signatures, raw or CMS, over data of any size |

---

## Read these three before deploying it

### The specification is not published

Everything composite here follows `draft-ietf-lamps-pq-composite-sigs-19`,
which is in the RFC Editor queue. The OID `1.3.6.1.5.5.7.6.48`, the label
`COMPSIG-MLDSA65-Ed25519-SHA512`, and the `M'` construction all come from that
draft.

**If any of them changes at publication, signatures produced by this release
stop verifying under conforming implementations.** Anything signed for
long-term retention may need re-issuing. That is why this is a beta.

### The composite mechanism ships in the interop profile only

The default build is fips-strict, where every entry point refuses it —
`C_GenerateKeyPair`, `C_SignInit`, `C_VerifyInit` and the multipart calls
alike. Building the tools requires:

```bash
make PROFILE=interop
```

`docs/COMPOSITE_SIGS_GAP.md` sets out why the mechanism is not announced as
FIPS-approved: the draft states the design goal that a composite be
*considered* approved and, two lines earlier, that this guidance is not
authoritative and carries no NIST endorsement.

### Composite key generation does not use this module's DRBG

`EVP_PKEY_keygen` is called with a `NULL` library context, so the ML-DSA seed
and the Ed25519 scalar come from OpenSSL's RAND rather than `fhsm_drbg`. The
SP 800-90B health tests never see that draw, and an alarm that would latch the
module into `FHSM_STATE_ERROR` does not prevent a key pair being generated.

This is a gap, not a defect — OpenSSL's DRBG is not a weak generator. What is
lost is the property the module's own DRBG was built for. Certificate serial
numbers were on the same path and are fixed in this release; closing it for key
generation needs a library context backed by `fhsm_drbg` and is not done.

---

## What is new

**Composite ML-DSA, conforming.** `MLDSA65-Ed25519-SHA512`, verified against
the draft's Appendix D vectors and reachable through PKCS#11 as
`CKM_COMPOSITE_MLDSA65_ED25519`.

**A complete PKI chain.** Requests, self-signed roots, issuance with proof of
possession, `subjectAltName`, `cRLDistributionPoints`, revocation lists.
Issuance verifies the applicant's signature against the key the request
carries before anything is signed — the difference between a CA and a rubber
stamp.

**Signing over data of any size.** Multipart composite signing was added to
the module for it: the construction hashes the message internally, so one-shot
`C_Sign` needed the whole thing and refused anything past 2 GiB. A 40 MiB file
now signs in 0.63 s with 8.9 MiB resident.

**CMS/PKCS#7, with a verifier that needs nothing.** Detached `SignedData` with
signed attributes, carrying the signer's certificate — so `fhsm-sign
cms-verify` needs no token, no PIN and no module. It is the only verification
here a third party can run with the file, the data, and the tool.

---

## What no third party can do yet

**Nothing off the shelf verifies a composite signature.** OpenSSL 3.5 has no
implementation and prints the algorithm as a bare OID. Certificates, requests,
CRLs and CMS structures produced here **parse** in any DER-aware tool — that
is the protocol backwards compatibility the draft is designed for — but the
signatures cannot be checked outside this project. `fhsm-sign cms-verify` is
currently the answer, which is why verification shipped with the tool rather
than after it.

---

## Not in this release

* **OCSP.** Only CRLs. OCSP is a network service and belongs with #111.
* **Delta CRLs**, countersignatures, timestamps, certificate chains in CMS.
* **`signingTime`** in CMS: OpenSSL adds it by default, this does not.
  Recording when a signature was made is a decision for the operator.
* **A FIPS certificate.** There is not one and there will not be one. FreeHSM
  is built to FIPS 140-3 Level 1 and CC EAL4+ requirements and documented with
  their methodologies; it holds no certificate and will not pursue one.

---

## Upgrading from v1.6.0

The token store format is unchanged. The module now answers `2.0` to
`C_GetInfo`, `C_GetSlotInfo` and `C_GetTokenInfo` — v1.6.0 answered `1.5`
through those, which is fixed.

`CKR_PIN_LEN_RANGE` is now returned for a PIN outside 4–64 characters, where
`CKR_ARGUMENTS_BAD` was returned before. An application that treated the old
code as fatal will now see a value the user can correct.

---

## Verifying this release

```bash
scripts/release.sh 2.0.0-beta
```

runs the pre-flight and performs no git write operations: it checks, prints
the commands, and stops. It refuses to proceed on a dirty tree, a mismatched
version string or macros, a `CHANGELOG` still saying *Unreleased*, a tag that
already exists locally or on the remote, a failing build, a failing test, or a
build profile that is not fips-strict.

---

*FreeHSM exists to put auditable cryptography within reach of public bodies,
universities and countries that cannot buy a certified module.*

— Afchine Madjlessi, Simorgh Labs
