<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.4.0

Keys that do not sign. The tools now manage the token's objects and encrypt
files with its keys, and the module gains HashML-DSA.

`fhsm-crypt`, a new tool, and a new tab in `fhsm-gui` list, describe, make
and delete keys and certificates, and encrypt a file for a key on the token
or for a certificate's holder, as CMS that OpenSSL reads. The module offers
the eleven HashML-DSA mechanisms of PKCS#11 v3.2, checked byte for byte
against NIST's signatures, and answers a context string over 255 bytes the
way FIPS 204 defines it.

**Check your templates if an application imports ML-KEM, ML-DSA or SLH-DSA
keys.** `C_CreateObject` now requires `CKA_PARAMETER_SET`, as the
specification does; without it the import answers `CKR_TEMPLATE_INCOMPLETE`.

There is no security advisory in this release.

---

## Files encrypted with the token's keys

`fhsm-crypt encrypt --key L` writes CMS AuthEnvelopedData (RFC 5083) with
AES-256-GCM content (RFC 5084). The content key is fresh per file and
protected by the token:

| key on the token | recipient | how the content key is protected |
|---|---|---|
| AES (`keygen --alg aes128` / `aes256`) | KEKRecipientInfo, identified by the key's label | AES key wrap through `C_Encrypt`; the AES key never leaves the token |
| RSA 3072 (`keygen --alg rsa-oaep`) | KeyTransRecipientInfo, by subjectKeyIdentifier or issuer and serial | RSAES-OAEP, SHA-256 and MGF1-SHA-256 |

`--cert C` encrypts for the holder of a certificate without the module or a
PIN: encrypting for someone is a public operation. `fhsm-crypt decrypt`
finds the key from the file, keeps its output only once the GCM tag has
verified, and leaves nothing behind for an altered file. Files are streamed
in 64 KiB chunks, and an existing output is never overwritten.

**Checked by something else.** `tests/test_pkiops_envelope.c` and
`test_pkiops_envelope_rsa.c` have OpenSSL open the files written here and
open the files OpenSSL writes, for both recipient kinds. PKCS#1 v1.5 key
transport, OpenSSL's default, and OAEP with SHA-1 are refused by name.

The structure is written by hand: OpenSSL's CMS API builds a KEK recipient
only from the key-encryption key's bytes, which a token key never yields.

## Managing what is on the token

- `fhsm-crypt list` and `show --label L`: certificates and public, private and
  secret keys, and an object's attributes as a person reads them — usage,
  size or curve, allowed mechanisms, protection, origin; a certificate's
  subject, issuer, serial and validity. A private or secret key's value is
  never asked for.
- `fhsm-crypt keygen --alg aes128|aes256|hmac|rsa-oaep`: sensitive,
  non-extractable keys with every usage stated. An AES key encrypts and wraps
  and cannot sign; an `rsa-oaep` pair can only be used for RSA-OAEP.
- `fhsm-crypt delete --label L` names what it would destroy and stops; only
  `--yes` destroys.

`fhsm-gui` has the same: certificates beside the keys in the Token tab, an
attribute pane, secret-key generation, **Delete…** with a confirmation per
object, and an Encryption tab. Operator mode refuses to delete the CA's key,
and may now re-initialise a token it has seen empty. `docs/FHSM_CRYPT.md`.

## HashML-DSA

`CKM_HASH_ML_DSA` and the ten `CKM_HASH_ML_DSA_<hash>` — SHA-2, SHA-3 and
SHAKE — FIPS 204 Algorithm 4, in both profiles. OpenSSL 3.5 does not
implement HashML-DSA, so the module builds the message
`M' = 0x01 ‖ len(ctx) ‖ ctx ‖ OID(PH) ‖ PH(M)` and signs it with
ML-DSA.Sign_internal, the path pure ML-DSA rests on.

- The hash-specific mechanisms take the message, in one part or streamed.
- The generic one takes PH(M), single-part, with the hash named in
  `CK_HASH_SIGN_ADDITIONAL_CONTEXT` (§6.67.6, Table 283). SHA-512/224 and
  SHA-512/256 are reached this way only.

A signature that verifies against the module's own verification proves
nothing about M', so `tests/test_hash_ml_dsa.c` signs NIST's ACVP preHash
vectors deterministically and compares the signatures byte for byte.

## Eight SLH-DSA parameter sets

SLH-DSA-128f, 192f, 256s and 256f, SHA2 and SHAKE alike, could not be
generated: the pair-wise consistency check that follows `C_GenerateKeyPair`
signed into a 16384-byte buffer, their signatures are larger, and the
failure latched the module into ERROR — one request for such a key left the
token unusable until the application restarted. The check now asks the
signature's size, and `tests/test_slh_dsa_sets.c` generates, signs and
verifies all twelve sets. Found by running OpenSC's pkcs11-tool against the
module (`tests/pkcs11_tool_pqc.sh`).

## RSA-OAEP: SHA-224, SHA-3, and two return codes

OAEP with SHA-224 or any SHA-3 hash was refused, though PKCS#11 v3.2
defines them; the module now takes them as hash and as MGF1 hash. An unknown
hash is refused at Init with `CKR_MECHANISM_PARAM_INVALID` instead of at the
operation with `CKR_MECHANISM_INVALID`, and a message too long for the key
is `CKR_DATA_LEN_RANGE` instead of `CKR_FUNCTION_FAILED`. Found by a new
test that has OpenSSL encrypt with the token's public key and the module
decrypt, for RSA 2048, 3072 and 4096; its AES counterpart checks every AES
mechanism at 128, 192 and 256 bits against OpenSSL and found nothing.

## One token, several threads

An application that used sessions on the same token from several threads
could have a key freed under a running signature: `C_DestroyObject` or
`C_CloseSession` in one thread zeroized and freed a key value another
thread's `C_Sign` was still reading, which answered `CKR_FUNCTION_FAILED`
or signed over a reallocated block. Three smaller races sat beside it — a
torn or foreign `CKA_LABEL` from `C_GetAttributeValue`, the login state
read without the token's mutex, and a half-filled function table handed to
two threads loading the module at once. Every `C_` function now runs under
one read-write lock: shared for most calls, so signatures still run in
parallel, exclusive for the six that free what others may be reading. A
single-threaded application sees no change. Found by
`tests/test_concurrency_store`, written for #111-prep, which failed on every
ThreadSanitizer run before the change and on none of ten after; CI now runs
it under TSan.

## What the module now answers differently

- **A context string over 255 bytes** for ML-DSA, SLH-DSA and HashML-DSA is
  refused at `C_SignInit` (`CKR_MECHANISM_PARAM_INVALID`) and is a signature
  that does not verify (`CKR_SIGNATURE_INVALID`), as FIPS 204 and 205 define
  it. At 256 bytes the module answered `CKR_FUNCTION_FAILED`; beyond that,
  and for a NULL `pContext` with a length, it dropped the context and signed
  or verified under the empty one. A NULL context with a length is now
  refused.
- **`CKA_PARAMETER_SET` is required** when an ML-KEM, ML-DSA or SLH-DSA key
  is imported, public or private (v3.2 Table 13, footnote 1); the set was
  inferred from the key's length. A DER SubjectPublicKeyInfo is held to the
  stated set as a raw key was.
- **`CKM_ML_DSA` refuses a key of another type** at Init with
  `CKR_KEY_TYPE_INCONSISTENT`; it failed at `C_Sign` before.
- **`CKM_EDDSA` without a parameter on an RFC 8032 `edwards448` key** is
  refused at `C_SignInit` and `C_VerifyInit` with
  `CKR_MECHANISM_PARAM_INVALID`: under that form of `CKA_EC_PARAMS` every
  scheme takes a `CK_EDDSA_PARAMS` block. `CKA_EC_PARAMS` now reads back in
  the form it was given. Keys made with the RFC 8410 OID, which OpenSC
  `pkcs11-tool` sends, keys made before this release, and Ed25519 are
  unchanged.
- **`CKA_PARAMETER_SET` reads back** on ML-KEM, ML-DSA and SLH-DSA keys,
  both halves, as the `CKP_*` selector. It was taken at generation and
  import and answered `CKR_ATTRIBUTE_TYPE_INVALID` afterwards, so OpenSC
  `pkcs11-tool --read-object` refused every ML-KEM public key.
- **`C_DecapsulateKey` with a ciphertext of the wrong size** answers
  `CKR_ENCRYPTED_DATA_LEN_RANGE`; it was `CKR_FUNCTION_FAILED`.

## The build image is pinned

`Dockerfile.build` names its base image by digest and installs from
snapshot.debian.org at one instant, and the image carries a dated tag,
`freehsm-c-build:debian13-20261006`. From v2.2.0 to v2.3.1, `dist-verify` —
which rebuilds the image from that file, as an outsider would — failed on
every tag while the published binaries matched their references: the
release image kept the toolchain of the day it was built, and a fresh build
took that day's packages. Before the merge, a build in the published image
and a fresh rebuild gave the same bytes. `docs/REPRODUCIBLE_BUILD.md` §5-6.

The toolchain moved with the pin, so this release's bytes are not what the
old image would have made. `freehsm-c-build:debian13-openssl-3.5` stays
published, unchanged, as the image of v2.2.0 to v2.3.1.

## Measured

pkcs11-check 0.2.3, full corpus, signed module, `main` on 2026-10-17:
55 870 passed in `nist-approved-only` and 56 325 in `all-mechanisms`, with 2
and 3 failures, all of them the known ones listed in
`tests/pkcs11_check_known_failures.txt` -- the async probes, fixed in the
harness and not yet released, and in `all-mechanisms` the v1.5 structured
oracle. Against the 2.3.1 candidate, two stages, every move attributed in
`docs/PKCS11_CHECK_FINDINGS.md` and none backwards: 453 moves on 2026-10-12
with HashML-DSA and the context fix (+262 passed), then 212 on 2026-10-17
with the OAEP, PSS, SLH-DSA, ML-KEM and Ed448 fixes (+212 passed, and the
two Ed448 failures gone). The 8 new xfails are all on
`CKM_HASH_ML_DSA`, which takes PH(M) single-part: four tests pass it the
message, four call it without its required parameter
(mingulov/pkcs11-check#51).

Wycheproof: the ML-DSA adapter now sends contexts over 255 bytes instead of
skipping them, 629 match and 0 violations; ML-KEM 21 match, 0 violations.

The two ML-KEM answers above came after those runs. pkcs11-check 0.2.3,
category `pqc`, unsigned module, 2026-10-17: 103 passed and 4 xfailed,
against 102 and 5 before; `TestMLKEMNegative::test_decapsulate_invalid_ciphertext_length`
moved from xfail to pass and nothing else moved.

`make tests`, `tests/fhsm_crypt_cli.sh` and `make gui-smoke` pass, and
`tests/test_hash_ml_dsa` in both profiles.
`make tsan-concurrency` passes: the concurrency tests under ThreadSanitizer,
ten runs clean.

## Why minor and not patch

New mechanisms, a new tool and a new tab, and imports answered differently
than before, in the direction the specification asks. Under semantic
versioning that is a minor release, as 2.1.0 to 2.3.0 were.

## What this release does not do

ML-KEM recipients in encrypted files wait: OpenSSL 3.5 has ML-KEM but no CMS
`KEMRecipientInfo`, so nothing independent could check an encoding written
here. HashSLH-DSA is not implemented. ML-DSA keys cannot be imported from a
seed: the module has no `CKA_SEED`.

## Credits

Govardhan Yadava's acvp-assay asked for HashML-DSA, so that its preHash
cases have a token to be measured on, and raised `CKA_PARAMETER_SET`. Its
PKCS#11 reference harness now answers ML-DSA, and through it this module
passes 90 of NIST's pinned sigGen and 90 sigVer cases, preHash included,
with nothing failing; he reproduced those counts on his own build
(Govardhan527/acvp-assay#2). The harness is Denis Mingulov's
`pkcs11-check`; Wycheproof's ML-DSA context vectors found the context
defect, and OpenSC's `pkcs11-tool` the SLH-DSA one and the two ML-KEM
answers above. `ACKNOWLEDGEMENTS.md`
records who found what.

## Verifying this release

    scripts/release.sh 2.4.0
