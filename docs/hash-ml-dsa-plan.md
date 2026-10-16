# HashML-DSA in the module — plan

Status: stage 1 done, 2026-10-12: `tests/test_hash_ml_dsa` passes under
`nist-approved-only` and `all-mechanisms`. Stage 2 done the same day, same
two profiles, and the whole suite. Stage 3 done the same day: advertised in
both profiles, full pkcs11-check 0.2.3 runs attributed in
`PKCS11_CHECK_FINDINGS.md` (2026-10-12). Waits for the 2.3.1 tag, then
merges for 2.4.0. Branch `hash-ml-dsa`, for 2.4.0.

## What is being asked

The HashML-DSA mechanisms of PKCS#11 v3.2 §6.67.6–6.67.7, which FreeHSM does
not offer: today it has `CKM_ML_DSA_KEY_PAIR_GEN` and `CKM_ML_DSA` only.
Asked because the ACVP preHash cases have no token to be measured on
otherwise (Govardhan Yadava's acvp-assay, 2026-10-12), and because a module
that implements FIPS 204 should implement its Algorithm 4.

| Mechanism | Value | Input | Parts |
|---|---|---|---|
| `CKM_HASH_ML_DSA` | `0x1F` | `PH(M)`, already hashed; the hash named in `CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash` | single |
| `CKM_HASH_ML_DSA_SHA224` … `_SHA512` | `0x23`–`0x26` | `M` | single and multi |
| `CKM_HASH_ML_DSA_SHA3_224` … `_SHA3_512` | `0x27`–`0x2A` | `M` | single and multi |
| `CKM_HASH_ML_DSA_SHAKE128`, `_SHAKE256` | `0x2B`, `0x2C` | `M` | single and multi |

The hash-specific ones take an optional `CK_SIGN_ADDITIONAL_CONTEXT`; the
generic one requires `CK_HASH_SIGN_ADDITIONAL_CONTEXT`. Both carry the hedge
variant and a context of at most 255 bytes, as for `CKM_ML_DSA`.

## Measured first

`tests/probe_hash_ml_dsa.c`, Debian 13, OpenSSL 3.5.7, 2026-10-12, under the
default provider and under the FIPS provider loaded as the module loads it.
Both gave the same three answers:

1. **OpenSSL does not do HashML-DSA.** An ML-DSA key refuses a digest name at
   `EVP_DigestSignInit` ("invalid digest").
2. **It signs and verifies a message as given** with
   `OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING = 0`: ML-DSA.Sign_internal and
   Verify_internal of FIPS 204.
3. **The framing built here is right.** Deterministically,
   Sign_internal(`0x00 ‖ len(ctx) ‖ ctx ‖ M`) is byte for byte the pure
   signature of `M` under `ctx`, and verifies as one.

## Design

HashML-DSA is FIPS 204 Algorithm 4: Sign_internal over

    M' = 0x01 ‖ len(ctx) ‖ ctx ‖ OID(PH) ‖ PH(M)

so the module computes `PH(M)` with OpenSSL's digest, builds `M'`, and signs
it with message-encoding 0, deterministic when `CKH_DETERMINISTIC_REQUIRED`
asks for it. Verification is the same `M'` through Verify_internal. Measured
point 3 is what makes this safe: the internal path is the one pure ML-DSA
rests on, and the only new bytes are the prefix and `OID ‖ PH(M)`.

`OID(PH)` is the DER of the hash's object identifier, 2.16.840.1.101.3.4.2.x:

| Hash | Arc | `PH(M)` bytes |
|---|---|---|
| SHA-256, -384, -512 | 1, 2, 3 | 32, 48, 64 |
| SHA-224 | 4 | 28 |
| SHA-512/224, SHA-512/256 | 5, 6 | 28, 32 |
| SHA3-224, -256, -384, -512 | 7, 8, 9, 10 | 28, 32, 48, 64 |
| SHAKE128, SHAKE256 | 11, 12 | 32, 64 (FIPS 204: 256 and 512 bits of output) |

**Multipart** for the hash-specific mechanisms streams `M` into the digest
and signs at Final: nothing proportional to the message is held.

**The generic mechanism** is given `PH(M)` — v3.2 §6.67.6: "The data
passed in is an already hashed message PH(M)" — and Table 283 sets its
`C_Sign` input to the length of the hash, single-part only. `C_Sign` refuses
any other length with `CKR_DATA_LEN_RANGE`; `C_Verify`, whose input the table
gives as "any", answers `CKR_SIGNATURE_INVALID`. `C_SignUpdate`,
`C_SignFinal`, `C_VerifyUpdate` and `C_VerifyFinal` answer
`CKR_FUNCTION_NOT_SUPPORTED` and end the operation. It names the hash
by digest mechanism: `CKM_SHA224` … `CKM_SHA512`, `CKM_SHA512_224`,
`CKM_SHA512_256`, `CKM_SHA3_224` … `CKM_SHA3_512`. SHA-512/224 and SHA-512/256
reach HashML-DSA only this way: they have no `CKM_HASH_ML_DSA_<hash>`.

**One table.** The mechanism, its digest, the OID arc and the output length
are one row, so the hash-specific mechanisms, the generic mechanism's `hash`
field and the verify path cannot disagree.

**Profiles.** HashML-DSA is approved (FIPS 204), and the measurement shows it
works under the FIPS provider: `nist-approved-only` offers it.

## Checked against

- **NIST's ACVP vectors.** pkcs11-check's `TestMlDsaSigVer` compares FreeHSM's
  verdict with NIST's, preHash groups included, once the mechanisms are
  advertised. Its `TestMlDsaSigGen` only re-verifies what was signed, so a
  test here takes deterministic preHash sigGen vectors and compares the
  signature byte for byte — the check that matters, since a wrong `M'` would
  still verify against itself.
- **pkcs11-check's `test_hash_ml_dsa.py`**: availability, round trips,
  tampered messages, empty messages, for all eleven mechanisms.
- **acvp-assay**, once its PKCS#11 example asks preHash cases.

## Stages

1. **The table, the generic mechanism, single-part sign and verify** for all
   eleven, with the deterministic KAT test.
   Multipart already works through the buffered path every asymmetric
   mechanism takes: the message is held and signed at Final, which
   `tests/test_hash_ml_dsa.c` checks against the known answers.
   `CKM_ML_DSA` itself now also refuses a key that is not `CKK_ML_DSA` with
   `CKR_KEY_TYPE_INCONSISTENT` at Init, as the HashML-DSA mechanisms do.
2. **Multipart** for the ten hash-specific mechanisms: `M` streamed into
   the digest instead of held. At the first Final, `PH(M)` replaces the
   message in the multipart buffer, so the retry after
   `CKR_BUFFER_TOO_SMALL` signs the same `PH(M)` through the same
   `sign_asymmetric()`. The generic mechanism's multipart calls are refused.
   `op_init` now also releases a digest context an abandoned operation left,
   which the composite mechanism needed as well.
3. **Advertisement and documentation**: the generated mechanism table,
   `MECHANISMS.md`, `CKA_ALLOWED_MECHANISMS` handling, and a pkcs11-check run.

## CHANGELOG, at the 2.4.0 merge

Held here until the 2.3.1 tag, and moved into `[Unreleased]` at the merge
(2026-10-14):

    ### Added
    * **HashML-DSA** (FIPS 204 Algorithm 4; PKCS#11 v3.2 §6.67.6-6.67.7):
      `CKM_HASH_ML_DSA` and the ten `CKM_HASH_ML_DSA_<hash>`, SHA-2, SHA-3
      and SHAKE, single- and multi-part, in both profiles. OpenSSL 3.5 has no
      HashML-DSA: the module builds M' and signs it with ML-DSA.Sign_internal.
      Checked byte for byte against NIST's deterministic ACVP signatures
      (`tests/test_hash_ml_dsa`). Asked for by Govardhan Yadava's acvp-assay.

    ### Fixed
    * **A context string over 255 bytes** for `CKM_ML_DSA` and `CKM_SLH_DSA`.
      At 256 bytes signing and verification answered `CKR_FUNCTION_FAILED`;
      beyond that, and for a NULL `pContext` with a length, the context was
      dropped and the signature made or checked under the empty one, with
      nothing to say so. Now, as FIPS 204 and 205 define it: `C_SignInit`
      refuses with `CKR_MECHANISM_PARAM_INVALID`, verification answers
      `CKR_SIGNATURE_INVALID`, and a NULL context with a length is refused.
      Wycheproof's InvalidContext cases, 18 xfails in pkcs11-check 0.2.3.

    ### Changed
    * `CKM_ML_DSA` refuses a key that is not `CKK_ML_DSA` with
      `CKR_KEY_TYPE_INCONSISTENT` at Init; it failed at C_Sign before.
    * **`C_CreateObject` requires `CKA_PARAMETER_SET`** on an ML-KEM, ML-DSA
      or SLH-DSA key, public or private: `CKR_TEMPLATE_INCOMPLETE` without
      it (PKCS#11 v3.2 Tables 280-281, 287-288, 290-291, footnote 1). It was
      inferred from the key's length. A DER SubjectPublicKeyInfo is now held
      to the stated set as a raw key was. Callers that relied on the
      inference must send the attribute. Raised by Govardhan Yadava for
      acvp-assay's PKCS#11 harness.

## Open questions

- **pkcs11-check's generic test.** `TestHashMLDSAGeneric` signs a 47-byte
  message with `CKM_HASH_ML_DSA`, where §6.67.6 asks for `PH(M)`. It lists
  `CKR_DATA_LEN_RANGE` among the codes it reports as "not operational", so
  this module will show there as an expected failure. To raise with Denis
  once the stage 3 run shows it; `test_hash_slh_dsa.py` has the same shape.

  Measured 2026-10-12 (pkcs11-check 0.2.1 and 0.2.3 alike, nist-approved-only, ML-DSA
  subset): eight xfails, all on the generic mechanism, for two reasons.
  `TestHashMLDSAGeneric::test_sign_verify_roundtrip` (4) passes the message.
  The registry tests `TestMechSignRoundtrip` (2) and `TestMultipartSign` (2)
  call `C_SignInit` without the required `CK_HASH_SIGN_ADDITIONAL_CONTEXT`
  (the registry entry has no parameter recipe) and meet
  `CKR_MECHANISM_PARAM_INVALID`. The forty tests of the ten hash-specific mechanisms
  pass, and `TestMlDsaSigGen` / `TestMlDsaSigVer` pass all they run, 258 and
  82, where the 2026-09-18 run had 180 and 45 with the rest skipped or xfail.

- **SHAKE in the generic mechanism.** v3.2 has no digest mechanism for
  SHAKE128 or SHAKE256 (only `CKM_SHAKE_*_KEY_DERIVATION`), so
  `CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash` cannot name them. SHAKE is reached
  through `CKM_HASH_ML_DSA_SHAKE128` and `_SHAKE256` only; the generic
  mechanism refuses an unknown `hash` with `CKR_MECHANISM_PARAM_INVALID`.
- **The KAT vectors.** Deterministic preHash sigGen cases from NIST's
  ACVP-Server JSON, a few per parameter set and hash, kept small in
  `tests/`; where the harness's pinned copy lives in the VM is to be found.
