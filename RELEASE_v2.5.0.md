<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.5.0

HashSLH-DSA, and SLH-DSA checked against NIST rather than against itself.

The module offers the eleven HashSLH-DSA mechanisms of PKCS#11 v3.2, and
its SLH-DSA and HashSLH-DSA signatures are now compared byte for byte with
NIST's ACVP vectors. That comparison found that SLH-DSA keys could not be
imported; they can now. AES-CMAC and AES-GMAC work in several parts, as
HMAC did. A curve the module does not take is now answered
`CKR_CURVE_NOT_SUPPORTED`.

**Check your error handling if an application tells curves apart by return
code.** A `CKA_EC_PARAMS` naming a curve the module does not serve --
brainpool, secp256k1, P-224, or X25519 and X448 under the FIPS provider --
was `CKR_ATTRIBUTE_VALUE_INVALID` and is now `CKR_CURVE_NOT_SUPPORTED`. A
value that names no curve is still `CKR_ATTRIBUTE_VALUE_INVALID`.

There is no security advisory in this release.

---

## HashSLH-DSA

`CKM_HASH_SLH_DSA` and the ten `CKM_HASH_SLH_DSA_<hash>` -- SHA-2, SHA-3 and
SHAKE -- FIPS 205 Algorithms 23 to 25, in both profiles. OpenSSL 3.5 does
not implement HashSLH-DSA, so the module builds the message

    M' = 0x01 ‖ len(ctx) ‖ ctx ‖ OID(PH) ‖ PH(M)

and signs it with slh_sign_internal, the way it has done for HashML-DSA
since 2.4.0. FIPS 205 defines the same M', with the same hash OIDs and the
same SHAKE output lengths, as FIPS 204, so the two families share one table
and one construction.

- The hash-specific mechanisms take the message, in one part or streamed.
- The generic one takes PH(M), single-part, with the hash named in
  `CK_HASH_SIGN_ADDITIONAL_CONTEXT`. SHA-512/224 and SHA-512/256 are reached
  this way only.

`tests/test_hash_slh_dsa.c` signs NIST's ACVP preHash vectors
deterministically for all twelve hashes and compares the signatures byte for
byte, through the hash-specific mechanism, the generic one and the streamed
path, and checks NIST's sigVer verdicts. OpenSC's `pkcs11-tool` signs and
verifies with them too, through the `HASH-SLH-DSA` names added upstream in
OpenSC #3882, the generic mechanism included (`tests/pkcs11_tool_pqc.sh`).

## SLH-DSA against NIST, and a defect it found

Wycheproof has no SLH-DSA vectors, and until this release the module's
SLH-DSA was checked against itself only: it verified its own signatures.
`tests/test_slh_dsa_kat.c` takes keys and signatures from NIST's ACVP
SLH-DSA-sigGen-FIPS205 and sigVer-FIPS205: deterministic signatures for all
twelve parameter sets, with and without a context, compared byte for byte,
and NIST's verdicts on modified messages, R, SIGFORS and SIGHT and on
signatures a byte short or long.

Its first run failed at the first step. `C_CreateObject` refused every
SLH-DSA public key with `CKR_TEMPLATE_INCONSISTENT`, and accepted a raw
SLH-DSA private key, stored it as sent, and answered `CKR_FUNCTION_FAILED`
at the first `C_Sign`. Both now build the key under the set
`CKA_PARAMETER_SET` names -- the only thing that can name it, since an
SLH-DSA key's length is shared by four sets. With the import fixed, all
twelve sets give NIST's signatures.

pkcs11-check had been saying so in every run: 456 of its SLH-DSA ACVP tests
per profile were recorded as "advertised but not operational", an xfail that
neither the known-failures list nor the run-to-run diffs looked at. They now
pass. The rest of those xfails were inventoried the same day, and the
changes below come from that inventory (`docs/PKCS11_CHECK_FINDINGS.md`,
2026-10-21 and 2026-10-22).

## What the module now answers differently

- **A curve the module does not take is `CKR_CURVE_NOT_SUPPORTED`**, at
  import and at key generation, as described above. pkcs11-check counts it
  as an absence, which moved some 13 100 Wycheproof vectors per profile from
  "not operational" to skipped -- and 7 202 invalid ECDSA vectors from
  passed to skipped: they had passed because the key was refused, not
  because the signature was examined.
- **An ECDSA signature whose verification reaches the point at infinity is
  `CKR_SIGNATURE_INVALID`.** OpenSSL returns -1 rather than 0 for it, and
  the module reported that as `CKR_FUNCTION_FAILED`, its own failure.
  Wycheproof's "point at infinity during verify" vectors, one-shot and
  multipart; RSA is unchanged.
- **`CKM_GENERIC_SECRET_KEY_GEN` makes the lengths it advertises**, 1 to 64
  bytes. The AES rule (16, 24 or 32) had been applied to generic secrets,
  so a 64-byte HMAC key was `CKR_KEY_SIZE_RANGE`.
- **`CKA_COPYABLE` can be cleared** with `C_SetAttributeValue`, CK_TRUE to
  CK_FALSE as PKCS#11 v3.0 §4.4 allows; `C_CopyObject` then refuses the
  object. The way back stays read-only.

## AES-CMAC and AES-GMAC in several parts

`CKM_AES_CMAC` and `CKM_AES_GMAC` through `C_SignUpdate` / `C_SignFinal` and
`C_VerifyUpdate` / `C_VerifyFinal`. `C_SignInit` accepted both for the
one-shot path and the first Update refused them. HMAC, CMAC and GMAC now
share one stream, opened in one place; a GMAC tag shorter than 16 bytes
(`CK_GCM_PARAMS.ulTagBits`) is the prefix of the full one, as one-shot.
`tests/test_aes_cmac_multipart.c` checks SP 800-38B's examples and
`tests/test_aes_gmac_multipart.c` OpenSSL's GMAC and the GCM specification's
Test Case 1, for AES-128, -192 and -256.

## Measured

pkcs11-check 0.2.3, full corpus, signed module, the 2.5.0 commit on
2026-10-22: 49 338 passed of 93 568 in `nist-approved-only` and 49 793 of
93 699 in `all-mechanisms`, with 2 and 3 failures, all of them the known
ones listed in `tests/pkcs11_check_known_failures.txt` -- the async probes,
fixed in the harness and not yet released, and in `all-mechanisms` the v1.5
structured oracle.

The passed count is lower than 2.4.0's 55 870 and 56 325, and the change is
an accounting one. Diffed by node-id, every move is attributed in
`docs/PKCS11_CHECK_FINDINGS.md` and none is a failure. What 2.5.0 itself
moved:

- 538 xfails passed: SLH-DSA key import (456), ECDSA at the point at
  infinity (80), a 512-bit generic secret, `CKA_COPYABLE`;
- 13 138 xfails became skips: curves the module does not take, now
  `CKR_CURVE_NOT_SUPPORTED`;
- 7 202 passes became skips: invalid ECDSA vectors on those curves, which
  had passed because the key was refused before any signature was looked
  at;
- then, on the release commit, 321 moves in each profile, the same 321: 4
  xfails passed (multipart AES-CMAC and AES-GMAC), 41 skips passed and 275
  new tests appeared with the eleven HashSLH-DSA mechanisms (88 passed,
  183 not applicable), and 5 xfails on the generic `CKM_HASH_SLH_DSA`,
  which the harness calls without its required parameter or on the message
  rather than PH(M) (mingulov/pkcs11-check#51).

One test went from passed to xfailed: `test_ec_below_min_is_refused` does
not count `CKR_CURVE_NOT_SUPPORTED` among the refusals it accepts, though the
harness's Wycheproof tests read it as absence (mingulov/pkcs11-check#63).

`make tests` passes, `tests/test_slh_dsa_kat`, `tests/test_hash_slh_dsa`,
`tests/test_aes_cmac_multipart` and `tests/test_aes_gmac_multipart`
included, and `tests/pkcs11_tool_pqc.sh` passes its 76 checks with OpenSC
master's `pkcs11-tool`.

## Why minor and not patch

New mechanisms, and an answer that changes for callers that meet it. Under
semantic versioning that is a minor release, as 2.1.0 to 2.4.0 were. The
fixes alone would have made a patch.

## What this release does not do

ML-KEM recipients in encrypted files still wait: OpenSSL 3.5 has no CMS
`KEMRecipientInfo`, so nothing independent could check an encoding written
here. ML-DSA and SLH-DSA keys cannot be imported from a seed: the module has
no `CKA_SEED`. X25519 and X448 remain unavailable when the FIPS provider is
loaded, which is the signed module's configuration.

## Credits

The SLH-DSA and HashSLH-DSA known answers are NIST's ACVP vectors. The
inventory that found the rest is of Denis Mingulov's `pkcs11-check`, which
had recorded each of these as an xfail; two of its tests read
`CKR_CURVE_NOT_SUPPORTED` and the generic hash-sign mechanisms differently
from the rest of the harness, and are reported upstream
(mingulov/pkcs11-check#51, #63). OpenSC's `pkcs11-tool`, maintained by Jakub
Jelen and the OpenSC team, exercises HashSLH-DSA here, and its proposed
`--encapsulate` / `--decapsulate` (OpenSC#3894) is tested against this
module and against kryoptic. `ACKNOWLEDGEMENTS.md` records who found what.

## Verifying this release

    scripts/release.sh 2.5.0
