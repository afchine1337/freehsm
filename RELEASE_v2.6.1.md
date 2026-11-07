<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.6.1

A security release. `C_WrapKey` wrapped a key whose `CKA_EXTRACTABLE` is
FALSE unless the key was also sensitive, so a logged-in session could take
such a key out of the token under a wrapping key it knew. It is fixed, with
four conformance fixes found by the same run of pkcs11-check 0.3.0.

**Upgrade.** The wrapping defect reaches every published release since
v1.1.0. The upgrade is a drop-in replacement of the module; token files are
read as they are.

One security advisory accompanies this release; `SECURITY.md` has it.

---

## `C_WrapKey` and unextractable keys

### What was wrong

PKCS#11 v3.2 §5.18.5 requires the key to be wrapped to have
`CKA_EXTRACTABLE=TRUE`. `C_WrapKey` refused only a key that was both
sensitive and not extractable. `CKA_SENSITIVE` defaults to FALSE, so a key
created with `CKA_EXTRACTABLE=FALSE` alone was wrapped on request, while
`C_GetAttributeValue` withheld its value for the same flag. A key cleared to
FALSE by `C_SetAttributeValue` or `C_CopyObject` went the same way, and so
did the outputs of the byte-level derivations and of HKDF.

### What changed

A private or secret key whose `CKA_EXTRACTABLE` is FALSE is refused
`CKR_KEY_UNEXTRACTABLE`, sensitive or not, the size query included.

### If you ran an affected version

Keys created with both `CKA_SENSITIVE=TRUE` and `CKA_EXTRACTABLE=FALSE` were
never wrapped. For the others, `SECURITY.md` says what to do.

## Answers that change

Each of these answered against PKCS#11 v3.2 and now answers as it says. A
caller that relied on the old answer meets the new one.

- **An RSA, EC, Edwards or Montgomery public key has no `CKA_VALUE`.** The
  module returned the SubjectPublicKeyInfo it stores; it now answers
  `CKR_ATTRIBUTE_TYPE_INVALID`. Read `CKA_MODULUS` and
  `CKA_PUBLIC_EXPONENT`, or `CKA_EC_PARAMS` and `CKA_EC_POINT`, as
  `pkcs11-tool --read-object` does. ML-KEM, ML-DSA and SLH-DSA public keys
  keep their raw `CKA_VALUE`.
- **Unwrapped and encapsulated keys are extractable unless the template says
  otherwise** (§5.18.6, §5.18.8, §5.18.9). They stay sensitive by default, so
  their values are still withheld; they can be wrapped again. A template
  with `CKA_EXTRACTABLE=FALSE` keeps them in.
- **`C_Logout` destroys the private session objects and invalidates the
  handles to private objects** (§5.6.8), for every session on the token,
  and closing the last session does the same. Private token objects stay,
  under new handles that `C_FindObjects` returns.

## Other fixes

- A DES, DES2, DES3 or CDMF key derived by concatenation, XOR, HKDF or ECDH
  gets its parity bits set. DES ignores them; no result changes.
- `C_EncapsulateKey` and `C_DecapsulateKey` give the new key the attributes
  §5.18.8 and §5.18.9 define, and refuse a template they cannot honour.
- `C_UnwrapKey` decrypts into the secure heap instead of a 4 KiB stack
  array, which also lets it take a wrapped ML-DSA-87 private key (#29).
- Audit events `encapsulate` (86) and `decapsulate` (87), appended.

## Measured

New: `tests/test_wrap_unextractable.c` (six wrapping cases, the unwrap
default), `tests/test_pub_value_absent.c` (four key types and an ML-DSA
control), `tests/test_derive_des_parity.c` (four key types, two mechanisms,
a generic control), and a logout case in `tests/test_session_objects.c`.

`make tests` in both profiles, green. pkcs11-check 0.3.0, run from its main
branch before release: of the 55 failures in `nist-approved-only`, the
wrapping (21), unwrap default (1), public `CKA_VALUE` (3), DES parity (16)
and logout session-object (1) failures are fixed. Not in this release:
`CKA_PRIVATE` is still set by class, and a byte-level derivation that asks
for a less protected key than its base is still given the base's
protection without being refused.

## Verifying this release

    scripts/release.sh 2.6.1
