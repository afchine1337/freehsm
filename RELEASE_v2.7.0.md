<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.7.0

A minor release with a security fix. A data object created with
`CKA_PRIVATE=TRUE` could be found and read by a session with nobody logged
in, once the user had logged out in the same process. With the SO logged
in, key wrapping, unwrapping and derivation also reached the user's private
objects and keys. Access now follows `CKA_PRIVATE`. The rest is conformance: places where the module answered
`CKR_OK` for a template it did not follow, or refused with the wrong error,
most of them reported by Alexandre Laroche.

**Upgrade.** The disclosure reaches every release since v1.5.0. The module
is a drop-in replacement and token files are read as they are, but several
calls now answer differently: read *Answers that change* below before
upgrading an application that relies on them.

One security advisory accompanies this release; `SECURITY.md` has it.

---

## Private data objects and `CKA_PRIVATE`

### What was wrong

PKCS#11 v3.2 §4.4 keeps a private object from anyone who has not
authenticated as the normal user. FreeHSM decided by class: only secret and
private keys were hidden from an unauthenticated session. A data object
reported `CKA_PRIVATE=TRUE` and was still listed and read once the user had
logged out. With the SO logged in, `C_SetAttributeValue`, `C_CopyObject`
and `C_DestroyObject` reached private objects through a guessed handle, and
so did `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey` and `C_DecapsulateKey`. The
SO wrapped the user's private data objects and extractable keys under an RSA
public key it had imported. `C_UnwrapKey` and `C_DeriveKey` accepted
`CKA_CLASS=CKO_DATA`, so the user's private key decrypted for the SO what was
sent to the user, and a non-extractable secret key was copied into a data
object that `C_WrapKey` then wrapped. And a data object created with `CKA_PRIVATE=FALSE` -- what
`pkcs11-tool --write-object` sends without `--private` -- read back TRUE.

### What changed

- Access follows `CKA_PRIVATE` in every call that takes an object handle, and
  in the search. A private object is `CKR_OBJECT_HANDLE_INVALID` to anyone
  but the user.
- A data object's `CKA_PRIVATE` is the template's. One created or copied with
  `CKA_PRIVATE=FALSE` is public: found and read before a login, stored in the
  token file's public section, kept across a `C_Logout`. Without the
  attribute a data object is private.
- Only the user makes a private object; the SO makes public ones (#31).
- Every key handle of `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey` and the KEM
  calls is checked before anything else, and a hidden key answers like a
  missing one.
- `C_UnwrapKey`, `C_DeriveKey` and the KEM calls make keys only
  (`CKM_HKDF_DATA` a data object): another `CKA_CLASS` is
  `CKR_TEMPLATE_INCONSISTENT`. `C_WrapKey` wraps private and secret keys
  only: a data object is `CKR_KEY_HANDLE_INVALID`, a public key
  `CKR_KEY_NOT_WRAPPABLE`.

### If you ran an affected version

An application that keeps secrets in data objects and logs out while other
code can run in its process should treat those values as exposed. One that
read data objects without logging in must log in after the upgrade, or
recreate them with `CKA_PRIVATE=FALSE`. Where the SO PIN is held by someone
the user's keys must be kept from, the user's extractable keys, derivable
generic secrets and data sent to the user's decryption keys were within that
person's reach.

## Answers that change

Each of these answered against PKCS#11 v3.2 and now answers as it says.

**Templates that were not followed are refused.**

- RSA key pair generation without `CKA_MODULUS_BITS`, and EC, Edwards or
  Montgomery generation without `CKA_EC_PARAMS`: `CKR_TEMPLATE_INCOMPLETE`.
  A 2048-bit key, or P-256, Ed25519 or X25519, was chosen silently.
- `C_GenerateKey` with a `CKA_KEY_TYPE` or `CKA_CLASS` the mechanism does not
  make: `CKR_TEMPLATE_INCONSISTENT`.
- A private key asked `CKA_SENSITIVE=FALSE`, generated, imported or
  unwrapped: `CKR_TEMPLATE_INCONSISTENT`. Private keys here are always
  sensitive. pkcs11-tool sends `CKA_SENSITIVE=TRUE` for them.
- `CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`,
  `CKA_KEY_GEN_MECHANISM` and `CKA_UNIQUE_ID` in a creation template:
  `CKR_ATTRIBUTE_READ_ONLY`.
- `CKA_OBJECT_ID` on a data object: `CKR_ATTRIBUTE_TYPE_INVALID`. It has no
  place in the token file yet and was dropped.
- A concatenation or XOR derivation asking for less protection than its base
  key: `CKR_TEMPLATE_INCONSISTENT`. Since 2.6.0 it was sealed anyway.
- `CKM_ECDH1_DERIVE` with `CKD_NULL` and shared data:
  `CKR_MECHANISM_PARAM_INVALID`.

**Templates that are now followed.**

- `CKA_PUBLIC_EXPONENT` is the RSA key's exponent, within FIPS 186-5 (odd,
  2^16 < e < 2^256). It was replaced by 65537. Other values, e = 3 included,
  are `CKR_ATTRIBUTE_VALUE_INVALID`.
- `CKM_ECDH1_DERIVE` truncates by `CKA_KEY_TYPE` and `CKA_VALUE_LEN`, keeping
  the trailing bytes of the shared secret (§6.3.16). All of it was stored.
  A generic secret derived without `CKA_VALUE_LEN` is unchanged.
- `C_FindObjects` matches every attribute of the template. It matched the
  class, label and id only, so `{CKA_TOKEN=FALSE}` found token objects too.

**Limits that are now enforced.**

- AES-CTR refuses data past the room `ulCounterBits` leaves, with
  `CKR_DATA_LEN_RANGE` (§6.11.3). The counter carried into the nonce.
- A hashing `CKM_SHAxxx_RSA_PKCS_PSS` refuses a `hashAlg` other than its own.
- A read-only session copying a token object without naming `CKA_TOKEN`:
  `CKR_SESSION_READ_ONLY` (#30).

**Return codes.**

- A second `C_Initialize`: `CKR_CRYPTOKI_ALREADY_INITIALIZED` (#32), not
  `CKR_FUNCTION_FAILED`.
- An RSA private key's private components: `CKR_ATTRIBUTE_SENSITIVE`.
- Setting key material the object carries: `CKR_ATTRIBUTE_READ_ONLY`.
- An attribute read into a buffer too small: `CKR_BUFFER_TOO_SMALL`.
- An AES-GCM tag length GCM does not have: `CKR_MECHANISM_PARAM_INVALID`.
- `C_DestroyObject` of an unknown handle: `CKR_OBJECT_HANDLE_INVALID`.
- `C_GetMechanismInfo` states `CKM_GENERIC_SECRET_KEY_GEN`'s range in bits,
  8 to 512, as §6.8.3 has it.

## Measured

New: `tests/test_private_attr.c` (eleven cases: the template, access before
and after a login, a new process image, the SO, read-only copies, key
wrapping, unwrapping and derivation),
`tests/test_aes_ctr_counter_bits.c`, `tests/test_ecdh_key_len.c`,
`tests/test_attr_rv.c` and `tests/test_template_checks.c`. Extended:
`tests/test_finalize_release.c`, `tests/test_rsa_pss_raw.c`,
`tests/test_key_history.c`, `tests/test_generic_secret_len.c` and
`tests/test_template_id.c`.

`make tests` in both profiles, green.

## Verifying this release

    scripts/release.sh 2.7.0
