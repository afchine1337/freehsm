<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.8.0

A minor release, with no security fix. It is the rest of Alexandre
Laroche's retest of 2.7.0 (#34 to #38, and three neighbours of #33): two
functions that did not work, `C_SetPIN` and AES-GCM decryption in parts;
key usages that now follow the key type; templates that are now followed;
and refusals that now carry the return code that names what is wrong.
`CKA_OBJECT_ID`, `CKA_KEY_GEN_MECHANISM` and two certificate hashes are now
stored, which takes a new token file format. Running python-pkcs11's test
suite against FreeHSM found three more items, fixed here as well.

**Upgrade.** Three things to read before upgrading:

- **The token file format is now v5, and the change is one way.** Tokens
  written by earlier versions are read as they are and rewritten as v5 at
  their first change. 2.7.0 cannot use a token that 2.8.0 has written: the
  login succeeds, then every call that needs the objects answers
  `CKR_USER_NOT_LOGGED_IN`, and the file is left as it is. Keep a copy of
  the token directory if a return to an earlier version must stay
  possible.
- **A secret key created with `CKA_PRIVATE=FALSE` is now a public object.**
  pkcs11-tool asks for exactly that unless `--private` is given.
- **An EC or Montgomery key made without `CKA_DERIVE=TRUE` no longer
  derives.**

The sections below give the details. Several calls also answer with
different return codes: see *Answers that change*.

---

## The token file: format v5

Two attributes had no field in the token file. `CKA_OBJECT_ID` of a data
object was accepted and dropped up to 2.6.1, then refused in 2.7.0.
`CKA_KEY_GEN_MECHANISM` could not be read at all: the key type does not
tell it, since `CKM_PKCS5_PBKD2` makes AES and generic secret keys as the
plain generators do.

- A data object keeps its `CKA_OBJECT_ID` (#38). `C_GetAttributeValue`
  reads it back, `C_FindObjects` matches it, `C_SetAttributeValue` changes
  it, and `C_CopyObject` carries or replaces it. It is at most 64 bytes,
  kept as given, and empty when never set. A public data object has it
  before a login too.
- `CKA_KEY_GEN_MECHANISM` is the mechanism `C_GenerateKey` or
  `C_GenerateKeyPair` was called with, on both halves of a pair, and a copy
  keeps it (#37 K3). A key that was imported, unwrapped, derived or
  decapsulated reads `CK_UNAVAILABLE_INFORMATION`. So does a key generated
  by 2.7.0 or earlier, whose mechanism was never stored.

- A certificate keeps `CKA_HASH_OF_SUBJECT_PUBLIC_KEY` and
  `CKA_HASH_OF_ISSUER_PUBLIC_KEY`. Both were accepted at creation and could
  not be read back. They are stored as given, at most 64 bytes each, and
  fixed once the certificate exists.

The v5 record is the v4 one with 208 more bytes per object. The magic
changes, so a build that predates v5 does not load the objects, and so
cannot rewrite them without the new fields. Checked with 2.7.0: the login
succeeds, the search answers `CKR_USER_NOT_LOGGED_IN`, and the file is
unchanged. `docs/TOKEN_STORE_FORMAT.md` describes it.
`tests/test_v4_fixture.c` loads a token written by v2.7.0.

## Secret keys and `CKA_PRIVATE`

A secret key created with `CKA_PRIVATE=FALSE` was accepted and kept
private, and read back TRUE (#37 K1). It is now a public object, as
PKCS#11 v3.2 §4.4 has it: a session that is not logged in finds it and can
use it. Data objects have worked this way since 2.7.0.

- Creating one still needs the user's login.
- One that is not sensitive is written in the token file's public section,
  which is in clear, so that it can be found before a login. One that is
  sensitive is not written there, and is seen after a login.
- A copy may make a public secret key private, not the reverse:
  `CKA_PRIVATE=FALSE` in the copy of a private secret key is
  `CKR_ATTRIBUTE_READ_ONLY`.
- Keys already in a token keep the privacy they had.

**With pkcs11-tool.** It sends `CKA_PRIVATE=FALSE` for the secret keys it
generates, imports, derives with HKDF, encapsulates and decapsulates,
unless `--private` is given. Its plain commands now make public secret
keys. Give `--private` for a key that must need a login, and `--sensitive`
for one that must not be written in clear. OpenSC/OpenSC#3950 proposes that
pkcs11-tool stop sending `CKA_PRIVATE=FALSE` for secret keys.

## Key usages follow the key type

The usages of a new private or public key came from its class alone (#34).
A P-256 key asked for `CKA_SIGN` also reported `CKA_DERIVE=TRUE` and could
be used for ECDH, and an X25519 key reported `CKA_SIGN=TRUE`. Every
creation path now reads one table:

- RSA: decrypt, sign and unwrap; encrypt, verify and wrap for the public
  key.
- EC: sign, and derive when asked; verify for the public key.
- Edwards, ML-DSA, SLH-DSA and the composite key: sign; verify.
- Montgomery: derive when asked, and nothing else.
- ML-KEM: none of these; it has `CKA_ENCAPSULATE` and `CKA_DECAPSULATE`.

`CKA_DERIVE` is FALSE unless the template says TRUE, the default PKCS#11
v3.2 gives it. An EC or Montgomery key made without it no longer derives,
and `C_DeriveKey` answers `CKR_KEY_FUNCTION_NOT_PERMITTED`. pkcs11-tool
names the usages it wants, so its commands are unaffected. Keys already in
a token keep the usages they were stored with.

A usage the type does not have, asked TRUE, is accepted and reads back
FALSE. That is a deviation, kept because pkcs11-tool asks for such usages
by default: `CKA_DERIVE` for an Edwards key pair, `CKA_SIGN` for a
Montgomery one, `CKA_DECRYPT` for any private key it unwraps.

## What did not work

- **`C_SetPIN` changes a PIN** (#36). It failed in every session state. An
  R/W user or SO session now changes its own PIN, and an R/W public session
  the user's. A wrong old PIN is counted and throttled as a failed login.
  Objects are untouched.
- **AES-GCM decrypts in parts** (#35). `C_DecryptFinal` refused every
  ciphertext, because the tag was never set. As with any decryption in
  parts, the earlier parts are given out before the tag is verified; a
  caller that must not act on unauthenticated data uses `C_Decrypt`.
- **A single-part call no longer ends a multi-part operation** (#37 M1).
  `C_Digest` after `C_DigestUpdate` gave the digest of its own data alone.
  `C_Digest`, `C_Sign`, `C_Verify`, `C_Encrypt` and `C_Decrypt` now answer
  `CKR_OPERATION_ACTIVE` after an Update, and the operation ends.
- **An operation no longer carries on in the context of one that failed.**
  A MAC, encryption or decryption in parts that ended on an error after its
  first Update kept its context. The next operation in parts of the same
  kind in the session reused it: the earlier key, IV and parts, whatever
  its own Init named. It took a failed call by the application itself, in
  the same session. Found while testing the item above.

## What python-pkcs11 found

Running python-pkcs11's test suite against FreeHSM, ahead of a proposal to
add FreeHSM to its CI, found three items beyond the certificate hashes
above.

- **`CKR_CRYPTOKI_NOT_INITIALIZED`.** The module never answered it. After
  `C_Finalize`, `C_GetSlotList`, `C_GetInfo` and the rest went on answering
  `CKR_OK`. Every function but `C_Initialize`, `C_GetFunctionList` and the
  interface functions now answers `CKR_CRYPTOKI_NOT_INITIALIZED` before
  `C_Initialize` and after `C_Finalize`. An application that called the
  module there gets that code instead of an answer.
- **EC capability flags.** `C_GetMechanismInfo` now reports `CKF_EC_F_P`,
  `CKF_EC_OID` and `CKF_EC_UNCOMPRESS` for the Weierstrass EC mechanisms.
  It reported none, which read as "no named curve".

## Answers that change

**Templates that are now refused.**

- `C_GenerateKeyPair` with a `CKA_CLASS` or `CKA_KEY_TYPE` other than the
  mechanism's, in either template: `CKR_TEMPLATE_INCONSISTENT`, and no key
  is made (#33).
- `C_CreateObject` of a secret key of an asymmetric type, or of a private
  key of a secret type: `CKR_TEMPLATE_INCONSISTENT` (#33).
- `C_CreateObject` of an AES key whose value is not 16, 24 or 32 bytes:
  `CKR_ATTRIBUTE_VALUE_INVALID` (#37 K2).

**Return codes.**

- AES-ECB or AES-CBC without padding, encrypting a partial block:
  `CKR_DATA_LEN_RANGE`, not `CKR_FUNCTION_FAILED` (#37 B1).
- AES-ECB, AES-CBC or AES-CBC-PAD, decrypting a partial block, and
  AES-CBC-PAD decrypting nothing: `CKR_ENCRYPTED_DATA_LEN_RANGE`, not
  `CKR_ENCRYPTED_DATA_INVALID` (#37 B2).
- `CKM_ECDH1_DERIVE` with no parameter, a KDF other than `CKD_NULL`, or a
  peer value that is not a point of the curve: `CKR_MECHANISM_PARAM_INVALID`,
  not `CKR_ARGUMENTS_BAD` or `CKR_ATTRIBUTE_VALUE_INVALID` (#37 E1, E2).
- An EC private key created without `CKA_EC_PARAMS`:
  `CKR_TEMPLATE_INCOMPLETE`, not `CKR_TEMPLATE_INCONSISTENT` (#33).
- `C_CopyObject` with a new `CKA_VALUE`: `CKR_ATTRIBUTE_READ_ONLY`, not
  `CKR_TEMPLATE_INCONSISTENT` (#33).
- `CKA_OBJECT_ID` on a data object is accepted and kept; 2.7.0 refused it
  with `CKR_ATTRIBUTE_TYPE_INVALID`.

## Corrections to the 2.7.0 notes

Two sentences of the 2.7.0 notes were inexact, both about the refusal of
`CKA_SENSITIVE=FALSE` on a private key.

- They list it among answers that now follow PKCS#11 v3.2. It is this
  module's choice, not a rule of the standard: §4.1.1 lets a token refuse a
  template that goes against a requirement of its own, and another token
  may accept the same template.
- They say pkcs11-tool sends `CKA_SENSITIVE=TRUE` for private keys. That
  holds for the keys it generates and imports. `pkcs11-tool --unwrap` sends
  `CKA_SENSITIVE=FALSE` unless `--sensitive` is given, so unwrapping a
  private key needs `--sensitive`.

## Measured

New: `tests/test_set_pin.c`, `tests/test_gcm_multipart_decrypt.c`,
`tests/test_single_part_after_update.c`, `tests/test_usage_defaults.c`,
`tests/test_len_and_param_rv.c`, `tests/test_class_type_checks.c`,
`tests/test_store_v5.c` and `tests/test_v4_fixture.c`, with the fixture
`tests/fixtures/token-v4.tok` written by v2.7.0. Extended:
`tests/test_private_attr.c`, `tests/test_template_checks.c` and
`tests/test_finalize_release.c`. python-pkcs11's own suite passes against
this release but for tests that need what FreeHSM does not offer by design:
`C_SeedRandom`, and the P-192 curve.

`make tests` in both profiles, green. pkcs11-check 0.2.3: every failure is
listed in `tests/pkcs11_check_known_failures.txt`, 31 in `all-mechanisms`
and 30 in `nist-approved-only`. 28 of them ask for a private key that is
not sensitive (mingulov/pkcs11-check#72); 2.7.0 was released before they
were listed.

## Verifying this release

    scripts/release.sh 2.8.0
