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
suite against FreeHSM found three more items, fixed here as well. And the
module offers PKCS#11 mechanisms it did not, for which OpenSSL does the
computation: see *New mechanisms*. Among them, DSA and finite-field
Diffie-Hellman, whose key pair generators were listed and refused until
now; the TLS 1.2 and IKE key derivations; key wrapping in two layers;
RIPEMD-160, BLAKE2b, Camellia, ARIA and RSA X9.31. pkcs11-check 0.3.0 and
Alexandre Laroche's #39 found four more defects on the way, fixed here.

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
- **HMAC takes a generic secret or an HMAC key, and nothing else.** An AES
  or DES3 key used for HMAC is now `CKR_KEY_TYPE_INCONSISTENT`.

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

- Creating one still needs the user's login. So does creating any object:
  PKCS#11 gives a session that is not logged in read/write access to
  public objects, and this module creates none before a login, of any
  class -- the token's store takes no object without the key the login
  unlocks. `C_EncapsulateKey`, which needs only a public key, is therefore
  `CKR_USER_NOT_LOGGED_IN` without a login. Planned for 2.9.0.
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
for one that must not be written in clear. OpenSC/OpenSC#3964 makes
pkcs11-tool leave `CKA_PRIVATE` of a secret key to the token unless
`--private` is given, except for the secret of `--encapsulate`, which it
keeps public (OpenSC/OpenSC#3950).

## Private keys that are not sensitive

PKCS#11 leaves `CKA_SENSITIVE` to the caller. 2.7.0 refused a private key
asked `CKA_SENSITIVE=FALSE`, with `CKR_TEMPLATE_INCONSISTENT`; earlier
versions accepted the template and made the key sensitive anyway. It is now
made as asked, by `C_GenerateKeyPair`, `C_CreateObject` and `C_UnwrapKey`,
in both build profiles.

- A private key that does not name `CKA_SENSITIVE` is sensitive, as before.
- When the key is also `CKA_EXTRACTABLE=TRUE`, `C_GetAttributeValue` gives
  its private value in the form PKCS#11 v3.2 defines: the six RSA
  components, from `CKA_PRIVATE_EXPONENT` to `CKA_COEFFICIENT`; the scalar
  d of an EC key in `CKA_VALUE`; the raw private key of an Edwards,
  Montgomery, ML-KEM, ML-DSA or SLH-DSA key in `CKA_VALUE`. `CKA_SEED` is
  not given.
- A key that is not sensitive but not extractable withholds them:
  `CKR_ATTRIBUTE_SENSITIVE`.
- `CKA_SENSITIVE` can still be set to TRUE afterwards, and not back.
- **In strict mode** the template is refused, as in 2.7.0, and no private
  value is given, not even from a key made not sensitive in permissive mode
  on the same token.
- The composite ML-DSA-65 + Ed25519 key has no private value the standard
  defines, and is refused not sensitive in every mode.
- A private key's value is kept in the secure heap whether it is sensitive
  or not.

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

## More EC curves and RSA sizes

- **EC.** The all-mechanisms build in permissive mode takes Weierstrass
  curves from 192 bits: P-192, P-224 and their neighbours. The
  nist-approved-only build and the strict mode keep the 256-bit floor.
  Elsewhere the floor is the smallest of P-192 and P-224 the loaded
  provider can build: 224 on the OpenSSL FIPS provider, which has P-224 and
  not P-192. `C_GetMechanismInfo` states which applies.
- **RSA.** Keys are generated from 1024 bits in permissive mode, 2048
  otherwise, up to 8192 bits, in steps of 512. Only 2048, 3072 and 4096
  were taken.
- **Signing with an RSA key over 4096 bits** works. It failed, the
  signature buffer having been sized for RSA-4096; an imported key could
  already be that large.

## New mechanisms

PKCS#11 mechanisms the module did not offer, for which OpenSSL does the
computation. Each has its own test, with the published vectors where there
are some (RFC 3962, RFC 4493, RFC 8439, IEEE 1619, FIPS 197, SP 800-38A,
SP 800-67) and otherwise values computed without OpenSSL.

**Approved, in both builds.**

- **HMAC.** The `*_HMAC_GENERAL` mechanisms, HMAC truncated to the length
  asked, for SHA-1, SHA-2 and SHA-3; at least 4 bytes where NIST's rules
  apply. The HMAC key generators `CKM_SHA*_KEY_GEN`, which make keys typed
  `CKK_SHA*_HMAC`.
- **Signatures.** `CKM_ECDSA_SHA224`, `CKM_ECDSA_SHA3_224` to
  `CKM_ECDSA_SHA3_512`, and `CKM_SHA3_224_RSA_PKCS_PSS` to
  `CKM_SHA3_512_RSA_PKCS_PSS`.
- **AES.** OFB, CFB1, CFB8 and CFB128 (CFB64 is not offered: OpenSSL has
  no such cipher). CTS, variant CS3, the one of RFC 3962. XTS, on a new key
  type `CKK_AES_XTS` with its generator `CKM_AES_XTS_KEY_GEN`, one data unit
  per operation. `CKM_AES_CMAC_GENERAL`, at least 8 bytes where NIST's rules
  apply.
- **Key utilities of PKCS#11 v3.2.** `CKM_PUB_KEY_FROM_PRIV_KEY` gives the
  public key of a private key as a new object, for every key type but the
  composite one; it does not ask the private key for `CKA_DERIVE`.
  `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` makes an EC key pair whose private key
  comes from the extra random bits method of FIPS 186-5 A.2.1.
- **`CKM_RSA_AES_KEY_WRAP`.** A fresh AES key wraps the key with AES-KWP
  (RFC 5649) and travels in front of it, RSA-OAEP-encrypted under the
  wrapping key: the format cloud providers take for key import.
- **TLS 1.2** (PKCS#11 v3.2 6.40), through its PRF with SHA-256, SHA-384 or
  SHA-512. The extended master secret of RFC 7627,
  `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE` and `_DH`; the key block,
  `CKM_TLS12_KEY_AND_MAC_DERIVE` and `CKM_TLS12_KEY_SAFE_DERIVE`; and the
  Finished message's verify_data, `CKM_TLS_MAC` (alias `CKM_TLS12_MAC`), in
  `C_Sign` and `C_Verify`.
- **IKE** (PKCS#11 v3.2 6.64), the prf an HMAC on SHA-1, SHA-2 or SHA-3:
  `CKM_IKE_PRF_DERIVE` (SKEYID, SKEYSEED and the IKEv2 rekey),
  `CKM_IKE1_PRF_DERIVE` (SKEYID_d, _a, _e) and `CKM_IKE2_PRF_PLUS_DERIVE`
  (prf+).
- **Finite-field Diffie-Hellman.** PKCS #3 (`CKM_DH_PKCS_KEY_PAIR_GEN`,
  `CKM_DH_PKCS_DERIVE`) on the safe-prime groups of SP 800-56A rev. 3,
  ffdhe and MODP from 2048 to 8192 bits; X9.42 (`CKM_X9_42_DH_KEY_PAIR_GEN`,
  `CKM_X9_42_DH_DERIVE`, with `CKD_NULL` or the SHA-1 concatenation KDF) on
  those groups and on the FB and FC parameter sets, (2048, 224) and (2048,
  256), RFC 5114's 2048-bit groups among them. Both key pair generators
  were listed and refused until now. Where NIST's rules apply, these groups
  alone.

**Not approved, in the all-mechanisms build.** As `CKM_DES3_CBC` and
`CKM_SHA1_RSA_PKCS` already were: `CKM_ECDSA_SHA1`; 3DES in ECB and with
PKCS#7 padding beside CBC, all three in parts as well as single-part; and
`CKM_DES2_KEY_GEN` with the `CKK_DES2` key type, a 16-byte key that every
DES3 mechanism takes as K1 K2 K1.

**Not approved, in the all-mechanisms build in permissive mode only.**
Refused in strict and FIPS mode as well:

- **Key derivation by digest**, the `*_KEY_DERIVATION` mechanisms, SHA-1 to
  SHAKE256 (the SHA-3 and SHAKE ones also named `*_KEY_DERIVE`).
- **Key derivation by encryption**, `CKM_AES_ECB_ENCRYPT_DATA`,
  `CKM_AES_CBC_ENCRYPT_DATA`, `CKM_DES3_ECB_ENCRYPT_DATA` and
  `CKM_DES3_CBC_ENCRYPT_DATA`.
- **`CKM_EXTRACT_KEY_FROM_KEY`**, a run of the bits of a generic secret.
- **CBC-MAC**, `CKM_AES_MAC` and `CKM_AES_MAC_GENERAL`, and the four 3DES
  MACs: `CKM_DES3_CMAC`, `CKM_DES3_CMAC_GENERAL`, `CKM_DES3_MAC` and
  `CKM_DES3_MAC_GENERAL`.
- **ChaCha20, Poly1305 and ChaCha20-Poly1305** (RFC 8439), with
  `CKM_CHACHA20_KEY_GEN`, `CKM_POLY1305_KEY_GEN` and the `CKK_CHACHA20` and
  `CKK_POLY1305` key types, where the loaded provider serves them. The
  OpenSSL FIPS provider does not, and there they are neither listed nor
  accepted.
- **RIPEMD-160**: the digest, `_HMAC`, `_HMAC_GENERAL` and
  `CKM_RIPEMD160_RSA_PKCS`.
- **BLAKE2b** at 160, 256, 384 and 512 bits: digest, HMAC, HMAC_GENERAL,
  key derivation and HMAC key generation, twenty mechanisms, with the
  `CKK_BLAKE2B_*_HMAC` key types. The size is BLAKE2b's own parameter, not a
  truncation of the 512-bit output.
- **Camellia and ARIA**: ECB, CBC, CBC-PAD, CTR (Camellia only: PKCS#11 has
  no ARIA CTR), the CBC-MAC, key generation and the derivations by
  encryption, on `CKK_CAMELLIA` and `CKK_ARIA` keys of 16, 24 or 32 bytes.
- **`CKM_ECDH_AES_KEY_WRAP`**, the two-layer wrapping above with an
  ephemeral EC key in front: the AES key comes from the ECDH with the
  wrapping key, through `CKD_NULL` or the ANSI X9.63 KDF. An EC key may now
  have `CKA_WRAP` and `CKA_UNWRAP`, off unless the template asks.
- **TLS.** The master secret without the session hash
  (`CKM_TLS12_MASTER_KEY_DERIVE` and `_DH`), the RFC 5705 exporter
  (`CKM_TLS_KDF`, alias `CKM_TLS12_KDF`), and `CKM_TLS_MAC` and
  `CKM_TLS_KDF` over the TLS 1.0 and 1.1 PRF (`CKM_TLS_PRF`).
- **IKE.** `CKM_IKE1_EXTENDED_DERIVE`, RFC 2409 appendix B.
- **DSA.** `CKM_DSA_KEY_PAIR_GEN` on the caller's domain parameters, one of
  FIPS 186-4's sizes and validated, and the signatures `CKM_DSA` and
  `CKM_DSA_SHA1` to `CKM_DSA_SHA3_512`, r || s. FIPS 186-5 withdrew DSA.
- **Diffie-Hellman on other groups**: any prime group of 1024 bits and up
  that validates, for PKCS #3 and X9.42.
- **RSA X9.31.** `CKM_RSA_X9_31_KEY_PAIR_GEN`, key pairs of 2048 bits and
  more whose primes are strong in X9.31's sense, and the signatures
  `CKM_RSA_X9_31` and `CKM_SHA1_RSA_X9_31`. FIPS 186-5 withdrew X9.31.

RIPEMD-160, BLAKE2b, Camellia, ARIA, DSA, Diffie-Hellman on other groups
and the X9.31 signatures run only where a provider other than the OpenSSL
FIPS one serves them: the FIPS provider has none of the first four, refuses
DSA and X9.31 signing, and validates only the safe-prime groups by itself.
Under it they are neither listed nor accepted. The X9.31 key pair
generator stays, its keys being RSA keys.

**Points to know.**

- ChaCha20 takes a 32-bit counter with a 96-bit nonce, or a 64-bit counter
  with a 64-bit nonce. Data past the counter is `CKR_DATA_LEN_RANGE`; the
  counter is not carried into the nonce.
- ChaCha20-Poly1305 takes a 12-byte nonce only. Poly1305's key is a
  one-time key, and keeping it so is the caller's.
- In parts, CTS and XTS give all their output at `C_EncryptFinal` /
  `C_DecryptFinal`: the cipher needs the whole message. ChaCha20-Poly1305
  checks its tag at `C_DecryptFinal`, as AES-GCM does.
- Key generation by `CKM_DES2_KEY_GEN` and `CKM_DES3_KEY_GEN` now sets the
  parity bits, as `C_DeriveKey` already did for these types. The cipher
  ignores them.
- The TLS master secret is 48 bytes and gets a `CKA_ALLOWED_MECHANISMS`
  naming the TLS 1.2 mechanisms that take it, which the template may narrow.
  `CKM_TLS12_KEY_AND_MAC_DERIVE` accepts `phKey` NULL.
- DSA and ECDSA signatures are r || s, each half the length of q or of the
  curve's order. A DH agreement gives Z padded to p's length, cut to the
  template's `CKA_VALUE_LEN`.
- X9.42 takes neither `CKD_SHA1_KDF_ASN1` nor the hybrid and MQV forms.
  The FIPS provider cannot validate an FB or FC set without the seed it was
  generated from, which a template does not carry; where it alone serves
  DH, the module checks the set itself: p and q prime, q dividing p - 1, g
  of order q.
- `CKM_RSA_X9_31` signs the caller's hash followed by its trailer ID (0x33
  for SHA-1, 0x34 for SHA-256, ...), at most k - 2 bytes; the module adds
  the header, the padding and the final 0xCC, and gives min(s, n - s). The
  module builds the block itself: OpenSSL's X9.31 padding failed through
  its raw signing call, and its check refuses the block written for k - 3
  bytes of input. A modulus that is not 1024 + 256s bits is
  `CKR_KEY_SIZE_RANGE` for both X9.31 signatures.
- **Not offered**: HOTP and the other OTP mechanisms, which need fields the
  token file does not have yet.

## What did not work

- **`C_SetPIN` changes a PIN** (#36). It failed in every session state. An
  R/W user or SO session now changes its own PIN, and an R/W public session
  the user's. A wrong old PIN is counted and throttled as a failed login.
  Objects are untouched.
- **AES-GCM decrypts in parts** (#35). `C_DecryptFinal` refused every
  ciphertext, because the tag was never set. As with any decryption in
  parts, the earlier parts are given out before the tag is verified; a
  caller that must not act on unauthenticated data uses `C_Decrypt`.
- **An EC public key imports on every curve the module generates on**
  (#39). `C_CreateObject` resolved a public key's curve with a table of the
  three NIST curves, where key generation and private-key import take
  secp256k1 and brainpool in the all-mechanisms build: a peer's secp256k1
  or brainpool public key, or the pair's own `CKA_EC_POINT`, was
  `CKR_CURVE_NOT_SUPPORTED`. All three paths now resolve the curve the same
  way, and the point is still checked on it. Reported by Alexandre Laroche.
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
  `CKR_ATTRIBUTE_VALUE_INVALID` (#37 K2). Likewise a `CKK_DES3` key of
  other than 24 bytes, and the new key types at their own lengths.

**Templates that are now accepted.**

- A private key asked `CKA_SENSITIVE=FALSE`, outside strict mode: made as
  asked, where 2.7.0 answered `CKR_TEMPLATE_INCONSISTENT`. See *Private keys
  that are not sensitive*.

**Return codes.**

- AES-ECB or AES-CBC without padding, encrypting a partial block:
  `CKR_DATA_LEN_RANGE`, not `CKR_FUNCTION_FAILED` (#37 B1).
- The same encrypted in parts, a total that is not whole blocks:
  `CKR_DATA_LEN_RANGE` at `C_EncryptFinal`, not `CKR_FUNCTION_FAILED`.
- AES-ECB, AES-CBC or AES-CBC-PAD, decrypting a partial block, and
  AES-CBC-PAD decrypting nothing: `CKR_ENCRYPTED_DATA_LEN_RANGE`, not
  `CKR_ENCRYPTED_DATA_INVALID` (#37 B2). 3DES-CBC the same.
- `CKM_ECDH1_DERIVE` with no parameter, a KDF other than `CKD_NULL`, or a
  peer value that is not a point of the curve: `CKR_MECHANISM_PARAM_INVALID`,
  not `CKR_ARGUMENTS_BAD` or `CKR_ATTRIBUTE_VALUE_INVALID` (#37 E1, E2).
- An EC private key created without `CKA_EC_PARAMS`:
  `CKR_TEMPLATE_INCOMPLETE`, not `CKR_TEMPLATE_INCONSISTENT` (#33).
- `C_CopyObject` with a new `CKA_VALUE`: `CKR_ATTRIBUTE_READ_ONLY`, not
  `CKR_TEMPLATE_INCONSISTENT` (#33).
- `CKA_OBJECT_ID` on a data object is accepted and kept; 2.7.0 refused it
  with `CKR_ATTRIBUTE_TYPE_INVALID`.
- An HMAC mechanism with a secret key that is neither a generic secret nor
  of an HMAC key type (AES, DES3, ChaCha20, ...): `CKR_KEY_TYPE_INCONSISTENT`
  at `C_SignInit` and `C_VerifyInit`. Only RSA, EC and EdDSA keys were
  refused; found by pkcs11-check 0.3.0 on BLAKE2b and RIPEMD-160 HMAC.
- A key derivation by digest to a key type without a length of its own,
  AES among them, with no `CKA_VALUE_LEN`: `CKR_TEMPLATE_INCOMPLETE`
  (PKCS#11 v3.2 6.20.5). The key was made at the digest's length.
- A mechanism no loaded provider serves: `CKR_MECHANISM_INVALID` at its
  Init, as `C_GetMechanismList` already left it out, rather than a failure
  at the first operation.

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
`tests/fixtures/token-v4.tok` written by v2.7.0. Also new:
`tests/test_key_sizes.c` and `tests/test_private_not_sensitive.c`.
Extended: `tests/test_private_attr.c`, `tests/test_template_checks.c` and
`tests/test_finalize_release.c`. For the new mechanisms:
`tests/test_hmac_general.c`, `tests/test_hmac_keygen_derive.c`,
`tests/test_sig_sha3_family.c`, `tests/test_aes_feedback_modes.c`,
`tests/test_aes_mac_family.c`, `tests/test_aes_cts.c`,
`tests/test_aes_xts.c`, `tests/test_encrypt_data_derive.c`,
`tests/test_des3_modes.c`, `tests/test_des3_mac_family.c`,
`tests/test_des2_keys.c`, `tests/test_chacha20_poly1305.c`,
`tests/test_chacha20_poly1305_aead.c`, `tests/test_extract_pub_from_priv.c`
and `tests/test_ec_extra_bits.c`; then `tests/test_ripemd160.c`,
`tests/test_blake2b.c`, `tests/test_camellia_aria.c`,
`tests/test_rsa_ecdh_aes_wrap.c`, `tests/test_tls12_kdf.c`,
`tests/test_ike_prf.c`, `tests/test_dsa.c`, `tests/test_dh_pkcs.c`,
`tests/test_dh_x942.c` and `tests/test_rsa_x931.c`, and for #39
`tests/test_ec_pub_import_curves.c`. CI now runs `make tests` against
OpenSSL's default provider in both profiles, as it did against the FIPS
provider. python-pkcs11's own suite passes against
this release but for one that needs what FreeHSM does not offer by design,
`C_SeedRandom`. Its P-192 test passes in the all-mechanisms build in
permissive mode.

`make tests` in both profiles, green. Under pkcs11-check 0.2.3, the 28
failures of 2.7.0 that asked for a private key that is not sensitive
(mingulov/pkcs11-check#72) pass now that such a key is made, and are no
longer listed. Its tests of `CKM_EXTRACT_KEY_FROM_KEY` derive a generic
secret without `CKA_VALUE_LEN`; the module answers
`CKR_TEMPLATE_INCOMPLETE`, which they record as an expected refusal.

CI now runs pkcs11-check 0.3.0. By hand, full corpus, unsigned module:
- nist-approved-only (2026-11-19): 60,484 passed and 1 failed;
- all-mechanisms (2026-11-20): 81,252 passed and 23 failed;
- all-mechanisms again (2026-11-21, this release's mechanisms included):
  81,300 passed and 4 failed.

Of the 23, 21 were the module's -- the HMAC key types and the digest
derivation above -- and are fixed. The four left are the harness's, and
listed in `tests/pkcs11_check_known_failures.txt`:
- its CTS variant detection runs in a session that is not logged in, so
  7,499 `CKM_AES_CTS` vectors are skipped (mingulov/pkcs11-check#89, the
  one nist-approved-only failure as well);
- `test_camellia_ctr_different_nonces` encrypts twice with the same counter
  block and expects two ciphertexts (mingulov/pkcs11-check#92);
- two X9.31 tests whose oracle reads only s^e mod n, where X9.31 signs
  min(s, n - s): about half of correct signatures fail it
  (mingulov/pkcs11-check#94).

In the signed CI jobs, the one failure is an X25519 import the FIPS
provider cannot serve (mingulov/pkcs11-check#93).

Since #39, 8,433 Wycheproof ECDSA vectors on brainpool and secp256k1 run
and pass in the all-mechanisms build under the default provider; before,
their public key was refused and they were skipped.

## Verifying this release

    scripts/release.sh 2.8.0
