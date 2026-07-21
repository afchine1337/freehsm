# pkcs11-check Findings Triage (#125)

*First external-harness run, 2026-07-10, against libfreehsm-fips.so
(v1.4.0 line + #108/#110). pkcs11-check by Denis Mingulov.*

Headline counts: **162 passed · 691 xfailed · 517 failed · 7 crashed · 5 error**.

Per the harness's own guidance, large xfail/fail counts are expected:
PKCS#11 cannot express many capability constraints, so one gap fans out
across thousands of vectors. Counts are evidence to triage, not defects
in the harness. This document records the triage.

## Fixed

### F1 — C_Decrypt NULL-pointer dereference (SIGSEGV) — FIXED
* **Finding**: `test_operation_termination::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-*]` crashed the run with SIGSEGV.
* **Root cause**: `C_Decrypt` dereferenced `pulDataLen` on every path
  (size-query and copy) with no NULL check, unlike `C_Encrypt` which
  guarded `pulEncLen`. A caller (or the harness's NULL-argument probe)
  passing `pulDataLen = NULL` triggered a NULL-pointer dereference.
* **Fix**: reject `pulDataLen == NULL` (and `pEncryptedData == NULL`
  with a non-zero length) with `CKR_ARGUMENTS_BAD`, terminating the
  operation so the session is not stranded. The symmetric
  `pData`-with-length guard was added to `C_Encrypt`.
* **Confirmed** in the sandbox: negative control (guard removed) exits
  139/SIGSEGV; with the fix, `CKR_ARGUMENTS_BAD` (0x7).
* **Regression test**: `tests/test_decrypt_null_args.c`, wired into
  `make tests` (drives the public API via `dlopen`).
* **Follow-up (2026-07-10)**: the re-run (crashes 7 → 4) showed the same
  NULL-deref class in the multi-part update entry points.
  `C_EncryptUpdate` and `C_DecryptUpdate` dereferenced their length
  out-parameter without a NULL check ; both now guarded, negative-
  control confirmed, and covered by the same regression test (GCM
  `C_EncryptUpdate` probe).
* Threat-model note: a NULL-deref in a TSFI entry point is an
  availability/robustness defect (AVA_VAN class). No key material is
  exposed; no CVE requested (same informational-disclosure posture as
  the v1.2.x GHSA line).

### F2 — Mechanism advertisement drifted from the dispatch table — FIXED
* **Finding**: pkcs11-check reported several implemented mechanisms as
  "missing" (EdDSA, HKDF_DERIVE, ML-DSA, ML-DSA/SLH-DSA key-pair-gen).
* **Root cause**: `C_GetMechanismList` / `C_GetMechanismInfo` were a
  hand-maintained list + `switch` that had drifted from the generated
  dispatch table. Concretely: PQ mechanisms advertised under stale
  values (ML-DSA `0x403F` instead of the dispatched `0x4024`), phantom
  `FALCON`/`KYBER` entries with no handler, and ~40 dispatched
  mechanisms (all SHA-3/SHAKE, KMAC, HKDF, EdDSA, X25519/X448, ML-KEM/
  ML-DSA/SLH-DSA at correct values) never advertised. PQ signatures
  were therefore undiscoverable.
* **Fix**: both functions now derive from `fhsm_mechanism_table[]` (the
  generated single source of truth). Advertise iff a mechanism resolves
  to a real handler in the active profile. Coherence guard
  `tests/test_mech_advertise.c`.
* **General-purpose / FIPS-by-config note**: the module is intended as a
  general-purpose PKCS#11 provider that switches to FIPS by profile.
  The advertisement machinery is now profile-correct (interop advertises
  every real handler; fips-strict only approved). However, the 12
  currently-declared non-FIPS mechanisms (MD5, SHA-1, DES, RC4, DSA, DH,
  ...) have `dispatch_reject_fips` hardcoded in the Mech table, so they
  are rejected in *both* profiles today — i.e. general-purpose support
  for those is scaffolded but not yet implemented. Realizing it is a
  separate item: implement their real handlers and set the Mech
  `handler` to the real symbol (interop keeps it, fips-strict rejects),
  after which they will be advertised in interop automatically.

### F3 — TSFI robustness: NULL pointers & integer-overflow counts (SIGSEGV/SIGBUS) — FIXED
* **Finding**: 21 subprocess-isolated crashes (reported `failed`, not
  `crashed`, because the harness runs each raw probe in a child):
  `security/test_api_boundary` (NULL template + non-zero count),
  `security/test_arithmetic_overflow` (`template_count` = `ULONG_MAX`,
  `sizeof`-overflow, `0x100000000`), and `security/test_ffi_null_pointer`
  (NULL data pointer + non-zero length) on `C_FindObjectsInit`,
  `C_GenerateKey`, `C_GenerateKeyPair`, and `C_Sign`/`C_Verify`/`C_Digest`
  (one-shot and `*Update`).
* **Root cause**: template-consuming entry points iterated the caller
  array (`find_attr`, the `C_FindObjectsInit` loop) with no guard, so a
  NULL pointer dereferenced and an absurd count walked far out of bounds
  (SIGBUS on the `ULONG_MAX` case). The data entry points passed the
  caller pointer straight to the digest/HMAC/EVP path, dereferencing NULL
  when the length was non-zero.
* **Fix**: a shared `fhsm_check_template()` guard rejects
  `pTemplate == NULL && ulCount != 0` and any `ulCount` above a generous
  ceiling (`FHSM_MAX_TEMPLATE_ATTRS`, default 1024) with
  `CKR_ARGUMENTS_BAD`, before any iteration; the data entry points reject
  `pData == NULL && ulDataLen != 0` (terminating the active operation).
  An empty template / zero-length NULL buffer stays legal.
* **Confirmed** in the sandbox: a fork-per-probe negative control shows
  all four representative probes crash (signal 11 / signal 7) before the
  fix and return `CKR_ARGUMENTS_BAD` after.
* **Regression test**: `tests/test_robustness_args.c`, wired into
  `make tests` (in-process via `dlopen`, so a regression faults the
  test). The full `security/*` subset re-run is done via `make
  pkcs11-check` (needs opensc + pkcs11-check).
* Threat-model note: same AVA_VAN availability/robustness class as F1; no
  key material exposed, no CVE requested.

### F4 — Operation-state hygiene: session reuse & buffer-too-small — FIXED
* **Finding**: ~18 `CKR_OPERATION_ACTIVE` failures where a param/handle
  error was expected (`ckr/test_ckr_{sign,encrypt,decrypt}Init`,
  `TestOperationActive`), plus `TestBufferTooSmall::test_sign_buffer_too_small`
  returning `CKR_FUNCTION_FAILED` (0x6) instead of `CKR_BUFFER_TOO_SMALL`.
* **Root cause (state bleed)**: PKCS#11 session handles come from a
  reusable pool, but neither `C_OpenSession` nor `C_CloseSession` reset
  the per-session operation slots. A session closed mid-operation left
  `active == 1`, and the next `C_OpenSession` handed the same handle back
  dirty, so the first `C_*Init` returned `CKR_OPERATION_ACTIVE` before it
  could validate its own arguments. Secondary: `C_EncryptUpdate` /
  `C_DecryptUpdate` did not clear `active` on their error paths.
* **Root cause (buffer)**: `C_Sign`'s asymmetric path signed straight
  into the caller buffer, so an undersized buffer made OpenSSL fail with
  `CKR_FUNCTION_FAILED` rather than the spec's `CKR_BUFFER_TOO_SMALL`.
* **Fix**: `fhsm_session_ops_reset()` frees the EVP contexts and zeroes
  every per-session slot (encrypt/decrypt/sign/verify/digest, object
  search, OAEP); called on both `C_OpenSession` and `C_CloseSession`.
  The `*Update` error paths now clear `active`. `C_Sign` signs into a
  scratch buffer sized to the mechanism, returns `CKR_BUFFER_TOO_SMALL`
  with the required length when the caller buffer is short, and keeps the
  operation active for retry.
* **Regression test**: `tests/test_op_state.c` (session-reuse no-bleed +
  `C_Sign` buffer-too-small + retry), wired into `make tests`.
* **Residual**: the 3 raw `TestOperationActive` double-init probes and
  the AES-CBC-PAD / AES-CTR `terminates_after_multipart` cases exercise
  non-GCM multipart, which is a separate feature gap (multipart is
  currently GCM-centric) tracked apart from this state-hygiene fix.

### F5 — Object-store exhaustion under the harness (CKR_DEVICE_MEMORY) — MITIGATED + follow-up
* **Finding**: ~119 `CKR_DEVICE_MEMORY` (0x131) failures fanned out
  across dozens of unrelated classes (TestObjectSearch, TestECDSASignature,
  TestRSAOAEPRoundtrip, TestSessionObjectLifecycle, RO-session suites, ...).
* **Root cause**: two layers.
  1. *Immediate (masking)*: the token object store is a fixed
     `FHSM_MAX_OBJECTS` array (default 64). A full pkcs11-check run creates
     far more objects than that, so once the store fills every later test
     that creates an object fails with `CKR_DEVICE_MEMORY`, regardless of
     what it was actually testing.
  2. *Deeper (real defect)*: `CKA_TOKEN` is not honoured — every created
     object is treated as a persistent token object and written to the
     `.tok` file, and **session objects are never destroyed when their
     session closes**. So the store only ever grows within a run. This
     also fails the object-lifecycle suites directly
     (TestSessionObjectLifecycle, TestROSessionObjectsAllowed,
     TestROTokenObjectCreation).
* **Mitigation (this change)**: `make pkcs11-check` and the CI workflow
  build the module under test with `FHSM_MAX_OBJECTS=4096` (an
  `#ifndef`-guarded, `-D`-overridable cap), so store exhaustion no longer
  masks unrelated findings. The default shipped build is unchanged (64).
* **Follow-up (tracked)**: implement PKCS#11 session-object semantics —
  parse `CKA_TOKEN`, keep session objects (`CKA_TOKEN=FALSE`) in memory
  only (not persisted), and destroy them in `C_CloseSession`. That is the
  correct fix and additionally clears the object-lifecycle failures. It
  touches the object struct + creation paths and is scoped as its own
  item.

### F6 — FIPS-approved digests/HMACs advertised but not callable — FIXED (partial tranche)
* **Finding**: ~70 `CKR_MECHANISM_INVALID` failures. Triage:
  - **~32 real gaps** — SHA-224, SHA-512/224, SHA-512/256, SHA3-256/384/512
    digests and the SHA-224 / SHA-3 HMACs were advertised by the dispatch
    table but the hand-written `C_DigestInit` / `C_SignInit` /
    `C_VerifyInit` switches only handled SHA-256/384/512 (and `C_Verify`
    only SHA-256-HMAC). Callers got `CKR_MECHANISM_INVALID`.
  - **~18 legitimate** — AES-ECB / SHA-1 etc. are non-FIPS and correctly
    rejected under the `fips-strict` profile the harness builds against;
    these are harness-vs-profile expectation mismatches, not defects.
    (Running the harness against the `interop` build would reclassify
    them; tracked separately.)
  - **~8 phantom advertisements** — XEDDSA / X3DH / X2RATCHET (Signal
    protocol) are advertised with sign flags but not implemented; they
    should be de-advertised from the dispatch generator (follow-up).
* **Fix (this tranche)**: wired the FIPS-approved digests (FIPS 180-4 /
  202) into `C_DigestInit` and added `fhsm_hmac_hash_of()` so
  `C_SignInit` / `C_Sign` / `C_VerifyInit` / `C_Verify` accept the
  SHA-224 and SHA-3 HMAC families (and fixed SHA-384/512 HMAC *verify*,
  which previously only handled SHA-256). New enum values
  `FHSM_HASH_SHA224 / SHA512_224 / SHA512_256` + EVP names.
* **Verified**: digest "abc" KATs match FIPS published vectors for
  SHA-224, SHA-512/224, SHA-512/256, SHA3-256, SHA3-512 ; HMAC
  sign->verify round-trips for SHA-224/384/512 and SHA3-256/512.
  Regression: `tests/test_fips_digests.c`, wired into `make tests`.
* **Follow-up**: de-advertise the phantom Signal mechanisms; optionally
  run the harness against `interop` to clear the non-FIPS rejections.

### F7 — C_GetAttributeValue missing standard attributes (KeyError) — FIXED (partial)
* **Finding**: 30 pkcs11-check failures surfaced as Python `KeyError` on
  a `CKA_*` type: the harness queried a standard attribute and the module
  returned `CK_UNAVAILABLE_INFORMATION`, which it reads as "attribute
  absent". Affected: boolean policy/usage flags (CKA_TOKEN, CKA_PRIVATE,
  CKA_ENCRYPT/DECRYPT/SIGN/VERIFY/WRAP/UNWRAP/DERIVE, CKA_LOCAL,
  CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_MODIFIABLE,
  CKA_COPYABLE, CKA_ALWAYS_AUTHENTICATE, ...), date attributes
  (CKA_START_DATE / CKA_END_DATE), certificate fields (CKA_SUBJECT,
  CKA_ISSUER, CKA_SERIAL_NUMBER), and public-key material on private
  keys (CKA_MODULUS / CKA_PUBLIC_EXPONENT / CKA_EC_PARAMS).
* **Fix**: `C_GetAttributeValue` now returns the boolean flags (PKCS#11
  defaults, or derived from the object's stored sensitive/extractable
  flags and class), empty date attributes, and X.509 subject/issuer/
  serial (via a new `extract_cert_attr()` that DER-parses the stored
  certificate). Regression: `tests/test_attributes.c`.
* **Residual (follow-up)**: (a) per-object usage restrictions are not
  stored, so CKA_ENCRYPT/etc. reflect the class default rather than a
  per-key override -- the two TestKeyUsageRestrictions cases need a
  stored usage-flag byte; (b) CKA_MODULUS/PUBLIC_EXPONENT/EC_PARAMS on
  *private* keys (extract_pubkey_attr only handles public keys).

### F8 — Input/parameter validation hardening (AVA_VAN) — FIXED (partial)
* **Finding**: ~30 pkcs11-check security probes had invalid inputs
  *accepted* (CKR_OK) instead of rejected.
* **Fixed this tranche**:
  - **AES-CBC IV** : a wrong-size or missing IV is now rejected at
    C_EncryptInit / C_DecryptInit with CKR_MECHANISM_PARAM_INVALID
    (was deferred / accepted). test_mechanism_param_invalid,
    TestBadParameters.
  - **AES-GCM weak IV** : an IV shorter than 96 bits (NIST SP 800-38D)
    is rejected at init. TestGcmIvWeakness (0/1/4-byte IVs).
  - **RSA public exponent** : C_GenerateKeyPair validates
    CKA_PUBLIC_EXPONENT (must be odd and >= 3 per FIPS 186-5) ;
    e = 0/1/2/4 rejected with CKR_ATTRIBUTE_VALUE_INVALID.
    TestRsaExponent.
  - **Over-long boolean attributes** : a CK_BBOOL attribute supplied
    with a length != 1 (e.g. CK_ULONG-sized) is rejected in
    C_GenerateKey / C_GenerateKeyPair / C_DeriveKey / C_UnwrapKey via a
    shared `fhsm_check_bool_attr_lengths()`.
    test_scalar_attr_length_extended.
* Regression: `tests/test_input_validation.c`.
* **Fixed in the second half of this tranche**: RSA-PSS salt-length and
  RSA-OAEP source-length boundaries (absurd/negative lengths rejected at
  Init with CKR_MECHANISM_PARAM_INVALID); NULL inner IV/AAD/source
  pointers with non-zero lengths (GCM/OAEP) rejected; EC private key
  created without CKA_EC_PARAMS rejected (CKR_TEMPLATE_INCONSISTENT).
* **Remaining in this cluster (follow-up)**: AES-KW/KWP corrupted-blob
  integrity on unwrap, AES-CCM null-nonce, C_SeedRandom isize length,
  and wrong-key-type rejection for several mechanisms.

### F9 — PKCS#11 session-object lifecycle (CKA_TOKEN) — IMPLEMENTED (F5 follow-up)
* The deeper fix promised in F5 is now in place. `fhsm_object_t` carries
  an in-memory `owner_session` (0 = persistent token object ; non-zero =
  session object). Creation paths (C_GenerateKey, C_GenerateKeyPair,
  C_CreateObject, C_DeriveKey, C_UnwrapKey) read CKA_TOKEN (default
  FALSE) and mark session objects owned by the creating session. Session
  objects are never serialised to the `.tok` file, and
  `C_CloseSession` destroys the closing session's session objects via
  `fhsm_token_destroy_session_objects()`.
* Creating a token object (CKA_TOKEN=TRUE) on a read-only session now
  returns CKR_SESSION_READ_ONLY.
* This resolves the object-lifecycle failures (TestSessionObjectLifecycle,
  TestROSessionObjectsAllowed, TestROTokenObjectCreation) and removes the
  underlying store-exhaustion cause behind F5 (session objects are now
  freed on close rather than accumulating). Regression:
  `tests/test_session_objects.c` (session destroyed on close, token
  persists, RO token rejected). The large-store harness build (F5) is
  kept as belt-and-braces.

### F10 — Key-handle validation at Init + C_GetAttributeValue buffer-too-small — FIXED
* **Finding (use-after-destroy)**: C_EncryptInit / C_DecryptInit /
  C_SignInit / C_VerifyInit did not check the key handle, so a call on a
  destroyed or never-created handle *succeeded* (the failure only
  surfaced later, or not at all). pkcs11-check use-after-destroy probes.
* **Finding (buffer)**: C_GetAttributeValue returned CKR_OK when a
  requested attribute did not fit the supplied buffer (it set
  ulValueLen = CK_UNAVAILABLE_INFORMATION but did not signal the caller).
  TestGetAttrUndersizedBuffer.
* **Fix**: a shared `fhsm_require_key()` validates the key handle in all
  four keyed *Init entry points (CKR_KEY_HANDLE_INVALID otherwise);
  C_GetAttributeValue now returns CKR_BUFFER_TOO_SMALL if any attribute
  was truncated. Regression added to `tests/test_op_state.c`.
* **Note**: this investigation (the 63 unclassified failures) also
  surfaced further real items now tracked as follow-ups: private-object
  visibility in public/post-logout sessions (access control),
  key-type-vs-mechanism mismatch at Init, AES-KW/KWP key-type confusion
  on unwrap (Tookan), CKA_VALUE on a sensitive key should return
  CKR_ATTRIBUTE_SENSITIVE, and a few computed-value cross-verifies.

### F11 — Private-object access control in C_FindObjects — FIXED
* **Finding**: objects with CKA_PRIVATE=TRUE were visible to sessions
  that were not logged in as the normal user -- a public session saw
  private objects, and a session still saw them after C_Logout
  (pkcs11-check access-control probes).
* **Fix**: `C_FindObjectsInit` now filters out private objects when the
  session role is not `FHSM_ROLE_USER`. CKA_PRIVATE is derived from the
  object class (secret and private keys are private ; public keys,
  certificates and data objects are public), matching the value
  C_GetAttributeValue reports. Regression added to
  `tests/test_session_objects.c` (private object hidden after logout).
* **Direct-handle access** is gated too: `C_GetAttributeValue` and
  `C_GetObjectSize` return CKR_OBJECT_HANDLE_INVALID for a private object
  when the session is not logged in as the user, so a handle kept from a
  prior authenticated session cannot read the object after C_Logout.
* **Note**: CKA_PRIVATE is derived from class rather than an explicit
  stored flag ; an object explicitly created with CKA_PRIVATE=FALSE is
  still treated as private if it is a secret/private key. Storing an
  explicit CKA_PRIVATE bit, and per-token (per-application) login state
  so C_Logout in one session affects the others, are small follow-ups.

### F12 — PQC mechanism values collided with official Signal mechanisms — FIXED (ABI change)
* **Finding**: pkcs11-check reported ML-DSA / SLH-DSA / HASH-ML-DSA
  advertised with sign/verify flags as XEDDSA / X3DH / X2RATCHET
  (test_mech_flags). Root cause: the module assigned its PQC mechanisms
  to values in 0x4021-0x4029, a range **already allocated** by
  PKCS#11 v3.2 to the Signal-protocol mechanisms (CKM_X3DH_RESPOND
  0x4024, CKM_X2RATCHET_* 0x4025-0x4027, CKM_XEDDSA 0x4029). The harness
  maps advertised values through the official registry, so it read the
  module's ML-DSA (0x4024) as X3DH_RESPOND, etc. The advertised value
  also differed from the operation-path value (ML-DSA advertised 0x4024
  but C_SignInit expected 0x403F), an internal inconsistency.
* **Fix**: reassigned the PQC mechanisms to their official PKCS#11 v3.2
  values and unified advertisement with the operation path:
  ML-KEM keygen 0x0F / op 0x17, ML-DSA keygen 0x1C / sign 0x1D,
  HASH-ML-DSA-SHA256 0x24 / SHA512 0x26, SLH-DSA keygen 0x2D / sign 0x2E.
  Regenerated the dispatch table + `MECHANISMS.md`, updated the operation
  #defines, the e2e tests and the Wycheproof adapter.
* **ABI note**: this changes the advertised PQC mechanism identifiers.
  The module is pre-1.0 (v1.5.0 line); the old values were non-standard
  and colliding, so this is a conformance correction. Verified: smoke
  KATs (ML-DSA-65, SLH-DSA, ML-KEM-768) pass, advertisement is at the
  official values, and the old colliding values are gone
  (tests/test_mech_advertise.c updated to enforce this).

## Expected gaps (xfail-class, not defects)

### G1 — CKO_DATA data objects unsupported
* `test_data_objects::*`, `test_attribute_defaults::TestDataObjectDefaults`
  return `CKR_TEMPLATE_INCONSISTENT`. `C_CreateObject` supports keys and
  (since #110) X.509 certificates, not generic `CKO_DATA` objects. This
  is a deliberate scope boundary for the current profile. Candidate for
  a future item if a consumer needs opaque data objects.

## To investigate (follow-up items)

### I1 — Certificate import reports CKR_HOST_MEMORY under load — RESOLVED
* `x509::test_core_ops::TestCertificateImport::test_import_der_certificate`
  returned `CKR_HOST_MEMORY`. `fhsm_token_object_add` returned this when
  the store is full (`FHSM_MAX_OBJECTS = 64`), because the harness had
  already filled the token with prior objects.
* **Resolution (2026-07-10)**: the return code was wrong — a full token
  is `CKR_DEVICE_MEMORY` (token storage exhausted), not `CKR_HOST_MEMORY`
  (host RAM). Fixed in `fhsm_token_object_add`. `FHSM_MAX_OBJECTS` is now
  overridable at build time (`-DFHSM_MAX_OBJECTS=N`, default 64) for
  general-purpose deployments that need a larger store. Regression:
  `tests/test_token_capacity.c` asserts the 65th object is rejected with
  `CKR_DEVICE_MEMORY`. The residual harness-ordering noise (filling the
  token before the cert-import case) is a run-script concern, tracked
  with I2.

### I2 — Login throttle bleeds across harness tests
* `test_ckr_session::TestLoginErrors::test_already_logged_in` and
  `test_ckr_codes::...test_ckr_mechanism_invalid` observed
  `0x80000004` (`FHSM_RV_PIN_THROTTLED`) where a standard CKR was
  expected. The exponential login throttle (a security feature) is
  persistent and cross-session by design, so the harness's many
  negative-login probes trip it for later tests. **Action**: not a
  module defect, but two options — (a) document that the harness needs
  a fresh token or throttle reset between login-negative suites, or
  (b) provide a dev-only env knob to relax the throttle for testing
  (mirroring FHSM_INTEGRITY_ALLOW_UNSIGNED). Prefer (a).

## General-purpose non-FIPS mechanisms (#125 tranche A/B)

The module is a general-purpose PKCS#11 provider that switches to FIPS by
build profile (`FHSM_BUILD_FIPS_STRICT`). The following non-FIPS
mechanisms are executable in the `interop` build and rejected under
`fips-strict` (advertised iff executable), each gated in the relevant
operation function (not `op_init`, which is shared with signing):

* **Digests**: SHA-1, MD5.
* **Ciphers**: AES-ECB, 3DES-CBC, 3DES key generation.
* **RSA**: PKCS#1 v1.5 encryption, X.509 raw encryption, SHA1-RSA-PKCS
  signature.

### Deferred: DSA / DH key generation (#22)

DSA and DH key-pair generation were scoped for tranche B but
**deferred**: the module has **no consuming operation** for them — there
is no DSA signature mechanism and no DH `C_DeriveKey` wired anywhere. A
`CKM_DSA_KEY_PAIR_GEN` / `CKM_DH_PKCS_KEY_PAIR_GEN` would therefore
produce keys that nothing in the module can use, which is a poorer
general-purpose experience than not offering them. When a consumer
actually needs them, they should be added as a *bundle*: keygen +
paramgen + the consuming operation (DSA `C_Sign` / DH `C_DeriveKey`) +
the corresponding `FHSM_PAIRWISE_*` family — not keygen alone.

RC4 and single-DES (tranche C) remain deferred as well: they require the
OpenSSL **legacy** provider, which is a separate provider-loading policy
decision for the interop build.

## Method

Run: `make pkcs11-check` (local) 
## F13 — Advertised-but-unimplemented online cipher paths (CCM/CTS)

`CKM_AES_CCM` (and `CKM_AES_CTS`) are advertised by `C_GetMechanismList` and
carry a KAT vector, but the interactive `C_Encrypt`/`C_Decrypt` data path is not
wired. `C_EncryptInit`/`C_DecryptInit` now return `CKR_MECHANISM_INVALID` for
them via `fhsm_cipher_mech_valid`, which satisfies the pkcs11-check CCM
"must-reject" tests (null nonce, missing params). Follow-up: either implement the
online CCM/CTS path or de-advertise these mechanisms in the fips-strict profile so
the advertised list and the online behaviour stay consistent.

## F13 update — CCM/CTS de-advertised (was: advertised-but-unimplemented)

AES-CCM was de-advertised (like the non-standard SHAKE128/256 digests) because
its online C_Encrypt/C_Decrypt path is not wired, so advertising CKF_ENCRYPT was
inconsistent with C_EncryptInit returning CKR_MECHANISM_INVALID. Follow-up:
implement the CCM two-pass EVP path (CK_CCM_PARAMS: nonce 7-13B, MAC 4-16B,
AAD, ulDataLen), validate a NIST SP 800-38C vector, then re-advertise
fips=approved. The dispatch_aes_ccm KAT handler is retained for that work.

## F13 — RESOLVED (AES-CCM online implemented)

The AES-CCM online C_Encrypt/C_Decrypt path is now wired (CK_CCM_PARAMS parsing,
two-pass EVP, NIST SP 800-38C Example 1 byte-exact). CCM is re-advertised
fips=approved; the flag<->behaviour inconsistency that motivated the earlier
de-advertisement is gone. The KAT handler dispatch_aes_ccm is back in the table.

---

# Closing triage — 2026-07-21 : 361 → 5

Final run against `main` (`ac52ec7`) :

```
failed 5 · passed 1689 · skipped 2099 · crashed 0
```

The campaign opened at **517 failed / 7 crashed** on 2026-07-10 and, after the
harness's own re-classification of capability gaps, tracked **361 → 5** on the
failure count. Crashes reached 0 and stayed there.

**The five remaining are positions, not backlog.** Each is listed with what
would have to change for it to move. Anyone reading this in six months should
be able to disagree with a decision, not discover an oversight.

## R1 — `TestTookanUnwrapAttrs::test_unwrapped_key_cannot_unset_sensitive`

An unwrap template carrying `CKA_SENSITIVE=False` produces a readable copy of a
key that was sensitive before it was wrapped (Tookan §3.3). Reproduced during
the campaign: a `SENSITIVE=True` AES key came back as
`8a6257b04169cf7d5fe9e4d97484d71f` in the clear.

**Position: hardening is opt-in, via `CKA_UNWRAP_TEMPLATE` on the unwrapping
key.** A blanket refusal was implemented, measured, and reverted: it blocked
this attack and broke seven legitimate round-trips, including the module's own
`test_wrap_unwrap_oaep`. PKCS#11 has no way to say "this key was sensitive
before it was wrapped" — the wrapped blob carries no attributes — so the choice
is between refusing all attribute downgrades on unwrap or letting the operator
state the policy. The spec provides `CKA_UNWRAP_TEMPLATE` for exactly that, and
it is honoured on every unwrap path including the RSA v1.5 and raw-RSA ones
added later.

**What would move it:** deciding that the default should be restrictive and
accepting that callers must set `CKA_UNWRAP_TEMPLATE` to permit downgrades —
the inverse default. Defensible; it was not chosen because it breaks
conforming callers silently at their next unwrap.

## R2 — `TestAESPaddingOracle::test_cbc_pad_all_last_block_positions`

`CKM_AES_CBC_PAD` decryption distinguishes a valid PKCS#7 pad from an invalid
one, which is a padding oracle.

**Position: inherent to the mechanism.** CBC-PAD without an authentication tag
cannot report "this ciphertext did not decrypt" without revealing why, and
`C_Decrypt` must return something. Suppressing the distinction would return
garbage plaintext on corruption, which is worse for every honest caller.

**What would move it:** nothing, short of removing `CKM_AES_CBC_PAD`. Callers
who need integrity want `CKM_AES_GCM` or `CKM_AES_KEY_WRAP`. This is worth
saying in user-facing documentation rather than only here.

## R3 — `TestGcmIvReuse::test_gcm_iv_reuse_same_key`

The module does not detect an IV reused with the same GCM key across
operations — a catastrophic failure mode for GCM.

**Position: not implemented, because doing it honestly requires state we do not
keep.** Detecting reuse means remembering every IV ever used per key, across
sessions and across restarts, or constraining IV construction (deterministic
counter per SP 800-38D §8.2.1). A partial check — remembering only recent IVs,
or only within a session — would report "no reuse" while missing the case that
matters, which is the pattern this whole campaign exists to remove.

**What would move it:** implementing SP 800-38D §8.2.1 deterministic IV
construction, where the module owns the counter and the caller cannot supply a
colliding IV. That is a feature, and the right one; it is not a bug fix.

## R4 / R5 — `test_rsa_encrypt_boundary`, `test_rsa_decrypt_timing_sanity`

Both exercise `CKM_RSA_PKCS` encryption/decryption without first checking that
the module advertises it. Under `fips-strict` it does not:

```
CKM_RSA_PKCS   in C_GetMechanismList : no
               C_GetMechanismInfo    : 0x70 (CKR_MECHANISM_INVALID)
CKM_RSA_X_509  in C_GetMechanismList : no
               C_GetMechanismInfo    : 0x70
```

RSA PKCS#1 v1.5 *encryption* is not FIPS-approved, so a module claiming
FIPS 140-3 candidacy must not offer it in that profile. (v1.5 *signature* is
approved and remains available in both profiles; the two gates are separate.)
Both mechanisms are implemented and advertised in the `interop` profile, where
these tests would exercise real code.

**Position: harness gap, reported upstream.** The tests need a `has_mechanism`
guard like their siblings. Verified by direct probe rather than asserted — see
`probes/rsa_mech_advertised.c`.

**What would move it:** a guard upstream, or running the harness against the
interop build.

## What the campaign found that no counter measured

Seven defects that a passing test suite had not surfaced, listed because the
pattern matters more than the individual bugs:

* a wrong MAC algorithm served under a standardised mechanism ID;
* PQC parameter sets unselectable — `ML-DSA-87` silently produced `ML-DSA-65`;
* a function-list off-by-one that segfaulted every v3.0 caller;
* `CKA_LOCAL` reporting false provenance;
* Tookan §3.3 key extraction, reproduced in the clear;
* no fork isolation — a child inherited session objects **and** logged-in state;
* the FIPS §7.10.2 integrity self-test comparing a digest against itself, so it
  had never verified anything;
* a `size_t → int` cast in the DRBG that killed the module on one oversized
  `C_GenerateRandom` and reported it as **"DRBG RCT alarm"** — an entropy-source
  failure that had not happened;
* `C_FindObjectsInit` reading past its buffer and returning stack bytes as
  object handles, invisible until the store round-trip was run under UBSan.

**The recurring shape is one guard wired to some of the paths that reach a
shared state.** `CKA_TRUSTED` covered 1 of 3 creation paths; `CKA_UNWRAP_TEMPLATE`
2 of 3; `fhsm_check_ro_token` 3 of 6; `fhsm_apply_token_scope` 5 of 6; the
metadata attributes 6 of 8 on the first attempt; and the `prelim` bound was
enforced on the write and not on the read. Counting insertion sites against
creation paths, rather than trusting a search-and-replace, is what caught the
last two.

## Method

Every fix in this batch was measured one change at a time against the harness,
with the count recorded before and after. Two regressions were introduced and
caught this way — a blanket unwrap refusal that broke seven legitimate paths,
and a `CKA_TRUSTED` guard that added an unbounded template scan. Neither was
visible to the unit suite.

`make SANITIZE=1` (ASan + UBSan) was added during the store-format work. It
turned 10 of 13 unit tests red on first use: they had been passing a short
string literal as `C_InitToken`'s 32-byte `pLabel` field. The module was right
and the tests were wrong, and a suite green for months went red the moment
something was watching.
