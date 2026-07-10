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

## Expected gaps (xfail-class, not defects)

### G1 — CKO_DATA data objects unsupported
* `test_data_objects::*`, `test_attribute_defaults::TestDataObjectDefaults`
  return `CKR_TEMPLATE_INCONSISTENT`. `C_CreateObject` supports keys and
  (since #110) X.509 certificates, not generic `CKO_DATA` objects. This
  is a deliberate scope boundary for the current profile. Candidate for
  a future item if a consumer needs opaque data objects.

## To investigate (follow-up items)

### I1 — Certificate import reports CKR_HOST_MEMORY under load
* `x509::test_core_ops::TestCertificateImport::test_import_der_certificate`
  returned `CKR_HOST_MEMORY`. `fhsm_token_object_add` returns this when
  the store is full (`FHSM_MAX_OBJECTS = 64`). Most likely the harness
  had already filled the token with prior objects rather than a leak,
  but worth confirming the harness runs against a fresh token per
  file, and considering whether `FHSM_MAX_OBJECTS` should be
  configurable. **Action**: reproduce in isolation; if store-full is
  the cause, return is arguably correct but the harness ordering makes
  it noisy — consider per-test token reset in `run_pkcs11_check.sh`.

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

## Method

Run: `make pkcs11-check` (local) or the `pkcs11-check` CI workflow.
Baseline regression gating (`pkcs11-check compare-results` against a
stored baseline) is tracked as follow-up so that *new* crashed/error
findings fail CI while the known xfail/fail population does not.
