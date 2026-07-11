# pkcs11-check Hardening Campaign (#125)

Summary of the behavioural-conformance and hardening campaign driven by
Denis Mingulov's `pkcs11-check` harness against `libfreehsm-fips.so`.
The harness runs >100k vendor-neutral checks (spec conformance, CKR
negatives, security probes, Wycheproof / ACVP vectors). Large xfail/fail
counts are expected — findings are evidence to triage, not a verdict.

## Metrics (native harness summary)

| Outcome  | Start | End   | Δ        |
|----------|-------|-------|----------|
| passed   | 974   | 1252  | **+278** |
| failed   | 361   | 152   | **−209 (−58 %)** |
| error    | 36    | 24    | −12      |
| crashed  | 7     | **0** | eliminated |

Pass rate (excluding skipped/xfail): **87.7 %**. Zero crashes throughout
after the first hardening tranche.

## Commits (on top of the pre-campaign baseline)

Infrastructure / CI:
* fix pkcs11-check summary heredoc + cross-directory build reproducibility (gcc < 12)
* ci: sign build2 in the reproducibility job (signed-vs-signed compare)
* build the pkcs11-check module with a larger object store (FHSM_MAX_OBJECTS)

Robustness (AVA_VAN):
* harden TSFI against NULL pointers & integer-overflow counts (21 SIGSEGV → 0)
* fix per-session operation-state bleed + C_Sign buffer-too-small
* validate key handle at *Init (use-after-destroy) + C_GetAttributeValue buffer-too-small

Conformance:
* wire FIPS-approved digests + HMACs into the operation path (SHA-224, SHA-512/t, SHA-3)
* return standard boolean/date/certificate attributes in C_GetAttributeValue
* implement PKCS#11 session-object lifecycle (CKA_TOKEN)
* fix multipart HMAC to match one-shot (SHA-384/512/SHA-3)

Input validation (AVA_VAN):
* CBC/GCM IV, RSA exponent, over-long boolean attributes
* PSS/OAEP length bounds, NULL inner params, EC-without-params

Access control:
* hide private objects from unauthenticated sessions (C_FindObjects)
* gate direct-handle access to private objects (C_GetAttributeValue / C_GetObjectSize)

## Findings (see docs/PKCS11_CHECK_FINDINGS.md for detail)

| ID | Area | Status |
|----|------|--------|
| F1 | C_Decrypt NULL-deref (SIGSEGV) | fixed |
| F2 | Mechanism advertisement drift | fixed |
| F3 | TSFI NULL/overflow robustness (21 SIGSEGV) | fixed |
| F4 | Operation-state hygiene + C_Sign buffer | fixed |
| F5 | Object-store exhaustion (CKR_DEVICE_MEMORY) | mitigated + F9 |
| F6 | FIPS digests/HMACs advertised but not callable | fixed |
| F7 | C_GetAttributeValue missing attributes | fixed |
| F8 | Input/parameter validation | fixed |
| F9 | Session-object lifecycle (CKA_TOKEN) | fixed |
| F10 | Key-handle validation + buffer-too-small | fixed |
| F11 | Private-object access control | fixed |

## Regression tests added

`test_robustness_args`, `test_op_state`, `test_fips_digests`,
`test_attributes`, `test_input_validation`, `test_session_objects`
(all wired into `make tests`), plus the standalone
`scripts/pkcs11_check_summary.py`.

## Remaining (documented, non-defect or scoped follow-ups)

* **Correct behaviour, not defects**: non-FIPS mechanisms (AES-ECB,
  SHA-1, ...) rejected under the `fips-strict` profile the harness builds
  against; `CKO_DATA` data objects out of scope.
* **Follow-ups**: per-object usage-flag storage (CKA_ENCRYPT=FALSE
  enforcement); public-key material (CKA_MODULUS/EC_PARAMS) on private
  keys; per-token (per-application) login state; de-advertise phantom
  Signal mechanisms (XEDDSA/X3DH/X2RATCHET); key-type-vs-mechanism
  checks at Init; AES-KW/KWP corrupted-blob and key-type-confusion on
  unwrap; CKA_VALUE on a sensitive key → CKR_ATTRIBUTE_SENSITIVE;
  a handful of computed-value cross-verifies.
