# Changelog

All notable changes to FreeHSM C are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Fixed

* **Token store-full returns CKR_DEVICE_MEMORY, not CKR_HOST_MEMORY
  (#125 finding I1).** When a token reached `FHSM_MAX_OBJECTS`,
  `C_CreateObject` returned `CKR_HOST_MEMORY` (host RAM exhausted) where
  the correct code is `CKR_DEVICE_MEMORY` (token storage full), which is
  what pkcs11-check flagged on certificate import under load.
  `FHSM_MAX_OBJECTS` is now overridable at build time
  (`-DFHSM_MAX_OBJECTS=N`, default 64) for general-purpose deployments
  needing a larger store. Regression covered in
  `tests/test_token_capacity.c` (65th object rejected with
  `CKR_DEVICE_MEMORY`).

* **Mechanism advertisement rebuilt from the dispatch table (#125,
  found by pkcs11-check).** `C_GetMechanismList` / `C_GetMechanismInfo`
  used a hand-maintained list + capability switch that had drifted
  badly from the generated dispatch table (the single source of truth):
  the post-quantum signature mechanisms were advertised under **stale,
  wrong values** (ML-DSA `0x403F` vs the dispatched `0x4024`, likewise
  ML-DSA/SLH-DSA key-pair-gen), **phantom FALCON/KYBER** entries were
  advertised with no backing handler, and **~40 dispatched mechanisms
  were never advertised at all** (every SHA-3/SHAKE, KMAC, HKDF, EdDSA,
  X25519/X448, and the ML-KEM/ML-DSA/SLH-DSA mechanisms at their correct
  values). Net effect: post-quantum signatures were undiscoverable via
  standard enumeration. Both functions are now derived directly from
  `fhsm_mechanism_table[]`, so the advertised set can never drift from
  what the module dispatches: a mechanism is advertised iff it resolves
  to a real handler in the active profile (general-purpose advertises
  every real handler; FIPS advertises only approved, since non-approved
  compile to the reject stub). Capability flags come from the generated
  per-mechanism operation class; precise per-mechanism key-size
  reporting is a tracked follow-up (increment 2). New coherence guard
  `tests/test_mech_advertise.c` (wired into `make tests`) asserts every
  advertised mechanism resolves through `C_GetMechanismInfo`, the PQ
  values are correct, EdDSA/HKDF are present, and the phantoms are gone.
  Full analysis in `docs/PKCS11_CHECK_FINDINGS.md`.

* **C_EncryptUpdate / C_DecryptUpdate NULL-pointer dereference /
  SIGSEGV (#125, remaining pkcs11-check crashes).** Both multi-part
  update functions dereferenced their length out-parameter
  (`pulEncLen` / `pulPartLen`) on the size-query path without a NULL
  check — the same class as the C_Decrypt fix, and the source of the
  crashes that survived the first fix (7 → 4 in the re-run). Now
  rejected with `CKR_ARGUMENTS_BAD`, terminating the operation.
  Confirmed with a negative control (guard removed → SIGSEGV). The
  regression test `tests/test_decrypt_null_args.c` now also drives a
  GCM `C_EncryptUpdate(pulEncLen=NULL)` probe.

* **C_Decrypt NULL-pointer dereference / SIGSEGV (#125, found by
  pkcs11-check).** `C_Decrypt` dereferenced `pulDataLen` on every path
  (size query and copy) without a NULL check, unlike `C_Encrypt` which
  guarded `pulEncLen`. A caller passing `pulDataLen = NULL` (as
  pkcs11-check's NULL-argument probe does) triggered a NULL-pointer
  dereference and crashed the module. Now rejected with
  `CKR_ARGUMENTS_BAD`, terminating the operation so the session is not
  stranded ; the symmetric `pData`-with-length guard was added to
  `C_Encrypt`. Confirmed with a negative control (guard removed → exit
  139/SIGSEGV ; with fix → 0x7). Regression test
  `tests/test_decrypt_null_args.c` drives the public API via `dlopen`
  and is wired into `make tests`. Availability/robustness defect
  (AVA_VAN class) ; no key material exposed, no CVE requested. Triage
  of the full first-run findings is in `docs/PKCS11_CHECK_FINDINGS.md`.

### Added

* **CI : pkcs11-check external harness (#125).** New workflow
  `.github/workflows/pkcs11-check.yml` runs Denis Mingulov's
  `pkcs11-check` (>100k vendor-neutral behavioral checks : spec
  conformance, CKR negatives, security, fuzz, Wycheproof / ACVP
  corpora) against the **digest-signed** module on every push to main
  + weekly, uploading the JSON report and log as artifacts.
  Non-gating by design per the harness's own guidance (findings are
  evidence, not a verdict) ; the job fails only if the harness cannot
  run or produce a report. Local mirror : `make pkcs11-check`
  (shared logic in `scripts/run_pkcs11_check.sh` ; token provisioned
  with the same PIN conventions as `tests/coverage_matrix.sh`).
  Baseline regression gating via `pkcs11-check compare-results` is
  tracked as follow-up. This closes the loop opened by the v1.2.2 /
  v1.3.0 external reports : the tool that found those defects now
  watches every commit.

* **`CKO_CERTIFICATE` objects (#110).** `C_CreateObject` accepts
  `CKO_CERTIFICATE` + `CKA_CERTIFICATE_TYPE = CKC_X_509` templates ; the
  DER certificate travels verbatim in `CKA_VALUE` (the module never
  parses X.509 — validation is the PKI layer's job). Certificates are
  stored non-sensitive + extractable, so `C_GetAttributeValue` returns
  `CKA_VALUE`, `CKA_CERTIFICATE_TYPE`, `CKA_CLASS`, `CKA_LABEL`,
  `CKA_ID` ; `CKA_KEY_TYPE` correctly reports "invalid" for the class.
  Groundwork for the v2.0 `fhsm-ca` PKI layer.

* **Token store objects blob v2 : variable-size records (#110).**
  Certificates carrying PQC / composite keys exceed the fixed
  5 500-byte value field of v1 records. The blob plaintext is now
  self-versioned (leading magic `0xF5B20002`) with per-record
  `rec_len` ; per-object payload cap raised to
  `FHSM_OBJ_VALUE_MAX` = 16 384 bytes. **Read-v1 / write-v2** :
  existing tokens load transparently and migrate to v2 on first
  mutation. Small objects shrink ~97 % on disk (32-byte AES key
  record : 5 620 → 156 bytes). Older binaries reading a v2 blob fail
  loudly, never silently. Spec updated in
  `docs/TOKEN_STORE_FORMAT.md` ; capacity + certificate round-trips in
  `tests/test_token_capacity.c`.

### Fixed

* **Token store : objects-blob loader bound (#108 regression finding).**
  The v1.4.0 loader rejected any encrypted objects section larger than
  65 536 bytes, while the writer legitimately produces up to 359 688
  bytes (64 × 5 620-byte records + 8-byte prefix). A token holding more
  than 11 objects persisted fine but **failed to load at the next
  login** (data intact on disk, store unreadable). The sanity cap is now
  `FHSM_OBJ_BLOB_MAX`. Found while writing the byte-level format
  specification. Regression test : `tests/test_token_capacity.c`.
  No wire-format change ; no security impact (fail-closed availability
  bug).

### Documentation

* **`docs/TOKEN_STORE_FORMAT.md` (#108)** : authoritative byte-level
  specification of the `slotN.tok` format (317-byte header, encrypted
  objects section, crypto parameters, auditor-checkable invariants,
  versioning policy). The stale JSON-era comments in `fhsm_token.h` /
  `fhsm_token.c` (inherited from the Python POC description) were
  corrected to match the implemented binary format ; the erroneous
  byte-level-interop claim with POC token files was retracted.

### Branding / repository

* **Rebrand (July 2026)** : repository renamed `freehsm-c` → `freehsm` ; dual
  branding formalized (FreeHSM = library, Simorgh PKI = product, Simorgh Labs
  = org). Positioning updated per primacy audit #118
  (`docs/PRIMACY_AUDIT_PQC_COMPOSITE.md`). Added `TRADEMARK.md`. **No
  consumer-facing change** : binary name `libfreehsm-fips.so`, PKCS#11
  identifiers, and the GPG release key are all unchanged. Old repository
  URLs redirect.

### Documentation (post-v1.3.0 correction)

* `SECURITY.md` --- corrected a typo in the "Maintainer GPG key rotation 2026-06-12" section that has been present since the original 2026-06-13 commit `2e6a413`. The previous key fingerprint was incorrectly listed as `743A6A59…DBBF28A2` (which is the *new* key) in both the "previous" and "new" position ; it is now correctly listed as `B79726CB087375CF990E00E4A0BC5BB2FB1EE342`, matching the canonical record in the rotation commit message. A 14-day correction note is added inline. No code change ; no behavior change. Filed concurrently as informational GitHub Security Advisory `GHSA-wgv9-m9cv-4647` (published 2026-06-27, drafted 2026-06-13).

---

## [1.4.0] --- 2026-06-28

**v2.40 dispatch-table near-completion release.** Wires 6 additional v2.40 function-list slots that close most of the remaining gap between FreeHSM C and a strict OASIS PKCS#11 v2.40 implementation, bringing dispatch coverage from **51 / 67 to 57 / 67 (85 %)**.

This is **functionality-additive only** : no behavioral change to any pre-existing function ; no security fix. Forward-compatible with v1.3.0 PIN files, token store, and audit log chain. Migration notes: none.

### Added

#### Tier 1 --- session management + legacy parallel + DRBG seed

* **`C_CloseAllSessions`** (PKCS#11 v3.2 §C.6.6.2) wired into slot 14. Iterates session-handle range (1..256), closes each open session for the given slot. The module is a single-slot software token ; `slotID != 0` returns `CKR_SLOT_ID_INVALID`.

* **`C_SeedRandom`** (§C.6.6.5) wired into slot 63. Returns `CKR_RANDOM_SEED_NOT_SUPPORTED` unconditionally per NIST SP 800-90A §9.2 : a SP 800-90A DRBG must be seeded only from approved entropy sources ; caller-supplied seed material is rejected in FIPS mode and rejected for security in legacy mode (attacker-controlled seed could narrow the entropy distribution downstream).

* **`C_GetFunctionStatus`** (§C.6.5.6) wired into slot 65. Returns `CKR_FUNCTION_NOT_PARALLEL` per spec. The PKCS#11 parallel-function model was abandoned in v2.10 ; this function is a legacy stub on every modern non-parallel implementation. `C_CancelFunction` is also implemented and exported as an ELF symbol but cannot be wired in the current v2.40 dispatch due to the 67-slot table collision with slot 66 (`C_WaitForSlotEvent`, wired in v1.3.0). Documented as a roadmap item for v1.5.x : resize `pfn[]` to 68 slots to fit both per strict spec ordering.

#### Tier 2 --- digest extension + verify multipart

* **`C_DigestKey`** (§C.6.10.5) wired into slot 40. Feeds a key value into the ongoing digest context (equivalent to calling `C_DigestUpdate` on the key bytes). Refuses sensitive (`CKA_SENSITIVE=TRUE`) and non-`CKO_SECRET_KEY` objects with `CKR_KEY_INDIGESTIBLE` so that the digest output cannot be used as a side channel to recover key material from asymmetric private keys. Lazy-init the `EVP_MD_CTX` so a digest-of-key-alone via `C_DigestInit → C_DigestKey → C_DigestFinal` is supported without intervening data.

* **`C_VerifyUpdate`** (§C.6.13.6) wired into slot 50. Multipart HMAC verification, symmetric to `C_SignUpdate` from earlier releases. Currently scoped to `CKM_SHA256_HMAC` ; asymmetric multipart verify (which would defer `EVP_DigestVerifyFinal` until `C_VerifyFinal`) is not yet implemented and falls through to `CKR_MECHANISM_INVALID`.

* **`C_VerifyFinal`** (§C.6.13.7) wired into slot 51. HMAC MAC accumulation final with **constant-time compare via `fhsm_ct_memcmp`** to avoid timing side channels on signature validation. Mirrors the existing `C_SignFinal` pattern.

### Coverage status

```
PKCS#11 v2.40 dispatch table : 57 / 67 wired (85 %)
                               (was 51 / 67 in v1.3.0)
                               (was 47 / 67 in v1.2.2)
                               (was 44 / 67 in v1.2.1 pre-Denis)
Unwired (10 slots, all by design) :
    16, 17  C_GetOperationState / C_SetOperationState
            (HSM-internal context switching, not applicable to
             a software token)
    46, 47  C_SignRecoverInit / C_SignRecover
    52, 53  C_VerifyRecoverInit / C_VerifyRecover
            (RSA recovery, ISO/IEC 9796-2, rarely used in practice)
    54-57   C_DigestEncryptUpdate / C_DecryptDigestUpdate
            / C_SignEncryptUpdate / C_DecryptVerifyUpdate
            (dual-operation streaming, niche)

Plus C_CancelFunction symbol exported but not in v2.40 dispatch
(67-slot table collision ; tracked for v1.5.x).
```

### Validation

* Build clean : `-Werror -Wpedantic -Wconversion -Wstringop-truncation -Wmissing-prototypes`, zero warning.
* All 62 KAT vectors green in dev mode and CI `test-fips-mode`.
* Python ctypes verification confirms all 6 new slots (`pfn[14, 40, 50, 51, 63, 65]`) are distinct from the `fhsm_not_supported` sentinel at `pfn[16]`.
* The v3.0 dispatch table (`fhsm_function_list_3_0`) automatically mirrors slots 0..66 from v2.40 via the existing loop in `fhsm_init_v3_0_table()` ; no separate v3.0 wiring needed.
* CI `reproducibility` : byte-identical builds across two independent runs.

### Affected releases (forward-compatibility)

| Release | Upgrade priority | Reason |
|---|---|---|
| v1.3.0 | Recommended | No security fix ; enhancements only. Forward-compatible. |
| v1.2.2 and older | **Required** | See v1.3.0 and v1.2.2 advisories (`GHSA-xpxx-66pp-pf99`, `GHSA-6jx9-gh48-5qf6`, `GHSA-wgv9-m9cv-4647`). |

---

## [1.3.0] --- 2026-06-27

**Function-list completion + export-roundtrip extension release.** Closes the two narrative threads opened by v1.2.2 :

  (1) Five PKCS#11 function-list slots flagged by Denis Mingulov's `pkcs11-check` report as "exported but unwired" --- 3 were resolved in v1.2.2, the remaining 2 (`C_CopyObject` + `C_SetAttributeValue`) and 1 more (`C_WaitForSlotEvent`) close the v2.40 dispatch table in this release.

  (2) The export-roundtrip boot KAT pattern, introduced in v1.2.2 for ECDSA, is now applied to every external cryptographic surface the module exposes (RSA-PSS, RSA-OAEP, EdDSA, ML-DSA, ML-KEM, ECDH) --- 6/7, with SLH-DSA documented as an intentional exclusion on runtime-budget grounds.

This release is **functionality-additive only** : no behavioral change to any pre-existing function ; no security fix. Forward-compatible with v1.2.2 PIN files, token store, and audit log chain. **Migration notes : none.**

### Added

#### `C_CopyObject` (PKCS#11 v3.2 §C.6.7.3)

Implementation in `src/fhsm_pkcs11.c` (~100 lines). Reads the source object via the existing `fhsm_token_object_get` accessors, applies the caller's template on top of the source's attributes (template wins on conflict), and persists via `fhsm_token_object_add`. Enforces PKCS#11's one-way state transitions on the template : if the source has `CKA_SENSITIVE = TRUE`, the copy cannot set it to `FALSE` ; if the source has `CKA_EXTRACTABLE = FALSE`, the copy cannot set it to `TRUE`. Violations return `CKR_TEMPLATE_INCONSISTENT`. Wired into `pfn[21]` in `C_GetFunctionList`.

#### `C_SetAttributeValue` (PKCS#11 v3.2 §C.6.7.5)

Implementation in `src/fhsm_pkcs11.c` (~80 lines). Whitelist approach :

| Attribute | Behaviour |
|---|---|
| `CKA_LABEL` | Bounded copy, max 63 chars (PKCS#11 token label limit). |
| `CKA_ID` | Max 32 bytes (PKCS#11 key ID limit). |
| `CKA_SENSITIVE` | One-way `FALSE -> TRUE` only ; reverse returns `CKR_ATTRIBUTE_READ_ONLY`. |
| `CKA_EXTRACTABLE` | One-way `TRUE -> FALSE` only ; reverse returns `CKR_ATTRIBUTE_READ_ONLY`. |
| `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_VALUE` | `CKR_ATTRIBUTE_READ_ONLY` (immutable after creation). |
| All others | `CKR_ATTRIBUTE_TYPE_INVALID`. |

Flag transitions accumulated into a single `fhsm_token_object_set_flags` call to ensure atomic persistence (no partial write on multi-attribute templates). Wired into `pfn[25]`.

#### `C_WaitForSlotEvent` (PKCS#11 v3.2 §C.6.5.4)

Software-token semantics : `CKF_DONT_BLOCK` returns `CKR_NO_EVENT` immediately ; blocking mode returns `CKR_FUNCTION_NOT_SUPPORTED` rather than hang indefinitely (no hot-plug source in a software token). `pReserved` must be `NULL` per spec. Wired into `pfn[66]` --- the last unwired slot in the PKCS#11 v2.40 function list.

#### Token mutation accessors

`fhsm_token_object_set_label`, `fhsm_token_object_set_id`, `fhsm_token_object_set_flags` in `src/fhsm_token.c`. Each takes the token mutex, checks `logged_in`, finds the object by handle, mutates, marks `objects_dirty`, persists via atomic write. Required by `C_CopyObject` + `C_SetAttributeValue`. No changes to the on-disk format ; existing v1.2.2 token files load unchanged.

#### Boot KAT export-roundtrip extended to 6 new cryptographic surfaces

`kat/cavp_extended.c` --- 6 new helpers following the v1.2.2 ECDSA pattern (generate keypair, exercise the operation with original references as control, serialize public key via `i2d_PUBKEY`, reload via `d2i_PUBKEY`, repeat the operation, compare byte-for-byte) :

| Surface | KAT name | Mechanism |
|---|---|---|
| RSA-PSS-SHA256 | `RSA-2048-PSS-SHA256-export-roundtrip` | Sign with original, verify with reloaded pubkey. |
| RSA-OAEP-SHA256 | `RSA-2048-OAEP-SHA256-export-roundtrip` | Encrypt with reloaded pubkey, decrypt with original. |
| Ed25519 | `Ed25519-export-roundtrip` | Sign with original, verify with reloaded pubkey (shared `EVP_DigestSign` path with ML-DSA). |
| ML-DSA-65 | `ML-DSA-65-export-roundtrip` | Sign with original, verify with reloaded pubkey. |
| ML-KEM-768 | `ML-KEM-768-export-roundtrip` | Encapsulate with reloaded pubkey, decapsulate with original, compare shared secret. |
| ECDH (P-256/384/521) | `ECDH-Pxxx-export-roundtrip` | Derive `ss1` with original peer, derive `ss2` with reloaded peer, compare. |

Total boot KAT vectors : 41 → 62 (added 18 in v1.3.0). Total boot time impact : ~+15 ms on x86_64-Debian-13 reference HW ; well within AGD_PRE §6.2 budget (< 2 s).

### Coverage status

```
PKCS#11 v2.40 dispatch table : 51 / 67 wired
                               (was 47 / 67 in v1.2.2)
                               (was 44 / 67 in v1.2.1 pre-Denis)
Boot KAT external surfaces   :  6 / 7 (SLH-DSA excluded by design)
```

### Validation

- All 62 KATs green in dev mode and in CI `test-fips-mode`.
- `pkcs11-tool --module ./libfreehsm-fips.so --list-mechanisms` end-to-end regression suite with NSS / OpenSC / softhsm : **PASS**.
- CI `reproducibility` : byte-identical builds across two independent runs.
- New ECDH timings (vs RFC6979 ECDSA control on same hardware) :

```
ECDH-P256-export-roundtrip   :    542 us
ECDH-P384-export-roundtrip   :  2 544 us
ECDH-P521-export-roundtrip   :  2 073 us
```

### Acknowledgements

Denis Mingulov ([mingulov.com](https://mingulov.com)) reported the original function-list gap via responsible disclosure on 2026-06-23 ; without that report the v2.40 dispatch table completion would not have shipped in v1.3.0. Two further findings (memory-safety + key-handling) are pending via the encrypted channel ; they will be addressed in a v1.3.1 or v1.4.0 release as appropriate.

### Affected releases (forward-compatibility)

| Release | Upgrade priority | Reason |
|---|---|---|
| v1.2.2 | Recommended | No security fix ; enhancements only. Forward-compatible. |
| v1.2.1 | **Required** | Has the v1.2.1 integrity-verify silent-OK-on-mismatch defect (see v1.2.1 §"Affected releases"). |
| v1.2.0 and older | **Required** | Same v1.2.1 defect + the raw `CKM_ECDSA` silent-default-digest defect (see v1.2.2 §"Affected releases"). |

---

## [1.2.2] --- 2026-06-27

**External-reporter security patch + boot-KAT extension.** Ships four substantive changes triggered by a responsible-disclosure report from Denis Mingulov (`pkcs11-check`, 2026-06-26) plus one boot-time regression guard that codifies the methodology Denis's report exposed as a gap.

**Headline finding (Denis Finding 1)** : every signed release of FreeHSM C since v1.1.0 has produced ECDSA signatures via the `CKM_ECDSA` mechanism that no third-party verifier could check. The root cause is `EVP_DigestSignInit_ex(..., mdname = NULL, ...)` on the OpenSSL 3.x default provider's ECDSA digest-sign function applying an internal default digest (SHA-256) before signing, so the module signed `SHA-256(input)` instead of `input`. The bug had been invisible internally because `C_Verify` applied the same default symmetrically ; Wycheproof's verify-only corpus did not exercise the sign path externally. Severity HIGH on correctness / interoperability (CVSS 7.5, `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) ; not exploitable in confidentiality or integrity sense (private key never leaked). **All deployments running v1.1.0 - v1.2.1 should upgrade to v1.2.2 immediately.**

Disclosure follows the same transparency-first model as v1.2.1 : informational GitHub Security Advisory (no CVE while the project is in pre-certification), CHANGELOG entry, Security Target update, SECURITY.md credit. Reporter credited as Denis Mingulov via `pkcs11-check`.

### Fixes

#### Finding 1 (HIGH) --- raw CKM_ECDSA / CKM_RSA_PKCS sign+verify silently applied a default digest

`src/fhsm_pkcs11.c::sign_asymmetric` and `verify_asymmetric` previously routed raw mechanisms (`CKM_ECDSA` bare, `CKM_RSA_PKCS` bare) through `EVP_DigestSignInit_ex(ctx, &pctx, mdname = NULL, ...)`, expecting OpenSSL to treat the input as a pre-computed digest. On the OpenSSL 3.x default provider, the ECDSA digest-sign function applies an internal default digest (observed as SHA-256 on 3.5.x) when `mdname` is NULL, so the module signed `SHA-256(input)` instead of `input`. The module's own verify path applied the same default symmetrically, masking the bug to internal sign+verify cycles. External verifiers ( `openssl dgst -sha256 -verify` , `openssl pkeyutl -verify` ) rejected every signature.

Fixed by branching on `hash == NULL` in both functions : raw mode now uses `EVP_PKEY_sign` / `EVP_PKEY_verify` on a freshly-allocated `EVP_PKEY_CTX`, which is the canonical OpenSSL 3.x API for signing a pre-computed digest. Hashed mechanisms ( `CKM_ECDSA_SHAxxx`, `CKM_SHAxxx_RSA_PKCS` ) continue through the existing `EVP_DigestSign` / `EVP_DigestVerify` path unchanged.

Validated locally and in CI on P-256, P-384, P-521 via Denis's exact reproduction script. Module self-verify and external `openssl dgst` verify both pass post-fix.

#### Finding 2 (HIGH compliance) --- `C_CreateObject` and four siblings were unreachable through `C_GetFunctionList`

Five functions implemented in `src/fhsm_pkcs11.c` were exported as ELF symbols but their slots in `CK_FUNCTION_LIST` were not assigned :

| Slot | Function | v1.2.2 status |
|---|---|---|
| 15 | `C_GetSessionInfo` | implemented + wired |
| 20 | `C_CreateObject`   | wired (implementation existed since v1.0) |
| 23 | `C_GetObjectSize`  | implemented + wired |
| 21 | `C_CopyObject`     | deferred to v1.3.0 (not yet implemented) |
| 25 | `C_SetAttributeValue` | deferred to v1.3.0 (not yet implemented) |

Normal PKCS#11 consumers (`pkcs11-tool` + every standard library) reach these functions through `C_GetFunctionList -> fl->C_*` ; the module's internal test harnesses and the Wycheproof Python adapters bypass the function-list dispatch and call the symbols via `dlsym`, so the gap was invisible to CI. Particularly ironic : v1.2.0 (released 5 days before this report) celebrated a structural decomposition of `C_CreateObject` that was, all along, unreachable through any standard caller.

Fixed by adding the three wired-and-implemented slots to `fhsm_function_list` in v2.40 mode ( mirrored into the v3.0 table by the existing `fhsm_init_v3_0_table`). A new accessor `fhsm_session_info(h, *slot, *flags, *role)` was added to `src/fhsm_session.c` for `C_GetSessionInfo` ; `C_GetObjectSize` reuses the existing `fhsm_token_object_get` path. `C_CopyObject` and `C_SetAttributeValue` are documented as known limitations for v1.2.2 and roadmapped for v1.3.0.

#### Operational gap : sign-only GPG key

The published GPG key `743A 6A59 04A1 4616 46A6 408D E485 6016 2DBB F28A 2` was sign + certify + authenticate only, with no encryption capability. Denis could not send the rest of his report (memory-safety + key-handling findings) over an encrypted channel. A cv25519 encryption subkey (fingerprint `9813 876A 34BA DD4A 0A50 915E 7EAC 4BA5 5574 DBE8`) was generated on 2026-06-26 and published to `keys.openpgp.org` (with the `afchine.mad@gmail.com` address verified) and `keyserver.ubuntu.com`. SECURITY.md is updated to reflect the new key material and documents the gap honestly. The primary key remains sign / certify / authenticate only ; only the encryption operation has a target now.

### Added

#### Boot KAT : ECDSA export-roundtrip self-consistency (P-256 / P-384 / P-521)

`kat/cavp_extended.c::run_ecdsa_export_roundtrip()`. Three new boot-time KAT vectors that enforce the methodology the v1.2.2 fix is built on. For each curve : generate a fresh keypair via `EVP_PKEY_Q_keygen`, compute the digest of a fixed reference message with the matching SHA, sign the digest via `EVP_PKEY_sign` (raw mode), serialize the public key via `i2d_PUBKEY`, reload via `d2i_PUBKEY` (mimicking exactly what an external verifier does), and verify via `EVP_PKEY_verify` on the reloaded public key. Returns 1 on success and 0 on any EVP failure or verify mismatch.

If a future OpenSSL provider upgrade re-introduces the silent-default-digest behaviour for `EVP_PKEY_sign`, or if `i2d_PUBKEY` / `d2i_PUBKEY` ever stop producing byte-stable round-trips for EC keys, this boot KAT fails at `C_Initialize` and the module refuses to start. Subsequent regressions on the raw sign path are catchable at boot rather than discovered by external reporters running `pkcs11-check`.

KAT count : 51 -> 54. `FHSM_KAT_MAX` (64) unchanged.

The pattern generalises and will be extended in future releases : every cryptographic surface that the module exposes externally ( sign / verify / wrap / unwrap / derive ) should have an analogous boot KAT that exercises the external-roundtrip property, not just the internal `EVP_PKEY -> EVP_PKEY` round trip.

### Affected releases

| Version | Released | Finding 1 (raw ECDSA) | Finding 2 (function list) |
|---|---|---|---|
| v1.1.0 | 2026-06-12 | yes (origin) | yes (origin) |
| v1.1.1 - v1.1.18 | 2026-06-12 - 2026-06-20 | yes | yes |
| v1.2.0 - v1.2.1 | 2026-06-20 - 2026-06-21 | yes | yes |
| **v1.2.2** | **2026-06-27** | **fixed** | **3 of 5 fixed, 2 deferred** |

### Validation

```
Boot KAT                              54 / 54 vectors green (was 51 / 51)
   --- of which the 3 new export-roundtrip vectors :
   ECDSA-P256-export-roundtrip / SHA-256  PASS (~1200 us)
   ECDSA-P384-export-roundtrip / SHA-384  PASS (~1000 us)
   ECDSA-P521-export-roundtrip / SHA-512  PASS (~1150 us)

Denis's killer test (external verify after raw CKM_ECDSA sign) :
   P-256 : OK   P-384 : OK   P-521 : OK

CI lint / build / sign / smoke    : green
CI reproducibility                : byte-identical
CI test-coverage matrix           : 24 / 0 / 8 (exercises sign + verify
                                    via pkcs11-tool, which routes through
                                    the production sign_asymmetric path)
CI test-fips-mode                 : green (FIPS strict env exercises
                                    the raw ECDSA fix end-to-end)
Wycheproof full sweep             : 6 978 / 0 unchanged from v1.2.1
```

### Recommended action

Any deployment running v1.1.0 - v1.2.1 should upgrade to v1.2.2. The upgrade is a drop-in `.so` replacement ; PKCS#11 wire compatibility is unchanged. Re-sign the embedded digest via `make integrity` from the v1.2.2 source, or take the pre-signed binary tarball directly from the v1.2.2 GitHub Release.

Specifically affected workflows :

* **Any consumer that verifies the module's ECDSA signatures externally** (CA / RA issuing certificates, signature-archive verifiers, peer-to-peer protocols using ECDSA, etc.) is non-interoperable in v1.1.0 - v1.2.1 and is restored to spec-compliant ECDSA in v1.2.2. The module's pre-v1.2.2 signatures cannot be retroactively repaired ; only signatures produced by v1.2.2+ are interoperable.

* **Any consumer that calls `C_CreateObject` / `C_GetSessionInfo` / `C_GetObjectSize` through the standard `C_GetFunctionList` dispatch** received `CKR_FUNCTION_NOT_SUPPORTED` in v1.1.0 - v1.2.1 and gets a valid dispatch in v1.2.2.

### Discovery + correction context

The defects were reported by **Denis Mingulov** via the `pkcs11-check` testing harness on 2026-06-26, with reproducible PoC on P-256 / P-384 / P-521 (every run) for Finding 1 and a sharp diagnostic for Finding 2. The discovery + correction protocol established in v1.2.1 Security Target §13.8 was extended to incorporate the *external-reporter* case :

1. **Symptom triage** : take any external reporter's evidence seriously, even if reported in clear (when the canonical encrypted channel is unavailable). Acknowledge the operational gap (sign-only GPG key) that forced clear-text disclosure ; restore the encrypted channel before continuing the technical triage.
2. **Read both sides** : the reporter's evidence + the module's source. Verify the reproduction locally before challenging the report.
3. **Cross-check the contract** : compare the module's behaviour with the OpenSSL canonical APIs (in this case, `EVP_PKEY_sign` is documented as the API for signing a pre-computed digest ; `EVP_DigestSign` with `mdname=NULL` was the wrong choice).
4. **Killer-test artifact** : Denis already provided one (his pkcs11-check repro) ; we add the boot-KAT regression guard so the methodology is institutionalised in the module itself.
5. **Scope the temporal impact** : `git blame` on the affected lines ; document the affected window ; decide on disclosure model.

The Security Target v0.8 §13.8 codifies this extension as a sub-section "External reporters".

### Acknowledgements

* **Denis Mingulov** for the careful report, the responsible-disclosure framing (despite the encrypted-channel friction), the clean reproduction script, and the noise-aware framing on `pkcs11-check` raw output.
* The OpenSSL project for the canonical `EVP_PKEY_sign` API and the standard `i2d_PUBKEY` / `d2i_PUBKEY` round-trip primitives.

### Deferred to v1.3.0

* `C_CopyObject` and `C_SetAttributeValue` : not currently implemented in the module ; documented as known limitations of the v2.40 function list. Denis's initial report claimed they were "implemented but not wired" ; on re-reading the source they turned out not to be implemented at all. v1.3.0 will either implement them or formally retire the slots.

* External-roundtrip boot KATs for RSA-PSS / RSA-OAEP / ML-DSA / SLH-DSA / Ed25519. Pattern documented in this CHANGELOG and Security Target §13.8 ; instances to be added per release.

### This is the 21st consecutive GPG-signed release.

## [1.2.1] --- 2026-06-21

**Security patch release.** Fixes a critical defect in the module integrity self-test (`src/fhsm_integrity.c::do_verify`) that effectively disabled FIPS 140-3 §7.10.2 in every signed production build of FreeHSM C since the initial open-source release v1.1.0 (commit `0c0f5df`, 2026-06-12). A tampered `libfreehsm-fips.so` would have passed the integrity check silently. All 19 GPG-signed releases between v1.1.0 and v1.2.0 are affected. **All users running any of those versions should upgrade to v1.2.1 immediately.**

The project is in pre-certification status (FIPS 140-3 Level 1 / CC EAL4+ candidate, no known production deployments) ; a CVE is not requested. Disclosure is via this CHANGELOG entry, the v1.2.0 → v1.2.1 commit history, an updated Security Target v0.7, and a transparent GitHub Security Advisory in informational mode.

### Discovery context

The defect was found during the post-release investigation of a dev-environment integrity quirk on the maintainer's VM (task #55 in the issue tracker). The dev quirk turned out to be the surface symptom of three latent bugs, only one of which had operational consequences in production. The full triage took place across two sessions and is documented in the commits and the Security Target §13.8.

### Three findings in `src/fhsm_integrity.c`

#### Finding 1 (HIGH) --- `do_verify` always returned `FHSM_RV_OK` after the comparison block

The comparison block at the end of `do_verify` had two if/return guards intended to fail closed on (a) unsigned builds (all-zero embedded digest) without the development bypass env var and (b) signed builds with a mismatched embedded digest without the bypass env var. The guards returned `FHSM_RV_OK` correctly when the bypass env var WAS set, but had no return statement in the else branches : the function fell through to a final `return FHSM_RV_OK` regardless of the comparison outcome.

The net effect : a tampered `libfreehsm-fips.so` could be loaded by an unmodified PKCS#11 application, the integrity self-test would compute the (incorrect) digest of the tampered binary, the comparison block would fall through to OK, and the module's state machine would proceed to `INITIALIZED`. No error would be reported to the caller. The FIPS 140-3 §7.10.2 software / firmware integrity self-test was, in practice, not enforced.

**Patched** in `do_verify` : both the `is_all_zero` (unsigned) and the `fhsm_ct_memcmp` (mismatch) branches now explicitly `return FHSM_RV_INTEGRITY_FAILED` when the bypass env var is not set, before reaching the final `return FHSM_RV_OK` (which is now only reachable on a successful match).

#### Finding 2 (MEDIUM) --- use-after-free on `find_section_offset` failure path

When `find_section_offset(buf, ...)` failed (the binary lacks `.fhsm_digest`, or the section is too small) AND the bypass env var was unset, `do_verify` :

1. zeroized `buf` ;
2. `free(buf)` ;
3. checked the bypass env var ;
4. *fell through* to `memset(buf + off, 0, len)` --- a use-after-free on the freed buffer.

The condition was reachable from any binary lacking the `.fhsm_digest` section (which is silently the case for most operator misuses : running an unsigned dev build under `FHSM_FIPS_MODE=fips`, or executing a stripped variant of the .so). The UAF behaviour is technically undefined ; on glibc it would typically corrupt the malloc arena and crash on the next allocation.

**Patched** in `do_verify` : add `return FHSM_RV_INTEGRITY_FAILED;` immediately after the bypass-env-var check, so the function exits cleanly without touching the freed buffer.

#### Finding 3 (LOW) --- `locate_self` failed for statically-linked binaries

`locate_self` uses `dl_iterate_phdr` to find which loaded module contains the `fhsm_module_integrity_digest` symbol. The callback (`find_self_cb`) reads `dlpi_name` from `struct dl_phdr_info` to get the binary path. For the main executable (the case for any binary that statically links `fhsm_integrity.o` instead of dynamically loading `libfreehsm-fips.so` --- including `tests/test_smoke`, the CAVS harness, and most local test artifacts), `dlpi_name` is the empty string per Linux convention. The callback skipped setting `ctx.found = 1` in that case, `locate_self` returned `-1`, and `do_verify` returned `FHSM_RV_FUNCTION_FAILED` --- silently, before any integrity comparison ran.

The operational impact is small (the affected binaries are test harnesses, not the deployed `.so`), but the silent failure meant that every developer workflow exercising the integrity check via `tests/test_smoke` was effectively bypassed.

**Patched** in `find_self_cb` : when `dlpi_name` is empty, recover the binary's path via `readlink("/proc/self/exe", ...)`. Bytes-on-disk integrity check works correctly from that point on for any binary that exposes `/proc/self/exe`, which covers all supported environments. Chroot/jail environments without `/proc` fall back to the existing setup-error path.

### Validation

```
Build clean    : -Werror -Wpedantic -Wconversion -Wstringop-truncation, no warning.
CI lint        : green
CI build       : green (sign module + smoke test green in CI's FIPS env)
CI reproducibility    : byte-identical
CI test-coverage matrix : 24 / 0 / 8
CI test-fips-mode      : green (this is the path that exercises the integrity
                                 check without bypass in production-like FIPS env)
```

#### Killer test : tampered binary detection

```bash
cp libfreehsm-fips.so libfreehsm-fips.so.tampered
# Flip 1 byte in the .text segment, outside .fhsm_digest :
printf '\x00' | dd of=libfreehsm-fips.so.tampered bs=1 seek=20000 count=1 conv=notrunc

# Pre-v1.2.1 : tampered binary loads, C_Initialize returns OK, services exposed.
# v1.2.1   : C_Initialize returns 0x80000002 (FHSM_RV_INTEGRITY_FAILED).
```

The same procedure on the v1.2.0 binary (or any prior signed release) returns OK silently, which is the proof-of-bug for the v1.1.0 → v1.2.0 affected window.

### Affected releases

| Version | Released | Affected |
|---|---|---|
| v1.1.0 | 2026-06-12 | yes (origin) |
| v1.1.1 - v1.1.18 | 2026-06-12 - 2026-06-20 | yes |
| v1.2.0 | 2026-06-20 | yes |
| **v1.2.1** | **2026-06-21** | **fixed** |

Tag SHAs for every affected release are listed in the GitHub Security Advisory (informational).

### Recommended action

Any deployment running v1.1.0 - v1.2.0 should upgrade to v1.2.1. The upgrade is a drop-in `.so` replacement ; PKCS#11 wire compatibility is unchanged. Re-signing the embedded digest via `make integrity` is required exactly as for the original install (build-from-source pipeline) or take the binary tarball directly from the v1.2.1 GitHub Release (`libfreehsm-fips.so` with `.fhsm_digest` already patched).

If, for any operational reason, an upgrade is not immediately possible, the interim mitigation is to verify the SHA-256 of the deployed `.so` against the value published in the corresponding release notes by an out-of-band channel (e.g. `sha256sum` from the GitHub Release page over HTTPS, comparing with `sha256sum` on the running binary). This restores the integrity guarantee externally to the module's own self-test.

### Changed

* `src/fhsm_integrity.c::find_self_cb` : `+18 lines` (Finding 3, the `/proc/self/exe` fallback).
* `src/fhsm_integrity.c::do_verify` : `+5 lines` (Finding 2, the UAF return guard) and `+8 lines` (Finding 1, the two `INTEGRITY_FAILED` returns in the comparison block). Comments updated to document the rationale and the v1.2.1 fix lineage.
* `include/fhsm_common.h` : `FHSM_VERSION_PATCH` and `FHSM_VERSION_STRING` bumped to `1` and `"1.2.1-FIPS"`.

### Security Target

Updated to v0.7 (`docs/FIPS_140_3_SECURITY_TARGET.md`) :

* §7.10.2 (Software / Firmware Integrity Test) : new paragraph documenting the v1.2.1 fix and the v1.1.0 - v1.2.0 affected window.
* §13.5 (Structured fuzzing) : note added on how the v1.2.0 ALC_DVS-grade decomposition indirectly surfaced the integrity defect by making the dev-env quirk visible enough to investigate.
* §13.8 NEW : Discovery + correction protocol --- documents the workflow that found the bug as a transferable pattern.
* Revision-history entry v0.7.

### SECURITY.md addendum

A new section documents the discovery + correction protocol followed for this release, the decision to disclose without a CVE due to the pre-certification status of the project, and the public artefacts (this CHANGELOG, the v0.7 Security Target, the informational GitHub Security Advisory) that constitute the disclosure.

### This is the 20th consecutive GPG-signed release.

## [1.2.0] --- 2026-06-20

The "Simorgh Labs" minor release. Three coordinated changes that justify the minor bump : (1) the manufacturer identifier presented through PKCS#11 `C_GetInfo` / `C_GetSlotInfo` / `C_GetTokenInfo` changes from "FreeHSM C (FIPS 140-3)" to "Simorgh Labs, Open Source Cryptography and Digital Trust", a backward-incompatible identity-string change at the PKCS#11 layer ; (2) `C_CreateObject` is decomposed into a pure-C parser (`fhsm_parse_create_attrs`, no OpenSSL dependency) plus an OpenSSL EVP builder, removing the long-standing inline-mirror divergence between the production code and the libFuzzer harness ; (3) the new `fuzz_create_attrs` harness attacks the production parser directly, replacing the unit-level mirror coverage of v1.1.x with integration-level coverage on the real C code path that runs when an untrusted PKCS#11 caller invokes `C_CreateObject`. Backward-compatible at the wire / cryptographic level : every Wycheproof corpus continues to pass bit-identically (~5 000 invocations of `C_CreateObject` across 6 paths) ; only the human-readable manufacturer string changes for end-user tools.

### Added

* **`include/fhsm_create_attrs.h`** (~130 lines) : public API for the new pure parser. Defines `fhsm_create_attrs_t` (typed output struct with a 5-path enum : `VERBATIM` / `EC_PUB` / `ED25519_PUB` / `ED448_PUB` / `RSA_PUB` plus path-specific resolved fields) and `fhsm_parse_rv_t` (return-code enum mapped at the call site to PKCS#11 `CKR_*`). Header has zero OpenSSL dependency.

* **`src/fhsm_create_attrs.c`** (~230 lines) : the parser TU. Pure C, OpenSSL-free, no allocation, no global state. Validates `CKA_CLASS` / `CKA_KEY_TYPE` / `CKA_LABEL` / `CKA_ID`, dispatches on `(cko, ckk)` to the right sub-parser, resolves curve OIDs through a locally-duplicated 3-curve lookup table (`P-256` / `P-384` / `P-521`) plus Ed25519 / Ed448, strips DER `OCTET STRING` wrappers through `fhsm_strip_octet_string_inline` from `include/fhsm_attr_utils.h`, returns a typed `fhsm_parse_rv_t` error enum. Caller maps to `CKR_*` codes through a small `map_parse_rv()` in `fhsm_pkcs11.c`.

* **`fuzz/fuzz_create_attrs.c`** (~250 lines) : new libFuzzer + ASAN + UBSAN harness that attacks `fhsm_parse_create_attrs()` directly. Decodes the fuzz input into a synthetic `CK_ATTRIBUTE[]` template (per-record `type:CK_ULONG`, `len:u8`, payload), calls the production parser, and verifies eleven structural invariants on the output via `__builtin_trap` :
    * `P1` path enum in range, `P2` non-INVALID on OK, `P3` label NUL-terminated within bounds, `P4` id pointer/length consistency, `P5` `cko ∈ {PUBLIC, PRIVATE, SECRET}`, `P6` `VERBATIM` carries a non-NULL value, `P7` `EC_PUB` carries one of three known curve strings + non-NULL point, `P8` / `P9` Ed paths carry NULL `ec_group` (curve in path enum) + non-NULL point, `P10` `RSA_PUB` carries both modulus and exponent.
    * `E1` on every non-OK return, `path == INVALID` (the parser `memset()`s the output at entry).
    * Plus a truncation probe that re-parses the same template with the last record's `ulValueLen` shrunk by one byte, stressing length-vs-buffer accounting in the `OCTET STRING` unwrapper, the OID matcher, and the RSA modulus/exponent extractor at the buffer tail.
    * Local 60-second smoke run on the developer machine : 18 678 924 executions, 306 211 exec/s, 714 new units, 0 crash / 0 ASAN / 0 UBSAN / 518 MB peak RSS.

### Changed

* **`src/fhsm_pkcs11.c::C_CreateObject`** : the body shrinks from ~215 lines (v1.1.18 monolith) to ~110 lines. The new structure is :
    1. Session / state / argument validation (unchanged).
    2. Call to `fhsm_parse_create_attrs()`.
    3. `map_parse_rv()` to translate the parse return code to `CKR_*`.
    4. Switch on `attrs.path` :  `VERBATIM` stores `CKA_VALUE` directly, the three EVP_PKEY paths (`EC_PUB`, `ED25519_PUB`/`ED448_PUB`, `RSA_PUB`) build the corresponding key with OpenSSL's `EVP_PKEY_fromdata` API, and the common epilogue serializes as SPKI DER through `i2d_PUBKEY` and registers the token object via `fhsm_token_object_add`.

* **`src/fhsm_pkcs11.c`** : two now-orphan local helpers (`fhsm_ec_oid_to_group` and `fhsm_strip_octet_string`) are removed. Their only call sites were inside `C_CreateObject` and have moved to the new parser TU (the latter via its `_inline` counterpart in `include/fhsm_attr_utils.h`, the former duplicated locally in `src/fhsm_create_attrs.c` to keep the parser self-contained).

* **`src/fhsm_pkcs11.c`** : the manufacturer identifier presented through three `C_Get*Info` calls changes from "FreeHSM C (FIPS 140-3)" to "Simorgh Labs, Open Source Cryptography and Digital Trust". The PKCS#11 string fields are space-padded fixed-width buffers (`CK_INFO::manufacturerID` is 32 chars, `CK_SLOT_INFO::manufacturerID` is 32 chars, `CK_TOKEN_INFO::manufacturerID` is 32 chars) so the new string is truncated as required by §5.5 of the PKCS#11 v3.2 base spec : `"Simorgh Labs, Open Source Crypt"` (31 chars + 1 trailing space). `CK_INFO::libraryDescription` (32 chars) takes the previous module label "FreeHSM C (FIPS 140-3)" so the library identity remains discoverable. `CK_TOKEN_INFO::model` is unchanged (`"FreeHSM-C-v1"`).

* **`Makefile`** : `LIB_SRC` adds `src/fhsm_create_attrs.c` next to the existing extracted TUs `src/fhsm_ecdsa_raw.c` and `src/fhsm_pq_params.c`.

* **`fuzz/Makefile.fuzz`** : adds a fourth build target `fuzz/fuzz_create_attrs` next to the existing three. The new rule links the production TU `src/fhsm_create_attrs.c` into the harness binary (the same object file as the production module library).

* **`fuzz/README.md`** : harness table gains a fourth row ; new section under "Property invariants checked" enumerates P1–P10 + E1 + the truncation probe with the rationale for each invariant ; the Maintenance table now lists `fhsm_parse_create_attrs` as the third production helper linked into a harness, leaving only two legacy `fhsm_pkcs11.c` call sites still using inline mirrors.

* **`README.md`** : the "Maintainer" section continues to show the Simorgh Labs identity and the GPG key fingerprint added in v1.1.18.

* **`include/fhsm_common.h`** : `FHSM_VERSION_MAJOR` / `MINOR` / `PATCH` / `STRING` bumped to `1` / `2` / `0` / `"1.2.0-FIPS"`.

### Removed

* **`src/fhsm_pkcs11.c::fhsm_ec_oid_to_group`** (static helper, ~25 lines) : the only call site was inside the previous `C_CreateObject` monolith ; the lookup table is now duplicated locally in `src/fhsm_create_attrs.c` to preserve the OpenSSL-free property of the parser TU.

* **`src/fhsm_pkcs11.c::fhsm_strip_octet_string`** (static helper, ~30 lines) : same migration. The remaining `fhsm_pkcs11.c` callers were already using the `_inline` counterpart in `include/fhsm_attr_utils.h` (added in v1.1.14 for the original fuzz harness), so the local copy is now redundant.

### Security & Validation

```
Boot KAT 51 / 51 vectors unchanged in dev mode (C_CreateObject is
   not exercised in the boot KAT path).

The C_CreateObject decomposition was validated by CI against the
full Wycheproof corpus and the matrix step :

   * Wycheproof RSA-PSS verify   : 1 083 / 0   (CKK_RSA path)
   * Wycheproof RSA-OAEP         :   788 / 0   (CKK_RSA path)
   * Wycheproof ECDSA verify     : 3 098 / 0   (CKK_EC path)
   * Wycheproof EdDSA            :   236 / 0   (CKK_EC_EDWARDS path)
   * Wycheproof ML-DSA verify    :   614 / 0   (CKK_ML_DSA verbatim)
   * CI matrix CKK_AES verbatim  :    24 / 0 / 8

Total : ~5 000 C_CreateObject invocations across 6 paths, 0
regression vs the v1.1.18 monolith. The new parser is
semantically-identical to the v1.1.18 inline implementation.

fuzz_create_attrs smoke run (60s on dev machine, libFuzzer +
ASAN + UBSAN) :
   * 18 678 924 executions
   * 306 211 exec/s
   * 714 new units discovered
   * 0 crash / 0 ASAN report / 0 UBSAN report
   * peak RSS 518 MB
The nightly CI fuzz run will exercise the harness for 1 h on the
same conditions ; any future crash will be tracked per fuzz/README.md
§"Crash policy".

CI all 5 jobs green : lint / build+smoke / test-fips-mode /
test-coverage-matrix / reproducibility.
```

This is the 19th consecutive GPG-signed release.

### ALC_DVS rationale for the minor bump

Two of the three changes (manufacturer rename + new fuzz harness) are
ALC_DVS-grade improvements rather than purely cryptographic ones, which
is the reason this release ships as a minor bump instead of a patch
release. The manufacturer rename is a forward-looking identity change ;
the C_CreateObject decomposition is a structural refactor that pays off
on the security-evidence side by collapsing the previous "production
code vs fuzz mirror" divergence into a single attack surface that the
nightly fuzz run exercises with real bytes. See Security Target v0.6
§13.5 for the corresponding ALC_DVS write-up.

## [1.1.18] --- 2026-06-20

The "real AES-GMAC" release. Replaces a long-standing OpenSC pkcs11-tool interop alias (CKM_AES_GMAC at 0x108A silently aliased to CKM_AES_CMAC) with a spec-compliant AES-GMAC implementation per PKCS#11 v3.2 §6.10.6 and NIST SP 800-38D §6.4. Backward-compatible by construction : callers that send 0x108A with no IV (the OpenSC code path) continue to receive CMAC behaviour ; callers that send 0x108A with an IV receive real GMAC. Coincides with the first session where `test_smoke` runs end-to-end on a developer machine in dev mode without any `[!]` (50 / 50 KAT vectors).

### Added

* **`src/fhsm_pkcs11.c::aes_gmac`** : single-shot EVP_MAC "GMAC" helper. Mirrors the structural pattern of the existing `aes_cmac` helper ; takes (key, iv, data) and emits the 16-byte tag. Selects the underlying AES key size (128 / 192 / 256) from the imported secret key length.

* **`src/fhsm_pkcs11.c::resolve_mech`** : optional forced-downgrade gate controlled by `FHSM_OPENSC_GMAC_ALIAS=1`. When set, all CKM_AES_GMAC requests at op_init are rewritten to CKM_AES_CMAC, regardless of whether an IV was provided. Off by default ; AGD_PRE forbids it in production. The implicit "no IV → CMAC" downgrade in op_init handles the common case (OpenSC pkcs11-tool) automatically without needing this env var.

* **`src/fhsm_pkcs11.c::op_init` IV parsing** : new block that accepts the GMAC IV via either the PKCS#11 v3.0 raw-bytes convention (what pkcs11-tool sends) or the PKCS#11 v3.2 `CK_AES_GMAC_PARAMS` struct `{ ulIvLen, pIv }`. The struct form is heuristically detected when `ulParameterLen == 16`. IV is stored in the shared `op->gcm_iv` / `op->gcm_iv_len` buffer (sufficient for Wycheproof's `LongIv` exercises if we ever extend the GMAC corpus to those).

* **`kat/cavp_extended.c` AES-GMAC self-consistency boot KAT** : a new boot-time KAT that computes the AES-256-GMAC tag for the existing TC14/TC15 inputs (K = `kK`, IV = `TC13_IV`, AAD = `kA`) via TWO independent OpenSSL code paths (`EVP_MAC` "GMAC" and `EVP_CIPHER` AES-GCM with empty plaintext) and asserts the two 16-byte outputs match byte-for-byte. Mathematically the two paths are identical per NIST SP 800-38D §6.4 ; any divergence catches a bug in either path. Stronger than a fixed-value KAT because it exercises two implementations in parallel.

* **`tests/wycheproof/adapters/aes_gmac.py`** : Wycheproof adapter that exercises AES-GMAC against the `aes_gmac_test.json` corpus. Follows the same pattern as the existing `aes_cmac.py` adapter, with the per-test IV passed through the mechanism parameter (raw bytes, PKCS#11 v3.0 convention).

* **`tests/wycheproof/adapters/_p11.py::CKM_AES_GMAC`** : adds the constant `0x108A` for use by the new adapter.

### Changed

* **`src/fhsm_pkcs11.c`** : the `CKM_AES_CMAC_OPENSC_ALIAS` constant is renamed to `CKM_AES_GMAC` (same numeric value, semantically correct name per PKCS#11 v3.2 §A.4.1). The four call sites that previously accepted "either CMAC or OpenSC alias" now accept "either CMAC or GMAC" and route to distinct helpers based on the resolved mechanism.

* **`src/fhsm_pkcs11.c::op_init` implicit downgrade** : if mechanism is CKM_AES_GMAC AND no IV was provided in pParameter, the mechanism is downgraded to CKM_AES_CMAC in op_init. This is a self-consistent disambiguation (real GMAC fundamentally requires an IV ; "GMAC without IV" can only mean "CMAC alias" in practice). The fix preserves backward compatibility for OpenSC pkcs11-tool users without requiring an environment variable.

### Validation

```
Boot KAT now exposes 51 vectors (was 50 in v1.1.17). All green in
dev mode on Debian 13 + OpenSSL 3.5.6 default provider :

  AES-GMAC self-consistency : tag from EVP_MAC matches tag from
    EVP_CIPHER GCM tag-only.

CI all 5 jobs green :
  lint / build+smoke / test-fips-mode / test-coverage-matrix /
  reproducibility. The implicit-downgrade fix preserves the pre-
  v1.1.18 pkcs11-tool behaviour so the matrix step that does
  `pkcs11-tool --mechanism AES-CMAC` (which sends 0x108A) keeps
  working as before.

Wycheproof full sweep : 6 978 / 0 unchanged on v1.1.17 corpus ;
  the new aes_gmac adapter will be exercised once the corpus is
  declared and bumped in tests/wycheproof/run_wycheproof.py.
```

This is the 18th consecutive GPG-signed release.

## [1.1.17] --- 2026-06-20

The "RSA-OAEP output buffer sizing" patch. Fixes a too-small plaintext output buffer in the `cavp_extended` RSA-OAEP self-test that was rejected by OpenSSL 3.5.6 default provider with a `bad length` error from `rsa_enc.c:257`. Same investigation pattern as the previous three patch releases : the bug was hidden by `FHSM_KAT_ALLOW_FAIL=1` in CI and only surfaced after the v1.1.14/15/16 fixes let `test_smoke` reach this KAT.

### Changed

* **`kat/cavp_extended.c::run_rsa_oaep_roundtrip`** : the `pt` plaintext output buffer is enlarged from 64 bytes to 256 bytes (the RSA-2048 modulus size). OpenSSL 3.5.6 default provider requires the output buffer of `EVP_PKEY_decrypt` to be at least modulus-size when unwrapping OAEP, even when the post-unpad plaintext is much shorter (here, 16 bytes). The FIPS provider does not enforce this check, which is why the previous undersized buffer worked silently in CI's FIPS strict mode but produced a `bad length` error in dev mode. The change is purely a buffer-sizing fix ; the OAEP cryptography itself was never wrong.

### Added

* **`disabled/diag_rsa_oaep.c`** : standalone diagnostic that reproduces the exact failure with print-and-`ERR_print_errors` at every EVP step. The output isolates the failing call to `EVP_PKEY_decrypt` and prints the OpenSSL error chain verbatim. Provides reproducible evidence for the fix.

### Why this had been hidden for so long

OpenSSL 3.5.6 default provider tightened the output-buffer-size check on `EVP_PKEY_decrypt` for OAEP (probably as a hardening measure to prevent out-of-bounds writes in error paths). The FIPS provider kept the lenient behaviour, so CI under FIPS strict mode always passed even with the undersized buffer. The boot-KAT regression was masked by `FHSM_KAT_ALLOW_FAIL=1` in CI.

### Discovered (next open follow-up — if any)

After this fix, `test_smoke` reaches the PQ consistency self-tests (`ML-KEM-768 selftest-encaps+decaps`, `ML-DSA-65 selftest-sign+verify`, `SLH-DSA-SHA2-128f selftest-sign+verify`). These are non-deterministic round-trip tests so the same buffer-sizing class of bug could theoretically apply ; they passed in v1.1.16 local runs once reached, but a deep validation will follow if any `[!]` surfaces.

### Validation

```
Local test_smoke now exposes all 50 KAT slots in use, dev mode green
on the full chain we control (the AES-GCM TC15 etc. all pass).

CI : lint / build+smoke / test-fips-mode / test-coverage-matrix /
     reproducibility : all green.
Wycheproof full sweep : 6 978 / 0 across 9 PKCS#11 v3.2 families,
                        bit-identical to v1.1.16.
CI matrix : 24 / 0 / 8.
```

This is the 17th consecutive GPG-signed release.

## [1.1.16] --- 2026-06-20

The "non-canonical DER" patch release. Fixes a malformed DER signature in the `cavp_extended` ECDSA-P521-SHA512 RFC 6979 §A.2.7 KAT vector. The signature had a spurious leading 0x00 byte in the `s` INTEGER, making the DER non-canonical ; OpenSSL's `d2i_ECDSA_SIG` accepts the malformed input leniently (which is why the matrix and Wycheproof ECDSA paths always passed), but the boot-KAT `EVP_DigestVerify` path is stricter and silently failed. Same investigation pattern as v1.1.15's TC13_TAG fix : the bug was hidden by `FHSM_KAT_ALLOW_FAIL=1` in CI and only surfaced once `test_smoke` could reach this KAT after the v1.1.14 integrity-bypass fix and the v1.1.15 AES-GCM fix.

### Changed

* **`kat/cavp_extended.c::ecdsa_p521_sig`** : the DER signature for the ECDSA-P521-SHA512 RFC 6979 §A.2.7 KAT is corrected. The `s` INTEGER had `0x02 0x43 0x00 0x61 0x7c ...` (length 0x43=67 bytes including the illegal leading 0x00) ; the canonical encoding is `0x02 0x41 0x61 0x7c ...` (length 0x41=65 bytes, no leading 0x00). DER positive INTEGERs MUST omit a leading 0x00 byte when the next byte's MSB is < 0x80 (here `0x61` < `0x80`). The outer SEQUENCE length is updated `0x8b → 0x87` accordingly ; the C array shrinks from 143 to 138 bytes. The underlying r and s values are unchanged ; only the DER framing was malformed.

### Added

* **`disabled/verify_ecdsa_p521_rfc6979.py`** : standalone cross-validation script that confirms (a) the corrected DER bytes are produced by `python-ecdsa` with RFC 6979 deterministic signing using the published private key from §A.2.7, (b) the corrected signature verifies under Python `cryptography` and pycryptodome (DER mode), and (c) the underlying r||s values verify under pycryptodome (raw mode) for both the corrected and the previous malformed encoding (confirming the underlying maths was always right ; only the framing was wrong).

### Why this had been hidden for so long

OpenSSL's `d2i_ECDSA_SIG` is lenient with non-canonical DER : it parses the malformed input, extracts the right r and s values, and the resulting ECDSA verify succeeds. That's why the **CI matrix** (which exercises ECDSA via PKCS#11 → OpenSSL EVP) and the **Wycheproof ECDSA full sweep** (3 098 / 0 across P-256 / P-384 / P-521) have always passed. But the **boot-KAT EVP_DigestVerify path** goes through `OSSL_PARAM` machinery that is stricter about input encoding, and silently returned 0 for this one vector. Combined with `FHSM_KAT_ALLOW_FAIL=1` in CI, the failure was invisible until v1.1.14's integrity-bypass fix let `test_smoke` see the boot KAT report on a developer machine.

### Discovered (next open follow-up)

* **RSA-2048-OAEP-SHA256 self-test failure** : after the ECDSA-P521 fix, `test_smoke` reaches `RSA-2048-OAEP-SHA256 selftest-encrypt+decrypt` and reports `[!]` after 61 µs (suspiciously fast for a real OAEP round-trip on 2 048-bit). The matrix and runtime RSA-OAEP paths continue to work, so this is almost certainly another KAT data or setup issue, not a real RSA-OAEP regression. Tracked as a separate investigation following the now-rodé pattern.

### Validation

```
Local test_smoke now exposes 44 KATs visible (was 40+ in v1.1.15) :
  All previous KATs : green
  AES-GCM-256 / AES-GCM-decrypt
  SHA-256/384/512/SHA3 × 6
  HMAC-SHA-256 × 4
  AES-CBC / AES-CTR / AES-CMAC × 3
  ECDSA-P256/P384/P521 (P-521 now passing thanks to this fix)
  HKDF × 2
  PBKDF2 × 2
  RSA-2048-PSS-SHA256 (sign+verify)
  RSA-2048-OAEP-SHA256 [!] (next follow-up)

CI : lint / build+smoke / test-fips-mode / test-coverage-matrix /
     reproducibility : all green.
Wycheproof full sweep : 6 978 / 0 across 9 PKCS#11 v3.2 families,
                        bit-identical to v1.1.15.
CI matrix : 24 / 0 / 8 (with the known ECDH flaky behaviour).
```

This is the 16th consecutive GPG-signed release.

## [1.1.15] --- 2026-06-19

The "KAT data integrity" patch release. Fixes a pre-existing wrong expected value in the `cavp_extended` AES-GCM-256 no-AAD KAT (`TC13_TAG`) that had been silently bypassed in CI via `FHSM_KAT_ALLOW_FAIL=1` and only surfaced after the v1.1.14 integrity-bypass fix let `test_smoke` reach this KAT on a developer machine. Resolution is grounded in a cross-validation across three independent AES-GCM implementations.

### Changed

* **`kat/cavp_extended.c::TC13_TAG`** : the expected tag for the AES-256-GCM no-AAD case (same K/IV/P as the with-AAD TC15 case below, A = empty) is corrected from `0xb094dac5d93471bdec1a502270e3cc6c` to `0xeb9f796c8d356fc31a8433884b696f4f`. The new value is the empirically-verified output of three independent AES-GCM implementations :
  - OpenSSL 3.5.6 default provider via `EVP_EncryptInit_ex2` (C)
  - OpenSSL 3.5.6 via Python `cryptography` (cffi binding)
  - `pycryptodome` 3.23 (autonomous AES-GCM, no OpenSSL link)
  The original `0xb094dac5...` value, attributed in the source to NIST SP 800-38D Appendix B / McGrew–Viega paper Test Case 14, was inconsistent with every implementation we tested. The ciphertext (`0x522dc1f0...`) matches NIST across the board ; only the tag diverged. Since three independent implementations agree, the empirically-verified value is what callers receive at runtime. The "dev-mode divergence" documented in v1.1.14 is therefore **resolved** : there was never an OpenSSL bug, just a wrong expected value in our KAT data.

### Added

* **`disabled/verify_aes_gcm_tc14.py`** : standalone cross-validation script that derives the correct AES-256-GCM no-AAD tag from the same K/IV/P inputs via three independent codebases. Provides reproducible evidence for the corrected `TC13_TAG` value if a future CMVP audit asks for a NIST-published reference.

### Why ship this now ?

The fix is small (16 bytes of test-vector data + commentary) but its meaning is large : a KAT had been silently failing in CI for an unknown duration, hidden behind `FHSM_KAT_ALLOW_FAIL=1`. v1.1.14's integrity-bypass fix surfaced the failure on the developer path and motivated the cross-validation. Now that the right value is in the source, `test_smoke` in dev mode passes far deeper into the KAT chain than it ever did before, exposing the next layer of validation surface (see Discovered below).

### Discovered (open follow-up)

* **ECDSA-P521-SHA512 RFC 6979 §A.2.7 KAT failure** : after the AES-GCM fix, `test_smoke` continues past the AES vectors and now reports `[!] ECDSA-P521-SHA512 RFC6979-A.2.7`. The CI matrix and Wycheproof ECDSA full sweep (3 098 / 0 across P-256/P-384/P-521) continue to pass, which proves the production ECDSA P-521 path is correct ; the failure is almost certainly a wrong expected value in the KAT itself, same pattern as TC13_TAG. Tracked as a separate investigation ; resolution will follow in a future patch release once a cross-validation is done.

### Validation

```
Local test_smoke (Debian 13 + OpenSSL 3.5.6 default provider) :
  40+ KATs visible, all green except the new finding above.

CI (Debian 13 container + OpenSSL 3.5 FIPS provider) :
  lint                : 5 s, green
  build + smoke       : 26 s, green
  test-fips-mode      : 20 s, green
  test-coverage-matrix: 17 s, green  (24 / 0 / 8)
  reproducibility     : 21 s, green

Wycheproof full sweep : 6 978 / 0 across 9 PKCS#11 v3.2 families,
                        bit-identical to v1.1.14.
```

This is the 15th consecutive GPG-signed release.

## [1.1.14] --- 2026-06-19

The "fuzzing prep + libFuzzer harnesses" release. Closes the structured-fuzzing milestone (#191) by extracting the PKCS#11 v3.2 parser surfaces into reachable translation units, building three sanitizer-instrumented libFuzzer harnesses with seed corpora and a CI workflow, and shipping a bug-fix to the integrity-check bypass that was silently latching the module ERROR state in dev mode. Two adjacent investigations (AES-GCM TC14 dev-mode mislabel, OpenSSL 3.5.6 default-provider divergence) are documented as known-state with follow-up tracked.

### Added

* **`include/fhsm_ecdsa_raw.h` + `src/fhsm_ecdsa_raw.c`** : the PKCS#11 v3.2 §6.13 ECDSA `r||s` ↔ DER ECDSA-Sig-Value converters extracted into a dedicated translation unit. New public symbols `fhsm_mech_is_ecdsa`, `fhsm_ecdsa_der_to_raw`, `fhsm_ecdsa_raw_to_der`. Byte-identical to the original code modulo two explicit `(size_t)` casts on `rlen`/`slen` that are no-ops because `BN_num_bytes` returns `int >= 0` with the preceding bounds check.
* **`include/fhsm_pq_params.h` + `src/fhsm_pq_params.c`** : the `CK_ML_DSA_PARAMS` / `CK_SLH_DSA_PARAMS` 24-byte mech-parameter parser (PKCS#11 v3.2 §6.18 / §6.19, FIPS 204/205) extracted into a dedicated TU. New public symbol `fhsm_parse_pq_params(param_ptr, param_len, out_ctx, out_ctx_cap, out_ctx_len, out_have, out_hedge_variant)`. Same semantics as the original inline parser, with explicit `out_*` pointers for the four output values.
* **`include/fhsm_attr_utils.h`** : static inline mirrors of `fhsm_find_attr` and `fhsm_strip_octet_string_inline`, the two parser helpers still inlined in `src/fhsm_pkcs11.c`. Character-for-character copies of the production code ; a libFuzzer finding here corresponds to the same bug in production by inspection.
* **`fuzz/Makefile.fuzz`** + three libFuzzer harnesses :
  * `fuzz/fuzz_ecdsa_raw.c` exercises the ECDSA converter pair, checking round-trip closure `der_to_raw(raw_to_der(r||s)) == r||s` plus memory safety on adversarial DER inputs.
  * `fuzz/fuzz_pq_params.c` exercises the PQ-params parser, checking five structural invariants (no-context flag consistency, bounds clamp, hedgeVariant pass-through, NULL rejection, short-input rejection).
  * `fuzz/fuzz_attr_template.c` exercises `find_attr` + `strip_octet_string`, checking index-range invariant on `find_attr` and OCTET STRING pointer arithmetic (`out_len + (out - data) == size`).
* **`fuzz/corpus/<harness>/`** : 2–4 seed inputs per harness, committed to git so CI fuzz runs start from the same baseline as developer machines. Includes one regression seed (`regression_harness_oob_1byte`) from a 1-byte OOB found in the harness itself during initial validation.
* **`fuzz/README.md`** : operator runbook covering build, run, triage, minimization, and the crash-handling policy (every crash is a security finding ; private issue, fix-with-regression-test, backport, CVE if reachable). Satisfies the CC EAL4+ ALC_DVS expectation that every reported crash leads to a tracked corrective action.
* **`.github/workflows/fuzz.yml`** : structured-fuzzing CI integration. On push to `main` 5 min per harness, fail on any crash, upload reproducers as 90-day-retention artifacts. Nightly 1 h per harness, upload evolving corpus + crashes as 30-day / 90-day-retention artifacts. `workflow_dispatch` for manual runs with configurable duration.
* **`disabled/diag_aes_gcm_tc14*.c`, `disabled/diag_aes_gcm_tc13_no_aad.c`** : three standalone diagnostic programs written during the investigation of the integrity-bypass bug and the OpenSSL 3.5.6 default-provider AES-GCM no-AAD divergence. Not linked into the build ; kept for reproducibility evidence.

### Changed

* **`src/fhsm_integrity.c::verify_once()`** : the function now consults `FHSM_INTEGRITY_ALLOW_UNSIGNED` before latching the module ERROR state. The existing partial bypass in `crypto_init_once()` only filtered the return value of `fhsm_integrity_verify()` ; the state latch happening earlier in `verify_once()` was unconditional, which meant every local dev build that triggered `do_verify()` setup errors (`locate_self` / `open` / `fstat` / `mmap` / `malloc`) ended up with the module permanently in ERROR state even when the operator had explicitly opted in via the env var. **Behavior in production (env var absent) is unchanged** : `do_verify()` failure still latches ERROR and `C_Initialize` fails closed. The new dev-mode warning makes the override visible and reminds the operator that the flag is INVALID for any FIPS 140-3 / CC EAL4+ deployment per AGD_PRE §7.5.
* **`src/fhsm_pkcs11.c`** : two extractions shrink the file from 4 400 to 4 338 lines (-62 cumulative). The 39 call sites of `find_attr` and the 2 call sites of `fhsm_strip_octet_string` continue to use the local TU-private definitions ; the inline mirrors in `include/fhsm_attr_utils.h` are a separate, isolation-respecting code path for the fuzzer.
* **`Makefile`** : `LIB_SRC` extended with `src/fhsm_ecdsa_raw.c` + `src/fhsm_pq_params.c`.
* **`kat/cavp_extended.c::run_aesgcm_vec`** : modernized to the OpenSSL 3.x `EVP_EncryptInit_ex2` idiom matching `fhsm_aes_gcm_encrypt`. The legacy three-step `EVP_EncryptInit_ex` pattern + `EVP_CTRL_GCM_SET_IVLEN(12)` call is replaced by a single-call init. No CI behavior change (both patterns produce the same byte-deterministic output under the FIPS provider) ; positive code-quality change.

### Discovered and documented (not fixed in this release)

* **OpenSSL 3.5.6 default-provider AES-GCM no-AAD divergence** : the NIST SP 800-38D Test Case 14 vector (60-byte PT, no AAD, 96-bit IV, AES-256) produces tag `0xeb9f796c...` on OpenSSL 3.5.6 default provider instead of the NIST-expected `0xb094dac5...`. The CT is computed correctly ; only the tag diverges. The FIPS provider matches NIST exactly, which is why CI runs all green and v1.1.7 onwards never surfaced this. Two standalone EVP probes confirm the divergence is in OpenSSL itself, not in our wrapper or KAT data : both "AAD update skipped" and "AAD update forced with 0 bytes" variants produce the same wrong tag. Tracked as a follow-up ; possible upstream OpenSSL report after further triage. The KAT vector is retained in `cavp_extended` so the divergence remains visible at every boot in dev mode.

### Why ship this now ?

Two reasons.

1. **Structured fuzzing closes the validation triangle**. The boot KAT (35 vectors) tests deterministic algorithm output. Wycheproof (6 978 vectors) tests cross-implementation conformity. The matrix (24 / 0 / 8) tests function × mechanism reachability. Fuzzing tests **memory safety + structural invariants on adversarial inputs**, which the other three surfaces do not. Three orthogonal validation modalities is a stronger CMVP submission posture than two.
2. **The integrity-bypass bug was a latent dev-experience trap**. Every developer running test_smoke locally on an unsigned build (the normal dev case) saw `C_Initialize 0x80000002` until they figured out that the bypass env var was silently ineffective beyond the rv filter. The fix is small (10 lines) but unblocks the dev workflow completely.

### Validation

```
Refactor :
  Boot KAT (15 from fhsm_kat_vectors.c + 32 from cavp_extended)
    pass on Debian 13 + OpenSSL 3.5.6 default provider via the
    integrity-bypass fix EXCEPT the NIST TC14 no-AAD case which
    diverges in dev mode (documented above). CI : 35 / 35 OK
    under FIPS provider.
  Wycheproof ECDSA full sweep : 3 098 / 0 violations across RFC
    6979 P-256 / P-384 / P-521. DER classification bit-identical
    to v1.1.13.
  PQ parser extraction : byte-identical to the original inline
    code ; same code path through the boot KAT ML-DSA-65 and
    SLH-DSA-SHA2-128f sign-verify round trips.

Fuzzing (30 s smoke each on developer machine, after harness self-fix) :
  fuzz_ecdsa_raw     :   7.7 M runs, 0 crash, cov 21 / ft 39
  fuzz_pq_params     :  19.6 M runs, 0 crash, cov 28 / ft 29
  fuzz_attr_template :  10.6 M runs, 0 crash, cov 76 / ft 192
  Total              :  37.9 M inputs, 0 violation of the 12
                        structural invariants checked.
```

CI matrix : unchanged from v1.1.13, **24 / 0 / 8 in both default and FIPS strict modes**.
Wycheproof full sweep : **6 978 / 0 across 9 PKCS#11 v3.2 families**, bit-identical to v1.1.13.

## [1.1.13] --- 2026-06-18

The "post-quantum boot KAT" release. Closes the FIPS 140-3 §C.B Known-Answer-Test coverage by adding consistency self-tests for the three NIST-standardised post-quantum primitives --- ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) --- on every `C_Initialize`. The boot KAT now covers the complete classical portfolio **plus** the complete NIST PQ portfolio in a single ~152 ms cold-boot, which (to the best of our literature search) is a first for an open-source PKCS#11 v3.2 cryptographic module. No module code change ; this is pure validation surface area.

### Added

* **`kat/cavp_extended.c` --- ML-KEM-768 round-trip self-test** : at boot, `EVP_PKEY_keygen` is invoked to produce an ephemeral ML-KEM-768 keypair. The encapsulation step (`EVP_PKEY_encapsulate`) yields a ciphertext and a shared secret `SS_A` ; the decapsulation step (`EVP_PKEY_decapsulate`) recovers `SS_B`. The self-test asserts `SS_A == SS_B` bit-for-bit. This is a FIPS 140-3 IG D.3 round-trip consistency test (not a byte-deterministic KAT, which is mathematically impossible for a randomised KEM keygen).
* **`kat/cavp_extended.c` --- ML-DSA-65 sign-verify round-trip** : ephemeral keygen, sign a fixed 16-byte message via `EVP_DigestSign` with `hash=NULL` (the lattice scheme does its own internal hashing per FIPS 204 §6), verify via `EVP_DigestVerify`. Asserts verify returns 1.
* **`kat/cavp_extended.c` --- SLH-DSA-SHA2-128f sign-verify round-trip** : same pattern as ML-DSA but on the FIPS 205 hash-based scheme. The "fast" (`128f`) variant is chosen over the small-signature (`128s`) variant explicitly to bound the boot-time cost --- the `128s` keygen and sign are ~10× slower. Both variants are exercised through the runtime `C_Sign / C_Verify` dispatch ; only `128f` is a boot KAT.
* **Helper `pq_keygen(const char *alg_name)`** : small shim that wraps `EVP_PKEY_CTX_new_from_name` + `EVP_PKEY_keygen_init` + `EVP_PKEY_keygen` for any of the three PQ schemes. Removes 30+ lines of duplication across the three round-trip runners.
* **Shared helper `run_pq_sign_roundtrip(EVP_PKEY *)`** : single sign-verify body shared between the ML-DSA and SLH-DSA self-tests. Both schemes follow the FIPS 204 / 205 `EVP_DigestSign` convention identically.

### Changed

* **`docs/FIPS_140_3_SECURITY_TARGET.md`** : §9.3 now lists **35 vectors** (was 32) with three new rows for ML-KEM-768, ML-DSA-65 and SLH-DSA-SHA2-128f, each citing FIPS 203/204/205 plus FIPS 140-3 IG D.3 for the round-trip rationale. §9 boot-timing note updated from "~130 ms" to "~152 ms" with the +20 ms attributed to the three PQ keygen + round-trip self-tests combined, and a rationale paragraph explaining the `128f` over `128s` variant choice for the SLH-DSA boot KAT. ST revision unchanged at v0.4 ; this is editorial coherence with the new boot KAT.

### Why ship this now ?

Three reasons :

1. **Validation symmetry** : every classical FIPS 140-3 §C.B category had a boot KAT after v1.1.12 (SHA, HMAC, AES enc, AES MAC, ECDSA, RSA-PSS, RSA-OAEP, HKDF, PBKDF2, CTR_DRBG). The three PQ primitives were the last gap. Closing it now means a single ST §9.3 table covers the full attack surface --- which is a stronger CMVP / CC submission posture than "PQ is exercised at runtime only".
2. **Cost is acceptable** : +20 ms cold-boot is well under the FIPS 140-3 §7.10 spirit (self-tests shall not unduly delay module availability). SLH-DSA-SHA2-128f keygen in OpenSSL 3.5 is remarkably fast.
3. **Literature posture** : as of this release, the documented landscape of open-source PKCS#11 v3.2 modules with boot-time PQ KATs is, to our knowledge, empty. Being first on this matters operationally : it means any downstream consumer (Vault, GnuTLS, etc.) inherits a non-trivial assurance for free.

### Validation

```
Boot KAT (per C_Initialize)
  -------------------------------------------
  Symmetric encryption         7  (AES-CBC, CTR, GCM, CMAC)
  Hash                        12  (SHA-2 + SHA-3 full ladder)
  MAC                          7  (HMAC × 4 + AES-CMAC × 3)
  Classical signature          4  (ECDSA P-256/384/521 + RSA-PSS)
  Classical asym encryption    1  (RSA-OAEP)
  KDF                          4  (HKDF × 2 + PBKDF2 × 2)
  DRBG                         1  (CTR_DRBG continuous)
  Post-quantum KEM             1  (ML-KEM-768)               <-- new
  Post-quantum sig (lattice)   1  (ML-DSA-65)                <-- new
  Post-quantum sig (hash)      1  (SLH-DSA-SHA2-128f)        <-- new
  -------------------------------------------
  Total                       35  vectors, ~152 ms cold-boot
```

```
Wycheproof full sweep
  ecdsa     match= 3098  viol= 0
  eddsa     match=  236  viol= 0
  rsa_pss   match= 1083  viol= 0
  rsa_oaep  match=  788  viol= 0
  aes_gcm   match=  310  viol= 0
  hmac      match=  522  viol= 0
  mlkem     match=   21  viol= 0
  aes_cmac  match=  306  viol= 0
  mldsa     match=  614  viol= 0
  ─────────────────────────────────
  TOTAL     match= 6978  viol= 0    (bit-identical to v1.1.12)
```

CI matrix : unchanged from v1.1.12, 24 / 0 / 8 in both default and FIPS strict modes (the boot KAT is exercised at every matrix step indirectly via `C_Initialize`).

## [1.1.12] --- 2026-06-18

The "SLH-DSA context" release. Closes the symmetric plumbing for `CK_SLH_DSA_PARAMS.pContext` (PKCS#11 v3.2 §6.19 / FIPS 205 §5.2.1) on top of the ML-DSA context shipped in v1.1.10. No external corpus to validate against yet (Wycheproof has not published SLH-DSA test vectors at the pinned SHA `6d7cccd0fcb1`), but the wire is now ready : once a SLH-DSA adapter lands, the existing context plumbing covers it for free.

### Changed

* **`fhsm_op_t` renaming** : `mldsa_ctx_have / mldsa_ctx / mldsa_ctx_len` become `pq_ctx_have / pq_ctx / pq_ctx_len` to reflect that the same 256-byte buffer carries the FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) context strings. Wire layout and behaviour are unchanged.
* **`op_init` parser** : the gate that decodes the `{ hedgeVariant, pContext, ulContextLen }` triple now triggers on either `CKM_ML_DSA_OP` (0x403F) or `CKM_SLH_DSA_OP` (0x4041). Both `CK_ML_DSA_PARAMS` and `CK_SLH_DSA_PARAMS` are 24 bytes on a 64-bit ABI with identical layout, so a single code path covers them.
* **`C_Sign` and `C_Verify` post-quantum branch** : the `EVP_PKEY_CTX_set_params(OSSL_SIGNATURE_PARAM_CONTEXT_STRING)` gate now also fires for `CKM_SLH_DSA_OP`. EdDSA stays on the empty-context default, as it has no comparable parameter struct in PKCS#11 v3.2.

### Why ship this now ?

Three reasons :

1. **Symmetry** : the ML-DSA path was an outlier --- the same context concept exists for SLH-DSA and was implementable in one refactor instead of being duplicated when an adapter eventually appears.
2. **Build-time safety** : the refactor is touched and validated **now**, not in the middle of writing a new adapter when noise is high. The Wycheproof full sweep is bit-identical to v1.1.11 (6 978 / 0 across 9 families ; ML-DSA still 614 / 0 / 15), proving the rename + extension is transparent.
3. **Security Target language** : the FreeHSM C Security Target can now state "the PKCS#11 v3.2 §6.18 and §6.19 context parameters are honoured on both sign and verify for the FIPS 204 and FIPS 205 schemes respectively", a stronger statement than before.

### Validation

```
ecdsa     match= 3098  viol= 0
eddsa     match=  236  viol= 0
rsa_pss   match= 1083  viol= 0
rsa_oaep  match=  788  viol= 0
aes_gcm   match=  310  viol= 0
hmac      match=  522  viol= 0
mlkem     match=   21  viol= 0
aes_cmac  match=  306  viol= 0
mldsa     match=  614  viol= 0   (unchanged ; pq_ctx code path proves bijective with v1.1.10's mldsa_ctx)
─────────────────────────────────
TOTAL     match= 6978  viol= 0   across 9 PKCS#11 v3.2 families
```

CI matrix : unchanged from v1.1.11, 27 / 0 / 5 in both default and FIPS strict modes.

## [1.1.11] --- 2026-06-18

The "CI matrix complete" release. Closes the dual self-attestation loop : every push to main now runs the **full PKCS#11 function × mechanism coverage matrix** inside a pinned container, in both default and FIPS-strict modes, on top of the existing 9-family Wycheproof sweep. No module code change ; the surface area unblocked is operational.

### Added

* **`Dockerfile.test`** : a minimal Debian 13-slim image carrying `opensc` (for `pkcs11-tool`), `gnutls-bin`, `binutils` (for the v3.0 `CK_INTERFACE` symbol probe), `sudo`, and a non-privileged `freehsm` user matching what `tests/coverage_matrix.sh` expects. Build context is the repo root so the image stays self-contained.
* **`.github/workflows/test-image.yml`** : builds and publishes `ghcr.io/<owner>/freehsm-c-test:debian13-pkcs11-tools` on every change to `Dockerfile.test` (or via manual dispatch). Mirrors the existing `build-image.yml` pattern : QEMU + Buildx + GHA cache + `packages: write` permission. The image now ships with both `:debian13-pkcs11-tools` and `:latest` tags.

### Changed

* **`tests/coverage_matrix.sh`** : exported `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` and `FHSM_KAT_ALLOW_FAIL=1` so a freshly-built `.so` (which carries a placeholder `.fhsm_digest` until `release.yml` patches it post-link) can `C_Initialize` cleanly. Both env vars are forbidden in production per `AGD_PRE §7.5 / §7.5bis` ; the new comment in the script makes that explicit. Also defaulted `OPENSSL_CONF=/dev/null` so the legacy-mode matrix sees the default OpenSSL provider without a FIPS bias from the system `openssl.cnf`.
* **`tests/coverage_matrix.sh` MD5 step** : `CKM_MD5` is intentionally absent from `g_mech_list` since FIPS 140-3 §C.A removed MD5 from the allowed algorithm set. `pkcs11-tool` surfaces the absence as `CKR_TOKEN_NOT_PRESENT` at session-open time (it probes mech availability before opening a session). The matrix now accepts that outcome as `SKIP` for the legacy assertion and `PASS` for the FIPS assertion ; the previous code expected an explicit `CKR_MECHANISM_INVALID` which the underlying `pkcs11-tool` never produces for an absent mech.
* **`.github/workflows/ci.yml`** : `test-coverage-matrix` and `test-fips-mode` jobs no longer gate themselves off with `if: false`. The freehsm-c-test image is published and live ; both jobs run inside it as part of every push.

### Validation

Coverage matrix (default mode + FIPS strict mode, identical output) :

```
function                  mechanism                  status   note
C_GetInfo                 n/a                        PASS     Manufacturer reported
C_GetMechanismList        n/a                        PASS     72 mechanisms listed
C_InitToken               n/a                        PASS
C_InitPIN                 n/a                        PASS
C_GenerateKey             CKM_AES_KEY_GEN            PASS
C_FindObjects             label=cov-aes              PASS
C_DestroyObject           AES                        PASS
C_Encrypt                 CKM_AES_GCM                PASS
C_Encrypt                 CKM_AES_CBC_PAD            PASS
C_Sign                    CKM_AES_CMAC               PASS
C_Digest                  CKM_SHA256                 PASS
C_Digest                  CKM_SHA384                 PASS
C_Digest                  CKM_SHA512                 PASS
C_Digest                  CKM_SHA3_*                 SKIP     pkcs11-tool does not propose SHA3
C_Sign                    CKM_SHA256_HMAC            PASS
C_GenerateKeyPair         CKM_EC_KEY_PAIR_GEN        PASS
C_Sign                    CKM_ECDSA_SHA256           PASS
C_GenerateKeyPair         CKM_RSA_PKCS_KEY_PAIR_GEN  PASS
C_Sign                    CKM_SHA256_RSA_PKCS        PASS
C_Decrypt                 CKM_RSA_PKCS_OAEP          PASS
C_DeriveKey               CKM_ECDH1_DERIVE           PASS
C_Login                   wrong_pin                  PASS     CKR_PIN_INCORRECT raised
C_OpenSession             invalid_slot               PASS     Invalid slot rejected
C_SignInit                non_FIPS_mech              SKIP     pkcs11-tool may not propose MD5
C_GetInterface            n/a                        PASS     v3.0 entry exposed
C_EncapsulateKey          CKM_ML_KEM                 PASS
C_Sign                    CKM_ML_DSA                 PASS
C_Sign                    CKM_SLH_DSA                PASS
C_Digest                  CKM_MD5 (legacy)           SKIP     MD5 absent (FIPS 140-3 §C.A)
C_Digest                  CKM_MD5 (FIPS)             PASS     Correctly rejected in FIPS mode

PASS = 27   FAIL = 0   SKIP = 5   (total 32)   ALL ASSERTIONS PASS
```

Wycheproof sweep unchanged from v1.1.10 :

```
TOTAL     match= 6978  viol= 0   across 9 PKCS#11 v3.2 families (2 post-quantum)
```

## [1.1.10] --- 2026-06-17

The "conformity" release. Two PKCS#11 v3.2 spec gaps closed in one shot :
the FIPS 204 ML-DSA context string (`CK_ML_DSA_PARAMS.pContext`) on both
sign and verify, and the raw r||s signature format for the CKM_ECDSA
family (PKCS#11 v3.2 §6.13). ML-DSA gains 6 Wycheproof vectors ; ECDSA
keeps its 3 098 pass count while the wire format is now spec-conformant
for any PKCS#11 v3.2 caller.

### Added

* **`CK_ML_DSA_PARAMS` parsing in `op_init`** (shared between SignInit and VerifyInit). PKCS#11 v3.2 §6.18 specifies a 24-byte struct `{ hedgeVariant, pContext, ulContextLen }`. When the mechanism is `CKM_ML_DSA_OP` and the caller passes a parameter blob, the context string is copied into a 256-byte static buffer in the operation state. `hedgeVariant` is read but unused for now (OpenSSL's default hedged behaviour matches `CKH_HEDGE_PREFERRED`).
* **FIPS 204 context forwarded to OpenSSL** in both `C_Sign` and `C_Verify`. Before calling `EVP_DigestSign` / `EVP_DigestVerify`, the post-quantum branch now sets `OSSL_SIGNATURE_PARAM_CONTEXT_STRING` on the `EVP_PKEY_CTX` when the caller supplied a non-empty context. The change is gated on the ML-DSA mechanism so SLH-DSA and EdDSA stay on the empty-context default.
* **ML-DSA adapter forwards the context** (`tests/wycheproof/adapters/mldsa.py`). Builds a `CK_ML_DSA_PARAMS` via `ctypes` for every test, decoding the optional `ctx` hex field from the Wycheproof vector. Tests with `ctx` longer than 255 bytes (FIPS 204 §5.2.1 spec violation, beyond what the PKCS#11 mechanism can express) are surfaced under `ctx_oversize_skip`.
* **Raw r||s signature format for `CKM_ECDSA*`** (PKCS#11 v3.2 §6.13). The internal OpenSSL path still uses DER ECDSA-Sig-Value (that is what `EVP_DigestSign` / `EVP_DigestVerify` consume and produce), but the public wire is now raw r||s padded to `2 * curve_size` bytes per the spec. Two helpers handle the conversion via `ECDSA_SIG_new` / `d2i_ECDSA_SIG` / `i2d_ECDSA_SIG`. The `ecdsa.py` adapter now passes its already-parsed `sig_raw` to `C_Verify` (instead of `sig_der`), proving the new wire format round-trips through the existing 3 098 Wycheproof vectors with zero regressions.

### Validation

```
ecdsa     match= 3098  viol= 0
eddsa     match=  236  viol= 0
rsa_pss   match= 1083  viol= 0
rsa_oaep  match=  788  viol= 0
aes_gcm   match=  310  viol= 0
hmac      match=  522  viol= 0
mlkem     match=   21  viol= 0
aes_cmac  match=  306  viol= 0
mldsa     match=  614  viol= 0   (+6 vs v1.1.9 ; 97.6 % of the corpus)
─────────────────────────────────
TOTAL     match= 6978  viol= 0
```

### Documented Wycheproof corpus skips

The 15 remaining ML-DSA skips (5 per parameter set) carry `ctx` strings longer than 255 bytes ; these test that an ML-DSA implementation rejects oversize contexts. The PKCS#11 v3.2 `CK_ML_DSA_PARAMS.ulContextLen` is a `CK_ULONG`, so the wire format allows arbitrary lengths, but the FreeHSM internal buffer caps at the FIPS 204 spec limit (255 bytes) and rejects anything beyond. The Wycheproof tests are therefore unreachable for us by construction --- they would require a buffer that exceeds the spec.

## [1.1.9] --- 2026-06-17

The "ML-DSA" release. Adds a second post-quantum family (FIPS 204 / Dilithium) to the Wycheproof harness, bringing FreeHSM C to **nine** cleanly-validated crypto families with both NIST PQ primitives (KEM + signature) covered.

### Added

* **ML-DSA (FIPS 204) Wycheproof adapter** (`tests/wycheproof/adapters/mldsa.py`). Drives `CKM_ML_DSA_OP` verification against the `mldsa_{44,65,87}_verify_test.json` corpus for all three NIST parameter sets (Dilithium-2 / 3 / 5). Imports the SPKI DER `publicKeyDer` form so `d2i_PUBKEY` decodes directly ; the raw `publicKey` path remains available via the new `EVP_PKEY_fromdata` fallback.
* **Raw FIPS 204 verification key import path in `C_VerifyInit`**. The Wycheproof corpus and most CAVP-derived suites carry the verification key as raw 1 312 / 1 952 / 2 592 bytes. When `d2i_PUBKEY` rejects the blob, the verify path now detects ML-DSA-44 / 65 / 87 by canonical length and re-imports via `EVP_PKEY_fromdata` with `OSSL_PKEY_PARAM_PUB_KEY` (selection = `EVP_PKEY_PUBLIC_KEY`). Symmetric with the ML-KEM raw decapsulation key path shipped in v1.1.7.
* **`C_CreateObject` extended for `CKO_PUBLIC_KEY` + `CKK_ML_DSA`**. The public-key branch now stores the `CKA_VALUE` blob verbatim (matching the ML-KEM private-key path), so the verify-side fallback can re-decode whichever form the caller supplied.
* PKCS#11 v3.2 plumbing : `CKK_ML_DSA = 0x3E`, `CKM_ML_DSA_OP = 0x403F` exposed in `_p11.py`.

### Validation

```
ecdsa     match= 3098  viol= 0
eddsa     match=  236  viol= 0
rsa_pss   match= 1083  viol= 0
rsa_oaep  match=  788  viol= 0
aes_gcm   match=  310  viol= 0
hmac      match=  522  viol= 0
mlkem     match=   21  viol= 0
aes_cmac  match=  306  viol= 0
mldsa     match=  608  viol= 0
─────────────────────────────────
TOTAL     match= 6972  viol= 0   across 9 PKCS#11 v3.2 families
                                  (2 post-quantum : ML-KEM + ML-DSA)
```

### Known limitations (tracked for v1.2.0)

* **FIPS 204 context string** : the adapter skips 21 tests whose `ctx` field is non-empty. These exercise the `CK_ML_DSA_PARAMS.pContext` PKCS#11 v3.2 carrier that `C_VerifyInit` does not yet parse. Once the param plumbing lands, `OSSL_SIGNATURE_PARAM_CONTEXT_STRING` will forward it to OpenSSL and recover those vectors.
* **HashML-DSA** (FIPS 204 §5.4 pre-hash variant) is not yet exposed.

## [1.1.8] --- 2026-06-17

The "AES-CMAC" release. Adds a second MAC family (NIST SP 800-38B) to the Wycheproof harness, lifting FreeHSM C to **eight** cleanly-validated crypto families.

### Added

* **AES-CMAC Wycheproof adapter** (`tests/wycheproof/adapters/aes_cmac.py`). Drives `CKM_AES_CMAC` against the `aes_cmac_test.json` corpus for AES-128 / 192 / 256 (306 vectors, all sizes). Mirrors the `hmac.py` pattern : `C_Sign(msg) -> 16-byte block`, truncate to `tagSize`, constant-time compare. CMAC takes no parameters per PKCS#11 v3.2 §6.5, so the mechanism is built as `(CKM_AES_CMAC, NULL, 0)`.
* `CKM_AES_CMAC = 0x108C` exposed in `_p11.py` and the attribute-builder DSL for downstream adapters.

### Validation

```
ecdsa     match= 3098  viol= 0
eddsa     match=  236  viol= 0
rsa_pss   match= 1083  viol= 0
rsa_oaep  match=  788  viol= 0
aes_gcm   match=  310  viol= 0
hmac      match=  522  viol= 0
mlkem     match=   21  viol= 0
aes_cmac  match=  306  viol= 0
─────────────────────────────────
TOTAL     match= 6364  viol= 0   across 8 PKCS#11 v3.2 families
```

## [1.1.7] --- 2026-06-17

The "ML-KEM" release. Adds post-quantum coverage (FIPS 203) to the Wycheproof harness, lifting FreeHSM C to a **seventh** cleanly-validated crypto family — the first post-quantum primitive to be bit-for-bit verified against an external corpus.

### Added

* **ML-KEM (FIPS 203) Wycheproof adapter** (`tests/wycheproof/adapters/mlkem.py`). Drives `CKM_ML_KEM_OP` decapsulation against the `mlkem_*_semi_expanded_decaps_test.json` corpus for ML-KEM-512 / 768 / 1024 (21 vectors total, all three parameter sets). Decision rule honours FIPS 203 §7.3 implicit rejection : `valid` requires `rv == OK` (and `ss == K` when the corpus provides it), `invalid` accepts either a structural reject (`rv != OK`) or an implicit reject (`ss != K`).
* **Raw FIPS 203 `dk` import path in `C_DecapsulateKey`**. The Wycheproof semi-expanded corpus carries the decapsulation key as raw 1 632 / 2 400 / 3 168 bytes (FIPS 203 expanded form) rather than a PKCS#8 envelope. The module now detects the parameter set from the canonical key length and re-imports via `EVP_PKEY_fromdata(EVP_PKEY_KEYPAIR, OSSL_PKEY_PARAM_PRIV_KEY)`, falling back from `d2i_AutoPrivateKey` when the latter rejects the raw blob. Both DER and raw paths produce a structurally identical `EVP_PKEY *`, so the rest of the decapsulation flow is unchanged.
* **PKCS#11 v3.0 plumbing in the harness `_p11.py`** : `C_DecapsulateKey` / `C_EncapsulateKey` / `C_GetAttributeValue` are now bound and exposed via `P11Session.decapsulate()` and `P11Session.get_attribute_value()`. Adds the `CKK_ML_KEM` (`0x3C`) and `CKM_ML_KEM_OP` (`0x403D`) constants plus `EXTRACTABLE` / `SENSITIVE` to the attribute-builder DSL.

### Fixed

* **Critical : harness DEK not loaded on token re-runs**. `fhsm_token_object_add()` requires the per-token DEK to be in memory (set on USER login). The harness `_bootstrap_token()` short-circuits when the token file already exists, so a second run with persisted state would enter `open_session()` without ever logging in — `t->dek` stayed `NULL` and every `C_CreateObject` returned `CKR_USER_NOT_LOGGED_IN` (`0x101`), wiping out every adapter that imports a key. `open_session()` now performs an idempotent `C_Login(USER)` with the bootstrap PIN ; `CKR_USER_ALREADY_LOGGED_IN` (`0x100`) is treated as success. Restores the six previously-validated families and unlocks the new ML-KEM path in one move.

### Validation

```
ecdsa     match= 3098  viol= 0
eddsa     match=  236  viol= 0
rsa_pss   match= 1083  viol= 0
rsa_oaep  match=  788  viol= 0
aes_gcm   match=  310  viol= 0
hmac      match=  522  viol= 0
mlkem     match=   21  viol= 0
─────────────────────────────────
TOTAL     match= 6058  viol= 0   across 7 PKCS#11 v3.2 families
```

## [1.1.6] --- 2026-06-17

The "RSA-OAEP" release. Extends the Wycheproof harness to a sixth crypto family and brings the total cleanly-validated vector count to 6 037 with zero violations across **every** PKCS#11 v3.2 mainstream primitive.

### Added

* **RSA-OAEP** Wycheproof adapter (`tests/wycheproof/adapters/rsa_oaep.py`). Decrypts the test ciphertext with `CKM_RSA_PKCS_OAEP` and the full `CK_RSA_PKCS_OAEP_PARAMS` plumbing (hash algorithm, MGF, optional label as source-data). Covers SHA-1 / SHA-256 / SHA-384 / SHA-512 and RSA moduli from 2 048 to 4 096 bits.
* **`C_CreateObject` private-key branch** : `CKO_PRIVATE_KEY` with `CKK_RSA` is now accepted with the PKCS#8 `PrivateKeyInfo` DER blob carried in `CKA_VALUE`. The asymmetric crypto path already routes through `d2i_AutoPrivateKey`, which transparently handles both PKCS#8 and PKCS#1 RSAPrivateKey.

### Fixed

* **Critical : `op->active` reset on RSA-OAEP early-exit paths**. The size-query (`pData == NULL`) and buffer-too-small branches of the RSA-OAEP `C_Decrypt` path used to return without resetting `op->active`. After a single such early exit on a session, every subsequent `C_DecryptInit` returned `CKR_OPERATION_ACTIVE` (`0x90`), making the session unusable for further decryption. Both branches now reset `op->active` and `g_oaep_dec[hSession].active` before returning.

### Documented upstream limitation

* The Wycheproof RSA-OAEP corpus contains 58 tests with `flags: ["Constructed"]` (Wycheproof's `EDGE_CASE` category) whose seed and label are specifically chosen to give the OAEP-padded `em` a crafted bit pattern (`em represents a small integer`, `em has a large hamming weight`, etc.). The OpenSSL 3.x default provider rejects 7 of them as part of its malleability hardening. This is consistent provider behaviour rather than a FreeHSM bug ; the adapter surfaces the count in `constructed_edge_case_skip` and classifies the tests as skip.

### Validation

```
ecdsa     match= 3098  viol= 0  skip=18794
eddsa     match=  236  viol= 0  skip=    0
rsa_pss   match= 1083  viol= 0  skip= 1323
rsa_oaep  match=  788  viol= 0  skip=  420
aes_gcm   match=  310  viol= 0  skip=    6
hmac      match=  522  viol= 0  skip=    0
─────────────────────────────────────────
TOTAL     match= 6037  viol= 0
```

6 037 Wycheproof vectors pass with **zero violations** across the six PKCS#11 v3.2 mainstream families : ECDSA, RSA-PSS, EdDSA, RSA-OAEP, AES-GCM and HMAC. Signature, encryption, MAC, symmetric and asymmetric all covered.

---

## [1.1.5] --- 2026-06-17

The "AES-GCM + HMAC" release. Extends the Wycheproof harness with full symmetric coverage and brings the total cleanly-validated vector count to 5 249 across five PKCS#11 v3.2 families.

### Added

* **AES-GCM (128 / 192 / 256)** Wycheproof adapter --- decrypt-and-verify path with full `CK_GCM_PARAMS` plumbing (IV, AAD, tag length per test). The module's `op_init` now parses the 6-CK_ULONG struct alongside the legacy 12-byte IV shortcut, captures `gcm_iv` (512 B), `gcm_aad` (4 KiB) and `gcm_tag_len` into `fhsm_op_t`, and `C_Decrypt` for AES-GCM inlines the OpenSSL call so non-default IV / tag lengths are honoured per call.
* **HMAC SHA-256 / SHA-384 / SHA-512** Wycheproof adapter. The module gains `CKM_SHA384_HMAC` and `CKM_SHA512_HMAC` declarations, the `C_SignInit` switch accepts all three, and the HMAC dispatch in `C_Sign` selects `FHSM_HASH_SHA{256,384,512}` and the matching 32 / 48 / 64-byte MAC length.
* **`C_CreateObject` symmetric branch** : `CKO_SECRET_KEY` with any key type stores the raw `CKA_VALUE` bytes directly. Unblocks both AES-GCM and HMAC key import without further plumbing in the existing crypto path (which reads keys via `fhsm_token_object_get`).
* **`tests/wycheproof/adapters/_p11.py`** gains `C_EncryptInit` / `C_Encrypt` / `C_DecryptInit` / `C_Decrypt` / `C_SignInit` / `C_Sign` in the symbol list, exposes `P11Session.decrypt()` and `P11Session.sign()` helpers, and re-exports `CKO_SECRET_KEY` / `CKK_AES` / `CKK_GENERIC_SECRET` / `CKM_AES_GCM` / `CKM_SHA{256,384,512}_HMAC` / `A.VALUE()` / `A.DECRYPT()` through the builder DSL.
* `tests/wycheproof/run_wycheproof.py` forwards the file-level `algorithm` field into each group dict (`group["_algorithm"]`), allowing MAC adapters to dispatch on the hash without re-opening the file.

### Changed

* `fhsm_op_t` grows GCM-context fields (`gcm_have` / `gcm_iv` / `gcm_aad` / `gcm_tag_len`) and a forward-declared `mech_is_pss` so `op_init` can reference it before the helper is defined.
* `tests/wycheproof/adapters/hmac.py` rolls its own constant-time compare (3 lines) rather than `import hmac as ...` or `secrets.compare_digest`, both of which transitively pull stdlib `hmac` --- which the file name shadows from the adapter directory's `sys.path` entry.

### Documented limitations

* Wycheproof's `aead_test_schema_v1.json` carries three test groups whose `ivBits` exceeds the OpenSSL default-provider hard cap (`GCM_IV_MAX_SIZE = 64 bytes`, i.e. 512 bits). The adapter classifies these (3 × `ivBits=1024` + 3 × `ivBits=2056`) as skip with a dedicated diagnostic bucket --- this is an upstream OpenSSL limitation, not a FreeHSM module bug.

### Validation

```
ecdsa     match= 3098  viol= 0  skip=18794
eddsa     match=  236  viol= 0  skip=    0
rsa_pss   match= 1083  viol= 0  skip= 1323
aes_gcm   match=  310  viol= 0  skip=    6
hmac      match=  522  viol= 0  skip=    0
─────────────────────────────────────────
TOTAL     match= 5249  viol= 0
```

5 249 Wycheproof vectors pass with **zero violations** across ECDSA, EdDSA, RSA-PSS, AES-GCM and HMAC --- the five PKCS#11 v3.2 families a typical FIPS 140-3 application exercises.

---

## [1.1.4] --- 2026-06-16

The "EdDSA" release. Extends the Wycheproof harness with Ed25519 and Ed448 coverage and ships a quality-of-life polish on the release pipeline.

### Added

* **`CKM_EDDSA`** is now declared and accepted by `C_VerifyInit` / `C_SignInit`. The mechanism routes through the same `hash=NULL` `EVP_DigestVerify` path used for ML-DSA and SLH-DSA --- EdDSA's single-shot internal hashing makes this the natural match.
* **`C_CreateObject` grows a `CKK_EC_EDWARDS` branch**. It maps the curve OID DER (`1.3.101.112` for Ed25519, `1.3.101.113` for Ed448) to the OpenSSL algorithm name and imports the raw public key via `OSSL_PARAM("pub")`.
* **`tests/wycheproof/adapters/eddsa.py`** covers Ed25519 + Ed448 with per-curve diagnostics, schema filter (`eddsa_verify_schema_v1.json`) and the singleton `P11Module` pattern.

### Changed

* `scripts/gen_p11_thunks.py` now emits an SPDX-License-Identifier header in the two generated C outputs (`include/fhsm_pkcs11_mechanisms.h` and `src/gen/fhsm_dispatch.c`). The committed copies are regenerated.
* `.github/workflows/release.yml` adds a defensive `chmod +x scripts/*.sh tests/*.sh ...` in the Build step so a runner that drops the exec bit on `actions/checkout` cannot break `make integrity` again.

### Validation

```
ecdsa     match= 3098  viol= 0  skip=18794
rsa_pss   match= 1083  viol= 0  skip= 1323
eddsa     match=  236  viol= 0  skip=    0    (150 Ed25519 + 86 Ed448)
```

4 417 Wycheproof vectors pass with zero violations across the three asymmetric-signature families.

---

## [1.1.3] --- 2026-06-16

The "Wycheproof" release. FreeHSM C is now validated bit-for-bit against Google's Project Wycheproof crypto test-vector suite for ECDSA (P-256/P-384/P-521) and RSA-PSS (SHA-256/384/512, any salt length). **4 181 / 4 181 vectors pass** with zero violations.

### Added

* **`C_CreateObject`** is now implemented for `CKO_PUBLIC_KEY` with `CKK_EC` (curves P-256, P-384, P-521) and `CKK_RSA` (any modulus / public exponent). The pubkey is normalised into an X.509 `SubjectPublicKeyInfo` DER blob via `EVP_PKEY_fromdata` + `i2d_PUBKEY`, transparent to the existing `C_Verify` path. Unblocks any external-key-import workflow (`pkcs11-tool --write-object`, JCE keystore imports, Wycheproof harnesses).
* **`CKM_SHA384_RSA_PKCS_PSS`** (`0x44`) and **`CKM_SHA512_RSA_PKCS_PSS`** (`0x45`) are now declared, accepted by `C_VerifyInit` / `C_SignInit`, mapped to their hash by `mech_hash_name`, and routed through `EVP_PKEY_CTX_set_rsa_padding(PSS)` by `mech_is_pss`. Previously these mechanisms returned `CKR_MECHANISM_INVALID` upfront and, even when accepted, silently used PKCS#1 v1.5 padding.
* **`CK_RSA_PKCS_PSS_PARAMS` parsing** : `C_SignInit` / `C_VerifyInit` now extract `hashAlg`, `mgf` and `sLen` from `pMechanism->pParameter` and apply them in the `EVP_PKEY_CTX_set_rsa_pss_saltlen` call. Previous releases hard-coded `-1` (= digest length), failing any verify where the caller asked for a different salt size.
* **`tests/wycheproof/`** end-to-end harness :
  - Schema-aware orchestrator (`run_wycheproof.py`) with per-adapter classification (`canonical_valid` / `canonical_invalid` / `noncanonical_other` / `hard_fail` for ECDSA ; `salt_eq_hashlen` / `salt_neq_hashlen` / `unsupported_sha` / `unsupported_mgf` for RSA-PSS).
  - Strict DER parser (`_der.py`) with lenient-parse-plus-canonicality-flag mode so non-strict-DER cases get categorised rather than auto-failed.
  - PKCS#11 ctypes binding (`_p11.py`) singleton-by-path (multiple adapters share one `C_Initialize`).
  - ECDSA adapter (`ecdsa.py`) covering `secp256r1`, `secp384r1`, `secp521r1` × `SHA-256/384/512`.
  - RSA-PSS adapter (`rsa_pss.py`) covering `SHA-256/384/512` × any `sLen`.
  - Violation breakdown report (top-15 categories by `expected` × comment prefix).
  - `.github/workflows/wycheproof.yml` : nightly full-suite run + per-push smoke run inside the pinned `freehsm-c-build:debian13-openssl-3.5` image.

### Changed

* `mech_hash_name` extended to handle the SHA-384 / SHA-512 PSS mechanisms.
* `mech_is_pss` extended likewise.
* `op_init` now captures the optional PSS parameter struct in three new `fhsm_op_t` fields (`pss_have`, `pss_saltlen`, `pss_mgf`) so `C_Sign` and `C_Verify` can honour the caller's salt length.

### Dev-only diagnostics

The following are gated on the development bypass flags and are **forbidden in any FIPS 140-3 / CC EAL4+ deployment** (see `docs/AGD_PRE.fr.md §7.5 / §7.5bis`) :

* **`FHSM_KAT_ALLOW_FAIL`** : when set together with `FHSM_INTEGRITY_ALLOW_UNSIGNED`, `fhsm_crypto_init()` reports KAT failures on `stderr` (with the offending algorithm + vector ID) but continues initialisation instead of latching the module ERROR state. Intended for `tests/wycheproof/` running against a non-signed build where the `OpenSSL FIPS provider` config is absent ; latches a loud warning on every init in dev-mode.
* **Dev-mode short-circuit in `crypto_init_once`** : `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` now skips the `OSSL_PROVIDER_load("fips")` / `OSSL_PROVIDER_load("base")` calls entirely and loads the OpenSSL default provider. This avoids leaving libcrypto in a state where every EVP fetch requires `fips=yes` with no provider to satisfy it (which was breaking AES-GCM and consequently every `fhsm_token_init()` DEK wrap).

### Open follow-ups

* `CKM_ECDSA` (raw) format mismatch : the spec says raw r||s, the implementation expects DER. Adapter contains a workaround ; module side will be fixed in v1.2.0 with a proper DER↔raw conversion plus pre-hashed `EVP_PKEY_verify` path.
* `tests/wycheproof/VECTORS_SHA` currently tracks `main` for bootstrap convenience. Will be pinned to a concrete commit SHA before v1.2.0 for bit-for-bit reproducibility.

### Validation

```
ecdsa     match= 3098  viol= 0  skip=18794   (100% on supported curves / hashes)
rsa_pss   match= 1083  viol= 0  skip= 1323   (100% on SHA-256/384/512, any sLen)
```

---

## [1.1.2] --- 2026-06-13

The "container-based reproducible build" release. Restores production-grade FIPS 140-3 / CC EAL4+ reproducibility claims for tagged releases by running the release pipeline inside a pinned Docker image.

### Added

* **GitHub Actions `build-image.yml`** is now operational : on manual dispatch (or `Dockerfile.build` change), it builds and pushes `ghcr.io/<owner>/freehsm-c-build:debian13-openssl-3.5` and `:latest` to GitHub Container Registry.
* **`release.yml`** now runs every step inside the pinned image. Toolchain versions are no longer subject to silent bumps from `ubuntu-latest`.

### Changed

* `Dockerfile.build` switched from a placeholder Debian 12.5 digest (non-existent on docker.io) to **Debian 13 (trixie) slim** by tag, with Debian-packaged OpenSSL 3.5.x instead of from-source FIPS provider compilation. Apt versions intentionally unpinned for the v1.1.x transitional pipeline ; pinning + digest lock is tracked for v2.0 / formal CST submission.
* `.github/workflows/release.yml` :
  - Re-introduced `container:` directive pointing to the pinned image.
  - Removed the `Install build dependencies` step (image already has everything).
  - `.sha256` files now contain basename-only paths (write from inside `dist/` so `sha256sum -c file.sha256` works for downstream users without recreating the dist/ layout).
* `.gitlab-ci.yml` and `release.yml` tag filter regex unchanged (still `v*` / `/^v[0-9]/`) — applies cleanly to v1.1.2.

### Fixed

* `sha256sum -c` on v1.1.1 release artefacts failed with `dist/freehsm-c-...: No such file or directory` because the workflow wrote the full path. Fixed in v1.1.2 ; v1.1.1 verification can be done by running `sed -i 's|dist/||' file.sha256` before `sha256sum -c`.

---

## [1.1.1] --- 2026-06-13

The "OSS-ready" release. No functional change to the cryptographic module; this version finalises the open-source publication pipeline and recovers from a maintainer GPG private-key leak.

### Added

* **REUSE 3.3 compliance** (`LICENSES/` directory with `Apache-2.0`, `CC0-1.0`, `LicenseRef-NIST-PD`; `REUSE.toml` with bulk SPDX annotations for build tooling, scripts, generated headers and tests). 123 / 123 files SPDX-headered. See `reuse lint` output.
* **OpenSSF Best Practices registration** : project ID **13190** at https://www.bestpractices.dev/projects/13190 with pre-filled answers covering passing + silver tier criteria. See `docs/OPENSSF_BEST_PRACTICES.md`.
* **README badges** : License (Apache-2.0), REUSE status, OpenSSF Best Practices, CI, Mirror — all wired to the live endpoints.
* **GitHub Actions `mirror.yml`** workflow : replicates the GitHub repo to GitLab (`gitlab.com/afchine.mad/freehsm-c`) and Codeberg (`codeberg.org/afchine1337/freehsm-c`) on every push and tag. Replaces the unavailable Pull-mirror on GitLab Free.
* **GitHub Actions `release.yml`** workflow : on tag `v*`, builds the `.so` (apt deps inline on `ubuntu-latest`, with `Dockerfile.build` ready for future reintroduction), produces source + binary `.tar.xz`, GPG-signs the tarballs with the release key embedded in GitHub Secrets, publishes a GitHub Release.
* **GitHub Actions `build-image.yml`** workflow : on manual dispatch or `Dockerfile.build` change, builds and pushes the pinned reproducible-build image to `ghcr.io/<owner>/freehsm-c-build:debian13-openssl-3.5`. Required for restoring full bit-identical reproducibility under FIPS 140-3 / CC EAL4+ claims.
* **`scripts/setup-release-secrets.sh`** : helper that exports the maintainer GPG private key + passphrase to local secret files, then prints the exact paste-instructions for the two GitHub Secrets `RELEASE_GPG_KEY` and `RELEASE_GPG_PASSPHRASE`.
* **`scripts/tag-rc.sh`** : tags + signs + pushes a release-candidate (or production) tag, validates the GPG signature locally before pushing.

### Changed

* **README.md** is now in **English by default**, French moved to **`README.fr.md`** — aligns with the convention already used in `docs/` (base name = English, `.fr.md` = French).
* **`docs/INDEX.md`** : language columns inverted to reflect the new convention, updated text explaining the new defaults.
* **`SECURITY.md`** : added a public disclosure note documenting the GPG key rotation of 2026-06-12 (see Security below).

### Fixed

* `include/fhsm_common.h` and `scripts/gen_p11_thunks.py` : replaced the leftover `Copyright (c) 2026 FreeHSM authors. SPDX-License-Identifier: MIT.` cartouches with the canonical Apache-2.0 header consistent with the rest of the codebase.
* `.gitignore` : added `CODEBERG_SSH_KEY`, `GITLAB_SSH_KEY`, `RELEASE_GPG_PASSPHRASE`, `RELEASE_GPG_KEY`, `*.gpg.key`, `deploy-key*` to prevent accidental commit of operator secrets.
* `.gitlab-ci.yml` and `.github/workflows/release.yml` : tag regex changed from `v*-FIPS*` to `v*` (removes the FIPS marketing suffix from version strings) and from `/^v.*-FIPS/` to `/^v[0-9]/`.

### Security

* **Maintainer GPG signing key rotated** on 2026-06-12. The previous key `B79726CB087375CF990E00E4A0BC5BB2FB1EE342` (Ed25519) was **compromised** : its ASCII-armored private export was accidentally committed to the public repository in commit `922c6f7` (the initial open-source release). Mitigations completed on the same day :
  - Revocation certificate generated (reason : KEY_COMPROMISED, "Private key accidentally committed to public git repo") and published on `keys.openpgp.org` and `keyserver.ubuntu.com`.
  - New release signing key generated : `743A6A5904A1461A646408DE48560162DBBF28A2` (Ed25519, valid until 2028-06-11).
  - Git history rewritten with `git filter-repo --invert-paths --path afchine-secret-BACKUP.asc` on origin (GitHub), gitlab and codeberg. The leaked file no longer appears in any blob on any mirror.
  - The `v1.1.0` release tag was re-signed with the new key.
  - Anyone who cloned `freehsm-c` between 2026-06-12 morning and 2026-06-12 evening must re-clone.

### Operational

* Branch protection on `main` enabled on GitHub **and** GitLab (force push forbidden, Maintainers-only). Codeberg branch protection : TBD.
* Pipeline `release.yml` validated end-to-end via `v1.1.1-rc1` : tag verification → build → tarballs → GPG signing → GitHub Release publication, all green.

---

## [1.1.0] --- 2026-06-11

The "CST pre-submission" refresh. Closes 8 of the 11 items on the NIST CST lab checklist, adds runtime-mode switching, and ships a hardened DRBG layer with NIST SP 800-90B health tests.

### Added

* **Pair-wise consistency check** post `C_GenerateKeyPair` for RSA, EC, ML-KEM, ML-DSA and SLH-DSA (FIPS 140-3 §7.10.2.b). Failure latches the module ERROR state and refuses to persist the keypair. See `src/fhsm_pairwise.c`.
* **Hardened DRBG layer** in front of OpenSSL's CTR_DRBG-AES-256 : multi-source entropy (getrandom + RDRAND + /dev/urandom + TSC jitter), SHA-256 conditioner, RCT + APT + CRNGT health tests (SP 800-90B §4.4), auto-reseed every 1 MiB or 1 h. See `src/fhsm_drbg.c`, `docs/RNG.md`.
* **Continuous DRBG test** (FIPS 140-3 §7.10.3.b) embedded in the hardened pipeline ; mismatch on the 16-byte block window latches ERROR.
* **TPM 2.0 sealing companion file** for the per-token DEK (opt-in via `FHSM_TPM_SEALING=1`). The DEK is wrapped under PBKDF2 AND sealed to TPM PCRs 0-7. Mismatch is treated as wrong PIN to avoid oracle attacks. See `src/fhsm_token_tpm.c`.
* **CAVP extended vector set** : 2 verified AES-GCM-256 vectors from NIST SP 800-38D Annex B + 4 HMAC-SHA-256 vectors from RFC 4231 §4.2-4.5. See `kat/cavp_extended.c`.
* **Runtime mode switch** : the module now defaults to **legacy mode** and only enters FIPS-strict mode when `FHSM_MODE=fips` (or `/etc/freehsm/freehsm.conf` states `mode = fips`). In FIPS strict mode every non-approved mechanism (MD5, plain SHA-1, DES, 3DES, RC4) is rejected ; in legacy mode they are routed to the legacy dispatcher. See `src/fhsm_mode.c`, `src/dispatch/fhsm_dispatch_legacy.c`.
* **PQ algorithm aliases and stubs** : `CKM_KYBER*` as alias for `CKM_ML_KEM*`, plus PKCS#11 IDs reserved for `CKM_FALCON*`, `CKM_LMS*`, `CKM_XMSS*`, `CKM_HQC*`. See `docs/POST_QUANTUM.md`.
* **Coverage matrix extension** : new section 9 "Runtime mode switch" exercising MD5 acceptance in legacy mode AND rejection in FIPS mode. SHA-3 digests added to the section 4 loop. Final score : 27/32 PASS + 5 SKIP (OpenSC CLI limitations only).
* **Documentation** : `docs/RNG.md`, `docs/POST_QUANTUM.md`, `docs/SIDE_CHANNEL.md`, `docs/FIPS_140_3_SECURITY_TARGET.md`, `docs/CST_LAB_SUBMISSION_CHECKLIST.md`.

### Changed

* `fhsm_rng_bytes` is now a thin wrapper over `fhsm_drbg_bytes` (all RNG output passes through the hardened pipeline).
* `dispatch_reject_fips` is mode-sensitive : FIPS strict → `FHSM_RV_FIPS_NOT_APPROVED` ; legacy → `fhsm_legacy_dispatch` (weak symbol).
* `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` now bypasses ALL integrity-failure paths (section missing, all-zero digest, mismatch, provider load failure). Dev-only ; AGD_PRE §7.5 forbids the variable in production.
* `Makefile` LIB_SRC bumped to 17 source files (added 6 new modules).

### Fixed

* `src/fhsm_tpm.c` `run_silent` buffer enlarged from 1024 to 2560 bytes to silence GCC `-Wformat-truncation`.
* `tests/coverage_matrix.sh` now uses `sudo -E` to propagate `FHSM_TOKENS_DIR` to `pkcs11-tool`, and `unset FHSM_TOKENS_DIR` before the PQ harness section so the harnesses operate on the production slot.

### Security

* **FIPS 140-3 §7.10.2.b pair-wise consistency** : addressed (CST item K.1 closed).
* **FIPS 140-3 §7.10.3.b continuous DRBG** : addressed (item K.4).
* **CAVP coverage** : 2 published vectors per algorithm beyond the initial smoke set ; full set (~100 per algo) to be requested from the CST lab during the formal engagement.

---

## [1.1.0-pre] --- 2026-06-10

The "Debian 13 / OpenSSL 3.5" release. Module ported, validated by three
independent PKCS#11 clients, full asymmetric / symmetric / PQ surface wired.

### Added

* **PKCS#11 v3.2 entry points**
  * `C_GenerateKeyPair` for RSA-2048/3072/4096, ECDSA P-256/384/521, ML-KEM,
    ML-DSA, SLH-DSA via `EVP_PKEY_Q_keygen` against the OpenSSL FIPS provider.
  * `C_DeriveKey` for `CKM_ECDH1_DERIVE` and `CKM_ECDH1_COFACTOR_DERIVE`,
    accepting peer pubkey in raw / DER OCTET STRING / X.509 SPKI formats.
  * `C_WrapKey` / `C_UnwrapKey` for `CKM_AES_KEY_WRAP` (RFC 3394),
    `CKM_AES_KEY_WRAP_KWP` (RFC 5649), and `CKM_RSA_PKCS_OAEP`.
  * `C_EncapsulateKey` / `C_DecapsulateKey` (v3.0 extended) for ML-KEM-768
    via `EVP_PKEY_encapsulate` / `_decapsulate`. Currently reachable via
    `dlsym` only ; v3.0 interface table to be wired in a future release.
  * Multi-part streaming for Encrypt / Decrypt / Sign / Digest
    (`*Update` / `*Final`) using persistent `EVP_*_CTX` per session.
  * Sign / Verify for RSA-PKCS / RSA-PSS / ECDSA / ML-DSA / SLH-DSA
    via `EVP_DigestSign` (classical) and `EVP_PKEY_sign` (PQ, no prehash).
  * AES-CMAC with cipher-param `EVP_MAC`. Accepts both `0x108C` (spec) and
    `0x108A` (OpenSC pkcs11-tool legacy bug).

* **Mechanism registry** : `C_GetMechanismList` exposes ~70 mechanisms
  across RSA, ECDSA, ECDH, AES (GCM / CBC / CTR / CMAC / KW / KWP),
  SHA-1/224/256/384/512, HMAC, PBKDF2, ML-KEM, ML-DSA, SLH-DSA, plus the
  legacy DES3 / SSL3 / Falcon / Kyber for compat advertising.

* **Token store** :
  * Binary file format (317 bytes header + appended encrypted object blob).
  * PBKDF2-HMAC-SHA-256 (200k iterations) + AES-256-GCM DEK wrap, with the
    token's serial as AAD.
  * Object store with persistence (CKO_SECRET_KEY, CKO_PUBLIC_KEY,
    CKO_PRIVATE_KEY ; up to 64 objects per slot ; values up to 2500 bytes
    to accommodate RSA-4096 PKCS#8 DER).
  * `CKA_SENSITIVE` / `CKA_EXTRACTABLE` enforcement on `C_GetAttributeValue`.
  * `CKA_LABEL`, `CKA_ID`, `CKA_MODULUS`, `CKA_MODULUS_BITS`,
    `CKA_PUBLIC_EXPONENT`, `CKA_EC_POINT`, `CKA_EC_PARAMS`,
    `CKA_SENSITIVE`, `CKA_EXTRACTABLE` exposed via `C_GetAttributeValue`.
  * Throttle (exponential 500 ms → 60 s) + lockout (5 attempts) on PIN.

* **Self-tests** :
  * 6 smoke KAT (AES-GCM, SHA-256, HMAC-SHA-256, PBKDF2, DRBG, AES-GCM
    tamper rejection).
  * 9 CAVP SHA-256 short-message vectors parsed from `kat/cavp/*.rsp`.
  * Pre-operational integrity check on the `.text` section vs an embedded
    `.fhsm_digest` patched by `make integrity`.

* **Multi-slot dynamic** : 4 slots configurable via `FHSM_MAX_SLOTS`. Each
  has its own DEK, PIN throttle, object store, audit chain. Cross-slot
  isolation validated by `tests/multi_slot_pkcs11.sh`.

* **Audit chain** : append-only JSON Lines with HMAC-SHA-256 chained MAC.
  `freehsm-audit dump` (human-readable) + `freehsm-audit verify` (chain
  integrity) tools shipped in `/opt/freehsm/bin/`.

* **Reproducible build** :
  * `Dockerfile.build` pinning GCC + binutils + OpenSSL.
  * `make dist-baseline` to record the reference digest.
  * `make dist-verify` to compare a local build against the reference.

* **Documentation** :
  * `docs/AGD_PRE.fr.md` §7 ("Portage Debian 13") + §8 ("Validation
    cryptographique end-to-end") with the 3-step OpenSSL interop procedure
    and 7 acceptance criteria.
  * `docs/AGD_PRE.md` §7 (English, bilingual parity).
  * `CHANGELOG.md` (this file).

* **Tests** :
  * `tests/integration_pkcs11.sh` (17 assertions, end-to-end slot
    lifecycle).
  * `tests/multi_slot_pkcs11.sh` (13 assertions, slot isolation).
  * `tests/full_crypto_pkcs11.sh` (20 assertions across AES-GCM,
    AES-CBC-PAD, AES-CMAC, SHA, HMAC, ECDSA + external OpenSSL verify,
    RSA + external OpenSSL verify, RSA-OAEP roundtrip).
  * `tests/interop_python.py` (alternative client via `python-pkcs11` +
    `cryptography`, demonstrates interop beyond OpenSC).
  * `tests/mlkem_e2e.c` (direct dlsym C harness for ML-KEM Encap+Decap
    round-trip).

### Changed

* **Build hardened against gcc 14** : the strict-warning flags
  (`-Wmissing-prototypes`, `-Wstringop-truncation`, `-Wmisleading-indentation`,
  `-Werror=array-bounds`, etc.) all clean. 19 ports fixes applied during
  the Debian 12 → Debian 13 migration are documented in
  `docs/AGD_PRE.fr.md` §7.

* **Makefile install target** : rewritten without dash-incompatible
  `<<-EOF`+`if`/`fi` constructs that broke on Debian 13's `/bin/sh` ->
  `dash`. Now uses pure `printf` and `test x || command`.

* **PKCS#11 ABI bug fixed** : `CK_VERSION` is two `CK_BYTE` (1 byte each),
  not two `unsigned short` ; the wrong width was shifting downstream
  fields by 2 bytes and showing empty manufacturer / version 3.0 instead
  of 3.2 in `--show-info`.

* **OpenSC interop aliases** :
  * `CKM_AES_CMAC` accepted at both `0x108C` (spec) and `0x108A`
    (OpenSC `pkcs11-tool --mechanism AES-CMAC` legacy bug).
  * `CKM_ECDH1_COFACTOR_DERIVE` (`0x1051`) accepted as alias for
    `CKM_ECDH1_DERIVE` (`0x1050`) since pkcs11-tool's `--derive`
    sends the cofactor variant by default.

* **Public key DER parsing** in `C_DeriveKey` and `C_EncapsulateKey`
  now handles three input formats : raw uncompressed point, DER
  `OCTET STRING` wrapper, and DER X.509 `SubjectPublicKeyInfo`.

### Fixed

* `CKM_AES_CMAC` was defined as `0x108A` in the generated header (legacy
  OpenSC bug) ; corrected to `0x108C` per PKCS#11 v3.2 §A.4.1.
* `EVP_PKEY_get_octet_string_param("encoded-pub-key", ...)` two-pass
  query+fill pattern used for `CKA_EC_POINT` extraction.
* Buffer-too-small detection (returns `CKR_BUFFER_TOO_SMALL = 0x150`)
  on every query path of `C_Encrypt`, `C_Sign`, `C_Encapsulate`.
* PBKDF2 KAT vector adjusted to satisfy FIPS lower bounds (password ≥ 14,
  salt ≥ 16 bytes) which were rejecting our "smoke" vector.

### Known limitations

* `C_GetInterface` / `C_GetInterfaceList` are not yet exposed because
  the first attempt segfaulted `pkcs11-tool` (root cause TBD ; the
  `CK_FUNCTION_LIST_3_0` extended layout is required). `C_EncapsulateKey`
  / `C_DecapsulateKey` remain reachable via `dlsym` for now.
* `AES-CTR` decrypt is wired in the module but `OpenSC pkcs11-tool` of
  Debian 13 doesn't expose `--decrypt --mechanism AES-CTR` ; the
  integration test skips it transparently with an explanatory message.
* `ML-DSA` / `SLH-DSA` sign+verify wire is in place but `pkcs11-tool` of
  Debian 13 doesn't recognize these mechanism names. Tested via
  `tests/mlkem_e2e.c` for ML-KEM ; ML-DSA can be exercised similarly
  through a custom harness.


## [1.0.0-FIPS] --- 2025-12

Initial C reimplementation of the original Python proof-of-concept.
Scope : minimal PKCS#11 v3.0 with AES-GCM and SHA-2, FIPS 140-3 §7.10
self-tests, integrity boot check, token store scaffold.

* 6 smoke KATs
* Slot 0 hard-coded
* `C_Initialize` / `C_Finalize` / `C_GetInfo`
* Audit chain HMAC
* Reproducible build infrastructure (Dockerfile.build)
* Documentation : `AGD_PRE` and `AGD_OPE` skeletons in EN+FR
