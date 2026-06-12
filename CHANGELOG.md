# Changelog

All notable changes to FreeHSM C are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project adheres to [Semantic Versioning](https://semver.org/).

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
