# Changelog

All notable changes to FreeHSM C are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project adheres to [Semantic Versioning](https://semver.org/).

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
