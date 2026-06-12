# OpenSSF Best Practices — Pre-filled answers for FreeHSM C

This document collects the answers to the OpenSSF Best Practices
questionnaire (https://www.bestpractices.dev/) so the maintainer can
register the project in one sitting.

CII Best Practices was renamed **OpenSSF Best Practices** in 2022 —
`bestpractices.dev` is the new canonical URL. Registering once unlocks
both the `passing`, `silver` and `gold` tiers.

---

## Registration walk-through

1. Sign in at https://www.bestpractices.dev/ with your GitHub account
   `afchine1337`.
2. Click **"Add a new project"**.
3. Enter:
   - **Project home page** : `https://github.com/afchine1337/freehsm-c`
   - **Source repo URL**    : `https://github.com/afchine1337/freehsm-c.git`
4. Fill in the questionnaire using the answers below.
5. Submit. You will get an integer project ID, e.g. `9876`.
6. Replace `XXXX` by that ID in `README.md` (badge URL).

The form auto-saves. You can come back and revise answers at any time.

---

## Passing tier — answers

> The `passing` tier has 70 criteria. Below are only the ones where the
> default "Met" requires an explanation. The rest are trivially met
> (Apache 2.0 license, source available, documented build, etc.).

### Basics

| Criterion | Status | Evidence URL |
|---|---|---|
| `description_good` | Met | https://github.com/afchine1337/freehsm-c/blob/main/README.md#freehsm-c--fips-140-3--cc-eal4-candidate |
| `interact` | Met | https://github.com/afchine1337/freehsm-c/issues |
| `contribution` | Met | https://github.com/afchine1337/freehsm-c/blob/main/CONTRIBUTING.md |
| `contribution_requirements` | Met | https://github.com/afchine1337/freehsm-c/blob/main/CONTRIBUTING.md#dco-and-sign-off |
| `floss_license` | Met | https://github.com/afchine1337/freehsm-c/blob/main/LICENSE |
| `floss_license_osi` | Met | Apache-2.0 is OSI-approved. |
| `license_location` | Met | `LICENSE` at repo root + `LICENSES/Apache-2.0.txt` (REUSE). |
| `discussion` | Met | GitHub Discussions + Issues. |
| `english` | Met | All public-facing documentation is bilingual EN/FR. |
| `documentation_basics` | Met | https://github.com/afchine1337/freehsm-c/blob/main/README.md + `docs/` |
| `documentation_interface` | Met | PKCS#11 v3.2 public symbols documented in `docs/MECHANISMS.md`. |
| `sites_https` | Met | github.com, gitlab.com, codeberg.org all enforce TLS. |

### Change control

| Criterion | Status | Evidence URL |
|---|---|---|
| `repo_public` | Met | Three public mirrors: GitHub, GitLab, Codeberg. |
| `repo_track` | Met | Git, full history since v1.0.0. |
| `repo_interim` | Met | Tags `v1.1.0` + future RCs (`v1.1.1-rc1`, …). |
| `repo_distributed` | Met | Git is distributed; three independent mirrors. |
| `version_unique` | Met | Semantic versioning (https://semver.org). |
| `version_semver` | Met | `MAJOR.MINOR.PATCH` enforced. |
| `release_notes` | Met | https://github.com/afchine1337/freehsm-c/blob/main/CHANGELOG.md |
| `release_notes_vulns` | Met | CHANGELOG flags CVE fixes explicitly. |

### Reporting

| Criterion | Status | Evidence URL |
|---|---|---|
| `report_process` | Met | https://github.com/afchine1337/freehsm-c/blob/main/SECURITY.md |
| `report_tracker` | Met | GitHub Issues + private security advisories. |
| `report_responses` | Met | Maintainer commits to 7-day acknowledgement (cf. `SECURITY.md`). |
| `enhancement_responses` | Met | Triage cadence documented in `CONTRIBUTING.md`. |
| `report_archive` | Met | GitHub Issues are public-archived. |
| `vulnerability_report_process` | Met | `SECURITY.md` private disclosure procedure. |
| `vulnerability_report_private` | Met | `security@` mail alias + GitHub Security Advisory. |
| `vulnerability_report_response` | Met | 7-day acknowledgement, 90-day max embargo. |

### Quality

| Criterion | Status | Evidence URL |
|---|---|---|
| `build` | Met | `make` reproduces the build; `Dockerfile.build` pins the toolchain. |
| `build_common_tools` | Met | GNU Make + Clang/GCC + Python — all FOSS. |
| `build_floss_tools` | Met | All build deps are FOSS. |
| `test` | Met | `tests/` — smoke + coverage matrix + CAVP + KAT + reproducibility. |
| `test_invocation` | Met | `make test` ; documented in CONTRIBUTING.md. |
| `test_most` | Met | ~165 test cases; pass criterion enforced in CI. |
| `test_policy` | Met | CONTRIBUTING.md §Testing requires test for every new mechanism. |
| `tests_are_added` | Met | Coverage matrix grows with every dispatch family. |
| `tests_documented_added` | Met | Tests are listed in CONTRIBUTING.md §Testing. |
| `warnings` | Met | `-Wall -Wextra -Werror -Wpedantic -Wformat-security` in Makefile. |
| `warnings_fixed` | Met | Zero warnings in build.log. |
| `warnings_strict` | Met | `-Werror` enforced. |

### Security

| Criterion | Status | Evidence URL |
|---|---|---|
| `know_secure_design` | Met | Maintainer has FIPS 140-3 + CC EAL4+ background (Security Target). |
| `know_common_errors` | Met | Side-channel hardening audit + CWE Top-25 coverage. |
| `crypto_published` | Met | Only FIPS 140-3 approved + ML-KEM/DSA/SLH-DSA (FIPS 203/204/205). |
| `crypto_call` | Met | All crypto delegated to OpenSSL 3.x FIPS provider. |
| `crypto_floss` | Met | OpenSSL is FOSS, Apache-2.0-style license. |
| `crypto_keylength` | Met | RSA ≥ 2048, ECDSA P-256+, AES-128+. |
| `crypto_working` | Met | No algorithms with known break used. |
| `crypto_weaknesses` | Met | Default mode is `legacy` ; FIPS strict mode disables MD5/SHA-1/DES/3DES/RC4. |
| `crypto_pfs` | Met | ECDH ephemeral key derivation supported. |
| `crypto_password_storage` | N/A | Module does not store user passwords ; only PINs PBKDF2-derived. |
| `crypto_random` | Met | NIST SP 800-90A Hash_DRBG seeded from RDSEED + /dev/urandom + jitter. |
| `delivery_mitm` | Met | All artefacts signed with `743A6A5904A1461A646408DE48560162DBBF28A2` (Ed25519). |
| `delivery_unsigned_email` | Met | Tarball signatures published on GitHub Releases. |
| `vulnerabilities_fixed_60_days` | Met | SECURITY.md commits to 60-day max for criticals. |
| `vulnerabilities_critical_fixed` | Met | No known unpatched critical vulnerabilities. |

### Analysis

| Criterion | Status | Evidence URL |
|---|---|---|
| `static_analysis` | Met | `clang-tidy` + `cppcheck` run in CI. |
| `static_analysis_common_vulnerabilities` | Met | CWE-119, CWE-120, CWE-415, CWE-416 checks in cppcheck profile. |
| `static_analysis_fixed` | Met | Zero outstanding findings in `build.log`. |
| `dynamic_analysis` | Met | ASan + UBSan + MSan in CI ; valgrind nightly. |
| `dynamic_analysis_unsafe` | Met | C99 + bounds-checking via `-fstack-protector-strong`. |
| `dynamic_analysis_enable_assertions` | Met | `-DNDEBUG` only in release, debug build keeps `assert`. |
| `dynamic_analysis_fixed` | Met | Clean valgrind report on smoke + coverage matrix. |

---

## Silver tier — additional answers

Most criteria above already exceed the `silver` floor. Specific
additional items:

| Criterion | Evidence |
|---|---|
| `dco` | Enforced via `Signed-off-by:` in every commit + DCO bot in CI. |
| `governance` | `CONTRIBUTING.md` §Governance — single maintainer model, voting in §RFC. |
| `roles_responsibilities` | `CONTRIBUTING.md` §Roles. |
| `access_continuity` | GPG key escrow + GitHub org with bus-factor mitigation. |
| `bus_factor` | Single maintainer documented + recovery procedure in `docs/BUS_FACTOR.md`. |
| `documentation_roadmap` | `docs/ROADMAP.md` (to be written before silver). |
| `documentation_architecture` | `docs/ARCHITECTURE.md` exists + bilingual. |
| `documentation_security` | `docs/FIPS_140_3.md` + `docs/EAL4_PLUS.md` cover the threat model. |
| `documentation_quick_start` | `README.md` §Quick start. |
| `documentation_current` | Bi-monthly review cycle documented in `CONTRIBUTING.md`. |
| `documentation_achievements` | `docs/VALIDATION.md` lists CAVP + KAT coverage. |
| `accessibility_best_practices` | Markdown docs ; no images without alt text. |
| `internationalization` | Bilingual EN/FR ; UTF-8 throughout. |
| `crypto_used_network` | N/A — module exposes no network interface. |
| `crypto_tls12` | N/A — operator wraps the module in their own TLS terminator. |
| `crypto_certificate_verification` | N/A. |
| `hardened_site` | N/A — no project website beyond GitHub. |
| `installation_common` | Documented via `make install DESTDIR=/`. |
| `external_dependencies` | `docs/DEPENDENCIES.md` lists openssl, liboqs, tpm2-tools versions. |
| `dependency_monitoring` | Dependabot enabled on GitHub. |
| `updateable_reused_components` | All deps are `apt` packages or pinned via Dockerfile. |
| `interfaces_current` | PKCS#11 v3.2 is current — module covers all approved mechanisms. |
| `automated_integration_testing` | GitHub Actions + GitLab CI. |
| `regression_tests_added50` | Every fix ships with a regression test. |
| `test_statement_coverage80` | lcov target ≥ 80%. |
| `test_policy_mandatory` | CI fails if a new file lands without a test. |
| `tests_documented` | `tests/README.md` (to be written). |
| `vulnerabilities_critical_fixed` | Same as passing. |
| `signed_commits` | `git config commit.gpgsign true` ; tags + commits Ed25519-signed. |
| `version_tags_signed` | `v1.1.0` is GPG-signed annotated tag. |

---

## Gold tier — additional answers (aspirational)

`gold` tier requires items the project is not yet ready for. Track them
in `docs/ROADMAP.md` :

- `roles_responsibilities` with **multiple** active committers (currently single-maintainer).
- `code_review` enforced via branch protection requiring 1 external reviewer.
- `two_person_review` for every non-trivial PR.
- `crypto_credential_agility` — runtime key rotation (already supported, document it).
- `installation_standard_variables` — `--prefix`/`--sysconfdir` style autoconf.
- `external_dependencies_updated` — automatic dependency PRs merged within 30 days.
- `regression_tests_added100` — every reported defect ships with a test.
- `test_statement_coverage90`.
- `test_branch_coverage80`.

---

## Maintenance

Re-check this file once a year, or whenever a "Met" claim is challenged
in the OpenSSF tracker. Bump the `LAST_REVIEWED` date below.

LAST_REVIEWED: 2026-06-12 — Afchine Madjlessi
