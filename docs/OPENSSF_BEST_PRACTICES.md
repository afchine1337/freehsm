# OpenSSF Best Practices — answers for FreeHSM, passing level

The project is registered as **[bestpractices.dev/projects/13190](https://www.bestpractices.dev/projects/13190)**.
This file holds the answer to each of the 67 `passing` criteria, so the form can be
filled in one sitting by the maintainer — the only person who can edit it.

**Every answer below was checked against the repository on 2026-10-01**, not
carried over. The previous version of this file was written before registration,
in June, and much of it had stopped being true or never was: it said `clang-tidy`
and `cppcheck` run in CI (neither did), that the test target is `make test` (it is
`make tests`), that MSan and valgrind run nightly, that the default runtime mode is
`legacy`, that GitHub Discussions are enabled, and in the silver section that a DCO
bot, Dependabot and an 80 % lcov gate exist. None of those was checked. The silver
and gold sections are removed rather than corrected; they will be written when
`passing` is reached, against the repository as it is then.

## State of the entry on 2026-10-01

Read from the project's public JSON:

| | |
|---|---|
| name | `freehsm-c` |
| home page | `https://github.com/afchine1337/freehsm-c` |
| repository | `https://github.com/afchine1337/freehsm-c.git` |
| last edited | 2026-06-13 |
| passing | 16 % — 11 Met, 7 Unmet, 177 unanswered |

The repository was renamed `freehsm` in July; the old URLs redirect, but the entry
should not depend on that. **Change first**: name `FreeHSM`, home page
`https://github.com/afchine1337/freehsm`, repository
`https://github.com/afchine1337/freehsm.git`.

Five criteria are marked **Unmet** on the form although the repository has met them
for months: `contribution`, `contribution_requirements`, `license_location`,
`release_notes`, `report_process`. The other two Unmet entries, `achieve_passing`
and `achieve_silver`, are computed by the site.

## Two answers that needed a change in the repository

- **`static_analysis` (MUST).** The Makefile had a `lint` target running
  `cppcheck`, and its comment said the build refused to ship if `cppcheck` or
  `scan-build` flagged a defect. Nothing ran it, and `scan-build` was never in it.
  Since 2026-10-01 CI's `static-analysis` job runs `make lint` on every push,
  gating; its first CI run (commit `336a0db`) was green.
- **`test_invocation` (SHOULD).** `make test` and `make check` now alias
  `make tests`.

## Basics

| Criterion | Answer | Justification and evidence |
|---|---|---|
| `description_good` | Met | The README's first paragraph: a PKCS#11 v3.2 software HSM. https://github.com/afchine1337/freehsm#readme |
| `interact` | Met | README links to issues, releases and CONTRIBUTING.md. https://github.com/afchine1337/freehsm#readme |
| `contribution` | Met | Pull requests on GitHub; branch model and PR checklist in CONTRIBUTING.md §2–3. https://github.com/afchine1337/freehsm/blob/main/CONTRIBUTING.md |
| `contribution_requirements` | Met | Coding style (C11, naming, constant-time rules, secure heap) in CONTRIBUTING.md §4; DCO sign-off in §1. https://github.com/afchine1337/freehsm/blob/main/CONTRIBUTING.md |
| `floss_license` | Met | Apache-2.0. https://github.com/afchine1337/freehsm/blob/main/LICENSE |
| `floss_license_osi` | Met | Apache-2.0 is OSI-approved. |
| `license_location` | Met | `LICENSE` at the repository root, plus REUSE-compliant `LICENSES/`. https://github.com/afchine1337/freehsm/blob/main/LICENSE |
| `documentation_basics` | Met | README, installation guide `docs/AGD_PRE.md`, operator guide `docs/AGD_OPE.md`. https://github.com/afchine1337/freehsm/tree/main/docs |
| `documentation_interface` | Met | The interface is OASIS PKCS#11 v3.2; the mechanisms offered and their parameters are in `docs/MECHANISMS.md`, the service reference in `docs/AGD_OPE.md` §5. https://github.com/afchine1337/freehsm/blob/main/docs/MECHANISMS.md |
| `sites_https` | Met | GitHub, GitLab and Codeberg serve the repository and releases over HTTPS only. |
| `discussion` | Met | GitHub Issues: searchable, each issue and comment addressable by URL, open to anyone with an account. GitHub Discussions are *not* enabled; issues are the mechanism. https://github.com/afchine1337/freehsm/issues |
| `english` | Met | All documentation is in English; the Common Criteria documents also have French versions. Issues are handled in English. |
| `maintained` | Met | Commits most days; v2.3.0 released 2026-10-07. https://github.com/afchine1337/freehsm/commits/main |

## Change control

| Criterion | Answer | Justification and evidence |
|---|---|---|
| `repo_public` | Met | https://github.com/afchine1337/freehsm, mirrored to GitLab and Codeberg. |
| `repo_track` | Met | Git records what, who and when for every change. |
| `repo_interim` | Met | Every change lands on `main` between releases, not only release commits. |
| `repo_distributed` | Met | Git. |
| `version_unique` | Met | Each release has a unique `vMAJOR.MINOR.PATCH` version. https://github.com/afchine1337/freehsm/releases |
| `version_semver` | Met | Semantic Versioning. |
| `version_tags` | Met | Each release is an annotated, GPG-signed git tag `vX.Y.Z` (GitHub verifies v2.0.0, v2.1.0, v2.2.0). https://github.com/afchine1337/freehsm/tags |
| `release_notes` | Met | Hand-written `RELEASE_vX.Y.Z.md` published as each GitHub release body (enforced by `release.yml` since v2.0.0), plus `CHANGELOG.md`. https://github.com/afchine1337/freehsm/releases |
| `release_notes_vulns` | Met | Release notes name every advisory fixed; e.g. v2.2.0 carries GHSA-c634-gqj6-4p2f. https://github.com/afchine1337/freehsm/releases/tag/v2.2.0 |

## Reporting

| Criterion | Answer | Justification and evidence |
|---|---|---|
| `report_process` | Met | GitHub Issues. https://github.com/afchine1337/freehsm/issues |
| `report_tracker` | Met | GitHub Issues. |
| `report_responses` | Met | All 11 issues opened by others between June and September 2026 were answered and closed. https://github.com/afchine1337/freehsm/issues?q=is%3Aissue |
| `enhancement_responses` | Met | Same set; it includes enhancement requests (e.g. #1, #16), each answered. |
| `report_archive` | Met | GitHub Issues are public and searchable. https://github.com/afchine1337/freehsm/issues?q=is%3Aissue |
| `vulnerability_report_process` | Met | SECURITY.md "Reporting a vulnerability". https://github.com/afchine1337/freehsm/blob/main/SECURITY.md |
| `vulnerability_report_private` | Met | Email encrypted to the maintainer's GPG key, fingerprint in SECURITY.md. GitHub's private vulnerability reporting is *not* enabled. https://github.com/afchine1337/freehsm/blob/main/SECURITY.md |
| `vulnerability_report_response` | *maintainer to answer* | Met if every private report in the last six months was acknowledged within 14 days; N/A if none was received. The five published advisories were self-disclosed, so the repository cannot answer this. |

## Quality

| Criterion | Answer | Justification and evidence |
|---|---|---|
| `build` | Met | `make` builds the module from source; `Dockerfile.build` gives a reproducible build. https://github.com/afchine1337/freehsm/blob/main/Makefile |
| `build_common_tools` | Met | GNU Make, GCC, Python 3. |
| `build_floss_tools` | Met | Every build tool and dependency is FLOSS. |
| `test` | Met | About 90 test programs and scripts in `tests/`, run by `make tests`, documented in CONTRIBUTING.md §3. https://github.com/afchine1337/freehsm/tree/main/tests |
| `test_invocation` | Met | `make test` and `make check`, aliases of `make tests`. |
| `test_most` | Met | Functional coverage, measured externally: every corpus run of pkcs11-check (about 92,000 tests) exercises 76 of PKCS#11 v3.2's 104 functions and every advertised mechanism. Branch coverage is not measured. https://github.com/afchine1337/freehsm/blob/main/docs/PKCS11_CHECK_FINDINGS.md |
| `test_continuous_integration` | Met | GitHub Actions on every push. https://github.com/afchine1337/freehsm/actions |
| `test_policy` | Met | CONTRIBUTING.md §5: a new mechanism comes with a KAT vector and a coverage-matrix assertion. https://github.com/afchine1337/freehsm/blob/main/CONTRIBUTING.md |
| `tests_are_added` | Met | Recent changes each added a test: `test_login_conflicts.c`, `test_ec_curve_bounds.c`, `test_kw_iv.c`. https://github.com/afchine1337/freehsm/commits/main/tests |
| `tests_documented_added` | Met | CONTRIBUTING.md §5. |
| `warnings` | Met | `-Wall -Wextra -Wpedantic -Werror -Wconversion -Wshadow -Wformat=2` and more (`WARN_FLAGS` in the Makefile). https://github.com/afchine1337/freehsm/blob/main/Makefile |
| `warnings_fixed` | Met | `-Werror`: a warning fails the build. |
| `warnings_strict` | Met | Same flags, `-Werror`. |

## Security

| Criterion | Answer | Justification and evidence |
|---|---|---|
| `know_secure_design` | *maintainer to answer* | A statement about the maintainer. Evidence the repository can offer: integrity self-test at load, PINs never accepted on the command line, secrets in a locked secure heap, fail-closed defaults. https://github.com/afchine1337/freehsm/blob/main/docs/FIPS_140_3_SECURITY_TARGET.md |
| `know_common_errors` | *maintainer to answer* | Likewise. Evidence: the findings log, the ASan/UBSan job, fuzzing, and the published handling of CWE-787 defects. https://github.com/afchine1337/freehsm/blob/main/docs/PKCS11_CHECK_FINDINGS.md |
| `crypto_published` | Met | The default build (`nist-approved-only`) offers only NIST-approved algorithms, including FIPS 203/204/205. |
| `crypto_call` | Met | Every primitive is delegated to OpenSSL 3.5; the module implements none itself. |
| `crypto_floss` | Met | OpenSSL, Apache-2.0. |
| `crypto_keylength` | Met | RSA 2048–4096, EC P-256 to P-521, AES 128–256; the lower bounds are enforced and advertised. |
| `crypto_working` | Met | MD5, single DES, RC4 and 3DES are not compiled into the default build; they exist only in the `all-mechanisms` profile, and the `strict` runtime mode refuses them there too. |
| `crypto_weaknesses` | Met | SHA-1 digest and SHA-1 RSA signatures are not compiled into the default build. HMAC-SHA-1 is offered, as NIST SP 800-131A still allows it. |
| `crypto_pfs` | N/A | The module implements no key-agreement protocol. It provides ECDH and ML-KEM as primitives, with which a caller can use ephemeral keys. |
| `crypto_password_storage` | Met | PINs are not stored. They are stretched with PBKDF2-HMAC-SHA-256 (200,000 iterations, per-token salt) into a key that unwraps the token's data key. |
| `crypto_random` | Met | Keys and nonces come from OpenSSL's CSPRNG (`RAND_bytes`, CTR_DRBG under the FIPS provider). |
| `delivery_mitm` | Met | HTTPS delivery; release tarballs GPG-signed. |
| `delivery_unsigned` | Met | Each release tarball ships with a `.sha256` and a `.asc` signature; nothing relies on an unsigned hash fetched over HTTP. https://github.com/afchine1337/freehsm/releases |
| `vulnerabilities_fixed_60_days` | Met | Each of the five published advisories names a patched release: 2.2.0, 2.1.0, 1.2.2, 1.2.1, and the re-signed 1.1.0. https://github.com/afchine1337/freehsm/security/advisories |
| `vulnerabilities_critical_fixed` | Met | Same. |
| `no_leaked_credentials` | Met | No valid credential is in the repository. The maintainer's previous GPG signing key was published by mistake with v1.1.0, revoked and rotated within 14 hours, and disclosed as GHSA-wgv9-m9cv-4647. The PINs in `tests/` are fixed values for disposable test tokens. https://github.com/afchine1337/freehsm/security/advisories/GHSA-wgv9-m9cv-4647 |

## Analysis

| Criterion | Answer | Justification and evidence |
|---|---|---|
| `static_analysis` | Met | cppcheck (`make lint`) on every push, CI job `static-analysis`, failing on any finding. https://github.com/afchine1337/freehsm/actions/workflows/ci.yml |
| `static_analysis_common_vulnerabilities` | Met | cppcheck checks buffer overruns, null dereferences, use after free, uninitialised variables and leaks; run with `--check-level=exhaustive`. |
| `static_analysis_fixed` | Met | `--error-exitcode=1`: a finding fails CI. The first run (2026-10-01) found no defect; its 124 findings were fixed, or suppressed with a stated reason (Makefile, and in place). |
| `static_analysis_often` | Met | On every push. |
| `dynamic_analysis` | Met | AddressSanitizer + UBSan over the whole suite on every push (`sanitizers` job), libFuzzer nightly (`fuzz.yml`), and external harnesses: pkcs11-check on the signed module, Wycheproof. https://github.com/afchine1337/freehsm/actions |
| `dynamic_analysis_unsafe` | Met | C code: ASan/UBSan and four libFuzzer harnesses, routinely. |
| `dynamic_analysis_enable_assertions` | Met | The sanitizer build enables ASan and UBSan runtime checks across the suite. |
| `dynamic_analysis_fixed` | Met | Defects found this way were fixed and, where exploitable, published as advisories (e.g. GHSA-c634-gqj6-4p2f). |

LAST_REVIEWED: 2026-10-01
