# FreeHSM C --- Configuration Management Documentation (CC EAL4+ ALC_CMC.4)

**TOE :** FreeHSM Cryptographic Module v1.0.0-FIPS
**CC class :** ALC (Life-cycle Support) — components ALC_CMC.4 (production support, acceptance procedures, automation), ALC_CMS.4 (problem tracking CM coverage), ALC_DEL.1 (delivery procedures), ALC_FLR.2 (flaw remediation), ALC_LCD.1 (developer-defined life-cycle model), ALC_TAT.1 (well-defined development tools)
**Document version :** 1.0

---

## 1. CM scope (ALC_CMS.4)

The configuration items under management are :

| Category                      | Item(s)                                                | Storage              |
|-------------------------------|--------------------------------------------------------|----------------------|
| Source code                   | `include/`, `src/`, `src/dispatch/`, `src/gen/`, `kat/`, `tests/` | Git monorepo |
| Build infrastructure          | `Makefile`, `Dockerfile.build`, `scripts/*.sh`         | Git monorepo         |
| Source-of-truth generator     | `scripts/gen_p11_thunks.py`                            | Git monorepo         |
| Test vectors                  | `kat/cavp/*.rsp`, `kat/fhsm_kat_vectors.c`             | Git monorepo         |
| Documentation                 | `docs/*.md`                                            | Git monorepo         |
| Build artefacts (released)    | `libfreehsm-fips.so`, `freehsm-c-src.tar.xz`, `*.sha256` | Signed release bundle on the project's distribution server |
| Evaluation evidence           | `docs/{ATE_FUN,AVA_VAN,ALC_CMC,FIPS_140_3,EAL4_PLUS,ARCHITECTURE,MECHANISMS,REPRODUCIBLE_BUILD}.md` | Git monorepo |
| Issue tracker                 | label-managed by `evaluation/*` namespace              | Forge issue tracker  |
| Security advisories           | `SECURITY.md` + CVE numbers                            | Git monorepo + MITRE |

Every item lives in version control. Nothing relevant to the TOE identity is stored outside the Git monorepo, so the SHA-1 of `HEAD` after a release uniquely identifies the CM state.

## 2. CM capabilities (ALC_CMC.4)

### 2.1 Identification

The TOE identity is the triple :
```
(repo, commit_sha, tag)
```
where `tag` follows semantic versioning `vMAJOR.MINOR.PATCH` and matches `FHSM_VERSION_STRING` in `include/fhsm_common.h`. The version string is propagated into :

- The `.comment` ELF section of the `.so`
- The `-frandom-seed` linker flag (reproducible-build pinning)
- The source-archive prefix (`freehsm-c-1.0.0-FIPS/`)

### 2.2 Authorization controls

| Action | Required role | Enforcement                                   |
|--------|---------------|-----------------------------------------------|
| Push to `main`          | Maintainer | Branch protection : signed-commit-only ; PR review by ≥ 2 maintainers ; CI green |
| Tag release             | Release Manager | Tag must be GPG-signed by the listed release key |
| Publish release bundle  | Release Manager | Two-person rule : RM signs the tar, second maintainer signs the digest manifest |
| Modify `Dockerfile.build` apt pins | Build Engineer | Requires `dist-verify` CI pass + manual ATE rerun |
| Modify a CAVP vector    | Crypto Engineer | Requires cross-validation script `scripts/validate_cavp.py` to confirm with an independent implementation |

### 2.3 Automation

The CM is fully automated. Every push triggers :

1. `make generate` — refresh code-generated artifacts ; PR fails if the diff is non-empty (commit must include the regenerated files).
2. `make lint` — cppcheck + clang-tidy, both with `--error-exitcode=1`.
3. `make` — full build inside the pinned Docker image.
4. `make tests` — smoke + dispatch + CAVP runner.
5. `make dist-verify` — second build, byte-equality assertion.
6. `make integrity` — sign the .so ; verify the embedded digest matches the externally computed one.
7. `scripts/coverage.sh` — gcov + lcov ; fail if line coverage < 95 % or branch coverage < 90 %.

A release tag additionally triggers :

8. `make dist` — produce the signed source archive.
9. Distribution server upload via `scripts/release.sh` (uploads `.so`, `.so.sha256`, `.tar.xz`, `.tar.xz.sha256`, all GPG-signed by the release key).
10. Notification to the security mailing list of the new release digest.

## 3. Production support (ALC_CMC.4)

### 3.1 Build environment

The single source of truth for the build environment is `Dockerfile.build`. The reviewer is referred to `docs/REPRODUCIBLE_BUILD.md` for the full chain of trust. The pinned image digest is recorded in the release notes alongside the apt package versions.

### 3.2 Acceptance procedures

A produced `libfreehsm-fips.so` is **accepted into the release artefact set** only if **all** of the following are true :

1. `make all integrity tests dist-verify` exits 0 inside the pinned Docker image.
2. The embedded `fhsm_module_integrity_digest[]` matches the externally computed SHA-256 of the masked-section binary.
3. `readelf -p .comment libfreehsm-fips.so` reports the expected toolchain version.
4. `pwntools.checksec` reports : `RELRO=Full`, `NX=Yes`, `PIE=Yes`, `Canary=Yes`, `Stripped=No (debug separately)`.
5. Coverage thresholds met (§2.3 step 7).
6. AVA_VAN re-analysis triggers (`docs/AVA_VAN.md` §6) are clear OR an updated AVA_VAN.md is included in the release.

The acceptance evidence (CI run URL + signed digest manifest) is committed to `docs/releases/v<version>/acceptance.txt` and is part of the source archive.

## 4. Life-cycle model (ALC_LCD.1)

We use a documented, repeatable life-cycle :

```
       requirement   →   design    →   implementation   →   integration   →   release
            ↑                                                      |
            └───────────  flaw remediation (ALC_FLR.2)  ←──────────┘
```

Phases :

- **Requirement** : captured as Git issues labelled `phase/req`. SFRs are derived from the Protection Profile (when applicable) or from the Security Policy.
- **Design** : `docs/ARCHITECTURE.md` is the canonical design document. Changes to the modular decomposition require a PR + maintainer approval.
- **Implementation** : feature branches, PRs to `main`, CI green required.
- **Integration** : nightly build on `main` runs the full ATE suite. A red nightly halts further merges until green.
- **Release** : tagged commits trigger the release-tag automation. Release notes are auto-generated from labelled issues since the previous tag.
- **Flaw remediation** : `SECURITY.md` defines the disclosure procedure (90-day window, security@freehsm.example contact, GPG key fingerprint).

## 5. Tools (ALC_TAT.1)

| Tool                  | Pinned version    | Source                       |
|-----------------------|-------------------|------------------------------|
| GCC                   | 12.2.0-3          | Debian apt (pinned in Dockerfile.build) |
| binutils (incl. ld)   | 2.40-2            | Debian apt                   |
| libc6-dev (glibc)     | 2.36-9+deb12u4    | Debian apt                   |
| OpenSSL FIPS provider | 3.0.13 (CMVP cert TBD) | Built from source SHA-256-verified |
| Python                | 3.11.2            | Debian apt                   |
| cppcheck              | 2.10-2            | Debian apt                   |
| clang-tidy-14         | 1:14.0.6-12       | Debian apt                   |
| Docker buildx         | (host)            | host requirement            |
| diffoscope (optional) | (host)            | host requirement            |

Tool selection rationale : every tool listed produces deterministic output given the same input. We refuse tools with intrinsic randomness (e.g. PGO, LTO with random-stream merging, JIT-based linkers).

## 6. Delivery (ALC_DEL.1)

The release bundle is published at :

```
https://dist.freehsm.example/v<version>/
    libfreehsm-fips.so              # the cryptographic module
    libfreehsm-fips.so.sha256       # signed by release key
    freehsm-c-src.tar.xz            # reproducible source archive
    freehsm-c-src.tar.xz.sha256     # signed by release key
    RELEASE_NOTES.md                # human-readable summary
    ACCEPTANCE.txt                  # CI run URL + digest manifest
    Dockerfile.build.image-digest   # pinned base image digest
```

A customer / evaluator verifies :

1. Download all bundle files over HTTPS.
2. `gpg --verify libfreehsm-fips.so.sha256` against the published key fingerprint.
3. `sha256sum -c libfreehsm-fips.so.sha256` against the binary.
4. Optionally rebuild from source : `tar xf freehsm-c-src.tar.xz && cd freehsm-c-<version> && make dist-verify`. The produced digest MUST match.

## 7. Flaw remediation (ALC_FLR.2)

### 7.1 Reception

Security flaw reports are received at `security@freehsm.example` (GPG fingerprint published in `SECURITY.md`). A triage maintainer acknowledges within 72 hours.

### 7.2 Tracking

Every report is converted into a private issue with label `security/<severity>`. The issue links to the affected commit range, the proposed fix branch, and the disclosure schedule.

### 7.3 Distribution

Once a fix is merged :

1. A new patch release is tagged immediately.
2. Customers on the announce mailing list are notified.
3. After the 90-day window, the issue is made public and a CVE is requested if not already assigned.

### 7.4 Backport policy

Every supported branch (current major + previous major) receives every security fix within 14 days of public disclosure. The cut-off for "supported" branches is announced in the release notes one minor version in advance.

## 8. Re-certification triggers

The CMVP / CC certificates are tied to the exact source tree. Any of the following invalidates the certificate :

- Source code change outside documentation and test directories.
- Change to `Dockerfile.build` (toolchain bump).
- Change to `scripts/gen_p11_thunks.py` (mechanism database).
- Change to `include/fhsm_common.h::FHSM_VERSION_STRING`.

The release procedure refuses to publish under the same version string if any of these conditions occur ; a bump is mandatory.
