# FreeHSM C v1.1.1 — Release notes

**Date** : 2026-06-13
**Tagger** : Afchine Madjlessi `<afchine.mad@gmail.com>`
**Signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2` (Ed25519)
**License** : Apache-2.0
**Project** : https://github.com/afchine1337/freehsm-c

The "OSS-ready" release. No functional change to the cryptographic
module ; this version finalises the open-source publication pipeline and
recovers from a maintainer GPG private-key leak.

---

## Highlights

- **REUSE 3.3 compliant** — every one of the 123 source files now carries
  an SPDX header or is annotated via `REUSE.toml`. Verify with
  `reuse lint`.
- **OpenSSF Best Practices** project **ID 13190** — pre-filled
  questionnaire in `docs/OPENSSF_BEST_PRACTICES.md`. Badge live in the
  README.
- **Five status badges** in the README : License, REUSE, OpenSSF
  Best Practices, CI, Mirror.
- **Three public mirrors** with automatic propagation : GitHub +
  GitLab + Codeberg.
- **Signed releases** via GitHub Actions : `release.yml` builds the
  module, produces source + binary tarballs, GPG-signs each artefact
  with the release key stored in GitHub Secrets, and publishes the
  GitHub Release.
- **English README by default**, French moved to `README.fr.md`
  (matches the existing `docs/` convention).
- **GPG signing key rotated** after the v1.1.0 leak incident
  (cf. SECURITY section below).

## Behavioural changes

None for runtime users. The cryptographic perimeter, the PKCS#11 v3.2
ABI, the FIPS-strict and legacy modes, the DRBG pipeline and every
mechanism handler are byte-for-byte identical to v1.1.0. The diff
against v1.1.0 only touches :

- Documentation and metadata (`README*`, `CHANGELOG.md`,
  `LICENSES/`, `REUSE.toml`, `SECURITY.md`)
- CI/CD workflows (`.github/workflows/mirror.yml`,
  `release.yml`, `build-image.yml`)
- Two leftover license cartouches in `include/fhsm_common.h` and
  `scripts/gen_p11_thunks.py`

## Security advisory — GPG signing key rotation

The previous maintainer signing key
`B79726CB087375CF990E00E4A0BC5BB2FB1EE342` (Ed25519) was **compromised**
on 2026-06-12 : its ASCII-armored private export was accidentally
committed to the public repository in commit `922c6f7` (the initial
v1.0.0 open-source release).

Mitigations completed on 2026-06-12 :

| Step | Status |
|---|---|
| Revocation certificate generated (KEY_COMPROMISED) and published on `keys.openpgp.org`, `keyserver.ubuntu.com` | ✅ |
| New release signing key `743A6A5904A1461A646408DE48560162DBBF28A2` generated and published on the same keyservers | ✅ |
| Git history rewritten with `git filter-repo --invert-paths --path afchine-secret-BACKUP.asc` on GitHub, GitLab and Codeberg | ✅ |
| `v1.1.0` release tag re-signed with the new key | ✅ |
| `SECURITY.md` updated with the public disclosure | ✅ |

**Action required** : anyone who cloned `freehsm-c` between 2026-06-12
morning and 2026-06-12 evening **must re-clone** to drop the leaked
file from `.git/objects/`.

```bash
rm -rf freehsm-c
git clone git@github.com:afchine1337/freehsm-c.git
```

If you previously verified the `v1.1.0` tag, re-verify it with the new
key — the signature has changed.

## Verifying this release

```bash
# Import the maintainer public key
curl -fsSL https://github.com/afchine1337/freehsm-c/raw/main/afchine-pubkey.asc | gpg --import

# Or fetch from a keyserver
gpg --keyserver hkps://keys.openpgp.org --recv-keys 743A6A5904A1461A646408DE48560162DBBF28A2

# Verify the source tarball
wget https://github.com/afchine1337/freehsm-c/releases/download/v1.1.1/freehsm-c-v1.1.1-src.tar.xz
wget https://github.com/afchine1337/freehsm-c/releases/download/v1.1.1/freehsm-c-v1.1.1-src.tar.xz.asc
gpg --verify freehsm-c-v1.1.1-src.tar.xz.asc
# Expected : Good signature from "Afchine Madjlessi <afchine.mad@gmail.com>"

# Verify the tag
git clone https://github.com/afchine1337/freehsm-c.git
cd freehsm-c
git tag --verify v1.1.1
# Expected : Good signature, EDDSA key 743A6A5904A1461A646408DE48560162DBBF28A2
```

## Compatibility

- ABI : unchanged since v1.1.0 — drop-in replacement, no recompile of
  callers needed.
- PKCS#11 v3.2 surface : identical to v1.1.0.
- File formats (`.tok`, `.tok.tpm`, audit log) : identical to v1.1.0.

## Known limitations carried from v1.1.0

- The CI build runs on `ubuntu-latest` (not the pinned Docker image),
  so production reproducibility claims under FIPS 140-3 / CC EAL4+
  still require running the build inside the image produced by
  `Dockerfile.build`. The `build-image.yml` workflow can publish that
  image to `ghcr.io` on demand ; release.yml will reactivate the
  `container:` directive once the image is live.

## Acknowledgements

Thanks to the OpenSSF Best Practices reviewers and the REUSE.software
infrastructure for the public conformance checks. Apologies to the
community for the v1.1.0 key leak ; the incident is fully documented
in `SECURITY.md`.

---

— Afchine Madjlessi
