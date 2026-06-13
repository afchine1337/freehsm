# FreeHSM C v1.1.2 — Release notes

**Date** : 2026-06-13
**Tagger** : Afchine Madjlessi `<afchine.mad@gmail.com>`
**Signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2` (Ed25519)
**License** : Apache-2.0
**Project** : https://github.com/afchine1337/freehsm-c

The "container-based reproducible build" release. Tagged releases are
now produced inside the pinned image `freehsm-c-build:debian13-openssl-3.5`
on GitHub Container Registry, restoring the reproducibility claims that
the FIPS 140-3 / CC EAL4+ submission stream requires.

---

## What changed since v1.1.1

| Area | Change |
|---|---|
| Build environment | `release.yml` runs every step inside `ghcr.io/<owner>/freehsm-c-build:debian13-openssl-3.5` (built from `Dockerfile.build`) instead of `ubuntu-latest` with inline `apt-get install`. |
| Docker base | `Dockerfile.build` migrated from a non-existent Debian 12.5 sha256 digest to **Debian 13 trixie** with Debian-packaged OpenSSL 3.5.x. |
| Image publishing | New workflow `build-image.yml` publishes the image to GHCR on `Dockerfile.build` change or on manual dispatch. |
| Artefact hashing | `.sha256` files contain basename-only paths, so `sha256sum -c file.tar.xz.sha256` works from any directory. |

No functional change to the cryptographic module. PKCS#11 v3.2 ABI, FIPS
strict / legacy modes, the DRBG pipeline and every mechanism handler
are byte-for-byte identical to v1.1.1 (modulo build environment).

## Verifying this release

```bash
# Import the maintainer public key (one-shot)
curl -fsSL https://github.com/afchine1337/freehsm-c/raw/main/afchine-pubkey.asc | gpg --import

# Download tarball + signature + checksum
wget https://github.com/afchine1337/freehsm-c/releases/download/v1.1.2/freehsm-c-v1.1.2-src.tar.xz
wget https://github.com/afchine1337/freehsm-c/releases/download/v1.1.2/freehsm-c-v1.1.2-src.tar.xz.asc
wget https://github.com/afchine1337/freehsm-c/releases/download/v1.1.2/freehsm-c-v1.1.2-src.tar.xz.sha256

# Verify the GPG signature
gpg --verify freehsm-c-v1.1.2-src.tar.xz.asc
# Expected : Good signature from "Afchine Madjlessi <afchine.mad@gmail.com>"

# Verify the sha256 (now works out of the box -- basename-only paths)
sha256sum -c freehsm-c-v1.1.2-src.tar.xz.sha256
# Expected : freehsm-c-v1.1.2-src.tar.xz: OK

# Verify the tag
git clone https://github.com/afchine1337/freehsm-c.git
cd freehsm-c
git tag --verify v1.1.2
# Expected : Good signature, EDDSA key 743A6A5904A1461A646408DE48560162DBBF28A2
```

## Reproducing the binary locally

```bash
# Pull the same image used by the release pipeline
docker pull ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5

# Build inside the container with the same SOURCE_DATE_EPOCH
docker run --rm \
    -v "$PWD":/src:ro \
    -v "$PWD/out":/out \
    -e SOURCE_DATE_EPOCH=1717977600 \
    ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5

# Compare the digest with the one published in the release
sha256sum out/libfreehsm-fips.so
diff out/libfreehsm-fips.so.sha256 \
     <(curl -fsSL https://github.com/afchine1337/freehsm-c/releases/download/v1.1.2/libfreehsm-fips.so.sha256)
```

## Compatibility

- ABI : unchanged since v1.1.0 — drop-in replacement.
- PKCS#11 v3.2 surface : identical.
- File formats (`.tok`, `.tok.tpm`, audit log) : identical.

## Known limitations

- The Debian 13 base image is currently pulled by tag (`debian:trixie-slim`),
  not by digest. Production / FIPS submission images **MUST** pin the
  digest and freeze apt versions. Tracked for v2.0 (see
  `docs/REPRODUCIBLE_BUILD.md` for the upgrade plan).

---

— Afchine Madjlessi
