# Reproducible build --- FreeHSM C

This document describes how to reproduce the **bit-identical** `libfreehsm.so` shipped in a given release. Reproducibility is required by **CC EAL4+ ALC_CMC.4** ("production support, acceptance procedures, automation") and is the standard FIPS 140-3 lab expectation for binary-level conformance.

## 1. Quick verification

```bash
git clone https://github.com/freehsm/freehsm-c.git
cd freehsm-c
git checkout v1.0.0
make dist-verify
```

`dist-verify` performs two clean builds in the pinned Docker image and asserts that the SHA-256 of both `libfreehsm.so` artefacts is identical. Expected output :

```
[verify] run A digest : 4f9a3d2c...e15a8b04
[verify] run B digest : 4f9a3d2c...e15a8b04
[verify] OK : builds are bit-identical.
```

## 2. What is pinned

| Layer                   | Pinning mechanism                                |
|-------------------------|--------------------------------------------------|
| Base OS image           | `debian@sha256:b8084b1a...` (digest, not tag)    |
| Toolchain               | Exact `apt` versions (`gcc=4:12.2.0-3`, etc.)   |
| OpenSSL                 | Source tarball SHA-256 + version (`3.0.13`)     |
| `__DATE__` / `__TIME__` | `SOURCE_DATE_EPOCH=1735689600` + `-D` overrides  |
| Linker build-id         | `-Wl,--build-id=none`                            |
| Tar archive             | `--mtime=@SOURCE_DATE_EPOCH --sort=name --owner=root` |
| Hash table layout       | `-Wl,--hash-style=gnu`                           |
| ASLR-related metadata   | absent in PIC `.so` (no PIE base)                |
| Random gcc seeds        | `-frandom-seed=fhsm-1.0.0-FIPS`                  |
| Absolute paths          | `-ffile-prefix-map=$(CURDIR)=`                   |

## 3. Sources of nondeterminism eliminated

| Source                                  | Defense                                      |
|-----------------------------------------|----------------------------------------------|
| Compiler `__DATE__`, `__TIME__`         | `-D__DATE__='"redacted"' -D__TIME__='"redacted"'` |
| Compiler anonymous-namespace names      | `-frandom-seed=fhsm-<version>`               |
| Embedded source paths in DWARF / `__FILE__` | `-ffile-prefix-map`, `-fdebug-prefix-map`  |
| Linker `.note.gnu.build-id` (160 random bits) | `-Wl,--build-id=none`                  |
| Linker hash table ordering              | `-Wl,--hash-style=gnu --sort-common`         |
| `.comment` section (toolchain version)  | pinned by Docker image digest                |
| `ar` member timestamps in `.a`          | `SOURCE_DATE_EPOCH` honored by binutils 2.27+|
| Filesystem uid/gid in `tar`             | `--owner=root --group=root --numeric-owner`  |
| `tar` file ordering                     | `--sort=name`                                |
| `tar` PAX extended headers (atime/ctime/mtime) | `--pax-option=delete=atime,delete=ctime,delete=mtime` |
| Locale-dependent collation              | `LC_ALL=C` inside the image                  |

## 4. Manual reproduction (no Docker)

If your environment cannot run Docker (air-gapped lab), you can reproduce manually as long as you replicate the toolchain :

```bash
# Use the exact compiler & libc versions from Dockerfile.build
export SOURCE_DATE_EPOCH=1735689600
export LC_ALL=C TZ=UTC
make clean
make
sha256sum libfreehsm.so   # compare to the published digest
```

Any version drift in `gcc`, `binutils` or `libc6-dev` will cause the digest to differ. The `.comment` section of the produced ELF embeds the toolchain version string ; use `readelf -p .comment libfreehsm.so` to inspect.

## 5. CI integration

The reference CI runs the following on every push to `main` and on every release tag :

```yaml
# .github/workflows/repro.yml (excerpt)
jobs:
  reproducibility:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - name: Build A
        run: make repro && mv libfreehsm.so out/run-a.so
      - name: Build B (clean)
        run: docker volume prune -f && make repro
      - name: Assert byte-identical
        run: |
          a=$(sha256sum out/run-a.so | awk '{print $1}')
          b=$(sha256sum libfreehsm.so | awk '{print $1}')
          test "$a" = "$b" || { echo "REPRO FAIL"; exit 1; }
```

The CI uses `diffoscope` as a fallback when the digests diverge, surfacing the *exact* differing bytes in the artefact (section names, offsets, hex dump).

## 6. Bumping the build environment

Whenever a new release requires a toolchain update :

1. Update `ARG OPENSSL_VERSION` and `ARG OPENSSL_SHA256` in `Dockerfile.build`.
2. Update the apt version pins by hand, from a clean Debian container. A `scripts/freeze_apt_versions.sh` was named here to regenerate the list and does not exist; `scripts/build_reproducible.sh` and `scripts/verify_reproducibility.sh` do.
3. Bump `FHSM_VERSION_STRING` in `include/fhsm_common.h` — this propagates to `-frandom-seed` and to the source archive prefix.
4. Run `make dist-verify` locally to confirm reproducibility on the new toolchain.
5. Publish the new image digest and the resulting `libfreehsm.so` SHA-256 in the release notes.

## 7. Verification by an evaluator

For CMVP / CESTI evaluators :

1. Pull the published source archive : `freehsm-c-src.tar.xz` (and the sidecar `.sha256`).
2. Verify the archive digest matches the release notes.
3. Run `make dist-verify` ; the produced `libfreehsm.so` SHA-256 MUST match the one in the release notes and the one embedded in the signed `fhsm_module_integrity_digest[]` (see `docs/FIPS_140_3.md` §6.1).
4. Optionally, run the same on a second host (different distribution, different CPU vendor) to confirm the build is host-independent.

A successful match closes the **ALC_CMC.4** evidence requirement for the release.

## 8. First independent verification — v2.0.2, 2026-09-04

Until this date the procedure above had never been executed to completion by
anyone, including the maintainer: `make dist-verify` needs Docker, which the
development machine does not have, and the path carried four defects stacked
behind one another — a read-only mount that `make clean` wrote to, `out/`
inside that mount, `/out` not writable by the container's uid, and finally the
two sides hashing different artefacts (unsigned versus signed). Each was
invisible until the one before it was fixed. Three of the four were reported by
an external user following this document.

With those closed, **four independent environments produced the same bytes for
v2.0.2**:

| environment | digest |
|---|---|
| maintainer's development VM (Debian 13, OpenSSL 3.5.7) | `25b5051362eff…` |
| `.github/workflows/baseline.yml`, `ghcr.io/…/freehsm-c-build:debian13-openssl-3.5` | `25b5051362eff…` |
| `.github/workflows/dist-verify.yml`, image built from `Dockerfile.build` | `25b5051362eff…` |
| **an unaffiliated third party's machine**, issue #4 | `25b5051362eff…` |

and that digest is the SHA-256 of the published `libfreehsm.so` asset, recorded
at `dist/refs/v2.0.2.sha256`.

The fourth row is the one that matters. The first three share this repository's
assumptions; the fourth does not, and it is the row §7 step 4 asks an evaluator
to produce. It exists because someone outside the project ran the documented
instructions, reported what happened four times over two weeks, and kept going.

What this does **not** show: that the build is deterministic across
distributions or CPU vendors. All four are Debian 13 on x86-64. §7 step 4 is
therefore still open in its stronger form.
