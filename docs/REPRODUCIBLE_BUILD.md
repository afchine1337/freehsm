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
| `.comment` section (toolchain version)  | base-image digest and apt snapshot (§6)      |
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

Three workflows touch reproducibility, and they are meant to agree:

| workflow | builds in | does |
|---|---|---|
| `baseline.yml` (on demand) | `ghcr.io/…/freehsm-c-build:debian13-<snapshot date>` | builds and signs twice, refuses if the two differ, and gives `dist/refs/vX.Y.Z.sha256` to commit |
| `release.yml` (on a tag) | the same image | refuses to publish a build that does not match `dist/refs/` |
| `dist-verify.yml` (on a tag, or on demand) | an image built afresh from `Dockerfile.build` | `make dist-verify`: the outsider's path, compared with `dist/refs/` |

The ghcr image is itself built from `Dockerfile.build` (`build-image.yml`,
whenever that file changes on `main`). The first two rows therefore measure the
release image; the third measures whether someone else, starting from the
repository alone, gets the same bytes.

From v2.2.0 to v2.3.1 it did not: `dist-verify` failed on every tag while
`release.yml` passed. `Dockerfile.build` named `debian:trixie-slim` by tag and
installed whatever apt offered that day, so the ghcr image kept the toolchain
of the day it was built — later rebuilds came from the Actions layer cache —
and every fresh build moved on with Debian's point releases. The published
binaries matched their references throughout; an independent rebuild could
not have. Pinned on 2026-10-14, for v2.4.0 (§6).

## 6. Bumping the build environment

`Dockerfile.build` fixes the toolchain by two pins, and nothing else should
move it:

- the base image, `debian:trixie-YYYYMMDD-slim@sha256:…` — the multi-arch
  index digest of a dated tag, read from Docker Hub;
- `ARG SNAPSHOT`, a `snapshot.debian.org` timestamp: apt reads the archive as
  it was at that instant, so every package version follows from it.

To move them, for a toolchain or OpenSSL update:

1. Pick a dated `trixie-*-slim` tag and its index digest, and a `SNAPSHOT` at
   or after that date. Change both in `Dockerfile.build` in one commit.
2. Merging to `main` rebuilds the ghcr image (`build-image.yml`). Check that
   CI is green on it.
3. Bump the version: a new toolchain gives new bytes, and a reference belongs
   to one version.
4. Run `baseline.yml`, commit the reference, then run `dist-verify.yml` with
   `target: head` on that commit: it must now agree with the reference before
   the tag is made, not after.
5. State the new pins in the release notes.

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
