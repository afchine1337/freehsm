#!/usr/bin/env bash
# ===========================================================================
# dist_verify_ref.sh --- Compare the locally built libfreehsm.so
# against the reference digest published for this release.
#
#  Workflow :
#    1. Producer runs `make dist-baseline VERSION=1.0.0` once at release
#       time. This builds twice in clean Docker, asserts byte-identical
#       output, then writes the digest to dist/refs/v1.0.0.sha256 and
#       commits/signs it.
#    2. Auditor runs `make dist-verify` (or this script) which :
#         (a) builds the .so locally in the pinned Docker
#         (b) checks the resulting digest against dist/refs/v<VERSION>.sha256
#         (c) refuses the build if the digest differs
#
#  Exit codes :
#    0 = digest matches reference
#    1 = build infrastructure failed
#    3 = digest differs from reference (release contamination)
#    4 = no reference for this version (run dist-baseline first)
# ===========================================================================

set -euo pipefail

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Same defect as dist_baseline.sh: the grep -oP required an `=` the header
# does not have, so this looked for a reference named "unknown".
# Defensive. The header carried a -FIPS suffix until v2.0.0, when it was
# dropped -- it named a certification the project does not hold and reached
# the soname and the tarball prefix. Stripping it costs nothing now and
# would matter again the day a suffix returns for a real reason.
VERSION="${VERSION:-$(awk -F'"' '/FHSM_VERSION_STRING/{print $2; exit}' "$PROJ_ROOT/include/fhsm_common.h" 2>/dev/null || echo unknown)}"
VERSION="${VERSION%-FIPS}"
REF_FILE="${PROJ_ROOT}/dist/refs/v${VERSION}.sha256"
# Not inside PROJ_ROOT : the reproducible build mounts it read-only and its
# `make clean` runs `rm -rf out/` (issue #4). One base, read the same way by
# build_reproducible.sh, verify_reproducibility.sh and dist_baseline.sh.
OUT_DIR="${FHSM_REPRO_OUT:-${TMPDIR:-/tmp}/freehsm-repro-out}"

if [ ! -f "$REF_FILE" ]; then
    echo "[verify-ref] FAIL : no reference digest at $REF_FILE"
    echo "[verify-ref]        With Docker here : make dist-baseline"
    echo "[verify-ref]        Without          : run the 'Reproducibility baseline'"
    echo "[verify-ref]                           workflow, which builds in the same"
    echo "[verify-ref]                           image the release uses, and commit"
    echo "[verify-ref]                           the file it uploads."
    exit 4
fi

ref_digest="$(awk '{print $1}' "$REF_FILE")"
echo "[verify-ref] reference v${VERSION} : ${ref_digest}"

# Use the same scripts/build_reproducible.sh path used by `make repro`.
echo "[verify-ref] building locally ..."
"${PROJ_ROOT}/scripts/build_reproducible.sh"

if [ ! -f "${OUT_DIR}/digest.txt" ]; then
    echo "[verify-ref] FAIL : build did not produce out/digest.txt"
    exit 1
fi

local_digest="$(awk '{print $1}' "${OUT_DIR}/digest.txt")"
echo "[verify-ref] local      : ${local_digest}"

if [ "${local_digest}" = "${ref_digest}" ]; then
    echo "[verify-ref] OK : bit-identical to release reference."
    exit 0
fi

echo "[verify-ref] FAIL : digest divergence."
echo "[verify-ref]   ref   = ${ref_digest}"
echo "[verify-ref]   local = ${local_digest}"
echo "[verify-ref] possible causes, likeliest first :"
# The old list opened with "source modification" and reached Docker layer
# corruption before mentioning the one thing that is true nearly every time.
# dist/refs/v${VERSION}.sha256 anchors exactly one commit -- the tagged one --
# so on any tree that has moved since, divergence is the correct answer and
# says nothing about reproducibility. That case was missing entirely, and the
# first CI run of this check hit it.
if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
    if git rev-parse -q --verify "refs/tags/v${VERSION}" >/dev/null 2>&1; then
        if [ "$(git rev-parse HEAD)" != "$(git rev-parse "v${VERSION}^{commit}")" ]; then
            echo "  - YOU ARE NOT ON THE TAGGED COMMIT. HEAD is $(git rev-parse --short HEAD),"
            echo "    v${VERSION} is $(git rev-parse --short "v${VERSION}^{commit}"). The reference"
            echo "    anchors the tag; anything else is expected to differ."
            echo "    Try :  git checkout v${VERSION} && make dist-verify"
        fi
        if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
            echo "  - the working tree has uncommitted changes"
        fi
    fi
fi
echo "  - source modification (intentional ? then update dist/refs/v${VERSION}.sha256)"
echo "  - toolchain drift (gcc version, glibc, OpenSSL changed without bumping VERSION)"
echo "  - the reference was produced by a different image. dist/refs/ is written"
echo "    by .github/workflows/baseline.yml, which builds in"
echo "    ghcr.io/<owner>/freehsm-c-build ; this script builds in the image from"
echo "    Dockerfile.build. Two toolchains, one number."
echo "  - Docker layer corruption (try : docker build --no-cache -f Dockerfile.build .)"
echo "  - timestamp leak (check SOURCE_DATE_EPOCH override and embedded mtimes)"
exit 3
