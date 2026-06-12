#!/usr/bin/env bash
# ===========================================================================
# dist_verify_ref.sh --- Compare the locally built libfreehsm-fips.so
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
VERSION="${VERSION:-$(grep -oP 'FHSM_VERSION_STRING\s*=\s*"\K[^"]+' "$PROJ_ROOT/include/fhsm_common.h" 2>/dev/null || echo unknown)}"
REF_FILE="${PROJ_ROOT}/dist/refs/v${VERSION}.sha256"
OUT_DIR="${PROJ_ROOT}/out"

if [ ! -f "$REF_FILE" ]; then
    echo "[verify-ref] FAIL : no reference digest at $REF_FILE"
    echo "[verify-ref]        Run 'make dist-baseline' on the release machine first."
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
echo "[verify-ref] possible causes :"
echo "  - source modification (intentional ? then update dist/refs/v${VERSION}.sha256)"
echo "  - toolchain drift (gcc version, glibc, OpenSSL changed without bumping VERSION)"
echo "  - Docker layer corruption (try : docker build --no-cache -f Dockerfile.build .)"
echo "  - timestamp leak (check SOURCE_DATE_EPOCH override and embedded mtimes)"
exit 3
