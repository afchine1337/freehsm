#!/usr/bin/env bash
# ===========================================================================
# dist_baseline.sh --- Establish the reference digest for a release.
#
#  Runs scripts/verify_reproducibility.sh (build twice, compare). If
#  successful, writes the digest to dist/refs/v<VERSION>.sha256.
#
#  This script is run ONCE per release, by the release manager, on a
#  trusted build machine. The resulting reference file is then committed
#  + signed (e.g. GPG sign-off) so auditors can verify their local
#  builds against the same digest later via `make dist-verify`.
# ===========================================================================

set -euo pipefail

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# The header writes `#define FHSM_VERSION_STRING  "1.6.0-FIPS"`, with no `=`.
# The grep -oP that used to be here required one, so it never matched and this
# script would have written its baseline as "unknown" -- under a name
# dist-verify does not look for.
# Defensive. The header carried a -FIPS suffix until v2.0.0, when it was
# dropped -- it named a certification the project does not hold and reached
# the soname and the tarball prefix. Stripping it costs nothing now and
# would matter again the day a suffix returns for a real reason.
VERSION="${VERSION:-$(awk -F'"' '/FHSM_VERSION_STRING/{print $2; exit}' "$PROJ_ROOT/include/fhsm_common.h" 2>/dev/null || echo unknown)}"
VERSION="${VERSION%-FIPS}"
REF_DIR="${PROJ_ROOT}/dist/refs"
REF_FILE="${REF_DIR}/v${VERSION}.sha256"

if [ -f "$REF_FILE" ]; then
    echo "[baseline] WARNING : reference already exists for v${VERSION} :"
    echo "[baseline]   $REF_FILE"
    echo "[baseline] Refusing to overwrite. Bump VERSION or rm the file first."
    exit 2
fi

echo "[baseline] establishing reference for v${VERSION}"
"${PROJ_ROOT}/scripts/verify_reproducibility.sh"

# At this point both runs produced the same digest ; just take one.
#
# Same base as verify_reproducibility.sh and build_reproducible.sh. It moved
# out of PROJ_ROOT because the container mounts PROJ_ROOT read-only and its
# `make clean` runs `rm -rf out/` (issue #4). Four scripts derived this path;
# this one and dist_verify_ref.sh kept the old value after the first two were
# fixed, which is the identical shape as the v2.0.0 slice where four places
# derived the reference filename three ways.
src_digest_file="${FHSM_REPRO_OUT:-${TMPDIR:-/tmp}/freehsm-repro-out}/run-a/digest.txt"
if [ ! -f "$src_digest_file" ]; then
    echo "[baseline] FAIL : verify_reproducibility didn't leave run-a/digest.txt"
    exit 1
fi

mkdir -p "$REF_DIR"
{
    awk '{print $1}' "$src_digest_file" | tr -d '\n'
    printf '  libfreehsm.so v%s\n' "$VERSION"
} > "$REF_FILE"
echo "[baseline] wrote $REF_FILE :"
cat "$REF_FILE"
echo ""
echo "[baseline] NEXT STEPS :"
echo "  - git add $REF_FILE"
echo "  - git commit -S -m 'release v${VERSION} : reference digest'"
echo "  - git tag -s v${VERSION} -m 'FreeHSM C v${VERSION}'"
