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
VERSION="${VERSION:-$(grep -oP 'FHSM_VERSION_STRING\s*=\s*"\K[^"]+' "$PROJ_ROOT/include/fhsm_common.h" 2>/dev/null || echo unknown)}"
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
src_digest_file="${PROJ_ROOT}/out/run-a/digest.txt"
if [ ! -f "$src_digest_file" ]; then
    echo "[baseline] FAIL : verify_reproducibility didn't leave run-a/digest.txt"
    exit 1
fi

mkdir -p "$REF_DIR"
{
    awk '{print $1}' "$src_digest_file" | tr -d '\n'
    printf '  libfreehsm-fips.so v%s\n' "$VERSION"
} > "$REF_FILE"
echo "[baseline] wrote $REF_FILE :"
cat "$REF_FILE"
echo ""
echo "[baseline] NEXT STEPS :"
echo "  - git add $REF_FILE"
echo "  - git commit -S -m 'release v${VERSION} : reference digest'"
echo "  - git tag -s v${VERSION} -m 'FreeHSM C v${VERSION}'"
