#!/usr/bin/env bash
# ===========================================================================
# tests/wycheproof/fetch_vectors.sh
#
# Fetch Project Wycheproof test vectors at the pinned commit recorded in
# VECTORS_SHA. The download is sparse-checkout limited to the testvectors_v1/
# subtree to avoid pulling the entire ~150 MB upstream repo.
#
# Output layout :
#   tests/wycheproof/vectors/<file>.json
#
# Re-runnable. Idempotent (re-downloads only if VECTORS_SHA changed).
# ===========================================================================

set -euo pipefail

WP_REPO="https://github.com/C2SP/wycheproof.git"
HERE="$(cd "$(dirname "$0")" && pwd)"
PIN="$(grep -v '^#' "${HERE}/VECTORS_SHA" | tr -d '[:space:]')"
VECTORS_DIR="${HERE}/vectors"
STAMP="${VECTORS_DIR}/.fetched-sha"

if [[ -z "${PIN}" ]]; then
    echo "ERROR : VECTORS_SHA is empty. Pin a commit SHA before running." >&2
    exit 1
fi

# Skip if already at the right SHA.
if [[ -f "${STAMP}" ]] && [[ "$(cat "${STAMP}")" == "${PIN}" ]]; then
    echo "[wycheproof] vectors/ already at ${PIN:0:12}, nothing to do."
    exit 0
fi

# Fresh sparse clone -- keeps the directory small (~15 MB).
rm -rf "${VECTORS_DIR}.tmp" "${VECTORS_DIR}"
mkdir -p "${VECTORS_DIR}.tmp"
cd "${VECTORS_DIR}.tmp"

echo "[wycheproof] cloning ${WP_REPO} @ ${PIN:0:12}..."
git init -q
git remote add origin "${WP_REPO}"
git -c protocol.version=2 fetch -q --depth=1 origin "${PIN}"
git config core.sparseCheckout true
mkdir -p .git/info
cat > .git/info/sparse-checkout <<EOF
testvectors_v1/*.json
testvectors/*.json
EOF
git checkout -q FETCH_HEAD || true

# Move the vector JSONs to the canonical location.
mkdir -p "${VECTORS_DIR}"
for d in testvectors_v1 testvectors ; do
    if [[ -d "$d" ]]; then
        cp -p "$d"/*.json "${VECTORS_DIR}/" 2>/dev/null || true
    fi
done

cd "${HERE}"
rm -rf "${VECTORS_DIR}.tmp"

echo "${PIN}" > "${STAMP}"

N=$(ls -1 "${VECTORS_DIR}"/*.json 2>/dev/null | wc -l)
echo "[wycheproof] fetched ${N} vector files into ${VECTORS_DIR}/"
