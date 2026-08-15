#!/usr/bin/env bash
# ===========================================================================
# tests/wycheproof/fetch_vectors.sh
#
# Fetch Project Wycheproof test vectors at the reference recorded in
# VECTORS_SHA. The reference can be either :
#   - a 40-char hex commit SHA (most reproducible)
#   - a branch name like 'main' (bootstrap / convenience)
#   - a tag
#
# Output layout :
#   tests/wycheproof/vectors/<file>.json
#
# Re-runnable. Idempotent (re-downloads only if VECTORS_SHA changed).
# ===========================================================================

set -euo pipefail

WP_REPO="https://github.com/C2SP/wycheproof.git"
HERE="$(cd "$(dirname "$0")" && pwd)"
REF="$(grep -v '^#' "${HERE}/VECTORS_SHA" | tr -d '[:space:]')"
VECTORS_DIR="${HERE}/vectors"
STAMP="${VECTORS_DIR}/.fetched-sha"

if [[ -z "${REF}" ]]; then
    echo "ERROR : VECTORS_SHA is empty. Pin a commit SHA or branch before running." >&2
    exit 1
fi

# Detect : is REF a full commit SHA (40 hex chars), or a branch/tag ?
IS_SHA=0
if [[ "${REF}" =~ ^[0-9a-fA-F]{40}$ ]]; then
    IS_SHA=1
fi

# Skip if already at the right ref (only for pinned SHAs).
if [[ ${IS_SHA} -eq 1 ]] && [[ -f "${STAMP}" ]] && [[ "$(cat "${STAMP}")" == "${REF}" ]]; then
    echo "[wycheproof] vectors/ already at ${REF:0:12}, nothing to do."
    exit 0
fi

# Fresh sparse clone -- keeps the directory small (~15 MB).
rm -rf "${VECTORS_DIR}.tmp" "${VECTORS_DIR}"
mkdir -p "${VECTORS_DIR}.tmp"
cd "${VECTORS_DIR}.tmp"

echo "[wycheproof] cloning ${WP_REPO} @ ${REF}..."
git init -q
git remote add origin "${WP_REPO}"
git config core.sparseCheckout true
mkdir -p .git/info
cat > .git/info/sparse-checkout <<EOF
testvectors_v1/*.json
testvectors/*.json
EOF

if [[ ${IS_SHA} -eq 1 ]]; then
    # Pinned SHA : use depth=1 + explicit SHA fetch (requires the server
    # to have uploadpack.allowReachableSHA1InWant which github.com does).
    git -c protocol.version=2 fetch -q --depth=1 origin "${REF}"
    git checkout -q FETCH_HEAD
    RESOLVED_SHA="${REF}"
else
    # Branch or tag : fetch the ref, then resolve the SHA we got for the
    # stamp file. We still keep depth=1 to save bandwidth.
    git -c protocol.version=2 fetch -q --depth=1 origin "${REF}"
    git checkout -q FETCH_HEAD
    RESOLVED_SHA="$(git rev-parse HEAD)"
    echo "[wycheproof] resolved branch '${REF}' -> ${RESOLVED_SHA:0:12}"
fi

# Move the vector JSONs to the canonical location.
mkdir -p "${VECTORS_DIR}"
for d in testvectors_v1 testvectors ; do
    if [[ -d "$d" ]]; then
        cp -p "$d"/*.json "${VECTORS_DIR}/" 2>/dev/null || true
    fi
done

cd "${HERE}"
rm -rf "${VECTORS_DIR}.tmp"

echo "${RESOLVED_SHA}" > "${STAMP}"

N=$(ls -1 "${VECTORS_DIR}"/*.json 2>/dev/null | wc -l)
echo "[wycheproof] fetched ${N} vector files into ${VECTORS_DIR}/"

if [[ ${IS_SHA} -eq 0 ]]; then
    echo
    echo "[wycheproof] HINT : VECTORS_SHA points to branch '${REF}'."
    echo "             For maximum reproducibility, pin the SHA :"
    echo "             echo '${RESOLVED_SHA}' > ${HERE}/VECTORS_SHA"
fi
