#!/usr/bin/env bash
# ===========================================================================
# build_reproducible.sh --- Build libfreehsm-fips.so in the pinned Docker
# image and write the result + its SHA-256 digest to ./out/.
#
# Exit codes :
#   0   build successful, digest written to out/digest.txt
#   1   Docker missing or build failed
#   2   digest mismatch against expected (when --expect=<sha256> passed)
#
# The script is intentionally a thin wrapper around docker so the build
# logic stays inside Dockerfile.build (single source of truth for the
# build environment).
# ===========================================================================

set -euo pipefail

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="freehsm-build:1.0.0"
OUT_DIR="${PROJ_ROOT}/out"
EXPECTED_DIGEST=""
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1735689600}"

usage() {
    cat <<EOF
Usage: $0 [--expect=<sha256>] [--source-date-epoch=<unix-ts>]
       $0 --shell    Open an interactive shell in the build image.

Environment :
  SOURCE_DATE_EPOCH   default 1735689600 (2025-01-01 00:00 UTC)

After a successful build, the artefacts land in :
  ${OUT_DIR}/libfreehsm-fips.so
  ${OUT_DIR}/digest.txt
EOF
}

for arg in "$@"; do
    case "$arg" in
        --expect=*)             EXPECTED_DIGEST="${arg#--expect=}";;
        --source-date-epoch=*)  SOURCE_DATE_EPOCH="${arg#--source-date-epoch=}";;
        --shell)                EXEC_SHELL=1;;
        -h|--help)              usage; exit 0;;
        *) echo "unknown arg: $arg"; usage; exit 1;;
    esac
done

command -v docker >/dev/null || { echo "docker not found"; exit 1; }

# --- Build the image if absent. The Dockerfile pins everything by
# digest/version, so a successful build is byte-identical across hosts. ---
if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "[repro] building image ${IMAGE} ..."
    docker buildx build \
        --build-arg SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
        --output type=docker \
        --tag "${IMAGE}" \
        --file "${PROJ_ROOT}/Dockerfile.build" \
        "${PROJ_ROOT}"
fi

# --- Open a shell on demand for interactive debug. ---
if [ "${EXEC_SHELL:-0}" = 1 ]; then
    exec docker run --rm -it \
        -v "${PROJ_ROOT}:/src" \
        -v "${OUT_DIR}:/out" \
        --entrypoint /bin/bash \
        "${IMAGE}"
fi

# --- Actual build. -------------------------------------------------------
mkdir -p "${OUT_DIR}"
rm -f  "${OUT_DIR}/libfreehsm-fips.so" "${OUT_DIR}/digest.txt"

docker run --rm \
    -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    -v "${PROJ_ROOT}:/src:ro" \
    -v "${OUT_DIR}:/out" \
    "${IMAGE}"

if [ ! -f "${OUT_DIR}/digest.txt" ]; then
    echo "[repro] FAIL: digest.txt not produced"
    exit 1
fi

actual="$(awk '{print $1}' "${OUT_DIR}/digest.txt")"
echo "[repro] actual digest : ${actual}"

if [ -n "${EXPECTED_DIGEST}" ]; then
    if [ "${actual}" != "${EXPECTED_DIGEST}" ]; then
        echo "[repro] FAIL: digest mismatch"
        echo "          expected ${EXPECTED_DIGEST}"
        echo "          got      ${actual}"
        exit 2
    fi
    echo "[repro] OK: digest matches expected"
fi
