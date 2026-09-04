#!/usr/bin/env bash
# ===========================================================================
# build_reproducible.sh --- Build libfreehsm.so in the pinned Docker
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
# Bumped 1.0.0 -> 1.1.0 with the Dockerfile entrypoint that builds in a
# writable copy instead of in the read-only /src mount (issue #4). The script
# only builds the image when it is absent, so anyone with the old one cached
# would have kept running the broken entrypoint and seen no change. The tag is
# the only thing that makes a fix to the image reach an existing checkout.
IMAGE="freehsm-build:1.1.0"
# The output directory must NOT live inside PROJ_ROOT.
#
# PROJ_ROOT is mounted at /src:ro and the container's build runs `make clean`,
# whose recipe ends with `rm -rf out/`. With out/ inside the source tree that
# is a write to a read-only mount, and the build dies before it starts:
#
#   rm: cannot remove 'out/run-a': Read-only file system
#   uid=2000(freehsm) gid=2000(freehsm)
#
# Reported by an external user following AGD_PRE (issue #4, 2026-07-20). It
# survived because this path needs Docker, which the maintainer's dev VM does
# not have -- the same absence that left dist/refs/ empty through six releases
# and is why .github/workflows/baseline.yml exists. A documented step nobody
# on the project could execute.
OUT_DIR="${FHSM_REPRO_OUT:-${TMPDIR:-/tmp}/freehsm-repro-out}"
EXPECTED_DIGEST=""
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1735689600}"

usage() {
    cat <<EOF
Usage: $0 [--expect=<sha256>] [--source-date-epoch=<unix-ts>]
       $0 --shell    Open an interactive shell in the build image.

Environment :
  SOURCE_DATE_EPOCH   default 1735689600 (2025-01-01 00:00 UTC)

After a successful build, the artefacts land in :
  ${OUT_DIR}/libfreehsm.so
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
# The container runs as uid 2000 (freehsm), fixed in the image so that file
# ownership inside `make dist` archives is stable. /out is a host directory
# created here by whoever ran this script -- a different uid, mode 0755. The
# container could not write its own output:
#
#   /bin/bash: line 1: /out/digest.txt: Permission denied
#
# Reported on issue #4 after the read-only-mount fix let the build get that
# far. Third distinct failure on the same path, each hidden behind the last.
#
# 0777 rather than chown: this is a scratch directory under $TMPDIR holding a
# .so and a digest for the duration of one build, the script owns its whole
# lifecycle, and requiring root to run a reproducibility check would put the
# check further out of reach than it already is.
mkdir -p "${OUT_DIR}"
chmod 0777 "${OUT_DIR}"
rm -f  "${OUT_DIR}/libfreehsm.so" "${OUT_DIR}/digest.txt"

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
