#!/usr/bin/env bash
# ===========================================================================
# verify_reproducibility.sh --- Build twice in clean Docker volumes and
# confirm both .so artefacts have the same SHA-256. Optionally diffoscope
# them to print the *exact* difference if reproducibility breaks (useful
# during toolchain bumps).
#
# Exit codes :
#   0  both builds produced the same digest
#   1  Docker missing or build failed
#   3  digests differ (reproducibility regression -- investigate diffoscope output)
# ===========================================================================

set -euo pipefail

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Outside PROJ_ROOT, for the reason spelled out in build_reproducible.sh:
# PROJ_ROOT is mounted read-only in the container, and its `make clean` runs
# `rm -rf out/`. These two directories, created here before either build, were
# precisely what that rm tripped over (issue #4).
REPRO_BASE="${FHSM_REPRO_OUT:-${TMPDIR:-/tmp}/freehsm-repro-out}"
OUT_A="${REPRO_BASE}/run-a"
OUT_B="${REPRO_BASE}/run-b"
DIFFOSCOPE="${DIFFOSCOPE:-diffoscope}"  # optional; install via apt if missing

command -v docker >/dev/null || { echo "docker not found"; exit 1; }

echo "[verify] === run A ==="
rm -rf "${OUT_A}" "${OUT_B}"
mkdir -p "${OUT_A}" "${OUT_B}"

FHSM_REPRO_OUT="${REPRO_BASE}" "${PROJ_ROOT}/scripts/build_reproducible.sh"
mv "${REPRO_BASE}/libfreehsm.so" "${OUT_A}/"
mv "${REPRO_BASE}/digest.txt"    "${OUT_A}/"

echo "[verify] === run B (clean) ==="
docker volume prune -f >/dev/null 2>&1 || true
FHSM_REPRO_OUT="${REPRO_BASE}" "${PROJ_ROOT}/scripts/build_reproducible.sh"
mv "${REPRO_BASE}/libfreehsm.so" "${OUT_B}/"
mv "${REPRO_BASE}/digest.txt"    "${OUT_B}/"

dig_a="$(awk '{print $1}' "${OUT_A}/digest.txt")"
dig_b="$(awk '{print $1}' "${OUT_B}/digest.txt")"
echo "[verify] run A digest : ${dig_a}"
echo "[verify] run B digest : ${dig_b}"

if [ "${dig_a}" = "${dig_b}" ]; then
    echo "[verify] OK : builds are bit-identical."
    exit 0
fi

echo "[verify] FAIL : digests differ. Comparing with diffoscope ..."
if command -v "${DIFFOSCOPE}" >/dev/null 2>&1; then
    "${DIFFOSCOPE}" --max-page-diff-block-lines 50 \
                     "${OUT_A}/libfreehsm.so" \
                     "${OUT_B}/libfreehsm.so" \
                     || true
else
    echo "[verify] diffoscope unavailable ; falling back to objdump diff."
    diff -u <(objdump -h "${OUT_A}/libfreehsm.so") \
            <(objdump -h "${OUT_B}/libfreehsm.so") || true
fi
exit 3
