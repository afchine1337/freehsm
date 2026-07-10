#!/usr/bin/env bash
# ===========================================================================
# sign_module.sh --- Embed the integrity digest into libfreehsm-fips.so.
#
# Two-pass procedure (matches FIPS 140-3 §7.10.2 expectations) :
#
#   1. The .so is built with the .fhsm_digest section initialised to
#      zeros (cf. src/fhsm_integrity.c).
#   2. This script :
#        a. locates the .fhsm_digest section via `readelf -S`,
#        b. extracts its file offset and size (must be 32 bytes),
#        c. computes SHA-256 of the .so with that 32-byte slot zeroed
#           in a working copy (the file on disk is untouched),
#        d. patches the resulting digest into the original .so via
#           dd conv=notrunc.
#
# After patching, `fhsm_integrity_verify()` at boot re-runs the same
# masked SHA-256 and the comparison succeeds.
#
# Exit codes :
#   0  digest patched successfully
#   1  arg parse / file missing
#   2  .fhsm_digest section not found or wrong size
#   3  digest already present (would overwrite a signed build)
# ===========================================================================

set -euo pipefail

SO_PATH="${1:-libfreehsm-fips.so}"
FORCE="${2:-}"

if [ ! -f "${SO_PATH}" ]; then
    echo "sign_module: ${SO_PATH} not found" >&2
    exit 1
fi

command -v readelf >/dev/null || { echo "readelf not found" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "sha256sum not found" >&2; exit 1; }

# --- Locate the .fhsm_digest section --------------------------------------
# `readelf -S` columns : [Nr] Name Type Address Off Size ES Flg Lk Inf Al
sect_line=$(readelf -SW "${SO_PATH}" | awk '$2 == ".fhsm_digest" { print }')
if [ -z "${sect_line}" ]; then
    echo "sign_module: section .fhsm_digest not found in ${SO_PATH}" >&2
    echo "             rebuild with src/fhsm_integrity.c included." >&2
    exit 2
fi

# The columns for "Off" and "Size" are hex. Fields are :
#   index name type address off size ...
# readelf wraps long lines ; with -W (no wrap) we have one line per section.
sect_off_hex=$(awk '$2 == ".fhsm_digest" { print $5 }' <<<"$(readelf -SW "${SO_PATH}")")
sect_size_hex=$(awk '$2 == ".fhsm_digest" { print $6 }' <<<"$(readelf -SW "${SO_PATH}")")
sect_off=$((16#${sect_off_hex}))
sect_size=$((16#${sect_size_hex}))

if [ "${sect_size}" -lt 32 ]; then
    echo "sign_module: .fhsm_digest size ${sect_size} < 32, refusing" >&2
    exit 2
fi

echo "[sign_module] .fhsm_digest at offset 0x${sect_off_hex} size 0x${sect_size_hex} (${sect_size} bytes)"

# --- Refuse to overwrite a previously signed module unless --force ---------
current=$(python3 -c "print(open('${SO_PATH}','rb').read()[${sect_off}:${sect_off}+32].hex())")
if [ "${current}" != "0000000000000000000000000000000000000000000000000000000000000000" ] \
   && [ "${FORCE}" != "--force" ]; then
    echo "sign_module: ${SO_PATH} already signed (digest = ${current})." >&2
    echo "             Pass --force to overwrite (only for legitimate re-signing)." >&2
    exit 3
fi

# --- Compute SHA-256 of the .so with the digest area zeroed ----------------
tmp=$(mktemp --suffix=.so)
trap 'rm -f "${tmp}"' EXIT
cp "${SO_PATH}" "${tmp}"
dd if=/dev/zero of="${tmp}" bs=1 seek=${sect_off} count=32 conv=notrunc status=none

digest=$(sha256sum "${tmp}" | awk '{print $1}')
echo "[sign_module] computed digest = ${digest}"

# --- Patch the digest in place via dd --------------------------------------
python3 -c "open('${tmp}.dig','wb').write(bytes.fromhex('${digest}'))"
dd if="${tmp}.dig" of="${SO_PATH}" bs=1 seek=${sect_off} count=32 conv=notrunc status=none
rm -f "${tmp}.dig"

# --- Verify the patch ------------------------------------------------------
patched=$(python3 -c "print(open('${SO_PATH}','rb').read()[${sect_off}:${sect_off}+32].hex())")
if [ "${patched}" != "${digest}" ]; then
    echo "sign_module: post-patch read-back mismatch !" >&2
    exit 2
fi

echo "[sign_module] ${SO_PATH} signed with ${digest}"
echo "${digest}  ${SO_PATH}" > "${SO_PATH}.sha256"
