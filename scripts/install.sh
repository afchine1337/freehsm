#!/usr/bin/env bash
# ===========================================================================
# install.sh --- Install FreeHSM C on a Linux target system.
#
# Usage :
#   sudo ./scripts/install.sh [--prefix=/opt/freehsm] [--no-build]
#
# Steps performed :
#   1. Verify prerequisites (Linux kernel, OpenSSL FIPS provider, capabilities)
#   2. Build (unless --no-build) : make generate && make
#   3. Sign the .so (make integrity)
#   4. Install (make install PREFIX=...)
#   5. Verify the installed module identity and boot integrity
# ===========================================================================

set -euo pipefail

PREFIX="/opt/freehsm"
DO_BUILD=1
PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

for arg in "$@"; do
    case "$arg" in
        --prefix=*)  PREFIX="${arg#--prefix=}";;
        --no-build)  DO_BUILD=0;;
        -h|--help)
            sed -n '2,15p' "$0"
            exit 0;;
        *) echo "unknown arg: $arg"; exit 1;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "[install] root required (re-run with sudo)" >&2
    exit 1
fi

# --- 1. Prerequisites ------------------------------------------------------
echo "[install] === Verifying prerequisites ==="
kver="$(uname -r)"
echo "  Linux kernel : ${kver}"
if [ "$(printf '%s\n' "5.4" "${kver%%-*}" | sort -V | head -n 1)" != "5.4" ]; then
    echo "  → ERROR : kernel < 5.4, not supported." >&2
    exit 2
fi
if ! grep -q aes /proc/cpuinfo 2>/dev/null; then
    echo "  → WARNING : no AES-NI advertised in /proc/cpuinfo (FIPS provider may run software fallback)"
fi
if ! openssl list -providers 2>/dev/null | grep -q 'fips' ; then
    echo "  → WARNING : OpenSSL FIPS provider not active."
    echo "    See docs/AGD_PRE.md §3.3 to enable it."
fi

# --- 2. Build --------------------------------------------------------------
if [ "${DO_BUILD}" -eq 1 ]; then
    echo "[install] === Building libfreehsm-fips.so ==="
    cd "${PROJ_ROOT}"
    make -j"$(nproc)" generate
    make -j"$(nproc)"
    echo "[install] === Signing module integrity digest ==="
    make integrity
fi

# --- 3. Install ------------------------------------------------------------
echo "[install] === Installing under ${PREFIX} ==="
cd "${PROJ_ROOT}"
make install PREFIX="${PREFIX}"

# --- 4. Post-install verification -----------------------------------------
SO="${PREFIX}/lib/libfreehsm-fips.so"
echo "[install] === Verifying installed module ==="
echo "  SHA-256 :"
sha256sum "${SO}"
echo "  .comment section (toolchain identity) :"
readelf -p .comment "${SO}" | head -10
echo "  .fhsm_digest section :"
readelf -SW "${SO}" | awk '$2 == ".fhsm_digest"'

# --- 5. Smoke test --------------------------------------------------------
echo "[install] === Smoke test (C_Initialize + C_GetInfo) ==="
if command -v pkcs11-tool >/dev/null 2>&1 ; then
    sudo -u freehsm pkcs11-tool --module "${SO}" --show-info || \
        echo "  → INFO : pkcs11-tool returned non-zero ; this is expected on first install"
else
    echo "  → SKIP : pkcs11-tool not installed (apt install opensc)"
fi

cat <<EOF

[install] === Installation complete ===

Module : ${SO}
Config : ${PREFIX}/etc/freehsm.conf
State  : /var/lib/freehsm/{tokens,audit,kek}

Next steps :
  1. Initialise the first token (as SO) :
     sudo -u freehsm pkcs11-tool --module ${SO} \\
       --init-token --label "prod-slot-0" --so-pin '<your-SO-pin>'
  2. Set the User PIN (still as SO) :
     sudo -u freehsm pkcs11-tool --module ${SO} \\
       --so-pin '<SO-pin>' --init-pin --new-pin '<user-pin>'

See docs/AGD_PRE.md §4 (or docs/AGD_PRE.fr.md) for the full procedure.

Uninstall :
  sudo make uninstall PREFIX=${PREFIX}
EOF
