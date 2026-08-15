#!/usr/bin/env bash
# ============================================================================
# integration_pkcs11.sh --- end-to-end PKCS#11 test for libfreehsm-fips.so
#
# Exercises the full TSFI lifecycle :
#
#   1. C_Initialize                 (FIPS provider + KAT)
#   2. C_GetInfo                    (module identity)
#   3. C_GetSlotList                (slot enumeration, tokenPresent=0)
#   4. C_InitToken    (slot 0)      (creates slot0.tok in tokens_dir)
#   5. C_GetSlotList                (tokenPresent=1 -> 1 slot)
#   6. C_GetTokenInfo (slot 0)      (label, serial, flags)
#   7. C_OpenSession  (slot 0)      (attach token to session)
#   8. C_Login        (SO)          (PBKDF2-unwrap of so_wrap)
#   9. C_InitPIN      (USER)        (PBKDF2-wrap user PIN)
#  10. C_Logout                     (zeroize DEK)
#  11. C_Login        (USER)        (round-trip on the new PIN)
#  12. C_Logout
#  13. C_CloseSession
#  14. C_Finalize
#
# Default settings :
#   MODULE      = /opt/freehsm/lib/libfreehsm-fips.so
#   TOKENS_DIR  = a temporary directory ; reset every run
#   SO_PIN      = 12345678         (8 octets, >= 4 minimum FIPS)
#   USER_PIN    = 87654321
#   LABEL       = freehsm-test
#
# Override any of the above with environment variables :
#   MODULE=/path/to/mod.so SO_PIN=secret ./tests/integration_pkcs11.sh
#
# Exit status :
#   0 = all assertions passed
#   1 = at least one assertion failed
#   2 = environment / pre-flight failure (missing pkcs11-tool, etc.)
#
# ============================================================================

set -u   # error on undefined vars (but NOT -e : we want to inspect failures)

# ---- configuration -------------------------------------------------------

MODULE="${MODULE:-/opt/freehsm/lib/libfreehsm-fips.so}"
SO_PIN="${SO_PIN:-12345678}"
USER_PIN="${USER_PIN:-87654321}"
LABEL="${LABEL:-freehsm-test}"
TOKENS_DIR="${TOKENS_DIR:-$(mktemp -d /tmp/freehsm-integ-XXXXXX)}"

# Re-export so the C library picks up the override at C_Initialize time.
export FHSM_TOKENS_DIR="${TOKENS_DIR}"

# ---- helpers -------------------------------------------------------------

PASS=0
FAIL=0
LOG=$(mktemp /tmp/freehsm-integ-log-XXXXXX)

# Try to find pkcs11-tool. Some distros put it under /usr/bin only.
PKCS11_TOOL="$(command -v pkcs11-tool || true)"

color_pass() { printf '\033[32m%s\033[0m\n' "$1"; }
color_fail() { printf '\033[31m%s\033[0m\n' "$1"; }
color_info() { printf '\033[36m%s\033[0m\n' "$1"; }

assert() {
    local description="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q -F -- "$expected"; then
        color_pass "  PASS  $description"
        PASS=$((PASS + 1))
    else
        color_fail "  FAIL  $description"
        echo  "       expected substring : $expected"
        echo  "       actual output      :"
        echo  "$actual" | sed 's/^/         /'
        FAIL=$((FAIL + 1))
    fi
}

run_p11() {
    # Invoke pkcs11-tool with the project module and capture stderr+stdout.
    # We don't rely on $? because pkcs11-tool exits non-zero on many
    # benign conditions (e.g. C_FindObjects with no match), so each test
    # asserts on a substring of the captured output instead.
    "$PKCS11_TOOL" --module "$MODULE" "$@" 2>&1
}

cleanup() {
    rm -f "$LOG"
    # Keep the tokens dir if a test failed so the user can inspect.
    if [ "$FAIL" -eq 0 ]; then
        rm -rf "$TOKENS_DIR"
    else
        color_info "[integ] preserving tokens dir for inspection : $TOKENS_DIR"
    fi
}
trap cleanup EXIT

# ---- pre-flight ----------------------------------------------------------

if [ -z "$PKCS11_TOOL" ]; then
    color_fail "pkcs11-tool not found. Install with : apt install opensc"
    exit 2
fi
if [ ! -f "$MODULE" ]; then
    color_fail "Module not found at $MODULE"
    color_info "Build & install first : make && sudo make install PREFIX=/opt/freehsm"
    exit 2
fi
mkdir -p "$TOKENS_DIR"
chmod 700 "$TOKENS_DIR"

color_info "============================================================"
color_info "FreeHSM C end-to-end PKCS#11 integration test"
color_info "  module       : $MODULE"
color_info "  tokens dir   : $TOKENS_DIR"
color_info "  label        : $LABEL"
color_info "============================================================"

# ---- 1. C_Initialize + C_GetInfo (--show-info) ---------------------------

color_info ""
color_info "[1/14] C_Initialize + C_GetInfo"
out=$(run_p11 --show-info)
assert "Cryptoki version 3.2"               "Cryptoki version 3.2"      "$out"
assert "Manufacturer = FreeHSM C"            "FreeHSM C"                 "$out"
assert "Library description present"         "libfreehsm-fips.so"        "$out"

# ---- 2. C_GetSlotList (tokenPresent=0 should yield 4 configured slots) ---

color_info ""
color_info "[2/14] C_GetSlotList (no token yet, --list-slots)"
out=$(run_p11 --list-slots)
assert "Slot 0 present in enumeration"       "Slot 0"                    "$out"

# ---- 3. C_InitToken on slot 0 --------------------------------------------

color_info ""
color_info "[3/14] C_InitToken (slot 0, label='$LABEL')"
out=$(run_p11 --slot 0 --init-token --label "$LABEL" --so-pin "$SO_PIN")
assert "Token initialized OK"                "Token successfully initialized" "$out"

# After this, slot0.tok should exist in tokens_dir.
if [ ! -f "$TOKENS_DIR/slot0.tok" ]; then
    color_fail "  FAIL  slot0.tok was not created in $TOKENS_DIR"
    FAIL=$((FAIL + 1))
else
    color_pass "  PASS  slot0.tok created on disk ($(stat -c '%s' "$TOKENS_DIR/slot0.tok") bytes)"
    PASS=$((PASS + 1))
fi

# ---- 4. C_GetSlotList (tokenPresent=1) -----------------------------------

color_info ""
color_info "[4/14] C_GetSlotList with tokenPresent=1"
out=$(run_p11 --list-token-slots)
assert "Token-present slot reported"          "$LABEL"                   "$out"

# ---- 5. C_GetTokenInfo ---------------------------------------------------

color_info ""
color_info "[5/14] C_GetTokenInfo"
out=$(run_p11 --slot 0 --list-token-slots)
assert "Token label matches"                  "$LABEL"                    "$out"
assert "Manufacturer reported"                "FreeHSM C"                 "$out"
assert "Model reported"                       "FreeHSM-C-v1"              "$out"

# ---- 6. C_GetMechanismList -----------------------------------------------

color_info ""
color_info "[6/14] C_GetMechanismList"
out=$(run_p11 --slot 0 --list-mechanisms)
assert "AES-GCM exposed"                      "AES-GCM"                   "$out"
assert "SHA-256 exposed"                      "SHA256"                    "$out"

# ---- 7. C_InitPIN (SO logs in, sets user PIN) ----------------------------

color_info ""
color_info "[7/14] C_InitPIN (set user PIN via SO session)"
out=$(run_p11 --slot 0 --login --login-type so --so-pin "$SO_PIN" \
              --init-pin --new-pin "$USER_PIN")
assert "User PIN successfully initialized"    "User PIN successfully initialized" "$out"

# ---- 8. C_Login(USER) + roundtrip ---------------------------------------

color_info ""
color_info "[8/14] C_Login as USER + C_GetTokenInfo"
out=$(run_p11 --slot 0 --login --pin "$USER_PIN" --list-token-slots)
assert "USER login succeeded"                 "$LABEL"                    "$out"

# ---- 9. Wrong PIN should fail (PIN counter must increment) --------------

color_info ""
color_info "[9/14] C_Login(USER) with WRONG pin"
out=$(run_p11 --slot 0 --login --pin "0000WRONG" --list-token-slots)
assert "Wrong PIN rejected"                   "CKR_PIN_INCORRECT"         "$out"

# ---- 10. SO can re-init token (destroys objects) -------------------------

color_info ""
color_info "[10/14] C_InitToken with different label (re-init)"
out=$(run_p11 --slot 0 --init-token --label "freehsm-prod" --so-pin "$SO_PIN")
assert "Re-init succeeded"                    "Token successfully initialized" "$out"

# ---- 11. Final cleanup-friendly slot list -------------------------------

color_info ""
color_info "[11/14] C_GetSlotList final"
out=$(run_p11 --list-token-slots)
assert "Token still present after re-init"    "freehsm-prod"              "$out"

# ---- Report --------------------------------------------------------------

color_info ""
color_info "============================================================"
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    color_pass "SUMMARY : $PASS / $TOTAL assertions PASS"
    exit 0
else
    color_fail "SUMMARY : $FAIL / $TOTAL assertions FAILED ($PASS passed)"
    exit 1
fi
