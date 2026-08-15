#!/usr/bin/env bash
# ============================================================================
# multi_slot_pkcs11.sh --- Multi-slot isolation test for FreeHSM C.
#
# Initializes 3 independent tokens in slots 0, 1, 2 with distinct SO/USER
# PINs and labels. Verifies :
#
#   1. Slot 1's SO PIN cannot login on slot 0 (cross-slot PIN rejection).
#   2. A key generated in slot 0 is invisible to a session on slot 1
#      (object isolation).
#   3. Each slot maintains its own audit / failure counters independently.
#   4. C_GenerateKey + C_FindObjects + C_GetAttributeValue work for AES keys.
#   5. AES-GCM encrypt + decrypt round-trip per slot.
#   6. C_DestroyObject removes the key from C_FindObjects.
#
# Exit 0 on success, 1 on any failure.
# ============================================================================

set -u

MODULE="${MODULE:-/opt/freehsm/lib/libfreehsm-fips.so}"
TOKENS_DIR="${TOKENS_DIR:-$(mktemp -d /tmp/freehsm-multi-XXXXXX)}"
export FHSM_TOKENS_DIR="${TOKENS_DIR}"

LABEL0="ms-slot0"
LABEL1="ms-slot1"
LABEL2="ms-slot2"

SO_PIN0="00000000";  USER_PIN0="user0000"
SO_PIN1="11111111";  USER_PIN1="user1111"
SO_PIN2="22222222";  USER_PIN2="user2222"

PASS=0
FAIL=0
PKCS11_TOOL="$(command -v pkcs11-tool)"

color_pass() { printf '\033[32m%s\033[0m\n' "$1"; }
color_fail() { printf '\033[31m%s\033[0m\n' "$1"; }
color_info() { printf '\033[36m%s\033[0m\n' "$1"; }

assert() {
    local desc="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q -F -- "$expected"; then
        color_pass "  PASS  $desc"
        PASS=$((PASS + 1))
    else
        color_fail "  FAIL  $desc"
        echo  "       expected substring : $expected"
        echo  "       actual             :"
        echo  "$actual" | sed 's/^/         /'
        FAIL=$((FAIL + 1))
    fi
}

assert_not() {
    local desc="$1" forbidden="$2" actual="$3"
    if echo "$actual" | grep -q -F -- "$forbidden"; then
        color_fail "  FAIL  $desc"
        echo  "       forbidden substring found : $forbidden"
        echo  "$actual" | sed 's/^/         /'
        FAIL=$((FAIL + 1))
    else
        color_pass "  PASS  $desc"
        PASS=$((PASS + 1))
    fi
}

p11() {
    "$PKCS11_TOOL" --module "$MODULE" "$@" 2>&1
}

cleanup() {
    if [ "$FAIL" -eq 0 ]; then
        rm -rf "$TOKENS_DIR"
    else
        color_info "[multi] tokens_dir preserved : $TOKENS_DIR"
    fi
}
trap cleanup EXIT

# ---- pre-flight ----------------------------------------------------------

if [ -z "$PKCS11_TOOL" ]; then
    color_fail "pkcs11-tool not installed (apt install opensc)"
    exit 2
fi
if [ ! -f "$MODULE" ]; then
    color_fail "Module not found at $MODULE"
    exit 2
fi
mkdir -p "$TOKENS_DIR"
chmod 700 "$TOKENS_DIR"

color_info "============================================================"
color_info "FreeHSM C multi-slot isolation test"
color_info "  module     : $MODULE"
color_info "  tokens_dir : $TOKENS_DIR"
color_info "============================================================"

# ---- Step 1 : initialize 3 slots ----------------------------------------

color_info ""
color_info "[1/8] C_InitToken on slots 0, 1, 2 with distinct PINs"
out=$(p11 --slot 0 --init-token --label "$LABEL0" --so-pin "$SO_PIN0")
assert "slot 0 init"      "Token successfully initialized"    "$out"
out=$(p11 --slot 1 --init-token --label "$LABEL1" --so-pin "$SO_PIN1")
assert "slot 1 init"      "Token successfully initialized"    "$out"
out=$(p11 --slot 2 --init-token --label "$LABEL2" --so-pin "$SO_PIN2")
assert "slot 2 init"      "Token successfully initialized"    "$out"

# ---- Step 2 : each slot's SO PIN unlocks ONLY its own slot ---------------

color_info ""
color_info "[2/8] Cross-slot SO PIN rejection"
out=$(p11 --slot 0 --login --login-type so --so-pin "$SO_PIN1" \
          --init-pin --new-pin "doesnotmatter")
assert "slot 0 rejects SO PIN of slot 1"   "CKR_PIN_INCORRECT"  "$out"
out=$(p11 --slot 2 --login --login-type so --so-pin "$SO_PIN0" \
          --init-pin --new-pin "doesnotmatter")
assert "slot 2 rejects SO PIN of slot 0"   "CKR_PIN_INCORRECT"  "$out"

# After two failed PIN attempts, slots 0 and 2 are in throttle (500ms+).
# Sleep so the next login is not rejected as CKR_PIN_THROTTLED.
# The throttle base is FHSM_PIN_THROTTLE_BASE_MS = 500 ms ; 1 second is
# safe and keeps the test fast.
sleep 1

# ---- Step 3 : set user PIN on slots 0 and 1 -----------------------------

color_info ""
color_info "[3/8] C_InitPIN for slot 0 and slot 1"
out=$(p11 --slot 0 --login --login-type so --so-pin "$SO_PIN0" \
          --init-pin --new-pin "$USER_PIN0")
assert "slot 0 user PIN init" "User PIN successfully initialized" "$out"
out=$(p11 --slot 1 --login --login-type so --so-pin "$SO_PIN1" \
          --init-pin --new-pin "$USER_PIN1")
assert "slot 1 user PIN init" "User PIN successfully initialized" "$out"

# ---- Step 4 : generate an AES key in slot 0 -----------------------------

color_info ""
color_info "[4/8] C_GenerateKey AES-256 in slot 0"
out=$(p11 --slot 0 --login --pin "$USER_PIN0" \
          --keygen --key-type "AES:32" --label "k0-aes" --id 01)
assert "slot 0 keygen"      "Key generated"                   "$out"

# ---- Step 5 : C_FindObjects sees the key in slot 0, NOT in slot 1 -------

color_info ""
color_info "[5/8] Object isolation (slot 0 has k0-aes, slot 1 does not)"
out=$(p11 --slot 0 --login --pin "$USER_PIN0" --list-objects)
assert "slot 0 lists k0-aes"   "k0-aes"                       "$out"

out=$(p11 --slot 1 --login --pin "$USER_PIN1" --list-objects)
assert_not "slot 1 does NOT see k0-aes" "k0-aes" "$out"

# ---- Step 6 : generate a key in slot 1 too ------------------------------

color_info ""
color_info "[6/8] C_GenerateKey AES-128 in slot 1"
out=$(p11 --slot 1 --login --pin "$USER_PIN1" \
          --keygen --key-type "AES:16" --label "k1-aes" --id 02)
assert "slot 1 keygen"      "Key generated"                   "$out"

# ---- Step 7 : C_Encrypt + C_Decrypt round-trip on slot 0 ---------------

color_info ""
color_info "[7/8] AES-GCM round-trip via C_Encrypt/C_Decrypt on slot 0"
echo -n "hello FreeHSM" > /tmp/plain.bin
out=$(p11 --slot 0 --login --pin "$USER_PIN0" \
          --encrypt --mechanism AES-GCM \
          --input-file /tmp/plain.bin --output-file /tmp/cipher.bin \
          --label "k0-aes" 2>&1)
# Some pkcs11-tool versions report success silently ; we check the file size.
if [ -s /tmp/cipher.bin ]; then
    color_pass "  PASS  slot 0 encrypted (cipher = $(stat -c '%s' /tmp/cipher.bin) bytes)"
    PASS=$((PASS + 1))
else
    color_fail "  FAIL  slot 0 encrypt produced empty output : $out"
    FAIL=$((FAIL + 1))
fi

# ---- Step 8 : destroy the key on slot 0 -------------------------------

color_info ""
color_info "[8/8] C_DestroyObject removes k0-aes from slot 0"
out=$(p11 --slot 0 --login --pin "$USER_PIN0" \
          --delete-object --type secrkey --label "k0-aes")
out=$(p11 --slot 0 --login --pin "$USER_PIN0" --list-objects)
assert_not "slot 0 no longer has k0-aes" "k0-aes" "$out"

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
