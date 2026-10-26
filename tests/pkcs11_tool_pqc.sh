#!/usr/bin/env bash
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# pkcs11_tool_pqc.sh --- OpenSC pkcs11-tool against FreeHSM's post-quantum
# mechanisms.
#
# Written to test OpenSC PR #3836 (--sign-context, --sign-hedge) on a module
# that implements ML-DSA, HashML-DSA and SLH-DSA with their parameters, and
# kept as a check that FreeHSM answers a third-party caller the way its own
# tests say it does.
#
#   PKCS11_TOOL=~/build/opensc/src/tools/pkcs11-tool \
#       bash tests/pkcs11_tool_pqc.sh [module.so]
#
# The token is a throwaway in a fresh directory, with PINs generated here
# and never printed. pkcs11-tool takes a PIN on the command line, on a
# terminal, or from `--pin env:NAME`; the last is used, the variable set for
# one command at a time and never exported. FHSM_ALLOW_UNSIGNED=1 runs an
# unsigned module (integrity check off, default provider).
#
# Every line of the result is PASS, FAIL or SKIP with what was asked; the
# summary and the exit status count the FAILs. A SKIP is a capability the
# pkcs11-tool under test does not have, not a finding about the module.
# ===========================================================================
set -u

PKCS11_TOOL="${PKCS11_TOOL:-pkcs11-tool}"
MODULE="$(readlink -f "${1:-./libfreehsm.so}")"
[ -f "$MODULE" ] || { echo "no module at $MODULE" >&2; exit 2; }
command -v "$PKCS11_TOOL" >/dev/null || { echo "no $PKCS11_TOOL" >&2; exit 2; }
command -v openssl >/dev/null || { echo "openssl is needed for PH(M)" >&2; exit 2; }

WORK="$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/fhsm-p11tool.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
export FHSM_TOKENS_DIR="$WORK/tokens"
mkdir -m 700 "$FHSM_TOKENS_DIR"
if [ "${FHSM_ALLOW_UNSIGNED:-0}" = 1 ]; then
    export FHSM_INTEGRITY_ALLOW_UNSIGNED=1 OPENSSL_CONF=/dev/null
fi

SO_PIN="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
USER_PIN="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
PASS=0; FAIL=0; SKIP=0

p11()  { "$PKCS11_TOOL" --module "$MODULE" "$@"; }
user() { P11_PIN="$USER_PIN" "$PKCS11_TOOL" --module "$MODULE" --login --pin env:P11_PIN "$@"; }
ok()   { echo "PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL + 1)); [ -n "${2:-}" ] && sed 's/^/        /' "$2" | tail -12; }
skip() { echo "SKIP  $1"; SKIP=$((SKIP + 1)); }

# expect 0|1 NAME CMD...: 0 = must succeed, 1 = must be refused.
expect() {
    local want="$1" name="$2"; shift 2
    if "$@" >"$WORK/out" 2>&1; then got=0; else got=1; fi
    if [ "$got" = "$want" ]; then ok "$name"; else bad "$name" "$WORK/out"; fi
}

echo "pkcs11-tool : $(command -v "$PKCS11_TOOL")"
echo "module      : $MODULE"
echo

# --- token ---------------------------------------------------------------
P11_SO="$SO_PIN" p11 --init-token --label pqc --so-pin env:P11_SO >"$WORK/out" 2>&1 \
    || { bad "C_InitToken" "$WORK/out"; exit 1; }
P11_SO="$SO_PIN" P11_PIN="$USER_PIN" p11 --login --login-type so --so-pin env:P11_SO \
    --init-pin --new-pin env:P11_PIN >"$WORK/out" 2>&1 \
    || { bad "C_InitPIN" "$WORK/out"; exit 1; }

head -c 1000 /dev/urandom >"$WORK/msg"
CTX="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
CTX2="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
CTX256="$(od -An -N256 -tx1 /dev/urandom | tr -d ' \n')"

HAS_CONTEXT=0
"$PKCS11_TOOL" --help 2>&1 | grep -q -- '--sign-context' && HAS_CONTEXT=1
# pkcs11-tool names the mechanisms it knows when it lists the module's; one
# that predates PKCS#11 3.2 (OpenSC before 0.27) prints mechtype-0x1D for
# ML-DSA, and every PQC request would be refused by the tool, not the module.
HAS_PQC=0
p11 -M 2>/dev/null | grep -q '^ *ML-DSA,' && HAS_PQC=1

sign()   { user --sign --id "$1" --mechanism "$2" --input-file "$3" --output-file "$4" "${@:5}"; }
verify() { user --verify --id "$1" --mechanism "$2" --input-file "$3" --signature-file "$4" "${@:5}"; }

if [ "$HAS_PQC" = 0 ]; then
    skip "ML-DSA, HashML-DSA, SLH-DSA, ML-KEM: this pkcs11-tool predates PKCS#11 3.2 names (OpenSC 0.27)"
fi

# --- ML-DSA --------------------------------------------------------------
[ "$HAS_PQC" = 1 ] && {
for set in 44 65 87; do
    expect 0 "keygen ML-DSA-$set" user --keypairgen --key-type "ML-DSA-$set" \
        --label "mldsa$set" --id "$set"
    expect 0 "ML-DSA-$set sign" sign "$set" ML-DSA "$WORK/msg" "$WORK/sig$set"
    expect 0 "ML-DSA-$set verify" verify "$set" ML-DSA "$WORK/msg" "$WORK/sig$set"
done

if [ "$HAS_CONTEXT" = 1 ]; then
    expect 0 "ML-DSA-65 sign, 32-byte context" \
        sign 65 ML-DSA "$WORK/msg" "$WORK/sigc" --sign-context "$CTX"
    expect 0 "  verify under the same context" \
        verify 65 ML-DSA "$WORK/msg" "$WORK/sigc" --sign-context "$CTX"
    expect 1 "  verify under another context is refused" \
        verify 65 ML-DSA "$WORK/msg" "$WORK/sigc" --sign-context "$CTX2"
    expect 1 "  verify with no context is refused" \
        verify 65 ML-DSA "$WORK/msg" "$WORK/sigc"
    expect 1 "ML-DSA-65 sign, 256-byte context is refused (FIPS 204: at most 255)" \
        sign 65 ML-DSA "$WORK/msg" "$WORK/sig256" --sign-context "$CTX256"

    expect 0 "ML-DSA-65 sign, --sign-hedge deterministic (1)" \
        sign 65 ML-DSA "$WORK/msg" "$WORK/det1" --sign-hedge deterministic --sign-context "$CTX"
    expect 0 "ML-DSA-65 sign, --sign-hedge deterministic (2)" \
        sign 65 ML-DSA "$WORK/msg" "$WORK/det2" --sign-hedge deterministic --sign-context "$CTX"
    if cmp -s "$WORK/det1" "$WORK/det2"; then ok "  deterministic signatures are identical"
    else bad "  deterministic signatures are identical"; fi
    expect 0 "  and verify" verify 65 ML-DSA "$WORK/msg" "$WORK/det1" --sign-context "$CTX"
    expect 0 "ML-DSA-65 sign, --sign-hedge required" \
        sign 65 ML-DSA "$WORK/msg" "$WORK/hed1" --sign-hedge required
    expect 0 "ML-DSA-65 sign, --sign-hedge required, again" \
        sign 65 ML-DSA "$WORK/msg" "$WORK/hed2" --sign-hedge required
    if cmp -s "$WORK/hed1" "$WORK/hed2"; then bad "  hedged signatures differ"
    else ok "  hedged signatures differ"; fi
else
    skip "context and hedge: this pkcs11-tool has no --sign-context (OpenSC PR #3836)"
fi

# --- HashML-DSA ----------------------------------------------------------
for h in SHA256 SHA3_384 SHAKE256; do
    expect 0 "HASH-ML-DSA-$h sign" sign 65 "HASH-ML-DSA-$h" "$WORK/msg" "$WORK/sigh$h"
    expect 0 "HASH-ML-DSA-$h verify" verify 65 "HASH-ML-DSA-$h" "$WORK/msg" "$WORK/sigh$h"
done
if [ "$HAS_CONTEXT" = 1 ]; then
    expect 0 "HASH-ML-DSA-SHA512 sign with context" \
        sign 65 HASH-ML-DSA-SHA512 "$WORK/msg" "$WORK/sighc" --sign-context "$CTX"
    expect 0 "  verify under the same context" \
        verify 65 HASH-ML-DSA-SHA512 "$WORK/msg" "$WORK/sighc" --sign-context "$CTX"
fi
# The generic mechanism takes PH(M) (v3.2 6.67.6). pkcs11-tool has no name
# for it, so it is named by value, 0x1F, and the hash by --hash-algorithm --
# which pkcs11-tool refuses for anything but RSA-PSS (parse_pss_params), so
# its CKM_HASH_ML_DSA branch cannot be reached. That is reported as a SKIP:
# it says nothing about the module.
openssl dgst -sha256 -binary "$WORK/msg" >"$WORK/ph"
# By name once pkcs11-tool has one for it (OpenSC, after this was reported).
GEN=0x1f
p11 -M 2>/dev/null | grep -q '^ *HASH-ML-DSA,' && GEN=HASH-ML-DSA
if sign 65 "$GEN" "$WORK/ph" "$WORK/sigg" --hash-algorithm SHA256 >"$WORK/out" 2>&1; then
    ok "CKM_HASH_ML_DSA ($GEN), SHA256, on PH(M)"
    expect 0 "  verify" verify 65 "$GEN" "$WORK/ph" "$WORK/sigg" --hash-algorithm SHA256
    expect 0 "  and the same signature verifies under HASH-ML-DSA-SHA256 on M" \
        verify 65 HASH-ML-DSA-SHA256 "$WORK/msg" "$WORK/sigg"
elif grep -q "applicable only to RSA-PKCS-PSS" "$WORK/out"; then
    skip "CKM_HASH_ML_DSA: pkcs11-tool refuses --hash-algorithm outside RSA-PSS"
else
    bad "CKM_HASH_ML_DSA ($GEN), SHA256, on PH(M)" "$WORK/out"
fi

# --- SLH-DSA -------------------------------------------------------------
# Two sets, an "s" and an "f", because they are different code paths in the
# provider. The tests that need the key run only if it was made: a refusal to
# verify with no key would otherwise pass, for the wrong reason.
slh=0
slh_key=0
for kt in SLH-DSA-SHA2-128S SLH-DSA-SHA2-128F; do
    slh=$((slh + 1))
    if user --keypairgen --key-type "$kt" --label "slh$slh" --id "8$slh" >"$WORK/out" 2>&1; then
        ok "keygen $kt"
        [ "$slh_key" = 0 ] && slh_key="8$slh"
    else
        bad "keygen $kt" "$WORK/out"; continue
    fi
    expect 0 "$kt sign" sign "8$slh" SLH-DSA "$WORK/msg" "$WORK/sigs$slh"
    expect 0 "$kt verify" verify "8$slh" SLH-DSA "$WORK/msg" "$WORK/sigs$slh"
    if [ "$HAS_CONTEXT" = 1 ]; then
        expect 0 "$kt sign with context" \
            sign "8$slh" SLH-DSA "$WORK/msg" "$WORK/sigsc$slh" --sign-context "$CTX"
        expect 0 "  verify under the same context" \
            verify "8$slh" SLH-DSA "$WORK/msg" "$WORK/sigsc$slh" --sign-context "$CTX"
        expect 1 "  verify with another context is refused" \
            verify "8$slh" SLH-DSA "$WORK/msg" "$WORK/sigsc$slh" --sign-context "$CTX2"
    fi
done

# --- HashSLH-DSA ----------------------------------------------------------
# pkcs11-tool has names for these since OpenSC #3882; until FreeHSM had the
# mechanisms nothing had exercised them against a module. The same shape as
# HashML-DSA above, on the SHA2-128S key: three hash-specific mechanisms, one
# with a context, and the generic one on PH(M).
if [ "$slh_key" = 0 ]; then
    skip "HashSLH-DSA: no SLH-DSA key was generated"
elif ! p11 -M 2>/dev/null | grep -q '^ *HASH-SLH-DSA-SHA256,'; then
    skip "HashSLH-DSA: the module or this pkcs11-tool does not name HASH-SLH-DSA-SHA256"
else
    for h in SHA256 SHA3_384 SHAKE256; do
        expect 0 "HASH-SLH-DSA-$h sign" sign "$slh_key" "HASH-SLH-DSA-$h" "$WORK/msg" "$WORK/sigsh$h"
        expect 0 "HASH-SLH-DSA-$h verify" verify "$slh_key" "HASH-SLH-DSA-$h" "$WORK/msg" "$WORK/sigsh$h"
    done
    expect 1 "HASH-SLH-DSA-SHA256 signature does not verify under HASH-SLH-DSA-SHA3_384" \
        verify "$slh_key" HASH-SLH-DSA-SHA3_384 "$WORK/msg" "$WORK/sigshSHA256"
    if [ "$HAS_CONTEXT" = 1 ]; then
        expect 0 "HASH-SLH-DSA-SHA512 sign with context" \
            sign "$slh_key" HASH-SLH-DSA-SHA512 "$WORK/msg" "$WORK/sigshc" --sign-context "$CTX"
        expect 0 "  verify under the same context" \
            verify "$slh_key" HASH-SLH-DSA-SHA512 "$WORK/msg" "$WORK/sigshc" --sign-context "$CTX"
        expect 1 "  verify with another context is refused" \
            verify "$slh_key" HASH-SLH-DSA-SHA512 "$WORK/msg" "$WORK/sigshc" --sign-context "$CTX2"
    fi
    # The generic mechanism takes PH(M), with the hash named by
    # --hash-algorithm (accepted for HASH-SLH-DSA since OpenSC #3882).
    if sign "$slh_key" HASH-SLH-DSA "$WORK/ph" "$WORK/sigsg" --hash-algorithm SHA256 >"$WORK/out" 2>&1; then
        ok "CKM_HASH_SLH_DSA (HASH-SLH-DSA), SHA256, on PH(M)"
        expect 0 "  verify" verify "$slh_key" HASH-SLH-DSA "$WORK/ph" "$WORK/sigsg" --hash-algorithm SHA256
        expect 0 "  and the same signature verifies under HASH-SLH-DSA-SHA256 on M" \
            verify "$slh_key" HASH-SLH-DSA-SHA256 "$WORK/msg" "$WORK/sigsg"
    elif grep -q "applicable only to RSA-PKCS-PSS" "$WORK/out"; then
        skip "CKM_HASH_SLH_DSA: pkcs11-tool refuses --hash-algorithm outside RSA-PSS"
    else
        bad "CKM_HASH_SLH_DSA (HASH-SLH-DSA), SHA256, on PH(M)" "$WORK/out"
    fi
fi

# --- ML-KEM: key pairs, usages, and encapsulation where pkcs11-tool has it
for set in 512 768 1024; do
    expect 0 "keygen ML-KEM-$set, --usage-encapsulate" user --keypairgen \
        --key-type "ML-KEM-$set" --usage-encapsulate --label "kem$set" --id "9$((set / 256))"
done
user --list-objects --type pubkey --label kem768 >"$WORK/out" 2>&1
if grep -q "encapsulate" "$WORK/out"; then ok "ML-KEM-768 public key lists the encapsulate usage"
else bad "ML-KEM-768 public key lists the encapsulate usage" "$WORK/out"; fi
user --list-objects --type privkey --label kem768 >"$WORK/out" 2>&1
if grep -q "decapsulate" "$WORK/out"; then ok "ML-KEM-768 private key lists the decapsulate usage"
else bad "ML-KEM-768 private key lists the decapsulate usage" "$WORK/out"; fi
if "$PKCS11_TOOL" --help 2>&1 | grep -q -- '--encapsulate'; then
    # --encapsulate / --decapsulate, OpenSC/OpenSC#3894. The shared secret
    # goes to --secret-file both ways, and is written out only with
    # --extractable. Encapsulation needs only the public key, but this module
    # answers C_FindObjectsInit with CKR_USER_NOT_LOGGED_IN outside a logged-in
    # session, so it is run logged in here.
    for set in 512 768 1024; do
        id="9$((set / 256))"
        expect 0 "ML-KEM-$set encapsulate" user --encapsulate -m ML-KEM --id "$id" \
            --extractable --output-file "$WORK/ct$set" --secret-file "$WORK/ss$set"
        expect 0 "  decapsulate" user --decapsulate -m ML-KEM --id "$id" \
            --extractable --input-file "$WORK/ct$set" --secret-file "$WORK/ss${set}d"
        if cmp -s "$WORK/ss$set" "$WORK/ss${set}d"; then ok "  both sides hold the same secret"
        else bad "  both sides hold the same secret"; fi
    done
    head -c 100 "$WORK/ct768" >"$WORK/ctshort"
    expect 1 "ML-KEM-768 decapsulate, short ciphertext is refused" user --decapsulate \
        -m ML-KEM --id 93 --extractable --input-file "$WORK/ctshort" --secret-file "$WORK/ssx"
    expect 1 "ML-KEM-768 decapsulate without --extractable cannot write the secret" user \
        --decapsulate -m ML-KEM --id 93 --input-file "$WORK/ct768" --secret-file "$WORK/ssy"
    expect 0 "ML-KEM-768 public key reads back (CKA_PARAMETER_SET)" user --read-object \
        --type pubkey --id 93 --output-file "$WORK/kem768.der"
else
    skip "ML-KEM encapsulation: pkcs11-tool has no C_EncapsulateKey operation"
fi

}

# --- EdDSA with a context ------------------------------------------------
# --sign-context also fills CK_EDDSA_PARAMS, which asks for Ed25519ctx;
# FreeHSM refuses a parameter block on Ed25519 rather than sign pure Ed25519
# in its place.
expect 0 "keygen Ed25519" user --keypairgen --key-type EC:edwards25519 --label ed --id 70
expect 0 "EdDSA sign" sign 70 EDDSA "$WORK/msg" "$WORK/sige"
if [ "$HAS_CONTEXT" = 1 ]; then
    expect 1 "EdDSA sign with a context is refused (Ed25519ctx not implemented)" \
        sign 70 EDDSA "$WORK/msg" "$WORK/sigec" --sign-context "$CTX"
fi

echo
echo "$PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
