#!/bin/sh
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# fhsm_crypt_cli.sh --- fhsm-crypt list and delete, as an operator types them
# (docs/fhsm-crypt-plan.md, stage 0).
#
# The property that matters is delete's: without --yes it names what it would
# destroy and destroys nothing, and with --yes it destroys exactly the objects
# carrying the label, within the class asked for.
#
# Exit 0 pass, 1 fail.
# ===========================================================================
set -u

LIB="${LIB:-./libfreehsm.so}"
TOK="${TOK:-./tools/fhsm-token}"
CSR="${CSR:-./tools/fhsm-csr}"
CRYPT="${CRYPT:-./tools/fhsm-crypt}"

for t in "$TOK" "$CSR" "$CRYPT"; do
    [ -x "$t" ] || { echo "fhsm_crypt_cli: $t is not built" >&2; exit 1; }
done

export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
export OPENSSL_CONF=/dev/null
FHSM_TOKENS_DIR=$(mktemp -d); export FHSM_TOKENS_DIR
W=$(mktemp -d)
trap 'rm -rf "$FHSM_TOKENS_DIR" "$W"' EXIT

fails=0
ok() {   # ok WHAT STATUS -- on failure, what the last command said
    if [ "$2" -eq 0 ]; then printf '  %-62s OK\n' "$1"
    else
        printf '  %-62s FAIL\n' "$1"; fails=$((fails + 1))
        [ -s "$W/out" ] && sed 's/^/      | /' "$W/out"
    fi
}
q() { "$@" >"$W/out" 2>&1; }

echo "fhsm-crypt: list and delete"
FHSM_SO_PIN=sopin1234 FHSM_PIN=userpin1234 "$TOK" init --label crypt --module "$LIB" \
    >/dev/null 2>&1 || { echo "fhsm_crypt_cli: token init failed"; exit 1; }
export FHSM_PIN=userpin1234

q "$CSR" keygen --label keep --alg ecdsa-p256 --module "$LIB" \
  && q "$CSR" keygen --label gone --alg ed25519 --module "$LIB"
ok "two key pairs, keep and gone" $?

q "$CRYPT" list --module "$LIB"
[ $? -eq 0 ] && grep -q "^4 objects" "$W/out" \
  && [ "$(grep -c ' keep ' "$W/out")" -eq 2 ] && [ "$(grep -c ' gone ' "$W/out")" -eq 2 ]
ok "list shows four objects, two per label" $?

q "$CRYPT" list --class cert --module "$LIB"
[ $? -eq 0 ] && grep -q "^0 objects" "$W/out"
ok "list --class cert shows none" $?

q "$CRYPT" delete --label gone --module "$LIB"
[ $? -eq 1 ] && grep -q "would destroy 2 objects" "$W/out" && grep -q "nothing destroyed" "$W/out"
ok "delete without --yes names two objects and stops (exit 1)" $?

q "$CRYPT" list --module "$LIB"
grep -q "^4 objects" "$W/out"
ok "  and all four are still there" $?

q "$CRYPT" delete --label gone --class key --yes --module "$LIB"
[ $? -eq 0 ] && [ "$(grep -c 'destroyed' "$W/out")" -eq 2 ]
ok "delete --yes destroys both halves of gone" $?

q "$CRYPT" list --module "$LIB"
grep -q "^2 objects" "$W/out" && ! grep -q ' gone ' "$W/out" \
  && [ "$(grep -c ' keep ' "$W/out")" -eq 2 ]
ok "  and keep is untouched" $?

q "$CRYPT" delete --label gone --yes --module "$LIB"
[ $? -eq 3 ] && grep -q 'no object labelled "gone"' "$W/out"
ok "deleting it again: nothing labelled gone (exit 3)" $?

q "$CRYPT" delete --label keep --class cert --yes --module "$LIB"
[ $? -eq 3 ] && grep -q 'no certificate labelled "keep"' "$W/out"
ok "--class cert does not reach keep's keys (exit 3)" $?

q "$CRYPT" list --class nonsense --module "$LIB"
[ $? -eq 1 ] && grep -q "takes key, cert or all" "$W/out"
ok "an unknown --class is refused" $?

q "$CRYPT" list --pin userpin1234 --module "$LIB"
[ $? -eq 1 ] && grep -q "is not accepted" "$W/out"
ok "--pin is refused" $?

echo
if [ "$fails" -eq 0 ]; then echo "PASS"; exit 0; fi
echo "FAIL ($fails)"; exit 1
