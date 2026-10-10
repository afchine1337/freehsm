#!/bin/sh
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# fhsm_crypt_cli.sh --- fhsm-crypt list, keygen, delete, encrypt and decrypt,
# as an operator types them (docs/fhsm-crypt-plan.md, stages 0 to 2).
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

echo "fhsm-crypt: keygen"
q "$CRYPT" keygen --label sym --alg aes256 --module "$LIB" \
  && q "$CRYPT" keygen --label mac --alg hmac --module "$LIB"
ok "keygen aes256 and hmac" $?

q "$CRYPT" list --class key --module "$LIB"
grep -q "secret key.* sym .*aes256" "$W/out" && grep -q "secret key.* mac .*hmac" "$W/out" \
  && grep -q "public key.* keep .*ecdsa-p256" "$W/out"
ok "list names each key's algorithm, secret or pair" $?

q "$CRYPT" show --label sym --module "$LIB"
[ $? -eq 0 ] && grep -q "secret key" "$W/out" && grep -q "size  *256 bits" "$W/out" \
  && grep -q "sensitive  *yes" "$W/out" && grep -q "extractable  *no" "$W/out"
ok "show describes the aes256 key" $?

q "$CRYPT" show --label nothing-here --module "$LIB"
[ $? -eq 3 ]
ok "show of an unknown label: exit 3" $?

q "$CRYPT" keygen --label sym --alg aes128 --module "$LIB"
[ $? -eq 3 ] && grep -q "already on the token" "$W/out"
ok "a second key under a label in use is refused (exit 3)" $?

q "$CRYPT" keygen --label x --alg ecdsa-p256 --module "$LIB"
[ $? -eq 1 ] && grep -q "fhsm-csr keygen --alg ecdsa-p256" "$W/out"
ok "a signature algorithm is sent to fhsm-csr" $?

q "$CSR" keygen --label x --alg aes256 --module "$LIB"
[ $? -eq 1 ] && grep -q "fhsm-crypt keygen --alg aes256" "$W/out"
ok "and fhsm-csr sends a secret key to fhsm-crypt" $?

q "$CRYPT" keygen --label x --module "$LIB"
[ $? -eq 1 ] && grep -q "needs --alg" "$W/out"
ok "keygen without --alg is refused" $?

q "$CRYPT" delete --label sym --yes --module "$LIB"
[ $? -eq 0 ] && grep -q "destroyed secret key" "$W/out"
ok "a secret key is deleted like any other" $?

echo "fhsm-crypt: encrypt and decrypt"
printf 'a file to keep to ourselves\n' > "$W/plain"
q "$CRYPT" encrypt --key mac --in "$W/plain" --out "$W/x.p7m" --module "$LIB"
[ $? -eq 3 ] && grep -q "not an AES key" "$W/out"
ok "an HMAC key does not encrypt files (exit 3)" $?

q "$CRYPT" keygen --label filekey --alg aes256 --module "$LIB" \
  && q "$CRYPT" encrypt --key filekey --in "$W/plain" --out "$W/plain.p7m" --module "$LIB" \
  && q "$CRYPT" decrypt --in "$W/plain.p7m" --out "$W/plain.back" --module "$LIB" \
  && grep -q 'with "filekey"' "$W/out" && cmp -s "$W/plain" "$W/plain.back"
ok "encrypt, then decrypt with the key the file names" $?

q "$CRYPT" decrypt --in "$W/plain.p7m" --out "$W/plain.back" --module "$LIB"
[ $? -eq 1 ] && grep -q "exists" "$W/out"
ok "an existing output is not written over (exit 1)" $?

cp "$W/plain.p7m" "$W/bad.p7m" && printf 'X' | dd of="$W/bad.p7m" bs=1 seek=$(( $(wc -c < "$W/bad.p7m") - 20 )) conv=notrunc 2>/dev/null
q "$CRYPT" decrypt --in "$W/bad.p7m" --out "$W/bad.out" --module "$LIB"
[ $? -eq 4 ] && [ ! -e "$W/bad.out" ]
ok "an altered file: exit 4, and no output" $?

q "$CRYPT" encrypt --in "$W/plain" --out "$W/y.p7m" --module "$LIB"
[ $? -eq 1 ]
ok "encrypt without --key is a usage error" $?

q "$CRYPT" list --class nonsense --module "$LIB"
[ $? -eq 1 ] && grep -q "takes key, cert or all" "$W/out"
ok "an unknown --class is refused" $?

q "$CRYPT" list --pin userpin1234 --module "$LIB"
[ $? -eq 1 ] && grep -q "is not accepted" "$W/out"
ok "--pin is refused" $?

echo
if [ "$fails" -eq 0 ]; then echo "PASS"; exit 0; fi
echo "FAIL ($fails)"; exit 1
