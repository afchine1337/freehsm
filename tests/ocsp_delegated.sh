#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Simorgh Labs
#
# The delegated OCSP responder (RFC 6960 4.2.2.2), end to end through the
# tools, because every rule here is a rule of `fhsm-ca` and not of the library:
# the library will sign whatever it is handed. What decides whether an answer
# is acceptable is which certificate signs it, and that is chosen at this desk.
#
# A delegated responder exists so the CA key can stay offline. A verifier
# accepts an answer signed by something other than the CA only because the CA
# issued that something with extendedKeyUsage OCSPSigning. So a responder
# certificate without the EKU, or issued by a different CA, produces answers
# nobody will accept -- and the failure surfaces in production, days later, as
# clients that refuse a certificate that is perfectly good. Refusing at issuing
# time is the whole point of the two checks below.
#
#   sh tests/ocsp_delegated.sh
#
# Needs the tools built (`make all`) and an `openssl` on PATH to read back the
# responses. See the note at check 5 for what OpenSSL can and cannot tell us.
set -u
LIB="${LIB:-./libfreehsm-fips.so}"
CA="${CA:-./tools/fhsm-ca}"
CSR="${CSR:-./tools/fhsm-csr}"
TOK="${TOK:-./tools/fhsm-token}"
fail=0

say() { printf '  %-62s %s\n' "$1" "$2"; }
ok()  { if [ "$1" = 0 ]; then say "$2" OK; else say "$2" FAIL; fail=$((fail+1)); fi; }

# A missing tool is a missing test, not a passing one. `make tests` did not
# build the tools when audit_switch.sh was written and every assertion in it
# reported FAIL for that one uninteresting reason.
for t in "$CA" "$CSR" "$TOK"; do
    [ -x "$t" ] || { echo "ocsp_delegated.sh: $t is not built -- run 'make all' first" >&2; exit 2; }
done
command -v openssl >/dev/null || { echo "ocsp_delegated.sh: openssl is not on PATH" >&2; exit 2; }

export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
export FHSM_SO_PIN=sopin1234
export FHSM_PIN=userpin1234
FHSM_TOKENS_DIR=$(mktemp -d); export FHSM_TOKENS_DIR
W=$(mktemp -d)
trap 'rm -rf "$FHSM_TOKENS_DIR" "$W"' EXIT

echo "The delegated OCSP responder, through fhsm-ca"
echo

q() { "$@" >/dev/null 2>&1; }

# --- the material -------------------------------------------------------
# Two authorities, so that "issued by a different CA" is a real certificate
# and not a mangled one: the check has to reject a valid delegate that simply
# belongs to somebody else.
q "$TOK" init --label t

# The composite mechanism is interop-only: a fips-strict build answers
# CKR_MECHANISM_INVALID and every assertion below then fails for that one
# reason. Say which build is needed instead of printing nineteen failures --
# the same lesson as the missing-tool guard above.
if ! out=$("$CSR" keygen --label ca 2>&1); then
    echo "$out" | grep -q "0x70" && {
        echo "ocsp_delegated.sh: this build has no composite mechanism." >&2
        echo "  It is interop-only. Build with: make clean && make PROFILE=interop all" >&2
        exit 2; }
    echo "$out" >&2; exit 2
fi
for k in resp leaf other; do q "$CSR" keygen --label "$k"; done
q "$CSR" root --label ca    --subject "/CN=Test CA"   --out "$W/ca.der"
q "$CSR" root --label other --subject "/CN=Other CA"  --out "$W/other.der"
q "$CSR" csr  --label resp  --subject "/CN=Responder" --out "$W/resp.csr"
q "$CSR" csr  --label leaf  --subject "/CN=leaf"      --out "$W/leaf.csr"

out=$("$CA" issue --label ca --ca-cert "$W/ca.der" --csr "$W/resp.csr" \
        --profile ocsp-responder --out "$W/resp.der" 2>&1); rc=$?
ok $rc "a responder certificate is issued"

q "$CA" issue --label ca    --ca-cert "$W/ca.der"    --csr "$W/leaf.csr" --out "$W/leaf.der"
q "$CA" issue --label other --ca-cert "$W/other.der" --csr "$W/resp.csr" \
      --profile ocsp-responder --out "$W/foreign.der"

openssl x509 -in "$W/ca.der" -inform DER -out "$W/ca.pem" 2>/dev/null
[ -s "$W/ca.pem" ] || { echo "ocsp_delegated.sh: could not convert the CA to PEM" >&2; exit 2; }

printf '# fhsm-ca revocation database v1\ncrlNumber 1\n' > "$W/rev.db"
q openssl ocsp -issuer "$W/ca.der" -cert "$W/leaf.der" -reqout "$W/req.der" -no_nonce
[ -s "$W/req.der" ] || { echo "ocsp_delegated.sh: could not build a request" >&2; exit 2; }

# --- 1. the validity default --------------------------------------------
# A delegated responder carries id-pkix-ocsp-nocheck, which tells a verifier
# not to ask whether the responder itself is revoked. Revoking it is therefore
# not something a verifier observes, and the only thing that ends its authority
# is its own expiry. Hence a short default: 30 days, not the end-entity year.
d=$(openssl x509 -in "$W/resp.der" -inform DER -noout -enddate | cut -d= -f2)
end=$(date -u -d "$d" +%s 2>/dev/null); now=$(date -u +%s)
days=$(( (end - now + 43200) / 86400 ))
[ "$days" -ge 29 ] && [ "$days" -le 30 ]
ok $? "with no --days it is short-lived ($days days, not a year)"

# --- 2. long validity is allowed, and said out loud ---------------------
# Refusing would be wrong: an operator with an offline CA may have no way to
# reissue every month, and that is their call to make. Being quiet about it
# would also be wrong.
out=$("$CA" issue --label ca --ca-cert "$W/ca.der" --csr "$W/resp.csr" \
        --profile ocsp-responder --days 400 --out "$W/long.der" 2>&1); rc=$?
ok $rc "--days 400 is honoured rather than refused"
echo "$out" | grep -q "NOTE"
ok $? "  and is announced, with the reason it matters"
echo "$out" | grep -q "ocsp-nocheck"
ok $? "  naming ocsp-nocheck, not just warning vaguely"

# --- 3. the answer is signed by the delegate ----------------------------
out=$("$CA" ocsp-respond --label resp --ca-cert "$W/ca.der" --db "$W/rev.db" \
        --req "$W/req.der" --responder-cert "$W/resp.der" --out "$W/deleg.ocsp" 2>&1); rc=$?
ok $rc "a delegated response is produced"
openssl ocsp -respin "$W/deleg.ocsp" -resp_text -noverify 2>/dev/null \
    | grep -q "Responder Id: CN = Responder"
ok $? "  and names the responder, not the CA"
# The delegate has to travel with the answer: a client that has only the CA
# certificate cannot build the chain otherwise, and RFC 6960 4.2.2.2 is the
# reason it would want to.
n=$(openssl ocsp -respin "$W/deleg.ocsp" -resp_text -noverify 2>/dev/null | grep -c "^Certificate:")
[ "$n" = 1 ]
ok $? "  and carries the delegate in certs, so a client can chain it"

# --- 4. the control -----------------------------------------------------
# Without --responder-cert the CA answers for itself. This is here so that
# check 3 means something: it shows the responder ID changed because of the
# delegation and not because of how the tool always writes responses.
q "$CA" ocsp-respond --label ca --ca-cert "$W/ca.der" --db "$W/rev.db" \
      --req "$W/req.der" --out "$W/direct.ocsp"
openssl ocsp -respin "$W/direct.ocsp" -resp_text -noverify 2>/dev/null \
    | grep -q "Responder Id: CN = Test CA"
ok $? "without --responder-cert the CA still answers as itself"

# --- 5. what OpenSSL cannot tell us -------------------------------------
# `openssl ocsp -verify` fails on both responses, and it is important to know
# why before reading anything into it: it fails in X509_PUBKEY_get0, decoding
# the signer's public key, because the key is composite ML-DSA-65 + Ed25519 and
# OpenSSL 3.5 does not implement that algorithm. The same limit is recorded for
# CSRs, CRLs and CMS. The assertion is that BOTH fail the same way -- if only
# the delegated one failed, the delegation would be the cause and that would be
# a defect. The day OpenSSL implements composite, this check starts failing and
# should be replaced by a real verification.
openssl ocsp -respin "$W/deleg.ocsp"  -issuer "$W/ca.der" -cert "$W/leaf.der" \
    -CAfile "$W/ca.pem" -no_nonce >/dev/null 2>&1; a=$?
openssl ocsp -respin "$W/direct.ocsp" -issuer "$W/ca.der" -cert "$W/leaf.der" \
    -CAfile "$W/ca.pem" -no_nonce >/dev/null 2>&1; b=$?
[ "$a" != 0 ] && [ "$b" != 0 ]
ok $? "OpenSSL verifies neither: the composite key, not the delegation"
# Asserted, because the first version of this check passed while pointing
# -CAfile at a file that was never created: it was measuring a missing file.
# A negative assertion has to say which negative it got.
openssl ocsp -respin "$W/deleg.ocsp" -issuer "$W/ca.der" -cert "$W/leaf.der" \
    -CAfile "$W/ca.pem" -no_nonce 2>&1 | grep -q "X509_PUBKEY_get0"
ok $? "  and fails decoding the signer's key, which is that limit exactly"

# --- 6. a responder certificate without the EKU -------------------------
out=$("$CA" ocsp-respond --label ca --ca-cert "$W/ca.der" --db "$W/rev.db" \
        --req "$W/req.der" --responder-cert "$W/ca.der" --out "$W/no.ocsp" 2>&1); rc=$?
[ $rc -ne 0 ]
ok $? "a responder certificate without OCSPSigning is refused"
echo "$out" | grep -q "OCSPSigning"
ok $? "  naming the extension that is missing"
echo "$out" | grep -q "profile ocsp-responder"
ok $? "  and how to get one, not just that this one is wrong"
[ ! -s "$W/no.ocsp" ]
ok $? "  and nothing is written"

# --- 7. a delegate belonging to another CA ------------------------------
out=$("$CA" ocsp-respond --label resp --ca-cert "$W/ca.der" --db "$W/rev.db" \
        --req "$W/req.der" --responder-cert "$W/foreign.der" --out "$W/foreign.ocsp" 2>&1); rc=$?
[ $rc -ne 0 ]
ok $? "a delegate issued by another CA is refused"
echo "$out" | grep -q "not issued by"
ok $? "  saying the issuer does not match, which is what was checked"
[ ! -s "$W/foreign.ocsp" ]
ok $? "  and nothing is written"

# --- 8. the regression --------------------------------------------------
# The delegated block compares the responder's issuer against the CA's subject
# name, and did so before anything checked that --ca-cert had parsed. Without
# --responder-cert the tool printed a message; with it, the identical bad file
# was a segfault. A check wired to some of the paths that reach a state and not
# the rest -- the shape that keeps coming back.
echo "not a certificate" > "$W/junk.der"
out=$("$CA" ocsp-respond --label ca --ca-cert "$W/junk.der" --db "$W/rev.db" \
        --req "$W/req.der" --responder-cert "$W/resp.der" --out /dev/null 2>&1); rc=$?
[ $rc -lt 128 ]
ok $? "an unparseable --ca-cert is refused, not a crash (rc=$rc)"
echo "$out" | grep -q "not a certificate"
ok $? "  with the same message it gives without --responder-cert"

echo
if [ $fail -eq 0 ]; then echo "PASS : 0 failure(s)"; else echo "FAIL : $fail failure(s)"; fi
exit $((fail > 0))
