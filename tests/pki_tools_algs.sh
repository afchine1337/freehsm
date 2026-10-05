#!/bin/sh
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# pki_tools_algs.sh --- the four tools with every algorithm, checked by openssl.
#
# docs/classic-algorithms-plan.md stage 3. fhsm-csr keygen takes --alg, and
# everything after it reads the algorithm off the key. For each algorithm
# that is not the composite, this runs what an operator would -- a CA key and
# a leaf key, the root, the request, issuance, revocation and a CRL, an OCSP
# answer, a raw signature and a CMS -- and hands every file to the openssl
# command line, as a third party would: openssl req -verify, openssl verify,
# openssl crl, openssl dgst / pkeyutl -verify, openssl cms -verify, openssl
# ocsp. The composite is what tests/pki_tools_characterize.sh covers, and
# openssl cannot check it.
#
# For openssl ocsp both the exit status and the word "revoked" are required:
# 3.5 prints a status even when the response did not verify (see the OCSP
# note in include/fhsm_composite.h).
#
# Exit 0 pass, 1 fail, 77 openssl missing.
# ===========================================================================
set -u

LIB="${LIB:-./libfreehsm.so}"
TOK="${TOK:-./tools/fhsm-token}"
CSR="${CSR:-./tools/fhsm-csr}"
CA="${CA:-./tools/fhsm-ca}"
SIGN="${SIGN:-./tools/fhsm-sign}"

command -v openssl >/dev/null || { echo "pki_tools_algs: skipped, no openssl"; exit 77; }
for t in "$TOK" "$CSR" "$CA" "$SIGN"; do
    [ -x "$t" ] || { echo "pki_tools_algs: $t is not built" >&2; exit 1; }
done

export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
export OPENSSL_CONF=/dev/null
FHSM_TOKENS_DIR=$(mktemp -d); export FHSM_TOKENS_DIR
W=$(mktemp -d)
trap 'rm -rf "$FHSM_TOKENS_DIR" "$W"' EXIT

fails=0
D=""
ok() {   # ok WHAT STATUS -- on failure, what the last command said
    if [ "$2" -eq 0 ]; then printf '  %-62s OK\n' "$1"
    else
        printf '  %-62s FAIL\n' "$1"; fails=$((fails + 1))
        [ -n "$D" ] && [ -s "$D/out" ] && sed 's/^/      | /' "$D/out"
    fi
}

FHSM_SO_PIN=sopin1234 FHSM_PIN=userpin1234 "$TOK" init --label algs --module "$LIB" \
    >/dev/null 2>&1 || { echo "pki_tools_algs: token init failed"; exit 1; }
export FHSM_PIN=userpin1234
printf 'the data, as an operator would sign it\n' > "$W/data"
printf 'other data\n' > "$W/other"

for alg in ecdsa-p256 ecdsa-p384 rsa-pss rsa-pkcs1 ed25519 ml-dsa-44 ml-dsa-65 ml-dsa-87; do
    echo "[$alg]"
    D="$W/$alg"; mkdir -p "$D"
    q() { "$@" >"$D/out" 2>&1; }

    q "$CSR" keygen --label "ca-$alg" --alg "$alg" --module "$LIB" \
      && q "$CSR" keygen --label "ee-$alg" --alg "$alg" --module "$LIB"
    ok "keygen --alg $alg, a CA key and a leaf key" $?

    q "$CSR" csr --label "ca-$alg" --alg "$alg" --subject "/CN=x" --module "$LIB"
    [ $? -eq 1 ] && grep -q "belongs to keygen" "$D/out"
    ok "csr refuses --alg: the key says" $?

    q "$CSR" root --label "ca-$alg" --subject "/O=Simorgh Labs/CN=CA $alg" \
        --out "$D/ca.der" --module "$LIB" \
      && openssl x509 -inform DER -in "$D/ca.der" -out "$D/ca.pem"
    ok "root" $?

    q "$CSR" csr --label "ee-$alg" --subject "/O=Simorgh Labs/CN=ee $alg" \
        --out "$D/ee.csr" --module "$LIB" \
      && q openssl req -inform DER -in "$D/ee.csr" -verify -noout
    ok "request, and openssl req -verify accepts it" $?

    q "$CA" issue --label "ca-$alg" --ca-cert "$D/ca.der" --csr "$D/ee.csr" \
        --san "DNS:ee.example" --crl-url http://example.org/ca.crl \
        --out "$D/ee.der" --module "$LIB" \
      && openssl x509 -inform DER -in "$D/ee.der" -out "$D/ee.pem" \
      && openssl x509 -in "$D/ee.pem" -pubkey -noout > "$D/ee.pub" \
      && q openssl verify -CAfile "$D/ca.pem" "$D/ee.pem"
    ok "issued, and openssl verify accepts the chain" $?

    serial=$(openssl x509 -in "$D/ee.pem" -noout -serial | cut -d= -f2)
    q "$CA" revoke --db "$D/rev.db" --serial "$serial" --reason keyCompromise \
      && q "$CA" crl --label "ca-$alg" --ca-cert "$D/ca.der" --db "$D/rev.db" \
             --out "$D/ca.crl" --module "$LIB" \
      && openssl crl -inform DER -in "$D/ca.crl" -CAfile "$D/ca.pem" -noout >"$D/out" 2>&1 \
      && grep -q "verify OK" "$D/out" \
      && openssl crl -inform DER -in "$D/ca.crl" -noout -text | grep -q "$serial"
    ok "revoked, CRL signed, openssl crl verifies it and lists the serial" $?

    q openssl ocsp -issuer "$D/ca.pem" -cert "$D/ee.pem" -reqout "$D/req.der" -no_nonce \
      && q "$CA" ocsp-respond --label "ca-$alg" --ca-cert "$D/ca.der" --db "$D/rev.db" \
             --req "$D/req.der" --out "$D/resp.der" --module "$LIB" \
      && openssl ocsp -respin "$D/resp.der" -issuer "$D/ca.pem" -VAfile "$D/ca.pem" \
             -cert "$D/ee.pem" >"$D/out" 2>&1 \
      && grep -q ": revoked" "$D/out" && grep -q "Response verify OK" "$D/out"
    ok "OCSP: openssl ocsp verifies the answer and reads revoked" $?

    q "$SIGN" sign --label "ee-$alg" --in "$W/data" --out "$D/data.sig" --module "$LIB" \
      && q "$SIGN" verify --label "ee-$alg" --sig "$D/data.sig" --in "$W/data" --module "$LIB"
    ok "raw signature, and fhsm-sign verify accepts it" $?
    q "$SIGN" verify --label "ee-$alg" --sig "$D/data.sig" --in "$W/other" --module "$LIB"
    [ $? -eq 4 ]
    ok "  and refuses it for other data (exit 4)" $?
    case "$alg" in
        ecdsa-p256|rsa-pkcs1) q openssl dgst -sha256 -verify "$D/ee.pub" \
                                  -signature "$D/data.sig" "$W/data" ;;
        ecdsa-p384)           q openssl dgst -sha384 -verify "$D/ee.pub" \
                                  -signature "$D/data.sig" "$W/data" ;;
        rsa-pss)              q openssl dgst -sha256 -verify "$D/ee.pub" \
                                  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
                                  -sigopt rsa_mgf1_md:sha256 \
                                  -signature "$D/data.sig" "$W/data" ;;
        *)                    q openssl pkeyutl -verify -pubin -inkey "$D/ee.pub" -rawin \
                                  -in "$W/data" -sigfile "$D/data.sig" ;;
    esac
    ok "  and openssl verifies it with the certificate's key" $?

    q "$SIGN" cms --label "ee-$alg" --cert "$D/ee.der" --in "$W/data" --out "$D/data.cms" \
        --module "$LIB" \
      && q "$SIGN" cms-verify --cms "$D/data.cms" --in "$W/data"
    ok "CMS, and fhsm-sign cms-verify accepts it" $?
    q "$SIGN" cms-verify --cms "$D/data.cms" --in "$W/other"
    [ $? -eq 4 ]
    ok "  and refuses it for other data (exit 4)" $?
    q openssl cms -verify -binary -inform DER -in "$D/data.cms" -content "$W/data" \
        -noverify -out /dev/null
    ok "  and openssl cms -verify accepts it against the data" $?
done

if [ "$fails" -ne 0 ]; then
    echo "pki_tools_algs : $fails FAIL"
    exit 1
fi
echo "pki_tools_algs : PASS"
