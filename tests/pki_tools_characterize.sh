#!/bin/sh
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# pki_tools_characterize.sh --- what the four PKI tools do, written down.
#
# Not a test that passes or fails. It drives every subcommand of fhsm-token,
# fhsm-csr, fhsm-ca and fhsm-sign -- and their main refusals -- and prints a
# normalised transcript: each command's exit code, its messages, and the ASN.1
# shape of what it wrote. Run it before a change and after it, and diff:
#
#     sh tests/pki_tools_characterize.sh > reports/gui/before.txt
#     ...change...
#     sh tests/pki_tools_characterize.sh > reports/gui/after.txt
#     diff reports/gui/before.txt reports/gui/after.txt
#
# Written for docs/fhsm-gui-plan.md stage 0, which moves the tools'
# orchestration into a library: the tools must behave exactly as before, and
# the existing tests reach only part of what they do -- nothing ran
# `fhsm-sign sign`, `cms` or `cms-verify`.
#
# What is masked, because it differs between two runs of unchanged code:
# signature and key bytes, serial numbers (drawn from the token's DRBG),
# dates, and temporary paths. What is kept: exit codes, every message's text,
# and the structure of every artefact -- types, nesting, object identifiers,
# names. Run it twice on the same tree first; if the two transcripts differ,
# this script masks too little, and that has to be fixed before it is trusted.
#
# Needs a module with the composite mechanism: make PROFILE=all-mechanisms all
# ===========================================================================
set -u

LIB="${LIB:-./libfreehsm.so}"
TOK="${TOK:-./tools/fhsm-token}"
CSR="${CSR:-./tools/fhsm-csr}"
CA="${CA:-./tools/fhsm-ca}"
SIGN="${SIGN:-./tools/fhsm-sign}"

for t in "$TOK" "$CSR" "$CA" "$SIGN"; do
    [ -x "$t" ] || { echo "pki_tools_characterize.sh: $t is not built -- make PROFILE=all-mechanisms all" >&2; exit 2; }
done
command -v openssl >/dev/null || { echo "pki_tools_characterize.sh: openssl is not on PATH" >&2; exit 2; }

export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
export OPENSSL_CONF=/dev/null
FHSM_TOKENS_DIR=$(mktemp -d); export FHSM_TOKENS_DIR
W=$(mktemp -d)
trap 'rm -rf "$FHSM_TOKENS_DIR" "$W"' EXIT

# Values that change between runs of the same code, replaced by placeholders.
mask() {
    sed -E \
        -e 's#^(   out\| )[A-Za-z0-9+/]{16,}={0,2}$#\1<BASE64>#' \
        -e "s#$W#<W>#g" -e "s#$FHSM_TOKENS_DIR#<TOKENS>#g" \
        -e 's#/tmp/tmp\.[A-Za-z0-9]+#<TMP>#g' \
        -e 's/[0-9]{12,14}Z/<TIME>/g' \
        -e 's/[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4} GMT/<DATE>/g' \
        -e 's/[0-9A-Fa-f]{8,}/<HEX>/g' \
        -e 's/(public|private) [0-9]+/\1 <H>/g'
}
# The PEM body lines carry the key and the signature, which change every run;
# their number, which follows from the size, does not, and is kept.
# The module's own notices (the integrity-bypass NOTE among them) are left in:
# they are the same on every run, and deleting a multi-line block by pattern
# is how a script ends up deleting the messages it exists to compare.

# The ASN.1 shape of a DER file: nesting, types, OIDs and names, no bytes.
shape() {
    f=$1
    if [ ! -s "$f" ]; then echo "    (no file)"; return; fi
    openssl asn1parse -inform DER -in "$f" 2>&1 \
      | sed -E 's/^ *[0-9]+:d= *([0-9]+) +hl= *[0-9]+ +l= *[0-9]+ +(cons|prim): */    d=\1 \2 /' \
      | sed -E -e 's/(INTEGER|BIT STRING|OCTET STRING|UTCTIME|GENERALIZEDTIME) *:.*/\1 :<V>/' \
               -e 's/\[HEX DUMP\]:.*/[HEX DUMP]/' \
      | mask
}

n=0
# run NAME CMD...  -- one step: exit code, then stdout and stderr, masked.
run() {
    name=$1; shift
    n=$((n+1))
    "$@" >"$W/out" 2>"$W/err"; rc=$?
    echo "== $n. $name"
    echo "   exit $rc"
    if [ -s "$W/out" ] && ! LC_ALL=C grep -q "[^[:print:][:space:]]" "$W/out"; then
        sed 's/^/   out| /' "$W/out" | mask
    elif [ -s "$W/out" ]; then
        echo "   out| ($(wc -c < "$W/out" | tr -d ' ') bytes, binary)"
    fi
    [ -s "$W/err" ] && sed 's/^/   err| /' "$W/err" | mask
    return 0
}

echo "pki_tools_characterize: $(basename "$TOK") $(basename "$CSR") $(basename "$CA") $(basename "$SIGN")"
echo

# --- fhsm-token --------------------------------------------------------------
run "token info, nothing initialised"        "$TOK" info --module "$LIB"
run "token init without FHSM_SO_PIN"         env -u FHSM_SO_PIN FHSM_PIN=userpin1234 "$TOK" init --module "$LIB"
run "token init, PIN too short"              env FHSM_SO_PIN=1 FHSM_PIN=userpin1234 "$TOK" init --module "$LIB"
run "token init, --pin refused"              "$TOK" init --pin x --module "$LIB"
run "token init"                             env FHSM_SO_PIN=sopin1234 FHSM_PIN=userpin1234 "$TOK" init --label char --module "$LIB"
run "token init again, no --force"           env FHSM_SO_PIN=sopin1234 FHSM_PIN=userpin1234 "$TOK" init --label char --module "$LIB" --slot 0
run "token info"                             "$TOK" info --module "$LIB"

export FHSM_PIN=userpin1234

# --- fhsm-csr ----------------------------------------------------------------
run "csr without FHSM_PIN"                   env -u FHSM_PIN "$CSR" keygen --label ca --module "$LIB"
run "csr --pin refused"                      "$CSR" keygen --label ca --pin x --module "$LIB"
run "keygen ca"                              "$CSR" keygen --label ca --module "$LIB"
run "keygen ee"                              "$CSR" keygen --label ee --module "$LIB"
run "keygen resp"                            "$CSR" keygen --label resp --module "$LIB"
run "keygen dup (1)"                         "$CSR" keygen --label dup --module "$LIB"
run "keygen dup (2)"                         "$CSR" keygen --label dup --module "$LIB"
run "csr for a missing key"                  "$CSR" csr --label nope --subject "/CN=x" --module "$LIB"
run "csr for an ambiguous label"             "$CSR" csr --label dup --subject "/CN=x" --module "$LIB"
run "csr ee"                                 "$CSR" csr --label ee --subject "/C=FR/O=Simorgh Labs/CN=ee" --out "$W/ee.csr" --module "$LIB"
echo "   shape ee.csr"; shape "$W/ee.csr"
run "csr resp"                               "$CSR" csr --label resp --subject "/CN=Responder" --out "$W/resp.csr" --module "$LIB"
run "csr ee, PEM to stdout"                  "$CSR" csr --label ee --subject "/CN=ee" --pem --module "$LIB"
run "root ca"                                "$CSR" root --label ca --subject "/C=FR/O=Simorgh Labs/CN=Test CA" --days 3650 --serial 1 --out "$W/ca.der" --module "$LIB"
echo "   shape ca.der"; shape "$W/ca.der"

# --- fhsm-ca -----------------------------------------------------------------
run "issue ee"                               "$CA" issue --label ca --ca-cert "$W/ca.der" --csr "$W/ee.csr" --san "DNS:ee.example,IP:192.0.2.1" --crl-url http://example.org/ca.crl --days 365 --out "$W/ee.der" --module "$LIB"
echo "   shape ee.der"; shape "$W/ee.der"
run "issue with an https CRL URL"            "$CA" issue --label ca --ca-cert "$W/ca.der" --csr "$W/ee.csr" --crl-url https://example.org/ca.crl --out "$W/bad.der" --module "$LIB"
run "issue responder"                        "$CA" issue --label ca --ca-cert "$W/ca.der" --csr "$W/resp.csr" --profile ocsp-responder --out "$W/resp.der" --module "$LIB"
echo "   shape resp.der"; shape "$W/resp.der"
serial=$(openssl x509 -inform DER -in "$W/ee.der" -noout -serial 2>/dev/null | cut -d= -f2)
run "revoke, unknown reason"                 "$CA" revoke --db "$W/rev.db" --serial "$serial" --reason nonsense
run "revoke ee"                              "$CA" revoke --db "$W/rev.db" --serial "$serial" --reason keyCompromise --date 20260101000000Z
run "revoke ee again"                        "$CA" revoke --db "$W/rev.db" --serial "$serial" --reason keyCompromise --date 20260101000000Z
echo "   rev.db"; mask < "$W/rev.db" | sed 's/^/    /'
run "crl"                                    "$CA" crl --label ca --ca-cert "$W/ca.der" --db "$W/rev.db" --days 30 --out "$W/ca.crl" --module "$LIB"
echo "   shape ca.crl"; shape "$W/ca.crl"
echo "   rev.db after crl"; mask < "$W/rev.db" | sed 's/^/    /'
openssl ocsp -issuer "$W/ca.der" -cert "$W/ee.der" -reqout "$W/req.der" -no_nonce >/dev/null 2>&1
run "ocsp-respond as the CA"                 "$CA" ocsp-respond --label ca --ca-cert "$W/ca.der" --db "$W/rev.db" --req "$W/req.der" --days 7 --out "$W/direct.ocsp" --module "$LIB"
echo "   shape direct.ocsp"; shape "$W/direct.ocsp"
run "ocsp-respond delegated"                 "$CA" ocsp-respond --label resp --ca-cert "$W/ca.der" --db "$W/rev.db" --req "$W/req.der" --responder-cert "$W/resp.der" --out "$W/deleg.ocsp" --module "$LIB"
echo "   shape deleg.ocsp"; shape "$W/deleg.ocsp"
run "ocsp-respond, responder without EKU"    "$CA" ocsp-respond --label ca --ca-cert "$W/ca.der" --db "$W/rev.db" --req "$W/req.der" --responder-cert "$W/ca.der" --out "$W/no.ocsp" --module "$LIB"

# --- fhsm-sign ---------------------------------------------------------------
printf 'The quick brown fox jumps over the lazy dog\n' > "$W/data"
printf 'The quick brown fox jumps over the lazy cat\n' > "$W/other"
run "sign"                                   "$SIGN" sign --label ee --in "$W/data" --out "$W/data.sig" --module "$LIB"
echo "   data.sig: $(wc -c < "$W/data.sig" | tr -d ' ') bytes"
run "verify"                                 "$SIGN" verify --label ee --sig "$W/data.sig" --in "$W/data" --module "$LIB"
run "verify, other data"                     "$SIGN" verify --label ee --sig "$W/data.sig" --in "$W/other" --module "$LIB"
run "verify, missing key"                    "$SIGN" verify --label nope --sig "$W/data.sig" --in "$W/data" --module "$LIB"
run "cms"                                    "$SIGN" cms --label ee --cert "$W/ee.der" --in "$W/data" --out "$W/data.cms" --module "$LIB"
echo "   shape data.cms"; shape "$W/data.cms"
run "cms-verify"                             "$SIGN" cms-verify --cms "$W/data.cms" --in "$W/data"
run "cms-verify, other data"                 "$SIGN" cms-verify --cms "$W/data.cms" --in "$W/other"
run "sign --pin refused"                     "$SIGN" sign --label ee --pin x --module "$LIB"

# --- usage -------------------------------------------------------------------
run "token, no arguments"                    "$TOK"
run "csr, no arguments"                      "$CSR"
run "ca, no arguments"                       "$CA"
run "sign, no arguments"                     "$SIGN"
