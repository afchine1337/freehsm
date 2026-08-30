#!/bin/sh
# SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# The revocation database (#163).
#
# It had no test. Everything around it did -- the CRL encoder had a
# differential test against OpenSSL, the delegated responder had twenty
# assertions -- but the file those two read was exercised only incidentally,
# by tests that wrote one entry and never looked at the reading again.
#
# That is how `revoke` came to compare serials byte for byte while the
# responder compared them ignoring leading zeros: nothing asked the two the
# same question. Moving both into src/fhsm_revocation.c put them side by side
# and the difference became visible; this file is what keeps it visible.

set -u

CA="${CA:-./tools/fhsm-ca}"

fail=0
say() { printf '  %-58s %s\n' "$1" "$2"; }
ok()  { if [ "$1" = 0 ]; then say "$2" OK; else say "$2" FAIL; fail=$((fail+1)); fi; }

[ -x "$CA" ] || { echo "revocation_db.sh: $CA is not built" >&2; exit 2; }

D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
FHSM_TOKENS_DIR="$D"; export FHSM_TOKENS_DIR

echo "The revocation database"
echo

# --- recording -------------------------------------------------------------
"$CA" revoke --db "$D/r.db" --serial 4A3B2C1D --reason keyCompromise >/dev/null 2>&1
ok $? "a serial is recorded"

grep -q "^4A3B2C1D .* keyCompromise$" "$D/r.db"
ok $? "  in a line an operator can read, with the reason as a name"

grep -q "^crlNumber 0$" "$D/r.db"
ok $? "  and the CRL number lives in the same file as the entries"

# --- the same certificate, written another way -----------------------------
# DER prepends a zero octet to keep a top-bit-set magnitude positive, so the
# same serial reaches this tool in two forms depending on where the operator
# copied it from. Both name one certificate.
out=$("$CA" revoke --db "$D/r.db" --serial 004A3B2C1D 2>&1); rc=$?
[ "$rc" = 5 ]
ok $? "the same serial with a leading zero is the same certificate (rc=$rc)"

echo "$out" | grep -q "already revoked"
ok $? "  and is refused as already revoked, not silently added"

[ "$(grep -c '4A3B2C1D' "$D/r.db")" = 1 ]
ok $? "  so it appears once, and every future CRL lists it once"

# --- refusals --------------------------------------------------------------
out=$("$CA" revoke --db "$D/r.db" --serial F0O0 2>&1)
echo "$out" | grep -q "even number of hex digits"
ok $? "a serial that is not hex is refused"

out=$("$CA" revoke --db "$D/r.db" --serial FF --reason removeFromCRL 2>&1)
echo "$out" | grep -q "delta CRLs"
ok $? "removeFromCRL is refused, saying it belongs to delta CRLs"

echo "$out" | grep -q "keyCompromise"
ok $? "  and the accepted names are listed rather than left to guess"

out=$("$CA" revoke --db "$D/r.db" --serial FF --date 2026 2>&1)
echo "$out" | grep -q "YYYYMMDDHHMMSSZ"
ok $? "a date in another format is refused, naming the one accepted"

# --- a database that is only partly understood ------------------------------
# The whole file or nothing. A half-read database produces a list missing
# revocations, which is a signed assurance that a compromised certificate is
# still good -- worse than no list at all.
printf 'crlNumber 1\n4A3B2C1D 20260101000000Z -\nZZZZ 20260101000000Z -\n' > "$D/bad.db"
out=$("$CA" revoke --db "$D/bad.db" --serial AA 2>&1); rc=$?
[ "$rc" = 3 ]
ok $? "a malformed line stops the whole read (rc=$rc)"

echo "$out" | grep -q "line 3"
ok $? "  naming the line, so it can be fixed rather than hunted"

echo "$out" | grep -q "Nothing was read"
ok $? "  and saying nothing was read, not that some of it was"

[ ! -f "$D/bad.db.tmp" ] && grep -q "^ZZZZ" "$D/bad.db"
ok $? "  and the file is left exactly as it was"

printf 'crlNumber 1\ncrlNumber 2\n' > "$D/twice.db"
"$CA" revoke --db "$D/twice.db" --serial AA >/dev/null 2>&1
[ $? = 3 ]
ok $? "two crlNumbers is a refusal: a number that went backwards is the"
say  "  failure the number exists to prevent" ""

# --- a first run is not an error, an unreadable file is ---------------------
"$CA" revoke --db "$D/sub/nope.db" --serial AA >/dev/null 2>&1
[ $? != 0 ]
ok $? "a database in a directory that does not exist fails, not silently"

: > "$D/locked.db"; chmod 000 "$D/locked.db"
if [ "$(id -u)" = 0 ]; then
    say "an unreadable database is an error, not a first run (skipped: root)" OK
else
    out=$("$CA" revoke --db "$D/locked.db" --serial AA 2>&1); rc=$?
    [ "$rc" = 2 ]
    ok $? "an unreadable database is an error, not an empty first run (rc=$rc)"
fi
chmod 644 "$D/locked.db"

echo
if [ "$fail" = 0 ]; then echo "PASS : 0 failure(s)"; else echo "FAIL : $fail failure(s)"; fi
[ "$fail" = 0 ]
