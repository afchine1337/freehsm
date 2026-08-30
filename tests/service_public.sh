#!/bin/sh
# SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# The public listener (#111).
#
# docs/REST_API_DESIGN.md refuses anonymous requests, and that rule is right
# for every operation the authenticated socket offers. It cannot hold for the
# two the same document names: an OCSP responder answers relying parties, and a
# relying party has no client certificate to present. So there are two sockets
# rather than one rule with an exception, and this file exists to prove the
# separation is real in both directions -- that the public one asks for nothing
# and that the private one still refuses everything anonymous.

set -u

SVC="${SVC:-./service/fhsm-service}"
TOK="${TOK:-./tools/fhsm-token}"
CSR="${CSR:-./tools/fhsm-csr}"

fail=0
say() { printf '  %-58s %s\n' "$1" "$2"; }
ok()  { if [ "$1" = 0 ]; then say "$2" OK; else say "$2" FAIL; fail=$((fail+1)); fi; }

[ -x "$SVC" ] || { echo "service_public.sh: $SVC is not built" >&2; exit 2; }
# The profile the binary carries, not the profile the tree was generated for.
#
# This used to read `[ "$("$SVC" --profile)" != "interop" ]` and print "was
# built fips-strict" for anything that was not the word `interop` -- including
# the empty string you get when the binary does not run at all. Under a TSAN
# build that cannot map its shadow memory, that is exactly what happens, and
# the message sent the reader to rebuild a profile that was already correct.
# An absence in the output is not a value in the world; separate the two.
p=$("$SVC" --profile 2>/dev/null) || true
if [ -z "$p" ]; then
    echo "service_public.sh: $SVC did not run. Its own output:" >&2
    "$SVC" --profile >&2 2>&1 || true
    exit 2
fi
if [ "$p" != "interop" ]; then
    echo "service_public.sh: $SVC was built $p, which cannot sign with the" >&2
    echo "  composite mechanism. Rebuild: make PROFILE=interop" >&2
    exit 2
fi
command -v python3 >/dev/null || { echo "service_public.sh: python3 needed" >&2; exit 2; }

FHSM_TOKENS_DIR=$(mktemp -d); export FHSM_TOKENS_DIR
FHSM_INTEGRITY_ALLOW_UNSIGNED=1; export FHSM_INTEGRITY_ALLOW_UNSIGNED
: "${FHSM_SO_PIN:=sopin1234}"; export FHSM_SO_PIN
: "${FHSM_PIN:=userpin1234}";  export FHSM_PIN
D="$FHSM_TOKENS_DIR"
SOCK="$D/svc.sock"; PUB="$D/pub.sock"

PID=""
trap 'if [ -n "$PID" ]; then kill $PID 2>/dev/null; fi; rm -rf "$D"' EXIT

"$TOK" init >/dev/null 2>&1
"$CSR" keygen --label ca >/dev/null 2>&1 || {
    echo "service_public.sh: cannot generate a composite key" >&2; exit 2; }
"$CSR" root --label ca --subject "/C=FR/O=Example/CN=Root" --out "$D/ca.der" \
    >/dev/null 2>&1 || { echo "service_public.sh: cannot build a root" >&2; exit 2; }
printf '%s\n' "$FHSM_PIN" > "$D/pin"; chmod 600 "$D/pin"
printf '# policy\nCN=web01\tca\n' > "$D/policy"

echo "The public listener"
echo

# --- it refuses to be configured into something nobody can reach ---------
"$SVC" --socket "$SOCK" --ca-cert "$D/ca.der" --proxy-uid "$(id -u)" \
       --pin-file "$D/pin" --policy "$D/policy" >/dev/null 2>&1
[ $? = 2 ]
ok $? "--ca-cert without --public-socket is refused, not loaded and ignored"

"$SVC" --socket "$SOCK" --public-socket "$PUB" --ca-cert "$D/nope.der" \
       --proxy-uid "$(id -u)" --pin-file "$D/pin" --policy "$D/policy" \
       >/dev/null 2>&1
[ $? = 2 ]
ok $? "  and an unreadable certificate stops the start rather than half-serving"

"$SVC" --socket "$SOCK" --public-socket "$PUB" --ca-cert "$D/ca.der" \
       --proxy-uid "$(id -u)" --pin-file "$D/pin" --policy "$D/policy" \
       --workers 4 --pool-max 4 --public-workers 2 >/dev/null 2>&1
[ $? = 2 ]
ok $? "  and public workers count against --pool-max (4 + 2 > 4)"

"$SVC" --socket "$SOCK" --public-socket "$PUB" --ca-cert "$D/ca.der" \
       --proxy-uid "$(id -u)" --pin-file "$D/pin" --policy "$D/policy" \
       --workers 4 --pool-max 8 --public-workers 2 >>"$D/svc.log" 2>&1 &
PID=$!
i=0; while [ ! -S "$PUB" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
[ -S "$PUB" ] || { echo "service_public.sh: public socket never appeared" >&2; exit 2; }

python3 - "$PUB" "$SOCK" > "$D/out" 2>&1 <<'PUB_EOF'
import socket, sys
PUB, PRIV = sys.argv[1], sys.argv[2]

def call(sock, req):
    s = socket.socket(socket.AF_UNIX); s.settimeout(20); s.connect(sock)
    s.sendall(req.encode())
    d = b""
    while True:
        c = s.recv(65536)
        if not c: break
        d += c
    s.close()
    head, _, body = d.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode(), body, head.decode()

st, body, head = call(PUB, "GET /certificates HTTP/1.1\r\n\r\n")
print("CERT", st)
print("CERTLEN", len(body))
print("CERTDER", body[:1] == b"\x30")          # a DER SEQUENCE, not an error page
print("CERTTYPE", "application/pkix-cert" in head)
print("CERTCACHE", "Cache-Control" in head)

print("PUBHEALTH", call(PUB, "GET /health HTTP/1.1\r\n\r\n")[0])
print("PUBOCSP", call(PUB, "POST /ocsp HTTP/1.1\r\nContent-Length: 0\r\n\r\n")[0])

# Signing must not exist on the anonymous surface at all. Not 403, not 501 --
# absent, because a route that answers anything invites a second look.
print("PUBSIGN", call(PUB, "POST /sign HTTP/1.1\r\nContent-Length: 0\r\n\r\n")[0])
print("PUBVERIFY", call(PUB, "POST /verify HTTP/1.1\r\nContent-Length: 0\r\n\r\n")[0])

# An identity offered on the public socket must change nothing: it is ignored,
# not believed, or a caller could put a string of its choosing into the record.
a = call(PUB, "GET /certificates HTTP/1.1\r\n\r\n")
b = call(PUB, "GET /certificates HTTP/1.1\r\nX-FHSM-Client-Subject: CN=anyone\r\n\r\n")
print("IGNORESID", a[0] == b[0] and a[1] == b[1])

# And the private socket keeps its invariant.
print("PRIVANON", call(PRIV, "GET /health HTTP/1.1\r\n\r\n")[0])
PUB_EOF

grep -q "^CERT HTTP/1.1 200 OK" "$D/out"
ok $? "GET /certificates is served with no identity at all"

n=$(sed -n 's/^CERTLEN //p' "$D/out")
real=$(stat -c%s "$D/ca.der" 2>/dev/null || wc -c < "$D/ca.der")
[ "$n" = "$real" ]
ok $? "  and it is the whole certificate, byte for byte ($n of $real)"

grep -q "^CERTDER True" "$D/out"
ok $? "  starting with a DER SEQUENCE, not an error page"

grep -q "^CERTTYPE True" "$D/out" && grep -q "^CERTCACHE True" "$D/out"
ok $? "  typed application/pkix-cert and cacheable"

grep -q "^PUBHEALTH HTTP/1.1 200 OK" "$D/out"
ok $? "/health answers on the public socket too"

grep -q "^PUBOCSP HTTP/1.1 501" "$D/out"
ok $? "/ocsp is named and unwritten there, not silently absent"

grep -q "^PUBSIGN HTTP/1.1 404" "$D/out" && grep -q "^PUBVERIFY HTTP/1.1 404" "$D/out"
ok $? "signing and verifying do not exist on the anonymous surface"

grep -q "^IGNORESID True" "$D/out"
ok $? "an identity offered to the public socket changes nothing"

grep -q "^PRIVANON HTTP/1.1 403" "$D/out"
ok $? "and the private socket still refuses an anonymous request"

kill -TERM $PID 2>/dev/null
i=0; while kill -0 $PID 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
PID=""

# --- the audit, which is the decision most likely to be reversed by accident
# Across every log, not the first one. The three refused start attempts above
# each opened their own numbered log before exiting, so `head -1` reads a file
# that was never going to contain a start line -- the same mistake that made an
# assertion in service_budget.sh come out zero while the event was right there.
cat "$D"/audit.log* 2>/dev/null | grep -q '"public_socket"'
ok $? "the start line records that an anonymous surface exists"

# Eight public requests were made above. docs/REST_API_DESIGN.md and the note
# over serve_public() say none of them writes a line: a durable barrier per
# query hands the flood to anyone who can reach the socket.
n=$(cat "$D"/audit.log* 2>/dev/null \
    | grep -c '"event":"request_accepted"\|"event":"request_refused"')
[ "$n" -le 2 ]
ok $? "  and none of them wrote one ($n line(s), from the private probe)"

echo
if [ "$fail" = 0 ]; then echo "PASS : 0 failure(s)"; else echo "FAIL : $fail failure(s)"; fi
[ "$fail" = 0 ]
