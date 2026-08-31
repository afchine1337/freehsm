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
CA="${CA:-./tools/fhsm-ca}"

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
    echo "service_public.sh: could not generate a composite key. The tool said:" >&2
    "$CSR" keygen --label ca >&2 2>&1 || true
    echo "  Two causes give CKR_MECHANISM_INVALID (0x70) here, and this script" >&2
    echo "  cannot tell them apart from the outside:" >&2
    echo "    - the module resolved against an OpenSSL with no ML-DSA-65;" >&2
    echo "    - ./libfreehsm-fips.so was built fips-strict, where the composite" >&2
    echo "      mechanism does not exist. The service's --profile above says" >&2
    echo "      nothing about it: the service carries its profile statically." >&2
    echo "  Both are handled by going through make rather than sh:" >&2
    echo "    make PROFILE=interop service-public" >&2
    echo "  and 'make PROFILE=interop show-profile' reports the second." >&2
    exit 2
}
"$CSR" root --label ca --subject "/C=FR/O=Example/CN=Root" --out "$D/ca.der" \
    >/dev/null 2>&1 || { echo "service_public.sh: cannot build a root" >&2; exit 2; }
printf '%s\n' "$FHSM_PIN" > "$D/pin"; chmod 600 "$D/pin"
printf '# policy\nCN=web01\tca\n' > "$D/policy"

# The OCSP half needs an `openssl` to build requests and read answers back.
# Building a request touches no post-quantum algorithm -- a CertID is hashes
# of the issuer's name and of its public key *bit string*, neither of which is
# decoded -- so a distribution openssl is enough, and that is what runs here.
command -v openssl >/dev/null || { echo "service_public.sh: openssl is not on PATH" >&2; exit 2; }
openssl x509 -in "$D/ca.der" -inform DER -out "$D/ca.pem" 2>/dev/null || {
    echo "service_public.sh: openssl cannot read the root" >&2; exit 2; }

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

# The responder needs three things at once, and an incomplete set is an
# operator who meant something this daemon would not have done.
"$SVC" --socket "$SOCK" --revocation-db "$D/rev.db" --ocsp-label ca \
       --ca-cert "$D/ca.der" --proxy-uid "$(id -u)" \
       --pin-file "$D/pin" --policy "$D/policy" >/dev/null 2>&1
[ $? = 2 ]
ok $? "  and the OCSP options without --public-socket are refused"

"$SVC" --socket "$SOCK" --public-socket "$PUB" --revocation-db "$D/rev.db" \
       --ca-cert "$D/ca.der" --proxy-uid "$(id -u)" \
       --pin-file "$D/pin" --policy "$D/policy" >/dev/null 2>&1
[ $? = 2 ]
ok $? "  a database with no --ocsp-label is refused: nothing could sign"

"$SVC" --socket "$SOCK" --public-socket "$PUB" --revocation-db "$D/rev.db" \
       --ocsp-label ca --proxy-uid "$(id -u)" \
       --pin-file "$D/pin" --policy "$D/policy" >/dev/null 2>&1
[ $? = 2 ]
ok $? "  and without --ca-cert too: every CertID would come back unknown"

"$SVC" --socket "$SOCK" --public-socket "$PUB" --ca-cert "$D/ca.der" \
       --revocation-db "$D/rev.db" --ocsp-label ca \
       --proxy-uid "$(id -u)" --pin-file "$D/pin" --policy "$D/policy" \
       --workers 4 --pool-max 16 --public-workers 8 >>"$D/svc.log" 2>&1 &
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
# An empty body is not an OCSP request. RFC 6960 4.2.1: a responseStatus
# other than successful carries no responseBytes and therefore no signature,
# so this is five bytes and the client reads it as a responder error.
st, body, head = call(PUB, "POST /ocsp HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
print("PUBOCSPEMPTY", st)
print("PUBOCSPEMPTYBODY", body.hex())

# RFC 6960 A.1 also allows the request base64'd into the URL. Not served, and
# the answer names what is: a client that guessed wrong should not have to
# guess again.
st, body, head = call(PUB, "GET /ocsp HTTP/1.1\r\n\r\n")
print("PUBOCSPGET", st)
print("PUBOCSPALLOW", "Allow: POST" in head)

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

grep -q "^PUBOCSPEMPTY HTTP/1.1 200 OK" "$D/out"
ok $? "an empty POST /ocsp is answered, not refused at the transport"

grep -q "^PUBOCSPEMPTYBODY 30030a0101$" "$D/out"
ok $? "  with malformedRequest(1), unsigned, as RFC 6960 4.2.1 requires"

grep -q "^PUBOCSPGET HTTP/1.1 405" "$D/out" && grep -q "^PUBOCSPALLOW True" "$D/out"
ok $? "GET /ocsp is 405 and names POST, rather than a base64 decoder"

grep -q "^PUBSIGN HTTP/1.1 404" "$D/out" && grep -q "^PUBVERIFY HTTP/1.1 404" "$D/out"
ok $? "signing and verifying do not exist on the anonymous surface"

grep -q "^IGNORESID True" "$D/out"
ok $? "an identity offered to the public socket changes nothing"

grep -q "^PRIVANON HTTP/1.1 403" "$D/out"
ok $? "and the private socket still refuses an anonymous request"

# --- OCSP, against a real client ------------------------------------------
#
# The daemon is still running for all of this. That is the point of the block:
# the revocation below is recorded while it serves, and the answer has to
# change without anyone restarting anything. A responder that held its
# database at start would keep saying `good` for a certificate the operator
# revoked -- the failure OCSP exists to prevent, produced by the responder.

ask() {   # $1 = request DER, prints the openssl one-line status
    python3 - "$PUB" "$1" "$D/resp.der" <<'ASK_EOF'
import socket, sys
body = open(sys.argv[2], "rb").read()
s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect(sys.argv[1])
s.sendall(b"POST /ocsp HTTP/1.1\r\nContent-Type: application/ocsp-request\r\n"
          b"Content-Length: %d\r\n\r\n" % len(body) + body)
d = b""
while True:
    c = s.recv(65536)
    if not c: break
    d += c
s.close()
head, _, resp = d.partition(b"\r\n\r\n")
open(sys.argv[3], "wb").write(resp)
print(head.split(b"\r\n")[0].decode())
print("\n".join(l for l in head.decode().split("\r\n") if l.lower().startswith("content-type")))
ASK_EOF
}

openssl ocsp -issuer "$D/ca.pem" -serial 0xDEADBEEF -reqout "$D/req.der" -no_nonce \
    >/dev/null 2>&1
[ -s "$D/req.der" ]
ok $? "openssl builds a request against the composite root"

ask "$D/req.der" > "$D/askout" 2>&1
grep -q "HTTP/1.1 200 OK" "$D/askout"
ok $? "POST /ocsp is answered"

grep -qi "content-type: application/ocsp-response" "$D/askout"
ok $? "  typed application/ocsp-response, which is what a client dispatches on"

before=$(openssl ocsp -respin "$D/resp.der" -resp_text -noverify 2>/dev/null \
         | sed -n 's/.*Cert Status: *//p' | head -1)
[ "$before" = "good" ]
ok $? "  and an unrevoked serial is good (got '$before')"

openssl ocsp -respin "$D/resp.der" -resp_text -noverify 2>/dev/null \
    | grep -q "Responder Id"
ok $? "  the response names a responder, so it parses as a real BasicOCSPResponse"

# Now revoke it, with the daemon untouched.
"$CA" revoke --db "$D/rev.db" --serial DEADBEEF --reason cACompromise >/dev/null 2>&1
kill -0 $PID 2>/dev/null
ok $? "the certificate is revoked while the daemon keeps running"

ask "$D/req.der" >/dev/null 2>&1
after=$(openssl ocsp -respin "$D/resp.der" -resp_text -noverify 2>/dev/null \
        | sed -n 's/.*Cert Status: *//p' | head -1)
[ "$after" = "revoked" ]
ok $? "  and the next answer says revoked, with no restart (got '$after')"

openssl ocsp -respin "$D/resp.der" -resp_text -noverify 2>/dev/null \
    | grep -q "cACompromise"
ok $? "  carrying the reason that was recorded, not a bare status"

# A question about another authority. `unknown` is the honest answer and the
# RFC's: a responder that said `good` for an issuer it knows nothing about
# would be asserting something it cannot know.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$D/other.key" \
    -out "$D/other.pem" -days 2 -subj "/CN=Other CA" >/dev/null 2>&1
openssl ocsp -issuer "$D/other.pem" -serial 0xDEADBEEF -reqout "$D/req_other.der" \
    -no_nonce >/dev/null 2>&1
ask "$D/req_other.der" >/dev/null 2>&1
other=$(openssl ocsp -respin "$D/resp.der" -resp_text -noverify 2>/dev/null \
        | sed -n 's/.*Cert Status: *//p' | head -1)
[ "$other" = "unknown" ]
ok $? "a serial from another issuer is unknown, not good (got '$other')"

# The nonce, echoed. Without it a recorded response can be replayed until its
# nextUpdate -- which is how a revoked certificate keeps being accepted.
openssl ocsp -issuer "$D/ca.pem" -serial 0xDEADBEEF -reqout "$D/req_nonce.der" \
    >/dev/null 2>&1
ask "$D/req_nonce.der" >/dev/null 2>&1
openssl ocsp -respin "$D/resp.der" -resp_text -noverify 2>/dev/null | grep -q "Nonce"
ok $? "a nonce sent with the request comes back in the response"

# --- and all of it under load ---------------------------------------------
#
# Every assertion above asks one question and waits, which is the shape of
# test that let a `static` 8 KB buffer serve fifteen of sixteen concurrent
# clients another client's signature earlier in #111 -- found by
# ThreadSanitizer under load, not by the suite.
#
# The database is worse than a buffer: it is shared state that is *freed and
# replaced* under the readers walking it. So this runs queries from eight
# threads for three seconds while the file is rewritten every two
# milliseconds, and every answer must still be whole.
#
# Two things were learned writing it, both worth keeping.
#
# The rewrite has to be a plain file rename, not `fhsm-ca revoke`. Forking a
# process that opens the token costs tens of milliseconds; by the time the
# database changed, the queries had finished and the reload never overlapped a
# read. The real tool's write path is covered above, where the answer changing
# is the assertion.
#
# And the load has to last. With a single burst of sixteen one-shot queries,
# removing the read lock produced no ThreadSanitizer warning at all -- the
# suite would have been covering the lock by argument rather than by test.
# With this loop, removing it reports fhsm_rev_db_free() releasing entries
# another thread is still reading, four times over.
#
# To see that yourself:
#
#   make TSAN=1 PROFILE=interop service/fhsm-service
#   TSAN_OPTIONS="halt_on_error=0 log_path=/tmp/tsan.out" \
#       setarch -R sh tests/service_public.sh
#   grep -c "WARNING: ThreadSanitizer" /tmp/tsan.out.*
#
# log_path is not optional. ThreadSanitizer writes to the *daemon's* stderr,
# which goes to $D/svc.log, which the EXIT trap above deletes -- so grepping
# this script'"'"'s own output finds nothing and looks like a clean run. It cost
# an hour to notice, twice: an absence in the output is not an absence in the
# world. setarch -R is needed because TSan cannot map its shadow memory under
# some ASLR configurations, and then the binary does not start at all.
python3 - "$PUB" "$D/req.der" "$D/rev.db" > "$D/conc" 2>&1 <<'CONC_EOF'
import os, socket, sys, threading, time
PUB, REQ, DB = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(REQ, "rb").read()
head = (b"POST /ocsp HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body)) + body

done = False
answers = []          # (status line, response length)
lock = threading.Lock()

def query():
    while not done:
        try:
            s = socket.socket(socket.AF_UNIX); s.settimeout(60); s.connect(PUB)
            s.sendall(head)
            d = b""
            while True:
                c = s.recv(65536)
                if not c: break
                d += c
            s.close()
            h, _, resp = d.partition(b"\r\n\r\n")
            with lock:
                answers.append((h.split(b"\r\n")[0], resp))
        except Exception as e:
            with lock:
                answers.append((b"EXC " + str(e).encode(), b""))

reloads = 0
def churn():
    global reloads
    n = 2
    while not done:
        with open(DB + ".churn", "w") as f:
            f.write("crlNumber %d\nAABBCC 2026010100000%dZ -\n" % (n, n % 10))
        os.replace(DB + ".churn", DB)          # atomic, as fhsm-ca is
        n += 1; reloads += 1
        time.sleep(0.002)

ts = [threading.Thread(target=query) for _ in range(8)]
ch = threading.Thread(target=churn)
ch.start()
for t in ts: t.start()
time.sleep(3)
done = True
for t in ts: t.join()
ch.join()

ok    = sum(1 for st, _ in answers if st == b"HTTP/1.1 200 OK")
whole = sum(1 for _, b in answers if len(b) > 100 and b[:1] == b"\x30")
print("LOADTOTAL", len(answers))
print("LOADOK", ok)
print("LOADWHOLE", whole)
print("LOADRELOADS", reloads)
CONC_EOF

total=$(sed -n 's/^LOADTOTAL //p' "$D/conc")
okn=$(sed -n 's/^LOADOK //p' "$D/conc")
whole=$(sed -n 's/^LOADWHOLE //p' "$D/conc")
reloads=$(sed -n 's/^LOADRELOADS //p' "$D/conc")

[ "${total:-0}" -gt 20 ]
ok $? "the responder is asked ${total:-0} times over three seconds"

[ "${reloads:-0}" -gt 100 ]
ok $? "  while the database is replaced under it ${reloads:-0} times"

[ "$okn" = "$total" ]
ok $? "  every query is answered ($okn of $total)"

[ "$whole" = "$total" ]
ok $? "  and every response is whole, none truncated by shared state"

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
