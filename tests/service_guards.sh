#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Simorgh Labs
#
# The service's guards, driven through the socket an operator would use.
#
# Everything here is a refusal except two lines, which is the point: at this
# stage the service performs no cryptography, so what there is to test is what
# it turns away. docs/REST_API_DESIGN.md calls refusals "the part of an API
# that ages well", and they are cheapest to get right before anything depends
# on them.
#
# It drives the real binary over a real unix socket rather than calling the
# parser directly. The parser is not the guard -- SO_PEERCRED is, and that
# cannot be tested without a socket.
#
#   sh tests/service_guards.sh
#
# Needs `make service/fhsm-service` and a provisioned token.
#
# NOT COVERED HERE: the SO_PEERCRED check, which is the guard the whole design
# rests on. Testing it needs a second uid connecting to the socket, and this
# suite runs as one user. It is asserted by inspection and by the mutation
# below being absent, which is not the same thing and is said rather than
# glossed over. An integration test under two accounts would close it.
set -u
SVC="${SVC:-./service/fhsm-service}"
TOK="${TOK:-./tools/fhsm-token}"
CSR="${CSR:-./tools/fhsm-csr}"
SIGN="${SIGN:-./tools/fhsm-sign}"
fail=0

say() { printf '  %-58s %s\n' "$1" "$2"; }
ok()  { if [ "$1" = 0 ]; then say "$2" OK; else say "$2" FAIL; fail=$((fail+1)); fi; }

[ -x "$SVC" ] || { echo "service_guards.sh: $SVC is not built -- run 'make service/fhsm-service'" >&2; exit 2; }
[ -x "$TOK" ] || { echo "service_guards.sh: $TOK is not built -- run 'make all'" >&2; exit 2; }
command -v python3 >/dev/null || { echo "service_guards.sh: python3 is needed to speak HTTP" >&2; exit 2; }

export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
export FHSM_SO_PIN="${FHSM_SO_PIN:-sopin1234}"
export FHSM_PIN="${FHSM_PIN:-userpin1234}"
FHSM_TOKENS_DIR=$(mktemp -d); export FHSM_TOKENS_DIR
SOCK=$(mktemp -u /tmp/fhsm-guards.XXXXXX.sock)
PID=""   # set once the service starts; the trap runs before that on an
         # early exit, and an unset variable there is an error under set -u
trap 'if [ -n "$PID" ]; then kill $PID 2>/dev/null; fi; rm -rf "$FHSM_TOKENS_DIR" "$SOCK"' EXIT

"$TOK" init --label guards >/dev/null 2>&1
# The service refuses to start without a PIN source (docs/DAEMON_PIN.md), and
# a test rig is exactly the case --pin-file exists for. A deployment uses
# LoadCredentialEncrypted= and never has this file.
printf '%s\n' "$FHSM_PIN" > "$FHSM_TOKENS_DIR/pin"
chmod 600 "$FHSM_TOKENS_DIR/pin"

# Two keys and a policy that names exactly one of them. The second key exists
# so that "not authorised" and "no such key" can be told apart -- or rather,
# proved indistinguishable, which is what docs/RATE_LIMIT.md asks for.
# Ask the binary under test, not a sibling. fhsm-csr is built separately and
# can be interop while the service is fips-strict; the guard that consulted it
# passed while /sign failed for exactly the reason the guard exists to catch.
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
    echo "service_guards.sh: $SVC did not run. Its own output:" >&2
    "$SVC" --profile >&2 2>&1 || true
    exit 2
fi
if [ "$p" != "interop" ]; then
    echo "service_guards.sh: $SVC was built $p, which cannot sign with the" >&2
    echo "  composite mechanism. Rebuild: make PROFILE=interop" >&2
    exit 2
fi
"$CSR" keygen --label tls-web01 >/dev/null 2>&1 || {
    echo "service_guards.sh: could not generate a composite key. The tool said:" >&2
    "$CSR" keygen --label tls-web01 >&2 2>&1 || true
    echo "  Two causes give CKR_MECHANISM_INVALID (0x70) here, and this script" >&2
    echo "  cannot tell them apart from the outside:" >&2
    echo "    - the module resolved against an OpenSSL with no ML-DSA-65;" >&2
    echo "    - ./libfreehsm-fips.so was built fips-strict, where the composite" >&2
    echo "      mechanism does not exist. The service's --profile above says" >&2
    echo "      nothing about it: the service carries its profile statically." >&2
    echo "  Both are handled by going through make rather than sh:" >&2
    echo "    make PROFILE=interop service-guards" >&2
    echo "  and 'make PROFILE=interop show-profile' reports the second." >&2
    exit 2
}
"$CSR" keygen --label secret-ca >/dev/null 2>&1
# ghost-key is permitted by the policy and was never generated. Without it
# every refusal below fails on the policy check alone, and the branch that
# equalises "authorised but absent" with "not authorised" is never taken --
# a mutation distinguishing the two passed the test until this line existed.
printf '# fhsm-service authorisation policy v1\n# SUBJECT\tKEY-LABEL\nCN=web01\ttls-web01\nCN=web01\tghost-key\nCN=web02\ttls-web01\n' \
    > "$FHSM_TOKENS_DIR/policy"
printf 'the quick brown fox' > "$FHSM_TOKENS_DIR/msg.bin"

echo "The service's guards"
echo

"$SVC" --socket "$SOCK" --proxy-uid "$(id -u)" \
      --pin-file "$FHSM_TOKENS_DIR/pin" --policy "$FHSM_TOKENS_DIR/policy" \
      --workers 4 --pool-max 8 \
      >"$FHSM_TOKENS_DIR/svc.log" 2>&1 &
PID=$!
# Wait for the socket rather than sleeping a guessed amount: a fixed sleep is
# how a suite becomes flaky on a loaded machine.
i=0; while [ ! -S "$SOCK" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
[ -S "$SOCK" ] || { echo "service_guards.sh: the service never created its socket" >&2; cat "$FHSM_TOKENS_DIR/svc.log" >&2; exit 2; }

# One request, one connection, first line of the response on stdout.
req() {
    python3 - "$SOCK" "$1" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
try:
    s.connect(sys.argv[1])
    s.sendall(sys.argv[2].encode().decode('unicode_escape').encode('latin-1'))
    print(s.recv(400).decode(errors='replace').split('\r\n')[0])
except Exception as e:
    print(f'NO RESPONSE ({e})')
finally:
    s.close()
PY
}

# The same, but the whole head. req() keeps only the status line, which is what
# nearly every assertion here wants; an assertion about a header needs the rest,
# and reading it out of req() would have been reading a line that was thrown
# away -- as one of these did, silently, until the response was printed raw.
reqh() {
    python3 - "$SOCK" "$1" <<'PYH'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
try:
    s.connect(sys.argv[1])
    s.sendall(sys.argv[2].encode().decode('unicode_escape').encode('latin-1'))
    print(s.recv(4000).decode(errors='replace').split('\r\n\r\n')[0])
except Exception as e:
    print(f'NO RESPONSE ({e})')
finally:
    s.close()
PYH
}

H='X-FHSM-Client-Subject: CN=web01\r\n'

r=$(req "GET /health HTTP/1.1\r\nHost: x\r\n${H}\r\n")
echo "$r" | grep -q "200 OK"; ok $? "a valid request reaches /health"

r=$(req "GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
echo "$r" | grep -q "403"; ok $? "no identity header is refused"

r=$(req "GET /health HTTP/1.1\r\n${H}${H}\r\n")
echo "$r" | grep -q "400"; ok $? "  and a repeated one too, rather than resolved"

r=$(req "GET /sign HTTP/1.1\r\n${H}\r\n")
echo "$r" | grep -q "405"; ok $? "GET /sign is 405, neither 404 nor 501"

r=$(req "GET /certificates HTTP/1.1\r\n${H}\r\n")
echo "$r" | grep -q "404"; ok $? "/certificates is 404 here, not 501: it is on the public listener"
h=$(reqh "GET /certificates HTTP/1.1\r\n${H}\r\n")
echo "$h" | grep -q "Link: </certificates>"
ok $? "  and the answer names the listener that has it"

r=$(req "GET /token HTTP/1.1\r\n${H}\r\n")
echo "$r" | grep -q "200 OK"; ok $? "/token reaches the module through a pooled session"

r=$(req "GET /nope HTTP/1.1\r\n${H}\r\n")
echo "$r" | grep -q "404"; ok $? "an unknown route is 404"

r=$(req "DELETE /health HTTP/1.1\r\n${H}\r\n")
echo "$r" | grep -q "400"; ok $? "a method outside GET and POST is refused"

r=$(req "GET /health HTTP/1.0\r\n${H}\r\n")
echo "$r" | grep -q "400"; ok $? "HTTP/1.0 is refused rather than tolerated"

r=$(req "POST /sign HTTP/1.1\r\n${H}Transfer-Encoding: chunked\r\n\r\n")
echo "$r" | grep -q "400"; ok $? "chunked transfer is refused, not implemented"

r=$(req "POST /sign HTTP/1.1\r\n${H}Content-Length: 999999999\r\n\r\n")
echo "$r" | grep -q "413"; ok $? "an oversized body is refused before it is read"

r=$(req "POST /sign HTTP/1.1\r\n${H}Content-Length: 3\r\nContent-Length: 4\r\n\r\nabc")
echo "$r" | grep -q "400"; ok $? "two Content-Length headers are refused"

r=$(req "GET /health HTTP/1.1\r\nX-FHSM-Client-Subject: CN=\"a\r\n\r\n")
echo "$r" | grep -q "200\|400"; ok $? "a quote in the subject does not break the line"

# SIGTERM, and then check the process actually went. Asserting only that
# service_stop reached the log was not enough: under this script the daemon
# happened to exit for other reasons even when it was ignoring the signal, so
# the assertion passed against a build that a service manager would have had
# to SIGKILL. Measured separately: with SA_RESTART the process is still alive
# two seconds after SIGTERM and writes no stop line at all.
# --- /sign: the first route that reaches the module ---------------------
python3 - "$SOCK" "$FHSM_TOKENS_DIR" > "$FHSM_TOKENS_DIR/sign.out" 2>&1 <<'SIGN_EOF'
import socket, sys, threading
SOCK, DIR = sys.argv[1], sys.argv[2]

def req(key, subj, body):
    s = socket.socket(socket.AF_UNIX); s.settimeout(20); s.connect(SOCK)
    s.sendall(("POST /sign HTTP/1.1\r\nX-FHSM-Client-Subject: %s\r\n"
               "X-FHSM-Key: %s\r\nContent-Length: %d\r\n\r\n"
               % (subj, key, len(body))).encode() + body)
    d = b""
    while True:
        c = s.recv(65536)
        if not c: break
        d += c
    s.close(); return d

body = open(DIR + "/msg.bin", "rb").read()
r = req("tls-web01", "CN=web01", body)
head, _, sig = r.partition(b"\r\n\r\n")
print("STATUS", head.split(b"\r\n")[0].decode())
print("SIGLEN", len(sig))
open(DIR + "/msg.sig", "wb").write(sig)

# The three refusals a caller would try to tell apart.
a = req("secret-ca",   "CN=web01",    body)   # real key, not in the policy
b = req("no-such-key", "CN=web01",    body)   # not in the policy, and absent
c = req("tls-web01",   "CN=attacker", body)   # real and permitted, wrong caller
d = req("ghost-key",   "CN=web01",    body)   # permitted by the policy, absent
print("SAME", a == b == c == d)
print("REFUSED", a.split(b"\r\n")[0].decode())

# Sixteen at once, each holding a pooled session for the length of an ML-DSA
# signature. This is the load /token was too cheap to produce.
# Each thread signs a *different* message and its signature is kept, so that
# a buffer shared between workers shows up as a signature over somebody else's
# message. Verifying only the sequential signature above missed exactly that:
# a static 8 KB buffer in do_sign(), found by ThreadSanitizer and not here.
out = {}; bar = threading.Barrier(16)
def go(i):
    m = ("concurrent message %02d -- " % i).encode() + body
    open("%s/c%02d.bin" % (DIR, i), "wb").write(m)
    bar.wait()
    try:
        r = req("tls-web01", "CN=web01", m)
        head, _, sg = r.partition(b"\r\n\r\n")
        st = head.split(b"\r\n")[0].decode()
        # Only a served request produces a signature. A 429 body is "refused",
        # and writing it to a .sig would fail verification for a reason that
        # has nothing to do with the buffer this checks.
        if "200" in st:
            open("%s/c%02d.sig" % (DIR, i), "wb").write(sg)
        out[i] = st
    except Exception as e:
        out[i] = "ERR " + str(e)
ts = [threading.Thread(target=go, args=(i,)) for i in range(16)]
[t.start() for t in ts]; [t.join() for t in ts]
served = sum(1 for o in out.values() if "200" in o)
print("CONCURRENT", served)
print("OTHERSTATUS", sum(1 for o in out.values() if "200" not in o and "429" not in o))
SIGN_EOF

grep -q "STATUS HTTP/1.1 200 OK" "$FHSM_TOKENS_DIR/sign.out"
ok $? "/sign returns a signature for an authorised subject and key"

n=$(sed -n 's/^SIGLEN //p' "$FHSM_TOKENS_DIR/sign.out")
[ -n "$n" ] && [ "$n" -gt 3000 ]
ok $? "  and the body is a composite signature, not an error page ($n bytes)"

"$SIGN" verify --label tls-web01 --in "$FHSM_TOKENS_DIR/msg.bin" \
        --sig "$FHSM_TOKENS_DIR/msg.sig" >/dev/null 2>&1
ok $? "  which verifies against the module loaded directly"

grep -q "^SAME True" "$FHSM_TOKENS_DIR/sign.out"
ok $? "every refusal, absent key included, is one answer byte for byte"

grep -q "REFUSED HTTP/1.1 403" "$FHSM_TOKENS_DIR/sign.out"
ok $? "  and that answer is 403"

# Sixteen at once from one identity. They no longer all succeed, and that is
# the fairness cap doing its job: the guard above deliberately made a request
# under CN="a, which is served and therefore present, so CN=web01 is held to
# --workers minus one. The contract asserted here is what remains true --
# every answer is either a signature or a 429, several get through, and each
# signature is over its own message.
n=$(sed -n 's/^CONCURRENT //p' "$FHSM_TOKENS_DIR/sign.out")
[ -n "$n" ] && [ "$n" -ge 3 ]
ok $? "concurrent requests are served up to the fairness cap ($n of 16)"

grep -q "^OTHERSTATUS 0" "$FHSM_TOKENS_DIR/sign.out"
ok $? "  and the rest are 429, not some other failure"

bad=0
i=0
while [ $i -lt 16 ]; do
    f=$(printf '%s/c%02d' "$FHSM_TOKENS_DIR" $i)
    [ -f "$f.sig" ] || { i=$((i+1)); continue; }
    "$SIGN" verify --label tls-web01 --in "$f.bin" --sig "$f.sig" >/dev/null 2>&1 \
        || bad=$((bad+1))
    i=$((i+1))
done
[ "$bad" = 0 ]
ok $? "  and each signature is over its own message, not another's ($bad bad)"

# --- /verify: the only way to check a composite signature without our tools
python3 - "$SOCK" "$FHSM_TOKENS_DIR" > "$FHSM_TOKENS_DIR/ver.out" 2>&1 <<'VER_EOF'
import socket, sys
SOCK, DIR = sys.argv[1], sys.argv[2]
msg = open(DIR + "/msg.bin", "rb").read()

def call(path, hdrs, body, subj="CN=web01"):
    s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect(SOCK)
    h = "POST %s HTTP/1.1\r\nX-FHSM-Client-Subject: %s\r\n" % (path, subj)
    for k, v in hdrs:
        h += "%s: %s\r\n" % (k, v)
    h += "Content-Length: %d\r\n\r\n" % len(body)
    s.sendall(h.encode() + body)
    d = b""
    while True:
        c = s.recv(65536)
        if not c: break
        d += c
    s.close()
    head, _, payload = d.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode(), payload

st, sig = call("/sign", [("X-FHSM-Key", "tls-web01")], msg)
L = [("X-FHSM-Key", "tls-web01"), ("X-FHSM-Signature-Length", str(len(sig)))]

print("VALID", call("/verify", L, sig + msg)[0])

bad = bytearray(sig); bad[100] ^= 1
print("FLIPPED", call("/verify", L, bytes(bad) + msg)[0])
print("OTHERMSG", call("/verify", L, sig + b"a different message")[0])

# Malformed splits first, and refusals last. Three refusals push CN=web01 out
# of the budget's free allowance, and everything after that comes back 429 --
# which is the budget working, and would have made these assertions read as
# failures of /verify. Ordering a test around another control's state is worth
# saying out loud, because the next assertion added here will hit it too.
print("NOLEN", call("/verify", [("X-FHSM-Key", "tls-web01")], sig + msg)[0])
print("COVERS", call("/verify", [("X-FHSM-Key", "tls-web01"),
      ("X-FHSM-Signature-Length", str(len(sig) + len(msg)))], sig + msg)[0])
print("ZERO", call("/verify", [("X-FHSM-Key", "tls-web01"),
      ("X-FHSM-Signature-Length", "0")], sig + msg)[0])

# The refusals must stay one answer here too, or /verify becomes the oracle
# /sign refuses to be.
a = call("/verify", [("X-FHSM-Key", "secret-ca"),
                     ("X-FHSM-Signature-Length", str(len(sig)))], sig + msg)
b = call("/verify", [("X-FHSM-Key", "no-such-key"),
                     ("X-FHSM-Signature-Length", str(len(sig)))], sig + msg)
c = call("/verify", L, sig + msg, subj="CN=attacker")
print("SAMEREFUSAL", a == b == c, a[0])
VER_EOF

grep -q "^VALID HTTP/1.1 200 OK" "$FHSM_TOKENS_DIR/ver.out"
ok $? "/verify accepts a signature this service just made"

grep -q "^FLIPPED HTTP/1.1 422" "$FHSM_TOKENS_DIR/ver.out"
ok $? "  one flipped bit is 422, not 200"

grep -q "^OTHERMSG HTTP/1.1 422" "$FHSM_TOKENS_DIR/ver.out"
ok $? "  and so is the same signature over another message"

grep -q "^SAMEREFUSAL True HTTP/1.1 403" "$FHSM_TOKENS_DIR/ver.out"
ok $? "  its refusals are one answer too: /verify is not an oracle"

grep -q "^NOLEN HTTP/1.1 400" "$FHSM_TOKENS_DIR/ver.out"
ok $? "  a body with no X-FHSM-Signature-Length is refused"

grep -q "^COVERS HTTP/1.1 400" "$FHSM_TOKENS_DIR/ver.out"
ok $? "  a split that leaves no message is refused"

grep -q "^ZERO HTTP/1.1 400" "$FHSM_TOKENS_DIR/ver.out"
ok $? "  and so is a zero-length signature"

# --- fairness: one identity must not take every worker -------------------
# The pool cannot be the contended resource here -- main() refuses to start
# with --pool-max below --workers, so a session is always free. Measured with
# the wait instrumented: zero pool waits under 32 concurrent requests. What
# runs out is the worker, so the cap is on requests in flight per identity.
python3 - "$SOCK" "$FHSM_TOKENS_DIR" > "$FHSM_TOKENS_DIR/fair.out" 2>&1 <<'FAIR_EOF'
import socket, sys, threading, time
SOCK, DIR = sys.argv[1], sys.argv[2]

def req(subj):
    s = socket.socket(socket.AF_UNIX); s.settimeout(60); s.connect(SOCK)
    body = open(DIR + "/msg.bin", "rb").read()
    s.sendall(("POST /sign HTTP/1.1\r\nX-FHSM-Client-Subject: %s\r\n"
               "X-FHSM-Key: tls-web01\r\nContent-Length: %d\r\n\r\n"
               % (subj, len(body))).encode() + body)
    d = b""
    while True:
        c = s.recv(65536)
        if not c: break
        d += c
    s.close(); return d.split(b"\r\n")[0].decode()

# CN=web01 asks once so that it is a known identity; without this the cap
# cannot apply, and that is deliberate -- a lone client is never capped.
req("CN=web01")

stop = threading.Event(); served = [0]; refused = [0]
def hog():
    while not stop.is_set():
        try:
            st = req("CN=web02")
            if   "200" in st: served[0]  += 1
            elif "429" in st: refused[0] += 1
        except Exception: pass
hs = [threading.Thread(target=hog) for _ in range(12)]
[t.start() for t in hs]
time.sleep(1.5)
quiet = [req("CN=web01") for _ in range(6)]
stop.set(); [t.join() for t in hs]

print("HOGSERVED", served[0])
print("HOGREFUSED", refused[0])
print("QUIET429", sum(1 for q in quiet if "429" in q))
print("QUIET200", sum(1 for q in quiet if "200" in q))
FAIR_EOF

n=$(sed -n 's/^HOGREFUSED //p' "$FHSM_TOKENS_DIR/fair.out")
[ -n "$n" ] && [ "$n" -gt 0 ]
ok $? "a saturating identity is capped and refused ($n refusals)"

grep -q "^QUIET429 0" "$FHSM_TOKENS_DIR/fair.out"
ok $? "  while the other identity is never refused"

grep -q "^QUIET200 6" "$FHSM_TOKENS_DIR/fair.out"
ok $? "  and is served throughout"

n=$(sed -n 's/^HOGSERVED //p' "$FHSM_TOKENS_DIR/fair.out")
[ -n "$n" ] && [ "$n" -gt 0 ]
ok $? "  the capped identity is throttled, not locked out ($n served)"

# --- a peer that says nothing ---------------------------------------------
#
# This is the assertion the suite did not have, and its absence was not
# theoretical. Measured on the code before this block existed: with
# --workers 4, four connections that sent no bytes took /health from 9.8 ms to
# a timeout and held it there for as long as they stayed open, with nothing
# written to the audit log. Every worker sat in a blocking read() waiting for
# a header that was not coming. At sixty-nine such connections the accept
# backlog filled and connect() itself returned EAGAIN, so an honest client was
# refused by the kernel before the daemon saw it.
#
# Eight is used rather than four: with four the service could recover by
# chance if a worker happened to be free. Twice the worker count cannot.
python3 - "$SOCK" > "$FHSM_TOKENS_DIR/mute.out" 2>&1 <<'MUTE_EOF'
import socket, sys, time
SOCK = sys.argv[1]

def health(timeout=30):
    t0 = time.perf_counter()
    try:
        s = socket.socket(socket.AF_UNIX); s.settimeout(timeout)
        s.connect(SOCK)
        s.sendall(b"GET /health HTTP/1.1\r\nX-FHSM-Client-Subject: CN=web01\r\n\r\n")
        d = s.recv(200); s.close()
        return d.split(b"\r\n")[0].decode(), (time.perf_counter() - t0) * 1000
    except Exception as e:
        return type(e).__name__, (time.perf_counter() - t0) * 1000

held = []
for i in range(8):
    s = socket.socket(socket.AF_UNIX); s.connect(SOCK); held.append(s)
time.sleep(0.2)
st, ms = health()
print("MUTESTATUS", st)
print("MUTEMS", int(ms))

# What the silent peer is told. It is a refusal with a reason, not a socket
# closed under it: the peer that is holding a worker is exactly the one that
# should be able to find out why it was let go.
held[0].settimeout(20)
try:
    d = held[0].recv(300)
    print("MUTEGOT", d.split(b"\r\n")[0].decode())
except Exception as e:
    print("MUTEGOT", type(e).__name__)
for s in held:
    try: s.close()
    except Exception: pass
time.sleep(0.3)
st, ms = health()
print("AFTERSTATUS", st)

# A body that arrives slowly is still a body. The deadline for the rest of the
# request is ten seconds precisely so that this keeps working; only the wait
# for the *first* byte is short, because a proxy that has connected has its
# request in hand and nothing to compute.
def slowbody(n, gap):
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_UNIX); s.settimeout(40); s.connect(SOCK)
    s.sendall(b"POST /sign HTTP/1.1\r\nX-FHSM-Client-Subject: CN=web01\r\n"
              b"X-FHSM-Key: tls-web01\r\nContent-Length: %d\r\n\r\n" % n)
    try:
        for i in range(n):
            time.sleep(gap); s.sendall(b"x")
        d = s.recv(400)
        st = d.split(b"\r\n")[0].decode()
    except Exception as e:
        st = "cut:" + type(e).__name__
    s.close()
    return st, time.perf_counter() - t0

st, t = slowbody(8, 0.5)
print("SLOWOK", st)
print("SLOWSECS", round(t, 1))
st, t = slowbody(40, 0.6)
print("SLOWCUT", st)
print("SLOWCUTSECS", round(t, 1))
MUTE_EOF

grep -q "^MUTESTATUS HTTP/1.1 200 OK" "$FHSM_TOKENS_DIR/mute.out"
ok $? "eight connections that send nothing do not stop the service"

n=$(sed -n 's/^MUTEMS //p' "$FHSM_TOKENS_DIR/mute.out")
[ -n "$n" ] && [ "$n" -lt 6000 ]
ok $? "  and the wait is bounded by the deadline, not by them (${n:-?} ms)"

grep -q "^MUTEGOT HTTP/1.1 408" "$FHSM_TOKENS_DIR/mute.out"
ok $? "  the silent peer is told why it was let go, not just cut off"

grep -q "^AFTERSTATUS HTTP/1.1 200 OK" "$FHSM_TOKENS_DIR/mute.out"
ok $? "  and the service is unharmed once they are gone"

grep -q "^SLOWOK HTTP/1.1 200 OK" "$FHSM_TOKENS_DIR/mute.out"
ok $? "a body delivered over $(sed -n 's/^SLOWSECS //p' "$FHSM_TOKENS_DIR/mute.out") s is still signed"

grep -q "^SLOWCUT cut:" "$FHSM_TOKENS_DIR/mute.out"
ok $? "  but one still arriving at $(sed -n 's/^SLOWCUTSECS //p' "$FHSM_TOKENS_DIR/mute.out") s is not"

kill -TERM $PID 2>/dev/null
i=0; while kill -0 $PID 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done
if kill -0 $PID 2>/dev/null; then
    say "SIGTERM is obeyed" FAIL; fail=$((fail+1)); kill -9 $PID 2>/dev/null
else
    say "SIGTERM is obeyed" OK
fi
wait $PID 2>/dev/null

# --- what the log kept -------------------------------------------------
# The guards are only half the property. The other half is that every refusal
# left a record naming a reason, because a service that turns requests away
# silently is one nobody can operate.
# Every log, not the first one. Each opening of the module creates its own
# numbered file -- `fhsm-token init` made one and the service made another --
# because a hash chain has exactly one author. A test that looked at
# audit.log.000001 would be reading the provisioning tool's chain and
# concluding the service logged nothing.
LOG=$(grep -l '"event":"service_start"' "$FHSM_TOKENS_DIR"/audit.log* 2>/dev/null | head -1)
[ -n "$LOG" ]; ok $? "the service opened an audit log of its own"

if [ -n "$LOG" ]; then
    n=$(grep -c '"event":"request_refused"' "$LOG" 2>/dev/null)
    [ -n "$n" ] || n=0
    [ "$n" -ge 8 ]; ok $? "every refusal was recorded ($n lines)"

    grep -q '"event":"service_stop"' "$LOG"
    ok $? "  and so is the stop, which means SIGTERM was seen"

    # The actor is the point of the whole field: a refusal that happened
    # before an identity was established must not claim one.
    python3 - "$LOG" <<'PY' >/dev/null 2>&1
import json, sys
bad = 0
for line in open(sys.argv[1]):
    d = json.loads(line)
    if d["event"] == "request_refused" and d["params"].get("reason") == "no_identity":
        if d["actor"] != "":
            bad += 1
sys.exit(1 if bad else 0)
PY
    ok $? "  a refusal for no identity claims no actor"

    python3 - "$LOG" <<'PY' >/dev/null 2>&1
import json, sys
ok_ = any(json.loads(l)["actor"] == "CN=web01"
          for l in open(sys.argv[1])
          if json.loads(l)["event"] == "request_accepted")
sys.exit(0 if ok_ else 1)
PY
    ok $? "  an accepted request carries the certificate subject"

    grep -q '"event":"login_ok"' "$LOG"
    ok $? "  the daemon logged in once, from the credential"

    # docs/RATE_LIMIT.md rule 2: a burst of refusals must produce a handful of
    # lines, not one per refusal. Measured before this was written: a written
    # refusal cost 48.8 ms, so the log was both the flood and the reason the
    # cap did nothing. Asserted as "at most a handful" rather than an exact
    # count, because how many bursts open depends on timing.
    nref=$(grep -c '"reason":"too_many_in_flight"' "$LOG")
    nres=$(grep -c '"event":"identity_resumed"' "$LOG")
    nhog=$(sed -n 's/^HOGREFUSED //p' "$FHSM_TOKENS_DIR/fair.out")
    [ "$nref" -ge 1 ] && [ "$nref" -le 4 ]
    ok $? "  $nhog refusals wrote $nref line(s), not one each"

    [ "$nres" -ge 1 ]
    ok $? "  and the burst was closed by an identity_resumed line ($nres)"

    python3 - "$LOG" <<'SUP_EOF'
import json, sys
tot = 0
for line in open(sys.argv[1]):
    d = json.loads(line)
    if d.get("event") == "identity_resumed":
        tot += int(d.get("params", {}).get("suppressed", 0))
sys.exit(0 if tot > 0 else 1)
SUP_EOF
    ok $? "  carrying the count of what it stood for"

    # How many distinct pooled sessions signed. Not asserted to exceed one:
    # whether the pool grows depends on how the sixteen requests overlap, and
    # an assertion would be demanding a race resolve a particular way. Printed
    # so that the number is visible when it changes.
    npool=$(python3 - "$LOG" <<'POOL_EOF'
import json, sys
n = set()
for line in open(sys.argv[1]):
    d = json.loads(line)
    if d.get("event") == "sign" and d.get("result") == "OK":
        n.add(d.get("session"))
print(len(n))
POOL_EOF
)
    say "  distinct pooled sessions used for signing: $npool" "--"
fi

echo
if [ $fail -eq 0 ]; then echo "PASS : 0 failure(s)"; else echo "FAIL : $fail failure(s)"; fi
exit $((fail > 0))
