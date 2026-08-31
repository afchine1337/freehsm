#!/bin/sh
# SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# The refusal budget (#111, docs/RATE_LIMIT.md job 2).
#
# Separate from service_guards.sh because it needs the service stopped and
# started again: the property that matters most here is that a count survives
# a restart, and a suite that never restarts the daemon cannot see it. This is
# the service's analogue of tests/test_throttle_reboot.c, which exists because
# the token once stored a deadline and read it back as thirty days.

set -u

SVC="${SVC:-./service/fhsm-service}"
TOK="${TOK:-./tools/fhsm-token}"
CSR="${CSR:-./tools/fhsm-csr}"

fail=0
say() { printf '  %-58s %s\n' "$1" "$2"; }
ok()  { if [ "$1" = 0 ]; then say "$2" OK; else say "$2" FAIL; fail=$((fail+1)); fi; }

[ -x "$SVC" ] || { echo "service_budget.sh: $SVC is not built" >&2; exit 2; }
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
    echo "service_budget.sh: $SVC did not run. Its own output:" >&2
    "$SVC" --profile >&2 2>&1 || true
    exit 2
fi
if [ "$p" != "interop" ]; then
    echo "service_budget.sh: $SVC was built $p, which cannot sign with the" >&2
    echo "  composite mechanism. Rebuild: make PROFILE=interop" >&2
    exit 2
fi
command -v python3 >/dev/null || { echo "service_budget.sh: python3 needed" >&2; exit 2; }

FHSM_TOKENS_DIR=$(mktemp -d); export FHSM_TOKENS_DIR
FHSM_INTEGRITY_ALLOW_UNSIGNED=1; export FHSM_INTEGRITY_ALLOW_UNSIGNED
: "${FHSM_SO_PIN:=sopin1234}"; export FHSM_SO_PIN
: "${FHSM_PIN:=userpin1234}";  export FHSM_PIN
SOCK="$FHSM_TOKENS_DIR/svc.sock"

PID=""
trap 'if [ -n "$PID" ]; then kill $PID 2>/dev/null; fi;
      rm -rf "$FHSM_TOKENS_DIR" "$SOCK"' EXIT

"$TOK" init >/dev/null 2>&1
"$CSR" keygen --label tls-web01 >/dev/null 2>&1 || {
    echo "service_budget.sh: could not generate a composite key. The tool said:" >&2
    "$CSR" keygen --label tls-web01 >&2 2>&1 || true
    echo "  Two causes give CKR_MECHANISM_INVALID (0x70) here, and this script" >&2
    echo "  cannot tell them apart from the outside:" >&2
    echo "    - the module resolved against an OpenSSL with no ML-DSA-65;" >&2
    echo "    - ./libfreehsm-fips.so was built fips-strict, where the composite" >&2
    echo "      mechanism does not exist. The service's --profile above says" >&2
    echo "      nothing about it: the service carries its profile statically." >&2
    echo "  Both are handled by going through make rather than sh:" >&2
    echo "    make PROFILE=interop service-budget" >&2
    echo "  and 'make PROFILE=interop show-profile' reports the second." >&2
    exit 2
}
printf '%s\n' "$FHSM_PIN" > "$FHSM_TOKENS_DIR/pin"
chmod 600 "$FHSM_TOKENS_DIR/pin"
printf '# policy\nCN=web01\ttls-web01\n' > "$FHSM_TOKENS_DIR/policy"
printf 'the quick brown fox' > "$FHSM_TOKENS_DIR/msg.bin"

start() {
    "$SVC" --socket "$SOCK" --proxy-uid "$(id -u)" \
           --pin-file "$FHSM_TOKENS_DIR/pin" --policy "$FHSM_TOKENS_DIR/policy" \
           --workers 4 --pool-max 8 >>"$FHSM_TOKENS_DIR/svc.log" 2>&1 &
    PID=$!
    i=0
    while [ ! -S "$SOCK" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
    [ -S "$SOCK" ] || { echo "service_budget.sh: socket never appeared" >&2; exit 2; }
}
stop() {
    kill -TERM $PID 2>/dev/null
    i=0; while kill -0 $PID 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
    PID=""
    rm -f "$SOCK"
}

echo "The refusal budget"
echo

start

python3 - "$SOCK" "$FHSM_TOKENS_DIR" > "$FHSM_TOKENS_DIR/b1.out" 2>&1 <<'PHASE1'
import socket, sys, time
SOCK, DIR = sys.argv[1], sys.argv[2]
body = open(DIR + "/msg.bin", "rb").read()

def req(key, subj="CN=web01"):
    s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect(SOCK)
    s.sendall(("POST /sign HTTP/1.1\r\nX-FHSM-Client-Subject: %s\r\n"
               "X-FHSM-Key: %s\r\nContent-Length: %d\r\n\r\n"
               % (subj, key, len(body))).encode() + body)
    d = b""
    while True:
        c = s.recv(65536)
        if not c: break
        d += c
    s.close()
    head = d.split(b"\r\n\r\n")[0].decode()
    ra = [l.split(":")[1].strip() for l in head.split("\r\n")
          if l.startswith("Retry-After")]
    return head.split("\r\n")[0], (ra[0] if ra else "")

# Four probes: inside the free allowance, so a typo costs nothing.
free = [req("ghost-%d" % i)[0] for i in range(4)]
print("FREE403", sum(1 for f in free if "403" in f))
print("FREESERVED", "200" in req("tls-web01")[0])

# The fifth crosses. It is still a 403 -- the crossing changes what happens
# next, not what this request is told.
st, _ = req("ghost-x")
print("CROSSING", st)

# And now even a legitimate request waits. Deliberate: the interval belongs to
# the identity, not to the probing, which is what makes a stolen certificate
# cost its holder something.
st, ra = req("tls-web01")
print("AFTERCROSS", st, "RA", ra)

t = time.time()
time.sleep(1.3)
st, _ = req("tls-web01")
print("AFTERWAIT", st, "SLEPT", round(time.time() - t, 1))

# A client that keeps trying, which is what clients do. Every one of these
# retries is refused by the budget, and a refusal by the budget must not push
# the deadline forward -- otherwise retrying is what keeps you out, the control
# tightens under its own refusals, and the delay never expires for anyone who
# actually wants service. Sleeping once and asking once cannot see that: it
# takes a retry loop.
req("ghost-w")                      # earn a fresh interval
t = time.time(); got = None
while time.time() - t < 4.0:
    st, _ = req("tls-web01")
    if "200" in st:
        got = round(time.time() - t, 1)
        break
    time.sleep(0.1)
print("RETRYLOOP", got if got is not None else "never")
PHASE1

grep -q "^FREE403 4" "$FHSM_TOKENS_DIR/b1.out"
ok $? "four refusals inside the free allowance are just refusals"

grep -q "^FREESERVED True" "$FHSM_TOKENS_DIR/b1.out"
ok $? "  and the identity is still served normally"

grep -q "^CROSSING HTTP/1.1 403" "$FHSM_TOKENS_DIR/b1.out"
ok $? "the refusal that crosses the allowance is still a plain 403"

grep -q "^AFTERCROSS HTTP/1.1 429 Too Many Requests RA 1" "$FHSM_TOKENS_DIR/b1.out"
ok $? "  after it, even an authorised request waits, with Retry-After"

grep -q "^AFTERWAIT HTTP/1.1 200 OK" "$FHSM_TOKENS_DIR/b1.out"
ok $? "  and the delay expires: this is a throttle, never a lock"

grep -q "^RETRYLOOP never" "$FHSM_TOKENS_DIR/b1.out" && r=1 || r=0
[ "$r" = 0 ]
ok $? "  a client that keeps retrying still gets through ($(sed -n 's/^RETRYLOOP //p' "$FHSM_TOKENS_DIR/b1.out")s)"

# --- what is on disk -----------------------------------------------------
[ -f "$FHSM_TOKENS_DIR/budget" ]
ok $? "the count reached the disk before any clean shutdown"

# Six: the five that crossed the allowance, plus the one the retry loop above
# earned itself a fresh interval with. Pinned exactly rather than loosely,
# because a count that drifts is the thing this file exists to notice.
n=$(awk -F'\t' '/^[0-9]/ {print $1}' "$FHSM_TOKENS_DIR/budget" | head -1)
[ "$n" = 6 ]
ok $? "  and it is the count and nothing else, six ($n)"

# docs/RATE_LIMIT.md: persist the count, derive the delay. A deadline in any
# clock domain is the defect the token bought -- CLOCK_MONOTONIC restarts at
# boot, CLOCK_REALTIME moves under `date -s`. Nothing but counts and subjects
# may appear here.
awk -F'\t' '/^[0-9]/ { if (NF != 2) exit 1 } END { exit 0 }' "$FHSM_TOKENS_DIR/budget"
ok $? "  no second field: no deadline, no timestamp, nothing derived"

# --- the crossing was announced, once ------------------------------------
# Across every log file, not one of them: each run of the module opens its own
# numbered log, and the restart below makes a second. Reading only the first
# is how an assertion comes out zero while the event is right there.
nlim=$(cat "$FHSM_TOKENS_DIR"/audit.log* 2>/dev/null \
       | grep -c '"event":"identity_limited"')
[ "$nlim" = 1 ]
ok $? "the crossing was announced exactly once ($nlim)"

cat "$FHSM_TOKENS_DIR"/audit.log* 2>/dev/null \
    | grep '"event":"identity_limited"' \
    | grep -q '"refusals":"5"'
ok $? "  carrying the count that earned it"

cat "$FHSM_TOKENS_DIR"/audit.log* 2>/dev/null \
    | grep '"event":"identity_limited"' | grep -q '"delay_s":"1"'
ok $? "  and the delay derived from it"

# --- the restart, which is the whole reason this file exists -------------
stop
before=$(cat "$FHSM_TOKENS_DIR/budget")
start
after=$(cat "$FHSM_TOKENS_DIR/budget")

[ "$before" = "$after" ]
ok $? "a restart does not rewrite the budget"

grep -q "budget restored for" "$FHSM_TOKENS_DIR/svc.log"
ok $? "  and the service says it restored one"

python3 - "$SOCK" "$FHSM_TOKENS_DIR" > "$FHSM_TOKENS_DIR/b2.out" 2>&1 <<'PHASE2'
import socket, sys
SOCK, DIR = sys.argv[1], sys.argv[2]
body = open(DIR + "/msg.bin", "rb").read()
def req(key, subj="CN=web01"):
    s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect(SOCK)
    s.sendall(("POST /sign HTTP/1.1\r\nX-FHSM-Client-Subject: %s\r\n"
               "X-FHSM-Key: %s\r\nContent-Length: %d\r\n\r\n"
               % (subj, key, len(body))).encode() + body)
    d = b""
    while True:
        c = s.recv(65536)
        if not c: break
        d += c
    s.close()
    head = d.split(b"\r\n\r\n")[0].decode()
    ra = [l.split(":")[1].strip() for l in head.split("\r\n")
          if l.startswith("Retry-After")]
    return head.split("\r\n")[0], (ra[0] if ra else "")

# One more refusal after the restart. If the count had been lost this would be
# the first, well inside the allowance, and the answer would be a plain 403
# with no delay behind it.
req("ghost-y")
st, ra = req("tls-web01")
print("POSTRESTART", st, "RA", ra)

# Twenty more probes as fast as they will go. Most never reach /sign at all:
# they are refused by the budget itself, and a request refused by the budget is
# not charged to it -- otherwise the control would tighten under its own
# refusals and never let go. So this does not drive the count to the ceiling;
# it shows that probing cannot. What is asserted is the bound.
for i in range(20):
    req("ghost-z%d" % i)
st, ra = req("tls-web01")
print("BOUNDED", st, "RA", ra)
PHASE2

grep -q "^POSTRESTART HTTP/1.1 429" "$FHSM_TOKENS_DIR/b2.out"
ok $? "the count survived the restart: one more refusal still throttles"

ra=$(sed -n 's/^BOUNDED .* RA //p' "$FHSM_TOKENS_DIR/b2.out")
[ -n "$ra" ] && [ "$ra" -le 60 ]
ok $? "  and the delay stays under the cap of 60 s (Retry-After: $ra)"

# The count barely moved during those twenty probes, and that is the property.
n=$(awk -F'\t' '/^[0-9]/ {print $1}' "$FHSM_TOKENS_DIR/budget" | head -1)
[ -n "$n" ] && [ "$n" -lt 20 ]
ok $? "  because a request the budget refused is not charged to it (count $n)"

stop

echo
if [ "$fail" = 0 ]; then echo "PASS : 0 failure(s)"; else echo "FAIL : $fail failure(s)"; fi
[ "$fail" = 0 ]
