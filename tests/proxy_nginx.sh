#!/usr/bin/env bash
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# proxy_nginx.sh --- the proxy half of #169: nginx, configured as the
#                    deployment guide says, measured.
#
# WHY
#
# RELEASE_v2.0.0-beta.md: "no deployment of it has been made or measured".
# docs/DEPLOYING_THE_SERVICE.md describes the proxy in detail -- which header
# carries identity, what happens when the operator omits one line, what the
# subject string looks like -- and every sentence of it was a prediction.
#
# The security boundary is in the proxy. A header nginx never rewrites is
# indistinguishable, from inside the daemon, from one nginx wrote; the guide
# says so itself and calls that row "the one nothing in the daemon can catch".
# So this tests nginx, from the position of whatever is behind it.
#
# WHY THE BACKEND IS NOT fhsm-service
#
# Deliberate, and the honest scope of this file. What is being asked -- does
# nginx replace or merge, what string does it emit -- is answered by anything
# that reports the headers it received. Putting the daemon here would add a
# token, a PIN, a pool and a policy to a test whose subject is nginx.
#
# Running fhsm-service behind this configuration is the OTHER half of #169 and
# is NOT done. A first attempt at it made three wrong assumptions in a row --
# an endpoint /healthz that does not exist, an "actor" field in the daemon's
# stderr that is not there (audit goes through fhsm_audit_event), and the idea
# that /health enforces the policy, when it answers 200 without authorisation.
# That half needs a signing request against /sign and a key label. It is
# written down here rather than half-shipped.
#
# WHAT THIS ALREADY CORRECTED IN THE GUIDE (2026-09-02, nginx 1.18.0)
#
# The failure-mode table said:
#
#     | proxy sets the header, client also sends one | two headers | 400 |
#
# Measured: ONE header arrives, carrying the proxy's value. proxy_set_header
# replaces -- which is what the code comment three lines below that same table
# says in so many words. The table and its own commentary contradicted each
# other and the table was the wrong one. The daemon's 400-on-duplicate is
# still worth having, because a proxy that ADDS rather than replaces would
# produce it, but nginx configured as documented never does.
#
# The subject-format table was right, exactly.
#
# REQUIREMENTS: nginx, openssl, curl, python3. Skips when nginx is absent --
# not every machine running the suite is a deployment host, and a skip that
# announces itself is better than a pass that means nothing.
# ===========================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

NGINX="${NGINX:-$(command -v nginx || true)}"
if [ -z "$NGINX" ]; then
    echo "proxy_nginx.sh: no nginx on this host -- SKIPPED (this is not a pass)"
    exit 0
fi

fails=0
ok()  { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
bad() { printf '  \033[31mNON\033[0m   %s\n' "$1"; fails=$((fails+1)); }

W=$(mktemp -d)
cleanup() {
    [ -f "$W/nginx.pid" ] && kill "$(cat "$W/nginx.pid")" 2>/dev/null
    [ -n "${BPID:-}" ] && kill "$BPID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W"/{ca,logs,run,tmp/{cbt,pt,ft,ut,st}}

# --- a throwaway CA and a client identity with a full DN -------------------
# Full DN on purpose: it is what makes the RFC 4514 reordering visible, and
# the reordering is what makes a policy file written from `openssl x509`
# output refuse every request.
( cd "$W/ca"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 1 \
      -subj "/C=FR/O=Example/CN=Test CA" >/dev/null 2>&1
  for n in server web01; do
      openssl req -newkey rsa:2048 -nodes -keyout $n.key -out $n.csr \
          -subj "/C=FR/O=Example/CN=$n" >/dev/null 2>&1
      openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
          -out $n.crt -days 1 >/dev/null 2>&1
  done )

# --- the stand-in: reports which headers arrived, and how many -------------
cat > "$W/backend.py" <<'ENDPY'
import os, socket, sys, threading
p = sys.argv[1]
try: os.unlink(p)
except FileNotFoundError: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(p); os.chmod(p, 0o666); s.listen(64)
def one(c):
    d = b""
    while b"\r\n\r\n" not in d:
        b = c.recv(4096)
        if not b:
            c.close(); return
        d += b
    hdrs = [l.decode() for l in d.split(b"\r\n")[1:]
            if l.lower().startswith(b"x-fhsm-client-subject")]
    body = "count=%d\n" % len(hdrs) + "".join(
        "hdr=%s\n" % h.split(":", 1)[1].strip() for h in hdrs)
    c.sendall(("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n%s" % (len(body), body)).encode())
    c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=one, args=(c,), daemon=True).start()
ENDPY
python3 "$W/backend.py" "$W/run/service.sock" >"$W/logs/backend.log" 2>&1 &
BPID=$!
for _ in $(seq 1 50); do [ -S "$W/run/service.sock" ] && break; sleep 0.1; done
[ -S "$W/run/service.sock" ] || { bad "the stand-in never bound its socket"; exit 1; }

# --- nginx, configured exactly as the guide prints it ----------------------
cat > "$W/nginx.conf" <<EOF
daemon off;
error_log $W/logs/error.log warn;
pid $W/nginx.pid;
events { worker_connections 64; }
http {
    access_log $W/logs/access.log;
    client_body_temp_path $W/tmp/cbt; proxy_temp_path $W/tmp/pt;
    fastcgi_temp_path $W/tmp/ft; uwsgi_temp_path $W/tmp/ut; scgi_temp_path $W/tmp/st;
    server {
        listen 127.0.0.1:18443 ssl;
        ssl_certificate     $W/ca/server.crt;
        ssl_certificate_key $W/ca/server.key;
        ssl_client_certificate $W/ca/ca.crt;
        # \`optional\` rather than \`on\` so the no-certificate request reaches
        # the \`if\` and can be asserted. A deployment uses \`on\`.
        ssl_verify_client optional;

        location /set/ {
            if (\$ssl_client_verify != SUCCESS) { return 403; }
            proxy_set_header X-FHSM-Client-Subject \$ssl_client_s_dn;
            proxy_pass http://unix:$W/run/service.sock:/;
        }
        location /legacy/ {
            if (\$ssl_client_verify != SUCCESS) { return 403; }
            proxy_set_header X-FHSM-Client-Subject \$ssl_client_s_dn_legacy;
            proxy_pass http://unix:$W/run/service.sock:/;
        }
        # The same thing with the one line omitted. Nobody should ship this;
        # it is here because a claim about a hole is worth no more than a
        # claim about a guard, and the guide makes one.
        location /unguarded/ {
            proxy_pass http://unix:$W/run/service.sock:/;
        }
    }
}
EOF
"$NGINX" -t -c "$W/nginx.conf" -p "$W" >"$W/logs/nginxtest.log" 2>&1 \
  || { bad "nginx rejected the documented configuration -- see $W/logs/nginxtest.log"
       sed 's/^/        /' "$W/logs/nginxtest.log"; exit 1; }
"$NGINX" -c "$W/nginx.conf" -p "$W" >"$W/logs/nginx.out" 2>&1 &
for _ in $(seq 1 50); do [ -f "$W/nginx.pid" ] && break; sleep 0.1; done

C=(curl -sk --cert "$W/ca/web01.crt" --key "$W/ca/web01.key")
RFC4514='CN=web01,O=Example,C=FR'
LEGACY='/C=FR/O=Example/CN=web01'

echo "== nginx as docs/DEPLOYING_THE_SERVICE.md configures it =="

out=$("${C[@]}" https://127.0.0.1:18443/set/)
if [ "$out" = "count=1
hdr=$RFC4514" ]; then
    ok "PROXYSET  one header, the proxy's: \`$RFC4514\`"
else
    bad "PROXYSET  got:
$(printf '%s' "$out" | sed 's/^/        /')"
fi

# The guide's table predicted two headers and a 400 here. It is one.
out=$("${C[@]}" -H "X-FHSM-Client-Subject: CN=attacker,O=Example,C=FR" \
      https://127.0.0.1:18443/set/)
if [ "$out" = "count=1
hdr=$RFC4514" ]; then
    ok "SPOOF     a client-sent header is REPLACED, not merged -- one header,"
    printf '        the proxy'"'"'s value. The guide'"'"'s table said two and a 400.\n'
else
    bad "SPOOF     the client's header was not cleanly replaced:
$(printf '%s' "$out" | sed 's/^/        /')"
fi

out=$("${C[@]}" -H "X-FHSM-Client-Subject: CN=attacker,O=Example,C=FR" \
      https://127.0.0.1:18443/unguarded/)
if [ "$out" = "count=1
hdr=CN=attacker,O=Example,C=FR" ]; then
    ok "UNGUARDED without the line, the client's own subject arrives intact"
else
    bad "UNGUARDED expected the client's subject to arrive, got:
$(printf '%s' "$out" | sed 's/^/        /')"
fi

code=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:18443/set/)
[ "$code" = 403 ] && ok "NOCERT    no client certificate: nginx returns 403" \
                  || bad "NOCERT    expected 403, got $code"

out=$("${C[@]}" https://127.0.0.1:18443/legacy/)
if [ "$out" = "count=1
hdr=$LEGACY" ]; then
    ok "LEGACY    \$ssl_client_s_dn_legacy gives \`$LEGACY\`, the openssl form"
else
    bad "LEGACY    got:
$(printf '%s' "$out" | sed 's/^/        /')"
fi

echo
echo "  --  not covered here: fhsm-service itself behind this configuration."
echo "      The policy file matches byte for byte, so a policy written as"
echo "      \`$LEGACY\` refuses a request nginx labels"
echo "      \`$RFC4514\`. Asserting that needs /sign and a"
echo "      key label; /health answers 200 without authorisation and cannot"
echo "      show it."

echo
if [ "$fails" -eq 0 ]; then
    echo "== the proxy behaves as documented, on the one row where it did not =="
    exit 0
fi
echo "== $fails assertion(s) failed =="
exit 1
