<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Simorgh Labs
-->
# Deploying fhsm-service (#111)

**Status: the service is built; this is how to run it.** The design and the
measurements behind it are in `docs/REST_API_DESIGN.md`, the PIN in
`docs/DAEMON_PIN.md`, the throttles in `docs/RATE_LIMIT.md`. This file is the
operational half: what to install, what the reverse proxy must do, and how to
check that it did it.

The daemon listens on a UNIX socket, never on a port. It does not terminate
TLS, does not verify client certificates, and does not know what a certificate
is. A reverse proxy does all of that and tells the daemon who the client is.

---

## The one thing that matters most

**The service believes `X-FHSM-Client-Subject`.** Everything the policy file
decides rests on that header being written by the proxy and not by the client.
There is no signature on it, no shared secret, nothing to verify. The proxy is
trusted because `SO_PEERCRED` says the connection came from the proxy's uid,
and the proxy is trusted to tell the truth about who it authenticated.

So the proxy configuration is part of the security boundary, and a mistake in
it is not a misconfiguration that degrades service — it is a client choosing
its own name.

### What the daemon does about it

Two of the three failure modes are caught in the daemon, and it is worth
knowing exactly which:

| The proxy… | What arrives | What the daemon does |
|---|---|---|
| sets the header, client also sends one | two headers | **400**, refused. It does not pick one. Resolving an ambiguity about identity is how the wrong answer becomes authoritative |
| sets the header, client sends none | one header, the proxy's | served, correctly |
| **does not set the header at all** | the client's, if any | **served, and the client is whoever it said it was** |

The third row is the one nothing in the daemon can catch. A header it never
receives is indistinguishable from a header the proxy wrote. Every check below
exists because of that row.

### nginx

```nginx
location / {
    proxy_pass http://unix:/run/fhsm/service.sock;

    # This line is the security boundary. proxy_set_header REPLACES any header
    # of the same name that the client sent, so setting it is also stripping
    # it. Omitting the line does not fail closed: it passes the client's
    # through untouched.
    proxy_set_header X-FHSM-Client-Subject $ssl_client_s_dn;

    # And refuse anyone whose certificate did not verify, so the variable above
    # is never an empty string with a request behind it.
    if ($ssl_client_verify != SUCCESS) { return 403; }
}
```

with, in the enclosing `server` block, `ssl_verify_client on;` and an
`ssl_client_certificate` naming the CA that issues client certificates.

### Apache httpd

```apache
<Location "/">
    # unset first, then set. RequestHeader set already replaces, but the pair
    # says the intent out loud and survives someone reordering the file later.
    RequestHeader unset X-FHSM-Client-Subject
    RequestHeader set X-FHSM-Client-Subject "%{SSL_CLIENT_S_DN}s"

    SSLVerifyClient require
    SSLOptions +StdEnvVars
    ProxyPass "unix:/run/fhsm/service.sock|http://localhost/"
</Location>
```

---

## The subject format will not be what you expect

The policy file matches the subject **as a string, byte for byte**. The string
the proxy sends is not the one our own tools print.

| Source | Example |
|---|---|
| `fhsm-csr --subject`, `fhsm-ca`, OpenSSL's older output | `/C=FR/O=Example/CN=web01` |
| nginx `$ssl_client_s_dn`, 1.11.6 and later | `CN=web01,O=Example,C=FR` |
| nginx `$ssl_client_s_dn_legacy` | `/C=FR/O=Example/CN=web01` |
| Apache `%{SSL_CLIENT_S_DN}s` | `CN=web01,O=Example,C=FR` |

nginx changed the format in **1.11.6** (November 2016) to RFC 2253 / RFC 4514:
commas instead of slashes, and the components in reverse order. The old form
survives as `$ssl_client_s_dn_legacy`.

**Write the policy in whatever your proxy actually emits, and check rather than
assume.** The quickest way is to look: make one request and read the audit log,
where the subject appears as `actor`. A policy written in the wrong format does
not fail loudly — every request is simply refused as unauthorised, and the
refusals are indistinguishable from an attack by design.

---

## Installing

### What the host must have

* **systemd 250 or later.** `LoadCredentialEncrypted=` and `systemd-creds`
  arrived in v250 (December 2021); the credential logic they extend arrived in
  v247. On an older systemd the directive is not an error — it is **an unknown
  key, ignored with a warning**, so the unit starts, no credential is placed,
  and the daemon fails to find its PIN. Verified against systemd 249, where
  `systemd-analyze verify` says exactly that: `Unknown key name
  'LoadCredentialEncrypted' in section 'Service', ignoring.` Debian 12,
  Ubuntu 22.04 and RHEL 9 are all past this line; Ubuntu 20.04 and Debian 11
  are not.
* **A reverse proxy that terminates mTLS.** See above.
* **`tpm2-tools`, if the token is sealed to a TPM.** The unit keeps `/dev` open
  for `/dev/tpmrm0` only, and says so where the directive is.

Check the unit before trusting it:

```bash
systemd-analyze verify /etc/systemd/system/fhsm-service.service
```

### The steps

```bash
# A user that owns the token and nothing else.
useradd --system --home-dir /var/lib/freehsm --shell /usr/sbin/nologin freehsm

# The proxy needs to reach the socket. This is traversal, not authorisation:
# --proxy-uid is what actually checks the peer.
usermod -aG freehsm www-data

install -D -m 0755 service/fhsm-service /usr/libexec/fhsm-service
install -D -m 0644 systemd/fhsm-service.service /etc/systemd/system/fhsm-service.service
install -d -m 0700 -o freehsm -g freehsm /var/lib/freehsm/tokens
install -d -m 0750 -o root -g freehsm /etc/freehsm
```

Set `--proxy-uid` in the unit to the proxy's uid (`id -u www-data`). It is
written as a number rather than a name because the daemon compares the number
`SO_PEERCRED` returns, and resolving a name at start would be one more thing
that can differ between the check and the reality.

### The PIN

`docs/DAEMON_PIN.md` chose a machine-generated PIN in a systemd encrypted
credential, and explains why not an argument, not an environment variable, and
not our own TPM sealing.

**The PIN has to reach two places**: the token, through `fhsm-token init`,
which reads it from `FHSM_PIN`; and the credential, which is what the daemon
will read at every start. There is therefore one moment when it exists in a
shell, and the procedure is written to make that moment as short as possible
and to leave nothing behind.

```bash
# One shell, no history, no file. `set +o history` matters: without it the
# environment assignment is written to ~/.bash_history in clear.
set +o history
umask 0077

PIN=$(openssl rand -base64 32)          # 32 DRBG bytes, 44 characters
SO_PIN=$(openssl rand -base64 32)

# 1. the token
FHSM_SO_PIN="$SO_PIN" FHSM_PIN="$PIN" \
  sudo -u freehsm -E env FHSM_TOKENS_DIR=/var/lib/freehsm/tokens \
    /usr/bin/fhsm-token init --label freehsm

# 2. the credential the daemon will read
printf '%s' "$PIN" | systemd-creds encrypt --name=fhsm-pin - \
    /etc/credstore.encrypted/fhsm-pin.cred
chmod 0600 /etc/credstore.encrypted/fhsm-pin.cred

unset PIN SO_PIN
set -o history
```

Keep the SO PIN somewhere an operator can reach — it is what re-initialises or
re-PINs the token, and the daemon never needs it. The user PIN, from here on,
exists only inside the credential: **nobody has to know it, and nobody should.**

systemd decrypts it to `$CREDENTIALS_DIRECTORY/fhsm-pin` at start, mode 0400,
on a tmpfs unmounted when the unit stops. The daemon reads it once, calls
`C_Login` once, and zeroizes it. **One attempt, never a retry loop:** the token
locks a role after five failures, and a restart loop would spend them.

After the first start, check that systemd was able to back the credential with
unswappable memory rather than assuming it:

```bash
systemd-creds list        # the fhsm-pin row must read "secure", not "weak"
```

`weak` means it landed in ordinary swappable memory. `DAEMON_PIN.md` asks for
this to be read rather than assumed, because a silent downgrade is exactly the
kind this project keeps finding.

### The policy

```
# /etc/freehsm/policy -- SUBJECT<TAB>KEY-LABEL, one pair per line
CN=web01,O=Example,C=FR	tls-web01
CN=web02,O=Example,C=FR	tls-web02
```

Tab-separated, `#` for comments. Re-read on `SIGHUP` and applied at the next
request. **A reload that fails to parse keeps the policy already in force** —
the alternative, an empty policy, fails open on the reload path.

---

## Checking that it works, and that it fails

Starting the service proves very little. These four do.

**1. An authorised request is served.**

```bash
curl --cert client.pem --key client.key https://ca.example/sign \
     -H 'X-FHSM-Key: tls-web01' --data-binary @message.bin -o sig.bin
```

**2. The client cannot name itself.** This is the check that the whole section
above exists for. Send the header yourself:

```bash
curl --cert client.pem --key client.key https://ca.example/sign \
     -H 'X-FHSM-Client-Subject: CN=somebody-else' \
     -H 'X-FHSM-Key: tls-web01' --data-binary @message.bin -i
```

Expect **400**. That is the daemon seeing two headers and refusing to choose.
If it returns **200**, your proxy is not setting the header and the client just
chose its own identity — stop and fix the proxy before going further.

**3. An unauthorised key is refused, and says nothing.**

```bash
curl ... -H 'X-FHSM-Key: tls-web02' ...   # a key this subject does not own
curl ... -H 'X-FHSM-Key: no-such-key' ... # a key nobody owns
```

Both must be **403**, byte for byte identical. A difference between them is a
map of the token, one request at a time.

**4. A signature can be checked without our tools.**

```bash
SIG=$(stat -c%s sig.bin)
cat sig.bin message.bin | curl --cert client.pem --key client.key \
     https://ca.example/verify -H 'X-FHSM-Key: tls-web01' \
     -H "X-FHSM-Signature-Length: $SIG" --data-binary @- -o /dev/null -w '%{http_code}\n'
```

**200** and nothing else means it verified. Anything other than 200 — including
422, which is an invalid signature — means it did not. Check the status, not
the body: that is the way round this route was built.

**5. The audit log names the actor.**

```bash
freehsm-audit verify /var/lib/freehsm/tokens/audit.log.NNNNNN
grep '"event":"sign"' /var/lib/freehsm/tokens/audit.log.NNNNNN | tail -1
```

The `actor` field is the certificate subject. If it is empty on a request that
was served, the identity is not reaching the daemon.

---

## What the throttles will do to a client

Two controls answer **429**, and an operator seeing one should know which:

* **Fairness.** While another identity is present, each is held to
  `--workers` minus one, so no client can take every worker. `Retry-After: 1`.
  A single client is never capped.
* **The refusal budget.** Four authorisation refusals are free; past that the
  delay doubles from one second to a maximum of sixty, and the count decays by
  one every ten quiet minutes. `Retry-After` carries the derived interval. The
  crossing is logged once as `identity_limited`, with the count and the delay.

**Neither is ever a lock**, and the budget's count survives a restart on
purpose — a crash must not hand back a reset. `docs/RATE_LIMIT.md` has the
measurements and the reasoning.

Note that the budget's interval belongs to the *identity*, so once a client
crosses, its legitimate requests wait too. That is what makes a stolen
certificate cost its holder something. Suspending an identity is the operator's
job, and the way to do it is to revoke the certificate.

---

## What this deployment does not do

* **No TLS, no client-certificate verification, no revocation checking.** All
  of that is the proxy's. If the proxy does not check the CRL or ask an OCSP
  responder, a revoked certificate keeps working; `fhsm-ca crl` and
  `fhsm-ca ocsp-respond` exist to be pointed at.
* **`/certificates` and `/ocsp` are on the public listener, not this one.**
  The authenticated socket answers 404 for both, with a `Link:` header naming
  where they live, because a relying party has no identity to present. On the
  public socket `GET /certificates` is served and `POST /ocsp` still answers
  501. Implemented on the authenticated socket: `/health`, `/token`,
  `POST /sign` and `POST /verify`.
* **No queue with a depth.** Requests beyond the worker count wait in the
  kernel's accept backlog, where the daemon can neither see nor reorder them.
  `docs/REST_API_DESIGN.md` records this as a later slice, and it is why one
  identity saturating the service still costs another a factor of 2.4 in
  latency rather than nothing.
* **Nothing here has been run against a real reverse proxy in production.**
  The daemon's own guards are tested in `tests/service_guards.sh` and
  `tests/service_budget.sh`; the proxy configurations above are written from
  the documentation of each server and checked for the format question, not
  deployed and measured. Check number 2 above is the one that would catch a
  mistake in them, which is why it is written as a command rather than a
  reassurance.

---

## See also

* `docs/REST_API_DESIGN.md` — why the service is shaped this way, and what was
  measured
* `docs/DAEMON_PIN.md` — where the PIN comes from, and the two options rejected
* `docs/RATE_LIMIT.md` — fairness and the refusal budget
* `docs/AGD_OPE.md` — operating the module itself
