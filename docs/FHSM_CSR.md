<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# `fhsm-csr` — certification requests and roots with a post-quantum composite key

`fhsm-csr` creates a composite ML-DSA key inside a PKCS#11 module and uses it to
produce PKCS#10 certification requests and self-signed CA certificates. The
private key is generated in the module and never leaves it; every signature is
made by the module through `C_Sign`.

**Read [Limitations](#limitations) before relying on this for anything.** The
composite algorithm is not yet implemented by general-purpose tooling, which
constrains what a request produced here can be used for today.

---

## Synopsis

```
fhsm-csr keygen --label NAME [--module PATH] [--slot N]
fhsm-csr csr    --label NAME --subject DN [--out FILE] [--pem] [--module PATH] [--slot N]
fhsm-csr root   --label NAME --subject DN [--days N] [--serial N] [--out FILE] [--pem] ...

fhsm-ca  issue  --label NAME --ca-cert FILE --csr FILE [--subject DN] [--san LIST] [--crl-url URL]... [--days N] ...
fhsm-ca  revoke --db FILE --serial HEX [--reason NAME] [--date WHEN]
fhsm-ca  crl    --label NAME --ca-cert FILE --db FILE [--days N] [--out FILE] [--pem]
```

The PIN is read from the `FHSM_PIN` environment variable.

---

## Commands

### `keygen` — create a composite key pair

Generates an `id-MLDSA65-Ed25519-SHA512` key pair as two token objects sharing
one label: a public key and a private key. Both components (ML-DSA-65 and
Ed25519) are generated together inside the module.

```bash
export FHSM_PIN=…
fhsm-csr keygen --label ca
```

The key pair cannot be assembled from two existing keys — there is no option to
do so, and that is deliberate. `draft-ietf-lamps-pq-composite-sigs` §3.1
forbids reusing component key material between a composite and a non-composite,
or between two composites; the prohibition is met by making the situation
unrepresentable rather than by checking for it.

### `csr` — produce a PKCS#10 certification request

```bash
fhsm-csr csr --label ca \
             --subject "/C=FR/O=Simorgh Labs/CN=demo.example" \
             --out demo.csr.der
```

The request is signed by the module over the DER of `CertificationRequestInfo`.

### `root` — produce a self-signed CA certificate

```bash
fhsm-csr root --label ca \
              --subject "/C=FR/O=Simorgh Labs/CN=Simorgh Composite Root" \
              --days 3650 --serial 1 \
              --out ca.der
```

A v3 certificate with `basicConstraints CA:TRUE` and
`keyUsage keyCertSign,cRLSign`, both critical, plus a `subjectKeyIdentifier`
computed as SHA-1 of the composite public key (RFC 5280 §4.2.1.2 method 1).

---

## Options

| Option | Meaning | Default |
|---|---|---|
| `--module PATH` | PKCS#11 module to load | `./libfreehsm-fips.so` |
| `--slot N` | Slot index | `0` |
| `--label NAME` | Key label. Required by every command. | — |
| `--subject DN` | Subject, OpenSSL one-line form: `/C=FR/O=…/CN=…` | — |
| `--days N` | Validity in days (`root` only) | `3650` |
| `--serial N` | Certificate serial (`root` only), must be > 0 | `1` |
| `--out FILE` | Output file | stdout |
| `--pem` | PEM instead of DER | DER |

### The PIN, and why there is no `--pin`

The PIN is read from `FHSM_PIN` and from nowhere else. Passing `--pin` prints
an explanation and exits non-zero.

A PIN given as a command-line argument is visible in `ps` to every user on the
machine, and it lands in shell history. A tool that offers the convenient
insecure option is a tool whose users take it, so the option does not exist.

If a script needs the PIN, keep it in a file readable only by the service
account and source it, or pass it through the process environment from a
secrets manager:

```bash
FHSM_PIN="$(systemd-creds cat fhsm-pin)" fhsm-csr csr --label ca --subject …
```

---

## Working with another PKCS#11 module

`fhsm-csr` loads the module at runtime and uses only standard PKCS#11 calls, so
it drives **any** module implementing `CKM_COMPOSITE_MLDSA65_ED25519`, not only
FreeHSM. The composite DER encoding is built inside the tool; the key stays
wherever the module keeps it.

```bash
fhsm-csr keygen --label ca --module /usr/lib/softhsm/libsofthsm2.so --slot 1
```

An institution that already owns a hardware HSM can use these tools with it.
That is the point of the layering, and it is the one thing a PKI which merely
*talks to* HSMs cannot offer.

---

## A complete example

```bash
export FHSM_PIN=…

# 1. a key for the CA, generated inside the module
fhsm-csr keygen --label root-ca

# 2. the CA's own certificate, self-signed, ten years
fhsm-csr root --label root-ca \
              --subject "/C=FR/O=Université Exemple/CN=Exemple Root CA" \
              --days 3650 --out root-ca.crt --pem

# 3. a key and a request for a server
fhsm-csr keygen --label web01
fhsm-csr csr --label web01 \
             --subject "/C=FR/O=Université Exemple/CN=web01.exemple.fr" \
             --out web01.csr --pem
```

Both outputs can be read with the usual tools:

```bash
openssl x509 -in root-ca.crt -text -noout
openssl req  -in web01.csr   -text -noout
```

---

## Limitations

**The signature cannot be verified by generally available tooling.**
`openssl req -text` and `openssl x509 -text` will print
`Unable to load Public Key` and, for a certificate, a self-signature warning.
This is not a defect in the output. OpenSSL 3.5 has no implementation of
Composite ML-DSA — it prints the algorithm as a bare OID because it has no name
for it — and cannot verify an algorithm it does not implement.

The consequences are worth being precise about:

* A composite request or certificate **can** be produced, transported, stored,
  archived, and parsed by any DER-aware tool. The structure is standard PKIX;
  this is the "protocol backwards compatibility" the draft is designed for.
* It **cannot** be validated by anything off the shelf today. A CA that
  implements composite signatures would accept the request; none of the
  common ones do yet, because the RFC has not published.
* Anyone told otherwise will find out when they submit one.

`draft-ietf-lamps-pq-composite-sigs` is in the RFC Editor queue. This lifts when
implementations follow, and nothing in the output format is expected to change.

**Not FIPS-approved, and not announced as such.** The mechanism is available in
the interop profile only. See `docs/COMPOSITE_SIGS_GAP.md` for the reasoning —
in short, the draft states the design goal that a composite be *considered*
approved and, two lines earlier, that this guidance is not authoritative and has
no NIST endorsement.

**Issuance lives in `fhsm-ca`.** `fhsm-csr root` signs the CA's own
certificate; signing somebody else's request is `fhsm-ca issue`:

```bash
fhsm-ca issue --label root-ca --ca-cert root.crt --csr web01.csr \
              --days 365 --out web01.crt
```

Alternative names come from `--san`, in the syntax you already know:

```bash
fhsm-ca issue --label root-ca --ca-cert root.crt --csr web01.csr \
              --san "DNS:web01.exemple.fr,DNS:www.exemple.fr,IP:10.0.0.7" \
              --out web01.crt
```

`DNS:`, `IP:`, `email:` and `URI:` are accepted. Anything malformed — a missing
type prefix, an empty value, an address that is not one — makes the whole
command fail rather than dropping that entry, because a name silently missing
from a certificate is a name you believe is covered and is not.

**Where the revocation list lives comes from `--crl-url`**, which you repeat
rather than comma-separate:

```bash
fhsm-ca issue --label root-ca --ca-cert root.crt --csr web01.csr \
              --crl-url "http://crl.exemple.fr/exemple-root.crl" \
              --crl-url "ldap://ldap.exemple.fr/cn=CRL,ou=CA,o=Exemple?certificateRevocationList" \
              --out web01.crt
```

It repeats because an LDAP URI carries commas inside its DN, and a comma
separator would cut that into invalid pieces. The order you give is the order a
client walks, and it is preserved.

All the URLs go into **one** distribution point, not one each: RFC 5280
§4.2.1.13 reads several names inside a point as several routes to the *same*
list, which is what publishing over both HTTP and LDAP is. Separate points
would claim separate lists.

Three refusals worth knowing before you hit them:

* **`https` is refused.** A CRL is a signed object, so transport
  confidentiality adds nothing, and fetching one over TLS can require
  validating a certificate — which can require a CRL. The CA/Browser Forum
  Baseline Requirements mandate plain HTTP for that reason, and §4.2.1.13 names
  only HTTP and LDAP. It is an easy habit to reach for; better refused here than
  discovered as a circular dependency in production.
* **`ldap://` without a `?attribute` part is refused.** Such a URI names a
  directory entry but not which attribute holds the list, so a client has
  nothing to read. Any attribute is accepted —
  `certificateRevocationList`, `authorityRevocationList` and
  `deltaRevocationList` are all legitimate; the check is only that one is
  present.
* **Non-ASCII is refused.** `IA5String` is ASCII by definition. Punycode your
  host names.

As with `--san`, a URL that is not understood fails the issuance rather than
being dropped — and here the reason is sharper. A certificate that silently
lost its only reachable URL points at a list nobody can fetch, and unlike a
missing name, nothing about it looks wrong.

At most eight `--crl-url` entries; a ninth is refused rather than ignored.

The extension is optional: omit `--crl-url` and the certificate simply carries
none, which is what every certificate issued before this option existed does.

---

## Revocation

An authority that can issue but not withdraw cannot correct its own mistakes.
Two commands, deliberately separate:

```bash
# record a revocation --- no key, no PIN, nothing signed
fhsm-ca revoke --db ca.db --serial 5A223663B7571B2345CC3E06A2F4E3DB6899713F \
               --reason keyCompromise

# publish the signed list
fhsm-ca crl --label root-ca --ca-cert root-ca.crt --db ca.db \
            --days 30 --out ca.crl
```

They are separate because recording a revocation is urgent and may fall to
whoever noticed, at any hour, while signing a list needs the token and its
PIN. Combining them would mean either that a revocation cannot be written
down without the key present, or that the key has to be reachable by a more
casual operation than it should be.

The serial is the one the certificate carries, in the form `openssl` prints:

```bash
openssl x509 -in web01.crt -noout -serial
```

Accepted reasons, from RFC 5280 §5.3.1: `unspecified`, `keyCompromise`,
`cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`,
`certificateHold`, `privilegeWithdrawn`, `aACompromise`. `removeFromCRL` is
not accepted — it belongs to delta CRLs, which this tool does not produce.
Omitting `--reason` is legitimate and says less than guessing.

### The database

```
# fhsm-ca revocation database v1
# SERIAL(hex)  DATE(YYYYMMDDHHMMSSZ)  REASON  ('-' for none)
crlNumber 5
5A223663B7571B2345CC3E06A2F4E3DB6899713F 20260806195116Z keyCompromise
```

Plain text, one entry per line: readable, greppable, diffable, and something
you can put under version control. **Back it up.** Serials here are random, so
the CA keeps no other record of what it has issued; this file is the only
thing that remembers what has been withdrawn.

`crlNumber` lives in the same file as the entries on purpose. Two files can be
backed up, copied or restored separately, and a number that has gone backwards
relative to its list is precisely the failure it exists to prevent: a verifier
holding a newer list must be able to tell that an older one is older, or
replaying last month's list hides every revocation since.

Each `crl` run advances the number before signing and writes the database
before the list leaves the process. If signing then fails, a number has been
consumed and nothing published — a gap, which is harmless. The reverse order
would publish two different lists under one number, which is not.

**A malformed line refuses the whole file**, naming the line and changing
nothing. Reading a database only partly would produce a list missing
revocations, and a list missing revocations is a signed statement that a
compromised certificate is still good — worse than publishing none at all.

**There is no locking.** This is a single-operator tool for small
authorities; two people running `revoke` at the same moment is a situation it
does not handle. Saying so is more useful than a lock that would only narrow
the window.

### What a verifier sees

`openssl crl` reads the result completely, including the fields it has no
verifier for:

```
$ openssl crl -inform DER -in ca.crl -text -noout
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: 1.3.6.1.5.5.7.6.48
        Issuer: C=FR, O=Université Exemple, CN=Exemple Root CA
        Last Update: Aug  6 19:51:16 2026 GMT
        Next Update: Sep  5 19:51:16 2026 GMT
        CRL extensions:
            X509v3 Authority Key Identifier:
                5F:93:57:27:2B:96:BC:13:C5:13:99:1C:89:E5:9A:D6:36:00:2A:F6
            X509v3 CRL Number:
                1
Revoked Certificates:
    Serial Number: 5A223663B7571B2345CC3E06A2F4E3DB6899713F
        Revocation Date: Aug  6 19:51:16 2026 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Key Compromise
```

The `authorityKeyIdentifier` is copied from the CA certificate's
`subjectKeyIdentifier`, so the list can be tied to the certificate that signed
it without guessing. The limitation stated above applies here too: OpenSSL
parses the structure but cannot check the signature, because it has no
implementation of Composite ML-DSA.

---

## OCSP

A CRL answers "which certificates are revoked" for all of them at once. OCSP
answers "is this one revoked" for the one a verifier actually asked about. Both
read the same database.

```bash
# a verifier produces a request --- this is the client's job, not the CA's
openssl ocsp -issuer ca.pem -cert leaf.pem -reqout req.der

# the CA answers it
fhsm-ca ocsp-respond --label ca --ca-cert ca.der --db ca.db \
                     --req req.der --out resp.der
```

```
fhsm-ca: 1 asked, 1 ours (1 revoked), 0 unknown, valid 7 days, nonce echoed.
```

`--days` sets `nextUpdate`, seven by default. A response is a statement with an
expiry, not a permanent fact.

### File in, file out

There is no listening service. A responder that listens is a network service
with its own concurrency, its own key lifetime and its own denial-of-service
surface, and none of that is cryptography. `ocsp-respond` produces the signed
object; serving it is your business, and a static file behind a web server is a
legitimate way to do it for a small authority.

### Three answers, and why `unknown` matters

| Answer | When |
|---|---|
| `good` | the CertID names a certificate this CA issued, and the database has no revocation for that serial |
| `revoked` | the database has an entry, with its date and reason |
| `unknown` | the CertID names a certificate issued by somebody else |

`unknown` is not an error. A responder that answered `good` for an issuer it
knows nothing about would be asserting something it cannot know — and a
verifier would believe it. RFC 6960 §2.2 has the same reading.

To decide, the responder rebuilds the CertID it would have produced for that
serial under this CA and compares. That means computing the hash the *client*
chose, and OpenSSL's own client still chooses SHA-1 by default.

**On that SHA-1.** It is not a signature. SP 800-131A withdraws SHA-1 for
signature generation, not for identification, and a CertID identifies. It
proves nothing about the certificate and nothing relies on it: the response's
integrity comes from the composite signature over the whole of it. It is also
OpenSSL's SHA-1, in the tool — the module's `fips-strict` profile is never
asked for it and does not provide it.

### The nonce

If the request carries one, it is copied into the response. RFC 8954 exists for
a reason: without a nonce, a recorded response can be replayed at a verifier
until its `nextUpdate` passes, which is exactly how a revoked certificate keeps
being accepted after revocation. The nonce is echoed, never generated — one the
responder chose would prove nothing to the client that did not choose it.

`openssl ocsp` sends a nonce unless you pass `-no_nonce`. Note that checking it
requires giving the client the actual request:

```bash
openssl ocsp -reqin req.der -respin resp.der -resp_text -noverify
```

Without `-reqin`, the command builds a fresh request with a *new* nonce and
then reports `Nonce Verify error` against a response that was perfectly
correct.

### What a verifier sees

```
$ openssl ocsp -respin resp.der -resp_text -noverify
OCSP Response Status: successful (0x0)
Response Type: Basic OCSP Response
Produced At: Aug 18 13:17:05 2026 GMT
Responses:
  Certificate ID:
    Hash Algorithm: sha1
    Serial Number: 0324DDD0B2F325C3FFD8C8856B6061CB8C997DD1
  Cert Status: revoked
  Revocation Time: Aug 18 13:17:05 2026 GMT
  Revocation Reason: keyCompromise (0x1)
  This Update: Aug 18 13:17:05 2026 GMT
  Next Update: Aug 25 13:17:05 2026 GMT
Response Extensions:
  OCSP Nonce:
```

Everything is readable. The signature is not checkable — `no signer key`,
because OpenSSL cannot parse a composite public key, the same wall the
certificates and the CRL run into.

### A warning about scripting `openssl ocsp`

Measured on OpenSSL 3.5.6: the command prints `<cert>: good` on standard output
**even when verification failed** — with an unknown signature algorithm, and
with a deliberately corrupted Ed25519 signature. The exit status is correct: 0
when the signature verified, 1 when it did not.

So read the exit status. A script that pipes the output through `grep good`
accepts a forged response, and will do so silently.

### Limitations

**No delegated responder.** The CA's own key signs. RFC 6960 §4.2.2.2 allows a
separate responder certificate carrying `id-kp-OCSPSigning`, which is what
keeps the CA key offline in a serious deployment. Not implemented.

**No `ocsp-verify`.** Nothing in this project verifies a composite OCSP
response yet, and OpenSSL cannot. `fhsm-sign cms-verify` does the equivalent
for CMS; the OCSP counterpart is not written. Until it is, a response's
signature can be checked only by code you write against
`fhsm_composite_verify`.

**No archive cutoff, no `id-pkix-ocsp-nocheck`, no CRL entry extensions beyond
the reason code.**

**No OCSP.** Only CRLs. OCSP is a network service and belongs with the rest of
the service work (#111), not with a set of command-line tools.

**No delta CRLs.** Only full lists. `removeFromCRL` is refused for the same
reason.

**Publishing the list is still yours.** `--crl-url` puts the address in the
certificates you issue, so a verifier knows where to look — but nothing here
uploads the file. Whatever `fhsm-ca crl --out` produced has to reach that URL
by your own means, and it has to be replaced before its `nextUpdate` passes.

**Private and loopback addresses are accepted.** A public CA must refuse them;
this one exists for the internal networks of universities and public bodies,
where `10.0.0.0/8` is the entire point. Applying a rule written for public
issuance would break the intended use and protect nobody.

The list comes from you, never from the request: the applicant does not choose
what the CA asserts about them.

The request's own signature is verified against the key it carries before
anything is issued — a request whose signature does not match is refused with
exit code 4 and nothing is written. Extensions asked for by the applicant are
ignored; the CA sets `basicConstraints CA:FALSE`, `keyUsage`, and both key
identifiers itself, so a request cannot talk the CA into issuing it a CA
certificate. Serials are 20 random octets.


---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Usage error, `FHSM_PIN` unset, or `--pin` passed |
| `2` | Module could not be loaded, or a PKCS#11 call failed |
| `3` | No key with that label, or more than one; or a malformed revocation database |
| `4` | The request's signature does not match the key it carries (`fhsm-ca issue`) |
| `5` | That serial is already revoked; the database was left unchanged |

Two keys sharing a label is refused rather than resolved by taking the first
match: signing with a key the operator did not intend is worse than a command
that fails.

---

## Troubleshooting

**`C_OpenSession failed (0xe0)`** — `CKR_TOKEN_NOT_PRESENT`. The slot has no
initialised token. Run `fhsm-token init` first (see
[`FHSM_TOKEN.md`](FHSM_TOKEN.md)), and check `FHSM_TOKENS_DIR` points where you
think it does.

This sentence used to say "or the module's own provisioning tool". There was
none, so the advice sent the reader looking for something that did not exist —
which is how the gap was eventually found.

**`C_Login failed (0xa0)`** — wrong PIN. After `FHSM_PIN_MAX_FAILED`
consecutive failures the role locks; see `AGD_OPE.md` §4.1.

**`C_GenerateKeyPair failed (0x70)`** — `CKR_MECHANISM_INVALID`. The module was
built in the fips-strict profile, where the composite mechanism is deliberately
refused, or the module does not implement it at all.

**`no public key labelled "x"`** — run `keygen` first, or check the label. The
tool looks for objects whose `CKA_LABEL` matches exactly.

---

## See also

* `docs/COMPOSITE_SIGS_GAP.md` — what Composite ML-DSA is, what the module
  implements, and the measurements behind both.
* `docs/AGD_OPE.md` — operator guidance for the module itself.
* `draft-ietf-lamps-pq-composite-sigs-19` — the specification.
