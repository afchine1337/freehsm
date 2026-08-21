<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# `fhsm-ca` --- issuing, revoking and answering for a post-quantum CA

`fhsm-ca` is the issuing side of the pair. `fhsm-csr` makes keys and requests
and signs the CA's own certificate; everything a CA does *to somebody else's*
request happens here: issuing it, recording its revocation, publishing a
revocation list, and answering OCSP.

The CA's private key lives in a PKCS#11 module and never leaves it. Every
signature below is made by the module through `C_Sign`.

**Read [Limitations](#limitations) before relying on this for anything.** The
composite algorithm is not yet implemented by general-purpose tooling, which
constrains what these objects can be used for today. `docs/FHSM_CSR.md` states
that limit in full and it applies to everything on this page.

---

## Synopsis

```
fhsm-ca issue  --label NAME --ca-cert FILE --csr FILE
               [--profile end-entity|ocsp-responder]
               [--subject DN] [--san LIST] [--crl-url URL]...
               [--days N] [--out FILE] [--pem]
fhsm-ca revoke --db FILE --serial HEX [--reason NAME] [--date WHEN]
fhsm-ca crl    --label NAME --ca-cert FILE --db FILE
               [--days N] [--out FILE] [--pem]
fhsm-ca ocsp-respond --label NAME --ca-cert FILE --db FILE --req FILE
               [--responder-cert FILE] [--days N] [--out FILE]
```

The PIN is read from the `FHSM_PIN` environment variable. There is no `--pin`
option, and passing one is refused rather than ignored: an argument is visible
in `ps` to every user on the machine, and a tool that offers the convenient
insecure option is a tool whose users take it.

---

## `issue` --- signing somebody else's request

`fhsm-csr root` signs the CA's own certificate. Signing somebody else's
request is `fhsm-ca issue`:

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

### Profiles

The CA sets extensions, never the applicant. `--profile` is how the operator
says what a certificate is *for*, and it is the only way to get anything other
than an end entity:

| `--profile` | What it adds | Default validity |
|---|---|---|
| `end-entity` (default) | `basicConstraints CA:FALSE`, `keyUsage digitalSignature + nonRepudiation` | 365 days |
| `ocsp-responder` | the same, plus `extendedKeyUsage OCSPSigning` and `id-pkix-ocsp-nocheck` | 30 days |

Extensions asked for by the applicant are ignored, so a request cannot talk the
CA into issuing it a CA certificate --- or, now, into calling itself a
responder.

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


### The delegated responder

By default the CA's own key signs the answers, which means the CA key has to be
reachable every time somebody asks a question. RFC 6960 §4.2.2.2 exists to
break that: the CA issues a *responder* certificate, and that certificate's key
--- a different key, on a machine that can be online --- signs the answers.

```bash
# 1. a key and a request for the responder, like any other subject
fhsm-csr keygen --label ocsp01
fhsm-csr csr    --label ocsp01 --subject "/O=Exemple/CN=OCSP Responder" \
                --out ocsp01.csr

# 2. the CA issues it, once, with the offline key
fhsm-ca issue --label root-ca --ca-cert root.crt --csr ocsp01.csr \
              --profile ocsp-responder --out ocsp01.crt

# 3. from then on the responder answers, and the CA key stays away
fhsm-ca ocsp-respond --label ocsp01 --ca-cert root.crt --db ca.db \
                     --req req.der --responder-cert ocsp01.crt \
                     --out resp.der
```

`--label` then names the *delegate's* key, not the CA's. The response carries
the delegate's name as its responder ID and the delegate's certificate in its
`certs` field, so a client holding only the CA certificate can still build the
chain.

A verifier accepts an answer signed by something other than the CA for exactly
one reason: the CA issued that something with `extendedKeyUsage OCSPSigning`.
So `--responder-cert` refuses two files rather than signing with them:

* **a certificate without the EKU.** A verifier will refuse every response it
  signs, so producing them would only fill a directory with answers nobody
  accepts --- discovered in production, days later, as clients rejecting
  certificates that are perfectly good.
* **a certificate issued by a different CA.** Whatever its EKU says, it has no
  authority over these certificates.

The second check compares names, and **a name is not a signature.** Verifying
that this CA really issued the delegate would mean checking a composite
signature, which nothing off the shelf can do --- the same wall as everywhere
else on this page. It catches the ordinary mistake, the wrong file, and not a
forgery. It is written here rather than left to be inferred, because a check
that sounds stronger than it is, is worse than no check.

### How long a responder certificate should live

A delegated responder carries `id-pkix-ocsp-nocheck`, which tells verifiers not
to ask whether the responder itself has been revoked. It has to: otherwise a
verifier checking the responder's status must ask the responder, which is the
loop §4.2.2.2.1 exists to cut.

The consequence is the thing to understand before deploying one. **A
compromised responder certificate cannot be revoked in any way a verifier will
notice.** You can put it in the CRL; nobody is required to look, and by design
they do not. The only control left is expiry.

So `--profile ocsp-responder` defaults to **30 days** rather than the
end-entity year, and reissuing becomes routine rather than exceptional.

`--days` still overrides it, because refusing would be wrong: an operator whose
CA key is in a safe in another building may have no way to reissue monthly, and
that trade is theirs to make, not this tool's. Past 90 days it prints a NOTE
saying what is being traded away. It issues the certificate.

```
$ fhsm-ca issue ... --profile ocsp-responder --days 400
fhsm-ca: NOTE -- 400 days for a delegated responder.
  It carries id-pkix-ocsp-nocheck, so revoking it is not something
  a verifier will observe: ...
```

A warning that also refused would be a policy pretending to be advice. A
default that was silently long would be a policy pretending to be nothing.

---

## Limitations

**No `ocsp-verify`.** Nothing in this project verifies a composite OCSP
response yet, and OpenSSL cannot. `fhsm-sign cms-verify` does the equivalent
for CMS; the OCSP counterpart is not written. Until it is, a response's
signature can be checked only by code you write against
`fhsm_composite_verify`. This bears directly on the delegated responder above:
`tests/ocsp_delegated.sh` asserts that OpenSSL fails on *both* a delegated and
a CA-signed response, and fails the same way --- decoding the signer's key ---
so that the failure is never read as a fault in the delegation.

**No archive cutoff, and no CRL entry extensions beyond the reason code.**

A line here used to read "**No OCSP.** Only CRLs." It sat four paragraphs
below a section documenting `ocsp-respond`, having survived the commit that
implemented it. It is recorded rather than quietly deleted: a limitations list
is the part of a document readers trust most and check least, so it is exactly
where a stale sentence does the most damage.

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


**`C_Sign failed` after `--responder-cert`** --- `--label` names the delegate's
key when a responder certificate is given, not the CA's. Passing the CA label
with someone else's certificate signs with a key that does not match it, and
the answer is refused by every verifier that reads it.

---

## See also

* `docs/COMPOSITE_SIGS_GAP.md` — what Composite ML-DSA is, what the module
  implements, and the measurements behind both.
* `docs/AGD_OPE.md` — operator guidance for the module itself.
* `draft-ietf-lamps-pq-composite-sigs-19` — the specification.

* `RFC 6960` §4.2.2.2 --- delegated responders and `id-pkix-ocsp-nocheck`.
