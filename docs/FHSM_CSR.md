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
| `--slot N` | Slot identifier, as reported by `C_GetSlotList` | the one slot holding a token |
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

**Issuance, revocation, CRLs and OCSP live in `fhsm-ca`** and are documented
in [`FHSM_CA.md`](FHSM_CA.md). `fhsm-csr root` signs the CA's own certificate;
everything the CA then does to somebody else's request is the other tool.

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


---

## See also

* `docs/COMPOSITE_SIGS_GAP.md` — what Composite ML-DSA is, what the module
  implements, and the measurements behind both.
* [`FHSM_CA.md`](FHSM_CA.md) --- issuing, revoking, CRLs and OCSP.
* `docs/AGD_OPE.md` — operator guidance for the module itself.
* `draft-ietf-lamps-pq-composite-sigs-19` — the specification.
