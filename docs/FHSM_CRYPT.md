<!--
Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# `fhsm-crypt` — keys that do not sign, and files encrypted with them

Lists and deletes what a token holds, generates keys for encryption and MACs,
describes any object's attributes, and encrypts and decrypts files for a key
held in a PKCS#11 module. Signature keys stay with `fhsm-csr keygen`
([`FHSM_CSR.md`](FHSM_CSR.md)); each tool, given the other's algorithm, names
the other.

The design and its reasons are in [`fhsm-crypt-plan.md`](fhsm-crypt-plan.md);
`fhsm-gui` does the same work in its Token and Encryption tabs
([`FHSM_GUI.md`](FHSM_GUI.md)).

---

## Synopsis

```
fhsm-crypt list    [--class key|cert|all]
fhsm-crypt show    --label NAME [--class key|cert|all]
fhsm-crypt keygen  --label NAME --alg aes128|aes256|hmac|rsa-oaep
fhsm-crypt delete  --label NAME [--class key|cert|all] [--yes]
fhsm-crypt encrypt --key LABEL  --in FILE --out FILE.p7m
fhsm-crypt encrypt --cert CERT  --in FILE --out FILE.p7m
fhsm-crypt decrypt --in FILE.p7m --out FILE
```

Every command takes `--module PATH` and `--slot N`. The PIN is read from
`FHSM_PIN`, except by `encrypt --cert`, which needs neither the module nor a
PIN.

---

## Example

```bash
export FHSM_PIN=…

fhsm-crypt keygen  --label archive --alg aes256
fhsm-crypt encrypt --key archive --in ledger.csv --out ledger.csv.p7m
fhsm-crypt decrypt --in ledger.csv.p7m --out ledger-restored.csv
# fhsm-crypt: ledger.csv.p7m decrypted with "archive" into ledger-restored.csv

fhsm-crypt keygen  --label operator --alg rsa-oaep
# Anyone with the operator's certificate can now encrypt for them,
# without a token and without a PIN:
fhsm-crypt encrypt --cert operator.pem --in report.pdf --out report.pdf.p7m
```

---

## The keys

| `--alg` | What is made | May | May not |
|---|---|---|---|
| `aes128`, `aes256` | an AES secret key | encrypt, decrypt, wrap, unwrap | sign |
| `hmac` | a 32-byte generic secret | sign and verify a MAC | encrypt or wrap |
| `rsa-oaep` | an RSA 3072 pair, `CKA_ALLOWED_MECHANISMS` = RSA-OAEP | encrypt and wrap (public), decrypt and unwrap (private) | sign |

Every key is made on the token, sensitive and not extractable, and every usage
is stated in the template, the ones it does not have as false: what a template
leaves out takes the module's default, and what a key may do should not depend
on which module made it.

A second key under a label already in use is refused: every later use of the
label would be ambiguous.

---

## Listing, describing, deleting

`list` shows certificates and keys, each with its class, handle, label,
algorithm and `CKA_ID`. `show` gives one label's objects attribute by
attribute — usage, size or curve, allowed mechanisms, whether it is sensitive
or extractable and was generated on the token; for a certificate, its subject,
issuer, serial and validity. A private or secret key's value is never asked
for.

`delete --label L` names every object it would destroy and stops. Only `--yes`
destroys, and nothing destroyed on a token comes back. `--class` narrows it: a
certificate and its key often share a label.

---

## Files

### The format

CMS `AuthEnvelopedData` (RFC 5083), the content in AES-256-GCM (RFC 5084), DER,
with one recipient:

| Recipient | `RecipientInfo` | The content key travels |
|---|---|---|
| an AES key on the token | `KEKRecipientInfo`, named by the key's label | wrapped by that key with AES key wrap (RFC 3394) |
| an `rsa-oaep` pair, or a certificate's RSA key | `KeyTransRecipientInfo`, named by subjectKeyIdentifier, or by issuer and serial for a certificate without one | RSAES-OAEP, SHA-256, MGF1-SHA-256 |

`openssl cms -decrypt` reads every file `fhsm-crypt` writes, given the key, and
`fhsm-crypt decrypt` reads what `openssl cms -encrypt` writes for the same
recipients — with `-secretkey`, or with
`-keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256`.
Both directions are tested.

### What stays on the token

The key that opens a file never leaves the token: every unwrap or RSA
decryption of a content key is a call to the module. The content key is fresh
for each file and exists in the process only while that file is encrypted or
decrypted, then is cleansed. Encrypting for an RSA recipient is a public
operation, done in software.

### Streaming, and what is never left behind

Files are encrypted and decrypted in 64 KiB chunks; their size is not bounded
by memory. Output goes to a temporary file beside its destination and is
renamed into place once complete. A decrypted file is kept only once its GCM
tag has verified: one that was altered, or not made for the key, leaves
nothing on disk — not even a temporary. An existing output is never written
over.

### What is refused, by name

- RSA PKCS#1 v1.5 key transport, `openssl cms -encrypt`'s default: it is the
  padding Bleichenbacher's attack works on. Ask OpenSSL for OAEP.
- RSA-OAEP with SHA-1, or with a label.
- Indefinite-length BER, a constructed encrypted content, authenticated
  attributes. A BER file converts with `openssl cms -cmsout -outform DER`.
- ML-KEM recipients (`KEMRecipientInfo`, RFC 9629). Not written yet: OpenSSL
  3.5 has ML-KEM but no `KEMRecipientInfo`, so nothing on the machine could
  check an encoding written here. It waits for an implementation that can.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | usage; a file this does not read; an output that exists; a recipient refused by name |
| 2 | the module or the file system |
| 3 | no such key, or no key on this token the file was made for |
| 4 | the file does not open with the key: altered after it was made, or made for another |

---

## See also

[`FHSM_CSR.md`](FHSM_CSR.md) for signature keys,
[`FHSM_SIGN.md`](FHSM_SIGN.md) for signing files,
[`FHSM_GUI.md`](FHSM_GUI.md) for the window,
[`fhsm-crypt-plan.md`](fhsm-crypt-plan.md) for the design.
