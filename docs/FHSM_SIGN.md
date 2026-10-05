<!--
Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# `fhsm-sign` — detached signatures with a key held in a PKCS#11 module

Signs arbitrary data with a key held inside a PKCS#11 module, and checks such
signatures back. The key's algorithm is the one it was generated for
(`fhsm-csr keygen --alg`, see [`FHSM_CSR.md`](FHSM_CSR.md)): the composite
ML-DSA-65 + Ed25519, ECDSA, RSA-PSS or PKCS#1 v1.5, Ed25519 or ML-DSA.
`fhsm-sign` takes no algorithm option; it reads the key. The data is streamed
through the tool, which never holds it.

Separate from `fhsm-csr` and `fhsm-ca` on purpose. Those two build PKI objects
— requests, certificates, revocation lists — where the structure is dictated by
X.509. This one signs whatever you hand it and asserts nothing about what the
bytes mean.

---

## Synopsis

```
fhsm-sign sign       --label NAME [--in FILE] [--out FILE] [--module PATH] [--slot N]
fhsm-sign verify     --label NAME --sig FILE [--in FILE] [--module PATH] [--slot N]
fhsm-sign cms        --label NAME --cert FILE [--in FILE] [--out FILE] [--module PATH]
fhsm-sign cms-verify --cms FILE [--in FILE]
```

`--in` defaults to standard input, `--out` to standard output. The PIN is read
from the `FHSM_PIN` environment variable.

---

## Example

```bash
export FHSM_PIN=…

fhsm-csr keygen --label release-signer          # once

fhsm-sign sign   --label release-signer --in freehsm-2.0.0.tar.xz \
                                        --out freehsm-2.0.0.tar.xz.sig
fhsm-sign verify --label release-signer --in freehsm-2.0.0.tar.xz \
                                        --sig freehsm-2.0.0.tar.xz.sig
```

It reads a pipe just as well, which is what makes it usable mid-pipeline:

```bash
tar cf - ./release | fhsm-sign sign --label release-signer --out release.sig
```

`sign` uses the **private** key carrying that label; `verify` uses the
**public** one. Two keys sharing a label is refused rather than resolved by
taking the first: signing with a key you did not mean is worse than a command
that fails.

---

## What the output is, and what it is not

The signature file is **the raw signature bytes and nothing else** — 3 373 of
them for `MLDSA65-Ed25519-SHA512`, being the 3 309-byte ML-DSA-65 component
followed by the 64-byte Ed25519 one.

There is no container, no header, no algorithm identifier. **The file does not
record which key or which algorithm produced it**, so whoever verifies has to
be told, out of band. If you publish one, publish alongside it the key it was
made with.

Carrying that metadata is what CMS is for — see [below](#cms--pkcs7-cms-cms-verify).

### What the bytes are, by algorithm

| Key | The signature file | Checked elsewhere with |
|---|---|---|
| composite | 3 373 bytes: ML-DSA-65 then Ed25519 | `fhsm-sign verify` only |
| ECDSA P-256 / P-384 | DER `Ecdsa-Sig-Value` | `openssl dgst -sha256` / `-sha384 -verify KEY -signature SIG DATA` |
| RSA-PSS | 384 bytes | `openssl dgst -sha256 -verify KEY -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 -signature SIG DATA` |
| RSA PKCS#1 v1.5 | 384 bytes | `openssl dgst -sha256 -verify KEY -signature SIG DATA` |
| Ed25519 | 64 bytes | `openssl pkeyutl -verify -pubin -inkey KEY -rawin -in DATA -sigfile SIG` |
| ML-DSA-44 / 65 / 87 | 2 420 / 3 309 / 4 627 bytes | the same `openssl pkeyutl` line |

ECDSA is written as **DER**, though PKCS#11 returns `r || s`: DER is what
`openssl dgst -verify` and every other verifier read, and a signature only its
own tool can check is half a signature. `verify` takes DER back and converts
it for the module. `KEY` above is the public key in PEM, which
`openssl x509 -in CERT -pubkey -noout` extracts from the key's certificate.
`tests/pki_tools_algs.sh` runs each of these lines.

---

## Streaming, and why it needed work in the module

The composite construction hashes the message internally:

```
M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)
```

so a one-shot `C_Sign` needs the whole of `M` — and `C_Sign` refuses anything
past 2 GiB. Signing a large file therefore required the module to accept the
message in pieces, which it did not: `C_SignUpdate` handled HMAC and nothing
else.

The module now computes `SHA-512(M)` incrementally across `C_SignUpdate` calls
and hands the digest to the composite combiner. SHA-512 over a stream equals
SHA-512 in one call, so **what gets signed is exactly what the one-shot path
would sign** — this is a conforming signature, not a private convention.

That equality is tested rather than asserted. `tests/test_composite_p11` signs
in deliberately awkward pieces — one byte, then zero bytes, then the rest — and
requires the result to verify through one-shot `C_Verify`; then signs one-shot
and verifies in pieces. A byte flipped mid-stream must break it, which is what
proves the update calls are actually feeding the digest.

Measured on a 40 MiB file: 0.63 s, **8.9 MiB peak resident memory**. The file
is never held.

**For the other algorithms, FreeHSM holds the input.** It accepts their
`C_SignUpdate` calls by accumulating the parts and signing at `C_SignFinal`,
with the same code as the one-shot path — one copy of every rule (PSS
parameters, the ML-DSA context, ECDSA's encoding) rather than a second
streaming path for each; the trade is recorded in `src/fhsm_pkcs11.c`. So the
module's memory bounds the file it can sign raw with those keys. Ed25519 and
pure ML-DSA are one-shot algorithms by construction, and another module may
refuse `C_SignUpdate` for them outright. `cms` has neither limit: only a
digest reaches the module.

---

## CMS / PKCS#7 (`cms`, `cms-verify`)

The raw form above records nothing about itself. CMS does: it carries the
signer's certificate, the algorithm, and the digest of what was signed.

```bash
fhsm-sign cms --label release-signer --cert release-signer.crt \
              --in freehsm-2.0.0.tar.xz --out freehsm-2.0.0.tar.xz.p7s

fhsm-sign cms-verify --cms freehsm-2.0.0.tar.xz.p7s \
                     --in freehsm-2.0.0.tar.xz
```

**`cms-verify` needs no token, no PIN and no module.** The signer's
certificate travels inside the structure, which is the whole reason CMS
carries it. That makes this the only verification in the project a third party
can run with nothing but the file, the data, and the tool.

The output is a **detached** `SignedData` with **signed attributes** —
`contentType` and `messageDigest`, the two RFC 5652 §5.3 requires when
`signedAttrs` is present. There is no attached form.

### Why signed attributes make large files cheap

With `signedAttrs`, the signature covers the attributes — about a hundred
bytes — rather than the content. The content is only hashed. So a file of any
size costs one digest pass and one signature, and nothing is held in memory.
Measured on 20 MiB with a composite key: 0.31 s, 11.5 MiB peak resident.

The digest is the signature algorithm's own hash where it has one, because a
verifier hashes the signed attributes with the CMS `digestAlgorithm`: SHA-256
for ECDSA P-256 and RSA, SHA-384 for P-384, SHA-512 for Ed25519 (RFC 8419),
ML-DSA and the composite. The data is read before the key or the structure is
looked at — it may come from a pipe — so `fhsm-sign` computes all three in the
same pass and keeps the one it needs.

### What a verifier checks, and in what order

`cms-verify` refuses early and for a stated reason:

1. the `signatureAlgorithm` is one this tool knows, with the parameters that
   algorithm requires — absent for the composite, ECDSA, Ed25519 and ML-DSA;
   for RSASSA-PSS exactly the block `fhsm-sign cms` writes; and a key of the
   matching type in the certificate;
2. the `messageDigest` attribute equals the digest, under the structure's own
   `digestAlgorithm`, of the data you supplied;
3. the signature verifies over the signed attributes **as they appear when
   the structure is re-encoded**.

The third point is not pedantry. Verifying over the bytes we were handed would
prove only that the tool agrees with itself. Re-encoding first means the check
is against what any other implementation would reconstruct.

### The one trap worth knowing

RFC 5652 §5.4: the signature is computed over the signed attributes in their
`SET OF` form (`0x31`), while the structure transmits the same bytes under
`[0] IMPLICIT` (`0xA0`). Sign one, send the other, and the result verifies
nowhere — with nothing in either encoding to say why.

This is handled in one place, and attributes handed over already in `[0]` form
are **refused** rather than accepted: tolerating both would make the
substitution a guess.

### Third-party tooling

For every key but the composite, OpenSSL verifies the structure against the
data:

```bash
openssl cms -verify -binary -inform DER -in file.p7s -content file -noverify -out /dev/null
```

(`-noverify` skips the signer certificate's own chain, which is a separate
question; drop it and give `-CAfile` to ask that too.)

For a composite one, `openssl cms -cmsout -inform DER -in file.p7s -print`
reads the whole structure, showing the composite OID as
`undefined (1.3.6.1.5.5.7.6.48)` — it has no name for an algorithm it does not
implement. It cannot verify the signature, for the same reason. That is the
limitation stated below, not a defect in the output.

---

## Options

| Option | Meaning |
|---|---|
| `--label NAME` | key label inside the module |
| `--in FILE` | data to sign or check; `-` or absent means standard input |
| `--out FILE` | where the signature goes; absent means standard output |
| `--sig FILE` | the signature to check (`verify` only) |
| `--cert FILE` | the signer's certificate, DER or PEM (`cms` only) |
| `--cms FILE` | the CMS structure to check (`cms-verify` only) |
| `--module PATH` | PKCS#11 module, default `./libfreehsm.so` |
| `--slot N` | slot identifier, as reported by `C_GetSlotList`; default: the one slot holding a token |

### The PIN, and why there is no `--pin`

The PIN is read from `FHSM_PIN`. There is no `--pin` option, and passing one is
refused with an explanation rather than ignored: a command-line argument is
visible in `ps` to every user on the machine, for as long as the process runs.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Usage error, `FHSM_PIN` unset, or `--pin` passed |
| `2` | Module could not be loaded, or an I/O or PKCS#11 call failed |
| `3` | No key with that label, or more than one |
| `4` | **The signature does not match** — and nothing else returns 4 |

Code 4 exists so a script can tell "did not verify" from "could not run". A
verification failure is not a tool failure, and collapsing the two into a
single non-zero code is how a broken pipeline gets read as a bad signature.

---

## Limitations

**Composite only.** The mechanism is `CKM_COMPOSITE_MLDSA65_ED25519`. Signing
with a plain ML-DSA, ECDSA or RSA key held in the token is not wired up.

**The CMS structure is assembled by hand.** OpenSSL builds the `SignedData`
envelope but refuses the `SignerInfo`: `CMS_add1_signer` calls
`X509_get_pubkey`, there is no provider for the composite OID, and it fails
with *private key does not match certificate*. The assemblers are checked
against OpenSSL's own output byte for byte on Ed25519 — see
`tests/test_composite_cms`.

**Not available in the FIPS-strict profile.** The composite mechanism ships in
the all-mechanisms profile only; in nist-approved-only every entry point refuses it. See
`docs/COMPOSITE_SIGS_GAP.md` for why.

**No third-party verifier exists yet.** No off-the-shelf tool can check a
Composite ML-DSA signature — OpenSSL 3.5 has no implementation. `fhsm-sign
verify` is currently the only way to check what `fhsm-sign sign` produced,
which is precisely why verification ships with the tool rather than after it.

**Detached only.** Neither form ever contains the data.

**CMS carries one signer and one certificate.** Countersignatures, certificate
chains and timestamps are not produced. `signingTime` is not added either —
OpenSSL adds it by default, this does not, because a signature that silently
records when it was made is a decision the operator should take rather than
inherit.

---

## See also

* [`FHSM_CSR.md`](FHSM_CSR.md) — keys, requests and the CA's own certificate
* [`FHSM_CA.md`](FHSM_CA.md) — issuing, revoking, revocation lists and OCSP
* [`COMPOSITE_SIGS_GAP.md`](COMPOSITE_SIGS_GAP.md) — what the composite
  implementation does and does not claim
