<!--
Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# `fhsm-sign` — detached signatures with a post-quantum composite key

Signs arbitrary data with a Composite ML-DSA key held inside a PKCS#11 module,
and checks such signatures back. The data is streamed, so its size is not
bounded by memory.

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

That is a deliberate first step, not an oversight. Carrying the metadata is
what CMS/PKCS#7 is for, and CMS with a composite algorithm needs its
`SignedData` assembled by hand — OpenSSL cannot build a structure for an
algorithm it does not implement, the same obstacle the revocation lists ran
into. It is worth its own change rather than a rushed addition here.

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
size costs one SHA-512 pass and one composite signature, and nothing is held
in memory. Measured on 20 MiB: 0.31 s, 11.5 MiB peak resident.

### What a verifier checks, and in what order

`cms-verify` refuses early and for a stated reason:

1. the `signatureAlgorithm` is the composite OID with parameters absent;
2. the `messageDigest` attribute equals SHA-512 of the data you supplied;
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

`openssl cms -cmsout -inform DER -in file.p7s -print` reads the whole
structure, showing the composite OID as `undefined (1.3.6.1.5.5.7.6.48)` —
it has no name for an algorithm it does not implement. It cannot verify the
signature, for the same reason. That is the limitation stated below, not a
defect in the output.

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
| `--module PATH` | PKCS#11 module, default `./libfreehsm-fips.so` |
| `--slot N` | slot index, default 0 |

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
the interop profile only; in fips-strict every entry point refuses it. See
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

* [`FHSM_CSR.md`](FHSM_CSR.md) — requests, certificates and revocation lists
* [`COMPOSITE_SIGS_GAP.md`](COMPOSITE_SIGS_GAP.md) — what the composite
  implementation does and does not claim
