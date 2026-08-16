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
fhsm-sign sign   --label NAME [--in FILE] [--out FILE] [--module PATH] [--slot N]
fhsm-sign verify --label NAME --sig FILE [--in FILE] [--module PATH] [--slot N]
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

## Options

| Option | Meaning |
|---|---|
| `--label NAME` | key label inside the module |
| `--in FILE` | data to sign or check; `-` or absent means standard input |
| `--out FILE` | where the signature goes; absent means standard output |
| `--sig FILE` | the signature to check (`verify` only) |
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

**Not available in the FIPS-strict profile.** The composite mechanism ships in
the interop profile only; in fips-strict every entry point refuses it. See
`docs/COMPOSITE_SIGS_GAP.md` for why.

**No third-party verifier exists yet.** No off-the-shelf tool can check a
Composite ML-DSA signature — OpenSSL 3.5 has no implementation. `fhsm-sign
verify` is currently the only way to check what `fhsm-sign sign` produced,
which is precisely why verification ships with the tool rather than after it.

**Detached only.** The signature never contains the data.

---

## See also

* [`FHSM_CSR.md`](FHSM_CSR.md) — requests, certificates and revocation lists
* [`COMPOSITE_SIGS_GAP.md`](COMPOSITE_SIGS_GAP.md) — what the composite
  implementation does and does not claim
