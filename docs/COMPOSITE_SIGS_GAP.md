<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# `CKM_HYBRID_ED25519_ML_DSA_65` is not Composite ML-DSA

**Established 2026-08-03, while scoping #112.**
**Reference read: `draft-ietf-lamps-pq-composite-sigs-19`, 21 April 2026, IESG state RFC Editor Queue.**

The mechanism works and does something defensible. What is wrong is the label on
it: three places in this repository cite the LAMPS composite draft as the
mechanism's reference, and the mechanism does not implement that draft. This
matters more than a normal documentation slip, because "PQC composite signatures
out-of-the-box" is the project's stated differentiator and the basis of the
category claim in `PRIMACY_AUDIT_PQC_COMPOSITE.md`.

## What the draft specifies

Composite ML-DSA does not sign the message. It signs a **message representative**
built by a signature combiner (§2.2, §3.2):

```
M' := Prefix || Label || len(ctx) || ctx || PH( M )

Prefix = "CompositeAlgorithmSignatures2025"          (32 bytes, ASCII)
Label  = a value unique to each algorithm combination (§6)
ctx    = application context, 0-255 bytes
PH     = the pre-hash function for that combination

mldsaSig = ML-DSA.Sign( mldsaSK, M', mldsa_ctx = Label )
tradSig  = Trad.Sign( tradSK, M' )
s        = SerializeSignatureValue( mldsaSig, tradSig )
```

Note `mldsa_ctx = Label`: the per-algorithm label is *also* passed down as the
FIPS 204 context string, so the ML-DSA component is bound twice.

## What this module does

`dispatch_hybrid_ed25519_ml_dsa_65` (`src/dispatch/fhsm_dispatch_hybrid.c`):

```
sig_ed = Ed25519.Sign( sk_ed, M )       /* the raw message */
sig_pq = ML-DSA-65.Sign( sk_pq, M )     /* the raw message, no ctx */
out    = sig_ed || sig_pq
```

## The differences, in order of seriousness

**1. No signature combiner, therefore no non-separability.** Both components
sign the bare message. The Ed25519 output is consequently a valid *standalone*
Ed25519 signature over that same message: anyone can lift it out of the
concatenation and present it as a plain Ed25519 signature. §2.2 states the Label
exists precisely to "protect against component signature values being removed
from the composite and used out of context", and §9.2.3 is devoted to
non-separability. This is a missing security property, not a formatting
difference.

**2. No `mldsa_ctx = Label`.** The ML-DSA component is not bound to the
combination it belongs to.

**3. No pre-hashing.** The draft signs `PH(M)`; we sign `M`. Beyond conformance,
this is the operational point of §2.1 — a composite otherwise has to stream the
whole message to both primitives.

**4. Component order is reversed.** The draft serializes
`(mldsaSig, tradSig)`; we emit Ed25519 first. Trivial on its own, fatal for
interoperability.

**5. No composite `AlgorithmIdentifier`.** §6 registers an OID per combination.
Without one the signature cannot appear in an X.509 certificate, a CSR, or a CMS
structure at all — which is the entire point of the specification, and the
entire point of #112.

## What is actually true about the mechanism

It is a reasonable PQ/T hybrid of local design: two independent signatures, both
required to verify, giving defence in depth against a break in either primitive.
That is worth having and is what the mechanism name says —
`CKM_HYBRID_ED25519_ML_DSA_65`, a vendor mechanism at `0x80004201`, "hybrid",
not "composite".

The error is entirely in the citations. They are now corrected: the mechanism is
described as what it is, and the draft is referenced as the thing #112 will
implement rather than as the thing this code follows.

## How this happened, since the pattern is the point

The KEM combiner **in the same file** does it correctly:

```
ss = SHA3-256( ss_x25519 || ss_pqkem || ct_x25519 || ct_pqkem
               || "HYBRID-X25519-ML-KEM-768" )
```

A domain-separation label, hashed in, exactly as it should be. The technique was
understood and applied on one path and not the other, fifty lines apart. That is
the same defect shape this project has now found seven times in its own code —
a control wired to some of the paths that reach a state and not the rest — and
it turns out to be sitting in the flagship feature.

It survived because nothing tested it against anything external. The KAT vectors
are self-generated: they check that our verify accepts our sign, which is true
of any self-consistent construction, including a wrong one.

## Consequences for #112

The PKI tooling cannot issue draft-conforming composite certificates on top of
this mechanism. Implementing Composite ML-DSA properly therefore becomes task
zero of #112, ahead of any CA ergonomics — a CA that issues certificates nothing
else can verify is worth less than no CA.

The work is well-bounded, because the draft is finished and generous:

* §6 gives the OIDs and Label values per combination.
* §4 gives the serialization routines.
* **Appendix E is 150 pages of test vectors.** This time the implementation can
  be checked against someone else's numbers rather than our own.
* §10.4 shortlists recommended combinations, so we do not have to implement all
  of them. `MLDSA65-Ed25519` is the natural first target since both primitives
  are already in the module.

## Everything needed to implement `MLDSA65-Ed25519-SHA512`

Collected 2026-08-03 from the working group's repository — `Composite-MLDSA-2025.asn`
and `src/algParams.md`, the file `{::include}`-ed into §6, which is why the labels
are not in the draft's own markdown.

**The target combination**, and it is the draft's own recommendation: §10.4 says
that for applications requiring the signature primitive to provide SUF-CMA,
`id-MLDSA65-Ed25519-SHA512` is the one to focus implementation effort on. Both
primitives are already in this module.

| | |
|---|---|
| OID | `1.3.6.1.5.5.7.6.48` — `{ pkix(7) alg(6) 48 }` |
| Label | `COMPSIG-MLDSA65-Ed25519-SHA512` (ASCII, 30 bytes) |
| Pre-hash `PH` | SHA-512 |
| ML-DSA variant | ML-DSA-65 |
| Traditional | Ed25519 (`id-Ed25519`) |
| Key usage permitted | `digitalSignature, nonRepudiation, keyCertSign, cRLSign` |

§6 is explicit that labels are written as ASCII in the document and
implementations MUST convert them to their ASCII byte values before
concatenation.

### The construction, fully resolved

```
Prefix = "CompositeAlgorithmSignatures2025"                        (32 bytes)
         436F6D706F73697465416C676F726974686D5369676E61747572657332303235
Label  = "COMPSIG-MLDSA65-Ed25519-SHA512"                          (30 bytes)
         434F4D505349472D4D4C44534136352D456432353531392D534841353132

M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)

     with an empty ctx: 32 + 30 + 1 + 0 + 64 = 127 bytes

mldsaSig = ML-DSA-65.Sign( mldsaSK, M', mldsa_ctx = Label )
edSig    = Ed25519.Sign( edSK, M' )

sig      = mldsaSig || edSig          /* that order; no ASN.1 wrapping */
```

Note the Label appears twice and in two roles: inside `M'`, and as the FIPS 204
context string handed to the ML-DSA primitive. Both are required.

Neither the public key nor the signature value carries ASN.1 wrapping
(`-- KEY no ASN.1 wrapping --`, `-- VALUE no ASN.1 wrapping --` in the module),
consistent with §4 serializing by plain concatenation of the component encodings.
So concatenating was never the error — the order was, and everything upstream of
it.

### The combiner is verified against the draft's own worked examples

Appendix D publishes two fully worked `M'` constructions. Both were reproduced
byte for byte before any code was written, and both are now in the repository as
`kat/composite/mprime_appendix_d.txt`:

| | `M'` length | reproduced |
|---|---|---|
| empty ctx | 130 bytes | yes |
| 8-byte ctx | 138 bytes | yes |

They use `id-MLDSA65-ECDSA-P256-SHA512`, because that is the combination the
draft chose to work through, but the combiner is identical apart from the label,
so they validate the construction our implementation has to share. The 130 and
138 differ from our 127 only because that label is 33 bytes against our 30.

These vectors are in the tree **before** the implementation on purpose. The
reason the existing hybrid could sign the wrong thing for months is that its KATs
were self-generated: they establish that our verify accepts our sign, which is
true of any self-consistent construction, a wrong one included. This time the
check exists first and it is somebody else's arithmetic.

### Still to collect

Signature-level vectors for our own combination, from Appendix E — in the
working group's repository as `src/testvectors_wrapped.json`. Those exercise the
component signatures and the serialization; the combiner is already covered
above. Everything needed to start writing the code is now in hand.

## Claims to review before the v2.0 announcements

`PRIMACY_AUDIT_PQC_COMPOSITE.md` §5 rests on "PQC composite signatures
out-of-the-box". That is a statement about a future release, and it stays
truthful only if the composite that ships is the specified one. Until then, no
announcement, README, or landing text may describe this module as implementing
composite signatures.
