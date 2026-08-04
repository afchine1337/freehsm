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

## Inputs already gathered for task zero

From `Composite-MLDSA-2025.asn` in the working group's repository
(`github.com/lamps-wg/draft-composite-sigs`), read 2026-08-03:

**Our target combination is `id-MLDSA65-Ed25519-SHA512`, OID `1.3.6.1.5.5.7.6.48`**
(`{ pkix(7) alg(6) 48 }`). Both primitives are already in the module, so this is
the natural first — and for the MVP, possibly only — composite to implement.
§10.4 of the draft shortlists recommended combinations rather than requiring all
eighteen.

Two useful details from the ASN.1 module:

* The public key and the signature value both carry **no ASN.1 wrapping**
  (`-- KEY no ASN.1 wrapping --`, `-- VALUE no ASN.1 wrapping --`), consistent
  with §4, which serializes by simple concatenation of the component encodings.
  So the concatenation itself is not the error — the order is
  (`mldsaSig || tradSig`), and the real error is upstream, in what gets signed.
* `CERT-KEY-USAGE { digitalSignature, nonRepudiation, keyCertSign, cRLSign }` —
  the composite is allowed to sign certificates and CRLs, which is what #112
  needs it for.

The pre-hash is SHA-512, as the combination name states.

**Still to collect before implementing:**

* the `Label` value for this combination (§6). The draft states labels are fully
  specified per algorithm and runtime-variable labels are forbidden.
* the Appendix E test vectors for `MLDSA65-Ed25519-SHA512`, which are what make
  this implementable with confidence rather than hopefully.

Both are in the draft text; neither was reachable in a single fetch because the
document is 233 pages. Collect them at the start of the implementation session,
from `https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-19.txt`.

## Claims to review before the v2.0 announcements

`PRIMACY_AUDIT_PQC_COMPOSITE.md` §5 rests on "PQC composite signatures
out-of-the-box". That is a statement about a future release, and it stays
truthful only if the composite that ships is the specified one. Until then, no
announcement, README, or landing text may describe this module as implementing
composite signatures.
