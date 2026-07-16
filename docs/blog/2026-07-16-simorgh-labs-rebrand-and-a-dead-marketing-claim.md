---
layout: default
title: "Simorgh Labs, FreeHSM, and a marketing claim we killed ourselves"
---

# Simorgh Labs, FreeHSM, and a marketing claim we killed ourselves

*2026-07-16*

Two announcements today. One is cosmetic, one is not.

## 1. The rebrand (cosmetic, deliberate)

The repository `freehsm-c` is now **`freehsm`**. Old URLs redirect. Nothing
else moves:

* Binary name stays `libfreehsm-fips.so`.
* PKCS#11 identifiers stay as they are (`manufacturerID = "Simorgh Labs"`).
* The GPG release key stays `743A 6A59 04A1 4616 46A6 408D E485 6016 2DBB F28A 2`.
* GHSA identifiers already published are permanent.

The naming is now explicit: **FreeHSM** is the Apache-2.0 PKCS#11 library.
**Simorgh PKI** is the product being built on top of it for v2.0 (a PKI CLI
plus a signing toolkit). **Simorgh Labs** is the entity that will carry the
FIPS 140-3 and CC EAL4+ submissions. A `TRADEMARK.md` now documents what you
can do with the names (almost everything) and what you cannot (call your
fork FreeHSM).

## 2. The claim we killed (not cosmetic)

Our v2.0 roadmap was built around a positioning line: *"the first
open-source PKI + signing toolkit with PQC composite signatures
out-of-the-box."* Before putting it on a landing page, we did what we said
we would do since the beginning of this project: we audited it as if we
wanted it to fail.

It failed.

**XiPKI 6.6.0** (Apache-2.0) shipped composite ML-DSA certificate issuance
per `draft-ietf-lamps-pq-composite-sigs` on 2026-03-15 — months before our
v2.0.0-beta target. Credit where due: it's a solid, compact PKI, and its
author co-authors IETF specs. Separately, **SignServer 7.6** added composite
signing in February 2026 (Enterprise edition only, for now), and the
composite draft itself (draft-19) is in the RFC Editor queue, so everyone
will converge on it soon.

The full audit — competitor matrix, dates, sources, retired claims — is in
the repo: [`docs/PRIMACY_AUDIT_PQC_COMPOSITE.md`](https://github.com/afchine1337/freehsm/blob/main/docs/PRIMACY_AUDIT_PQC_COMPOSITE.md).
We publish it for the same reason we publish security advisories against
ourselves: positioning claims that can't survive an adversarial audit are
technical debt with a marketing coat of paint.

## So what are we, then?

What the audit clarified is that nobody in open source occupies the
category we actually sit in. XiPKI is a PKI that talks to HSMs. Keyfactor
sells a PKI and a signing server that talk to HSMs. SoftHSM emulates an
HSM and stops there.

**FreeHSM/Simorgh PKI is the HSM, the PKI, and the signing toolkit in one
open-source product** — PKCS#11 v3.2 module with FIPS 140-3 / CC EAL4+
evaluation documents, and (with v2.0) certificate issuance and code signing
with PQC composite signatures out-of-the-box.

That is the claim we will ship with v2.0.0-beta. It doesn't depend on
winning a version-number race, and we re-audit it at tag time anyway.

*Sign your code for the quantum era.*
