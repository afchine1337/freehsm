# Design Notes from Commercial HSM Experience

*Captured 2026-07-04 by Afchine Madjlessi (Simorgh Labs), from hands-on
operational experience with a commercial network HSM. Rewritten 2026-09-04 to
keep the factual observations and drop the positioning, pricing and marketing
material that made up most of the original draft.*

**What this document is.** A record of how one widely deployed commercial HSM
behaves in production — its interfaces, its key hierarchy, its documentation,
its release cadence — and what those observations suggest for the design of a
software PKCS#11 module. It is a study of another product, not a description of
FreeHSM. Nothing here should be read as shipped functionality.

**What this document is not.** It is not a competitive analysis, it does not
compare offers, and it makes no claim about any market. Products are named only
where the statement about them is verifiable and carries no judgement —
"Proteccio ships PKCS#11 v2.20" is a fact about a published interface version.

**Method.** Structured extraction of the maintainer's own experience operating
Bull/Atos Trustway Proteccio, organised by theme. Where a claim depends on a
version or a date, it is stated; where it does not, it should be read as a
snapshot of 2026-07.

---

## 1 --- Interfaces and form factor

Proteccio is a **network HSM** (FPGA + PCI-express internally). Client-side, it
exposes three interfaces:

* a **PKCS#11 module** (standard interface)
* an **RPC client library** (proprietary protocol)
* a **configuration tool** (admin CLI)

It ships the HSM and nothing above it: no CA, no signing tool, no certificate
lifecycle management. An operator needing those builds them or buys them
separately.

**PKCS#11 version.** Proteccio ships **PKCS#11 v2.20**, published in 2004.
FreeHSM targets **v3.2**, published in 2024. The interface delta is not a
matter of opinion — it is the list of what v3.0/v3.1/v3.2 added:

| Feature | v2.20 | v3.2 |
|---|---|---|
| Interface framework | Legacy struct only | `CK_INTERFACE` + `C_GetInterface` |
| ML-KEM / ML-DSA / SLH-DSA | absent | standard mechanisms |
| Message-based Encrypt/Decrypt/Sign/Verify | absent | `C_Message*` family |
| Ed25519 / Ed448 | non-standard | standard |
| SHA-3 | non-standard | standard |
| AES-GMAC and modern modes | partial | full |

This says what the two specifications contain. It says nothing about the
quality of either implementation.

---

## 2 --- Certification stack (observed)

* **CC EAL4+ QR ANSSI** — Qualification Renforcée. This is the qualification
  that opens the French OIV and defence market.
* **eIDAS conformity** — required for qualified electronic signatures in the EU.
* **FIPS 140-2/140-3** — announced on the vendor roadmap, not shipped as of
  2026-07.

Recorded here as context for what a hardware HSM in this segment carries.
FreeHSM holds no certification and seeks none; its evaluation documents are
published as examples of method, not as claims.

---

## 3 --- Administration

The graphical admin tool is intuitive and bilingual (FR/EN), and covers:

* algorithm, key-size and per-slot key-count configuration
* key listing and deletion
* encrypted backup of keys to file
* slot (virtual HSM) configuration
* **creation of Shamir M-of-N installation cards**

Two limits observed in use:

* it **cannot create keys** — creation goes through a separate application over
  PKCS#11
* it is a **desktop application** built on the RPC client library, so it must be
  installed on every administrator workstation

### Shamir M-of-N installation cards

The install secret is split into M-of-N Shamir shares carried on physical cards.
Bringing the HSM online requires M shares brought together in physical presence.
No single administrator can bring up the device alone.

Design note for FreeHSM: this is a trust-anchor pattern worth having as one of
the sealing backends in #109, alongside TPM 2.0 and the KMS backends, with both
physical and soft shares as carriers.

---

## 4 --- Key hierarchy and backup

The backup mechanism is proprietary but cleanly layered:

```
Install Secret (Shamir M-of-N shares)
     ↓  KDF (vendor proprietary)
Slot Base Key (per virtual HSM, unique)
     ↓  AES wrapping
Object DEK (per key object)
     ↓  AES-GCM
Actual key material
```

Cross-HSM restore works if and only if source and destination were installed
with the same Shamir install secret. The install secret is the root of trust;
everything else derives from it.

Design note for FreeHSM: the same shape, with published primitives, is what the
token store design (#108) should adopt —

```
Install Secret (Shamir shares, TPM-sealed or KMS-sealed --- pluggable, #109)
     ↓  HKDF-SHA-256 (RFC 5869)
Slot Base Key (per slot, 256-bit)
     ↓  AES-256-GCM key wrap
Object DEK (per object, 256-bit)
     ↓  AES-256-GCM
Key material
```

### Key portability

Sensitive / non-extractable keys cannot be migrated — not to another vendor, and
not to another unit of the same model installed with a different install secret.
This is a deliberate security property, and it is also, unavoidably, a
one-way door for the operator.

Design note: the corresponding work for FreeHSM is to document the token store
format (`docs/TOKEN_STORE_FORMAT.md`, #108) and ship export/import tooling, so
that the same security property does not also mean the format is unreadable
without the implementation. That is a documentation and tooling task, not a
claim of any kind about anyone else.

---

## 5 --- Documentation

The documentation is kept current. Its structure is:

* one large document, presented linearly
* no quick-start path
* no use-case walkthroughs
* no task-oriented how-tos

In practice this means a reader reaches their own use case by reading reference
material in order until they find it.

Design note for FreeHSM: this is the argument for the **Diátaxis** structure
(<https://diataxis.fr/>) — tutorials, how-to guides, reference and explanation
kept as four distinct kinds of document rather than one linear manual. The
observation is about document architecture, and applies to this repository's own
documentation at least as much as to anyone else's.

---

## 6 --- Support and release cadence (observed)

* Support is provided **in French only**.
* Observed response times range from **1 to 15 days** depending on ticket
  difficulty.
* **One major version roughly every two years**, which is consistent with the
  weight of a CC EAL4+ QR requalification.
* **No CVE patches observed between versions.**

The two-year cadence and the certification are the same fact seen from two
sides: a qualified product cannot ship quickly without re-opening its
qualification. FreeHSM ships frequently because it is qualified by nobody. This
is a trade-off, not a ranking — the fast cadence buys same-day fixes and buys no
assurance whatsoever.

---

## 7 --- Cryptographic surface (observed, 2026-07)

Supported: AES, RSA, ECDSA, AES-GCM, and **ML-KEM, ML-DSA and SLH-DSA** — the
post-quantum primitives are present.

Not supported: **Ed25519/EdDSA** and the **SHA-3 family**. Ed25519 is the
default signature algorithm of OpenSSH, of git commit signing and of several
widely deployed protocols — which is what makes its absence worth recording
here, since it determines which applications can use the device at all.

FreeHSM ships Ed25519 (with an export-roundtrip KAT at boot since v1.3.0),
SHA3-256/384/512 with FIPS 202 KAT vectors, and ML-KEM-768 / ML-DSA-65 /
SLH-DSA-SHA2-128f.

Because the commercial product does have PQC primitives, any FreeHSM statement
about post-quantum coverage has to be specific about what is actually different
— composite signatures exposed through tooling, which is **unbuilt** (#112) and
whose primacy is **unverified** (see `docs/PRIMACY_AUDIT_PQC_COMPOSITE.md`). No
"first" wording anywhere without that survey behind it.

---

## 8 --- Where the product's scope ends

Three things sit outside the boundary of what the device provides. Stated as
scope, not as deficiency — a hardware HSM that does one thing and stops is a
defensible design; it just means the operator supplies the rest.

### Automation and infrastructure-as-code

No Kubernetes operator, no cert-manager or CSI integration, no Ansible or
Terraform module, no Vault engine, no Helm chart. The only integration path is
to link an application against the PKCS#11 module or the RPC client library.

### Observability

Plain text logs in `/var/log`. No structured (JSON/CEF) output, no syslog
forwarding, no metrics endpoint.

Design note for FreeHSM: structured logs following OTel or ECS semantics and a
Prometheus endpoint on the daemon (#111) are cheap to add early and expensive to
retrofit. The audit log hash chain (`audit_chain_head` in the token store) is
already the tamper-evidence half of this.

### Services above the HSM

No CA, no OCSP responder, no CRL server, no ACME service, no document or code
signing (PAdES, XAdES, CAdES, Cosign/sigstore). The device is an HSM and stops
there.

---

## 9 --- What a hardware HSM has that software does not

Recorded plainly, because it is the part most easily glossed over:

* **Physical true RNG.** A dedicated hardware entropy source. A software module
  depends on the kernel DRBG, optionally jitter entropy, optionally a TPM RNG or
  an external device. Pooling several sources defends against one of them
  failing; it does not produce a hardware entropy source.
* **Tamper-responsive enclosure.** The unit detects case opening, temperature,
  voltage and radiographic anomalies and zeroises itself. A software HSM cannot
  do this. TPM 2.0 measured boot, integrity attestation and an append-only audit
  chain give tamper *evidence*, not tamper *response*; a physically compromised
  host is a lost host.
* **FIPS 140-3 physical security levels.** Physical security above Level 1
  requires physical construction. A software module is Level 1 on that axis by
  definition, whatever else it does.

The FPGA is worth naming separately: it gives a hardware execution environment
with fault-injection and side-channel resistance properties. TPM 2.0 sealing
(#109) is the nearest analogue available to a software module — it binds keys to
a machine, which is a different and weaker property than executing on tamper-
resistant hardware, and should be described as such.

---

## 10 --- Design decisions this study supports

Technical only. Each is either already in the roadmap or a note to add to it.

| # | Decision | Observation behind it |
|---|---|---|
| 1 | PKCS#11 v3.2 as the target interface | The installed base is on a 2004 specification; the gap is in the spec, not the implementation |
| 2 | Ed25519 and SHA-3 as first-class mechanisms | Concrete functional gap observed in a shipping product |
| 3 | Shamir M-of-N as a sealing backend option (#109) | Direct adoption of an observed trust-anchor pattern |
| 4 | HKDF-based install-secret → slot key → object DEK hierarchy (#108) | The observed hierarchy is sound; the primitives should be published ones |
| 5 | Publish the token store format + export/import tooling (#108) | An opaque format turns a security property into an operational dead end |
| 6 | Diátaxis documentation structure | Observed failure mode: a maintained but linear manual with no entry point |
| 7 | Structured JSON logging (OTel/ECS) + Prometheus endpoint (#111) | Observed: text files only |
| 8 | Multi-source entropy pooling (kernel DRBG + jitter + optional TPM/external RNG) | Partial software answer to a hardware TRNG; must not be described as equivalent |
| 9 | Web admin surface over the REST API rather than a per-workstation desktop tool (#130) | Observed: admin tool requires client-side install and cannot create keys |

---

## 11 --- Two design lessons, about no one in particular

**Deployment share and design quality are independent variables.** An interface
can be everywhere because of installed base and migration cost rather than
because it is the interface anyone would design today. Both things are usually
true at once. The lesson for a new implementation is not to be dismissive of
what is deployed — compatibility is a real user need — but not to treat
ubiquity as a design specification either.

**Keep the HSM layer and anything built above it separately bounded.** Where
key-management policy features are bundled into an HSM, it becomes harder for
an evaluator, or for anyone reading the documentation, to say what is inside the
cryptographic boundary and what is not. Keeping the PKCS#11 module and the
tooling above it as distinct, separately described layers is cheaper to explain
and cheaper to evaluate.

---

*Observations only. Anything read here as a plan is a misreading: the roadmap is
`docs/ROADMAP.md`, and it distinguishes what ships from what does not.*
