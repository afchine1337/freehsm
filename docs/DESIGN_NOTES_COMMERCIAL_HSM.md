# Design Notes from Commercial HSM Experience

*Captured 2026-07-04 by Afchine Madjlessi (Simorgh Labs) based on hands-on experience with commercial HSM products. This document informs the design decisions for FreeHSM library + Simorgh PKI product (v1.5.0 onwards).*

**Scope of this study** :

* **Focus** : Bull/Atos Trustway Proteccio (French HSM, ANSSI CC EAL4+, direct competitor to Simorgh PKI on FR/EU sovereign market segment)
* **Explicitly out of scope** :
  * **Thales CipherTrust** --- categorically different layer. CipherTrust is a KMS (Key Management System) built on top of an HSM, not an HSM itself. Different market segment, different design decisions, not a fair parallel to Simorgh PKI.
  * **Thales Safenet Luna** --- widespread but the interface is dated and trivial. Notable as an anti-pattern (widespread ≠ well-designed ; installed base can be a concurrent trap) but not worth detailed study --- its dominance is legacy inertia, not design merit.

**Method** : structured interview extraction of maintainer's hands-on experience with Proteccio, organized by pass. Each pass focuses on a specific dimension.

---

## Pass 1 --- Product positioning

### Market segment addressed

Trustway Proteccio targets an **extremely narrow, extremely regulated niche** :

* Défense française + état FR
* Organismes publics (administrations, services publics)
* **OIV** (Opérateurs d'Importance Vitale) --- French regulatory category for critical infrastructure operators (energy, water, telecom, transport, health, finance) with special cyber obligations under the LPM 2013 loi de programmation militaire
* Entreprises de l'armement français

**Implication for Simorgh PKI positioning** :
* Proteccio is **not competing for SMB, DevOps, cloud-native regulated orgs, or francophone Africa's growing PKI market**. That entire segment is uncovered by the French-sovereign incumbent.
* Simorgh PKI can position as **"sovereign-crypto for the 90% of the market Proteccio doesn't reach"** --- keeping the same trust posture (ANSSI-friendly, EU sovereignty, French heritage) but with modern DevOps ergonomics + PQC + tier-adaptive pricing.

### Form factors

Proteccio is **network HSM only** (FPGA + PCI-express architecture internally). Client interfaces provided :

* **PKCS#11** module (standard interface)
* **RPC client library** (proprietary custom protocol)
* **Configuration tool** (admin CLI)

**Critical gap** : Proteccio ships the HSM **but no PKI application on top of it**. No CA, no signing tool, no cert lifecycle management, no integrated developer experience. The customer must build all of that themselves or buy a separate product (typically IDnomic or a custom in-house PKI).

**Implication for Simorgh PKI** : this directly validates our MVP v2.0 = Option B (PKI suite) decision. **Shipping HSM + PKI + signing as one integrated product is the exact gap Proteccio leaves open**. Even the incumbent's most premium customers must currently piece together HSM (Proteccio) + PKI (separate vendor) + signing tool (separate vendor). Simorgh PKI ships all three integrated.

**PCI card form factor** : in Bull/Atos roadmap but **blocked and delayed** due to *"fuite des experts"* --- Bull/Atos is losing crypto engineering talent, which means their delivery of new form factors is stalling.

**Strategic implication** : Bull/Atos is a **weakening incumbent**. The French sovereign crypto market has an opportunity gap opening precisely because the incumbent cannot execute on their own roadmap. Simorgh PKI enters at a moment of maximal competitive vulnerability of the incumbent.

### Certification stack

* **CC EAL4+ QR ANSSI** --- Qualification Renforcée, the **highest level of ANSSI qualification**, well above standard EAL4+. Only a few French crypto products carry QR. This is the certification that unlocks the OIV / défense market.
* **eIDAS conformity** --- the EU regulation for electronic signatures, essential for qualified signatures in EU regulated markets
* **FIPS 140-2 or 140-3** --- in Bull/Atos roadmap but **blocked, same expert flight problem**. No timeline announced.

**Implications for Simorgh PKI certification strategy** (validates Decision 6 in STRATEGY.md) :
1. **ANSSI QR is the primary cert target** (not just EAL4+). This is a higher bar than we initially planned but corresponds to the market segment we can grow into over time.
2. **eIDAS conformity should be pursued in parallel** --- essential for the signing use cases (fhsm-sign L3 PAdES) that we've scoped for v2.1.
3. **FIPS is genuinely secondary for our target geography**. Even the incumbent hasn't shipped it. We can positively differentiate on time-to-cert vs the incumbent (if we start CMVP submission in 2027-Q3 and ship faster than Bull/Atos, we can claim "faster-to-FIPS than Trustway").

### Pricing (per-unit indicative)

| Tier | Price |
|---|---|
| **EL** Entry Level | 10 k€ |
| **HR** High Range | 20 k€ |
| **XR** Extra Range | 30 k€ |

Network HSMs are typically deployed in HA pairs, so real per-site cost is **20-60 k€ minimum**. Plus annual maintenance contracts on top (~20% of capital cost per year is industry standard = 4-12 k€/year/site).

**Implications for Simorgh PKI pricing** :

* At Tier 1 (free OSS FreeHSM library) we are **∞× cheaper** than Proteccio for any customer whose security requirements don't strictly require QR. That covers 90 %+ of the crypto-consuming market.
* At Tier 2 (Pro Support, ~10-30 k€/year/customer) we compete on **annual maintenance-equivalent pricing** while delivering full core product access, which Proteccio does not.
* At Tier 3 (ANSSI EAL4+ evidence package, ~25-50 k€ one-time + 5 k€/year) we can plausibly sell **for the same annual budget as one Proteccio maintenance contract** but with a certified alternative + community + PQC composite modernity that Bull/Atos will struggle to catch up on given their expert flight.

**Marketing framing** : "One year of Proteccio maintenance = one full ANSSI EAL4+ submission package with Simorgh PKI. Choose sovereignty that scales."

---

## Pass 2 --- What works well (to inspire from)

### Admin tool ergonomics (partial win)

Proteccio ships a **graphical admin tool** that is intuitive, bilingual (FR/EN), and covers the main operational tasks :

* Configure supported algorithms, key sizes, max key count per slot
* List keys, delete keys
* Encrypted backup of keys to file
* Configure slots (virtual HSM instances)
* **Create Shamir (M of N) installation cards** ← notable trust-anchor feature

**Limitations** :
* **Cannot create keys** through the admin tool --- only lists/deletes. Key creation must go through a separate application via PKCS#11.
* **Requires client-side installation on each admin workstation** --- the tool is a desktop application built on the RPC client library.

**Implications for Simorgh PKI** :
* **Copy** : bilingual (FR/EN) admin UI, intuitive layout, Shamir M-of-N install cards support (see decision below).
* **Improve** : ship a **web-based admin UI (SPA hitting our REST API #111)** rather than desktop-installed tool. Zero client install. Works from any browser. Modernizes what was already a strength.
* **Improve** : the admin UI **can create keys** end-to-end (not just list/delete). This closes the workflow gap Proteccio leaves open.

### Shamir M-of-N installation cards

Proteccio requires the install secret to be split into M-of-N Shamir shares, distributed on physical cards / tokens. Bringing the HSM online requires bringing together M of the N shares in physical presence. This is a strong trust-anchor pattern (no single administrator can compromise the HSM ; requires collusion of M administrators).

**Implications for Simorgh PKI** :
* **Adopt** : Shamir M-of-N as one of the backend options for #109 (install-time secret / sealing backend). List currently includes TPM 2.0 + AWS-KMS + GCP-KMS + Vault + kms-quorum. Add explicit Shamir-cards backend (physical smart cards / YubiKeys / paper QR codes as share carriers).
* **Modernize** : accept both physical shares AND soft-shares (encrypted files distributed to administrators, requiring their key to decrypt). This gives flexibility for non-defense customers who don't want physical cards.

### PKCS#11 compliance level : ANOTHER MAJOR STRATEGIC INSIGHT

Proteccio ships **PKCS#11 v2.20** ← this is important : **PKCS#11 v2.20 dates from 2004**. Simorgh PKI targets **v3.2** (2024).

**Twenty years of PKCS#11 evolution separate the two**. This is a MAJOR positioning opportunity :

| Feature | PKCS#11 v2.20 (Proteccio) | PKCS#11 v3.2 (Simorgh PKI) |
|---|---|---|
| Interface Framework | Legacy struct | Modern CK_INTERFACE + C_GetInterface |
| ML-KEM / ML-DSA / SLH-DSA (PQC) | NOT SUPPORTED | Native mechanisms |
| Message-based Encrypt/Decrypt/Sign/Verify | NOT SUPPORTED | Full C_MessageEncrypt* family |
| Login sessions with user types beyond SO/USER | NOT SUPPORTED | Extended session model |
| Ed25519 / Ed448 (EdDSA) | NOT STANDARD | Native support |
| SHA-3 family | NOT STANDARD | Native |
| Modern cipher modes (AES-GMAC, etc.) | Partial | Full |

**Marketing framing** : *"Simorgh PKI ships two decades of PKCS#11 spec evolution ahead of Trustway Proteccio, including all NIST-standard post-quantum algorithms."*

### Backup / restore cryptography (clean design)

Proteccio uses a proprietary but well-designed backup mechanism :

```
Install Secret (Shamir M-of-N shares)
     ↓  KDF (Bull/Atos proprietary)
Slot Base Key (per virtual HSM, unique)
     ↓  AES wrapping
Object DEK (per key object)
     ↓  AES-GCM
Actual key material
```

Cross-HSM restore works : a backup from HSM A slot X can be restored to HSM B slot Y **if and only if HSM A and HSM B were installed with the same Shamir install secret**. This is clean crypto : the install secret is the root of trust, everything else derives from it.

**Implications for Simorgh PKI** :

**Adopt this hierarchy** in the token store design (#108) with modern crypto :

```
Install Secret (Shamir M-of-N shares, TPM-sealed, or KMS-sealed --- pluggable backend from #109)
     ↓  HKDF-SHA-256 (RFC 5869)
Slot Base Key (per virtual HSM, 256-bit AES key)
     ↓  AES-256-GCM key wrap
Object DEK (per key object, 256-bit)
     ↓  AES-256-GCM
Actual key material (RSA, ECDSA, ML-KEM, ML-DSA, etc.)
```

**Cross-HSM restore semantic** : works if and only if the same install secret is available at the destination. This unlocks a strong **multi-site deployment story** (site A can backup to site B if administrators of both sites hold Shamir shares of the same install secret).

### What is genuinely a strength but not visible

* **FPGA hardware execution** : gives Proteccio a "trusted hardware execution environment" story for adversarial attack scenarios (fault injection, side-channel resistance, tamper detection). Not a performance advantage but a security surface argument.
  * **Implication for Simorgh PKI** : we cannot replicate custom FPGA hardware. But **TPM 2.0 sealing (already in roadmap #109)** provides an analogous "hardware-anchored trust" story at 100× lower cost. Every modern laptop/server has a TPM 2.0 ; every deployment can be machine-bound. Proteccio's FPGA advantage collapses when the customer has a TPM.

---

## Pass 3 --- What underperforms (to avoid)

### Documentation : well-maintained but indigestible

Proteccio's documentation is **kept up-to-date but architected badly** :

* Everything presented linearly in one large document
* **No Quick Start** guide (customer must read 50+ pages before doing anything)
* **No use case walkthroughs** (each customer must reverse-engineer their own use case from reference material)
* **No task-oriented how-to's**

**Implication for Simorgh PKI** : adopt the **Diátaxis framework** ([diataxis.fr](https://diataxis.fr/)) for documentation architecture, which explicitly separates :

* **Tutorials** (learning-oriented, 30-min hands-on paths) : "Get your first CA online in 30 minutes"
* **How-To Guides** (goal-oriented, per use case) : "How to sign a container image with PQC composite", "How to renew an expired cert without downtime", "How to migrate keys from Proteccio to Simorgh PKI"
* **Reference** (information-oriented, encyclopedic, deeper than any human needs) : full PKCS#11 mechanism list, config file schemas, CLI reference
* **Explanation** (understanding-oriented, conceptual) : "Why we chose ANSSI QR", "The mosaic architecture of our key hierarchy", "PQC composite signatures explained"

This is now the **industry-standard** doc architecture. Adopting it from day 1 is a low-cost, high-visibility differentiator.

### Support : FR-only + variable response times

Proteccio support :

* **French clients only** (support in French language only)
* Response time : **1 to 15 days** depending on ticket difficulty
* This alone excludes 100% of the MENA / Africa / EU non-French customer base

**Implication for Simorgh PKI** :

* Support must be **multi-lingual from day 1** : English + Français (already bilingual repo) + Persan (roadmap i18n decision) + Arabic on-demand (via Tier 2/3/4 support contracts if customer requests)
* Response SLA in Tier 2 support contract must be **stricter than Proteccio's 1-15 day range** : e.g., 4h business hours for critical, 24h for high, 5 business days for medium/low. This is standard for modern DevOps-era enterprise support.
* Community support (GitHub Discussions + Discord/Matrix) available for OSS Tier 1 users --- free but community-driven.

### Vendor lock-in : total for sensitive keys

Proteccio's sensitive / non-extractable keys **cannot migrate** :

* Not to another HSM brand
* **Not even to another Proteccio HSM installed with a different install secret**
* Install secret is stored in Shamir M-of-N smart cards (typically 3-of-5)

By design, this is a security feature. But it also creates **total vendor lock-in** for the customer.

**Implication for Simorgh PKI** :

Adopt a "**sovereignty means freedom to migrate**" narrative. Practical implementation :

* Document the token store format transparently in `docs/TOKEN_STORE_FORMAT.md` (roadmap #108)
* Ship an OSS `fhsm-export` / `fhsm-import` tool that produces a portable encrypted blob when given the install secret + destination public key
* Cross-installation migration works if the destination admin has authorization from the original install secret holders (via signed re-encryption command)
* Document a "migrate FROM Proteccio TO Simorgh PKI" guide (for extractable keys ; sensitive keys remain locked but at least the story is honest)

**Marketing angle** : *"Sovereignty means the freedom to change vendor. Simorgh PKI is the only sovereign crypto stack that documents its migration paths openly."*

### Release cadence : one version every 2 years, no CVE patches

**THIS IS THE BIGGEST DIFFERENTIATION OPPORTUNITY** in this entire study.

Proteccio release cadence :
* **One major version every 2 years** (CC EAL4+ QR ANSSI qualification is heavy and slow)
* **No CVE patches** between versions

FreeHSM / Simorgh PKI release cadence :
* **23+ GPG-signed releases in 6 weeks** (v1.1.0 to v1.4.0 as of 2026-06-28)
* **3 GHSAs publicly disclosed transparently** (v1.2.1 integrity-verify, v1.2.2 raw-CKM_ECDSA Denis disclosure, v1.1.0 key-leak retrospective)
* Same-day patch cycles when a bug is reported (Denis found the raw-CKM_ECDSA bug → v1.2.2 shipped 4 hours later → v1.3.0 shipped 4 hours after that closing all Denis-flagged slots)
* Full CHANGELOG + Security Target + Community disclosure

**Marketing angle** (strong) :

> "In the last 6 weeks, we shipped 23 GPG-signed releases and disclosed 3 security advisories transparently. Trustway Proteccio ships one version every 2 years and has never published a CVE patch. Which cryptographic supply chain would you want between you and a nation-state actor ?"

This is **not exaggeration or unfair framing** --- it's a direct read of published release notes vs undocumented incumbent behaviour. This becomes a very strong differentiation in modern-security-response conversations, especially for CISO / RSSI audiences.

### Cryptographic surface : good on FIPS, gaps on modern algorithms

Proteccio supports : AES + RSA + ECDSA + AES-GCM + **ML-KEM + ML-DSA + SLH-DSA** (they have PQC ! good for them)

Proteccio does NOT support :
* **EdDSA (Ed25519)** ← major modern gap. Ed25519 is the default signing algorithm for SSH, TLS 1.3, git commit signing, Signal, IPFS, Tor, etc. Not shipping Ed25519 in 2026 signals conservative-legacy posture.
* **SHA-3 family** ← FIPS 202 standard, less used in practice but still expected

FreeHSM already ships :
* **Ed25519** (with `Ed25519-export-roundtrip` KAT in boot verification, since v1.3.0)
* **SHA-3 family** (SHA3-256, SHA3-384, SHA3-512 all with FIPS 202 KAT vectors)
* **All three NIST PQC finalists** : ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128f

**Marketing angle** : *"We ship what modern applications use --- SSH, git commit signing, TLS 1.3, all use Ed25519. The incumbent doesn't have it."*

**Nuance on PQC narrative** : Proteccio has ML-KEM / ML-DSA / SLH-DSA support (good !). So our "first OSS with PQC" claim needs qualification. What we still hold uniquely :

* **First OSS PKI + signing toolkit with PQC composite signatures OOTB** (composite = classical+PQ hybrid per draft-ietf-lamps-pq-composite-sigs). Proteccio has raw PQC primitives but no PKI/signing tool exposing composite mechanisms.
* **First OSS PKI + signing toolkit period, integrated with HSM + CA + signing**
* Public audit primacy claim (#118) must include "PKI + signing" qualifier consistently to survive audit against Proteccio's HSM-only PQC support.

---

## Pass 4 --- What's missing (opportunity gap)

### Cloud / DevOps / IaC integration : totally absent

Proteccio has **zero native cloud/DevOps integration**. The only interface is "plug your PKCS#11 application on the RPC client library". There is :

* No native Kubernetes operator (no cert-manager integration, no secret store CSI driver)
* No Ansible / Terraform module
* No HashiCorp Vault integration
* No AWS Secrets Manager / GCP Secret Manager / Azure Key Vault interconnect
* No Helm chart, no operator SDK
* No cloud-native monitoring hook

**In 2026 this is a fatal gap for adoption**. Every serious devops team expects at least Ansible + Terraform modules and a Kubernetes operator.

**Implication for Simorgh PKI** : ship an **ecosystem-first strategy** from v2.0 stable onwards :

* `simorgh-pki-operator` (Kubernetes) — declarative CA/cert creation via Custom Resources
* `terraform-provider-simorgh` — IaC provisioning of slots, keys, PKI issuers
* `ansible-collection-simorgh` — automation modules
* `helm-chart-simorgh` — one-command deployment
* HashiCorp Vault secrets engine plugin
* Cloud KMS bridge : mount AWS-KMS / GCP-KMS as sealing backends (already in #109 roadmap)

### PKI services : totally absent

Proteccio is **just a hardware HSM box** with a PKCS#11 interface. Zero PKI services : no CA CLI, no OCSP responder, no CRL server, no ACME service.

**Real strengths that Proteccio does have** :

1. **Physical True RNG** (hardware entropy source) --- a real cryptographic quality advantage
2. **Tamper-resistant physical vault** with automatic "noircissement" (blackening / zeroization) mechanism : the box resets and erases all secrets on attack detection

**These are non-software-replicable features** of a hardware HSM. Software HSMs cannot fully match these. But we can offer **software-equivalent security posture** :

* **Entropy** : /dev/urandom (Linux kernel DRBG) + jitter entropy (Stephan Muller's jitterentropy-rngd) + optional TPM 2.0 RNG interface + optional external hardware RNG (Yubikey, OpenTitan) --- multi-source pooled to defeat single-source failures
* **Tamper resistance** : TPM 2.0 measured boot (PCR-sealed keys) + system integrity attestation + audit logs signed with append-only hash chain + optional integration with intrusion detection at OS level

**Marketing angle** : *"Proteccio has hardware tamper resistance in one non-portable box for 20-60 k€. Simorgh PKI provides tamper resistance via TPM 2.0 measured boot on any modern hardware (server, workstation, RPi) at zero cost. Different tradeoffs, same security posture at 100× lower total cost of ownership."*

### Observability : just varlog text files

Proteccio ships plain text logs to `/var/log`. That's it.

* No syslog forwarding built-in
* No CEF / JSON structured logging
* No SIEM integration (Splunk / Datadog / Sentinel / QRadar / Elastic)
* No metrics endpoint (Prometheus, StatsD)
* No internal observability dashboard

In 2026, this fails all modern DevOps + compliance requirements.

**Implication for Simorgh PKI** : ship **structured logging + observability** from day 1 :

* Emit structured JSON logs (following the ECS or OTel semantic conventions)
* Optional CEF format for legacy SIEM
* Native Prometheus `/metrics` endpoint on the daemon (task #111 REST API)
* Integration plugins (Tier 4 commercial) : Splunk HEC forwarder, Datadog Logs API, Microsoft Sentinel, IBM QRadar
* Audit log chain (already implemented with `audit_chain_head` in the token store) as tamper-evidence

This is a strong Tier 4 (premium plugins) monetization opportunity aligned with the economic model decision #121.

### Signing services : zero (validates fhsm-sign scope in v2.0 MVP)

Proteccio has **no signing services** on top of the raw HSM. No PAdES, no XAdES, no CAdES, no Cosign, no sigstore compatibility.

**Implication for Simorgh PKI** : this fully validates the **fhsm-sign L1-L6 roadmap** (task #123). The market has zero incumbent alternative for HSM-backed integrated signing tools. Simorgh PKI can OWN this category outright.

### Ecosystem wishlist (maintainer's personal want-list based on years of Proteccio use)

Things a modern crypto-adjacent product should offer but Proteccio doesn't :

| Feature | Priority for Simorgh PKI |
|---|---|
| Plugin PKI (CA + cert lifecycle) | **v2.0 core** --- fhsm-ca in MVP (already scoped, #112) |
| Signing tool (code / doc / container / email) | **v2.0 core + v2.x additions** --- fhsm-sign L1-L6 (already scoped, #123) |
| KMS (key management with policy engine) | v3.x+ (new task, post-v2.0 stable) |
| Key generation service (higher-level than raw C_GenerateKey) | v2.x (part of PKI tool workflows) |
| VM encryption (VCenter / VSAN / hypervisor integration) | v3.x+ (new task, enterprise Tier 4 plugin) |
| File encryption (transparent + LUKS-like + application-level) | v3.x+ (new task, could be OSS or Tier 4 depending on scope) |

These become the **v3.x roadmap horizon** post-v2.0-stable adoption.

---

## Extracted design decisions for FreeHSM / Simorgh PKI

Synthesis of Passes 1-4. Each item is either (a) already in the existing roadmap and validated by this study, (b) a new design decision to add, or (c) a marketing/narrative claim ready to use.

### Category A --- Already in roadmap, validated by this study

| Item | Roadmap ref | Proteccio validation |
|---|---|---|
| MVP v2.0 = PKI suite (integrated HSM + CA + signing) | Decision #115 | Proteccio ships zero PKI or signing --- huge open gap |
| PKCS#11 v3.2 support | Already shipped in FreeHSM | Proteccio still on v2.20 (20-year delta) |
| ML-KEM / ML-DSA / SLH-DSA support | Already shipped in FreeHSM | Proteccio also has PQC, so refine claim to "PKI + signing + composite" |
| Ed25519 support | Already shipped in FreeHSM | Proteccio lacks it |
| SHA-3 family support | Already shipped in FreeHSM | Proteccio lacks it |
| ANSSI CC EAL4+ QR as primary cert target | Decision #121 | Proteccio's cert level ; validates our target |
| eIDAS conformity in parallel | Decision #121 | Proteccio has it ; required for signing use cases |
| Persan + Français + English support | Decision #124 | Proteccio is FR-only (excludes MENA + Africa + EU non-French) |
| TPM 2.0 sealing backend | Task #109 | Software equivalent for hardware tamper resistance |
| Shamir M-of-N as sealing backend option | Task #109 (enrich) | Direct copy of Proteccio strength |
| fhsm-sign L1-L6 signing tool | Task #123 | Proteccio has zero signing services --- category to own |
| Rapid release cadence + transparent GHSA disclosure | Project culture (23 releases + 3 GHSAs in 6 weeks) | Proteccio ships every 2 years with no CVE patches |
| REST API (not RPC) for network HSM | Task #111 | Proteccio has custom RPC lib requiring per-workstation install |
| Web-based admin UI (SPA) | Task #130 | Proteccio has desktop-installed admin GUI |
| Native HA / replication | Task #131 | Proteccio's biggest weakness |

### Category B --- New design decisions to add

| # | Decision | Rationale |
|---|---|---|
| B1 | Adopt Diátaxis documentation architecture (tutorials + how-to + reference + explanation) | Proteccio has monolithic linear doc ; Diátaxis is industry-standard modular approach |
| B2 | Publish `docs/TOKEN_STORE_FORMAT.md` + ship `fhsm-export` / `fhsm-import` tool | Sovereignty means freedom to migrate ; Proteccio locks customers in |
| B3 | Structured JSON logging (ECS or OTel semantics) + Prometheus /metrics endpoint | Proteccio has plain text /var/log only |
| B4 | Multi-source entropy pool (kernel DRBG + jitterentropy + TPM RNG + optional YubiKey/OpenTitan) | Software equivalent of Proteccio's TRNG hardware advantage |
| B5 | Kubernetes operator + Terraform provider + Ansible collection + Helm chart | Proteccio has zero cloud/DevOps integration |
| B6 | Tier 4 premium plugins for SIEM integration (Splunk / Datadog / Sentinel / QRadar) | Monetization aligned with Decision #121, gap left by Proteccio |
| B7 | Multi-lingual technical support in Tier 2 contracts (EN + FR + Persan + Arabic on demand) | Proteccio is FR-only |
| B8 | SLA in Tier 2 support : 4h critical / 24h high / 5 business days medium-low | Proteccio's 1-15 day range is unacceptable in 2026 |
| B9 | v3.x roadmap horizon : KMS (key policy engine), VM encryption, file encryption | Wishlist from years of Proteccio use, opportunity gaps |

### Category C --- Marketing / narrative claims (ready to use)

Direct, defensible framings for landing pages, blog posts, keynotes :

1. > *"Simorgh PKI ships 20 years of PKCS#11 spec evolution ahead of Trustway Proteccio, including Ed25519, SHA-3, and all three NIST post-quantum finalists integrated with a PKI + signing toolkit."*

2. > *"In the last 6 weeks Simorgh Labs shipped 23 GPG-signed releases and disclosed 3 security advisories transparently. Trustway Proteccio ships one version every 2 years and has never published a CVE patch."*

3. > *"Sovereignty means the freedom to change vendor. Simorgh PKI documents its token store format openly and ships an OSS migration tool. The incumbent doesn't."*

4. > *"Proteccio has hardware tamper resistance in one non-portable box for 20-60 k€. Simorgh PKI provides tamper resistance via TPM 2.0 on any modern hardware at zero cost. Different tradeoffs, same security posture, 100× lower total cost of ownership."*

5. > *"One year of Proteccio maintenance ≈ one full ANSSI EAL4+ evidence package with Simorgh PKI. Choose sovereignty that scales."*

6. > *"The incumbent is a boxed HSM. We are the integrated crypto-engineering stack : HSM library + PKI CA + signing tool + operator + IaC modules. Everything a modern devops team expects, native from day 1."*

### Category D --- Strategic timing observation

Bull/Atos Trustway is a weakening incumbent :

* PCI card form factor : blocked (expert flight)
* FIPS certification : blocked (expert flight)
* Doc / support quality : degraded (variable response times, no modernization)
* Release cadence : slow (every 2 years)
* Feature roadmap : no visible modernization to close cloud/DevOps/PQC-composite gaps

**Window of opportunity for Simorgh PKI** : the French sovereign crypto market is looking for alternatives precisely because the incumbent cannot execute on its own roadmap. Entry timing 2026-2027 (v2.0 beta + stable) is optimal --- close enough to Bull/Atos's stall to be perceived as a fresh alternative, far enough from a hypothetical Bull/Atos recovery (which would take 3-5 years even if they solved the expert flight tomorrow) to be safe.

**Suggested go-to-market timing** :

| Phase | Timing | Action |
|---|---|---|
| 1 | v2.0-beta (2026-09) | Announce publicly with clean positioning vs Proteccio (marketing claims C1-C6 above) |
| 2 | v2.0 stable (2026-12) | Reach out to French OIV + défense procurement contacts ; offer Tier 3 evidence package |
| 3 | 2027-Q1 | Present at FIC 2027 (Lille, January) --- French cyber premier event |
| 4 | 2027-Q2 | Approach ANSSI directly for CC EAL4+ QR evaluation kickoff |
| 5 | 2027-Q3-Q4 | Broaden to MENA / Afrique via GISEC + Black Hat MEA + Africa Cyber Defense Forum |

### Category E --- Honest limitations (things Proteccio does that we can't replicate)

For internal use --- do NOT hide these in customer conversations. Being honest here builds trust :

* **Hardware TRNG** : Proteccio has a physical entropy source. Simorgh PKI relies on OS + jitter + optional TPM RNG. For customers with extreme entropy requirements (nation-state adversary threat model), Proteccio's dedicated TRNG is a real advantage. We can partially close via optional YubiKey / OpenTitan integration but never fully.
* **Physical tamper detection with automatic zeroization** : Proteccio's box physically detects attack (opening the case, temperature anomaly, voltage anomaly, X-ray) and self-destructs. Software HSM cannot match this. We compensate via TPM measured boot + integrity attestation + audit log tamper evidence, but a physically compromised host is a lost host in our model.
* **FIPS 140-3 Level 3 physical security posture** : Proteccio's box is designed to withstand physical attacks scored at Level 3 in FIPS 140-3. Software HSMs are inherently Level 1 for physical security (no physical protection). Customers who need Level 3 physical security (very rare, mostly military/defense) will always need hardware HSM. That's fine --- we're not competing for that specific customer.

**Positioning implication** : we target the **99% of the crypto-consuming market that does NOT need FIPS 140-3 Level 3 physical**. That's a massive market and it's underserved by both hardware HSMs (too expensive) and software HSMs (too primitive vs modern devops expectations). Simorgh PKI occupies the sweet spot.

---

---

## Anti-patterns identified (across the commercial HSM landscape)

Not specific to Proteccio, but insights from broader industry observation :

### Anti-pattern 1 : "Widespread ≠ well-designed"

Thales Safenet Luna dominates the installed base but its interface is dated and trivial. Its widespread adoption is inertia (existing integrations, migration cost), not merit. **Implication for Simorgh PKI** : don't optimize for compatibility with existing bad interfaces ; optimize for the interface a modern developer would want.

### Anti-pattern 2 : "Blur the HSM and the KMS categories"

Thales CipherTrust bundles KMS features on top of an HSM. This can confuse the buyer (is this HSM certification I'm buying, or KMS functionality?) and dilutes the CC/FIPS evidence path. **Implication for Simorgh PKI** : keep FreeHSM (HSM library) and Simorgh PKI (product) as clean categorical layers. KMS-like features (policy engine, cross-cloud key sync, format-preserving encryption) belong in a separate product tier post-v2.0 stable, not bundled into v2.0 core.

*(more anti-patterns to be added as the interview progresses)*

---

*End of design notes template. Each Pass section will be filled in as the interview progresses.*
