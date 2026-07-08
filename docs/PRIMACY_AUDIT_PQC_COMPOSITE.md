# Primacy Audit — PQC Composite Signatures Claim (#118)

**Date:** 2026-07-08
**Status:** COMPLETE — verdict rendered
**Scope:** Verify whether the marketing claim *"first OSS PKI + signing toolkit with PQC composite signatures out-of-the-box"* survives adversarial scrutiny before the v2.0.0-beta tag.
**Method:** Web research against every known OSS PKI, signing platform, and crypto library with PQC ambitions. Sources cited inline; all checked 2026-07-08.

---

## 1. Verdict (TL;DR)

| Claim variant | Verdict |
|---|---|
| "First OSS **PKI** with PQC composite OOTB" | ❌ **INVALID** — XiPKI shipped it 2026-03-15 |
| "First OSS **PKI + signing toolkit** with PQC composite OOTB" | ⚠️ **Technically alive, strategically fragile** — see §4 |
| "First OSS **software HSM with integrated PKI + signing toolkit** shipping PQC composite OOTB" | ✅ **DEFENSIBLE** — recommended pivot, see §5 |

**Bottom line: the raw "first OSS PKI" framing is dead. The narrative must pivot from "first PKI" to "first integrated HSM + PKI + signing product" — a category we occupy alone.**

---

## 2. The standard itself (context)

`draft-ietf-lamps-pq-composite-sigs` (Composite ML-DSA for X.509):

* Current version: **draft-19** (2026-04-21)
* IESG state: **RFC Ed Queue** — RFC Editor "In Progress", IANA OID registrations "Expert Reviews OK"
* **RFC publication is imminent** (weeks, not quarters)
* Combinations: ML-DSA-44/65/87 × {RSA-PKCS1v1.5, RSA-PSS, ECDSA, Ed25519, Ed448}
* Final semantics: "AND" validation (both component signatures must verify)

Source: https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/

**Implication:** the moment the RFC number drops, every vendor announces "RFC-compliant composite" within a release cycle. Whatever claim we make must be tagged and shipped **before** that wave.

---

## 3. Competitor matrix (evidence)

| Product | License / OSS status | Composite sigs status | Since | Signing toolkit? | Software HSM? |
|---|---|---|---|---|---|
| **XiPKI 6.6.0+** | Apache-2.0, fully OSS | ✅ **SHIPPED**: issues certs with composite ML-DSA signature algo, composite ML-DSA/ML-KEM subject keys, composite keygen in mgmt CLI | **2026-03-15** (v6.6.0 changelog) | ❌ No (CA/OCSP/RA/ACME only, no CMS/code-signing service) | ❌ No (consumes external PKCS#11) |
| **EJBCA (Keyfactor)** | CE = LGPL; EE = commercial | ✅ Composite keys documented (RSA/ECDSA/EdDSA + ML-DSA-44/65/87); Chimera (X.509 alt-ext hybrid) also available | EJBCA 9.x era (2025–2026) | Via separate product (SignServer) | ❌ No |
| **SignServer (Keyfactor)** | CE = OSS; EE = commercial | ✅ EE 7.6.0 (Feb 2026): composite keys + Extended CMSSigner with composite. ⚠️ **Community Edition is at 7.3.2 — composite NOT in CE** | EE: 2026-02 | ✅ Yes (code/CMS signing) | ❌ No |
| **Bouncy Castle** | MIT-style, OSS | ✅ Library-level composite support (1.79+); PoC deployments reported | 2024–2025 | ❌ Library, not a product | ❌ No |
| **oqs-provider (OpenSSL 3)** | MIT, OSS | ⚠️ Experimental composite integration **removed**; pure/hybrid PQC X.509 + CMS available, not draft-composite | — | ❌ Provider, not a product | ❌ No |
| **step-ca, Dogtag, OpenXPKI, OpenBao/Vault PKI** | OSS | ❌ No composite support found (pure ML-DSA at best, partial) | — | ❌ | ❌ |
| **SoftHSM2** | OSS | ❌ No PQC at all | — | ❌ | ✅ (nearest analog to us; no PKI, no signing, no PQC) |
| **Proteccio / Trustway (incumbent, commercial)** | Proprietary | ❌ Raw ML-DSA/ML-KEM/SLH-DSA only, **no composite** (per design-notes interview, #113) | — | ❌ | Hardware HSM |

Key sources:

* XiPKI changelog v6.6.0: https://github.com/xipki/xipki/blob/master/CHANGELOG.md — "Added support of issuing certificate with composite ML-DSA signature (specified in draft-ietf-lamps-pq-composite-sigs)"
* XiPKI README (feature list incl. composite keygen): https://github.com/xipki/xipki
* EJBCA composite keys: https://docs.keyfactor.com/ejbca/latest/post-quantum-cryptography-keys-and-signatures
* EJBCA Chimera CA: https://docs.keyfactor.com/ejbca/latest/hybrid-ca
* SignServer 7.6 release notes (composite, Feb 2026): https://docs.keyfactor.com/signserver/latest/signserver-7-6-release-notes
* Keyfactor composite state-of-play (Nov 2025): https://www.ejbca.org/resources/keymaster-the-current-state-of-composites-signatures-and-certificates/
* oqs-provider (composite removed): https://github.com/open-quantum-safe/oqs-provider
* PKI Consortium PQC Capabilities Matrix: https://pkic.org/wg/pqc/pqccm/

---

## 4. Why the "PKI + signing" qualifier is alive but NOT recommended as the headline

The qualified claim *"first OSS PKI **+ signing toolkit** with composite OOTB"* survives on a technicality today:

* XiPKI: PKI ✅ composite ✅ — but **no signing toolkit** (no CMS/code-signing service)
* Keyfactor: signing toolkit ✅ composite ✅ — but **only in Enterprise** (SignServer CE = 7.3.2, pre-composite); and EJBCA + SignServer are **two separate products**, not one toolkit

Reasons NOT to bet the landing page on it:

1. **One release kills it.** The day SignServer CE rebases past 7.6, Keyfactor's OSS stack has composite PKI + signing. We control neither the timing nor the announcement.
2. **It invites a definitional fight** we can't referee ("EJBCA CE + SignServer CE is a toolkit too"). Marketing claims that require a footnote to survive an audit are liabilities in ANSSI/OIV sales cycles.
3. **RFC imminent** (§2) → the whole field converges within ~2 quarters.

---

## 5. Recommended narrative pivot (fallback executed)

Per STRATEGY v2.0 §"Risk", the prepared fallback was *"first OSS PQC composite + HSM backend"*. The audit sharpens it:

> **The first open-source software HSM with built-in PKI and signing toolkit — PQC composite signatures out-of-the-box.**
> *Sign your code for the quantum era.* (tagline unchanged)

Why this is audit-proof:

* **Category of one.** XiPKI is a PKI that *talks to* HSMs. Keyfactor sells PKI and signing that *talk to* HSMs. SoftHSM2 is an HSM emulator with no PKI, no signing, no PQC. **Nobody else IS the HSM and the PKI and the signing tool in one OSS product.** The claim doesn't depend on a version-number race.
* **Survives the RFC wave.** Even when everyone has composite, the integrated-product framing still holds.
* **Aligned with #113 design notes**: our anti-Proteccio pitch is exactly "not a boxed HSM — an integrated toolkit" (K8s/DevOps native, PKCS#11 v3.2, 6-week cadence). One coherent story from marketing to docs.

Secondary claims (all verified, use freely):

1. "PKCS#11 **v3.2** software HSM — the incumbent French HSM ships v2.20" ✅
2. "PQC composite signatures per IETF LAMPS, aligned with the final RFC — the incumbent supports raw PQC only, no composite" ✅ (Proteccio: confirmed no composite, #113)
3. "Among the first OSS signing toolkits with composite CMS signing" — safe with "among" ✅

Claims to RETIRE immediately:

* ❌ "First OSS PKI with PQC composite OOTB" (falsified by XiPKI 6.6.0)
* ⚠️ "First OSS PKI + signing toolkit with composite" — do not use as headline; acceptable only in long-form comparisons WITH the CE/EE footnote, and re-audit before each use.

---

## 6. Action items

| # | Action | Owner | Deadline |
|---|---|---|---|
| 1 | Update STRATEGY.md Decision 2 headline to the pivoted narrative (§5) | strategy doc | before rebrand weekend |
| 2 | Scrub "first OSS PKI" phrasing from README, landing draft, announce templates | repo | before v2.0.0-beta tag |
| 3 | Re-run this audit the week of the v2.0.0-beta tag (check: SignServer CE version, XiPKI releases, RFC number assignment) | recurring | 2026-08-25 |
| 4 | Optional deep-dive: verify composite presence/absence in EJBCA CE **source** (github.com/Keyfactor/ejbca-ce) to harden footnote claims | backlog | opportunistic |
| 5 | Monitor RFC publication of pq-composite-sigs → swap "draft-ietf-lamps-pq-composite-sigs" for "RFC XXXX" in code comments, docs, certprofiles | repo | on RFC publication |

---

## 7. Audit trail

* 2026-07-08 — Initial audit (this document). Research passes: OSS PKI landscape, XiPKI changelog dating, EJBCA/SignServer CE-vs-EE split, IETF draft status, oqs-provider/BC library check, adversarial counter-search. Verdict: pivot executed per prepared fallback.
