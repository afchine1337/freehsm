# PQC Composite Signatures — Who Ships What (#118)

**First written:** 2026-07-08 — as an audit of a marketing claim.
**Rewritten:** 2026-09-04 — the claim is gone; the survey it produced is kept.

---

## 0. What this document is, and what it stopped being

This started as an adversarial check on the sentence *"first OSS PKI + signing
toolkit with PQC composite signatures out-of-the-box"*, run before tagging
v2.0.0-beta. The check did its job: the claim was false, and the document said
so.

It then did something less useful. Having falsified one primacy claim, it
constructed a narrower one — a "category of one" — and worked out how to phrase
it so that it would survive an audit. That is not the same activity as finding
out what is true, and the project has no business doing it. FreeHSM is
Apache-2.0 software published for researchers, students, teaching, and for
people and institutions without a certification budget. It sells nothing, it
competes with nobody, and it has no landing page to defend.

What survives is the part that was research: a dated, sourced picture of which
projects implement composite signatures. That is worth keeping, because it is
what stops anyone here — including a future maintainer with a deadline — from
writing "first" again.

**The rule this document exists to enforce: FreeHSM makes no primacy claim of
any kind.** Not "first", not "only", not "the first open-source X". If a
statement's value depends on nobody else having done it, it does not go in the
README, the release notes, the announcements, or the code comments. What ships
is described by what it does.

---

## 1. The standard

`draft-ietf-lamps-pq-composite-sigs` (Composite ML-DSA for X.509):

* Version at last check: **draft-19** (2026-04-21)
* IESG state: **RFC Ed Queue** — RFC Editor "In Progress", IANA OID
  registrations "Expert Reviews OK"
* Combinations: ML-DSA-44/65/87 × {RSA-PKCS1v1.5, RSA-PSS, ECDSA, Ed25519,
  Ed448}
* Semantics: "AND" validation — both component signatures must verify

Source: <https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/>

Publication was expected in weeks rather than quarters as of 2026-07.
**Re-check the draft state before citing this section**; when the RFC number
lands, swap `draft-ietf-lamps-pq-composite-sigs` for it in code comments,
certificate profiles and docs.

---

## 2. Landscape (checked 2026-07-08, one correction 2026-08-15)

Who implements composite signatures, and in what kind of thing. Read as a
snapshot with a date on it, not as a ranking.

| Project | License | Composite status | Since | Signing tooling | Software HSM |
|---|---|---|---|---|---|
| **XiPKI 6.6.0+** | Apache-2.0 | ✅ Issues certificates with composite ML-DSA signature algorithms; composite ML-DSA/ML-KEM subject keys; composite keygen in the management CLI | 2026-03-15 | ❌ CA/OCSP/RA/ACME only | ❌ consumes an external PKCS#11 |
| **EJBCA (Keyfactor)** | CE = LGPL; EE = commercial | ✅ Composite keys documented (RSA/ECDSA/EdDSA + ML-DSA-44/65/87); Chimera (X.509 alt-ext hybrid) | EJBCA 9.x (2025–2026) | via SignServer | ❌ |
| **SignServer (Keyfactor)** | CE = OSS; EE = commercial | ✅ EE 7.6.0 (2026-02): composite keys + extended CMSSigner. Community Edition was at 7.3.2 at check time — composite not in CE | EE 2026-02 | ✅ code / CMS signing | ❌ |
| **Bouncy Castle** | MIT-style | ✅ Library-level composite (1.79+) | 2024–2025 | ❌ library | ❌ |
| **oqs-provider (OpenSSL 3)** | MIT | ⚠️ Experimental composite integration removed; pure/hybrid PQC X.509 + CMS available, not draft-composite | — | ❌ provider | ❌ |
| **step-ca, Dogtag, OpenXPKI, OpenBao/Vault PKI** | OSS | ❌ No composite support found (pure ML-DSA at best) | — | ❌ | ❌ |
| **SoftHSM2** | BSD-2 | ⚠️ **Corrected 2026-08-15**: ML-DSA and ML-KEM available via `--enable-mldsa` / `--enable-mlkem` (tracking issue #800). No composite. The earlier "no PQC at all" entry was wrong | 2026 | ❌ | ✅ |
| **EU DSS (European Commission)** | OSS | ❓ Composite status unconfirmed — eIDAS reference implementation | — | ✅ XAdES / CAdES / PAdES / JAdES / ASiC | ❌ |
| **Trustway Proteccio** | proprietary | ❌ Raw ML-DSA / ML-KEM / SLH-DSA, no composite (from the operational notes, #113) | — | ❌ | hardware HSM |

Sources:

* XiPKI changelog v6.6.0 — <https://github.com/xipki/xipki/blob/master/CHANGELOG.md>
* XiPKI README — <https://github.com/xipki/xipki>
* EJBCA PQC keys — <https://docs.keyfactor.com/ejbca/latest/post-quantum-cryptography-keys-and-signatures>
* EJBCA Chimera CA — <https://docs.keyfactor.com/ejbca/latest/hybrid-ca>
* SignServer 7.6 release notes — <https://docs.keyfactor.com/signserver/latest/signserver-7-6-release-notes>
* Keyfactor, state of composite signatures (Nov 2025) — <https://www.ejbca.org/resources/keymaster-the-current-state-of-composites-signatures-and-certificates/>
* oqs-provider — <https://github.com/open-quantum-safe/oqs-provider>
* PKI Consortium PQC Capabilities Matrix — <https://pkic.org/wg/pqc/pqccm/>
* SoftHSMv2 — <https://github.com/softhsm/SoftHSMv2>, issue #800 — <https://github.com/softhsm/SoftHSMv2/issues/800>
* EU DSS — <https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html>
* IETF composite draft — <https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html>
* Microsoft AD CS ML-DSA (KB5087539, May 2026) — <https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-ml-dsa-certification-authority>

The useful reading of this table is that composite signatures are arriving
everywhere at once, in libraries, in CAs and in signing servers, and that the
draft becoming an RFC will accelerate that. It is a field converging, not a
race with a winner.

---

## 3. Where FreeHSM actually stands

The module ships ML-DSA-65, ML-KEM-768 and SLH-DSA-SHA2-128f as PKCS#11
mechanisms. It **does not implement composite signatures** — see
`docs/COMPOSITE_SIGS_GAP.md` for the gap analysis and the conformance problem
found there.

Until a conforming implementation ships, no README, announcement, release note
or landing text may say this module does composite signatures. That restriction
is about honesty regardless of what anyone else ships, and it does not lapse
when the survey above changes.

---

## 4. Maintenance

Re-check and date a new entry when any of these happens:

1. The composite draft is published as an RFC (swap the reference everywhere).
2. FreeHSM implements composite signatures (§3 changes).
3. Anyone cites this table — it is a snapshot, and a stale snapshot presented as
   current is the failure mode this project keeps finding in other people's
   documentation.

Optional, if ever useful: verify composite presence in EJBCA CE source
(<https://github.com/Keyfactor/ejbca-ce>) rather than relying on the docs split
between CE and EE.

---

## 5. Trail

* **2026-07-08** — Original audit. Research passes over the OSS PKI landscape,
  XiPKI changelog dating, the EJBCA/SignServer CE-vs-EE split, IETF draft
  status, oqs-provider and Bouncy Castle, plus an adversarial counter-search.
  Falsified "first OSS PKI with PQC composite", which was then in the README and
  the announcement drafts, and had it removed. That part was worth doing.
* **2026-08-15** — SoftHSM2 row corrected: it does have ML-DSA and ML-KEM behind
  build flags. The original entry said it had no PQC at all. Recorded rather
  than silently fixed, because the error had been used in an argument.
* **2026-09-04** — Rewritten. Removed the claim variants, the recommended
  narrative, the "category of one" argument, the comparisons framed against a
  commercial product, and the action items about landing pages and strategy
  documents. Kept the standard's status, the landscape, the sources and the
  correction. Added the rule in §0: no primacy claims, in any wording.
