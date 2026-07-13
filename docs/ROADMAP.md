# Simorgh Labs / FreeHSM — Roadmap

Authoritative, living roadmap. Provenance: the phased plan from the planning
session, reconciled against what has actually shipped, plus the commercial-HSM
design study (`docs/DESIGN_NOTES_COMMERCIAL_HSM.md`), the rebrand plan
(`../REBRAND_CHECKLIST.md`), the brand reference
(`docs/SIMORGH_LABS_BRAND_REFERENCE.md`), the pkcs11-check campaign
(`docs/PKCS11_CHECK_CAMPAIGN.md` + `PKCS11_CHECK_FINDINGS.md`), and the
certification checklist (`docs/CST_LAB_SUBMISSION_CHECKLIST.md`).

Legend: ✅ done · 🟡 partial · ⏳ pending · ♻ continuous

---

## Layering (keep these categories clean)

* **FreeHSM** — the HSM *library* (`libfreehsm-fips.so`), PKCS#11 v3.2,
  FIPS 140-3 / CC EAL4+ evidence target. Apache-2.0.
* **Simorgh PKI** — the *product*: FreeHSM + CA + signing tool + operator +
  IaC modules. The integrated crypto-engineering stack.
* Anti-pattern to avoid (study): do **not** blur HSM and KMS. KMS-like features
  (policy engine, cross-cloud key sync, FPE) are a **post-v2.0** tier.

---

## Status at a glance

Phases 1–3 are essentially **complete**. The remaining real work is **Phase 4
(v2.0 = PKI tool + signing tool)**, the **rebrand mechanics** (repo rename +
domains — content is already rebranded), and two small threads (#126, #116).

---

## Phase 1 — before v1.5.0 (critical)

| # | Task | Effort | Status |
|---|---|---|---|
| #118 | Audit primacy claim "first OSS PKI + PQC composite" | ~4h | ✅ `docs/PRIMACY_AUDIT_PQC_COMPOSITE.md` — claim revised (pivoted to "PKI + signing + composite") |
| — | Rebrand migration (repo `freehsm-c`→`freehsm`, buy domains, brand everywhere) | ~10–12h | 🟡 Content rebrand ✅ (README, TRADEMARK, blog, brand ref, checklist). **Pending: repo rename on the 3 remotes + `freehsm.org`/`simorgh.io` domains** (see `REBRAND_CHECKLIST.md` phases 1–2) |

## Phase 2 — v1.5.0 (target 2026-07-20)

| # | Task | Effort | Status |
|---|---|---|---|
| #113 | Design notes "lessons from Trustway / Safenet / CipherTrust" | ~3h | ✅ `docs/DESIGN_NOTES_COMMERCIAL_HSM.md` |
| #108 | Token-store format doc (`TOKEN_STORE_FORMAT.md`) | ~2–3h | ✅ shipped |
| #110 | `CKO_CERTIFICATE` object support | ~3–4h | ✅ shipped (parser + store) |
| #125 | Integrate Denis Mingulov's pkcs11-check into CI | ~3–5h | ✅ shipped — plus a full hardening campaign (**361→<50 failures, 7→0 crashes**) |

## Phase 3 — v1.6.0 (target 2026-08-10)

| # | Task | Effort | Status |
|---|---|---|---|
| #107 | Session keys (`CKA_TOKEN=FALSE`) vs token keys | ~4h | ✅ session-object lifecycle implemented during #125 |
| #109 | TPM 2.0 sealing backend (machine-bound vault) | ~8h | 🟡 code present (`src/fhsm_tpm.c`, `src/fhsm_token_tpm.c`) — verify/finish + document |

## Phase 4 — v2.0.0-beta (target 2026-09-01) — **the MVP focus now**

| # | Task | Effort | Status |
|---|---|---|---|
| #112 | PKI tool (`fhsm-ca`, `fhsm-csr`, cert lifecycle, OCSP) + PQC composite sigs | ~14h | ⏳ **core of the v2.0 MVP** |
| #123 | Signing tool `fhsm-sign` L1+L2 (raw + CMS/PKCS#7), PQC-ready | ~10h | ⏳ **MVP multiplier** |

## Continuous / parallel

| # | Task | Cadence | Status |
|---|---|---|---|
| #116 | PQC watch (NIST + ANSSI + IETF + industry) → `docs/PQC_VEILLE.md` | quarterly ~1h | ♻ (create the doc) |
| #126 | PR to Denis's pkcs11-check README mentioning FreeHSM | after #125 | ⏳ **actionable now** (#125 done) — relationship + SEO backlink |

## Deferred — post-v2.0 stable

| # | Task | When | Notes |
|---|---|---|---|
| #106 | Exhaustive CC ATE_FUN test book | v2.0 stable +6mo | ANSSI EAL4+ submission → Tier-3 evidence |
| #111 | Network HSM via REST API | v2.5+ | The big architectural leap — wait for MVP validation |

---

## New design decisions to fold in (study Category B)

* **B1** Diátaxis documentation architecture.
* **B2** Portable key-blob format + `fhsm-export` / `fhsm-import` (sovereignty = freedom to migrate).
* **B3** Structured JSON logs (ECS/OTel) + Prometheus `/metrics`.
* **B4** Multi-source entropy pool (kernel DRBG + jitterentropy + TPM RNG + optional YubiKey/OpenTitan).
* **B5** K8s operator + Terraform provider + Ansible collection + Helm.
* **B6** SIEM plugins (Splunk/Datadog/Sentinel/QRadar) — Tier-4 monetization.
* **B7** Multilingual Tier-2 support (EN/FR/Persan/Arabic).
* **B8** Tier-2 SLA: 4h critical / 24h high / 5 business days medium-low.
* **B9** v3.x horizon: KMS + VM encryption + file encryption.

## Marketing claims (study Category C) — ready for the v2.0-beta landing

6 direct, defensible framings (verbatim in `docs/DESIGN_NOTES_COMMERCIAL_HSM.md`
§Category C): 20-year PKCS#11 lead, 23 signed releases + 3 GHSAs in 6 weeks vs
one version / 2 years, open token-store + migration tool, TPM tamper-resistance
at ~100× lower TCO, one year of incumbent maintenance ≈ a full EAL4+ evidence
package, "integrated crypto-engineering stack" vs "boxed HSM".

---

## The strongest insight — timing is the hidden strength

Bull/Atos Trustway has been in expert-flight for years and **no OSS project has
seriously taken over**. Each of these is individually a strong differentiator;
together they have **no OSS or commercial equivalent on the target geography**:

* 6-week release cadence vs their 2 years
* PKCS#11 v3.2 vs their v2.20
* integrated PKI + signing vs a boxed HSM
* DevOps-native vs zero cloud
* multilingual vs French-only
* **PQC composite** vs PQC-raw-only

The French OIV / defence / defence-industry market is actively looking for a
Proteccio alternative for exactly these reasons. The response arrives right as
they start searching. Entry window 2026–2027 (see GTM phasing).

## Go-to-market (study Category D)

| Phase | Timing | Action |
|---|---|---|
| 1 | v2.0-beta (2026-09) | Public announce, positioning vs Proteccio (claims C1–C6) |
| 2 | v2.0 stable (2026-12) | French OIV + defence procurement; Tier-3 evidence package |
| 3 | 2027-Q1 | Present at FIC 2027 (Lille) |
| 4 | 2027-Q2 | ANSSI CC EAL4+ QR evaluation kickoff |
| 5 | 2027-Q3/Q4 | MENA / Africa (GISEC, Black Hat MEA, Africa Cyber Defense Forum) |

## Honest scope boundary (study Category E)

Target the ~99% of the market that does **not** need FIPS 140-3 Level 3
*physical* security. Not matched (and that's fine): dedicated hardware TRNG,
physical tamper detection with auto-zeroization, Level 3 physical posture.
Compensated with TPM measured boot + integrity attestation + audit-log tamper
evidence; a physically compromised host is a lost host in our model.
