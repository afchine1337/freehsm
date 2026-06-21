# Security Policy

FreeHSM C is a cryptographic module : security vulnerabilities have direct impact on the confidentiality and integrity of every key managed by deployments.

We take security reports seriously and aim to acknowledge every responsible disclosure within **5 business days**.

Project lead : **Afchine Madjlessi** ([`afchine.mad@gmail.com`](mailto:afchine.mad@gmail.com))

---

## Maintainer GPG key rotation — 2026-06-12

The maintainer GPG signing key has been rotated. The previous key
`743A6A5904A1461A646408DE48560162DBBF28A2` (Ed25519, generated 2026-06-12)
was **compromised** : an ASCII-armored export of the private key was
accidentally committed to the public repository in commit `922c6f7`
during the initial open-source release.

Mitigations completed on 2026-06-12 :

- A revocation certificate was generated with reason **"Key has been
  compromised"** and pushed to `keys.openpgp.org` and
  `keyserver.ubuntu.com`. The old key now appears as `[revoked]` on
  any synchronized client.
- A new release signing key was generated :
  `743A6A5904A1461A646408DE48560162DBBF28A2` (Ed25519, valid until
  2028-06-11), published on the same keyservers.
- The git history on GitHub, GitLab and Codeberg was rewritten with
  `git-filter-repo --invert-paths --path afchine-secret-BACKUP.asc`
  to remove every blob reference to the leaked file. The current
  `git log -- afchine-secret-BACKUP.asc` is empty on all three
  mirrors.
- The release tag `v1.1.0` was re-signed with the new key and
  force-pushed.

If you cloned `freehsm-c` between 2026-06-12 morning and 2026-06-12
evening, your local clone may still contain the leaked file in
`.git/objects/`. You should re-clone from scratch:

```bash
rm -rf freehsm-c
git clone git@github.com:afchine1337/freehsm-c.git
```

If you previously verified the `v1.1.0` tag with the old key, please
re-verify with the new key — the signature has changed.

---

## Self-disclosed integrity self-test defect — v1.2.1 (2026-06-21)

A critical defect in the module's `§7.10.2` software / firmware integrity
self-test (`src/fhsm_integrity.c::do_verify`) was self-discovered and
self-corrected in v1.2.1.

**What was wrong.** The comparison block in `do_verify` was supposed to
return `FHSM_RV_INTEGRITY_FAILED` when the embedded SHA-256 (in
`.fhsm_digest`) did not match the runtime-computed SHA-256, and the
development bypass env var `FHSM_INTEGRITY_ALLOW_UNSIGNED` was not set.
The implementation fell through to a final `return FHSM_RV_OK` regardless
of the comparison outcome. As a result, a tampered `libfreehsm-fips.so`
would have passed the integrity self-test silently and the module would
have exposed cryptographic services on a binary that did not match the
signed digest.

**Affected releases.** Every signed release from v1.1.0 (origin :
commit `0c0f5df`, 2026-06-12) through v1.2.0 inclusive — that is, 19
GPG-signed releases over a 9-day window.

**Fixed in.** v1.2.1 (commit `63e1b35`, 2026-06-21). The fix returns
`FHSM_RV_INTEGRITY_FAILED` in both the all-zero (unsigned build) and the
mismatched-digest paths when the bypass env var is not set. Two adjacent
defects in the same translation unit (a use-after-free on the
`find_section_offset` failure path, and a `locate_self` regression for
binaries that statically link `fhsm_integrity.o`) were fixed in the same
commit ; see CHANGELOG entry for v1.2.1 and Security Target v0.7 §9.1.1
for the full breakdown.

**Validation.** A reproducible artifact (`tests/test_smoke.tampered`,
1 byte flipped in `.text` outside `.fhsm_digest`) is rejected with
`C_Initialize` returning `0x80000002 = FHSM_RV_INTEGRITY_FAILED` on
v1.2.1. The same artifact is accepted silently by v1.2.0, confirming
the defect's behaviour on the affected window.

**Disclosure decision : no CVE.** The project is in pre-certification
status (FIPS 140-3 Level 1 / CC EAL4+ candidate) with no known production
deployments. The defect is disclosed transparently via :

- the CHANGELOG entry for v1.2.1 ;
- this SECURITY.md section ;
- the updated Security Target v0.7 (§9.1.1 and §13.8) ;
- a GitHub Security Advisory published in **informational mode** (no CVE
  identifier) on the project's repository.

A CVE will be requested for any equivalent defect found post-certification
or post-first-deployment, following the standard MITRE coordination
described in [§Patch process](#patch-process) below.

**Recommended action for anyone running v1.1.0 through v1.2.0.** Upgrade
to v1.2.1 when it ships (within 48 hours of this writing). The upgrade is
a drop-in `.so` replacement ; PKCS#11 wire compatibility is unchanged.
Either re-sign the embedded digest via `make integrity` from the v1.2.1
source, or take the pre-signed binary tarball directly from the v1.2.1
GitHub Release.

For installations where an immediate upgrade is not possible, the interim
mitigation is to verify the SHA-256 of the deployed `.so` against the
value published in the corresponding release notes by an out-of-band
channel (e.g. download `sha256sum` from the GitHub Release page over
HTTPS, compare with `sha256sum` on the running binary). This restores
the integrity guarantee externally to the module's own self-test.

**Discovery + correction protocol.** This defect was found by following
the five-step protocol described in Security Target v0.7 §13.8 :
symptom triage in dev → read both sides of the disagreement → cross-check
the contract → produce a killer-test artifact → scope the temporal impact
via `git blame`. The protocol generalises the cross-validation
triangulation methodology established for KAT data between v1.1.13 and
v1.1.18 (§13.6 of the same Security Target) and is now documented as the
standing practice for any future evidence-bearing surface defect.

---

## Supported versions

| Version | Supported |
|---|---|
| `1.2.x-FIPS` | ✅ — active development + security backports (v1.2.1 is the first version not affected by the integrity self-test defect described above) |
| `1.1.x-FIPS` | ⚠️ — security backports only ; **all v1.1.x versions are affected by the integrity self-test defect ; upgrade to v1.2.1 is strongly recommended** |
| `1.0.x-FIPS` | ⚠️ — security fixes only until 2027-06 |
| `< 1.0` | ❌ — end of life (Python POC, not certified) |

---

## Reporting a vulnerability

**Do NOT open a public GitHub issue, pull request, or discussion thread.**

Instead :

1. Email [`afchine.mad@gmail.com`](mailto:afchine.mad@gmail.com) with subject prefix `[FreeHSM-SECURITY]`.
2. Encrypt the body with the maintainer's GPG public key (fingerprint below).
3. Include :
   - A description of the vulnerability.
   - The affected version(s) and architecture(s).
   - A proof-of-concept (PoC) or reproduction steps.
   - Your suggested severity (low / medium / high / critical).
   - Whether you would like to be credited in the advisory and how (handle, name, affiliation).

### Acknowledgement timeline

| Step | Target |
|---|---|
| Acknowledgement | ≤ 5 business days |
| Triage + initial assessment | ≤ 10 business days |
| Patch development | ≤ 30 days for critical, ≤ 90 days otherwise |
| Coordinated disclosure | 90 days from report (configurable on request) |
| Public advisory + CVE | Same day as patched release |

---

## Severity classification

We follow CVSS v3.1. Examples relevant to a PKCS#11 module :

| Severity | Examples |
|---|---|
| **Critical** | Key extraction via timing side-channel ; DRBG output predictability ; integrity bypass without `FHSM_INTEGRITY_ALLOW_UNSIGNED` |
| **High** | PIN-throttle bypass ; audit-log tampering ; CKA_SENSITIVE leak |
| **Medium** | Denial of service on `C_Initialize` ; misleading `CKR_*` return codes |
| **Low** | Information leak in error messages ; non-critical use-after-free in unauthenticated state |

---

## Patch process

1. The maintainer assigns a CVE via MITRE (or GitHub Security Advisory).
2. A private fork is created with the fix.
3. The patch is reviewed by at least one independent reviewer holding sufficient cryptographic expertise.
4. The fix is backported to every supported release branch.
5. A coordinated release date is agreed with the reporter.
6. On release day :
   - Patched tags are pushed (`v1.1.<patch>-FIPS`).
   - A signed advisory is published on the project's GitHub Security Advisories page.
   - The reporter is credited in the advisory (unless they declined).
   - The `CHANGELOG.md` is updated with a `### Security` entry citing the CVE.

---

## Hardening guidance (operator side)

Even with the latest patches applied, the following operational controls are **mandatory** to keep the certified configuration valid :

- `FHSM_INTEGRITY_ALLOW_UNSIGNED` MUST NOT be set in production.
- `FHSM_MODE=fips` MUST be set for any deployment claiming FIPS 140-3 conformance.
- TPM 2.0 sealing (`FHSM_TPM_SEALING=1`) is RECOMMENDED for any deployment storing long-lived keys.
- Audit log MUST be reviewed at least weekly ; alarms on `FHSM_EV_INTEGRITY_FAIL`, `FHSM_EV_KAT_REPORT (rv != OK)`, `FHSM_EV_LOGIN_LOCKED` MUST be paged.

See [`docs/AGD_OPE.md`](docs/AGD_OPE.md) §4 for the full operational hardening guide.

---

## Out of scope

The following are NOT considered vulnerabilities :

- Issues affecting only `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` dev mode.
- Issues that require root access on the host (out-of-boundary attacker per FIPS 140-3 §7.7).
- Issues in third-party dependencies (OpenSSL FIPS provider, tpm2-tools, etc.) — please report those upstream.
- Issues in mechanisms exposed only when `FHSM_MODE=legacy` (the operator has explicitly opted out of FIPS-strict).

---

## GPG public key

```
pub   ed25519 2026-06-11 [SC]
      <fingerprint to be filled at first signed release>
uid           Afchine Madjlessi <afchine.mad@gmail.com>
sub   cv25519 2026-06-11 [E]
```

The full public key is available at [`https://keys.openpgp.org`](https://keys.openpgp.org) once the maintainer has published it. Until then, request the key via email.
