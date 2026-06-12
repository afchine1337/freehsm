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

## Supported versions

| Version | Supported |
|---|---|
| `1.1.x-FIPS` | ✅ — active development + security backports |
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
