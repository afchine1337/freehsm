# FreeHSM C — v1.1.0 Release Notes

**Tag** : `v1.1.0`
**Date** : 2026-06-11
**Maintainer** : Afchine Madjlessi <afchine.mad@gmail.com>

---

## TL;DR

FreeHSM C v1.1.0 is a **PKCS#11 v3.2 cryptographic module** written in C11, candidate for **NIST FIPS 140-3 Level 1** and **Common Criteria EAL4+ augmented** (ALC_FLR.2 + AVA_VAN.5) certification.

This release includes the `.1` refresh : 11 task items closing 8 of the 11 NIST CST checklist items, a hardened DRBG layer, TPM 2.0 sealing, runtime mode switching between legacy and FIPS strict, and full bilingual documentation.

---

## Highlights

| Component | Status |
|---|---|
| **PKCS#11 v3.2 façade** | 78+ mechanisms declared, ~25 fully wired through OpenSSL FIPS provider |
| **FIPS-approved algorithms** | AES-{GCM,CBC-PAD,CMAC}, SHA-{2,3} family, HMAC, PBKDF2, RSA-{PKCS,OAEP}, ECDSA, ECDH, HKDF, ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s |
| **Hardened DRBG** | Multi-source seed (getrandom + RDRAND + /dev/urandom + TSC jitter) → SHA-256 conditioner → CTR_DRBG-AES-256 → RCT + APT + CRNGT health tests (SP 800-90B) |
| **Pair-wise consistency check** | Post-keygen sign-verify / encap-decap automatic round-trip (FIPS §7.10.2.b) |
| **TPM 2.0 sealing** | Companion-file approach, opt-in via `FHSM_TPM_SEALING=1` |
| **Runtime mode switch** | Default = legacy ; `FHSM_MODE=fips` enables FIPS strict |
| **Coverage matrix** | 27 PASS / 5 SKIP / 0 FAIL (5 SKIP = OpenSC CLI limitations only) |
| **Documentation** | Fully bilingual (EN + FR) for every CC class artefact ; 5 new docs for v1.1.0 |

---

## Verifying this release

```bash
# Verify the tag is signed
git verify-tag v1.1.0

# Verify the source tarball signature
gpg --verify freehsm-c-v1.1.0-src.tar.xz.asc

# Verify the source tarball digest
sha256sum -c freehsm-c-v1.1.0-src.tar.xz.sha256

# Verify the binary tarball
gpg --verify freehsm-c-v1.1.0-bin.tar.xz.asc
sha256sum -c freehsm-c-v1.1.0-bin.tar.xz.sha256

# Reproduce the build locally
tar xJf freehsm-c-v1.1.0-src.tar.xz
cd freehsm-c-v1.1.0/
make repro
sha256sum libfreehsm-fips.so
# Compare to the digest published in the release artefacts.
```

---

## Installation

```bash
sudo install -d /opt/freehsm/lib
sudo install -m 755 libfreehsm-fips.so /opt/freehsm/lib/
sudo useradd -r -d /var/lib/freehsm -m freehsm

# Use via pkcs11-tool :
pkcs11-tool --module /opt/freehsm/lib/libfreehsm-fips.so --list-mechanisms
```

For FIPS-conformant operation :

```bash
export FHSM_MODE=fips
```

For TPM-backed deployments :

```bash
sudo apt install tpm2-tools
export FHSM_TPM_SEALING=1
```

See [`docs/AGD_PRE.md`](docs/AGD_PRE.md) for the full preparative guidance.

---

## Known limitations

1. **CAVP coverage** : 2 vectors per algorithm beyond the smoke set ; full ~100-vector suites to be requested from the CST lab during the formal engagement.
2. **Legacy mode handlers** : MD5 and SHA-1 (digest only) are wired ; DES, 3DES, RC4 return `CKR_MECHANISM_INVALID` even in legacy mode (not yet implemented).
3. **Stateful PQ signatures** (LMS, XMSS) : PKCS#11 IDs reserved, full wiring deferred (requires careful state-counter persistence — see [`docs/POST_QUANTUM.md`](docs/POST_QUANTUM.md) §"Stateful signatures").
4. **`test_smoke`** : the static-linked harness cannot satisfy the integrity check without `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` (dev-only). Production validation is via the signed `.so` loaded through `dlopen` (see `/tmp/init_diag` example in CI logs).

---

## Upgrading

From `v1.1.0` (no `.1` suffix) :

1. Pull the new sources.
2. Re-run `make clean && make && make integrity`.
3. Replace `/opt/freehsm/lib/libfreehsm-fips.so`.
4. If you were previously running with implicit FIPS mode (no env var), now you MUST set `FHSM_MODE=fips` explicitly — the default has changed from FIPS-strict to legacy.

From the Python POC (v0.x) :

The on-disk `.tok` format is preserved. Existing tokens carry over verbatim — no re-keying required. See `tests/test_token_interop.c`.

---

## Acknowledgements

This release would not exist without :

- **The OpenSSL project** for the FIPS-validated CTR_DRBG-AES-256 and the EVP API that hosts our entire algorithm surface.
- **NIST CMVP and NIAP** for the published Security Policy templates and CAVP test vector sets.
- **The OpenSC project** for `pkcs11-tool`, which we use as the reference client in our test matrix.
- **OASIS PKCS#11 TC** for the v3.2 specification.

---

## Roadmap to v1.2.0

| Item | Owner | ETA |
|---|---|---|
| Full CAVP vector suites (AES, HMAC, SHA, RSA, ECDSA) | maintainer | 2026-Q4 |
| LMS / XMSS state-counter persistence | maintainer + community | 2027-Q1 |
| oqsprovider integration (Falcon, HQC) | community PRs welcome | 2027-Q1 |
| AVA_VAN.5 side-channel hardening (CT-PIN derive, AES-NI enforcement) | maintainer | 2027-Q2 |
| Formal CST lab submission | dependent on funding | 2027 |

---

**Project home** : (to publish) <https://github.com/AfchineMadjlessi/freehsm-c>
**Bug tracker** : (to publish) <https://github.com/AfchineMadjlessi/freehsm-c/issues>
**Security** : <afchine.mad@gmail.com> (see [SECURITY.md](SECURITY.md))
