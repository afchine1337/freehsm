# FreeHSM C --- NIST CST Lab Submission Checklist

Pre-submission checklist for a NIST-accredited Cryptographic and Security Testing (CST) lab seeking FIPS 140-3 Level 1 certification.

**Status :** This is the developer-side artifact list. The actual CST lab will issue their own Statement of Work and ask for additional items.

---

## A. Module Identity

- [ ] **Module name** : FreeHSM C
- [ ] **Version** : 1.1.0-FIPS (fixed at submission time ; any change requires re-validation)
- [ ] **Cryptographic boundary digest** : `dist/refs/v1.1.0.sha256` (committed and GPG-signed)
- [ ] **Build environment digest** : `Dockerfile.build` SHA-256 (committed)
- [ ] **Reproducibility proof** : `make repro && make dist-verify` returns 0 on at least two independent build machines

---

## B. Documents (Annex B of FIPS 140-3)

- [ ] **Security Target** : `docs/FIPS_140_3_SECURITY_TARGET.md` (this repo)
- [ ] **Algorithm Spec** : `docs/MECHANISMS.md` (78-mechanism table with FIPS-approval status)
- [ ] **Crypto Boundary Definition** : `docs/ARCHITECTURE.md` §3 (binary layout) + ELF `.fhsm_digest` section info
- [ ] **User/Admin Guidance** : `docs/AGD_PRE.md` + `docs/AGD_OPE.md` (FR + EN)
- [ ] **Functional Spec** : Inline Doxygen comments in headers + `docs/AGD_OPE.md` §4
- [ ] **Tests Documentation** : `tests/*.sh` (4 integration scripts) + `tests/*_e2e.c` (3 dlsym harnesses)
- [ ] **Source Code** : `freehsm-c-src.tar.xz` (tarball) + GPG signature
- [ ] **Build Instructions** : `Makefile` + `Dockerfile.build` + `docs/AGD_PRE.md` §3
- [ ] **Vendor Self-Assessment** : List of CKM_* and which are FIPS-approved (already in §3 of Security Target)

---

## C. CAVP Algorithm Validations (per §7.4)

The lab will require **published CAVP certificates** for every approved mechanism advertised. The OpenSSL FIPS provider already has cert #4282 covering the underlying primitives, but the lab will ask for our own CMVP-Implementation-Under-Test (IUT) certs derived from CAVP runs of our integration.

- [ ] Submit ACVP test vectors for the IUT (each algorithm × parameter set) to the lab
- [ ] Receive and embed in the cert : A-AES-####, A-SHS-####, A-HMAC-####, A-PBKDF-####, A-DRBG-####, A-RSA-####, A-ECDSA-####, A-KAS-####, A-MLKEM-####, A-MLDSA-####, A-SLHDSA-####

---

## D. Self-Test Evidence

- [ ] **Boot self-test** : Logs showing `fhsm_kat_results` after `C_Initialize` for every approved mechanism (use `tests/kat_report.c`) on the tested OE
- [ ] **Integrity verification** : Demonstrate that an artificially corrupted `.text` section causes `C_Initialize` to return `FHSM_RV_INTEGRITY_FAILED`
- [ ] **DRBG continuous test** : Code path exercise log (`tests/test_drbg.c` to be created)
- [ ] **Pair-wise consistency** : KAT log for `C_GenerateKeyPair` showing the sign+verify post-keygen

---

## E. SSP Management Evidence

- [ ] **Zeroization proof** : `fhsm_zeroize` test that demonstrates buffers are zero after `C_Logout`/`C_Finalize` (use `gdb` snapshots)
- [ ] **Key wrap algorithm justification** : PBKDF2 with 200 000 iterations (cite SP 800-132 §5)
- [ ] **DEK wrap scheme** : AES-256-GCM with serial as AAD (cite SP 800-38D)
- [ ] **PIN policy** : Throttle table, lockout after N=5, exponential backoff parameters
- [ ] **No keys in audit log** : `freehsm-audit dump` output showing only length-only event params

---

## F. Lifecycle Assurance Evidence (§7.11)

- [ ] **Version control** : git repository URL + signed tags
- [ ] **Build reproducibility** : Two-build comparison via `scripts/verify_reproducibility.sh`
- [ ] **Configuration management** : `Dockerfile.build` pinning gcc 14.2.0, binutils 2.40, OpenSSL 3.5.6
- [ ] **Delivery proof** : Signed release tarball + checksum file + GPG signature
- [ ] **Vendor incident response plan** : (to write) `docs/INCIDENT_RESPONSE.md`

---

## G. Test Suite

- [ ] **Functional tests** : `tests/integration_pkcs11.sh` (17 assertions) ; `tests/multi_slot_pkcs11.sh` (13) ; `tests/full_crypto_pkcs11.sh` (20)
- [ ] **End-to-end PQ** : `tests/mlkem_e2e`, `tests/mldsa_e2e`, `tests/slhdsa_e2e` (3 binaries)
- [ ] **External interop** : OpenSSL pkeyutl verify (already documented in `docs/AGD_PRE.md` §7) ; python-pkcs11 alternative client
- [ ] **Coverage matrix** : `tests/coverage_matrix.sh` exercising every wired C_* function × every wired mechanism (to be created)

---

## H. Operational Evidence

- [ ] **Audit log examples** : Sample `freehsm-audit dump` output showing the 13 event types over a full session
- [ ] **Multi-slot isolation** : `tests/multi_slot_pkcs11.sh` proof of cross-slot PIN rejection and object isolation
- [ ] **Error state demonstration** : Force integrity failure, observe LOCK + `C_*` rejecting

---

## I. Vendor Commitments

- [ ] **OE constraint enforcement** : `make integrity` refuses to sign on a build that contains non-FIPS providers loaded
- [ ] **Module manufacturer ID** : "FreeHSM C (FIPS 140-3)" embedded in `C_GetInfo` output
- [ ] **Version reporting** : "1.1.0-FIPS" in `C_GetTokenInfo`
- [ ] **Cert URL** : (post-cert) link in README to NIST cert page

---

## J. What the Lab Will Add

The lab will perform :
1. **Source review** of the boundary (typically 50-100 hours of senior reviewer time)
2. **CAVP test vector runs** on the tested OE
3. **Vendor questions** (typically 200+ rounds over 4-6 months)
4. **Penetration testing** for Level 2 candidates (AVA_VAN.5 if pursued)
5. **CMVP submission** : Lab files the Implementation Under Test (IUT) document with NIST CMVP

Total expected timeline : 6-12 months from initial submission to listed certificate.

Total expected cost : 80-200 k€ for Level 1, 200-500 k€ for Level 2 (excluding code remediation).

---

## K. Open items requiring code work

- [ ] Pair-wise consistency check after `C_GenerateKeyPair` (currently TBD)
- [ ] Full CAVP vector set for AES-GCM (currently 1 smoke vector)
- [ ] Full CAVP vector set for HMAC (currently 1 smoke vector)
- [ ] Continuous DRBG test wired into `fhsm_rng_bytes` (currently smoke-only)
- [ ] Side-channel hardening : audit + patches (see `docs/SIDE_CHANNEL.md`)
- [ ] TPM 2.0 sealing of DEK (see `src/fhsm_tpm.c` once implemented)

These items are tracked in the project's task list (#152, #153, #154 and follow-ups).
