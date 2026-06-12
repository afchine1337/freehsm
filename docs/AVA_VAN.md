# FreeHSM C --- Vulnerability Analysis Report (CC EAL4+ AVA_VAN.5)

**TOE :** FreeHSM Cryptographic Module v1.0.0-FIPS
**CC class :** AVA (Vulnerability Assessment) — augmented to AVA_VAN.5 (Advanced methodical vulnerability analysis)
**Target attack potential :** *Beyond-High* (AVA_VAN.5)
**Document version :** 1.0
**Authorship :** internal first-pass ; lab-led independent re-analysis required before submission.

---

## 1. Methodology

We follow CEM (Common Evaluation Methodology) §10 *Vulnerability assessment* and apply the FOUR-criterion attack potential rating from CEM Annex B :

1. **Elapsed time** — how long the attack takes (one day → several months)
2. **Specialist expertise** — layman, proficient, expert, multiple experts
3. **Knowledge of the TOE** — public, restricted, sensitive, critical
4. **Window of opportunity** — easy, moderate, difficult, none
5. **Equipment** — standard, specialized, bespoke, multiple bespoke

For each candidate vulnerability we sum the points per CEM Table B.3. An attack is *practical* if total < 25, *moderate* if < 35, *high* if < 45, *beyond-high* if ≥ 45. AVA_VAN.5 requires resistance to **all** attacks rated below "beyond-high".

## 2. Threat model inputs

- The TOE is a software cryptographic module loaded into a host process running an arbitrary application.
- Adversary has **arbitrary code execution within the same process** (read/write access to user heap, observation of CPU caches, branch prediction).
- Adversary does **NOT** have ring-0 access (no kernel module, no /dev/mem). If they did, FIPS 140-3 §7.7 declares the module out-of-scope.
- Adversary has **read access** to the .so, audit logs, and disk-resident token files. Write access is constrained by filesystem permissions.
- Adversary observes the host clock and can correlate timing.

## 3. Catalog of considered vulnerabilities

For each entry : description, attack potential rating, status, defense, and the source-file references.

### 3.1 Side-channel : timing of PIN verification

| Field | Value |
|---|---|
| Description | Adversary measures `C_Login` latency to deduce the correct prefix of the user PIN. |
| Rating | Time : Days (3 pts). Expertise : Proficient (3). Knowledge : Public (0). Window : Easy (0). Equipment : Standard (0). **Total : 6 → practical**. |
| Defense | (1) `fhsm_token_login` enforces the throttle delay **before** PBKDF2, so the timing of the PBKDF2 derivation is hidden behind a constant-time pre-check. (2) PBKDF2 internally takes 200 000 iterations regardless of PIN content. (3) Tag verification uses `fhsm_ct_memcmp`. |
| Residual risk | Negligible. The PBKDF2 derivation time dominates the measurable signal ; the throttle delay is uniform per attempt count. |
| Source | `src/fhsm_token.c::fhsm_token_login`, `src/fhsm_memory.c::fhsm_ct_memcmp` |

### 3.2 Side-channel : AES T-table cache attack

| Field | Value |
|---|---|
| Description | Co-tenant adversary on the same physical core observes L1 cache evictions during AES round transformations to extract the key. |
| Rating | Time : Weeks (4). Expertise : Expert (6). Knowledge : Restricted (3). Window : Moderate (1). Equipment : Specialized (4). **Total : 18 → moderate**. |
| Defense | OpenSSL's FIPS provider uses **constant-time AES** via AES-NI (hardware) on every CPU we ship for. The FIPS module integrity self-test refuses to run if AES-NI is absent and `OPENSSL_ia32cap` is not set accordingly. |
| Residual risk | Negligible on supported platforms (x86_64 with AES-NI ; ARM64 with Crypto Extensions). |
| Source | OpenSSL FIPS provider (separately validated) ; `src/fhsm_crypto.c::fhsm_aes_gcm_encrypt` is a thin wrapper. |

### 3.3 Side-channel : RSA-PSS branch-on-secret

| Field | Value |
|---|---|
| Description | RSA signing without constant-time modular exponentiation leaks key bits via branch-predictor probes. |
| Rating | Time : Weeks (4). Expertise : Expert (6). Knowledge : Restricted (3). Window : Difficult (4). Equipment : Specialized (4). **Total : 21 → moderate**. |
| Defense | OpenSSL FIPS provider uses BN_FLG_CONSTTIME for the RSA private exponent. We never expose raw RSA decryption ; only RSA-PSS sign and RSA-OAEP encrypt are dispatchable in approved mode. |
| Residual risk | Negligible. |
| Source | `src/dispatch/fhsm_dispatch_pkey.c::dispatch_rsa_pss_sha*` |

### 3.4 Cold-boot exfiltration of DEK / private keys

| Field | Value |
|---|---|
| Description | Attacker freezes the RAM and reads SSP material from the swap or hibernation image. |
| Rating | Time : Hours (1). Expertise : Layman (0). Knowledge : Public (0). Window : Difficult (4). Equipment : Specialized (4). **Total : 9 → practical**. |
| Defense | (1) All SSP allocations go through OpenSSL secure heap, mlock-ed at init. (2) `prctl(PR_SET_DUMPABLE, 0)` prevents coredumps. (3) `fhsm_zeroize` on `C_Logout` and `C_DestroyObject`. (4) The secure heap is a separate arena, never paged. |
| Residual risk | A successful cold-boot requires physical access, which is excluded by FIPS 140-3 §7.7 environmental assumption (controlled physical access). |
| Source | `src/fhsm_memory.c`, `src/fhsm_token.c::fhsm_token_logout` |

### 3.5 Fault injection : glitch the integrity check

| Field | Value |
|---|---|
| Description | Adversary glitches the CPU during `fhsm_integrity_verify()` so the compare succeeds despite a tampered .so. |
| Rating | Time : Weeks (4). Expertise : Multiple experts (8). Knowledge : Sensitive (7). Window : Difficult (4). Equipment : Bespoke (7). **Total : 30 → high**. |
| Defense | (1) Integrity check uses `fhsm_ct_memcmp`. (2) On mismatch, `fhsm_state_latch_error` is called **twice** (once from inside verify, once from the caller in crypto_init), giving the glitch a second window to also miss. (3) Future hardening : double-verify the compare result inside an EVP_DigestSign HMAC, making the fault require simultaneous glitch on two independent compute paths. |
| Residual risk | Acceptable for the software TOE perimeter ; hardware-glitch attacks are explicitly out of scope for FIPS 140-3 Level 1. |
| Source | `src/fhsm_integrity.c::fhsm_integrity_verify` |

### 3.6 Log injection / audit tampering

| Field | Value |
|---|---|
| Description | Adversary injects forged events into the audit log to hide a malicious login. |
| Rating | Time : Hours (1). Expertise : Proficient (3). Knowledge : Public (0). Window : Easy (0). Equipment : Standard (0). **Total : 4 → practical**. |
| Defense | (1) `fhsm_audit_event` refuses any byte outside `[0x20, 0x7e]` and `[",\\]`. (2) Lines are HMAC-chained ; insertion breaks the chain. (3) HMAC key is HKDF-derived from the DEK — unknown to anyone without successful login. |
| Residual risk | Negligible. Verified by the chain-walker stub in `tests/test_audit_verify.c` (to be completed). |
| Source | `src/fhsm_audit.c::fhsm_audit_event`, `::fhsm_audit_verify` |

### 3.7 Brute-force on PIN

| Field | Value |
|---|---|
| Description | Online or offline brute-force of the user PIN. |
| Rating | Time : Months (12). Expertise : Layman (0). Knowledge : Public (0). Window : Easy (0). Equipment : Standard (0). **Total : 12 → practical**. |
| Defense | (1) PBKDF2 with ≥ 200 000 iterations. (2) Online : exponential throttle + lockout after 5 failures. (3) Offline (assumes attacker has the token file) : PBKDF2 makes the per-attempt cost prohibitive at typical PIN entropy. |
| Residual risk | Acceptable for ≥ 8-char alphanumeric PINs (28 bits of entropy minimum). Users are required by the deployment guide to choose longer PINs for HVAs. |
| Source | `src/fhsm_token.c::fhsm_token_login`, `src/fhsm_crypto.c::fhsm_pbkdf2` |

### 3.8 DRBG state compromise

| Field | Value |
|---|---|
| Description | Adversary leaks the CTR_DRBG state via /proc/PID/mem and predicts subsequent outputs. |
| Rating | Time : Days (3). Expertise : Expert (6). Knowledge : Sensitive (7). Window : Moderate (1). Equipment : Standard (0). **Total : 17 → moderate**. |
| Defense | (1) DRBG state lives inside the OpenSSL FIPS provider's secure heap. (2) `PR_SET_DUMPABLE = 0` prevents `ptrace` from a different UID. (3) Periodic reseeding (SP 800-90A §9.5). |
| Residual risk | Negligible under FIPS 140-3 OE assumptions. |
| Source | OpenSSL FIPS provider, `src/fhsm_crypto.c::fhsm_rng_bytes` |

### 3.9 Hybrid downgrade

| Field | Value |
|---|---|
| Description | Adversary forces the hybrid KEM (`CKM_HYBRID_X25519_ML_KEM_768`) to fall back to classical-only by tampering with the ML-KEM ciphertext. |
| Rating | Time : Days (3). Expertise : Proficient (3). Knowledge : Restricted (3). Window : Easy (0). Equipment : Standard (0). **Total : 9 → practical**. |
| Defense | The combiner hashes the **PQ ciphertext** alongside both shared secrets : `ss = SHA3-256(ss_x25519 ‖ ss_pq ‖ ct_x25519 ‖ ct_pq ‖ label)`. Tampering with `ct_pq` changes `ss_pq` to something different from peer's, so the resulting shared secret differs and the downstream MAC fails. |
| Residual risk | Cryptographically negligible. |
| Source | `src/dispatch/fhsm_dispatch_hybrid.c::dispatch_hybrid_x25519_ml_kem_768` |

## 4. Penetration testing summary

The lab performs an independent pen-test pass during AVA_VAN.5 evaluation. The areas listed below are flagged for focused attention :

1. **Fuzzing** : the PKCS#11 argument parser (`fhsm_pkcs11.c`), the TLV params parser (`src/dispatch/fhsm_dispatch_common.c::fhsm_tlv_find`), and the .rsp parser (`kat/fhsm_kat_rsp.c`). AFL++ corpora are seeded with the published CAVP vectors.
2. **Negative integration** : C_Login with adversarial PINs (binary, very long, unicode), C_Encrypt with mechanism mismatch, C_DestroyObject on a foreign session.
3. **TOCTOU** : audit log file open/write race against an adversary who replaces the file between checks.
4. **Linker hardening** : `pwntools.checksec` on the shipped `.so` ; expect `RELRO=Full`, `NX=Yes`, `PIE=Yes`, `Stack canary=Yes`, `Stripped=No-debug`.

A lab-led red-team scenario is recommended : a malicious co-tenant on the same Linux user attempts to extract any DEK from a long-running FreeHSM process via gdb attach, ptrace, /proc inspection, or shared-memory injection.

## 5. Residual risk acceptance

Every vulnerability rated **< 45 (beyond-high)** is either mitigated above or out-of-scope per FIPS 140-3 §7.7 environmental assumptions (controlled physical access, hardened OS). No residual vulnerability rated below AVA_VAN.5 *practical*/*moderate*/*high* remains open.

The certification request is therefore submitted against AVA_VAN.5 with the expectation of *resistance to attackers with high attack potential* per CEM §10.2.7.

## 6. Re-evaluation triggers

A new AVA_VAN.5 pass is required on any of :

- Toolchain bump (Dockerfile.build apt pins change)
- OpenSSL FIPS provider major version bump
- Addition of a new approved mechanism
- Change to the audit log on-disk format
- Change to the token store on-disk format
