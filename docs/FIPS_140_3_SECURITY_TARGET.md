# FreeHSM C --- FIPS 140-3 Security Target (Draft v0.3)

**Status :** Pre-submission draft. Not yet evaluated by a NIST CST lab.

**Standard :** NIST FIPS 140-3 *Security Requirements for Cryptographic Modules*, issued March 2019, effective September 2020.

**Implementation Guidance :** NIST IG 9.5 (cryptographic module testing) ; FIPS 140-3 IG ; OASIS PKCS #11 v3.2.

---

## 1. Module identification

| Field | Value |
|---|---|
| **Module Name** | FreeHSM C |
| **Version** | 1.1.0-FIPS |
| **Module Type** | Software (`libfreehsm-fips.so`, ELF-64 shared object) |
| **Module Embodiment** | Multi-chip standalone (GPC host) |
| **Module Boundary** | The single `.so` file at SHA-256 = (see `.fhsm_digest` section, patched by `make integrity`) |
| **Operational Environment (OE)** | Debian 13 / Linux kernel ≥ 6.1 / glibc ≥ 2.40 / OpenSSL 3.5.6 FIPS provider |
| **Approved Cryptographic Algorithms** | See §3 below |
| **Tested Configuration** | x86_64 Debian 13.0 stable, FIPS-mode enabled in `/etc/ssl/openssl.cnf` |
| **Security Level Sought** | **Level 1** (initial) ; Level 2 candidate after AVA_VAN.5 testing |

---

## 2. Cryptographic Module Specification (§7.2)

### 2.1 Cryptographic Module Description

FreeHSM C is a software-only PKCS#11 v3.2 cryptographic module providing key generation, key storage, encryption, decryption, signature, and verification services to host applications. The module wraps the OpenSSL 3.5.6 FIPS provider for all approved cryptographic primitives. It does not implement any primitive in its own code ; all FIPS-relevant computations are delegated to the FIPS-validated OpenSSL FIPS provider (CMVP cert #4282 or successor).

### 2.2 Cryptographic Boundary

The cryptographic boundary is the entire address range of the `libfreehsm-fips.so` executable code, plus the embedded read-only `.fhsm_digest` section (32 octets of SHA-256). The boundary explicitly **excludes** :
- The host operating system kernel and user-land libraries (glibc, libdl, libpthread)
- The OpenSSL provider modules (`fips.so`, `default.so`) which have their own boundaries and CMVP cert
- The persistent token store on disk (treated as encrypted-at-rest data subject to §7.7 SSP transitions)
- The audit log files on disk (integrity-protected by HMAC chain)

### 2.3 Module Interfaces (§7.3)

| Logical Interface | Physical Realization |
|---|---|
| **Data Input** | `pData`, `pInput`, `pTemplate` parameters of `C_*` entry points |
| **Data Output** | `pSignature`, `pCiphertext`, `pPlaintext` return buffers |
| **Control Input** | `pMechanism`, `flags`, attribute templates |
| **Control Output** | `CK_RV` return codes mapped to PKCS#11 `CKR_*` |
| **Status Output** | `C_GetInfo`, `C_GetTokenInfo`, `fhsm_kat_results`, audit log entries |
| **Power Input** | N/A (software module ; host-supplied) |

All interfaces use the OASIS PKCS#11 v3.2 calling convention. The `CK_FUNCTION_LIST` (v2.40) and `CK_FUNCTION_LIST_3_0` are the only externally visible symbol tables.

---

## 3. Approved Cryptographic Functions (§7.4)

| Category | Function | Standard | CAVP Cert (TBD by lab) |
|---|---|---|---|
| **AES** | AES-128/192/256 CBC, CBC-PAD, CTR, GCM, KW (RFC 3394), KWP (RFC 5649), CMAC | FIPS 197, SP 800-38A, SP 800-38D, SP 800-38F, SP 800-38B | A-AES-#### |
| **Hash** | SHA-256, SHA-384, SHA-512 | FIPS 180-4 | A-SHS-#### |
| **HMAC** | HMAC-SHA-256/384/512 | FIPS 198-1 | A-HMAC-#### |
| **PBKDF2** | PBKDF2-HMAC-SHA-256 (≥ 200 000 iter, ≥ 14-byte password, ≥ 16-byte salt) | SP 800-132 | A-PBKDF-#### |
| **DRBG** | CTR_DRBG-AES-256, no derivation function | SP 800-90A Rev. 1 | A-DRBG-#### |
| **RSA** | RSA-2048/3072/4096 key generation, PKCS#1 v1.5 sign, PSS sign, OAEP encrypt/decrypt | FIPS 186-5 (sig), SP 800-56B (key transport) | A-RSA-#### |
| **ECDSA** | P-256, P-384, P-521 key generation + sign/verify with SHA-256/384/512 | FIPS 186-5 | A-ECDSA-#### |
| **ECDH** | P-256, P-384, P-521 (CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE ; cofactor = 1) | SP 800-56A Rev. 3 | A-KAS-#### |
| **ML-KEM** | ML-KEM-512/768/1024 key generation, encapsulate, decapsulate | FIPS 203 (Aug 2024) | A-MLKEM-#### |
| **ML-DSA** | ML-DSA-44/65/87 key generation, sign, verify | FIPS 204 (Aug 2024) | A-MLDSA-#### |
| **SLH-DSA** | SLH-DSA-SHA2-128s/128f/192s/192f/256s/256f key generation, sign, verify | FIPS 205 (Aug 2024) | A-SLHDSA-#### |

### Non-Approved (Rejected in FIPS Mode)

The module advertises these mechanisms in `C_GetMechanismList` for compatibility, but `C_*Init` will return `CKR_MECHANISM_INVALID` when the FIPS provider is loaded :

* MD2, MD5, SHA-1 for signing (allowed for HMAC by SP 800-131A till 2030 ; we still allow HMAC-SHA-1 in verify path)
* DES, 3DES, RC4, RC5, RC2
* RIPEMD-128, RIPEMD-160
* RSA without padding (raw RSA)
* RSA-PKCS1-v1.5 signing with SHA-1 alone
* DSA (deprecated by SP 800-131A)
* SSL3 KDF family
* AES-ECB on > 16 bytes (FIPS forbids)

---

## 4. Software/Firmware Security (§7.5)

### 4.1 Source Code Hash

The build is reproducible per `dist-verify` :
- Reference digest : `dist/refs/v1.1.0.sha256` (signed at release time)
- Each build inside `Dockerfile.build` produces an ELF binary with the same SHA-256

### 4.2 Integrity Mechanism

The module embeds its own SHA-256 in a read-only ELF section `.fhsm_digest` (32 octets), patched by `make integrity` using OpenSSL FIPS provider. At every `C_Initialize`, `fhsm_integrity_verify()` recomputes the SHA-256 of the `.text` section and compares it in constant time. On mismatch, the module enters ERROR state and refuses all service requests.

### 4.3 Authorization

Two roles per token :
* **Crypto Officer (CO / SO)** : initial token init, user PIN init, key-pair generation, PIN policy.
* **User (USER)** : data ops (encrypt/decrypt/sign/verify), object create/destroy.

PINs are bound to a per-role PBKDF2 derivation. Failed login attempts increment a counter ; after 5 failures the role is locked. Throttle is exponential (500 ms → 60 s).

---

## 5. Operating Environment (§7.6)

### 5.1 Tested Configuration

* **OS** : Debian 13.0 stable (kernel 6.1+)
* **C library** : glibc 2.40
* **Compiler** : gcc 14.2.0 (Debian 14.2.0-19)
* **OpenSSL** : 3.5.6 with FIPS provider activated
* **Provider load order** : `fips` (active), `base` (active)
* **Hardware** : x86_64 (Intel / AMD), required CPU features : AES-NI, AVX, CLMUL

### 5.2 Restrictions

The user must :
1. Set `fips_strict=true` in `/opt/freehsm/etc/freehsm.conf`
2. Configure OpenSSL `openssl.cnf` to load only the `fips` and `base` providers (no `default`)
3. Run with non-zero `.fhsm_digest` (signed module) — `FHSM_INTEGRITY_ALLOW_UNSIGNED` MUST be unset

---

## 6. Physical Security (§7.7)

**Not applicable.** Software-only module, no physical embodiment to protect.

If the host hardware (HSM appliance) is provided, the physical security testing must cover that hardware separately under FIPS 140-3 §7.7 IG 7.7.

---

## 7. Non-Invasive Security (§7.8)

The module relies on the OpenSSL FIPS provider's hardening for side-channel attacks (constant-time AES, masked DRBG, etc.). FreeHSM C's own code is audited for :
* `fhsm_ct_memcmp` is used everywhere a secret is compared.
* Stack-allocated key material is cleared with `fhsm_zeroize` (calls `OPENSSL_cleanse` underneath).
* PIN verification path uses a throttle-before-PBKDF2 ordering to defeat timing attacks on the PBKDF2 derivation step.

Documented residual side-channels are in `docs/SIDE_CHANNEL.md`.

---

## 8. Sensitive Security Parameter Management (§7.9)

| SSP | Type | Persistent | Wrap | Role Required |
|---|---|---|---|---|
| **DEK** (Token Data Encryption Key) | AES-256 GCM key | Yes (file) | PBKDF2-wrapped under each role's PIN | USER login required to use |
| **SO Wrap KEK** | AES-256, ephemeral | No | Derived from SO PIN by PBKDF2 | SO login required to derive |
| **USER Wrap KEK** | AES-256, ephemeral | No | Derived from USER PIN by PBKDF2 | USER login required to derive |
| **Audit MAC Key** | HMAC-SHA-256, 256-bit | Yes (separate file) | Plaintext (root-only access) | Audit-write only |
| **Module Integrity Digest** | SHA-256 (32 octets) | Yes (in `.fhsm_digest`) | None (read-only ELF section) | None ; checked at boot |
| **Generated RSA / ECDSA / ML-DSA / SLH-DSA Private Keys** | Per-algorithm | Yes (via objects_blob, AES-GCM(DEK)) | Wrapped under DEK | USER login required |

### SSP Transitions

* **Establishment** (generation): Always via the FIPS DRBG (`fhsm_rng_bytes` → `RAND_bytes`).
* **Use** : In-memory only after C_Login ; DEK kept in secure heap arena.
* **Storage** : Persistent SSPs are wrapped under AES-GCM with the role's KEK ; the wrap CT includes a GCM tag and the token's serial as AAD.
* **Zeroization** : Triggered on `C_Logout`, `C_Finalize`, `fhsm_token_close`. The DEK buffer is overwritten with `OPENSSL_cleanse`.

---

## 9. Self-Tests (§7.10)

### 9.1 Pre-Operational Self-Test (§7.10.2)

Runs once at `C_Initialize` :
1. **Software integrity check** : SHA-256 of `.text` vs `.fhsm_digest`.
2. **FIPS provider load** : `OSSL_PROVIDER_load("fips")` non-NULL.
3. **CSP zeroization** : `fhsm_secure_heap_init` allocates the secure arena and locks pages with `mlock`.

### 9.2 Conditional Self-Tests (§7.10.3)

* **Pair-wise consistency** : after each `C_GenerateKeyPair`, sign+verify a known plaintext to confirm the new private key matches the public key (TODO — not yet wired).
* **Continuous RNG test** : every `RAND_bytes` call is checked against the previous block (FIPS 140-3 §7.10.4 "stuck DRBG").

### 9.3 Known Answer Tests (KAT)

15 KATs run on first `C_Initialize` :

| Algorithm | Vector | Source |
|---|---|---|
| AES-256-GCM encrypt | TC14 | SP 800-38D §B |
| AES-256-GCM decrypt + tamper | TC14 + bit flip | Internal |
| SHA-256 | "abc" | FIPS 180-4 §B.1 |
| HMAC-SHA-256 | TC1 | RFC 4231 |
| PBKDF2-HMAC-SHA-256 | smoke (200k iter, 24+20 byte PW/salt) | Internal |
| CTR_DRBG-AES-256 | stuck-DRBG | Internal |
| SHA-256 CAVP | 9 short-message vectors (Len 0, 8, 24, 112, 448, 8, 16, 24, 896) | NIST CAVP |

Failure of any KAT latches the module ERROR state and returns `FHSM_RV_KAT_FAILED = 0x80000001`.

---

## 10. Lifecycle Assurance (§7.11)

| Item | Status |
|---|---|
| Vendor-supplied configuration management | `Makefile`, `Dockerfile.build`, `dist/refs/*.sha256` |
| Delivery and operation | `docs/AGD_PRE.md` + `docs/AGD_PRE.fr.md` |
| Lifecycle/development | `docs/ARCHITECTURE.md`, source code, git history |
| Guidance documentation | `docs/AGD_OPE.md` (administrator + user guide) |
| Reproducible build | `make repro` + `make dist-verify` against `dist/refs/v1.1.0.sha256` |

---

## 11. Operational Modes

| Mode | Trigger | Behavior |
|---|---|---|
| **Approved (FIPS)** | `fips_strict=true` in conf + OpenSSL FIPS provider loaded + signed `.fhsm_digest` | All non-FIPS mechanisms return `CKR_MECHANISM_INVALID` |
| **Error** | KAT failure, integrity mismatch, RNG failure | All `C_*` return `FHSM_RV_FUNCTION_FAILED`. Only `C_Finalize` permitted to clean up. |

The module has no "non-approved" mode in shipping builds. Development builds may set `FHSM_INTEGRITY_ALLOW_UNSIGNED` to skip integrity (developer only ; flagged as non-validated build).

---

## 12. Mitigation of Other Attacks (§7.12)

Out of scope at Security Level 1. Will be addressed at Level 2 candidate review (AVA_VAN.5).

Documented future work :
* Side-channel hardening audit and patches (see `docs/SIDE_CHANNEL.md`)
* TPM 2.0 sealing of the DEK (PCR-binding) for tamper-resistance at rest
* Multi-factor unlock via Shamir Secret Sharing quorum on the SO PIN

---

**Document Revision History**

| Version | Date | Author | Changes |
|---|---|---|---|
| 0.1 | 2026-04 | A.M. | Initial outline |
| 0.2 | 2026-05 | A.M. | §3 algorithm table draft |
| **0.3** | **2026-06-10** | **A.M.** | **First complete draft : §1-§12 all sections populated, ready for internal review before lab submission** |
