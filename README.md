# FreeHSM C --- FIPS 140-3 / CC EAL4+ candidate

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![REUSE status](https://api.reuse.software/badge/github.com/afchine1337/freehsm-c)](https://api.reuse.software/info/github.com/afchine1337/freehsm-c)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13190/badge)](https://www.bestpractices.dev/projects/13190)
[![CI](https://github.com/afchine1337/freehsm-c/actions/workflows/ci.yml/badge.svg)](https://github.com/afchine1337/freehsm-c/actions/workflows/ci.yml)
[![Mirror](https://github.com/afchine1337/freehsm-c/actions/workflows/mirror.yml/badge.svg)](https://github.com/afchine1337/freehsm-c/actions/workflows/mirror.yml)

> French version: see [`README.fr.md`](README.fr.md). Documentation index: [`docs/INDEX.md`](docs/INDEX.md).

Native **C11** re-implementation of the FreeHSM PKCS#11 v3.2 Soft HSM, designed to pass a FIPS 140-3 Level 1 evaluation and an augmented Common Criteria EAL4+ certification (ALC_FLR.2 + AVA_VAN.5).

## Why C ?

The Python POC is functionally complete (165 passing tests, façade + engine + store + CFFI binding + TPM/KMS sealing + PQ FIPS 203/204/205 coverage), but Python is not evaluable :

- The interpreter is inside the module boundary, which becomes unmanageable.
- The Python allocator is garbage-collected --- no zeroization guarantee.
- The crypto primitives delegate to `cryptography` (CFFI → libssl), adding an untraceable boundary.

The C port removes these obstacles : a single `.so` (`libfreehsm-fips.so`) directly loading the **OpenSSL 3.x FIPS provider** (separately validated), with a `mlock()`-ed *secure heap* for all SSP, and a boundary made exclusively of the `C_*` PKCS#11 symbols.

## Structure

```
freehsm_c/
├── Makefile                       # Hardened build + reproducibility + lint + generate
├── Dockerfile.build               # Pinned image for reproducible builds (Debian 12 + OpenSSL FIPS)
├── include/
│   ├── fhsm_common.h              # Types, return codes, state machine, roles
│   ├── fhsm_crypto.h              # FIPS-approved primitives (AES-GCM, HMAC, PBKDF2, DRBG)
│   ├── fhsm_token.h               # Token store, throttle, lockout
│   ├── fhsm_audit.h               # HMAC-chained audit log
│   ├── fhsm_integrity.h           # Boot integrity self-test (FIPS 140-3 §7.10.2)
│   └── fhsm_pkcs11_mechanisms.h   # [GENERATED] CKM_* + handler signature + table
├── src/
│   ├── fhsm_state.c               # State machine (FIPS 140-3 §7.4.2)
│   ├── fhsm_memory.c              # Secure heap (OpenSSL OPENSSL_secure_malloc)
│   ├── fhsm_crypto.c              # EVP wrappers + KAT runner
│   ├── fhsm_audit.c               # Append-only HMAC-chained log
│   ├── fhsm_token.c               # Slot persistence + PIN throttle
│   ├── fhsm_session.c             # Session table
│   ├── fhsm_pkcs11.c              # C_* entry points (TSFI)
│   ├── fhsm_integrity.c           # Boot self-test : .fhsm_digest section + SHA-256
│   ├── gen/
│   │   └── fhsm_dispatch.c        # [GENERATED] Dispatch table for 78 CKM_* + weak stubs
│   └── dispatch/                  # Concrete handlers per family (66 approved)
│       ├── fhsm_dispatch_digest.c # SHA-2/3, SHAKE128/256
│       ├── fhsm_dispatch_hmac.c   # HMAC-SHA-2/3
│       ├── fhsm_dispatch_aes.c    # AES-GCM/CBC/CTR/CCM/KW/KWP/CMAC
│       ├── fhsm_dispatch_kdf.c    # PBKDF2, HKDF, NIST PRF KDF
│       ├── fhsm_dispatch_pkey.c   # RSA-PSS/OAEP, ECDSA, EdDSA, ECDH
│       ├── fhsm_dispatch_pq.c     # ML-KEM/DSA, SLH-DSA (provider-aware)
│       ├── fhsm_dispatch_kmac.c   # KMAC128/256 (SP 800-185)
│       ├── fhsm_dispatch_concat.c # CONCATENATE_*, XOR_BASE_AND_DATA
│       └── fhsm_dispatch_hybrid.c # Hybrid PQ + classical KEM and signature
├── scripts/
│   ├── gen_p11_thunks.py          # Single source of truth for the dispatch (mechanism db)
│   ├── sign_module.sh             # Patches the SHA-256 digest into .fhsm_digest
│   ├── build_reproducible.sh      # Builds inside pinned Docker (out/digest.txt)
│   └── verify_reproducibility.sh  # Builds twice, asserts identical SHA-256
├── kat/
│   ├── fhsm_kat_rsp.{h,c}         # CAVP .rsp parser + 6 per-algorithm runners
│   ├── fhsm_kat_vectors.c         # In-binary vectors (boot self-test)
│   └── cavp/                      # 83 CAVP vectors (.rsp) cross-validated against Python
├── tests/
│   ├── test_smoke.c               # E2E smoke (init + KAT + encrypt/decrypt + tamper)
│   └── test_dispatch.c            # Checks weak/strong override, table sort, counts
└── docs/
    ├── INDEX.md                   # Bilingual doc index
    ├── ARCHITECTURE.md            # Modular decomposition + data flow
    ├── FIPS_140_3.md              # Non-proprietary Security Policy (FIPS 140-3)
    ├── EAL4_PLUS.md               # Target of Evaluation (CC EAL4+)
    ├── MECHANISMS.md              # [GENERATED] Dispatch reference (78 CKM_*)
    ├── REPRODUCIBLE_BUILD.md      # Bit-identical build procedure
    ├── ATE_FUN.md                 # Functional Test (ATE_FUN.1 + COV.2 + DPT.1)
    ├── AVA_VAN.md                 # Vulnerability Analysis (AVA_VAN.5)
    ├── ALC_CMC.md                 # Configuration Management (ALC_CMC.4)
    ├── AGD_PRE.md                 # Preparative Procedures (admin install guide)
    └── AGD_OPE.md                 # Operational Guidance (operator manual)
```

## Build

```bash
# Prerequisites : OpenSSL 3.x with the FIPS provider
sudo apt install -y libssl-dev cmake ninja-build
# (If the FIPS provider is not pre-installed, build it from OpenSSL sources with
#  ./Configure enable-fips && make install_fips.)

make generate                  # regenerate the mechanism dispatch (CKM_* + table + doc)
make generate PROFILE=interop  # same but with legacy CKM_* dispatchable (audit-only)
make                           # generate then build libfreehsm-fips.so
make tests                     # run test_smoke (POST + KAT + AES-GCM RT + tamper)
make integrity                 # patch SHA-256 into fhsm_module_integrity_digest[]
make repro                     # build inside the pinned Docker image
make dist-verify               # build twice, assert byte-identical SHA-256
make dist                      # reproducible source tar.xz for the evaluator
```

## Mechanism dispatch (78 `CKM_*`)

The module supports **66 FIPS-approved** mechanisms and **12 legacy** ones (rejected by default in `fips-strict` profile, audited in `interop`). The dispatch table is not hand-written : it is generated from a **single source of truth** (`scripts/gen_p11_thunks.py`), which lets an evaluator diff this one file against §4 of the Security Policy to verify exhaustiveness.

| Family            | Approved | Mechanisms |
|-------------------|----------|------------|
| AES               | 9        | `KEY_GEN`, `CBC`, `CBC_PAD`, `GCM`, `CCM`, `CTR`, `KEY_WRAP`, `KWP`, `CMAC` |
| SHA-2             | 6        | `SHA224/256/384/512`, `SHA512_224/256` |
| SHA-3 / SHAKE     | 5        | `SHA3_256/384/512`, `SHAKE128/256` |
| HMAC              | 6        | SHA-2-{256,384,512} + SHA-3-{256,384,512} |
| **KMAC**          | **2**    | **`KMAC128`, `KMAC256`** (SP 800-185) |
| RSA               | 6        | `KEY_PAIR_GEN`, `PSS` (+ `SHA256/384/512`), `OAEP` |
| EC (NIST)         | 7        | `KEY_PAIR_GEN`, `ECDSA` (+ 3 SHA), `ECDH1`, `ECDH1_COFACTOR` |
| EdDSA / X25519/X448 | 5      | `EC_EDWARDS_KEY_PAIR_GEN`, `EDDSA`, `EC_MONTGOMERY_KEY_PAIR_GEN`, `X25519_DERIVE`, `X448_DERIVE` |
| ML-KEM (FIPS 203) | 2        | `ML_KEM_KEY_PAIR_GEN`, `ML_KEM` |
| ML-DSA (FIPS 204) | 4        | `KEY_PAIR_GEN`, `ML_DSA`, `HASH_ML_DSA_SHA256/512` |
| SLH-DSA (FIPS 205)| 2        | `SLH_DSA_KEY_PAIR_GEN`, `SLH_DSA` |
| **Hybrid PQ**     | **2**    | **`HYBRID_X25519_ML_KEM_768`** (KEM), **`HYBRID_ED25519_ML_DSA_65`** (signature) |
| HKDF              | 3        | `DERIVE`, `DATA`, `KEY_GEN` |
| PBKDF2 / KDF      | 2        | `PKCS5_PBKD2` (200 000 iter min), `NIST_PRF_KDF` |
| **Concat KDF**    | **4**    | **`CONCATENATE_BASE_AND_KEY/DATA`, `CONCATENATE_DATA_AND_BASE`, `XOR_BASE_AND_DATA`** |
| Generic           | 1        | `GENERIC_SECRET_KEY_GEN` |
| **Legacy rejected** | **12** | `AES_ECB`, `RSA_PKCS`, `RSA_X_509`, `SHA1_RSA_PKCS`, `MD5`, `SHA_1`, `DES_KEY_GEN`, `DES3_KEY_GEN`, `DES3_CBC`, `RC4`, `DH_PKCS_KEY_PAIR_GEN`, `DSA_KEY_PAIR_GEN` |

## Evaluation status

| Step                                          | Status | Evidence |
|-----------------------------------------------|--------|----------|
| Strict C11 source                             | ✅     | `Makefile` (`-Werror -Wpedantic`) |
| Single cryptographic boundary                 | ✅     | `docs/FIPS_140_3.md` §2 |
| mlock-ed secure heap for SSPs                 | ✅     | `src/fhsm_memory.c` |
| FIPS 140-3 §7.4.2 state machine               | ✅     | `src/fhsm_state.c` |
| Boot KAT (AES-GCM, SHA, HMAC, DRBG)           | ✅     | `kat/fhsm_kat_vectors.c` |
| **Boot integrity** (SHA-256 of .so)           | ✅     | `src/fhsm_integrity.c` + `scripts/sign_module.sh` |
| HMAC-chained audit log                        | ✅     | `src/fhsm_audit.c` |
| Algorithms restricted to approved set         | ✅     | `FHSM_FIPS_ONLY = 1` default |
| Exponential PIN throttle + lockout            | ✅     | `src/fhsm_token.c` |
| **Full dispatch (78 `CKM_*`)**                | ✅     | `scripts/gen_p11_thunks.py` + `src/gen/` |
| Non-proprietary Security Policy               | ✅     | `docs/FIPS_140_3.md` |
| CC EAL4+ Target of Evaluation                 | ✅     | `docs/EAL4_PLUS.md` |
| Auto-generated mechanism reference            | ✅     | `docs/MECHANISMS.md` |
| **Concrete handlers** (66 approved)           | ✅     | `src/dispatch/` 10 files, ~2 400 l. |
| **KMAC + concat KDF + PQ hybrids**            | ✅     | `dispatch_{kmac,concat,hybrid}*.c` |
| **CAVP `.rsp` parser + 83 vectors**           | ✅     | `kat/fhsm_kat_rsp.c` + `kat/cavp/` |
| Full CAVP set (100+/algo)                     | 🟡     | infrastructure ready, set to download |
| **Reproducible build** (pinned Dockerfile)    | ✅     | `Dockerfile.build` + `make dist-verify` |
| **Complete CC EAL4+ docs** (ATE/AVA/ALC/AGD)  | ✅     | 10 documents in `docs/` |
| Fuzzing tests + coverage ≥ 95 %               | ⏳     | infra to wire (AFL++ + lcov) |
| Validated OpenSSL FIPS provider               | ⏳     | target-dependent (CMVP cert) |
| Third-party code audit (CC lab)               | ⏳     | commercial step |
| CMVP / CC lab submission                      | ⏳     | final commercial step |

Legend : ✅ implemented · 🟡 partial/scaffold · ⏳ to do

## Synthesis

- **Strict C11** hardened (`-Werror -Wpedantic -fstack-protector-strong ...`), single cryptographic boundary (`libfreehsm-fips.so` + OpenSSL 3.x FIPS provider).
- **78 `CKM_*`** dispatchable (66 FIPS-approved + 12 legacy rejected), generated from a single auditable source of truth.
- **66 concrete handlers** in `src/dispatch/` (10 files, ~2 400 l.), including KMAC, CONCATENATE/XOR KDFs, and 2 hybrid PQ + classical mechanisms.
- **Boot self-test FIPS 140-3 §7.10.2** : `.fhsm_digest` ELF section patched post-build, SHA-256 of the .so (digest area zeroized) verified before the FIPS provider loads.
- **Reproducible build** : `Dockerfile.build` pinned by digest. `make dist-verify` builds twice and asserts identical SHA-256.
- **CAVP `.rsp` parser** + **83 sample vectors** Python cross-validated.
- **10 evaluation documents** covering the full CC EAL4+ + FIPS 140-3 submission dossier (Security Policy, TOE, Architecture, Mechanisms, Reproducible Build, ATE_FUN, AVA_VAN, ALC_CMC, AGD_PRE, AGD_OPE).
- **~ 8 000 lines** of C + Python + Markdown across 40+ files.
- **Remaining roadmap** : third-party code audit (accredited lab), CMVP submission, CC EAL4+ submission (commercial 12-24 month steps).
