# FreeHSM C --- Post-Quantum Support Matrix (v1.1.0)

| Algorithm | PKCS#11 ID | FIPS status | Provider | State |
|---|---|---|---|---|
| **ML-KEM-512/768/1024** | `CKM_ML_KEM*` (0x4021,0x4022) | ✅ FIPS 203 | OpenSSL 3.5 FIPS | **WIRED + tested** (`mlkem_e2e`) |
| **Kyber alias** | `CKM_KYBER*` | Same as ML-KEM | OpenSSL 3.5 FIPS | **Alias of ML-KEM** in `fhsm_pkcs11_mechanisms.h` |
| **ML-DSA-44/65/87** | `CKM_ML_DSA*` (0x4023,0x4024) | ✅ FIPS 204 | OpenSSL 3.5 FIPS | **WIRED + tested** (`mldsa_e2e`) |
| **SLH-DSA-SHA2-128s/192s/256s** | `CKM_SLH_DSA*` (0x4025,0x4026) | ✅ FIPS 205 | OpenSSL 3.5 FIPS | **WIRED + tested** (`slhdsa_e2e`) |
| **Falcon / FN-DSA** | `CKM_FALCON*` (0x4032,0x4033) | ⚠️ FIPS 206 (draft) | oqsprovider required | **Constants declared**, dispatch returns NOT_APPROVED until oqsprovider loaded |
| **LMS** | `CKM_LMS*` (0x4034,0x4035) | ✅ NIST SP 800-208 | oqsprovider | **Constants declared**, awaiting provider integration |
| **XMSS** | `CKM_XMSS*` (0x4036,0x4037) | ✅ NIST SP 800-208 | oqsprovider | **Constants declared**, awaiting provider integration |
| **HQC** | `CKM_HQC*` (0x4038,0x4039) | ❌ NIST round 4 (alt KEM) | oqsprovider | **Constants declared**, not FIPS, legacy mode only |

## Stateful signatures (LMS / XMSS)

LMS and XMSS are **stateful** hash-based signatures. NIST SP 800-208 makes them FIPS-approved, but applications **MUST track and never reuse signing-state indices**. FreeHSM C's wiring (pending) will :
1. Store the state counter in the encrypted token blob alongside the private key.
2. Refuse to sign if the counter has reached the tree height.
3. Refuse to load a state that has been rolled back (anti-clone detection via monotonic counter).

This is more complex than stateless signatures and will be tracked as a follow-on task.

## Falcon / FN-DSA status

NIST has not yet ratified FIPS 206 as of June 2026 (last draft 2025-Q3). Once the standard is final and OpenSSL FIPS provider supports it, we'll wire `CKM_FALCON*` to `EVP_PKEY_Q_keygen(..., "FALCON-512")` and friends.

## Activation via oqsprovider

For pre-FIPS or non-FIPS deployments wanting these algorithms today :

```bash
apt install liboqs-dev oqsprovider
# In /etc/freehsm/freehsm.conf :
mode = legacy
oqs_provider = enabled
```

The legacy dispatch will then route Falcon/LMS/XMSS/HQC to oqsprovider through `EVP_PKEY_Q_keygen` with the provider-supplied names.
