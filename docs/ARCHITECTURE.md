# FreeHSM C --- Architecture & module decomposition

## 1. Goals

This document describes the internal architecture of the C reimplementation of FreeHSM. The primary goal is to make the cryptographic boundary auditable in isolation, which is required by both FIPS 140-3 (single boundary, well-defined interfaces) and CC EAL4+ (ADV_TDS.3 basic modular design, ADV_FSP.4 complete functional specification).

The Python POC remains the *reference implementation* for behavioral conformance: the C suite re-runs the same on-disk token format and PKCS#11 traces, so the two implementations interoperate byte-for-byte (see `tests/test_token_interop.c`).

## 2. Layer cake

```
                          ┌──────────────────┐
   ABI / TSFI ───────────►│  PKCS#11 C_* ABI │
                          │  fhsm_pkcs11.c   │
                          └─────────┬────────┘
                                    │ thin dispatch
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
   ┌──────────┐              ┌────────────┐              ┌──────────┐
   │ Sessions │              │   Tokens   │              │  Crypto  │
   │ fhsm_    │              │  fhsm_     │              │  fhsm_   │
   │ session  │              │  token     │              │  crypto  │
   └────┬─────┘              └─────┬──────┘              └────┬─────┘
        │                          │                          │
        ▼                          ▼                          ▼
        ┌───────────────────────────────────────────────────────┐
        │  Cross-cut : state machine, secure memory, audit log  │
        │   fhsm_state, fhsm_memory, fhsm_audit                 │
        └───────────────────────────────────────────────────────┘
                                    │
                                    ▼
                          ┌──────────────────┐
                          │ OpenSSL 3.x FIPS │
                          │     provider     │
                          └──────────────────┘
```

The arrows are one-way : the higher layers depend on the lower, never the reverse. Cross-cuts (state, memory, audit) are linked into every translation unit and have no caller-specific state.

## 3. Module responsibilities

| Module              | Responsibility                                                                 | TSFI       |
|---------------------|--------------------------------------------------------------------------------|------------|
| `fhsm_state.c`      | Module state machine (FIPS 140-3 §7.4.2). Pthread-locked.                       | internal   |
| `fhsm_memory.c`     | Secure heap wrappers, `fhsm_zeroize`, `fhsm_ct_memcmp`.                         | internal   |
| `fhsm_crypto.c`     | EVP_* wrappers, KAT runner, FIPS provider load/unload.                          | internal   |
| `fhsm_audit.c`      | Append-only HMAC-chained log.                                                   | internal   |
| `fhsm_token.c`      | Token JSON file I/O, PIN derivation, DEK wrap/unwrap, throttle, lockout.        | internal   |
| `fhsm_session.c`    | Bounded session table, slot↔token attach, role tracking.                        | internal   |
| `fhsm_pkcs11.c`     | C_* entry points: validate args, emit audit, dispatch.                          | **TSFI**   |
| `kat/fhsm_kat_*.c`  | CAVP-derived KAT vectors and runner.                                            | internal   |

Only `fhsm_pkcs11.c` exports symbols; all other modules are `static`-or-`hidden`-linked by the linker version script and `-fvisibility=hidden`.

## 4. Mechanism dispatch table

The full PKCS#11 mechanism set is fed by a code-generated table (script `scripts/gen_p11_thunks.py`, output `src/fhsm_dispatch.c`). Each entry is:

```c
{ CKM_AES_GCM, FHSM_FIPS_APPROVED, &dispatch_aes_gcm },
{ CKM_RSA_PKCS_PSS, FHSM_FIPS_APPROVED, &dispatch_rsa_pss },
{ CKM_ML_KEM_KEM_KEY_GEN, FHSM_FIPS_APPROVED, &dispatch_ml_kem_keygen },
{ CKM_DES3_CBC, FHSM_FIPS_NOT_APPROVED, NULL },           /* legacy ; rejected */
{ CKM_MD5_HMAC, FHSM_FIPS_NOT_APPROVED, NULL },           /* legacy ; rejected */
...
```

The dispatcher checks the FIPS-only flag and the operator role before invoking the handler. Unapproved mechanisms return `FHSM_RV_FIPS_NOT_APPROVED` when `FHSM_FIPS_ONLY = 1`.

## 5. Data flow for a typical operation (C_Encrypt)

```
C_Encrypt(session, pData, len, pOut, *pulOutLen)
       │
       │  1. State == INITIALIZED or AUTHENTICATED ? else fail
       │  2. Session handle valid ? else fail
       │  3. Mechanism in approved list ? else FIPS_NOT_APPROVED
       │  4. Audit "encrypt" event with (slot, session, role, mech_id, len)
       ▼
fhsm_dispatch_aes_gcm(...)
       │
       │  5. Lookup key handle in session.objects → fetch CKA_VALUE
       │  6. SSP material is already in the secure heap (from C_GenerateKey)
       ▼
fhsm_aes_gcm_encrypt(key_slice, iv_slice, aad_slice, pt_slice, ct, *len, tag)
       │
       │  7. EVP_CIPHER_CTX_new / EncryptInit / Update / Final / GET_TAG
       │  8. Zeroize ctx via EVP_CIPHER_CTX_free (also clears the internal key)
       ▼
return CKR_OK
```

Every step is logged in chronological order:
- Entry to `C_Encrypt` (params length only)
- `dispatch_aes_gcm` selected
- `fhsm_aes_gcm_encrypt` returned OK
- Exit from `C_Encrypt` (rv = CKR_OK, output length)

Sensitive bytes (`pData`, `pOut`, `key.data`) never appear in the log.

## 6. Build & reproducibility

The reproducible build target is `make dist`, which invokes a `Dockerfile.build` pinned to Debian 12 + OpenSSL 3.2 + the FIPS provider matching CMVP cert #4825 (placeholder until our cert is issued). The image digest is recorded in `docs/REPRODUCIBLE_BUILD.md` and is the authoritative input to ALC_CMC.4.

## 7. Threading

| Lock                    | Scope                                  | Held duration         |
|-------------------------|-----------------------------------------|----------------------|
| `g_state_mu` (state.c)  | Process global                          | Microseconds         |
| `g_audit_mu` (audit.c)  | Process global                          | One write+fsync      |
| `g_sess_mu` (session.c) | Process global                          | Table walk           |
| `t->mu` (per token)     | Per slot                                | Login / wrap / unwrap |

No lock is held across the OpenSSL provider boundary. The OpenSSL FIPS provider is itself reentrant per its own validation.

## 8. Code-generation pipeline

```
include/fhsm_pkcs11.in.h       (template, one source of truth)
        │
        ▼
scripts/gen_p11_thunks.py
        │
        ├──►  include/fhsm_pkcs11.h    (public ABI header)
        ├──►  src/fhsm_dispatch.c     (mechanism dispatch table)
        └──►  docs/MECHANISMS.md      (auto-generated reference)
```

Re-running the generator with a different `--profile=fips-strict` flag emits a build that rejects every non-approved mechanism at link time --- no runtime branching is involved, which simplifies the AVA_VAN.5 analysis.

## 9. Testing & coverage

| Suite               | Driver                                | Scope                                       |
|---------------------|---------------------------------------|---------------------------------------------|
| KAT                 | `kat/fhsm_kat_vectors.c`              | Every approved primitive at init time       |
| Smoke               | `tests/test_smoke.c`                  | End-to-end encrypt/decrypt + tamper         |
| Audit               | `tests/test_audit.c`                  | Chain verification, line injection rejection |
| Token interop       | `tests/test_token_interop.c`          | Bit-identical with Python POC               |
| Fuzzing             | `tests/fuzz/` + AFL++                 | Token parser, PKCS#11 argument parsing      |
| Coverage            | `make coverage`                       | gcov/lcov target ≥ 95% line, 90% branch    |
| Memcheck / asan     | `make memcheck` / `make asan`         | Mandatory clean on every release            |

## 10. Migration from the Python POC

The C TOE reads and writes the *exact same JSON token format* as the Python POC. An organization in production can therefore:

1. Stop the Python service.
2. Replace `libfreehsm.so` with `libfreehsm-fips.so` (same SONAME).
3. Start the C service.
4. All slots, all keys, all PIN counters, all audit chains carry over.

This is enforced by `tests/test_token_interop.c`, which generates a token under Python, opens it under C, performs an encrypt/decrypt round trip, and verifies both implementations agree on the resulting ciphertext + tag.

## 11. v1.1.0 layered additions

The CST pre-submission refresh adds 4 transverse modules. They sit at the same architectural layer as the existing crypto primitives but are wired into different lifecycle stages:

### 11.1 Hardened DRBG (`src/fhsm_drbg.c`)

A second-tier wrapper around OpenSSL CTR_DRBG-AES-256. Sits BEFORE every `fhsm_rng_bytes` consumer. Adds :
- Multi-source entropy aggregation : `getrandom(2)`, RDRAND, `/dev/urandom`, TSC jitter → SHA-256 conditioner → `RAND_add`.
- NIST SP 800-90B §4.4 health tests : RCT (cutoff 6), APT (W=512, cutoff 51), CRNGT (16-byte block).
- Auto-reseed every 1 MiB output or every hour wall-clock.
- Alarm → `fhsm_state_latch_error` → ERROR state.

Lifecycle : `fhsm_drbg_init` is called by `fhsm_crypto_init` AFTER FIPS provider load but BEFORE KAT runs (KATs may consume DRBG output).

### 11.2 Pair-wise consistency check (`src/fhsm_pairwise.c`)

Independent of the dispatch table. Called inline by `C_GenerateKeyPair` AFTER `EVP_PKEY_Q_keygen` returns and BEFORE the key is serialised to disk. Routes to family-specific paths : RSA encrypt-decrypt round-trip, EC sign-verify, ML-KEM encap-decap, ML-DSA/SLH-DSA sign-verify. Failure → ERROR latch + refusal to persist.

### 11.3 TPM 2.0 sealing glue (`src/fhsm_token_tpm.c` + `src/fhsm_tpm.c`)

Companion-file approach : `{path}.tpm` next to `{path}.tok`. Zero changes to the `.tok` binary format → forward/backward compatible across opt-in.

```
              fhsm_token_init                         fhsm_token_login (success)
                     │                                       │
                     ▼                                       ▼
              FHSM_TPM_SEALING=1 ?               {path}.tpm exists ?
                     │ yes                              │ yes
                     ▼                                       ▼
              fhsm_tpm_seal(DEK)            fhsm_tpm_unseal → compare DEKs
                     │                              │
                     ▼                              ▼ mismatch
              write {path}.tpm                CKR_PIN_INCORRECT
```

`src/fhsm_tpm.c` calls `tpm2` CLI via fork+exec (rather than libtss2 direct) to avoid TSS API churn.

### 11.4 Runtime mode switch (`src/fhsm_mode.c`)

Reads `FHSM_MODE` env first, then `/etc/freehsm/freehsm.conf` `mode =` directive. Result cached after first lookup. Used by `dispatch_reject_fips` (generated thunk) to decide between `FHSM_RV_FIPS_NOT_APPROVED` (strict) and delegation to `fhsm_legacy_dispatch` (legacy, weak symbol overridable via `src/dispatch/fhsm_dispatch_legacy.c`).

### 11.5 Updated layer cake

```
┌────────────────────────────────────────────────┐
│ PKCS#11 v3.2 façade (fhsm_pkcs11.c)            │
├────────────────────────────────────────────────┤
│ Pair-wise check (fhsm_pairwise.c)              │  ← new in .1
│ Mode switch (fhsm_mode.c)                      │  ← new in .1
│ Dispatch (gen + per-family handlers)           │
├────────────────────────────────────────────────┤
│ Token store (fhsm_token.c)                     │
│ TPM glue (fhsm_token_tpm.c)                    │  ← new in .1
├────────────────────────────────────────────────┤
│ Crypto primitives (fhsm_crypto.c)              │
│ Hardened DRBG (fhsm_drbg.c)                    │  ← new in .1
│ TPM CLI wrapper (fhsm_tpm.c)                   │  ← new in .1
├────────────────────────────────────────────────┤
│ Audit log + integrity + state machine          │
├────────────────────────────────────────────────┤
│ OpenSSL 3.5.x FIPS provider                    │
└────────────────────────────────────────────────┘
```
