# FreeHSM C --- Operational User Guidance (CC EAL4+ AGD_OPE.1)

**TOE :** FreeHSM Cryptographic Module v1.0.0-FIPS
**Audience :** Security Officer (SO) and User operators of an installed TOE
**Prerequisites :** the TOE has been installed and brought to the secure operational state per `docs/AGD_PRE.md`

This document tells operators which services they may call, what arguments are accepted, what each error means, and how to respond when things go wrong. Read it once before first use ; keep it within reach during operations.

---

## 1. Roles & responsibilities

| Role          | Identifier  | Allowed services                                                                |
|---------------|-------------|---------------------------------------------------------------------------------|
| Security Officer (CO) | `CKU_SO`    | `C_InitToken`, `C_InitPIN`, `C_SetPIN` (own), audit review                |
| User                  | `CKU_USER`  | `C_GenerateKey`, `C_GenerateKeyPair`, `C_Encrypt`/`Decrypt`, `C_Sign`/`Verify`, `C_Digest`, `C_DeriveKey`, `C_Wrap`/`Unwrap`, `C_SetPIN` (own) |

Anonymous (pre-login) services :

| Service          | Purpose                              |
|------------------|--------------------------------------|
| `C_Initialize`   | Module bring-up (called once per process) |
| `C_GetInfo`      | Module identity                     |
| `C_GetSlotList`  | Enumerate slots                     |
| `C_GetSlotInfo`  | Slot status                         |
| `C_GetTokenInfo` | Token status (incl. PIN counters)   |
| `C_OpenSession`  | Open a session for login            |
| `C_CloseSession` | Close a session                     |
| `C_GetMechanismList` | List dispatchable CKM_*         |
| `C_GetMechanismInfo` | Per-mechanism flags & key range |

## 2. Common operator workflow

```c
#include <pkcs11.h>

CK_FUNCTION_LIST_PTR p11;
C_GetFunctionList(&p11);          /* loaded from libfreehsm-fips.so */
p11->C_Initialize(NULL);          /* triggers integrity check + KAT  */

CK_SESSION_HANDLE s;
p11->C_OpenSession(slot, CKF_RW_SESSION|CKF_SERIAL_SESSION,
                    NULL, NULL, &s);
p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin));

/* ... call C_GenerateKey, C_Encrypt, etc. ... */

p11->C_Logout(s);                  /* zeroizes DEK in this session   */
p11->C_CloseSession(s);
p11->C_Finalize(NULL);
```

After `C_Finalize` the process must not call any other `C_*` function until a new `C_Initialize`. Doing so returns `CKR_CRYPTOKI_NOT_INITIALIZED (0x190)`.

## 3. Mechanism selection guidance

Pick mechanisms from the **approved set** listed in `docs/MECHANISMS.md` and `docs/FIPS_140_3.md` §4. The mapping below summarises the canonical choice per use case.

| Use case                              | Recommended mechanism                  |
|---------------------------------------|----------------------------------------|
| Symmetric encryption at rest          | `CKM_AES_GCM` (96-bit IV, 128-bit tag) |
| Symmetric encryption in transit       | `CKM_AES_GCM` or `CKM_AES_CCM`         |
| Symmetric authentication              | `CKM_SHA256_HMAC` or `CKM_AES_CMAC`    |
| Streaming MAC (large messages)        | `CKM_KMAC128` / `CKM_KMAC256`          |
| Asymmetric signature (classical)      | `CKM_SHA384_RSA_PKCS_PSS` or `CKM_ECDSA_SHA384` |
| Asymmetric signature (PQ)             | `CKM_ML_DSA` (parameter set ML-DSA-65) |
| Asymmetric signature (hybrid)         | `CKM_HYBRID_ED25519_ML_DSA_65`         |
| Key encapsulation (classical)         | `CKM_ECDH1_DERIVE` over P-256/384 or `CKM_X25519_DERIVE` |
| Key encapsulation (PQ)                | `CKM_ML_KEM` (parameter set ML-KEM-768) |
| Key encapsulation (hybrid)            | `CKM_HYBRID_X25519_ML_KEM_768`         |
| Password-based KEK derivation         | `CKM_PKCS5_PBKD2` with ≥ 200 000 iter  |
| Key derivation in a protocol          | `CKM_HKDF_DERIVE` (SHA-256+)           |

Any mechanism not in the approved list (e.g. `CKM_MD5`, `CKM_DES3_CBC`, `CKM_RSA_PKCS`) is **rejected at dispatch** in approved mode and returns `FHSM_RV_FIPS_NOT_APPROVED (0x80000003)`.

## 4. Security advice (operator-actionable)

### 4.1 PIN management

- Minimum PIN length is **8 octets**, enforced by `fhsm_token.c::fhsm_token_init`. Stronger PINs (≥ 12 chars, mixed case + digits + punctuation) are strongly recommended for High-Value-Asset (HVA) deployments.
- Never reuse a PIN across slots. The exponential-throttle defense is per-slot.
- After **5 consecutive failures**, the role is locked. The User PIN is unlocked by the SO via `C_InitPIN`. The SO PIN is unlocked only by `C_InitToken`, **which destroys all objects on the slot** --- so a SO lockout is functionally a re-bootstrapping.

### 4.2 Throttle handling (transient delay)

Between attempts, `C_Login` may return `FHSM_RV_PIN_THROTTLED (0x80000004)` with a wait time exposed via the `pinStatus.throttle_*_remaining` fields of `C_GetTokenInfo`. The client SHOULD :

1. Display the wait time to the human operator.
2. Sleep for the indicated number of milliseconds.
3. Retry exactly once.

Repeatedly hammering through the throttle does not change the outcome ; the cooldown survives process restart (timestamps persisted in the token JSON).

### 4.3 Audit log review

The audit log lives at `/var/lib/freehsm/audit/slot<n>.audit.log` and is HMAC-chained. The SO MUST :

1. Periodically (recommended : weekly) verify the chain with the supplied verifier :
   ```bash
   freehsm-audit-verify /var/lib/freehsm/audit/slot0.audit.log
   ```
2. Investigate every `login_fail`, `login_locked`, `login_throttled`, and `integrity_fail` event.
3. Archive monthly logs to immutable storage (WORM bucket, append-only volume) per the site's retention policy.

A broken chain (verifier returns `chain broken at line N`) is a **critical security event** : the on-disk log has been tampered with by someone with write access to the audit directory. Take the system offline and follow the incident response procedure (`SECURITY.md`).

### 4.4 Token backup

Token files are encrypted at rest under the operator PIN(s). Backups are therefore as safe as the PIN strength, **but only if the backup retains the same access controls** :

- Use `cp --preserve=mode,ownership,timestamps` (or `rsync -a`).
- Store backups on encrypted media (LUKS, GCM-encrypted tar, KMS-sealed envelope).
- Never copy the audit log without the corresponding token file --- the integrity chain depends on the token's DEK-derived HMAC key.

### 4.5 Logout discipline

After every operation sequence :

```c
p11->C_Logout(s);
p11->C_CloseSession(s);
```

`C_Logout` zeroizes the DEK in process memory. `C_CloseSession` zeroizes the session-local key buffers. Failing to log out *does not* leak material on a process crash (the secure heap is process-local), but it does leave the audit trail with an unclosed session.

## 5. Service reference (selected)

### 5.1 `C_GenerateKey` (AES-256)

```c
CK_MECHANISM mech    = { CKM_AES_KEY_GEN, NULL, 0 };
CK_OBJECT_HANDLE key = 0;
CK_ULONG keylen      = 32;
CK_BBOOL true_       = CK_TRUE;
CK_ATTRIBUTE templ[] = {
    { CKA_VALUE_LEN, &keylen, sizeof(keylen) },
    { CKA_TOKEN,     &true_,  sizeof(true_)  },   /* persist */
    { CKA_ENCRYPT,   &true_,  sizeof(true_)  },
    { CKA_DECRYPT,   &true_,  sizeof(true_)  },
};
p11->C_GenerateKey(s, &mech, templ, 4, &key);
```

Returns `CKR_OK` and a non-zero `key` handle. The key material lives in the secure heap until the slot is logged out.

### 5.2 `C_Encrypt` (AES-GCM)

```c
CK_GCM_PARAMS gcm = {
    .pIv      = iv,   .ulIvLen      = 12,
    .pAAD     = aad,  .ulAADLen     = sizeof(aad),
    .ulTagBits = 128,
};
CK_MECHANISM mech = { CKM_AES_GCM, &gcm, sizeof(gcm) };

p11->C_EncryptInit(s, &mech, key);
p11->C_Encrypt(s, plaintext, plen, ciphertext, &clen);
```

`clen` on entry is the output buffer capacity ; on exit it is the actual ciphertext length (plaintext length + 16 for the tag). For multi-part processing, use `C_EncryptUpdate`/`C_EncryptFinal`.

### 5.3 `C_Sign` (ECDSA-P-384 + SHA-384)

```c
CK_MECHANISM mech = { CKM_ECDSA_SHA384, NULL, 0 };
p11->C_SignInit(s, &mech, priv_key);
p11->C_Sign(s, msg, msg_len, sig, &sig_len);
```

## 6. Error response

| `CK_RV` (hex) | Symbol                          | Operator action                                                |
|---------------|---------------------------------|----------------------------------------------------------------|
| `0x00`        | `CKR_OK`                        | continue                                                       |
| `0x05`        | `CKR_GENERAL_ERROR`             | check syslog ; if recurring, contact vendor                    |
| `0x06`        | `CKR_FUNCTION_FAILED`           | retry once ; if persists, file a support ticket               |
| `0x60`        | `CKR_KEY_HANDLE_INVALID`        | handle expired (session closed?) ; restart sequence            |
| `0x70`        | `CKR_MECHANISM_INVALID`         | not in `C_GetMechanismList` ; pick approved mechanism          |
| `0xA0`        | `CKR_PIN_INCORRECT`             | retry with correct PIN ; mind the throttle                     |
| `0xA4`        | `CKR_PIN_LOCKED`                | call SO to unlock with `C_InitPIN`                             |
| `0xB3`        | `CKR_SESSION_HANDLE_INVALID`    | open a fresh session                                           |
| `0x101`       | `CKR_USER_NOT_LOGGED_IN`        | `C_Login` first                                                |
| `0x190`       | `CKR_CRYPTOKI_NOT_INITIALIZED`  | `C_Initialize` first ; do NOT call after `C_Finalize`          |
| `0x80000001`  | `FHSM_RV_KAT_FAILED`            | **Critical** : module halted ; do not reuse ; reinstall        |
| `0x80000002`  | `FHSM_RV_INTEGRITY_FAILED`      | **Critical** : binary tampered ; reinstall from verified bundle |
| `0x80000003`  | `FHSM_RV_FIPS_NOT_APPROVED`     | switch to an approved mechanism                                |
| `0x80000004`  | `FHSM_RV_PIN_THROTTLED`         | wait the indicated milliseconds, retry once                    |
| `0x80000007`  | `FHSM_RV_SECURE_HEAP_EXHAUSTED` | reduce key inventory or raise `secure_heap_kb`                  |
| `0x80000008`  | `FHSM_RV_RNG_FAILURE`           | **Critical** : DRBG failed self-test ; restart the process     |

Critical errors latch the module ERROR state. The only recovery is to restart the process (per FIPS 140-3 §7.10.5). The operator MUST also examine the audit log to determine the root cause before relaunching.

## 7. Routine maintenance

| Frequency | Task                                                                 |
|-----------|----------------------------------------------------------------------|
| Daily     | Confirm `freehsm-bound-service` is healthy ; check syslog for FHSM warnings |
| Weekly    | Verify each slot's audit chain ; archive log if it exceeds rotation threshold |
| Monthly   | Rotate User PINs as per site policy ; review audit aggregates for anomalies |
| Quarterly | Test `make repro` against a fresh checkout ; confirm digest still matches deployed binary |
| Yearly    | Re-run penetration-testing tooling ; update OE.OS / OE.OPENSSL pins if needed (triggers re-evaluation per ALC_CMC.md §8) |

## 7bis. Runtime modes (v1.1.0)

The module selects between **legacy** (default) and **FIPS strict** mode at runtime. The choice is read from the `FHSM_MODE` environment variable first, then from the `mode =` directive in `/etc/freehsm/freehsm.conf`.

| Mode | Activation | Behaviour |
|---|---|---|
| `legacy` (default) | nothing, or `FHSM_MODE=legacy` | All declared mechanisms callable. MD5 and SHA-1 (digest) route to `fhsm_legacy_dispatch`. DES, 3DES, RC4 currently return `CKR_MECHANISM_INVALID` (handlers reserved for future wiring). |
| `fips` (= strict) | `FHSM_MODE=fips` or `mode = fips` in conf | Every non-FIPS-approved mechanism returns `CKR_MECHANISM_INVALID` regardless of OpenSC's negotiation table. Conforms to SP 800-131A Rev. 3. |

For FIPS 140-3 evaluation runs the operator MUST set `FHSM_MODE=fips` (or write `mode = fips` in the conf) BEFORE any `C_Initialize`. The mode is cached on first lookup, so changing the variable after init has no effect.

### Hardware-backed sealing (opt-in)

| Variable | Effect |
|---|---|
| `FHSM_TPM_SEALING=1` | At token init, the DEK is sealed to the host TPM 2.0 (PCRs 0-7). A companion `{slot}.tok.tpm` file is written next to the token. At login, the PBKDF2-unwrapped DEK is compared to the TPM-unsealed DEK ; mismatch is silently returned as wrong PIN. |
| `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` | **DEV-ONLY** : bypasses every integrity-failure path (see §8 below) — this variable IS FORBIDDEN in production. |

### Hardened DRBG

The `fhsm_rng_bytes` API now routes through `fhsm_drbg_bytes` which adds (a) multi-source entropy seeding, (b) SP 800-90B health tests (RCT, APT, CRNGT), (c) auto-reseed every 1 MiB of output or every hour. Any health-test alarm latches the module to `FHSM_STATE_ERROR` and forces a service restart. See [`RNG.md`](RNG.md).

### Pair-wise consistency check

Every `C_GenerateKeyPair` (RSA, EC, ML-KEM, ML-DSA, SLH-DSA) is followed by an automatic sign-verify (or encap-decap) round-trip with the freshly-generated key. Failure latches ERROR. Cost : ~5 ms for RSA-2048, sub-ms for EC, ~50 ms for SLH-DSA-128s.

## 8. Forbidden actions

The following actions **invalidate** the certified configuration and **forfeit** the FIPS / CC certificate :

- Setting `mode = legacy` (or leaving `FHSM_MODE` unset) for a deployment claiming FIPS 140-3 conformance.
- Setting `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` in any production context.
- Replacing `libfreehsm-fips.so` with any other binary, even patched.
- Modifying any file in `/opt/freehsm/etc/`.
- Loading an OpenSSL provider other than the validated FIPS provider.
- Disabling `mlock` capability on the host.
- Disabling audit (`audit_mandatory=false`).
- Operating the host without controlled physical access (violates OE.PHYS).

A site that performs any of the above is operating *outside* the certified TOE and may not advertise FIPS 140-3 / CC EAL4+ compliance.
