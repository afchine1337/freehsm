# FreeHSM C --- Side-Channel Posture (v1.1.0)

This document audits FreeHSM C against the side-channel attack categories most commonly tested by FIPS 140-3 Level 2/3 evaluators and CC EAL4+ AVA_VAN.5 reviewers.

The module aims for **Level 1** initially, where non-invasive testing is out of scope, but documents Level 2 candidacy gaps below.

---

## 1. Threat model

We assume an attacker who can :

* Run unprivileged code on the same host as the module (co-resident attacker)
* Measure wall-clock time of `C_*` calls with µs precision
* Probe CPU performance counters (perf_event_open)
* Snoop the L1/L2 cache via Prime+Probe or Flush+Reload
* NOT measure power or electromagnetic emissions (out of scope for software module)
* NOT inject voltage glitches or laser fault attacks

---

## 2. Hardening already applied

### 2.1 Constant-time comparison

Every secret-vs-secret compare uses `fhsm_ct_memcmp` (implemented in `src/fhsm_state.c`). Locations audited :

| File | Function | Purpose |
|---|---|---|
| `src/fhsm_token.c` | `fhsm_token_login` | AES-GCM tag check uses OpenSSL's CT compare internally ; we don't re-verify |
| `src/fhsm_pkcs11.c` | `C_Verify` (HMAC path) | `fhsm_ct_memcmp(mac, pSig, mac_len)` |
| `src/fhsm_pkcs11.c` | `C_Verify` (CMAC path) | `fhsm_ct_memcmp(mac, pSig, 16)` |
| `src/fhsm_integrity.c` | `fhsm_integrity_verify` | `fhsm_ct_memcmp(g_last_digest, fhsm_module_integrity_digest, 32)` |
| `kat/fhsm_kat_vectors.c` | KAT comparisons | `fhsm_ct_memcmp` throughout |

### 2.2 PIN auth timing

The PIN throttle check happens **before** the PBKDF2 derivation in `fhsm_token_login` :

```c
if (*fails >= FHSM_PIN_MAX_FAILED) return FHSM_RV_PIN_LOCKED;
if (now < *until) return FHSM_RV_PIN_THROTTLED;
/* ... then PBKDF2 derivation ~100 ms ... */
```

This prevents an attacker from observing whether PBKDF2 ran or not (which would leak whether the throttle was active).

### 2.3 Memory zeroization

All sensitive buffers are cleared on the failure path AND on success-exit :

| Buffer | Where cleared |
|---|---|
| KEK (PBKDF2 output) | After AES-GCM wrap/unwrap |
| DEK (in secure heap) | `C_Logout`, `C_Finalize`, `fhsm_token_close` |
| Stack-allocated key buffers | `fhsm_zeroize` (calls `OPENSSL_cleanse`) |
| ECDH shared secret | Right after `fhsm_token_object_add` returns |
| OAEP label copy | After `EVP_PKEY_CTX_set0_rsa_oaep_label` (ctx takes ownership) |
| ML-KEM shared secret in harnesses | After comparison |

### 2.4 Audit log

Only **lengths and event types** are written to the audit log. No PIN, no DEK byte, no key value, no plaintext. Verified by `safe_ascii` filter in `fhsm_audit_event`.

### 2.5 Memory protection

* DEK and unwrapped keys live in the `fhsm_secure_heap` arena (`mlock`ed pages, allocated via `OPENSSL_secure_malloc`).
* The arena is allocated at module init and zeroized at finalize.
* PaX/grsecurity-style hardening : `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fstack-clash-protection`, `-fcf-protection=full` enabled in Makefile.

---

## 3. Known residual side-channels (Level 2 gaps)

The following are documented as known limitations for future hardening :

### 3.1 OpenSSL FIPS provider (out-of-boundary)

The OpenSSL FIPS provider has its own side-channel posture, audited by Cryptosense and others. FreeHSM C inherits it. Any timing variation in AES-GCM, ECDSA, RSA-PSS comes from there.

### 3.2 PBKDF2 iteration-loop timing

PBKDF2 internally runs 200 000 HMAC-SHA-256 iterations. Each iteration takes a deterministic time on a fixed CPU. An attacker measuring total time can confirm that the iteration count was 200 000 (not 0 = wrong PIN), but cannot extract the PIN itself. **No fix needed.**

### 3.3 EVP_DigestSign for PQ schemes

`EVP_DigestSign` for ML-DSA and SLH-DSA may not be fully constant-time in OpenSSL 3.5.6 (the implementations are very new). FIPS provider validation is in progress upstream. **Future hardening : pin to a provider version with constant-time PQ.**

### 3.4 File I/O side channels

Reading the token file from disk is not constant-time (cache effects, FS journaling). An attacker monitoring file I/O could learn that a login is happening but not the PIN. **Mitigation : run the module under `LD_PRELOAD=libnonblocking-fs.so` or unmount /tmp before sensitive ops** (operational guidance, not module-internal).

### 3.5 Power analysis

Not applicable for software module on a general-purpose CPU. If integrated into a dedicated HSM appliance, the appliance's hardware boundary handles this separately.

---

## 4. Future hardening (Level 2 candidate)

To pass AVA_VAN.5 / Level 2 :

1. **CT-PINcompare** : Even the early-exit on locked PIN reveals timing. Add a CT-equivalent path that always runs the PBKDF2 derivation and then ignores the result for locked PINs. Cost : ~100 ms per "locked" auth attempt.

2. **Cache attacks on AES** : OpenSSL FIPS provider uses AES-NI (constant-time) on modern x86. Confirm the build flags forbid the lookup-table fallback (`-DOPENSSL_NO_AES_NO_NI=0`).

3. **Spectre/Meltdown** : ARM/Intel mitigations apply at kernel level. We don't add LFENCE in our own code. If the host runs on a vulnerable CPU (Intel pre-CFL or AMD pre-Zen2), advise turning on retpoline / IBRS.

4. **TPM 2.0 binding** : Reduces the impact of a memory disclosure : the sealed DEK is useless without the TPM identity. See `src/fhsm_tpm.c`.

5. **PCR pinning** : Validate that the OS kernel + initrd + bootloader haven't been tampered with by binding the TPM seal to PCR 0-7. An attacker who replaces the kernel won't be able to unseal.

---

## 5. Audit method

The "Constant-Time Checker" `binsec` or `ctgrind` can be applied to the compiled `.so`. We have not yet run those tools (planned for v1.2.0).

For a manual quick check :
```bash
# Build with debug
make CFLAGS_EXTRA="-O0 -ggdb"

# Use perf to measure timing of C_Login with wrong PIN
perf stat -e cpu-clock -r 100 ./test_login_timing wrong_pin
perf stat -e cpu-clock -r 100 ./test_login_timing correct_pin

# Compare distributions. Expectation : both should be ~100 ms ± 5%
# (dominated by PBKDF2). If significantly different (> 1 ms variance),
# a timing oracle exists.
```

---

**Status :** Level 1 self-attestation. Level 2 hardening tracked as Task #155+ (TBD).
