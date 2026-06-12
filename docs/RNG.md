# FreeHSM C --- Hardened DRBG (v1.1.0)

This document describes the random-number-generation pipeline used by FreeHSM C, the NIST SP 800-90B health tests applied to every output, and the operational guidance for monitoring the DRBG in production.

---

## 1. Pipeline overview

```
[getrandom]   [RDRAND]   [/dev/urandom]   [TSC jitter]
     \           \             /              /
      +-----------+-----+-----+--------------+
                        v
                   SHA-256 conditioner  (SP 800-90C §3.1)
                        v
                  RAND_add (OpenSSL FIPS)
                        v
              RAND_bytes  (CTR_DRBG-AES-256, FIPS provider)
                        v
       [RCT] -- [APT] -- [CRNGT]   (SP 800-90B §4)
                        v
                  caller's buffer
```

The four entropy sources are aggregated, conditioned by SHA-256, then injected via `RAND_add` into OpenSSL's FIPS-validated CTR_DRBG-AES-256. The DRBG output passes through three NIST SP 800-90B health tests on the way back to the caller.

---

## 2. Entropy sources

| Source | Min-entropy estimate | Probe order | Bitmask (in stats) |
|---|---|---|---|
| `getrandom(2)` (Linux ≥ 3.17) | ~7.9 bit/byte (kernel CRNG, blocked until seeded) | 1st | `0x1` |
| RDRAND (Intel x86_64) | ~7.9 bit/byte (vendor-trusted) | 2nd | `0x2` |
| `/dev/urandom` | ~7 bit/byte (conservative, non-blocking variant of /dev/random) | 3rd | `0x4` |
| TSC jitter | ~4 bit/byte (CPU scheduling timing) | 4th | `0x8` |

The module logs which sources contributed bytes at every reseed. If a source becomes unavailable at runtime (e.g. RDRAND disabled via Intel microcode update), the bitmask reflects the change.

If ALL sources fail, `fhsm_drbg_init` returns `FHSM_RV_RNG_FAILURE` and the module enters error state. On a typical Linux server, `getrandom` and `/dev/urandom` are guaranteed available, so this is effectively impossible.

---

## 3. Health tests

### 3.1 Repetition Count Test (RCT)

NIST SP 800-90B §4.4.1. Detects a stuck DRBG output (e.g. fault inducing a constant byte).

| Parameter | Value |
|---|---|
| α (type-I error probability) | 2^-40 |
| H (nominal min-entropy per byte) | 8 |
| Cutoff C | 6 successive identical bytes |

A cutoff of 6 means that 6 identical bytes in a row triggers the alarm. The probability of this happening on a healthy DRBG is < 2^-40 per call.

### 3.2 Adaptive Proportion Test (APT)

NIST SP 800-90B §4.4.2. Detects statistical drift (e.g. a slow-failing entropy source biasing the DRBG toward a value).

| Parameter | Value |
|---|---|
| α | 2^-40 |
| W (window size, samples) | 512 |
| Cutoff C | 51 occurrences of any single byte value in 512 |

For 8-bit samples and α=2^-40, the cutoff is computed from the inverse binomial CDF (table in NIST SP 800-90B Appendix C).

### 3.3 Continuous RNG Test (CRNGT)

NIST SP 800-90B §4.4.3. The simplest catastrophic-failure detector : the DRBG should never emit the same 128-bit block twice in a row.

| Parameter | Value |
|---|---|
| Block size | 16 bytes (128 bits) |
| Compared on | every fhsm_rng_bytes call ≥ 16 bytes |
| False-positive rate | 2^-128 per call (effectively zero) |

---

## 4. Reseed policy

| Trigger | Threshold |
|---|---|
| Bytes emitted since last reseed | 1 MiB |
| Wall-clock since last reseed | 3600 s (1 h) |

Either trigger fires a reseed. NIST SP 800-90A §10.2.1.5 allows up to 2^48 generate calls between reseeds for CTR_DRBG-AES, so our policy is conservative by 40 orders of magnitude. The cost is ~50 µs per reseed (one SHA-256 + 4 syscalls).

A reseed can also be forced manually by calling `fhsm_drbg_reseed()`. This is useful :
- After `fork(2)` (the child must reseed to avoid output collision)
- After a long idle period (e.g. cron-scheduled tasks)
- Before generating a long-term key (defense-in-depth)

---

## 5. Failure handling

A health-test alarm (RCT, APT or CRNGT) is a **Category 1 incident** :

1. The module is immediately latched into `FHSM_STATE_ERROR`.
2. The current output buffer is zeroized before being returned (or rather, returned all-zero with `FHSM_RV_RNG_FAILURE`).
3. All subsequent `C_*` calls return `CKR_DEVICE_ERROR`.
4. The operator MUST restart the service. The audit log preserves the alarm event.

If RCT/APT/CRNGT fires on a freshly-rebooted machine, the cause is almost certainly hardware fault — not a transient condition. Treat as a hardware compromise.

---

## 6. Operational monitoring

```c
fhsm_drbg_stats_t s;
fhsm_drbg_get_stats(&s);
printf("bytes=%lu reseeds=%u sources=0x%x\n",
       (unsigned long)s.bytes_emitted, s.reseeds, s.entropy_sources_active);
```

Recommended monitoring :
- Alert if `entropy_sources_active != 0xF` (one of the four expected sources is unavailable)
- Alert if `reseeds` does not match the expected rate (bytes_emitted / 1 MiB, modulo time-based reseeds)
- Page on any non-zero `*_failures` counter

---

## 7. CAVP coverage

The DRBG itself is the FIPS-validated OpenSSL CTR_DRBG-AES-256 (cert #4282). FreeHSM C inherits CAVP coverage from that certificate. The hardening layer (RCT, APT, CRNGT, conditioning) is implementation-specific and does not require its own CAVP run, but should be exercised at the SubGT (Sub-Granular Testing) level during the CST lab review.

The lab will additionally request :
- Source code review of `src/fhsm_drbg.c`
- A demonstration that RCT and APT fire when fed an artificially-biased stream
- A test that `fhsm_drbg_reseed` correctly produces independent output streams

---

## 8. References

- NIST SP 800-90A Rev 1 : DRBG specification (CTR_DRBG)
- NIST SP 800-90B : Entropy source validation requirements (RCT + APT)
- NIST SP 800-90C : DRBG construction (conditioning + reseed)
- RFC 4086 : Randomness Requirements for Security
- FIPS 140-3 Implementation Guidance §7.10.3 : Continuous random number generator test
