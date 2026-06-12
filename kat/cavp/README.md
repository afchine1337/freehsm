# CAVP Test Vectors

This directory holds the **representative subset** of NIST CAVP test vectors used by the boot-time KAT runner (`fhsm_rsp_run_directory`). Every file is in the standard CAVP `.rsp` format and is parsed by `kat/fhsm_kat_rsp.c`.

## Files shipped (sample set)

| File | Algorithm | Source | Count |
|---|---|---|---|
| `sha2_256_short.rsp` | SHA-256 short-message | FIPS 180-4 + Python `hashlib` cross-check | 9 |
| `sha2_384_short.rsp` | SHA-384 short-message | FIPS 180-4 + Python `hashlib` cross-check | 9 |
| `sha2_512_short.rsp` | SHA-512 short-message | FIPS 180-4 + Python `hashlib` cross-check | 9 |
| `sha3_256_short.rsp` | SHA3-256 short-message | FIPS 202 + Python `hashlib` cross-check | 9 |
| `sha3_384_short.rsp` | SHA3-384 short-message | FIPS 202 + Python `hashlib` cross-check | 9 |
| `sha3_512_short.rsp` | SHA3-512 short-message | FIPS 202 + Python `hashlib` cross-check | 9 |
| `hmac_sha256.rsp` | HMAC-SHA-256 | RFC 4231 + cross-check | 6 |
| `hmac_sha384.rsp` | HMAC-SHA-384 | RFC 4231 + cross-check | 6 |
| `hmac_sha512.rsp` | HMAC-SHA-512 | RFC 4231 + cross-check | 6 |
| `aes_gcm_128.rsp` | AES-128-GCM | SP 800-38D Appendix B + cross-check | 4 |
| `aes_gcm_256.rsp` | AES-256-GCM | SP 800-38D Appendix B + cross-check | 3 |
| `pbkdf2_sha256.rsp` | PBKDF2-HMAC-SHA-256 | RFC 7914 + cross-check (iter ≥ 200_000) | 4 |
| `ctr_drbg.rsp` | CTR_DRBG-AES-256 | structure only (walker pending) | 0 |

The sample set covers ~90 vectors, enough to detect any totally-broken implementation. For FIPS 140-3 / CC EAL4+ submission, replace with the full CAVP corpus per below.

## Loading the full CAVP corpus

For a real FIPS 140-3 / CAVP submission, the lab requires the *complete* vector set ‒ typically 100+ vectors per primitive, including:

- *Short-message* vectors (block-aligned and unaligned inputs)
- *Long-message* vectors (multi-block, multi-MiB inputs)
- *Monte Carlo* vectors (chained hashing 1 000 000 iterations)
- *Tag-truncation* and *short-IV* edge cases for AES-GCM
- *Reseed* and *prediction-resistance* paths for CTR_DRBG

Download from the official ACVP server :

```bash
# Vectors are published per submission lot. The fips-acvp-data project
# mirrors the public set:
git clone --depth 1 https://github.com/usnistgov/ACVP-Server.git
cp ACVP-Server/gen-val/json-files/*/*.rsp kat/cavp_full/
```

Once placed under `kat/cavp_full/`, set the environment variable
`FHSM_KAT_DIR=kat/cavp_full` before running the test binary, or pass
the directory as the first argument to the test harness. The runner
walks every `.rsp` file and dispatches to the appropriate algorithm
runner based on filename prefix.

## File-naming convention

The directory walker (`fhsm_rsp_run_directory`) routes by filename prefix :

| Prefix | Algorithm runner |
|---|---|
| `sha2_*`    | `fhsm_rsp_run_sha2`    |
| `sha3_*`    | `fhsm_rsp_run_sha3`    |
| `hmac_*`    | `fhsm_rsp_run_hmac`    |
| `aes_gcm_*` | `fhsm_rsp_run_aes_gcm` |
| `pbkdf2_*`  | `fhsm_rsp_run_pbkdf2`  |
| `ctr_drbg*` | `fhsm_rsp_run_ctr_drbg`|

If you obtain CAVP files with different names (e.g. `SHA256ShortMsg.rsp` from the historical CAVS tool), rename them to fit the prefix above. A helper script `scripts/normalize_cavp_names.sh` (to be added) automates this.

## Cross-validation

Every shipped vector was independently computed using a **different implementation** than OpenSSL :

- SHA-2 / SHA-3 / HMAC : Python `hashlib` / `hmac` (built on Python's own SHA implementation)
- AES-GCM : Python `cryptography` library (built on the cffi binding to OpenSSL, but compiled separately from the FreeHSM OpenSSL provider)
- PBKDF2 : Python `hashlib.pbkdf2_hmac`

This independence is required by FIPS 140-3 §7.10.4 ("the KAT outputs shall be computed by a tool other than the one under test").

## Status

- ✅ Format parser : streams the whole CAVP corpus without buffering
- ✅ SHA-2 / SHA-3 / HMAC / AES-GCM / PBKDF2 runners
- 🟡 CTR_DRBG walker (placeholder — SP 800-90A reseed + prediction-resistance paths not yet wired)
- ⏳ Monte Carlo loops (FIPS 180-4 §6.4) — file structure recognized, looped runner pending
- ⏳ ECDSA / EdDSA / RSA-PSS / ML-DSA / SLH-DSA runners — need handler integration with the dispatch layer

The full set should be loaded ahead of CMVP submission. The infrastructure is in place ; only the runner specializations for the asymmetric / PQ primitives and the Monte Carlo loop are pending.
