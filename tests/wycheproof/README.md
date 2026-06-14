# Wycheproof test runner for FreeHSM C

This directory integrates **[Project Wycheproof][wp]** (originally by
Google, now stewarded by C2SP) into the FreeHSM C test suite. Wycheproof
publishes thousands of crafted test vectors designed to surface subtle
crypto bugs that conventional functional tests miss : timing-sensitive
padding oracles, malformed signatures, edge-case scalars, curve confusion,
nonce reuse, etc.

[wp]: https://github.com/C2SP/wycheproof

## What we test

| Wycheproof category            | FreeHSM mechanism                       | Adapter                |
|--------------------------------|------------------------------------------|------------------------|
| `rsa_signature_*.json`         | `CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS`       | `adapters/rsa_pss.py`  |
| `ecdsa_*.json`                 | `CKM_ECDSA`                              | `adapters/ecdsa.py`    |
| `eddsa_*.json`                 | `CKM_EDDSA`                              | `adapters/eddsa.py`    |
| `aes_gcm_test.json`            | `CKM_AES_GCM`                            | `adapters/aes_gcm.py`  |
| `hmac_*.json`                  | `CKM_SHA*_HMAC`                          | `adapters/hmac.py`     |
| `mlkem_*.json` (when published)| `CKM_ML_KEM`                             | `adapters/ml_kem.py`   |

## Running

```bash
cd tests/wycheproof

# 1. Fetch latest vectors (excluded from git -- ~30 MB JSON)
./fetch_vectors.sh

# 2. Run all adapters against libfreehsm-fips.so
./run_wycheproof.py --module ../../libfreehsm-fips.so

# 3. Or target a single adapter
./run_wycheproof.py --module ../../libfreehsm-fips.so --only ecdsa

# 4. Smoke subset (~30 s, runs on every push)
./run_wycheproof.py --smoke
```

## Interpretation

Each test vector carries one of three expected results :

* **valid** — the module MUST accept (return success, signature verifies, etc.)
* **invalid** — the module MUST reject (return CKR_FUNCTION_FAILED or equivalent)
* **acceptable** — both behaviours are tolerated. Logged but not failed.

The runner exits non-zero if any **valid** test is rejected or any
**invalid** test is accepted.

## CI wiring

A nightly GitHub Actions job (`.github/workflows/wycheproof.yml`) runs the
full suite and publishes the JSON report as a build artefact. A run
failure on a **valid** vector is treated as a P1 issue.

## Why nightly and not on every commit

The full Wycheproof suite is large (~20 minutes wall-clock for the python
adapter on a single core). On every push we run only the smoke subset
(`run_wycheproof.py --smoke`) ; the full sweep happens at 02:00 UTC.

## Reproducing the analysis

`./fetch_vectors.sh` pins a Wycheproof commit SHA recorded in `VECTORS_SHA`.
When the upstream repo gains new vectors that are relevant, bump that
file and commit ; the runner stays bit-identical otherwise.

## See also

* `kat/` — Known Answer Tests for FIPS self-test.
* `tests/cavp_extended.c` — published-vector subset (current).
* `tests/cavp/` — extended CAVP coverage (planned).
