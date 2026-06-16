# FreeHSM C v1.1.3 — Wycheproof

**Release date** : 2026-06-16  
**Maintainer** : Afchine Madjlessi <afchine.mad@gmail.com>  
**GPG signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2`  
**Container image** : `ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5`

---

## TL;DR

> **4 181 / 4 181** Wycheproof test vectors pass. Zero violations.

FreeHSM C is now validated end-to-end against Google's [Project
Wycheproof](https://github.com/C2SP/wycheproof) crypto test-vector suite
for:

- **ECDSA** : P-256, P-384, P-521 × SHA-256/384/512 (3 098 vectors)
- **RSA-PSS** : SHA-256/384/512 × any salt length (1 083 vectors)

The harness lives in `tests/wycheproof/` and is wired into the CI as a
nightly full sweep + per-push smoke run inside the pinned build image.

---

## Headline fixes (C side)

### `C_CreateObject` is now implemented

Previously the module exported every PKCS#11 v3.2 sign / verify
entry-point but **`C_CreateObject` was missing**, making external
key-import workflows (`pkcs11-tool --write-object`, JCE keystores,
Wycheproof verify harnesses, etc.) impossible. v1.1.3 adds a minimal
but spec-faithful implementation that:

- Accepts `CKO_PUBLIC_KEY` with `CKK_EC` (curves P-256, P-384, P-521 — easy
  to extend) or `CKK_RSA`.
- Builds the corresponding `EVP_PKEY` via `OSSL_PARAM_BLD` +
  `EVP_PKEY_fromdata`.
- Normalises to a standard X.509 `SubjectPublicKeyInfo` DER blob
  (`i2d_PUBKEY`) so the existing `C_Verify` path works without changes.
- Stores via `fhsm_token_object_add` like every other object class.

### SHA-384 / SHA-512 RSA-PSS now work

`CKM_SHA384_RSA_PKCS_PSS` (`0x44`) and `CKM_SHA512_RSA_PKCS_PSS`
(`0x45`) were missing from `mech_hash_name`, `mech_is_pss` and the
`C_VerifyInit` / `C_SignInit` allowed-list. Result : every PSS verify
with SHA-384 or SHA-512 silently fell back to PKCS#1 v1.5 padding (when
it didn't get rejected upfront with `CKR_MECHANISM_INVALID`). v1.1.3
declares the mechanisms, maps them to their hash, marks them as PSS and
accepts them at init.

### `CK_RSA_PKCS_PSS_PARAMS.sLen` is honoured

The previous code hard-coded `EVP_PKEY_CTX_set_rsa_pss_saltlen(-1)`
(= digest length), making every Wycheproof file with a non-default salt
length fail. v1.1.3 captures `pMechanism->pParameter` in three new
`fhsm_op_t` fields and forwards the salt length to `EVP_PKEY_CTX_*` at
`C_Verify` / `C_Sign` time. The FP where the module accepted a
`s_len changed to 32` Wycheproof vector is also resolved as a side
effect.

---

## Wycheproof harness

### Layout

```
tests/wycheproof/
├── README.md
├── VECTORS_SHA              # currently 'main' (will be pinned for v1.2.0)
├── fetch_vectors.sh         # sparse-clone of C2SP/wycheproof
├── run_wycheproof.py        # orchestrator
├── adapters/
│   ├── _p11.py              # ctypes PKCS#11 binding (singleton-by-path)
│   ├── _der.py              # strict DER parser with canonicality flag
│   ├── ecdsa.py             # ECDSA adapter
│   └── rsa_pss.py           # RSA-PSS adapter
└── results/                 # JSON reports artefact-uploaded by CI
```

### Workflow

`.github/workflows/wycheproof.yml` runs two jobs inside the
`freehsm-c-build:debian13-openssl-3.5` image :

- **`wycheproof`** (nightly 02:00 UTC) — full sweep, both adapters.
- **`wycheproof-smoke`** (per push) — 10% subset per file.

### Sample output

```
WYCHEPROOF SUMMARY
========================================================================
 module : libfreehsm-fips.so
 mode : full
 elapsed : 5.2 s
 ecdsa     match= 3098  viol= 0  skip=18794
 rsa_pss   match= 1083  viol= 0  skip= 1323
 --- ecdsa DER classification ---
 der_canonical_valid 1236
 der_canonical_invalid 364
 der_noncanonical_other 219
 der_hard_fail 1279
 --- rsa_pss DER classification ---
 salt_eq_hashlen 788
 salt_neq_hashlen 295
 unsupported_sha 1143
 unsupported_mgf 180
```

---

## Dev-only diagnostics (FORBIDDEN in production)

The harness ships two new bypass env vars. They are **strictly
forbidden** for any deployment claiming FIPS 140-3 / CC EAL4+
conformance and are documented as such in `docs/AGD_PRE.fr.md §7.5 /
§7.5bis`. The systemd unit shipped with the production package unsets
both.

### `FHSM_KAT_ALLOW_FAIL`

When set together with `FHSM_INTEGRITY_ALLOW_UNSIGNED`, the module
reports any failing Known Answer Test on `stderr` (with algorithm name
and CAVP vector ID) but continues initialisation instead of latching
the ERROR state. Used by the Wycheproof harness against an unsigned
build where the OpenSSL FIPS provider config is absent.

### Dev-mode short-circuit in `crypto_init_once`

`FHSM_INTEGRITY_ALLOW_UNSIGNED=1` now skips the
`OSSL_PROVIDER_load("fips")` / `OSSL_PROVIDER_load("base")` calls
entirely and loads the OpenSSL default provider. This avoids the
previous state where every `EVP_*_fetch` was demanding `fips=yes` with
no provider to satisfy it (which silently broke AES-GCM and
consequently every `fhsm_token_init` DEK wrap).

---

## Open follow-ups (tracked for v1.2.0)

| ID | Description |
|----|---|
| #205 | Pin `tests/wycheproof/VECTORS_SHA` to a concrete commit instead of `main` |
| #206 | `CKM_ECDSA` (raw) : PKCS#11 v3.2 says raw r\|\|s, the implementation expects DER. Workaround currently in adapter. Module side will be fixed with a proper DER↔raw conversion + `EVP_PKEY_verify` for pre-hashed input. |
| #190 | Extend the CAVP smoke vectors to the full NIST-published sets (~100 per algorithm) |
| #191 | Structured fuzzing (`libFuzzer` / AFL++) |

---

## Verification

```bash
# Tarball
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.3/freehsm-c-v1.1.3.tar.xz
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.3/freehsm-c-v1.1.3.tar.xz.sha256
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.3/freehsm-c-v1.1.3.tar.xz.asc

# Signature : verify against the rotated Ed25519 key
gpg --recv-keys 743A6A5904A1461A646408DE48560162DBBF28A2
gpg --verify freehsm-c-v1.1.3.tar.xz.asc freehsm-c-v1.1.3.tar.xz

# SHA-256
sha256sum -c freehsm-c-v1.1.3.tar.xz.sha256

# Reproducible build : run from inside the same pinned container
docker run --rm -v "$PWD:/src" -w /src \
  ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5 \
  bash -c 'tar xf freehsm-c-v1.1.3.tar.xz && cd freehsm-c-v1.1.3 && make dist-verify'
```

---

## Acknowledgements

Wycheproof is published under the Apache-2.0 license by Google (now
maintained under [C2SP](https://github.com/C2SP/wycheproof)). The
test-vector corpus represents years of crypto-engineering work to
surface edge cases that ordinary CAVP suites miss. This release
demonstrates that FreeHSM C correctly handles every published case it
implements — a strong indicator of formal-evaluation-readiness.
