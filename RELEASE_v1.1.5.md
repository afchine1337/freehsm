# FreeHSM C v1.1.5 — AES-GCM + HMAC

**Release date** : 2026-06-17  
**Maintainer** : Afchine Madjlessi <afchine.mad@gmail.com>  
**GPG signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2`  
**Container image** : `ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5`

---

## TL;DR

> **5 249 / 5 249** Wycheproof test vectors pass. Zero violations across five PKCS#11 v3.2 families.

```
ecdsa     match= 3098  viol= 0  skip=18794
eddsa     match=  236  viol= 0  skip=    0
rsa_pss   match= 1083  viol= 0  skip= 1323
aes_gcm   match=  310  viol= 0  skip=    6     ← 6 IV-sizes > OpenSSL cap
hmac      match=  522  viol= 0  skip=    0     ← 174 × {SHA-256, SHA-384, SHA-512}
─────────────────────────────────────────
TOTAL     match= 5249  viol= 0
```

This release extends the v1.1.4 asymmetric-signature coverage with the two
remaining mainstream symmetric primitives :

- **AES-GCM** (authenticated encryption) — all three AES key sizes,
  variable IV up to 512 bits (the OpenSSL provider's cap), variable AAD,
  truncated and full tags.
- **HMAC SHA-{256, 384, 512}** — full key-length sweep with
  per-test tag-length truncation.

The five-family corpus is now what a real-world PKCS#11 application
exercises end-to-end on a daily basis : RSA-PSS or ECDSA at the TLS /
JWS / S/MIME boundary, EdDSA for SSH and modern protocols, AES-GCM for
record-layer payloads, HMAC for OAuth tokens, JWT and HMAC-DRBG
seeding.

---

## Headline changes

### AES-GCM, properly parameterised

Until v1.1.4 the `C_Decrypt` AES-GCM path hard-coded a 12-byte IV, an
empty AAD and a 16-byte tag (inherited from `fhsm_aes_gcm_decrypt`'s
helper signature). v1.1.5 :

- `fhsm_op_t` carries three new GCM-context fields populated by
  `op_init` from `CK_GCM_PARAMS` :
  ```c
  uint8_t gcm_iv[512];     /* IV, up to 4096 bits */
  uint8_t gcm_aad[4096];   /* AAD, up to 32 Kibit */
  size_t  gcm_tag_len;     /* in BYTES (ulTagBits / 8) */
  ```
- Both the legacy 12-byte IV shortcut (what OpenSC's `pkcs11-tool` sends
  with `--iv`) and the canonical PKCS#11 v3.x 48-byte struct are
  accepted in `op_init`.
- `C_Decrypt` for AES-GCM inlines the OpenSSL `EVP_CIPHER_CTX_ctrl` /
  `EVP_DecryptInit_ex` sequence so the IV length, AAD and tag length
  are set per call. The pre-existing helper still backs the rest of the
  module via 12-byte IVs.

### HMAC SHA-384 / SHA-512

The two longer-hash HMAC mechanisms were missing from the `C_SignInit`
allowed-list **and** unmapped by the dispatch in `C_Sign`. v1.1.5
declares them, accepts them, and the HMAC branch dispatches by
mechanism to `FHSM_HASH_SHA{256,384,512}` with the matching 32 / 48 /
64-byte MAC length.

### `C_CreateObject` symmetric-secret branch

A short branch was added to `C_CreateObject` for `CKO_SECRET_KEY` (any
key type) that stores the raw `CKA_VALUE` bytes directly. AES-GCM and
HMAC reuse the existing `fhsm_token_object_get` lookup path without
further plumbing.

### Harness updates

- **`tests/wycheproof/adapters/aes_gcm.py`** : decrypt-and-verify path
  with `CK_GCM_PARAMS` packed via `ctypes.Structure` (6 `c_ulong`-sized
  words, 48 bytes).
- **`tests/wycheproof/adapters/hmac.py`** : sign-truncate-compare with
  a self-contained constant-time compare (rolling our own avoids the
  Python-side namespace collision with stdlib `hmac` that the file name
  causes).
- **`tests/wycheproof/run_wycheproof.py`** : forwards the file-level
  `algorithm` string into each `group` dict so MAC adapters can pick
  the hash without re-reading the file.

---

## Documented upstream limitation

The Wycheproof AES-GCM corpus contains three test groups with `ivBits`
greater than the OpenSSL 3.x default provider's hard cap
(`GCM_IV_MAX_SIZE = 64 bytes`, i.e. 512 bits) :

| ivBits | Count |
|---|---|
| 1024 | 3 |
| 2056 | 3 |

These appear in the adapter's diag block as `iv_over_openssl_limit 6`
(and split per-size as `iv_skip_1024_bits 3` / `iv_skip_2056_bits 3`)
and are classified as **skip**, not violation. The limitation is in
the OpenSSL provider, not in FreeHSM ; using a build with the FIPS
provider (which can support longer IVs depending on configuration)
would re-enable them.

---

## Verification

```bash
# Tarball
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.5/freehsm-c-v1.1.5.tar.xz
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.5/freehsm-c-v1.1.5.tar.xz.sha256
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.5/freehsm-c-v1.1.5.tar.xz.asc

# GPG signature
gpg --recv-keys 743A6A5904A1461A646408DE48560162DBBF28A2
gpg --verify freehsm-c-v1.1.5.tar.xz.asc freehsm-c-v1.1.5.tar.xz

# SHA-256
sha256sum -c freehsm-c-v1.1.5.tar.xz.sha256

# Reproducible build
docker run --rm -v "$PWD:/src" -w /src \
  ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5 \
  bash -c 'tar xf freehsm-c-v1.1.5.tar.xz && cd freehsm-c-v1.1.5 && make dist-verify'

# Replay the Wycheproof suite
cd freehsm-c-v1.1.5
tests/wycheproof/fetch_vectors.sh
tests/wycheproof/run_wycheproof.py --module ./libfreehsm-fips.so
```

---

## Open follow-ups (tracked for v1.2.0)

| ID | Description |
|----|---|
| #206 | `CKM_ECDSA` (raw) PKCS#11 v3.2 conformity : the module currently consumes / produces DER signatures, not raw r\|\|s as the spec says. Adapter has a workaround. |
| #190 | Extend CAVP smoke vectors to the full published NIST sets (~100 per algorithm). |
| #191 | Structured fuzzing (`libFuzzer` / AFL++). |
| follow-ups | RSA-OAEP, ML-KEM, AES-CMAC adapters (the remaining Wycheproof families a typical PKCS#11 app uses). |
