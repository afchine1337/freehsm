# FreeHSM C v1.1.7 --- ML-KEM, seven-family complete

**Release date** : 2026-06-17
**Maintainer**   : Afchine Madjlessi <afchine.mad@gmail.com>
**GPG signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2`
**Container image** : `ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5`

---

## TL;DR

> First **post-quantum** Wycheproof family lands cleanly. 21 / 21 ML-KEM-512/768/1024 vectors pass. Seven families, **zero** violations.

```
ecdsa     match= 3098  viol= 0
eddsa     match=  236  viol= 0
rsa_pss   match= 1083  viol= 0
rsa_oaep  match=  788  viol= 0
aes_gcm   match=  310  viol= 0
hmac      match=  522  viol= 0
mlkem     match=   21  viol= 0     <-- new
─────────────────────────────────
TOTAL     match= 6058  viol= 0
```

This release closes the first NIST post-quantum primitive --- **ML-KEM (FIPS 203)** --- against the external Wycheproof corpus. FreeHSM C now spans :

- **Signature**        : ECDSA + RSA-PSS + EdDSA
- **Encryption**       : RSA-OAEP + AES-GCM
- **MAC**              : HMAC
- **Key encapsulation (PQ)** : ML-KEM-512 / 768 / 1024

All standard parameter sets, all hash variants for the classical families, every Wycheproof PKCS#11 v3.2-style negative test.

---

## Headline changes

### ML-KEM adapter

`tests/wycheproof/adapters/mlkem.py` drives `C_DecapsulateKey(CKM_ML_KEM_OP)` against the `mlkem_*_semi_expanded_decaps_test.json` corpus for the three NIST parameter sets. Decision rule follows FIPS 203 §7.3 implicit rejection :

- `valid` test : `rv == OK` (and `ss == K` when the corpus provides a shared-secret field)
- `invalid` test : `rv != OK` (structural reject) **or** `ss != K` (implicit reject)

This means **both** kinds of negative tests are handled with one harness without short-circuiting the decapsulation path : length checks and structural rejects are caught by OpenSSL ; the few "valid-shape, malformed content" cases (Wycheproof `InvalidDecapsulationKey` flag) are caught by the keymgmt consistency check inside `EVP_PKEY_fromdata`.

### Raw FIPS 203 `dk` import path

The Wycheproof semi-expanded corpus serialises the decapsulation key as raw 1 632 / 2 400 / 3 168 bytes (the FIPS 203 expanded form) rather than as a PKCS#8 PrivateKeyInfo envelope. `C_DecapsulateKey` now :

1. Tries `d2i_AutoPrivateKey(NULL, &p, kvl)` first --- handles PKCS#8 / PKCS#1 input transparently.
2. On failure, detects ML-KEM-512 / 768 / 1024 by the canonical key length and re-imports via `EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_KEYPAIR, params)` with `OSSL_PKEY_PARAM_PRIV_KEY`. The `EVP_PKEY_KEYPAIR` selection is required (not `PRIVATE_KEY`-only) because OpenSSL 3.5's ML-KEM keymgmt cross-checks the embedded public component during the import dance.

Both paths produce an identical `EVP_PKEY *` for downstream use, so `EVP_PKEY_decapsulate` and the secret-key object creation remain unchanged.

### Critical fix : harness DEK loaded on every session

`fhsm_token_object_add()` returns `CKR_USER_NOT_LOGGED_IN` (`0x101`) when the token's data-encryption key is not in memory --- the DEK is loaded on `C_Login`. The Wycheproof harness `_bootstrap_token()` opens the token idempotently : if the token file already exists from a previous run, the probe `C_OpenSession` succeeds and bootstrap returns early **without doing any login**. On a fresh `/tmp` this was masked because the very first call followed the `C_InitToken` + `C_Login(SO)` + `C_InitPIN` path, which transitively populated `t->dek`. On a re-run with persisted state, the DEK stayed `NULL`, and every `C_CreateObject` in every adapter returned `0x101` --- silently wiping out all six previously-validated families.

`P11Module.open_session()` now performs an idempotent `C_Login(USER, "user0000")` against the bootstrap PIN. `CKR_USER_ALREADY_LOGGED_IN` (`0x100`) is accepted as success. This restores all six classical families and unlocks the new ML-KEM path in one change.

### PKCS#11 v3.0 plumbing in the harness

`tests/wycheproof/adapters/_p11.py` now binds `C_DecapsulateKey`, `C_EncapsulateKey`, and `C_GetAttributeValue`, and adds :

- `P11Session.decapsulate(priv_key, mech, ct, template)` returning `(rv, new_key_handle)` --- the shared secret is materialised as a fresh `CKO_SECRET_KEY` (`CKK_GENERIC_SECRET`) per PKCS#11 v3.0 §6.13.
- `P11Session.get_attribute_value(obj_handle, attr_type)` for reading `CKA_VALUE` back from the harness.
- Constants `CKK_ML_KEM = 0x3C`, `CKM_ML_KEM_OP = 0x403D`.
- `EXTRACTABLE` and `SENSITIVE` constructors in the attribute-builder DSL.

---

## Verification

```bash
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.7/freehsm-c-v1.1.7.tar.xz
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.7/freehsm-c-v1.1.7.tar.xz.sha256
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.7/freehsm-c-v1.1.7.tar.xz.asc

gpg --recv-keys 743A6A5904A1461A646408DE48560162DBBF28A2
gpg --verify freehsm-c-v1.1.7.tar.xz.asc freehsm-c-v1.1.7.tar.xz
sha256sum -c freehsm-c-v1.1.7.tar.xz.sha256

# Reproducible build inside the pinned container
docker run --rm -v "$PWD:/src" -w /src \
  ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5 \
  bash -c 'tar xf freehsm-c-v1.1.7.tar.xz && cd freehsm-c-v1.1.7 && make dist-verify'

# Replay the full Wycheproof sweep
cd freehsm-c-v1.1.7
tests/wycheproof/fetch_vectors.sh
tests/wycheproof/run_wycheproof.py --module ./libfreehsm-fips.so
```

---

## Open follow-ups (tracked for v1.2.0)

| ID    | Description |
|-------|---|
| #206  | `CKM_ECDSA` (raw) PKCS#11 v3.2 conformity (raw r\|\|s vs DER) |
| #190  | Extend CAVP smoke vectors to the full published NIST sets |
| #191  | Structured fuzzing (`libFuzzer` / AFL++) |
| follow-ups | ML-DSA (FIPS 204), SLH-DSA (FIPS 205) Wycheproof adapters ; main `mlkem_*_test.json` corpus (193 × 3 vectors, requires seed→dk derivation) ; AES-CMAC, KDF adapters |
