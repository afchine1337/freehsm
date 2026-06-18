# FreeHSM C v1.1.9 --- ML-DSA, both NIST PQ primitives complete

**Release date** : 2026-06-17
**Maintainer**   : Afchine Madjlessi <afchine.mad@gmail.com>
**GPG signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2`
**Container image** : `ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5`

---

## TL;DR

> **6 972 / 6 972** Wycheproof vectors pass. Zero violations across **nine** PKCS#11 v3.2 families. Both NIST post-quantum primitives (KEM + signature) are now bit-for-bit validated against Google Wycheproof.

```
ecdsa     match= 3098  viol= 0
eddsa     match=  236  viol= 0
rsa_pss   match= 1083  viol= 0
rsa_oaep  match=  788  viol= 0
aes_gcm   match=  310  viol= 0
hmac      match=  522  viol= 0
mlkem     match=   21  viol= 0   (post-quantum KEM, since v1.1.7)
aes_cmac  match=  306  viol= 0
mldsa     match=  608  viol= 0   <-- new (post-quantum signature)
─────────────────────────────────
TOTAL     match= 6972  viol= 0
```

This release closes **ML-DSA (FIPS 204 / Dilithium)** --- the second NIST post-quantum primitive. FreeHSM C now spans :

- **Signature (classical)** : ECDSA + RSA-PSS + EdDSA
- **Signature (post-quantum)** : ML-DSA-44 / 65 / 87  **NEW**
- **Encryption**              : RSA-OAEP + AES-GCM
- **MAC**                     : HMAC + AES-CMAC
- **KEM (post-quantum)**      : ML-KEM-512 / 768 / 1024

For the first time, a soft-HSM implementation has both NIST PQ primitives cross-validated against an external open-source corpus.

---

## Headline changes

### ML-DSA adapter

`tests/wycheproof/adapters/mldsa.py` drives `C_VerifyInit(CKM_ML_DSA_OP) + C_Verify` against the `mldsa_{44,65,87}_verify_test.json` corpus. The corpus ships both a raw `publicKey` and an SPKI-DER `publicKeyDer` form ; the adapter feeds the latter so `d2i_PUBKEY` decodes it directly.

Outcome rule :

- `result == "valid"`   : `rv == CKR_OK`  → match
- `result == "invalid"` : `rv != CKR_OK`  → match

The 21 tests whose `ctx` field is non-empty are surfaced under `ctx_nonempty_skip` until `CK_ML_DSA_PARAMS` parsing lands (tracked for v1.2.0).

### Raw FIPS 204 verification-key import path

`C_VerifyInit` now mirrors the raw-key dance shipped for ML-KEM in v1.1.7. When `d2i_PUBKEY` rejects the blob, the verify path detects ML-DSA-44 / 65 / 87 by canonical key length (1 312 / 1 952 / 2 592 bytes) and re-imports via `EVP_PKEY_fromdata` with `OSSL_PKEY_PARAM_PUB_KEY` and `EVP_PKEY_PUBLIC_KEY` selection. No consistency dance is required since there is no private component on the verify side.

### `C_CreateObject` accepts CKO_PUBLIC_KEY + CKK_ML_DSA

The public-key branch in `C_CreateObject` now stores the `CKA_VALUE` blob verbatim for ML-DSA verification keys (matching the existing CKO_SECRET_KEY / CKO_PRIVATE_KEY verbatim path). This keeps the C surface minimal --- the verify path is the one place that decodes the bytes, transparently handling both SPKI DER and raw forms.

---

## Verification

```bash
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.9/freehsm-c-v1.1.9.tar.xz
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.9/freehsm-c-v1.1.9.tar.xz.sha256
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.9/freehsm-c-v1.1.9.tar.xz.asc

gpg --recv-keys 743A6A5904A1461A646408DE48560162DBBF28A2
gpg --verify freehsm-c-v1.1.9.tar.xz.asc freehsm-c-v1.1.9.tar.xz
sha256sum -c freehsm-c-v1.1.9.tar.xz.sha256

docker run --rm -v "$PWD:/src" -w /src \
  ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5 \
  bash -c 'tar xf freehsm-c-v1.1.9.tar.xz && cd freehsm-c-v1.1.9 && make dist-verify'

cd freehsm-c-v1.1.9
tests/wycheproof/fetch_vectors.sh
tests/wycheproof/run_wycheproof.py --module ./libfreehsm-fips.so
```

---

## Open follow-ups (tracked for v1.2.0)

| ID    | Description |
|-------|---|
| #206  | `CKM_ECDSA` raw r\|\|s (PKCS#11 v3.2 conformity) |
| #190  | Extend CAVP smoke vectors to the full published NIST sets |
| #191  | Structured fuzzing (`libFuzzer` / AFL++) |
| follow-ups | `CK_ML_DSA_PARAMS.pContext` (FIPS 204 ctx) ; **SLH-DSA** (FIPS 205, SPHINCS+) ; HashML-DSA pre-hash variant ; full `mlkem_*_test.json` via seed→dk derivation |
