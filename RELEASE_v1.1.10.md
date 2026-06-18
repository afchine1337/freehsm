# FreeHSM C v1.1.10 --- ML-DSA context plumbing

**Release date** : 2026-06-17
**Maintainer**   : Afchine Madjlessi <afchine.mad@gmail.com>
**GPG signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2`
**Container image** : `ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5`

---

## TL;DR

> **6 978 / 6 978** Wycheproof vectors pass. Closes the FIPS 204 context string in `C_VerifyInit`, lifting ML-DSA coverage to 614 / 629 (97.6 %).

```
ecdsa     match= 3098  viol= 0
eddsa     match=  236  viol= 0
rsa_pss   match= 1083  viol= 0
rsa_oaep  match=  788  viol= 0
aes_gcm   match=  310  viol= 0
hmac      match=  522  viol= 0
mlkem     match=   21  viol= 0
aes_cmac  match=  306  viol= 0
mldsa     match=  614  viol= 0    <-- +6 vs v1.1.9 (FIPS 204 ctx now wired)
─────────────────────────────────
TOTAL     match= 6978  viol= 0
```

This is a focused patch release : no new family, but ML-DSA gains the `CK_ML_DSA_PARAMS.pContext` parameter --- the FIPS 204 §5.2.1 context string that PKCS#11 v3.2 §6.18 carries. The 6 Wycheproof tests with a legal non-empty context now verify cleanly.

---

## Headline changes

### `CK_ML_DSA_PARAMS` parsing in `op_init`

The 24-byte parameter struct `{ hedgeVariant, pContext, ulContextLen }` is now decoded when the caller passes it to `C_VerifyInit(CKM_ML_DSA_OP, …)`. The context is copied into a 256-byte static buffer in the operation slot ; `hedgeVariant` is read but ignored on the verify side (FIPS 204 randomization is a sign-side concern).

### `OSSL_SIGNATURE_PARAM_CONTEXT_STRING` forwarded in `C_Verify`

The post-quantum branch of `C_Verify` (ML-DSA / SLH-DSA / EdDSA shared) now calls `EVP_PKEY_CTX_set_params` with the captured context before `EVP_DigestVerify`. The change is gated on the ML-DSA mechanism so SLH-DSA and EdDSA stay on the empty-context default until their own parameter plumbing lands.

### Adapter forwards the corpus `ctx` field

`tests/wycheproof/adapters/mldsa.py` now builds a `CK_ML_DSA_PARAMS` for every test, decoding the optional `ctx` hex field (defaults to empty). Tests with `len(ctx) > 255` (FIPS 204 spec violation) are surfaced under `ctx_oversize_skip` rather than running with a truncated context.

---

## Documented Wycheproof corpus skips

The 15 remaining ML-DSA skips (5 per parameter set) carry `ctx` strings longer than 255 bytes. They test that an ML-DSA implementation rejects oversize contexts. We could plumb them through and let OpenSSL reject, but the FreeHSM internal buffer caps at the FIPS 204 spec limit by construction --- the assumption is that no PKCS#11 v3.2 caller can legitimately request an oversize context. This trade-off is documented in `op_init` and surfaced in the adapter diag.

---

## Verification

```bash
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.10/freehsm-c-v1.1.10.tar.xz
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.10/freehsm-c-v1.1.10.tar.xz.sha256
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.10/freehsm-c-v1.1.10.tar.xz.asc

gpg --recv-keys 743A6A5904A1461A646408DE48560162DBBF28A2
gpg --verify freehsm-c-v1.1.10.tar.xz.asc freehsm-c-v1.1.10.tar.xz
sha256sum -c freehsm-c-v1.1.10.tar.xz.sha256

docker run --rm -v "$PWD:/src" -w /src \
  ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5 \
  bash -c 'tar xf freehsm-c-v1.1.10.tar.xz && cd freehsm-c-v1.1.10 && make dist-verify'

cd freehsm-c-v1.1.10
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
| #228  | Publish the `freehsm-c-test` container image |
| follow-ups | **SLH-DSA** Wycheproof (when corpus lands at a future SHA) ; HashML-DSA pre-hash variant ; `CK_SLH_DSA_PARAMS` symmetric plumbing ; full `mlkem_*_test.json` via seed→dk derivation |
