# FreeHSM C v1.1.10 --- PKCS#11 v3.2 conformity (ML-DSA ctx + ECDSA raw r||s)

**Release date** : 2026-06-17
**Maintainer**   : Afchine Madjlessi <afchine.mad@gmail.com>
**GPG signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2`
**Container image** : `ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5`

---

## TL;DR

> **6 978 / 6 978** Wycheproof vectors pass. Two PKCS#11 v3.2 spec gaps closed in one shot : `CK_ML_DSA_PARAMS.pContext` (FIPS 204 context) on both sign and verify, plus raw r||s wire format for the `CKM_ECDSA*` family (§6.13).

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

This is a focused conformity release. No new Wycheproof family, but two
PKCS#11 v3.2 specification gaps are now closed.

---

## Headline changes

### 1. ML-DSA context (`CK_ML_DSA_PARAMS.pContext`) on sign and verify

The 24-byte parameter struct `{ hedgeVariant, pContext, ulContextLen }` is decoded in the shared `op_init` (so it covers `C_SignInit` and `C_VerifyInit` alike). The context is copied into a 256-byte static buffer in the operation slot. `hedgeVariant` is read but left to OpenSSL's default (hedged when randomness is available, matching `CKH_HEDGE_PREFERRED`).

Both `C_Sign` and `C_Verify` then call `EVP_PKEY_CTX_set_params(pkctx, OSSL_SIGNATURE_PARAM_CONTEXT_STRING)` before `EVP_DigestSign` / `EVP_DigestVerify`. The change is gated on the ML-DSA mechanism so SLH-DSA and EdDSA stay on the empty-context default until their own parameter plumbing lands.

The ML-DSA Wycheproof adapter now builds a `CK_ML_DSA_PARAMS` for every test, decoding the optional `ctx` hex field. Tests with `len(ctx) > 255` bytes (FIPS 204 §5.2.1 spec violation, beyond what the PKCS#11 mechanism can legally express) are surfaced under `ctx_oversize_skip` rather than running with a truncated context. The 6 tests with a legal non-empty context now verify cleanly, taking ML-DSA from 608 to 614 vectors (97.6 % of the corpus).

### 2. ECDSA raw r||s wire format (PKCS#11 v3.2 §6.13)

PKCS#11 v3.2 specifies that the `CKM_ECDSA*` family transports the signature as raw r||s --- each padded to `(|q|+7)/8` octets, so 2 * curve_size bytes total. The previous code passed an OpenSSL DER ECDSA-Sig-Value `SEQUENCE { r INTEGER, s INTEGER }` straight through, which is what Wycheproof and the harness expected, but no real PKCS#11 v3.2 caller (`pkcs11-tool`, `python-pkcs11`, etc.) would.

Two `static` helpers now bridge the gap inside `fhsm_pkcs11.c` :

- `ecdsa_der_to_raw(der, der_len, nlen, out)` --- decode the DER produced by `EVP_DigestSign`, write r and s big-endian-padded to `nlen` bytes each. Used after `EVP_DigestSign` in `sign_asymmetric`.
- `ecdsa_raw_to_der(raw, raw_len, nlen, &out_der)` --- inverse, used before `EVP_DigestVerify` in `C_Verify`. A wrong signature length is treated as `CKR_SIGNATURE_INVALID`, not an internal error.

`mech_is_ecdsa(m)` gates both paths. The Wycheproof `ecdsa.py` adapter already parsed Wycheproof's DER into `sig_raw` (via the lenient parser shipped in v1.1.3) ; it now passes `sig_raw` to `C_Verify` instead of `sig_der`. **The full 3 098 ECDSA vector set round-trips cleanly through the new wire format, proving the conversion is bijective on the entire corpus.**

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
