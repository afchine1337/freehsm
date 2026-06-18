# FreeHSM C v1.1.12 --- SLH-DSA context plumbing

**Release date** : 2026-06-18
**Maintainer**   : Afchine Madjlessi <afchine.mad@gmail.com>
**GPG signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2`
**Container image** : `ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5`

---

## TL;DR

> Closes the symmetric `CK_SLH_DSA_PARAMS.pContext` plumbing (PKCS#11 v3.2 §6.19 / FIPS 205 §5.2.1) on top of the ML-DSA context shipped in v1.1.10. No Wycheproof regression (still 6 978 / 0 across 9 families). No external SLH-DSA corpus to validate against yet, but the wire is ready : the next time someone writes an `slhdsa.py` adapter or a FIPS 205 test harness, the context-string code path is already there.

```
TOTAL     match= 6978  viol= 0    (unchanged from v1.1.11)
```

---

## Headline changes

### `fhsm_op_t` field rename : `mldsa_ctx*` → `pq_ctx*`

The same 256-byte static buffer carries both the FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) context strings :

- Both `CK_ML_DSA_PARAMS` (PKCS#11 v3.2 §6.18) and `CK_SLH_DSA_PARAMS` (PKCS#11 v3.2 §6.19) are 24 bytes on a 64-bit ABI with identical layout : `{ CK_ULONG hedgeVariant; CK_BYTE_PTR pContext; CK_ULONG ulContextLen }`.
- Both specs cap the context at 255 bytes (FIPS 204 §5.2.1 / FIPS 205 §5.2.1).
- Both use the same OpenSSL provider param (`OSSL_SIGNATURE_PARAM_CONTEXT_STRING`).

Renaming the field surfaces the shared semantics in the operation slot. No change in storage size or layout.

### `op_init` parser extended

The gate that decodes the parameter triple now triggers on either `CKM_ML_DSA_OP` (`0x403F`) or `CKM_SLH_DSA_OP` (`0x4041`). The parsing logic itself is identical to v1.1.10 (read `p[2]` as `ulContextLen`, copy from `p[1]` interpreted as a pointer, reject lengths over 255), so the existing ML-DSA test coverage carries over.

### `C_Sign` and `C_Verify` post-quantum branch

The `EVP_PKEY_CTX_set_params(OSSL_SIGNATURE_PARAM_CONTEXT_STRING)` gate now fires for both ML-DSA and SLH-DSA mechanisms. EdDSA stays on the empty-context default --- it has no comparable PKCS#11 parameter struct.

`hedgeVariant` is read but unused. OpenSSL's default policy (hedged when entropy is available) matches `CKH_HEDGE_PREFERRED` for both ML-DSA and SLH-DSA. The deterministic case (`CKH_DETERMINISTIC_REQUIRED`) is tracked as a follow-up for v1.2.0.

### Why ship this now ?

1. **Symmetry** : the ML-DSA path was an outlier. Same context concept exists for SLH-DSA ; implementing it in one refactor instead of duplicating later cuts code volume and review surface.
2. **Build-time safety** : the rename is touched, compiled clean (`-Werror -Wpedantic -Wconversion`), and validated against the **full 6 978-vector Wycheproof sweep** **now**, before any new adapter is added. ML-DSA's 614 / 0 / 15 score is bit-identical to v1.1.10 / v1.1.11, proving the rename is bijective.
3. **Security Target language** : we can now state "the PKCS#11 v3.2 §6.18 and §6.19 context parameters are honoured on both sign and verify for the FIPS 204 and FIPS 205 schemes respectively", a stronger statement for the Security Target.

---

## Verification

```bash
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.12/freehsm-c-v1.1.12.tar.xz
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.12/freehsm-c-v1.1.12.tar.xz.sha256
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.12/freehsm-c-v1.1.12.tar.xz.asc

gpg --recv-keys 743A6A5904A1461A646408DE48560162DBBF28A2
gpg --verify freehsm-c-v1.1.12.tar.xz.asc freehsm-c-v1.1.12.tar.xz
sha256sum -c freehsm-c-v1.1.12.tar.xz.sha256

docker run --rm -v "$PWD:/src" -w /src \
  ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5 \
  bash -c 'tar xf freehsm-c-v1.1.12.tar.xz && cd freehsm-c-v1.1.12 && make dist-verify'

cd freehsm-c-v1.1.12
tests/wycheproof/fetch_vectors.sh
tests/wycheproof/run_wycheproof.py --module ./libfreehsm-fips.so
```

---

## Open follow-ups (tracked for v1.2.0)

| ID    | Description |
|-------|---|
| #190  | Extend CAVP smoke vectors to the full published NIST sets |
| #191  | Structured fuzzing (`libFuzzer` / AFL++) |
| follow-ups | **SLH-DSA Wycheproof adapter** (when corpus lands at a future SHA) ; `hedgeVariant` -> `OSSL_SIGNATURE_PARAM_DETERMINISTIC` mapping ; HashML-DSA pre-hash variant ; full `mlkem_*_test.json` via seed→dk derivation |
