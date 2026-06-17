# FreeHSM C v1.1.8 --- AES-CMAC, eight-family complete

**Release date** : 2026-06-17
**Maintainer**   : Afchine Madjlessi <afchine.mad@gmail.com>
**GPG signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2`
**Container image** : `ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5`

---

## TL;DR

> **6 364 / 6 364** Wycheproof vectors pass. Zero violations across **eight** PKCS#11 v3.2 families. Second MAC primitive (NIST SP 800-38B AES-CMAC) added cleanly.

```
ecdsa     match= 3098  viol= 0
eddsa     match=  236  viol= 0
rsa_pss   match= 1083  viol= 0
rsa_oaep  match=  788  viol= 0
aes_gcm   match=  310  viol= 0
hmac      match=  522  viol= 0
mlkem     match=   21  viol= 0
aes_cmac  match=  306  viol= 0    <-- new
─────────────────────────────────
TOTAL     match= 6364  viol= 0
```

This release closes **AES-CMAC** (NIST SP 800-38B) --- the block-cipher-based MAC commonly required alongside HMAC for FIPS 140-3 keyed-MAC coverage. FreeHSM C now spans :

- **Signature**         : ECDSA + RSA-PSS + EdDSA
- **Encryption**        : RSA-OAEP + AES-GCM
- **MAC**               : HMAC + AES-CMAC
- **KEM (post-quantum)** : ML-KEM-512 / 768 / 1024

---

## Headline change

### AES-CMAC adapter

`tests/wycheproof/adapters/aes_cmac.py` runs the Wycheproof MAC schema (`mac_test_schema.json`) for AES-128 / 192 / 256 :

1. Imports the AES key as `CKO_SECRET_KEY` + `CKK_AES` + `CKA_VALUE`.
2. `C_SignInit(CKM_AES_CMAC)` + `C_Sign(msg)` --- the module always emits the full 16-byte AES block (per PKCS#11 v3.2 §6.5, MAC truncation is the caller's responsibility).
3. Truncates to the per-group `tagSize` and constant-time compares with the expected tag.

The module's CMAC path was already wired up in v1.1.0 (via `EVP_MAC_fetch("CMAC")`) and exposed as `CKM_AES_CMAC = 0x108C` in `g_mech_list`. No C-side change was needed for this release ; the adapter alone unlocks the 306-vector corpus.

### Harness helpers

* `CKM_AES_CMAC` constant exposed both at the module level and via the attribute-builder DSL (`A.CKM_AES_CMAC`), for symmetry with the other mechanism constants.

---

## Verification

```bash
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.8/freehsm-c-v1.1.8.tar.xz
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.8/freehsm-c-v1.1.8.tar.xz.sha256
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.8/freehsm-c-v1.1.8.tar.xz.asc

gpg --recv-keys 743A6A5904A1461A646408DE48560162DBBF28A2
gpg --verify freehsm-c-v1.1.8.tar.xz.asc freehsm-c-v1.1.8.tar.xz
sha256sum -c freehsm-c-v1.1.8.tar.xz.sha256

docker run --rm -v "$PWD:/src" -w /src \
  ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5 \
  bash -c 'tar xf freehsm-c-v1.1.8.tar.xz && cd freehsm-c-v1.1.8 && make dist-verify'

cd freehsm-c-v1.1.8
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
| follow-ups | **ML-DSA** (FIPS 204), **SLH-DSA** (FIPS 205), AES-GMAC, full `mlkem_*_test.json` (193 × 3) via seed→dk derivation |
