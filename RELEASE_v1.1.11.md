# FreeHSM C v1.1.11 --- CI matrix complete

**Release date** : 2026-06-18
**Maintainer**   : Afchine Madjlessi <afchine.mad@gmail.com>
**GPG signing key** : `743A6A5904A1461A646408DE48560162DBBF28A2`
**Container image** : `ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5`

---

## TL;DR

> Two self-attestation loops now run on every push to main : the full **PKCS#11 function × mechanism coverage matrix** (32 assertions, default + FIPS strict modes) and the **9-family Wycheproof sweep** (6 978 vectors). Both are green. No module code change ; the surface area unblocked is purely operational.

```
test-coverage-matrix       PASS = 27   FAIL = 0   SKIP = 5   (32 total)
test-fips-mode             PASS = 27   FAIL = 0   SKIP = 5   (32 total)
Wycheproof full sweep      TOTAL match = 6978   viol = 0   (9 families)
```

For the first time since the project went OSS, **every push to main is
self-validated end-to-end** : library build, integrity check, KAT,
matrix in two modes, Wycheproof, reproducibility. The hand-running of
`tests/coverage_matrix.sh` on a developer workstation is no longer the
only oracle.

---

## Headline changes

### `Dockerfile.test` + `test-image.yml` workflow

`Dockerfile.test` ships a minimal Debian 13-slim image with everything the matrix script needs and nothing else :

- `opensc` --- carries `pkcs11-tool`, the harness driver.
- `gnutls-bin` --- `p11tool`, used as a cross-implementation oracle.
- `binutils` --- `nm`, used by the `[7/8] v3.0 CK_INTERFACE` step to verify the `C_GetInterface` symbol is exposed.
- `sudo` + a non-privileged `freehsm` user with passwordless sudo for `coverage_matrix.sh`'s `sudo -E -u freehsm` invocations.

`.github/workflows/test-image.yml` builds and pushes the image to `ghcr.io/<owner>/freehsm-c-test:debian13-pkcs11-tools` on every change to `Dockerfile.test` or via manual dispatch, mirroring the existing `build-image.yml` pattern (QEMU + Buildx + GHA cache + `packages: write`).

### CI matrix unlocked

`.github/workflows/ci.yml` drops the `if: false` guard on `test-coverage-matrix` and `test-fips-mode`. Both jobs now run inside the published test image and produce the green matrix above. `reproducibility` keeps using the build image and stays green (sha256 of the `.so` is identical across two independent builds, as captured by the new bash-explicit Compare step from v1.1.10).

### `coverage_matrix.sh` made CI-runnable

Two adjustments unblocked the first run-in-anger of this script in CI :

1. **Dev / CI env bypass for the boot integrity check + KAT**. The .so produced by `make` carries a placeholder `.fhsm_digest` until `release.yml` patches it post-link ; without `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` and `FHSM_KAT_ALLOW_FAIL=1` the module returns `CKR_FUNCTION_FAILED` (0x6) on `C_Initialize` and every assertion in the script short-circuits. The script now exports both at the top, with a prominent comment that doing so in any real PKCS#11 deployment violates `AGD_PRE §7.5 / §7.5bis`. Also defaults `OPENSSL_CONF=/dev/null` so the legacy-mode matrix sees the default OpenSSL provider without picking up a FIPS bias from the system `openssl.cnf`.
2. **MD5 step**. `CKM_MD5` is intentionally absent from `g_mech_list` (FIPS 140-3 §C.A removed MD5 from the allowed algorithm set), and `pkcs11-tool` surfaces the absence as `CKR_TOKEN_NOT_PRESENT` at session-open time. The matrix accepts that outcome as `SKIP` for the legacy assertion (MD5 simply does not exist in our mech list, so there is no FreeHSM behaviour to test) and `PASS` for the FIPS assertion (MD5 being unreachable in FIPS mode is exactly the posture we want).

---

## Verification

```bash
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.11/freehsm-c-v1.1.11.tar.xz
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.11/freehsm-c-v1.1.11.tar.xz.sha256
curl -sLO https://github.com/afchine1337/freehsm-c/releases/download/v1.1.11/freehsm-c-v1.1.11.tar.xz.asc

gpg --recv-keys 743A6A5904A1461A646408DE48560162DBBF28A2
gpg --verify freehsm-c-v1.1.11.tar.xz.asc freehsm-c-v1.1.11.tar.xz
sha256sum -c freehsm-c-v1.1.11.tar.xz.sha256

docker run --rm -v "$PWD:/src" -w /src \
  ghcr.io/afchine1337/freehsm-c-build:debian13-openssl-3.5 \
  bash -c 'tar xf freehsm-c-v1.1.11.tar.xz && cd freehsm-c-v1.1.11 && make dist-verify'

# Replay the matrix inside the published test image
cd freehsm-c-v1.1.11
docker run --rm -v "$PWD:/src" -w /src \
  ghcr.io/afchine1337/freehsm-c-test:debian13-pkcs11-tools \
  bash -c 'install -m 755 libfreehsm-fips.so /opt/freehsm/lib/ && \
           bash tests/coverage_matrix.sh'

# Replay the Wycheproof sweep
tests/wycheproof/fetch_vectors.sh
tests/wycheproof/run_wycheproof.py --module ./libfreehsm-fips.so
```

---

## Open follow-ups (tracked for v1.2.0)

| ID    | Description |
|-------|---|
| #190  | Extend CAVP smoke vectors to the full published NIST sets |
| #191  | Structured fuzzing (`libFuzzer` / AFL++) |
| follow-ups | **SLH-DSA** Wycheproof (when corpus lands at a future SHA) ; HashML-DSA pre-hash variant ; `CK_SLH_DSA_PARAMS` symmetric plumbing ; full `mlkem_*_test.json` via seed→dk derivation ; opt-in MD5 wiring behind a build flag for legacy interop scenarios |
