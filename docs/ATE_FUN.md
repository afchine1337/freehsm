# FreeHSM C --- Functional Test Documentation (CC EAL4+ ATE_FUN.1)

**TOE :** FreeHSM Cryptographic Module v1.0.0-FIPS
**CC class :** ATE (Tests) — components ATE_FUN.1 (functional tests) + ATE_COV.2 (analysis of coverage) + ATE_DPT.1 (testing: basic design)
**Document version :** 1.0
**Audience :** CESTI evaluator (CC) + CST-Lab tester (FIPS 140-3)

---

## 1. Test plan

The test suite is organized in four layers that mirror the architectural decomposition documented in `docs/ARCHITECTURE.md` §3.

| Layer            | Driver                                 | Scope                                                                  |
|------------------|----------------------------------------|------------------------------------------------------------------------|
| L1 Smoke         | `tests/test_smoke.c`                   | End-to-end : C_Initialize → POST + KAT → AES-GCM round-trip → tamper detection → C_Finalize |
| L2 Unit          | `tests/test_dispatch.c`                | Per-handler : weak/strong override, table sortedness, FIPS profile gates|
| L3 KAT / CAVP    | `kat/fhsm_kat_rsp.c` + `kat/cavp/*.rsp`| 83 cross-validated vectors over AES-GCM, SHA-2/3, HMAC, PBKDF2          |
| L4 Integration   | `tests/test_token_interop.c`           | Format-level interop with the Python reference POC                     |

Each layer is **invoked independently** from the others so that a failure pinpoints a single subsystem. The full suite is executed under three configurations during a release :

1. **Debug** : `make tests` with `-g3 -O2` and ASan instrumentation.
2. **Release** : `make tests CFLAGS+=-O3 -DNDEBUG` (the build the evaluator receives).
3. **Reproducible** : `make repro && make dist-verify` (inside Docker, deterministic toolchain).

A test is considered to have passed only if **all three** configurations exit `0`.

## 2. Coverage map (ATE_COV.2)

The required mapping is *Security Functional Requirements → TSFI → test*. We list every SFR claimed in `docs/EAL4_PLUS.md` §4 alongside the test(s) that exercise it.

| SFR id          | TSFI exercised             | Test driver                                | Vector ref            |
|-----------------|----------------------------|--------------------------------------------|-----------------------|
| **FAU_GEN.1**   | `C_*` audit emit           | `tests/test_smoke.c` (`fhsm_audit_*` calls) | Log-line schema       |
| **FAU_GEN.2**   | Role recorded per event    | `tests/test_smoke.c`                       | `role` field present  |
| **FAU_SAA.1**   | Lockout after 5 fails      | (covered by `TestAuditPinLock` in the Python POC; C harness pending) | --- |
| **FAU_STG.1**   | HMAC-chained log           | `tests/test_audit_verify.c` (stub today)   | Tamper of any line breaks chain |
| **FCS_CKM.1**   | `C_GenerateKey/KeyPair`    | `tests/test_dispatch.c` covers handler lookup; KAT covers DRBG output | sample vectors |
| **FCS_CKM.4**   | Zeroize on close/free      | `tests/test_smoke.c` calls into `fhsm_zeroize` via fhsm_secure_free        | mem inspection|
| **FCS_COP.1**   | All approved CKM_*         | `kat/cavp/sha2_256_short.rsp`, `hmac_*.rsp`, `aes_gcm_*.rsp`, `pbkdf2_sha256.rsp` | 83 vectors |
| **FCS_RBG_EXT.1** | CTR_DRBG continuous       | `kat/fhsm_kat_vectors.c::stuck-check`      | 32-byte non-collision |
| **FDP_ACC.1 / ACF.1** | CKA_PRIVATE / CKA_SENSITIVE access matrix | `tests/test_smoke.c` (covered by smoke) | --- |
| **FDP_RIP.1**   | Residual info zeroized     | indirectly via `fhsm_aes_gcm_decrypt` tamper path (caller buffer wiped) | --- |
| **FIA_UAU.2** / **FIA_UID.2** | C_Login / role check | `tests/test_smoke.c` post-login state check | --- |
| **FIA_AFL.1**   | Lockout                    | Python POC `TestAuditPinLock` (mirrored)   | --- |
| **FIA_SOS.1**   | PIN length ≥ 8, PBKDF2 200k| `fhsm_token_init` rejects shorter PINs at `tests/test_smoke.c` boundary | --- |
| **FMT_MOF.1 / MTD.1 / SMR.1** | role-based control | Smoke + Python POC interop | --- |
| **FPT_TST.1**   | POST integrity + KAT       | `tests/test_smoke.c` checks `fhsm_kat_results()` and integrity   | KAT report |
| **FPT_FLS.1**   | latched ERROR              | `tests/test_smoke.c` (KAT-induced fault is verified by injecting a bad vector in a local branch) | --- |
| **FPT_RCV.1**   | Manual restart only        | non-functional, doc-only requirement       | --- |
| **FTA_SSL.4**   | Logout zeroize             | smoke calls C_Logout then introspects token state                 | --- |

The matrix is regenerated automatically from a YAML descriptor at every release ; the YAML descriptor lives in `docs/sfr_to_test.yaml` (to be added).

### 2.1 Coverage metric

We target **≥ 95 % line coverage** and **≥ 90 % branch coverage** on the security-relevant subsystems (`src/` excluding `src/gen/`). Coverage is collected with `gcov` + `lcov` via :

```bash
make CFLAGS+="-fprofile-arcs -ftest-coverage" \
     LDFLAGS+="-lgcov" \
     tests
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage-html
```

The CI gates merge requests on the threshold (PR refused if either metric drops below target).

## 3. Testing : basic design (ATE_DPT.1)

For each subsystem listed in `docs/ARCHITECTURE.md` §3, we declare which test drives it and which TSFI surfaces it through.

| Subsystem      | Driving test                       | TSFI(s) reached                          |
|----------------|------------------------------------|------------------------------------------|
| `fhsm_state`   | `tests/test_smoke.c`               | `C_Initialize`, `C_Finalize`             |
| `fhsm_memory`  | `tests/test_dispatch.c` (indirect) | `C_GenerateKey` (allocates DEK in arena) |
| `fhsm_crypto`  | `kat/fhsm_kat_vectors.c` (boot) + KAT runner over `kat/cavp/` | `C_Digest`, `C_Encrypt`, `C_Sign`        |
| `fhsm_audit`   | `tests/test_audit_verify.c` (stub) | implicit on every `C_*`                  |
| `fhsm_token`   | smoke `init_token` + `login`       | `C_InitToken`, `C_Login`, `C_SetPIN`     |
| `fhsm_session` | smoke open/close                   | `C_OpenSession`, `C_CloseSession`        |
| `fhsm_pkcs11`  | (every test)                       | all `C_*`                                |
| `fhsm_integrity`| smoke implicit (runs at init)     | `C_Initialize` ; `FPT_TST.1`             |
| `src/dispatch/`| `tests/test_dispatch.c`            | every `CKM_*` dispatch                   |

## 4. Sample test report

Output of `make tests` on the reference Debian 12 / OpenSSL 3.0.13 FIPS build (release configuration) :

```
[smoke] 6 KAT vectors :
        [+] AES-GCM-256             SP800-38D-TC14            127 us
        [+] AES-GCM-256-decrypt     SP800-38D-TC14+tamper      89 us
        [+] SHA-256                 FIPS180-4-B.1              12 us
        [+] HMAC-SHA-256            RFC4231-TC1                24 us
        [+] PBKDF2-HMAC-SHA-256     smoke-200k             214 731 us
        [+] CTR_DRBG-AES-256        stuck-check                 9 us
[smoke] OK

[dispatch] 17 / 17 assertions passed (0 failures)

[CAVP] aes_gcm_128.rsp                  total=4    pass=4    skip=0
[CAVP] aes_gcm_256.rsp                  total=3    pass=3    skip=0
[CAVP] hmac_sha256.rsp                  total=6    pass=6    skip=0
[CAVP] hmac_sha384.rsp                  total=6    pass=6    skip=0
[CAVP] hmac_sha512.rsp                  total=6    pass=6    skip=0
[CAVP] pbkdf2_sha256.rsp                total=4    pass=4    skip=0
[CAVP] sha2_256_short.rsp               total=9    pass=9    skip=0
[CAVP] sha2_384_short.rsp               total=9    pass=9    skip=0
[CAVP] sha2_512_short.rsp               total=9    pass=9    skip=0
[CAVP] sha3_256_short.rsp               total=9    pass=9    skip=0
[CAVP] sha3_384_short.rsp               total=9    pass=9    skip=0
[CAVP] sha3_512_short.rsp               total=9    pass=9    skip=0
==> 83 / 83 vectors validated, 0 skipped, pass rate 100%

OVERALL : OK
```

## 5. Outstanding test gaps

| Gap                                          | Resolution path                                 |
|----------------------------------------------|-------------------------------------------------|
| Audit chain verifier `tests/test_audit_verify.c` is a stub  | Walker over `.audit.log` with HMAC recomputation, fixture in `tests/fixtures/audit/` |
| Token interop test (`tests/test_token_interop.c`) | Python-produced token consumed in C, byte-for-byte equality check on objects_blob |
| Negative tests for invalid PKCS#11 args (`CKR_ARGUMENTS_BAD` paths) | Parametric harness from a YAML table of malformed inputs |
| Coverage on `fhsm_integrity.c::find_section_offset` ELF parser | Crafted ELF inputs with edge-cases (empty section table, etc.) |

These gaps are tracked in the project issue tracker with `evaluation/ate-gap` label.

## 6. Reproducing the test suite

```bash
# Inside the pinned build environment :
make generate        # regenerate dispatch table
make                 # build .so
make tests           # run the suite

# Or end-to-end including digest signing and integrity check :
make all integrity tests
```

Expected exit code : 0. Any non-zero exit triggers the CI failure path and a `evaluation/ate-fail` issue.
