# FreeHSM C — Documentation de tests fonctionnels (CC EAL4+ ATE_FUN.1)

> English version: [`ATE_FUN.md`](ATE_FUN.md). In case of discrepancy, the English version prevails.

**TOE :** FreeHSM Cryptographic Module v1.0.0-FIPS
**Classe CC :** ATE (Tests) — composants ATE_FUN.1 (tests fonctionnels) + ATE_COV.2 (analyse de couverture) + ATE_DPT.1 (testing : conception de base)

---

## 1. Plan de tests

La suite de tests est organisée en quatre couches qui reflètent la décomposition architecturale documentée dans `ARCHITECTURE.fr.md` §3.

| Couche            | Driver                                 | Portée                                                                  |
|-------------------|----------------------------------------|-------------------------------------------------------------------------|
| L1 Smoke          | `tests/test_smoke.c`                   | End-to-end : C_Initialize → POST + KAT → AES-GCM round-trip → tamper → C_Finalize |
| L2 Unitaire       | `tests/test_dispatch.c`                | Par handler : override weak/strong, table triée, gates profil FIPS      |
| L3 KAT / CAVP     | `kat/fhsm_kat_rsp.c` + `kat/cavp/*.rsp`| 83 vecteurs cross-validés sur AES-GCM, SHA-2/3, HMAC, PBKDF2            |
| L4 Intégration    | `tests/test_token_interop.c`           | Interop format-level avec le POC Python                                 |

Un test est considéré comme réussi seulement si **les trois configurations** (debug, release, reproducible) sortent en code 0.

## 2. Carte de couverture (ATE_COV.2)

Le mapping requis est *Security Functional Requirements → TSFI → test*. Voir le tableau équivalent dans `ATE_FUN.md` §2. Chaque SFR revendiquée dans `EAL4_PLUS.fr.md` §4 est exercée par au moins un test driver de la liste.

### 2.1 Métrique de couverture

Cible : **≥ 95 % de couverture lignes** et **≥ 90 % de couverture branches** sur les sous-systèmes pertinents pour la sécurité (`src/` hors `src/gen/`). Collecte via `gcov` + `lcov` :

```bash
make CFLAGS+="-fprofile-arcs -ftest-coverage" \
     LDFLAGS+="-lgcov" \
     tests
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage-html
```

La CI verrouille les merge requests sur le seuil (PR refusé si l'une des métriques descend sous la cible).

## 3. Testing : conception de base (ATE_DPT.1)

Pour chaque sous-système listé dans `ARCHITECTURE.fr.md` §3, on déclare quel test le pilote et quel(s) TSFI il atteint à travers lui.

| Sous-système   | Test pilote                       | TSFI atteint(s)                          |
|----------------|-----------------------------------|------------------------------------------|
| `fhsm_state`   | `tests/test_smoke.c`              | `C_Initialize`, `C_Finalize`             |
| `fhsm_memory`  | `tests/test_dispatch.c` (indirect)| `C_GenerateKey` (alloue DEK dans arène)  |
| `fhsm_crypto`  | `kat/fhsm_kat_vectors.c` + runner | `C_Digest`, `C_Encrypt`, `C_Sign`        |
| `fhsm_audit`   | `tests/test_audit_verify.c` (stub)| implicite sur chaque `C_*`               |
| `fhsm_token`   | smoke `init_token` + `login`      | `C_InitToken`, `C_Login`, `C_SetPIN`     |
| `fhsm_session` | smoke open/close                  | `C_OpenSession`, `C_CloseSession`        |
| `fhsm_pkcs11`  | (chaque test)                     | tous les `C_*`                           |
| `fhsm_integrity`| smoke implicite (au démarrage)   | `C_Initialize` ; `FPT_TST.1`             |
| `src/dispatch/`| `tests/test_dispatch.c`           | chaque dispatch `CKM_*`                  |

## 4. Rapport de test sample

Sortie de `make tests` sur le build de référence Debian 12 / OpenSSL 3.0.13 FIPS (configuration release) :

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
[CAVP] sha2_256_short.rsp               total=9    pass=9    skip=0
... (12 .rsp files total)
==> 83 / 83 vecteurs validés, 0 skipped, pass rate 100%

OVERALL : OK
```

## 5. Gaps de test restants

| Gap                                          | Voie de résolution                              |
|----------------------------------------------|-------------------------------------------------|
| Audit chain verifier `tests/test_audit_verify.c` est un stub | Walker sur `.audit.log` avec recomputation HMAC |
| Test interop token (`tests/test_token_interop.c`) | Token Python consommé en C, égalité byte-pour-byte |
| Tests négatifs args PKCS#11 invalides (`CKR_ARGUMENTS_BAD`) | Harness paramétrique depuis table YAML d'inputs malformés |
| Couverture `fhsm_integrity.c::find_section_offset` (parseur ELF) | ELF crafted avec edge-cases |

Ces gaps sont suivis dans le tracker d'issues avec le label `evaluation/ate-gap`.

## 6. Reproduire la suite de tests

```bash
# Dans l'environnement de build épinglé :
make generate
make
make tests

# Ou end-to-end incluant signature du digest et integrity check :
make all integrity tests
```

Code de sortie attendu : 0. Tout code non-zéro déclenche le chemin d'échec CI et crée une issue `evaluation/ate-fail`.
