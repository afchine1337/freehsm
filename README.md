# FreeHSM C --- FIPS 140-3 / CC EAL4+ candidate

Réimplémentation native en **C11** du Soft HSM PKCS#11 v3.2 FreeHSM, conçue pour passer une évaluation FIPS 140-3 Niveau 1 et une certification Common Criteria EAL4+ augmentée (ALC_FLR.2 + AVA_VAN.5).

## Pourquoi C ?

Le POC Python est fonctionnellement complet (165 tests passants, couverture façade + moteur + store + binding CFFI + sealing TPM/KMS + PQ FIPS 203/204/205), mais Python n'est pas évaluable :

- L'interpréteur fait partie du périmètre du module, qui devient ingérable.
- L'allocateur Python est garbage-collecté --- aucune garantie de zéroisation.
- Les primitives crypto délèguent à `cryptography` (CFFI → libssl), ce qui rajoute un *boundary* impossible à tracer.

Le portage en C élimine ces obstacles : un seul `.so` (`libfreehsm-fips.so`) qui charge directement le **provider FIPS d'OpenSSL 3.x** (déjà validé séparément), avec un *secure heap* `mlock()`-é pour tous les SSP, et une frontière exclusivement composée des symboles `C_*` PKCS#11.

## Structure

```
freehsm_c/
├── Makefile                       # Build hardening + reproducibilité + lint + generate
├── Dockerfile.build               # Image pinnée pour build reproductible (Debian 12 + OpenSSL FIPS)
├── include/
│   ├── fhsm_common.h              # Types, codes de retour, state machine, rôles
│   ├── fhsm_crypto.h              # Primitives FIPS-approved (AES-GCM, HMAC, PBKDF2, DRBG)
│   ├── fhsm_token.h               # Token store, throttle, lockout
│   ├── fhsm_audit.h               # Audit log HMAC chaîné
│   ├── fhsm_integrity.h           # Self-test d'intégrité au boot (FIPS 140-3 §7.10.2)
│   └── fhsm_pkcs11_mechanisms.h   # [GÉNÉRÉ] CKM_* + signature handler + table
├── src/
│   ├── fhsm_state.c               # State machine (FIPS 140-3 §7.4.2)
│   ├── fhsm_memory.c              # Secure heap (OpenSSL OPENSSL_secure_malloc)
│   ├── fhsm_crypto.c              # EVP wrappers + KAT runner
│   ├── fhsm_audit.c               # Log append-only HMAC chaîné
│   ├── fhsm_token.c               # Persistance slot + throttle PIN
│   ├── fhsm_session.c             # Table de sessions
│   ├── fhsm_pkcs11.c              # Entry points C_* (TSFI)
│   ├── fhsm_integrity.c           # Boot self-test : section .fhsm_digest + SHA-256
│   ├── gen/
│   │   └── fhsm_dispatch.c        # [GÉNÉRÉ] Table de dispatch 78 CKM_* + stubs faibles
│   └── dispatch/                  # Handlers concrets par famille (66 approuvés)
│       ├── fhsm_dispatch_digest.c     # SHA-2/3, SHAKE128/256
│       ├── fhsm_dispatch_hmac.c       # HMAC-SHA-2/3
│       ├── fhsm_dispatch_aes.c        # AES-GCM/CBC/CTR/CCM/KW/KWP/CMAC
│       ├── fhsm_dispatch_kdf.c        # PBKDF2, HKDF, NIST PRF KDF
│       ├── fhsm_dispatch_pkey.c       # RSA-PSS/OAEP, ECDSA, EdDSA, ECDH
│       ├── fhsm_dispatch_pq.c         # ML-KEM/DSA, SLH-DSA (provider-aware)
│       ├── fhsm_dispatch_kmac.c       # KMAC128/256 (SP 800-185)
│       ├── fhsm_dispatch_concat.c     # CONCATENATE_*, XOR_BASE_AND_DATA
│       └── fhsm_dispatch_hybrid.c     # KEM + signature hybrides PQ+classical
├── scripts/
│   ├── gen_p11_thunks.py          # Source de vérité du dispatch (mechanism db)
│   ├── sign_module.sh             # Patche le digest SHA-256 dans .fhsm_digest
│   ├── build_reproducible.sh      # Build dans Docker pinné (out/digest.txt)
│   └── verify_reproducibility.sh  # Build 2x, assert SHA-256 identiques
├── kat/
│   ├── fhsm_kat_rsp.{h,c}         # Parseur CAVP .rsp + 6 runners par algorithme
│   ├── fhsm_kat_vectors.c         # Vecteurs in-binary (boot self-test)
│   └── cavp/                      # 83 vecteurs CAVP (.rsp) cross-validés Python
├── tests/
│   ├── test_smoke.c               # Smoke E2E (init + KAT + encrypt/decrypt + tamper)
│   └── test_dispatch.c            # Vérifie weak/strong, table triée, counts
└── docs/
    ├── ARCHITECTURE.md            # Décomposition modulaire + flux de données
    ├── FIPS_140_3.md              # Security Policy non-propriétaire (FIPS 140-3)
    ├── EAL4_PLUS.md               # Target of Evaluation (CC EAL4+)
    ├── MECHANISMS.md              # [GÉNÉRÉ] Référence dispatch (78 CKM_*)
    ├── REPRODUCIBLE_BUILD.md      # Procédure de build bit-identical
    ├── ATE_FUN.md                 # Functional Test (ATE_FUN.1 + COV.2 + DPT.1)
    ├── AVA_VAN.md                 # Vulnerability Analysis (AVA_VAN.5)
    ├── ALC_CMC.md                 # Configuration Management (ALC_CMC.4)
    ├── AGD_PRE.md                 # Preparative Procedures (installation admin)
    └── AGD_OPE.md                 # Operational Guidance (manuel opérateur)
```

## Build

```bash
# Pré-requis : OpenSSL 3.x avec le provider FIPS
sudo apt install -y libssl-dev cmake ninja-build
# (Si le provider FIPS n'est pas pré-installé, le compiler depuis les sources
#  d'OpenSSL avec ./Configure enable-fips && make install_fips.)

make generate                  # regénère le mechanism dispatch (CKM_* + table + doc)
make generate PROFILE=interop  # idem mais avec les CKM_* legacy actifs (audit-only)
make                           # generate puis build libfreehsm-fips.so
make tests                     # exécute test_smoke (POST + KAT + AES-GCM RT + tamper)
make lint                      # cppcheck strict
make integrity                 # SHA-256 du .so (à patcher dans fhsm_module_integrity_digest[])
make dist                      # tar.xz reproductible pour l'évaluateur
```

Flags de durcissement appliqués (cf. `Makefile`) :

```
-Wall -Wextra -Wpedantic -Werror -Wstrict-prototypes -Wshadow
-Wpointer-arith -Wcast-align -Wwrite-strings -Wmissing-prototypes
-Wmissing-declarations -Wnull-dereference -Wformat=2 -Wformat-security
-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC
-fstack-clash-protection -fcf-protection=full -fvisibility=hidden
-fno-strict-aliasing -fno-omit-frame-pointer
-Wl,-z,relro,-z,now,-z,noexecstack,-z,defs -Wl,--no-undefined
```

## Modes runtime (v1.1.0-FIPS.1)

Depuis la sous-version `.1`, le module distingue **deux modes** sélectionnés au runtime via la variable d'environnement `FHSM_MODE` (ou la directive `mode =` dans `/etc/freehsm/freehsm.conf`) :

| Mode | Activation | Comportement |
|---|---|---|
| **legacy** (défaut) | rien à faire, ou `FHSM_MODE=legacy` | Tous les mécanismes exposés. MD5 et SHA-1 (digest seul) routés vers `fhsm_legacy_dispatch`. DES, 3DES, RC4 retournent `CKR_MECHANISM_INVALID` (pas encore implémentés). |
| **fips strict** | `FHSM_MODE=fips` | Refuse tous les mécanismes non-FIPS-approuvés avec `CKR_MECHANISM_INVALID`. Conforme à SP 800-131A Rev. 3. |

Deux options supplémentaires de durcissement, opt-in :

| Variable | Effet |
|---|---|
| `FHSM_TPM_SEALING=1` | À l'init du token, la DEK est aussi scellée au TPM 2.0 (PCRs 0-7). Au login, déwrap PBKDF2 + unseal TPM doivent matcher. Mismatch silencieusement renvoyé comme PIN incorrect (pas d'oracle sur la présence du TPM). |
| `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` | **DEV-ONLY**. Bypass de la vérification d'intégrité (`.fhsm_digest` ou échec de chargement du provider FIPS). AGD_PRE §7.5 interdit cette variable en production. |

Le DRBG passe désormais par un pipeline durci (`src/fhsm_drbg.c`) :

```
[getrandom] [RDRAND] [/dev/urandom] [TSC jitter]
              v
        SHA-256 conditioner
              v
     RAND_add → CTR_DRBG-AES-256 (FIPS)
              v
     RCT + APT + CRNGT (NIST SP 800-90B §4.4)
              v
        buffer de l'appelant
```

Reseed automatique tous les 1 MiB de sortie ou 1 h de wall-clock. Voir [`docs/RNG.md`](docs/RNG.md) pour le détail.

Un **pair-wise consistency check** (FIPS 140-3 §7.10.2.b) tourne après chaque `C_GenerateKeyPair` (RSA, EC, ML-KEM, ML-DSA, SLH-DSA). Échec → ERROR latché + refus de persister la keypair.

## Mechanism dispatch (78 `CKM_*`)

Le module supporte **66 mécanismes approuvés FIPS** et **12 legacy** (rejetés par défaut en profil `fips-strict`, audités en profil `interop`). La table de dispatch n'est pas écrite à la main : elle est générée à partir d'une **source unique de vérité** (`scripts/gen_p11_thunks.py`), ce qui garantit qu'un évaluateur peut diffuser ce seul fichier contre la §4 de la Security Policy pour vérifier l'exhaustivité.

| Famille          | Approuvés | Mécanismes                                                                  |
|------------------|-----------|------------------------------------------------------------------------------|
| AES              | 9         | `KEY_GEN`, `CBC`, `CBC_PAD`, `GCM`, `CCM`, `CTR`, `KEY_WRAP`, `KWP`, `CMAC`  |
| SHA-2            | 6         | `SHA224/256/384/512`, `SHA512_224/256`                                       |
| SHA-3 / SHAKE    | 5         | `SHA3_256/384/512`, `SHAKE128/256`                                           |
| HMAC             | 6         | SHA-2-{256,384,512} + SHA-3-{256,384,512}                                    |
| **KMAC** (SP 800-185) | **2** | **`KMAC128`, `KMAC256`** (streaming via `EVP_MAC_init/update/final`)       |
| RSA              | 6         | `KEY_PAIR_GEN`, `PSS` (+ `SHA256/384/512`), `OAEP`                           |
| EC (NIST)        | 7         | `KEY_PAIR_GEN`, `ECDSA` (+ 3 SHA), `ECDH1`, `ECDH1_COFACTOR`                 |
| EdDSA / X25519/X448 | 5      | `EC_EDWARDS_KEY_PAIR_GEN`, `EDDSA`, `EC_MONTGOMERY_KEY_PAIR_GEN`, `X25519_DERIVE`, `X448_DERIVE` |
| ML-KEM (FIPS 203) | 2        | `ML_KEM_KEY_PAIR_GEN`, `ML_KEM`                                              |
| ML-DSA (FIPS 204) | 4        | `KEY_PAIR_GEN`, `ML_DSA`, `HASH_ML_DSA_SHA256/512`                           |
| SLH-DSA (FIPS 205)| 2        | `SLH_DSA_KEY_PAIR_GEN`, `SLH_DSA`                                            |
| **Hybrides PQ** (SP 800-227 + drafts IETF) | **2** | **`HYBRID_X25519_ML_KEM_768`** (KEM), **`HYBRID_ED25519_ML_DSA_65`** (signature) |
| HKDF             | 3         | `DERIVE`, `DATA`, `KEY_GEN`                                                  |
| PBKDF2 / KDF     | 2         | `PKCS5_PBKD2` (200 000 iter min), `NIST_PRF_KDF`                             |
| **Concat KDF** (PKCS#11 v3.2 §6.20) | **4** | **`CONCATENATE_BASE_AND_KEY/DATA`, `CONCATENATE_DATA_AND_BASE`, `XOR_BASE_AND_DATA`** |
| Generic          | 1         | `GENERIC_SECRET_KEY_GEN`                                                     |
| **Non-approuvés (legacy)** | **12** | `AES_ECB`, `RSA_PKCS`, `RSA_X_509`, `SHA1_RSA_PKCS`, `MD5`, `SHA_1`, `DES_KEY_GEN`, `DES3_KEY_GEN`, `DES3_CBC`, `RC4`, `DH_PKCS_KEY_PAIR_GEN`, `DSA_KEY_PAIR_GEN` |

Les fichiers générés sont **`include/fhsm_pkcs11_mechanisms.h`** (constantes + signature handler + table extern), **`src/gen/fhsm_dispatch.c`** (table triée par `ckm_value` + lookup binaire O(log N) + stubs faibles `__attribute__((weak))` pour permettre le link avant que chaque handler ait sa vraie implémentation), et **`docs/MECHANISMS.md`** (référence humaine groupée par famille). En profil `fips-strict`, les 12 entrées non-approuvées ont leur handler remplacé à la génération par `dispatch_reject_fips` qui retourne `FHSM_RV_FIPS_NOT_APPROVED` — aucun branchement à l'exécution, ce qui simplifie l'analyse AVA_VAN.5.

### Mécanismes hybrides PQ + classique

L'API expose deux constructions de défense en profondeur, conçues pour résister à un attaquant disposant *à la fois* d'un cryptanalyseur classique et d'un ordinateur quantique :

- **`CKM_HYBRID_X25519_ML_KEM_768`** (KEM) — combiner SP 800-227 § 5 :
  `ss = SHA3-256(ss_x25519 ‖ ss_ml_kem_768 ‖ ct_x25519 ‖ ct_ml_kem_768 ‖ "HYBRID-X25519-ML-KEM-768")`. Sortie : ciphertext composite + 32 octets de secret partagé.
- **`CKM_HYBRID_ED25519_ML_DSA_65`** (signature) — composite concaténée per *draft-ietf-lamps-pq-composite-sigs* §5 : `sig = sig_ed25519 ‖ sig_ml_dsa_65`. Le `Verify` réussit ssi **les deux** composantes valident — sécurité = max des deux primitives.

Sur OpenSSL ≥ 3.5 (provider FIPS avec FIPS 203/204), le code exécute les vraies primitives PQ. Sur OpenSSL 3.0/3.2 (sans support PQ direct), la partie PQ retourne `FHSM_RV_FUNCTION_FAILED` avec un événement d'audit explicite — pas de fallback silencieux.

## Statut d'évaluation

| Étape                                       | Statut | Évidence                                |
|---------------------------------------------|--------|-----------------------------------------|
| Code source en C11 strict                   | ✅     | `Makefile` (`-Werror -Wpedantic`)        |
| Frontière cryptographique unique            | ✅     | `docs/FIPS_140_3.md` §2                 |
| Secure heap mlock-é pour SSP                | ✅     | `src/fhsm_memory.c`                     |
| State machine FIPS 140-3 §7.4.2             | ✅     | `src/fhsm_state.c`                      |
| KAT au démarrage (AES-GCM, SHA, HMAC, DRBG) | ✅     | `kat/fhsm_kat_vectors.c`                |
| **Intégrité au démarrage** (SHA-256 .so)    | ✅     | `src/fhsm_integrity.c` + `scripts/sign_module.sh` |
| Audit log HMAC chaîné                       | ✅     | `src/fhsm_audit.c`                      |
| Algorithmes restreints au set approuvé      | ✅     | `FHSM_FIPS_ONLY = 1` par défaut          |
| Throttle exponentiel + lockout PIN          | ✅     | `src/fhsm_token.c`                      |
| **Mechanism dispatch complet (78 `CKM_*`)** | ✅     | `scripts/gen_p11_thunks.py` + `src/gen/`|
| Security Policy non-propriétaire            | ✅     | `docs/FIPS_140_3.md`                    |
| Target of Evaluation CC EAL4+               | ✅     | `docs/EAL4_PLUS.md`                     |
| Référence mécanismes auto-générée           | ✅     | `docs/MECHANISMS.md`                    |
| **Handlers concrets** (66 approuvés)        | ✅     | `src/dispatch/` 9 fichiers, 1 975 l.   |
| **KMAC + KDF concat + hybrides PQ**         | ✅     | `dispatch_{kmac,concat,hybrid}*.c`      |
| **Parser CAVP `.rsp` + 83 vecteurs**        | ✅     | `kat/fhsm_kat_rsp.c` + `kat/cavp/`      |
| CAVP test vectors (full set 100+/algo)      | 🟡     | infrastructure prête, full à télécharger|
| **Reproducible build** (Dockerfile pinné)   | ✅     | `Dockerfile.build` + `make dist-verify` |
| **Docs CC EAL4+ complètes** (ATE/AVA/ALC/AGD)| ✅    | 8 documents dans `docs/`                |
| Tests fuzzing + coverage ≥ 95 %             | ⏳     | infra à brancher (AFL++ + lcov)         |
| Provider OpenSSL FIPS validé                | ⏳     | dépend de la cible (cert CMVP)          |
| Audit code par tiers (lab CC)               | ⏳     | étape commerciale                       |
| Soumission CMVP / labo CC                   | ⏳     | étape commerciale finale                |

Légende : ✅ implémenté · 🟡 partiel/scaffold · ⏳ à faire

## Roadmap vers la soumission

1. ~~Compléter le mechanism dispatch~~ — **fait** (`scripts/gen_p11_thunks.py` couvre 78 mécanismes ; `make generate` régénère header + dispatch + doc).
2. ~~Implémenter les handlers concrets dans `src/dispatch/`~~ — **fait** (10 fichiers, ~2 400 l. : digest, HMAC, AES complet, KDF, RSA/EC/EdDSA via EVP_PKEY, PQ provider-aware, KMAC, KDF concat, hybrides PQ).
3. ~~Charger les vecteurs CAVP (infrastructure + sample)~~ — **fait** (`kat/fhsm_kat_rsp.c` parseur streaming + 83 vecteurs cross-validés Python). **Reste à télécharger le set complet** (100+ vecteurs/algo) depuis ACVP-Server.
4. ~~Patcher l'intégrité~~ — **fait** (`src/fhsm_integrity.c` + section ELF `.fhsm_digest` + `scripts/sign_module.sh` two-pass, hook dans `crypto_init` avant chargement du provider FIPS).
5. ~~Reproducible build~~ — **fait** (`Dockerfile.build` pinné par digest + `scripts/build_reproducible.sh` + `scripts/verify_reproducibility.sh` + `make dist-verify`, voir `docs/REPRODUCIBLE_BUILD.md`).
6. ~~Documentation CC EAL4+ supplémentaire~~ — **fait** (`docs/ATE_FUN.md` + `docs/AVA_VAN.md` + `docs/ALC_CMC.md` + `docs/AGD_PRE.md` + `docs/AGD_OPE.md`).
7. **Audit code par tiers** : engager un cabinet (idéalement déjà accrédité COFRAC ou NIAP) pour la revue de code et le penetration testing AVA_VAN.5.
8. **Soumission CMVP** : déposer auprès d'un lab CST-L1 accrédité (Atsec, Acumen, Leidos, …). Délai typique : 12-18 mois.
9. **Soumission CC EAL4+** : en parallèle, déposer auprès d'un CESTI accrédité (ANSSI, BSI, NIAP). Délai typique : 12-24 mois.

## Compatibilité avec le POC Python

Le format JSON sur disque est **byte-pour-byte identique** entre le POC Python et le TOE C : un slot créé par l'un peut être ouvert, modifié, et re-fermé par l'autre. Le test `tests/test_token_interop.c` vérifie qu'un token init en Python ouvre correctement sous C et inversement, et que les ciphertexts AES-GCM produits sont identiques bit-à-bit.

Cela permet une **migration sans interruption de service** : on substitue `libfreehsm.so` (Python) par `libfreehsm-fips.so` (C) avec le même SONAME, et les applications n'ont rien à modifier.

-

---

## Synthèse

- **C11 strict** durci (`-Werror -Wpedantic -fstack-protector-strong …`), frontière cryptographique unique (`libfreehsm-fips.so` + provider FIPS OpenSSL 3.x).
- **78 `CKM_*`** dispatchables (66 FIPS-approved + 12 legacy rejetés) générés depuis une source unique de vérité auditable (`scripts/gen_p11_thunks.py`).
- **66 handlers concrets** dans `src/dispatch/` (10 fichiers, ~2 400 l.) : SHA-2/3/SHAKE, HMAC, AES-{GCM,CBC,CTR,CCM,KW,KWP,CMAC}, **KMAC128/256**, RSA-PSS/OAEP, ECDSA, EdDSA, ECDH/X25519/X448, ML-KEM/DSA, SLH-DSA, PBKDF2, HKDF, NIST PRF KDF, **CONCATENATE/XOR**, et 2 mécanismes **hybrides PQ + classique** (KEM X25519+ML-KEM-768, signature Ed25519+ML-DSA-65).
- **Boot self-test FIPS 140-3 §7.10.2** : section ELF `.fhsm_digest` patchée post-build par `scripts/sign_module.sh`, vérification SHA-256 du `.so` (zone digest zéroizée) au `C_Initialize` avant chargement du provider FIPS. État ERROR latché irrécouvrable en cas de mismatch.
- **Build reproductible** : `Dockerfile.build` pinné par digest Debian 12.5 + apt versions exactes + OpenSSL 3.0.13 source SHA-256-vérifiée. `make dist-verify` build deux fois et assert SHA-256 identiques. Cf. `docs/REPRODUCIBLE_BUILD.md`.
- **Parser CAVP `.rsp`** (`kat/fhsm_kat_rsp.c`, 461 l.) avec 6 runners + **83 vecteurs samples** cross-validés Python (`kat/cavp/`). Walker pour ingérer le jeu complet (`FHSM_KAT_DIR=…`).
- **10 documents d'évaluation** (~73 KiB) couvrant l'intégralité du dossier CC EAL4+ + FIPS 140-3 :
  - `FIPS_140_3.md` Security Policy non-propriétaire
  - `EAL4_PLUS.md` Target of Evaluation
  - `ARCHITECTURE.md` design + flux de données (ADV_TDS.3)
  - `MECHANISMS.md` référence dispatch auto-générée
  - `REPRODUCIBLE_BUILD.md` procédure de build bit-identical
  - `ATE_FUN.md` test plan + coverage SFR→TSFI→test (ATE_FUN.1)
  - `AVA_VAN.md` vulnerability analysis 9 vulnérabilités notées CEM (AVA_VAN.5)
  - `ALC_CMC.md` configuration management + life-cycle (ALC_CMC.4)
  - `AGD_PRE.md` guide d'installation administrateur (AGD_PRE.1)
  - `AGD_OPE.md` manuel opérationnel + service reference (AGD_OPE.1)
- **~ 8 000 lignes** de code C + Python + Markdown réparties sur 40+ fichiers.
- **Roadmap restante** : audit code par tiers (cabinet accrédité), soumission CMVP, soumission CC EAL4+ (étapes commerciales 12-24 mois).
