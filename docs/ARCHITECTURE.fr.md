# FreeHSM C — Architecture et décomposition modulaire

> English version: [`ARCHITECTURE.md`](ARCHITECTURE.md). In case of discrepancy, the English version prevails.

## 1. Objectifs

Ce document décrit l'architecture interne de la réimplémentation C de FreeHSM. L'objectif principal est de rendre la frontière cryptographique auditable en isolation, ce qui est requis à la fois par FIPS 140-3 (frontière unique, interfaces bien définies) et par CC EAL4+ (ADV_TDS.3 conception modulaire de base, ADV_FSP.4 spécification fonctionnelle complète).

Le POC Python reste l'**implémentation de référence** pour la conformité comportementale au niveau de l'**API** : la suite C rejoue les mêmes traces PKCS#11. Ce n'est **pas** une référence de format sur disque — le POC utilisait du JSON, ce module utilise un store binaire à champs fixes, et un `.tok` du POC ne s'ouvre pas ici. `docs/TOKEN_STORE_FORMAT.md` fait foi, et le disait déjà pendant que cette ligne revendiquait une identité octet pour octet garantie par un `tests/test_token_interop.c` qui n'a jamais existé.

## 2. Gâteau en couches

```
                          ┌──────────────────┐
   ABI / TSFI ───────────►│  PKCS#11 C_* ABI │
                          │  fhsm_pkcs11.c   │
                          └─────────┬────────┘
                                    │ dispatch fin
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
   ┌──────────┐              ┌────────────┐              ┌──────────┐
   │ Sessions │              │   Tokens   │              │  Crypto  │
   └────┬─────┘              └─────┬──────┘              └────┬─────┘
        │                          │                          │
        ▼                          ▼                          ▼
        ┌───────────────────────────────────────────────────────┐
        │  Transverse : state machine, secure memory, audit log │
        └───────────────────────────────────────────────────────┘
                                    │
                                    ▼
                          ┌──────────────────┐
                          │ Provider FIPS    │
                          │ OpenSSL 3.x      │
                          └──────────────────┘
```

Les flèches sont à sens unique : les couches supérieures dépendent des inférieures, jamais l'inverse.

## 3. Responsabilités par sous-système

| Module              | Responsabilité                                              | TSFI       |
|---------------------|-------------------------------------------------------------|------------|
| `fhsm_state.c`      | Machine à états du module (FIPS 140-3 §7.4.2). Locked pthread. | interne |
| `fhsm_memory.c`     | Wrappers secure heap, `fhsm_zeroize`, `fhsm_ct_memcmp`.     | interne    |
| `fhsm_crypto.c`     | Wrappers EVP_*, runner KAT, chargement provider FIPS.       | interne    |
| `fhsm_audit.c`      | Log append-only HMAC-chaîné.                                | interne    |
| `fhsm_token.c`      | Persistance JSON du token, dérivation PIN, wrap/unwrap DEK, throttle, lockout. | interne |
| `fhsm_session.c`    | Table de sessions bornée, attache slot↔token, suivi de rôle.| interne    |
| `fhsm_pkcs11.c`     | Entry points C_* : valider args, émettre audit, dispatcher. | **TSFI**   |
| `fhsm_integrity.c`  | Auto-test d'intégrité au boot (FIPS 140-3 §7.10.2).         | interne    |
| `kat/fhsm_kat_*.c`  | Vecteurs CAVP et runner.                                    | interne    |

Seul `fhsm_pkcs11.c` exporte des symboles ; tous les autres modules sont liés `static`-ou-`hidden` par le script de version du linker et `-fvisibility=hidden`.

## 4. Table de dispatch des mécanismes

L'ensemble complet des mécanismes PKCS#11 est alimenté par une table code-générée (script `scripts/gen_p11_thunks.py`, sortie `src/gen/fhsm_dispatch.c`).

Le dispatcher vérifie le flag FIPS-only et le rôle de l'opérateur avant d'invoquer le handler. Les mécanismes non approuvés retournent `FHSM_RV_FIPS_NOT_APPROVED` quand `FHSM_FIPS_ONLY = 1`.

## 5. Flux de données pour une opération typique (C_Encrypt)

```
C_Encrypt(session, pData, len, pOut, *pulOutLen)
       │
       │  1. État == INITIALIZED ou AUTHENTICATED ? sinon fail
       │  2. Handle de session valide ? sinon fail
       │  3. Mécanisme dans la liste approuvée ? sinon FIPS_NOT_APPROVED
       │  4. Audit événement « encrypt » (slot, session, role, mech_id, len)
       ▼
fhsm_dispatch_aes_gcm(...)
       │
       │  5. Lookup du handle de clé dans session.objects → fetch CKA_VALUE
       │  6. Le SSP est déjà dans le secure heap (depuis C_GenerateKey)
       ▼
fhsm_aes_gcm_encrypt(key_slice, iv_slice, aad_slice, pt_slice, ct, *len, tag)
       │
       │  7. EVP_CIPHER_CTX_new / EncryptInit / Update / Final / GET_TAG
       │  8. Zéroisation du ctx via EVP_CIPHER_CTX_free
       ▼
return CKR_OK
```

Chaque étape est loguée en ordre chronologique. Les octets sensibles n'apparaissent jamais dans le log.

## 6. Build et reproductibilité

La cible de build reproductible est `make dist`, qui invoque un `Dockerfile.build` épinglé à Debian 12 + OpenSSL 3.2 + le provider FIPS correspondant au cert CMVP #4825 (placeholder jusqu'à l'émission de notre certificat). Voir `REPRODUCIBLE_BUILD.fr.md`.

## 7. Threading

| Lock                    | Portée                                  | Durée de détention   |
|-------------------------|-----------------------------------------|----------------------|
| `g_state_mu` (state.c)  | Process global                          | Microsecondes        |
| `g_audit_mu` (audit.c)  | Process global                          | Une écriture+fsync   |
| `g_sess_mu` (session.c) | Process global                          | Parcours de table    |
| `t->mu` (par token)     | Par slot                                | Login / wrap / unwrap|

Aucun lock n'est détenu en traversant la frontière du provider OpenSSL. Le provider FIPS OpenSSL est lui-même réentrant per sa propre validation.

## 8. Tests et couverture

| Suite               | Driver                                | Portée                                  |
|---------------------|---------------------------------------|-----------------------------------------|
| KAT                 | `kat/fhsm_kat_vectors.c`              | Chaque primitive approuvée à l'init     |
| Smoke               | `tests/test_smoke.c`                  | End-to-end encrypt/decrypt + tamper     |
| Dispatch            | `tests/test_dispatch.c`               | Override weak/strong, table triée       |
| Audit               | `tests/test_audit_verify.c` et six voisins | Vérification de chaîne, rejet d'injection, contre-pression, group commit, multi-processus |
| Interop token       | *(aucun)*                             | **Non construit.** Voir `docs/ATE_FUN.md` §Known gaps — l'interop au niveau des octets avec le POC n'est pas un objectif : les formats diffèrent par choix |
| Fuzzing             | `tests/fuzz/` + AFL++                 | Parseur token, parseur args PKCS#11     |
| Couverture          | `make coverage`                       | Cible gcov/lcov ≥ 95% lignes, 90% branches |

## 9. Migration depuis le POC Python

Le TOE C lit et écrit le **format JSON de token exact** du POC Python. Une organisation en production peut donc :

1. Arrêter le service Python.
2. Remplacer `libfreehsm.so` par `libfreehsm-fips.so` (même SONAME).
3. Démarrer le service C.
4. Tous les slots, toutes les clés, tous les compteurs PIN, toutes les chaînes d'audit sont conservés.

**Rien ne le vérifie, parce que ce n'est pas vrai du format sur disque.** Un test de cette forme était décrit ici et dans `docs/ATE_FUN.md` comme le niveau d'intégration L4 ; il n'a jamais été écrit, et l'écrire échouerait, puisque le store JSON du POC et le store binaire de ce module sont deux formats différents à dessein. Ce qui est partagé, c'est l'API PKCS#11 et le comportement derrière.

## 11. Ajouts couches v1.1.0

Le rafraîchissement pré-soumission CST ajoute 4 modules transverses qui s'insèrent à la même couche architecturale que les primitives crypto mais sont câblés à des étapes différentes du cycle de vie :

### 11.1 DRBG durci (`src/fhsm_drbg.c`)

Wrapper de second tier autour d'OpenSSL CTR_DRBG-AES-256. S'intercale AVANT chaque consommateur de `fhsm_rng_bytes`. Ajoute :
- Agrégation multi-source d'entropie : `getrandom(2)`, RDRAND, `/dev/urandom`, jitter TSC → conditionneur SHA-256 → `RAND_add`.
- Health tests NIST SP 800-90B §4.4 : RCT (cutoff 6), APT (W=512, cutoff 51), CRNGT (bloc 16 octets).
- Reseed automatique tous les 1 MiB de sortie ou toutes les heures.
- Alarme → `fhsm_state_latch_error` → état ERROR.

Cycle de vie : `fhsm_drbg_init` est appelé par `fhsm_crypto_init` APRÈS le chargement du provider FIPS mais AVANT l'exécution des KAT (les KAT peuvent consommer la sortie DRBG).

### 11.2 Pair-wise consistency check (`src/fhsm_pairwise.c`)

Indépendant de la table de dispatch. Appelé inline par `C_GenerateKeyPair` APRÈS le retour de `EVP_PKEY_Q_keygen` et AVANT la sérialisation de la clé sur disque. Routes spécifiques par famille : aller-retour chiffre-déchiffre RSA, sign-verify EC, encap-decap ML-KEM, sign-verify ML-DSA/SLH-DSA. Échec → latch ERROR + refus de persister.

### 11.3 Glue TPM 2.0 sealing (`src/fhsm_token_tpm.c` + `src/fhsm_tpm.c`)

Approche fichier compagnon : `{path}.tpm` à côté de `{path}.tok`. Aucun changement au format binaire `.tok` → compatibilité bidirectionnelle de l'opt-in.

`src/fhsm_tpm.c` invoque la CLI `tpm2` via fork+exec (plutôt que liaison directe libtss2) pour éviter le churn de l'API TSS.

### 11.4 Mode runtime (`src/fhsm_mode.c`)

Lit d'abord `FHSM_MODE` dans l'env, puis la directive `mode =` dans `/etc/freehsm/freehsm.conf`. Résultat mis en cache au premier lookup. Utilisé par `dispatch_reject_fips` (thunk généré) pour choisir entre `FHSM_RV_FIPS_NOT_APPROVED` (strict) et la délégation à `fhsm_legacy_dispatch` (legacy, weak symbol surchargeable via `src/dispatch/fhsm_dispatch_legacy.c`).

### 11.5 Layer cake mise à jour

```
┌────────────────────────────────────────────────┐
│ Façade PKCS#11 v3.2 (fhsm_pkcs11.c)            │
├────────────────────────────────────────────────┤
│ Pair-wise check (fhsm_pairwise.c)              │  ← nouveau .1
│ Mode switch (fhsm_mode.c)                      │  ← nouveau .1
│ Dispatch (gen + handlers par famille)          │
├────────────────────────────────────────────────┤
│ Token store (fhsm_token.c)                     │
│ Glue TPM (fhsm_token_tpm.c)                    │  ← nouveau .1
├────────────────────────────────────────────────┤
│ Primitives crypto (fhsm_crypto.c)              │
│ DRBG durci (fhsm_drbg.c)                       │  ← nouveau .1
│ Wrapper CLI TPM (fhsm_tpm.c)                   │  ← nouveau .1
├────────────────────────────────────────────────┤
│ Audit log + intégrité + machine à états        │
├────────────────────────────────────────────────┤
│ Provider FIPS OpenSSL 3.5.x                    │
└────────────────────────────────────────────────┘
```
