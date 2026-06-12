# FreeHSM C — Cible d'évaluation Common Criteria EAL4+

> English version: [`EAL4_PLUS.md`](EAL4_PLUS.md). In case of discrepancy, the English version prevails.

**Nom de la TOE :** FreeHSM Cryptographic Module
**Version :** 1.0.0-FIPS
**EAL cible :** EAL4 augmenté de ALC_FLR.2 (remédiation de défauts) et AVA_VAN.5 (analyse avancée de vulnérabilités)
**Profil de protection revendiqué :** *eIDAS QSCD* (EN 419211-2) ou *cPP for Cryptographic Modules* (NIAP, dès publication)

---

## 1. Description de la TOE (ASE_INT.1)

### 1.1 Type de TOE

La TOE est un module cryptographique logiciel (« Soft HSM ») fournissant des services PKCS#11 v3.2 aux applications. Elle est livrée sous la forme d'un seul objet partagé `libfreehsm-fips.so` plus le fichier de configuration `freehsm.conf`. Elle dépend du provider FIPS d'OpenSSL 3.x, traité comme module évalué séparément dans le même environnement opérationnel.

### 1.2 Fonctions de sécurité majeures

- Authentification multi-rôles (CO + USER) avec wrapping de clé dérivé par PBKDF2
- Throttle exponentiel sur le PIN + verrou permanent
- Chiffrement AES-GCM du token store avec rotation de la DEK au changement de PIN CO
- Log d'audit append-only HMAC-chaîné avec détection d'altération
- Secure heap OpenSSL pour tout matériel SSP (mlock + zéroisation)
- Auto-test pré-opérationnel (KAT) avant exposition d'aucun service
- Scellement optionnel de la DEK sur TPM 2.0, AWS KMS, GCP KMS, HashiCorp Vault, ou quorum (Shamir 3-of-5)

### 1.3 Matériel / firmware / logiciel hors TOE

- Noyau Linux ≥ 5.4 (pour `getrandom`, `memfd_secret`, `prctl`)
- glibc / musl
- Provider FIPS OpenSSL 3.x (évalué séparément, référence du certificat NIST CMVP à compléter)
- TPM 2.0 matériel optionnel (le TPM lui-même est hors TOE ; seule son API est utilisée)

## 2. Revendications de conformité (ASE_CCL.1)

- Version CC : 3.1 révision 5 (avril 2017) — conforme Parts 2 + Part 3
- Augmentation : ALC_FLR.2, AVA_VAN.5
- Conformité stricte au PP cPP-CMOD-v2.0 (dès publication)

## 3. Objectifs de sécurité (ASE_OBJ.2)

### 3.1 Objectifs de sécurité pour la TOE

| Identifiant | Énoncé |
|-------------|--------|
| O.CRYPTO    | La TOE doit fournir des services cryptographiques utilisant uniquement les primitives FIPS-validées chargées depuis le provider FIPS OpenSSL. |
| O.AUTH      | La TOE doit authentifier les opérateurs (CO, USER) avant tout accès au matériel de clé privée. |
| O.AUDIT     | La TOE doit enregistrer les événements pertinents pour la sécurité dans un log append-only résistant à l'insertion, à la suppression et à la modification par un attaquant sans la clé MAC d'audit. |
| O.SSP       | La TOE doit protéger les SSP (DEKs, clés privées, PINs) de la divulgation non autorisée durant l'opération et à la terminaison (zéroisation). |
| O.SELFTEST  | La TOE doit exécuter des auto-tests pré-opérationnels et conditionnels ; en cas d'échec, la TOE doit entrer dans un état ERROR irrécouvrable. |
| O.ROLE_SEP  | La TOE doit imposer la séparation entre rôles CO et USER : seul le CO peut ré-initialiser le token ou déverrouiller un PIN USER ; seul le propriétaire du rôle peut changer son propre PIN. |

### 3.2 Objectifs de sécurité pour l'environnement opérationnel

| Identifiant | Énoncé |
|-------------|--------|
| OE.OS       | L'OS opérationnel doit fournir l'isolation de processus (pas de `ptrace` depuis un autre UID) et la capacité `mlock`. |
| OE.STORAGE  | Le système de fichiers stockant les tokens doit fournir un remplacement atomique (rename + fsync). |
| OE.OPENSSL  | Le provider FIPS OpenSSL doit être installé, validé et en mode approuvé. |
| OE.OP       | Les opérateurs doivent protéger leurs credentials d'authentification (PIN) et ne pas se connecter via un canal non fiable. |
| OE.PHYS     | L'hôte doit être physiquement protégé contre les accès non autorisés (salle serveur ou équivalent). |

## 4. Exigences de sécurité (ASE_REQ.2)

### 4.1 Classe FAU — Audit

- **FAU_GEN.1** (génération de données d'audit) — la TOE génère des entrées d'audit pour les événements listés dans `fhsm_audit_event_t` (cf. `include/fhsm_audit.h`).
- **FAU_GEN.2** (association à l'identité utilisateur) — chaque entrée contient le slot, la session, et le rôle authentifié.
- **FAU_SAA.1** (analyse de violation potentielle) — la TOE détecte 5 échecs d'authentification consécutifs → événement de verrouillage.
- **FAU_STG.1** (stockage protégé du trail d'audit) — le log est HMAC-chaîné ; la clé MAC d'audit est dérivée de la DEK et ne sort jamais de la TOE.

### 4.2 Classe FCS — Support cryptographique

- **FCS_CKM.1** (génération de clé cryptographique) — toutes les clés sont générées par le DRBG du provider FIPS ; les services de génération émettent `FHSM_EV_GENERATE_KEY` / `_KEYPAIR`.
- **FCS_CKM.4** (destruction de clé cryptographique) — tous les SSP sont stockés dans le secure heap et zéroïsés par `OPENSSL_secure_clear_free` lors de `C_DestroyObject`, `C_Logout`, `C_Finalize`, ou verrouillage.
- **FCS_COP.1** (opération cryptographique) — opérations restreintes aux algorithmes listés en §4 de `FIPS_140_3.fr.md`.
- **FCS_RBG_EXT.1** (génération de bits aléatoires) — CTR_DRBG-AES-256 du provider FIPS OpenSSL avec source d'entropie conforme SP 800-90B.

### 4.3 Classe FDP — Protection des données utilisateur

- **FDP_ACC.1** (contrôle d'accès partiel) — la SFP « accès objet » restreint les privilèges SO/USER per §3 de `FIPS_140_3.fr.md`.
- **FDP_ACF.1** (contrôle d'accès basé sur attributs de sécurité) — décisions basées sur `CKA_PRIVATE`, `CKA_SENSITIVE`, `CKA_EXTRACTABLE` et le rôle authentifié.
- **FDP_ITC.2** (import avec attributs de sécurité) — `C_UnwrapKey` positionne `CKA_LOCAL = false` ; les imports passent par le même contrôle d'accès.
- **FDP_RIP.1** (protection des informations résiduelles) — zéroisation du secure heap au free ; les objets détruits via `C_DestroyObject` sont irrécupérables.

### 4.4 Classe FIA — Identification et authentification

- **FIA_UAU.2** (authentification utilisateur avant toute action) — `C_GetTokenInfo` est le seul service public appelable avant `C_Login`.
- **FIA_AFL.1** (gestion des échecs d'authentification) — 5 échecs consécutifs → verrou ; compteur persisté dans le token.
- **FIA_UID.2** (identification utilisateur avant toute action) — le rôle (CO/USER) est identifié au `C_Login` via le flag `CKU_*`.
- **FIA_SOS.1** (vérification des secrets) — PIN ≥ 8 octets ; passé à PBKDF2 avec ≥ 200 000 itérations.

### 4.5 Classe FMT — Gestion de la sécurité

- **FMT_MOF.1** (gestion du comportement des fonctions de sécurité) — seul le CO peut appeler `C_InitToken` et `C_SetPIN` sur le PIN USER.
- **FMT_MTD.1** (gestion des données TSF) — modification d'attributs limitée per la SFP.
- **FMT_SMR.1** (rôles de sécurité) — CO et USER sont les seuls rôles.

### 4.6 Classe FPT — Protection de la TSF

- **FPT_TST.1** (test de la TSF) — auto-tests pré-opérationnels au `C_Initialize`.
- **FPT_FLS.1** (préservation d'un état sécurisé en cas de défaillance) — en cas d'échec d'auto-test, la TOE entre dans l'état ERROR latché.
- **FPT_RCV.1** (recovery manuel de confiance) — la sortie de ERROR exige un redémarrage manuel par l'administrateur.

### 4.7 Classe FTA — Accès à la TOE

- **FTA_SSL.4** (terminaison utilisateur) — `C_Logout` et `C_CloseSession` zéroïsent les secrets de session.

## 5. Conception modulaire (ADV_TDS.3)

| Sous-système     | Fichier(s)                       | TSFI exposé                  |
|------------------|----------------------------------|------------------------------|
| State machine    | `src/fhsm_state.c`               | (interne uniquement)         |
| Secure memory    | `src/fhsm_memory.c`              | (interne uniquement)         |
| Primitives crypto| `src/fhsm_crypto.c` + `kat/`     | (interne uniquement)         |
| Token store      | `src/fhsm_token.c`               | (interne uniquement)         |
| Session table    | `src/fhsm_session.c`             | (interne uniquement)         |
| Audit log        | `src/fhsm_audit.c`               | (interne uniquement)         |
| Façade PKCS#11   | `src/fhsm_pkcs11.c`              | `C_*` (PKCS#11 v3.2 complet) |

La TSFI est exclusivement l'ensemble des symboles `C_*` exportés par `libfreehsm-fips.so`. Tous les autres symboles sont cachés par `-fvisibility=hidden` et le script de version du linker.

## 6. Cycle de vie (ALC_*)

### 6.1 ALC_CMC.4 — Support de production, procédures d'acceptation, automatisation

- Contrôle de version : Git, tags signés uniquement (signing GPG via clé listée dans `docs/keys/dev-pubkeys.gpg`).
- Build : reproductible via `Dockerfile.build` épinglé (Debian 12 + OpenSSL 3.x).
- Acceptation : chaque tag de release déclenche la suite de tests complète + KAT + lint + `cppcheck` + `clang-tidy`.

### 6.2 ALC_FLR.2 — Procédures de signalement de défauts

- Contact sécurité public : `security@freehsm.example` (empreinte de clé PGP à compléter).
- Fenêtre de divulgation coordonnée : 90 jours.
- Politique de backport : chaque branche supportée (courante + N-1) reçoit chaque correctif de sécurité dans les 14 jours suivant la divulgation publique.

### 6.3 ALC_TAT.1 — Outils de développement bien définis

- Compilateur : `gcc ≥ 12.0` ou `clang ≥ 15.0` avec le jeu de flags défini dans `Makefile`.
- Testé sous `valgrind --tool=memcheck`, `valgrind --tool=helgrind`, `ASAN`, `UBSAN`.

## 7. Analyse de vulnérabilités (AVA_VAN.5)

La TOE est conçue pour résister à des attaquants avec potentiel d'attaque **au-dessus du Haut** (Beyond-High), la cible AVA_VAN.5. Preuves :

- **Résistance aux canaux auxiliaires** : compare constant-time des tags/MAC ; mlock du secure heap pour défier l'exfiltration cold-boot ; pas de branchement sur secret dans AES-GCM, HMAC ou PBKDF2 (délégué au provider FIPS OpenSSL, validé séparément).
- **Résistance à l'injection de faute** : chaque résultat d'auto-test est doublement vérifié (compare constant-time) ; l'état ERROR est latché donc une seule faute ne peut pas déverrouiller une opération précédemment rejetée.
- **Attaques logiques** : le log d'audit rend la détection après coup triviale ; le throttle + lockout rend le brute-force en ligne impraticable.
- **Analyse de couverture** : rapport lcov (cible ≥ 95% lignes, 90% branches) attaché à chaque release.

## 8. Livraison (ALC_DEL.1)

La TOE est livrée sous forme d'archive source `.tar.xz` signée (`make dist`) et un package binaire RPM/DEB compilé reproductiblement. Les deux bundles sont signés par la même clé GPG. Les clients vérifient la signature et l'empreinte SHA-256 publiée sur le site du projet via HTTPS.

## 9. Liste des TSF — ajouts v1.1.0

Le rafraîchissement pré-soumission CST ajoute 4 TSF transverses qui complètent la couverture fonctionnelle EAL4+ :

| Identifiant TSF | Famille | Description | Source |
|---|---|---|---|
| **FCS_RBG_EXT.1** | FCS (Support cryptographique) | DRBG durci avec seed multi-source (getrandom + RDRAND + /dev/urandom + jitter TSC), conditionneur SHA-256 selon SP 800-90C, health tests NIST SP 800-90B (RCT, APT, CRNGT), reseed auto 1 MiB ou 1 h. | `src/fhsm_drbg.c`, [`RNG.md`](RNG.md) |
| **FCS_CKM_EXT.4** | FCS | Pair-wise consistency check post `C_GenerateKeyPair` (RSA, EC, ML-KEM, ML-DSA, SLH-DSA). Échec → ERROR latché + refus de persister. Conforme FIPS 140-3 §7.10.2.b. | `src/fhsm_pairwise.c` |
| **FPT_TST_EXT.1** | FPT (Protection des TSF) | Sealing TPM 2.0 de la DEK par token (opt-in via `FHSM_TPM_SEALING=1`). DEK liée aux PCR 0-7 de la chaîne de boot. Mismatch à l'unseal traité comme PIN incorrect (résistance aux oracles). | `src/fhsm_token_tpm.c`, `src/fhsm_tpm.c` |
| **FMT_SMR_EXT.1** | FMT (Gestion sécurité) | Bascule mode runtime entre **legacy** (défaut) et **FIPS strict** via env `FHSM_MODE` ou directive `mode =`. Permet à un binaire unique de satisfaire l'évaluateur FIPS 140-3 ET les opérateurs interop-only. | `src/fhsm_mode.c`, `src/dispatch/fhsm_dispatch_legacy.c` |

### 9.1 Couverture ADV_FSP mise à jour

| Interface externe | TSF couvertes |
|---|---|
| `C_GenerateKeyPair` | FCS_CKM_EXT.4 (pair-wise check) + FCS_CKM.1 existante |
| Tout consommateur de `fhsm_rng_bytes` | FCS_RBG_EXT.1 (RCT + APT + CRNGT) |
| `fhsm_token_init` / `fhsm_token_login` | FPT_TST_EXT.1 (sealing TPM optionnel) |
| Tout appel `C_*` de mécanisme | FMT_SMR_EXT.1 (dispatch mode-dépendant) |
