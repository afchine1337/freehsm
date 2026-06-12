# FreeHSM C — Documentation de gestion de configuration (CC EAL4+ ALC_CMC.4)

> English version: [`ALC_CMC.md`](ALC_CMC.md). In case of discrepancy, the English version prevails.

**TOE :** FreeHSM Cryptographic Module v1.0.0-FIPS
**Classe CC :** ALC (Support du cycle de vie) — composants ALC_CMC.4 (support production, procédures d'acceptation, automatisation), ALC_CMS.4 (couverture CM de tracking de problèmes), ALC_DEL.1 (procédures de livraison), ALC_FLR.2 (remédiation de défauts), ALC_LCD.1 (modèle de cycle de vie défini par développeur), ALC_TAT.1 (outils de développement bien définis)

---

## 1. Portée CM (ALC_CMS.4)

Items sous gestion :

| Catégorie                       | Item(s)                                                  | Stockage          |
|---------------------------------|----------------------------------------------------------|-------------------|
| Code source                     | `include/`, `src/`, `src/dispatch/`, `src/gen/`, `kat/`, `tests/` | Mono-repo Git |
| Infrastructure de build         | `Makefile`, `Dockerfile.build`, `scripts/*.sh`           | Mono-repo Git     |
| Générateur source-of-truth      | `scripts/gen_p11_thunks.py`                              | Mono-repo Git     |
| Vecteurs de test                | `kat/cavp/*.rsp`, `kat/fhsm_kat_vectors.c`               | Mono-repo Git     |
| Documentation                   | `docs/*.md`                                              | Mono-repo Git     |
| Artefacts de build (releases)   | `libfreehsm-fips.so`, `freehsm-c-src.tar.xz`, `*.sha256` | Serveur de release signé |
| Evidence d'évaluation           | `docs/{ATE_FUN,AVA_VAN,ALC_CMC,FIPS_140_3,EAL4_PLUS,ARCHITECTURE,MECHANISMS,REPRODUCIBLE_BUILD,AGD_PRE,AGD_OPE}.md` | Mono-repo Git |
| Issue tracker                   | label-managed `evaluation/*`                             | Forge issue tracker |
| Avis de sécurité                | `SECURITY.md` + numéros CVE                              | Mono-repo + MITRE |

Tout item vit en contrôle de version. Rien de pertinent pour l'identité TOE n'est stocké hors mono-repo Git ; le SHA-1 de `HEAD` après une release identifie uniquement l'état CM.

## 2. Capacités CM (ALC_CMC.4)

### 2.1 Identification

L'identité TOE est le triple :
```
(repo, commit_sha, tag)
```
où `tag` suit semantic versioning `vMAJOR.MINOR.PATCH` et correspond à `FHSM_VERSION_STRING` dans `include/fhsm_common.h`.

### 2.2 Contrôles d'autorisation

| Action | Rôle requis | Enforcement |
|--------|-------------|-------------|
| Push sur `main`          | Mainteneur | Branch protection : signed-commit-only ; PR review par ≥ 2 mainteneurs ; CI vert |
| Tag release              | Release Manager | Tag doit être GPG-signé par la clé de release |
| Publier le bundle release| Release Manager | Règle deux-personnes : RM signe le tar, second mainteneur signe le manifeste de digest |
| Modifier les pins apt `Dockerfile.build` | Build Engineer | Exige passage `dist-verify` CI + relance ATE manuelle |
| Modifier un vecteur CAVP | Crypto Engineer | Exige script de cross-validation `scripts/validate_cavp.py` |

### 2.3 Automatisation

Le CM est entièrement automatisé. Chaque push déclenche :

1. `make generate` — rafraîchir les artefacts code-générés.
2. `make lint` — cppcheck + clang-tidy.
3. `make` — build complet dans l'image Docker épinglée.
4. `make tests` — smoke + dispatch + runner CAVP.
5. `make dist-verify` — second build, assertion d'égalité byte.
6. `make integrity` — signer le `.so` ; vérifier le digest embarqué.
7. `scripts/coverage.sh` — gcov + lcov ; fail si couverture lignes < 95 % ou branches < 90 %.

Un tag release déclenche en plus :

8. `make dist` — produire l'archive source signée.
9. Upload sur serveur de distribution via `scripts/release.sh` (uploads `.so`, `.so.sha256`, `.tar.xz`, `.tar.xz.sha256`, tous GPG-signés).
10. Notification de la mailing list de sécurité.

## 3. Support production (ALC_CMC.4)

### 3.1 Environnement de build

Single source of truth = `Dockerfile.build`. Le reviewer est référé à `REPRODUCIBLE_BUILD.fr.md` pour la chaîne complète.

### 3.2 Procédures d'acceptation

Un `libfreehsm-fips.so` produit est **accepté dans le set d'artefacts release** uniquement si **toutes** les conditions sont vraies :

1. `make all integrity tests dist-verify` sort 0 dans l'image Docker épinglée.
2. Le `fhsm_module_integrity_digest[]` embarqué correspond au SHA-256 calculé externement.
3. `readelf -p .comment libfreehsm-fips.so` rapporte la version de toolchain attendue.
4. `pwntools.checksec` rapporte : `RELRO=Full`, `NX=Yes`, `PIE=Yes`, `Canary=Yes`.
5. Seuils de couverture atteints (§2.3 étape 7).
6. Déclencheurs ré-analyse AVA_VAN (`AVA_VAN.fr.md` §6) clairs OU un AVA_VAN mis à jour est inclus dans la release.

## 4. Modèle de cycle de vie (ALC_LCD.1)

```
       exigence    →   conception →   implémentation →   intégration →   release
            ↑                                                      |
            └─────── remédiation de défauts (ALC_FLR.2) ←──────────┘
```

## 5. Outils (ALC_TAT.1)

| Outil                 | Version épinglée  | Source                       |
|-----------------------|-------------------|------------------------------|
| GCC                   | 12.2.0-3          | Debian apt                   |
| binutils (incl. ld)   | 2.40-2            | Debian apt                   |
| libc6-dev (glibc)     | 2.36-9+deb12u4    | Debian apt                   |
| Provider FIPS OpenSSL | 3.0.13 (cert CMVP TBD) | Build depuis source SHA-256-vérifiée |
| Python                | 3.11.2            | Debian apt                   |
| cppcheck              | 2.10-2            | Debian apt                   |
| clang-tidy-14         | 1:14.0.6-12       | Debian apt                   |
| Docker buildx         | (host)            | exigence host                |

## 6. Livraison (ALC_DEL.1)

Bundle release publié à :

```
https://dist.freehsm.example/v<version>/
    libfreehsm-fips.so              # le module cryptographique
    libfreehsm-fips.so.sha256       # signé par clé de release
    freehsm-c-src.tar.xz            # archive source reproductible
    freehsm-c-src.tar.xz.sha256     # signé par clé de release
    RELEASE_NOTES.md
    ACCEPTANCE.txt
    Dockerfile.build.image-digest
```

Un client / évaluateur vérifie :

1. Télécharger tous les fichiers du bundle via HTTPS.
2. `gpg --verify libfreehsm-fips.so.sha256` contre l'empreinte de clé publiée.
3. `sha256sum -c libfreehsm-fips.so.sha256` contre le binaire.
4. Optionnellement, rebuilder depuis sources : `make dist-verify` (le digest produit DOIT correspondre).

## 7. Remédiation de défauts (ALC_FLR.2)

### 7.1 Réception

Rapports de faille de sécurité à `security@freehsm.example` (empreinte GPG publiée dans `SECURITY.md`). Un mainteneur de triage accuse réception sous 72 heures.

### 7.2 Tracking

Chaque rapport est converti en issue privée avec label `security/<severity>`. L'issue lie le range de commits affecté, la branche de fix proposée, et la planning de divulgation.

### 7.3 Distribution

Une fois le fix mergé :

1. Une nouvelle patch release est taguée immédiatement.
2. Les clients sur la mailing list d'annonces sont notifiés.
3. Après la fenêtre de 90 jours, l'issue est rendue publique et un CVE est demandé.

### 7.4 Politique de backport

Chaque branche supportée (majeure courante + majeure précédente) reçoit chaque fix de sécurité dans les 14 jours suivant la divulgation publique.

## 8. Déclencheurs de re-certification

Les certificats CMVP / CC sont liés à l'arbre source exact. Tout ce qui suit invalide le certificat :

- Changement de code source hors répertoires documentation et test.
- Changement de `Dockerfile.build` (bump toolchain).
- Changement de `scripts/gen_p11_thunks.py` (base de mécanismes).
- Changement de `include/fhsm_common.h::FHSM_VERSION_STRING`.
