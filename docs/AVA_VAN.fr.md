# FreeHSM C — Rapport d'analyse de vulnérabilités (CC EAL4+ AVA_VAN.5)

> English version: [`AVA_VAN.md`](AVA_VAN.md). In case of discrepancy, the English version prevails.

**TOE :** FreeHSM Cryptographic Module v1.0.0-FIPS
**Classe CC :** AVA (Évaluation de vulnérabilités) — augmenté à AVA_VAN.5 (analyse méthodique avancée)
**Potentiel d'attaque cible :** *Au-dessus du Haut* (Beyond-High)
**Auteur :** première passe interne ; ré-analyse indépendante par labo requise avant soumission.

---

## 1. Méthodologie

On suit la CEM (Common Evaluation Methodology) §10 et on applique le scoring à quatre critères de la CEM Annexe B (table B.3) :

1. **Temps écoulé** (jours → mois)
2. **Expertise spécialiste** (profane, compétent, expert, multiples experts)
3. **Connaissance de la TOE** (publique, restreinte, sensible, critique)
4. **Fenêtre d'opportunité** (facile, modérée, difficile, aucune)
5. **Équipement** (standard, spécialisé, bespoke, multiples bespoke)

Total < 25 = pratique, < 35 = modéré, < 45 = haut, ≥ 45 = au-dessus du haut. AVA_VAN.5 exige la résistance à toutes les attaques notées < 45.

## 2. Inputs du modèle de menace

- La TOE est un module cryptographique logiciel chargé dans un processus hôte exécutant une application arbitraire.
- L'adversaire a **exécution arbitraire dans le même processus** (lecture/écriture sur le heap utilisateur, observation des caches CPU, du branch predictor).
- L'adversaire n'a **PAS** d'accès ring-0 (FIPS 140-3 §7.7 le place hors champ s'il l'avait).
- L'adversaire a un **accès en lecture** au `.so`, aux logs d'audit et aux tokens. L'accès en écriture est contraint par les permissions du filesystem.
- L'adversaire observe l'horloge système et peut corréler les timings.

## 3. Catalogue des vulnérabilités considérées

Le document anglais (`AVA_VAN.md` §3) détaille 9 vulnérabilités candidates avec scoring CEM complet pour chaque. Synthèse en français :

| # | Vulnérabilité | Score | Défense principale | Risque résiduel |
|---|---------------|-------|--------------------|-----------------|
| 3.1 | Canal temporel sur vérification PIN | 6 (pratique) | Throttle avant PBKDF2 + `fhsm_ct_memcmp` | Négligeable |
| 3.2 | Cache attack T-tables AES | 18 (modéré) | OpenSSL FIPS provider utilise AES-NI constant-time | Négligeable |
| 3.3 | RSA-PSS branchement sur secret | 21 (modéré) | `BN_FLG_CONSTTIME` dans OpenSSL FIPS | Négligeable |
| 3.4 | Exfiltration cold-boot DEK | 9 (pratique) | Secure heap mlock + zéroize + `PR_SET_DUMPABLE=0` | Hors-OE (physique) |
| 3.5 | Injection de faute sur intégrité | 30 (haut) | Compare constant-time + état ERROR latché 2x | Acceptable Niveau 1 |
| 3.6 | Injection dans le log d'audit | 4 (pratique) | Refus de bytes hors safe-ASCII + chaîne HMAC | Négligeable |
| 3.7 | Brute-force PIN | 12 (pratique) | PBKDF2 200k iter + throttle exponentiel + lockout | Acceptable PIN ≥ 8c |
| 3.8 | Compromission de l'état DRBG | 17 (modéré) | Provider FIPS secure heap + dumpable=0 + reseed | Négligeable |
| 3.9 | Downgrade hybride | 9 (pratique) | Combiner hashe `ct_pq` → tampering échoue MAC en aval | Cryptographique négligeable |

Toutes les vulnérabilités sont notées **< 45 (au-dessus du haut)** et sont soit atténuées, soit hors-champ per FIPS 140-3 §7.7.

## 4. Synthèse pen-test

Le labo effectue une passe pen-test indépendante pendant l'évaluation AVA_VAN.5. Zones flaggées pour attention focalisée :

1. **Fuzzing** : parseur d'arguments PKCS#11 (`fhsm_pkcs11.c`), parseur de paramètres TLV (`src/dispatch/fhsm_dispatch_common.c::fhsm_tlv_find`), parseur `.rsp` (`kat/fhsm_kat_rsp.c`). Corpus AFL++ seedés avec les vecteurs CAVP.
2. **Intégration négative** : `C_Login` avec PINs adversariaux (binaire, très long, unicode), `C_Encrypt` avec mismatch de mécanisme, `C_DestroyObject` sur session étrangère.
3. **TOCTOU** : course sur ouverture/écriture du log d'audit contre un adversaire qui remplace le fichier entre vérifications.
4. **Durcissement linker** : `pwntools.checksec` sur le `.so` livré ; attendu `RELRO=Full`, `NX=Yes`, `PIE=Yes`, `Stack canary=Yes`.

Un scénario red-team mené par le labo est recommandé : un co-tenant malveillant sur le même utilisateur Linux tente d'extraire une DEK d'un long-running FreeHSM process via gdb attach, ptrace, inspection `/proc`, ou injection en shared memory.

## 5. Acceptation du risque résiduel

Toute vulnérabilité notée **< 45 (au-dessus du haut)** est soit atténuée ci-dessus, soit hors champ per les hypothèses environnementales FIPS 140-3 §7.7 (accès physique contrôlé, OS durci). Aucune vulnérabilité résiduelle notée sous *practical*/*moderate*/*high* AVA_VAN.5 ne reste ouverte.

La demande de certification est donc soumise contre AVA_VAN.5 avec l'attente d'une *résistance à des attaquants à fort potentiel d'attaque* per CEM §10.2.7.

## 6. Déclencheurs de ré-évaluation

Une nouvelle passe AVA_VAN.5 est requise sur n'importe lequel des :

- Bump toolchain (les pins apt du `Dockerfile.build` changent)
- Bump majeur du provider FIPS OpenSSL
- Ajout d'un nouveau mécanisme approuvé
- Changement du format on-disk du log d'audit
- Changement du format on-disk du token store
