# PQC — veille / watch

Suivi trimestriel des jeux de tests, standards et signaux post-quantiques qui
touchent FreeHSM (ML-DSA, ML-KEM, SLH-DSA, composite sigs).
Roadmap #116. Chaque entrée est datée ; la plus récente en haut.

Principe : on note ce qu'on a **vérifié**, avec la source et la méthode, pas ce
qu'on suppose. Un « absent » sans méthode de vérification ne vaut rien.

---

## 2026-07-24 — Wycheproof : ML-DSA présent, SLH-DSA absent

**Question posée :** y a-t-il des vecteurs SLH-DSA dans Wycheproof à intégrer ?

**Réponse : non, pas à ce jour.** ML-DSA, oui.

**Vérifié (pas supposé) :** sonde directe des fichiers bruts sur la branche
`main` de `C2SP/wycheproof`, `raw.githubusercontent.com` :

| Fichier sondé | Résultat |
|---|---|
| `testvectors_v1/mldsa_65_verify_test.json` | **présent** (~58 Ko) — sert de contrôle positif |
| `testvectors_v1/slh_dsa_sha2_128s_test.json` | 404 |
| `testvectors_v1/slhdsa_sha2_128s_verify_test.json` | 404 |

Aucune PR ni issue SLH-DSA ouverte trouvée. ML-DSA est arrivé via la PR #112
(mergée) ; le pipeline PQC de Wycheproof est donc actif et SLH-DSA suivra
vraisemblablement le même chemin (ML-DSA d'abord, plus déployé).

**Deux points à retenir :**

1. **Le canal de test SLH-DSA vivant aujourd'hui est ACVP, pas Wycheproof.**
   Internet-Draft NIST « ACVP SLH-DSA » de mars 2026 (schéma JSON de test). Pour
   valider notre SLH-DSA maintenant, c'est là qu'il faut aller — les vecteurs
   ACVP/CAVP existent, ceux de Wycheproof non.
2. **Piège de méthode : `doc/files.md` du dépôt Wycheproof est périmé** — il ne
   liste ni ML-DSA ni SLH-DSA alors que ML-DSA est bien dans `testvectors_v1/`.
   Ne jamais faire cette veille depuis le doc ; c'est le répertoire de vecteurs
   qui fait foi. (Ironie : c'est exactement le motif « l'index ment sur le
   contenu du magasin » qu'on traque dans notre propre code.)

**Prochain passage :** re-sonder `testvectors_v1/slhdsa_*` (convention `mldsa_`
sans underscore). Si présent, planifier l'intégration dans l'adaptateur
`tests/wycheproof/adapters/_p11.py`, comme pour ML-DSA.

**Sources :**
- https://github.com/C2SP/wycheproof
- https://github.com/C2SP/wycheproof/pull/112 (ML-DSA)
- https://github.com/C2SP/wycheproof/blob/main/doc/files.md (périmé — à ne pas utiliser seul)
- https://pages.nist.gov/ACVP/draft-livelsberger-acvp-slh-dsa.html (ACVP SLH-DSA, mars 2026)

---

## Gabarit d'entrée (à copier pour le prochain passage)

## AAAA-MM-JJ — <source> : <résumé en une ligne>

**Question posée :** …
**Réponse :** …
**Vérifié (méthode + source) :** …
**À retenir / action :** …
**Sources :** …
