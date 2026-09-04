# PQC — veille / watch

Suivi trimestriel des jeux de tests, standards et signaux post-quantiques qui
touchent FreeHSM (ML-DSA, ML-KEM, SLH-DSA, composite sigs).
Roadmap #116. Chaque entrée est datée ; la plus récente en haut.

Principe : on note ce qu'on a **vérifié**, avec la source et la méthode, pas ce
qu'on suppose. Un « absent » sans méthode de vérification ne vaut rien.

---

## 2026-09-04 — Le module tourne déjà contre les vecteurs PQC, et personne ne le savait

**Question posée :** y a-t-il du nouveau côté Wycheproof sur le PQC ?

**Réponse : oui, et davantage que prévu — les vecteurs sont là, ils sont
téléchargés, ils s'exécutent, et le module les passe.** Aucun de ces quatre
faits n'était connu avant de le mesurer.

### Ce qui existe en amont

Vingt-et-un fichiers PQC dans `testvectors_v1`, présents **à l'épingle que nous
utilisons déjà** (`VECTORS_SHA` = `6d7cccd0fcb1917368579adeeac10fe802f1b521`) :

| Famille | Fichiers |
|---|---|
| ML-DSA 44 / 65 / 87 | `verify`, `sign_seed`, `sign_noseed` — 9 |
| ML-KEM 512 / 768 / 1024 | `test`, `encaps`, `keygen_seed`, `semi_expanded_decaps` — 12 |
| SLH-DSA | **aucun** |

`HEAD` amont est à `3fa63dd0344a`, donc l'épingle est en retard — mais pas pour
le PQC, qui y figure déjà. Le retard reste à traiter séparément.

### Ce que le module rend

Run complet, `run_wycheproof.py` sans `--only`, module `/opt/freehsm/lib/libfreehsm.so`, 18,7 s :

    mldsa    match=  614   viol= 0   skip= 15
    mlkem    match=   21   viol= 0   skip=  0

**Zéro violation.** Première confrontation de ce module à des vecteurs PQC
conçus contre lui plutôt qu'aux siens. Pour situer : la même suite avait ouvert
à 517 échecs sur le classique le 2026-07-10.

Contrôle de cohérence : `rsa_pss match=1083 viol=0` dans le même run, identique
à la valeur enregistrée depuis plusieurs versions. La chaîne mesure bien.

### Ce que cela n'établit pas — trois réserves

**La mesure est hors de la frontière.** Le runner affiche
`NOTE : dev mode active (no FIPS provider)` : `run_pkcs11_check.sh` et ce
runner posent le contournement d'intégrité, donc les fetches EVP sont servis
par le fournisseur par défaut et non par le fournisseur FIPS. Le résultat vaut
pour l'implémentation, pas pour la configuration évaluée. Même réserve que pour
`coverage_matrix.sh`, et le même remède : refaire la mesure dans la frontière.

**La couverture ML-KEM est mince.** 21 assertions contre 614 pour ML-DSA, sur
douze fichiers contre neuf. Deux ordres de grandeur d'écart : soit les vecteurs
d'encapsulation contiennent peu de cas, soit `adapters/mlkem.py` n'en lit
qu'une partie. **Non établi**, et à regarder avant de présenter ce 21 comme une
couverture.

**SLH-DSA reste sans vecteurs publics.** Le module l'implémente, l'annonce et
en fait un KAT au démarrage. Rien en amont ne permet de l'éprouver de
l'extérieur. À formuler ainsi, et pas autrement : ce n'est pas « nos tests
SLH-DSA sont insuffisants », c'est « personne n'a publié de quoi les rendre
suffisants ». Vérifié le 2026-07-24 par sonde directe, inchangé au 2026-09-04.

### À faire

1. Rejouer les deux familles PQC **dans la frontière** — module signé,
   fournisseur FIPS, sans contournement — et consigner ces chiffres-là.
2. Comprendre le 21 de ML-KEM avant de s'en réclamer.
3. Faire monter `VECTORS_SHA` vers `3fa63dd0344a` et rejouer : ce qui bouge est
   nouveau en amont, ce qui ne bouge pas ne l'est pas.
4. Signaler à Denis une incohérence d'affichage repérée au passage : six lignes
   `[aes_gcm] viol tcId=…` sont imprimées pour des cas que le résumé compte en
   `skip=6` et non en `viol`. Le mot imprimé et le compteur ne disent pas la
   même chose. Nos refus d'IV courtes sont une position documentée ; ce qui est
   en cause est l'étiquette.

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
