# Rebrand Weekend — Execution Checklist (cible 2026-07-12 ; en cours 2026-07-16)

Prepared 2026-07-08. Everything markable ✅ PRÉPARÉ is already written and
committed (or staged) — the weekend is mostly clicking, not writing.

## Phase 0 — Préalable (5 min)

- [ ] **Supprimer `freehsm_c\.git\index.lock`** (verrou résiduel ; PowerShell :
  `Remove-Item freehsm_c\.git\index.lock`). Sans ça, aucun git ne passe.
- [ ] `git log --oneline -3` doit montrer `c443ada` (audit #118) + le commit rebrand.

## Phase 1 — Domaines — ABANDONNÉ (2026-08-03)

Les achats de `freehsm.org` et `simorgh.io` sont annulés. Le projet s'appuie sur
**chaharsou.com**, déjà détenu, déjà en ligne, et qui porte déjà le simorgh
comme emblème et un lien vers le dépôt FreeHSM.

Ce n'est pas un renoncement mais une cohérence avec la mission : l'objectif est
l'éducation et la mise à disposition, pas l'image de marque. Quarante-sept
dollars par an de domaines pour une identité que personne ne cherche encore, ce
sont quarante-sept dollars qui ne servent à personne.

Conséquence assumée : un visiteur venu chercher une bibliothèque PKCS#11 arrive
sur un site culturel bilingue français-persan. Le lien inverse existe déjà
depuis chaharsou.com vers le dépôt, donc le chemin se fait dans les deux sens.

- [ ] Recherche marque rapide : **INPI** (data.inpi.fr) pour FR, **EUIPO eSearch**
  pour l'UE — chercher "Simorgh" et "FreeHSM" classes 9 et 42. But : absence de
  conflit bloquant, pas un dépôt (le dépôt INPI ~190€ peut attendre la v2.0).
  Toujours utile : sans domaine, le nom reste.

## Phase 2 — Renames — ✅ FAIT (vérifié 2026-08-03)

> Le 404 décrit ici n'existe plus. `bash scripts/post_rename.sh --check` sort
> tout en vert : URLs du miroir, les trois remotes, et un **200** sur
> `github.com/afchine1337/freehsm`. Les cinq badges du README sont vivants.
>
> Relancer cette commande plutôt que de faire confiance à ces cases : elle
> interroge le réseau, une case cochée n'interroge rien.

- [x] GitHub : renommé, redirections automatiques actives
- [x] GitLab : chemin renommé
- [x] Codeberg : renommé
- [x] Local : les trois remotes pointent sur `freehsm.git`
- [x] `mirror.yml` : URLs à jour, et les trois forges ont répondu le 2026-08-03

## Phase 3 — Contenu repo (✅ PRÉPARÉ — juste vérifier + pousser)

- ✅ PRÉPARÉ `README.md` + `README.fr.md` : dual branding, nouveau narrative,
  URLs `freehsm`, note de rename, arbre `freehsm/`
- ✅ PRÉPARÉ `TRADEMARK.md` (nouveau)
- ✅ PRÉPARÉ `CHANGELOG.md` : entrée Unreleased "Branding / repository"
- ✅ PRÉPARÉ `docs/index.md` (Jekyll) : rebrandé, release v1.4.0, URLs freehsm
- ✅ PRÉPARÉ `docs/blog/2026-07-16-simorgh-labs-rebrand-and-a-dead-marketing-claim.md`
  (redaté du 12 au 16 : la date pilote l'URL Jekyll ET le lien depuis
  `docs/index.md`, qui pointait vers l'ancien nom — lien mort corrigé)
- ✅ (fait avant) `docs/PRIMACY_AUDIT_PQC_COMPOSITE.md` + `DOC_INDEX.md` (commit c443ada)
- [ ] NON MODIFIÉ (volontaire) : `SECURITY.md` §incident 2026-06-12 garde les
  anciennes URLs `freehsm-c` (texte historique ; les redirects GitHub couvrent)
- [ ] Relire le tout, committer, **signer** : `git commit -S` (et amender c443ada
  si tu veux le signer : `git rebase -i` ou `git commit --amend -S` si HEAD)
- [ ] Pousser vers les 3 remotes

## Phase 4 — Pages & landing (~1-2h)

- [ ] GitHub Pages : re-vérifier la config après rename (Settings → Pages) ;
      l'URL devient `afchine1337.github.io/freehsm/` (ancienne redirigée)
- [x] ~~Landing simorgh.io~~ — sans objet depuis l'abandon du domaine, et le
      draft `simorgh_landing/index.html` n'est de toute façon plus dans l'arbre.
      Si une page vitrine devient utile, ce sera sur chaharsou.com ou sur GitHub
      Pages.
- [ ] Ajouter le logo final (fichier chez toi — non disponible dans la session)
      à la landing + au repo (`docs/assets/`) — remplacer le wordmark texte
- [x] ~~DNS~~ — sans objet : pas de domaine dédié. GitHub Pages sert sur
      `afchine1337.github.io/freehsm/`, et chaharsou.com renvoie vers le dépôt.

## Phase 5 — Annonces (~1h, APRÈS que tout est live)

- ✅ PRÉPARÉ Blog post (dans le repo, publié via Pages en Phase 4)
<!-- doc-audit: allow simorgh_rebrand_announce/01_linkedin.md -->
<!-- doc-audit: allow simorgh_rebrand_announce/02_mastodon_x.md -- written
     outside this repository; the lines below say so. -->
- ✅ PRÉPARÉ LinkedIn — rédigé hors de ce dépôt, cité ici comme
      `simorgh_rebrand_announce/01_linkedin.md` ; ce chemin n'existe pas dans
      ce dépôt et on n'établit plus s'il survit ailleurs sous ce nom.
- ✅ PRÉPARÉ Mastodon + X (thread de 3) — même remarque, cité comme
      `simorgh_rebrand_announce/02_mastodon_x.md`.
- [ ] Poster : blog d'abord, puis LinkedIn (lien en 1er commentaire), puis
      Mastodon/X
- [ ] Éventuel : courte note sur la ML habituelle (le ton oss-security ne se
      justifie pas — pas de contenu sécurité)

## Phase 6 — Optionnel / peut glisser

- [ ] GPG : si un UID « Simorgh Labs » est ajouté, l'adresse ne peut plus être
      `contact@simorgh.io` (domaine abandonné). Utiliser une adresse qui existe
      réellement, sinon ne rien ajouter — un UID qui pointe vers un domaine mort
      est pire qu'aucun UID. (PAS de rotation : le fingerprint ne change jamais.)
- ✅ `LICENSE-BRAND.md` vs `TRADEMARK.md` : **tranché — TRADEMARK.md**, qui est
      livré. `LICENSE-BRAND.md` était l'option écartée et n'a jamais été écrit.
      Reste à décider si le
      logo est ajouté au repo avec mention "all rights reserved" dans REUSE.toml
- [ ] Mettre à jour le profil bestpractices.dev (nom du repo)
- [ ] OpenSSF Scorecard / REUSE : re-lancer après rename pour vérifier badges

## Ce qui ne change JAMAIS (garde-fous)

* `libfreehsm-fips.so` — nom du binaire
* Identifiants PKCS#11 (`manufacturerID = "Simorgh Labs"`, etc.)
* Clé GPG `743A 6A59 04A1 461A 6464 08DE 4856 0162 DBBF 28A2`
* GHSA publiés
