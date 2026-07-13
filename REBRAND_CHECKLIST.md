# Rebrand Weekend — Execution Checklist (target 2026-07-12)

Prepared 2026-07-08. Everything markable ✅ PRÉPARÉ is already written and
committed (or staged) — the weekend is mostly clicking, not writing.

## Phase 0 — Préalable (5 min)

- [ ] **Supprimer `freehsm_c\.git\index.lock`** (verrou résiduel ; PowerShell :
  `Remove-Item freehsm_c\.git\index.lock`). Sans ça, aucun git ne passe.
- [ ] `git log --oneline -3` doit montrer `c443ada` (audit #118) + le commit rebrand.

## Phase 1 — Achats & vérifications (toi uniquement, ~1h30)

- [ ] Acheter **freehsm.org** (~$12/an) — registrar au choix (Gandi/OVH pour
  facturation FR, ou Cloudflare prix coûtant)
- [ ] Acheter **simorgh.io** (~$35/an) — vérifier dispo ; plan B : simorgh-labs.io,
  simorghpki.io, simorgh.dev
- [ ] Recherche marque rapide : **INPI** (data.inpi.fr) pour FR, **EUIPO eSearch**
  pour l'UE — chercher "Simorgh" et "FreeHSM" classes 9 et 42. But : absence de
  conflit bloquant, pas un dépôt (le dépôt INPI ~190€ peut attendre la v2.0).

## Phase 2 — Renames (30 min)

- [ ] GitHub : Settings → rename `freehsm-c` → `freehsm` (redirects auto)
- [ ] GitLab : Settings → General → rename path `freehsm-c` → `freehsm`
      ⚠ GitLab ne redirige PAS le git remote → mettre à jour le mirror workflow
- [ ] Codeberg : Settings → rename → `freehsm`
- [ ] Local : `git remote set-url origin git@github.com:afchine1337/freehsm.git`
      (+ gitlab, codeberg)
- [ ] Vérifier que le workflow `mirror.yml` passe après renames

## Phase 3 — Contenu repo (✅ PRÉPARÉ — juste vérifier + pousser)

- ✅ PRÉPARÉ `README.md` + `README.fr.md` : dual branding, nouveau narrative,
  URLs `freehsm`, note de rename, arbre `freehsm/`
- ✅ PRÉPARÉ `TRADEMARK.md` (nouveau)
- ✅ PRÉPARÉ `CHANGELOG.md` : entrée Unreleased "Branding / repository"
- ✅ PRÉPARÉ `docs/index.md` (Jekyll) : rebrandé, release v1.4.0, URLs freehsm
- ✅ PRÉPARÉ `docs/blog/2026-07-12-simorgh-labs-rebrand-and-a-dead-marketing-claim.md`
- ✅ (fait avant) `docs/PRIMACY_AUDIT_PQC_COMPOSITE.md` + `DOC_INDEX.md` (commit c443ada)
- [ ] NON MODIFIÉ (volontaire) : `SECURITY.md` §incident 2026-06-12 garde les
  anciennes URLs `freehsm-c` (texte historique ; les redirects GitHub couvrent)
- [ ] Relire le tout, committer, **signer** : `git commit -S` (et amender c443ada
  si tu veux le signer : `git rebase -i` ou `git commit --amend -S` si HEAD)
- [ ] Pousser vers les 3 remotes

## Phase 4 — Pages & landing (~1-2h)

- [ ] GitHub Pages : re-vérifier la config après rename (Settings → Pages) ;
      l'URL devient `afchine1337.github.io/freehsm/` (ancienne redirigée)
- [ ] Landing simorgh.io : draft prêt dans `simorgh_landing/index.html`
      (single-file, palette lapis+or du brand reference, tableau "category of
      one", roadmap). Options : servir tel quel (repo `simorgh-labs/site` +
      Pages + CNAME), ou le porter en Jekyll plus tard
- [ ] Ajouter le logo final (fichier chez toi — non disponible dans la session)
      à la landing + au repo (`docs/assets/`) — remplacer le wordmark texte
- [ ] DNS : CNAME simorgh.io → Pages ; freehsm.org → redirect vers simorgh.io
      ou vers le repo (décision à prendre, 5 min)

## Phase 5 — Annonces (~1h, APRÈS que tout est live)

- ✅ PRÉPARÉ Blog post (dans le repo, publié via Pages en Phase 4)
- ✅ PRÉPARÉ LinkedIn : `simorgh_rebrand_announce/01_linkedin.md`
- ✅ PRÉPARÉ Mastodon + X (thread de 3) : `simorgh_rebrand_announce/02_mastodon_x.md`
- [ ] Poster : blog d'abord, puis LinkedIn (lien en 1er commentaire), puis
      Mastodon/X
- [ ] Éventuel : courte note sur la ML habituelle (le ton oss-security ne se
      justifie pas — pas de contenu sécurité)

## Phase 6 — Optionnel / peut glisser

- [ ] GPG : ajouter un UID `Simorgh Labs <contact@simorgh.io>` à la clé
      existante (PAS de rotation — le fingerprint ne change jamais)
- [ ] `LICENSE-BRAND.md` vs `TRADEMARK.md` : TRADEMARK.md créé ; décider si le
      logo est ajouté au repo avec mention "all rights reserved" dans REUSE.toml
- [ ] Mettre à jour le profil bestpractices.dev (nom du repo)
- [ ] OpenSSF Scorecard / REUSE : re-lancer après rename pour vérifier badges

## Ce qui ne change JAMAIS (garde-fous)

* `libfreehsm-fips.so` — nom du binaire
* Identifiants PKCS#11 (`manufacturerID = "Simorgh Labs"`, etc.)
* Clé GPG `743A 6A59 04A1 4616 46A6 408D E485 6016 2DBB F28A 2`
* GHSA publiés
