# FreeHSM C — Référence des mécanismes PKCS#11 v3.2

> English version : [`MECHANISMS.md`](MECHANISMS.md) (auto-généré par `scripts/gen_p11_thunks.py`).

Ce document est **auto-généré** depuis la base de mécanismes de `scripts/gen_p11_thunks.py`. Le générateur produit uniquement la version anglaise — la table et les colonnes restent identiques quelle que soit la langue, et le vocabulaire technique (CKM, FIPS, NIST SP, RFC) est uniquement disponible en anglais dans les standards normatifs.

Ce wrapper français fournit le contexte général et les conventions de lecture ; pour la table complète des 78 mécanismes, voir le fichier canonique [`MECHANISMS.md`](MECHANISMS.md).

## Synthèse

- **78+ mécanismes** déclarés. Depuis v1.1.0-FIPS.1, 5 IDs PKCS#11 réservés en plus : Kyber (alias ML-KEM), Falcon, LMS, XMSS, HQC — voir [`POST_QUANTUM.md`](POST_QUANTUM.md).
- **66 approuvés FIPS** (dispatchables en mode FIPS strict)
- **12 legacy non-approuvés** : comportement piloté **au runtime** par `FHSM_MODE` (v1.1.0-FIPS.1) plutôt qu'au build time.

## Mode runtime (v1.1.0-FIPS.1)

Le profil n'est plus figé au build. Sélection au runtime via `FHSM_MODE` (ou `mode =` dans `/etc/freehsm/freehsm.conf`) :

| Mode | Comportement des mécanismes non-approuvés |
|---|---|
| `legacy` (défaut) | Délégation à `fhsm_legacy_dispatch` (weak symbol) via OpenSSL default provider. MD5 et SHA-1 (digest) câblés ; DES, 3DES, RC4 renvoient `CKR_MECHANISM_INVALID`. |
| `fips` (strict) | `dispatch_reject_fips` renvoie `FHSM_RV_FIPS_NOT_APPROVED`. |

Un seul binaire `libfreehsm-fips.so` couvre les deux cas.

## Conventions de lecture de la table

- **Colonne « FIPS »** : `✅` = approuvé (toujours dispatchable), `❌` = non-approuvé (comportement = mode runtime).
- **Colonne « Op »** : la catégorie d'opération PKCS#11 (`encrypt`, `decrypt`, `sign`, `verify`, `digest`, `keygen`, `keypair`, `wrap`, `derive`, `encap`, `decap`).
- **Colonne « Handler »** : le symbole C invoqué. Les non-approuvés pointent vers `dispatch_reject_fips` qui consulte `fhsm_mode_is_fips()` au runtime.

## Renvois croisés

- La **source unique de vérité** est `scripts/gen_p11_thunks.py`.
- La **table de dispatch** est générée dans `src/gen/fhsm_dispatch.c`.
- Les **constantes CKM_*** publiques sont générées dans `include/fhsm_pkcs11_mechanisms.h`.
- La §4 de `FIPS_140_3.fr.md` liste les mêmes algorithmes approuvés groupés par famille — l'évaluateur peut faire un diff de ce document avec la version anglaise auto-générée pour confirmer la conformité.

## Localisation du générateur

La localisation française complète du `MECHANISMS.md` auto-généré est suivie comme amélioration future dans le tracker d'issues (label `i18n/mechanisms`). Tant qu'elle n'est pas implémentée, la version anglaise prévaut.
