# FreeHSM C — Guide d'utilisation opérationnelle (CC EAL4+ AGD_OPE.1)

> **Non certifié, et sans intention de l'être.** FreeHSM est construit selon les
> exigences FIPS 140-3 niveau 1 et Critères Communs EAL4+, et documenté selon
> leurs méthodologies. Il ne détient aucun certificat et n'en cherchera pas : un
> certificat coûte plus que ce projet n'aura jamais, et ce coût est précisément
> la barrière qui écarte les organismes publics, les universités et les pays en
> développement d'une cryptographie auditable. Ce qu'un certificat atteste, la
> discipline peut le rendre vérifiable — par quiconque, gratuitement.
>
> Ce document est un livrable d'évaluation, rédigé comme la méthodologie
> l'exige, comme si un certificat existait. Lire « certifié » partout comme
> « la configuration selon laquelle ce module est construit ». Il est publié
> comme exemple travaillé, non dans le cadre d'une soumission.

**TOE :** FreeHSM Cryptographic Module v1.0.0-FIPS
**Audience :** opérateurs Security Officer (SO) et User d'une TOE installée
**Pré-requis :** la TOE a été installée et amenée à l'état opérationnel sécurisé per `AGD_PRE.fr.md`

---

## 1. Rôles et responsabilités

| Rôle          | Identifiant | Services autorisés                                                            |
|---------------|-------------|-------------------------------------------------------------------------------|
| Security Officer (CO) | `CKU_SO`    | `C_InitToken`, `C_InitPIN`, `C_SetPIN` (propre), revue d'audit          |
| User                  | `CKU_USER`  | `C_GenerateKey`, `C_GenerateKeyPair`, `C_Encrypt/Decrypt`, `C_Sign/Verify`, `C_Digest`, `C_DeriveKey`, `C_Wrap/Unwrap`, `C_SetPIN` (propre) |

Services anonymes (pré-login) :

| Service          | But                                  |
|------------------|--------------------------------------|
| `C_Initialize`   | Bring-up du module (1×/processus)    |
| `C_GetInfo`      | Identité du module                  |
| `C_GetSlotList`  | Énumérer les slots                  |
| `C_GetTokenInfo` | État du token (compteurs PIN inclus)|
| `C_OpenSession`  | Ouvrir session pour login           |
| `C_GetMechanismList` | Lister les CKM_* dispatchables  |

## 2. Workflow opérateur commun

```c
#include <pkcs11.h>

CK_FUNCTION_LIST_PTR p11;
C_GetFunctionList(&p11);          /* chargé depuis libfreehsm-fips.so */
p11->C_Initialize(NULL);          /* déclenche integrity check + KAT   */

CK_SESSION_HANDLE s;
p11->C_OpenSession(slot, CKF_RW_SESSION|CKF_SERIAL_SESSION,
                    NULL, NULL, &s);
p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin));

/* ... appeler C_GenerateKey, C_Encrypt, etc. ... */

p11->C_Logout(s);                  /* zéroïse la DEK dans cette session  */
p11->C_CloseSession(s);
p11->C_Finalize(NULL);
```

Après `C_Finalize`, le processus ne doit appeler aucun autre `C_*` avant un nouveau `C_Initialize`. Le faire retourne `CKR_CRYPTOKI_NOT_INITIALIZED (0x190)`.

## 3. Conseil pour le choix des mécanismes

| Cas d'usage                              | Mécanisme recommandé                       |
|------------------------------------------|--------------------------------------------|
| Chiffrement symétrique au repos          | `CKM_AES_GCM` (IV 96 bits, tag 128 bits) — **pas** `CKM_AES_CBC_PAD`, cf. §3.1 |
| Authentification symétrique              | `CKM_SHA256_HMAC` ou `CKM_AES_CMAC`        |
| MAC streaming (gros messages)            | `CKM_KMAC128` / `CKM_KMAC256`              |
| Signature asymétrique (classique)        | `CKM_SHA384_RSA_PKCS_PSS` ou `CKM_ECDSA_SHA384` |
| Signature asymétrique (PQ)               | `CKM_ML_DSA` (jeu paramètre ML-DSA-65)     |
| Signature asymétrique (hybride)          | `CKM_HYBRID_ED25519_ML_DSA_65`             |
| Encapsulation de clé (classique)         | `CKM_ECDH1_DERIVE` ou `CKM_X25519_DERIVE`  |
| Encapsulation de clé (PQ)                | `CKM_ML_KEM` (jeu paramètre ML-KEM-768)    |
| Encapsulation de clé (hybride)           | `CKM_HYBRID_X25519_ML_KEM_768`             |
| Dérivation KEK par mot de passe          | `CKM_PKCS5_PBKD2` avec ≥ 200 000 itér.     |
| Dérivation de clé protocole              | `CKM_HKDF_DERIVE` (SHA-256+)               |

Tout mécanisme hors liste approuvée (`CKM_MD5`, `CKM_DES3_CBC`, `CKM_RSA_PKCS`...) est **rejeté au dispatch** et retourne `FHSM_RV_FIPS_NOT_APPROVED (0x80000003)`.

### 3.1 Approuvé ne veut pas dire adapté à votre usage

Deux mécanismes de la liste approuvée portent une réserve que l'approbation FIPS
n'exprime pas, parce que l'approbation porte sur l'algorithme et la réserve porte
sur le protocole que vous construisez avec. Les deux sont utilisables et aucun
n'est un défaut du module ; le choix vous revient.

**`CKM_AES_CBC_PAD` est un oracle de padding.** Le déchiffrement indique à
l'appelant si le padding PKCS#7 était bien formé — `CKR_OK` quand oui,
`CKR_ENCRYPTED_DATA_INVALID` quand non. Ce seul bit, répété sur des chiffrés
choisis, permet de reconstituer le clair octet par octet (Vaudenay 2002 ;
POODLE, CVE-2014-3566). C'est inhérent : CBC-PAD ne porte aucun tag
d'authentification, donc `C_Decrypt` ne peut pas distinguer « corrompu » de
« pas pour vous » sans dire lequel, et renvoyer du clair aléatoire à la place
serait pire pour tout appelant honnête.

Mesuré sur ce module : 99,6 % des chiffrés corrompus sont refusés, et les 0,4 %
qui déchiffrent sont ceux dont le dernier bloc aléatoire porte par hasard un
padding valide — c'est le taux théorique de toute implémentation correcte. Le
module se comporte comme spécifié. L'exposition est dans le protocole.

> **Utilisez `CKM_AES_GCM` ou `CKM_AES_KEY_WRAP` partout où un attaquant peut
> soumettre des chiffrés de son choix et observer si le déchiffrement a
> réussi.** `CKM_AES_CBC_PAD` convient aux données que vous déchiffrez pour
> vous-même — un fichier au repos, une sauvegarde — sans adversaire aux
> commandes du déchiffrement.

**`CKM_AES_CBC` et `CKM_AES_CTR` n'offrent aucune intégrité.** Pas d'oracle,
puisqu'il n'y a pas de padding à vérifier, mais aucune détection d'altération
non plus : sous CTR, un bit retourné dans le chiffré retourne le bit
correspondant du clair, silencieusement. Associez-les à un `CKM_SHA256_HMAC` sur
le chiffré (encrypt-then-MAC, RFC 7366), ou prenez `CKM_AES_GCM` qui fait les
deux en une passe.

Voir R2 dans `docs/PKCS11_CHECK_FINDINGS.md` pour la mesure, et
`tests/test_cbc_pad_oracle.c` pour le garde-fou de non-régression.

## 4. Conseils de sécurité (actionnables par opérateur)

### 4.1 Gestion des PIN

- Longueur minimale : **8 octets**. Recommandation pour HVA : ≥ 12 caractères, mixité.
- Jamais réutiliser un PIN entre slots. Le throttle est par-slot.
- Après **5 échecs consécutifs**, le rôle est verrouillé. Le PIN USER est déverrouillé par le SO via `C_InitPIN`. Le PIN SO n'est déverrouillé que par `C_InitToken`, **ce qui détruit tous les objets du slot**.

### 4.2 Gestion du throttle

Entre tentatives, `C_Login` peut retourner `FHSM_RV_PIN_THROTTLED (0x80000004)`. Le client DEVRAIT :

1. Afficher le temps d'attente à l'opérateur humain.
2. Sleep pour le nombre de millisecondes indiqué.
3. Réessayer exactement une fois.

Marteler à travers le throttle ne change pas le résultat ; le cooldown survit au redémarrage du processus.

### 4.3 Revue du log d'audit

> **Le journal d'audit est produit, et la chaîne est vérifiable.**
> L'avertissement qui figurait ici — aucun journal écrit, contrôle sur lequel
> il ne fallait pas compter — ne s'applique plus. `C_Initialize` ouvre le
> journal, la chaîne survit aux redémarrages, une écriture ratée verrouille le
> module en `ERREUR`, et les deux vérificateurs détectent une entrée modifiée,
> supprimée, insérée ou réordonnée.
>
> Trois limites subsistent, à connaître avant de s'appuyer sur ce contrôle :
>
> 1. **Un journal tronqué à la fin n'est pas détecté**, et ne peut pas l'être
>    depuis le seul fichier : ce qui reste est une chaîne plus courte qui se
>    vérifie parfaitement, indistinguable d'un journal qui se serait arrêté là.
>    Atténuation : l'archivage (étape 3) et la comparaison du nombre d'entrées
>    entre deux archives — un `seq` qui recule est le signal.
> 2. **Un échec d'intégrité ou de KAT au démarrage n'est pas journalisé.** Le
>    journal s'ouvre après la couche cryptographique, parce que chaîner une
>    entrée exige HMAC. Si l'auto-test échoue, les primitives qui
>    authentifieraient l'entrée sont celles qui viennent d'échouer. Le module
>    verrouille en `ERREUR` et refuse tout, donc la condition reste observable
>    — mais la raison ne sera pas dans le journal. Lire la sortie d'erreur du
>    processus et les drapeaux de `C_GetTokenInfo` dans ce cas.
> 3. **La clé de chaînage ne protège pas d'un root actif.** Scellée dans le
>    TPM, elle résiste à qui emporte le disque ou modifie la chaîne de
>    démarrage ; elle est descellée en mémoire du processus pour servir. Voir
>    §4.4.

Le journal vit dans `{tokens_dir}/audit.log`, ou là où pointe
`FHSM_AUDIT_LOG`. Le SO DOIT :

1. Périodiquement (recommandé : hebdomadaire) vérifier la chaîne. Attention à
   la syntaxe : `verify` est une sous-commande et la clé d'audit de 32 octets
   est un argument obligatoire — le binaire s'appelle `freehsm-audit`, et
   `freehsm-audit-verify` n'existe pas.
   ```bash
   freehsm-audit verify /var/lib/freehsm/audit/slot0.audit.log <audit_key_hex_64>
   ```
2. Investiguer tout `login_fail`, `login_locked`, `login_throttled`, `integrity_fail`.
3. Archiver mensuellement vers stockage immuable.

Une chaîne brisée est un **événement de sécurité critique** : le journal sur
disque a été altéré par quelqu'un ayant accès en écriture au répertoire
d'audit. Le vérificateur nomme la première ligne fautive et ce qu'il y a
trouvé — entrée modifiée, `prev_hmac` qui ne suit pas, ou `seq` décalé.
Prendre le système hors ligne et suivre la procédure d'incident (`SECURITY.md`).

### 4.4 La clé d'audit

La chaîne est authentifiée par une clé de 32 octets, provisionnée au premier
démarrage puis récupérée. Elle n'est **pas** dérivée de la DEK du token : le
journal ne serait alors écrivable qu'une fois connecté, et `login_fail`,
`login_locked` et `integrity_fail` — les trois événements que l'étape 2
demande d'investiguer — ne seraient jamais enregistrés.

| Emplacement | Quand |
|---|---|
| `{tokens_dir}/audit.key.tpm`, scellée | `FHSM_TPM_SEALING=1` et TPM présent |
| `{tokens_dir}/audit.key`, mode 0600 | sinon |

Le module refuse de démarrer plutôt que de se dégrader en silence :

* une clé lisible par le groupe ou par tous est refusée — une clé de chaînage
  que tout le monde peut lire est une chaîne que tout le monde peut forger ;
* un blob scellé qui ne se descelle pas est refusé, au lieu d'être remplacé
  par une clé neuve qui démarrerait silencieusement une seconde chaîne dans le
  même fichier ;
* un scellement demandé et indisponible est refusé, au lieu d'écrire la clé en
  clair.

Vérifier un journal exige cette clé. La lire avec `xxd -p -c 32
{tokens_dir}/audit.key` sur l'hôte, ou l'y desceller. **Un journal archivé sans
sa clé ne pourra pas être vérifié plus tard** — archiver les deux séparément,
et jamais sur le même support.

### 4.4 Sauvegarde de token

Les fichiers token sont chiffrés au repos sous PIN(s). Backups sûres seulement si :

- Utiliser `cp --preserve=mode,ownership,timestamps` (ou `rsync -a`).
- Stocker sur média chiffré (LUKS, tar GCM-chiffré, envelope KMS).
- Ne jamais copier le log d'audit sans le token correspondant.

### 4.5 Discipline de logout

```c
p11->C_Logout(s);
p11->C_CloseSession(s);
```

`C_Logout` zéroïse la DEK en mémoire. `C_CloseSession` zéroïse les buffers de clés locaux à la session.

## 5. Référence des services (sélection)

### 5.1 `C_GenerateKey` (AES-256)

```c
CK_MECHANISM mech    = { CKM_AES_KEY_GEN, NULL, 0 };
CK_OBJECT_HANDLE key = 0;
CK_ULONG keylen      = 32;
CK_BBOOL true_       = CK_TRUE;
CK_ATTRIBUTE templ[] = {
    { CKA_VALUE_LEN, &keylen, sizeof(keylen) },
    { CKA_TOKEN,     &true_,  sizeof(true_)  },
    { CKA_ENCRYPT,   &true_,  sizeof(true_)  },
    { CKA_DECRYPT,   &true_,  sizeof(true_)  },
};
p11->C_GenerateKey(s, &mech, templ, 4, &key);
```

### 5.2 `C_Encrypt` (AES-GCM)

```c
CK_GCM_PARAMS gcm = {
    .pIv = iv, .ulIvLen = 12,
    .pAAD = aad, .ulAADLen = sizeof(aad),
    .ulTagBits = 128,
};
CK_MECHANISM mech = { CKM_AES_GCM, &gcm, sizeof(gcm) };

p11->C_EncryptInit(s, &mech, key);
p11->C_Encrypt(s, plaintext, plen, ciphertext, &clen);
```

## 6. Réponse aux erreurs

| `CK_RV` (hex) | Symbole                         | Action opérateur                                                |
|---------------|---------------------------------|-----------------------------------------------------------------|
| `0x00`        | `CKR_OK`                        | continuer                                                       |
| `0x05`        | `CKR_GENERAL_ERROR`             | vérifier syslog ; si récurrent, contacter vendor                |
| `0x06`        | `CKR_FUNCTION_FAILED`           | réessayer une fois                                              |
| `0x60`        | `CKR_KEY_HANDLE_INVALID`        | handle expiré ; relancer la séquence                            |
| `0x70`        | `CKR_MECHANISM_INVALID`         | pas dans `C_GetMechanismList` ; choisir mécanisme approuvé      |
| `0xA0`        | `CKR_PIN_INCORRECT`             | retry avec bon PIN ; attention au throttle                      |
| `0xA4`        | `CKR_PIN_LOCKED`                | appeler le SO pour déverrouiller via `C_InitPIN`                |
| `0xB3`        | `CKR_SESSION_HANDLE_INVALID`    | ouvrir une nouvelle session                                     |
| `0x101`       | `CKR_USER_NOT_LOGGED_IN`        | `C_Login` d'abord                                               |
| `0x190`       | `CKR_CRYPTOKI_NOT_INITIALIZED`  | `C_Initialize` d'abord ; ne PAS appeler après `C_Finalize`      |
| `0x80000001`  | `FHSM_RV_KAT_FAILED`            | **Critique** : module halted ; ne pas réutiliser ; réinstaller  |
| `0x80000002`  | `FHSM_RV_INTEGRITY_FAILED`      | **Critique** : binaire altéré ; réinstaller depuis bundle vérifié |
| `0x80000003`  | `FHSM_RV_FIPS_NOT_APPROVED`     | bascule sur mécanisme approuvé                                  |
| `0x80000004`  | `FHSM_RV_PIN_THROTTLED`         | attendre les ms indiquées, retry une fois                       |
| `0x80000007`  | `FHSM_RV_SECURE_HEAP_EXHAUSTED` | réduire l'inventaire de clés ou augmenter `secure_heap_kb`      |
| `0x80000008`  | `FHSM_RV_RNG_FAILURE`           | **Critique** : DRBG échoue auto-test ; redémarrer le processus  |

Les erreurs critiques verrouillent l'état module ERROR. La seule récupération est de redémarrer le processus (per FIPS 140-3 §7.10.5).

## 7. Maintenance routinière

| Fréquence | Tâche                                                                |
|-----------|----------------------------------------------------------------------|
| Quotidien | Confirmer santé `freehsm-bound-service` ; vérifier syslog            |
| Hebdo     | Vérifier la chaîne d'audit de chaque slot ; archiver si rotation     |
| Mensuel   | Rotation des PIN USER ; revue d'agrégats d'audit                     |
| Trimestriel | Tester `make repro` contre un checkout neuf                        |
| Annuel    | Re-lancer pen-testing ; mettre à jour pins OE.OS / OE.OPENSSL        |

## 7bis. Modes runtime (v1.1.0)

Le module choisit entre **legacy** (défaut) et **FIPS strict** au runtime via `FHSM_MODE` ou la directive `mode =` dans `/etc/freehsm/freehsm.conf`.

| Mode | Activation | Comportement |
|---|---|---|
| `legacy` (défaut) | rien, ou `FHSM_MODE=legacy` | Tous les mécanismes appelables. MD5 et SHA-1 (digest) routés vers `fhsm_legacy_dispatch`. DES, 3DES, RC4 retournent `CKR_MECHANISM_INVALID`. |
| `fips` (strict) | `FHSM_MODE=fips` ou `mode = fips` dans la conf | Tout mécanisme non-FIPS-approuvé retourne `CKR_MECHANISM_INVALID`. Conforme SP 800-131A Rev. 3. |

Pour une éval FIPS 140-3, l'opérateur DOIT poser `FHSM_MODE=fips` AVANT tout `C_Initialize`. Le mode est mis en cache au premier lookup.

### Sealing matériel (opt-in)

| Variable | Effet |
|---|---|
| `FHSM_TPM_SEALING=1` | À l'init du token, DEK scellée au TPM 2.0 (PCR 0-7). Fichier compagnon `{slot}.tok.tpm`. Au login : PBKDF2-unwrap + TPM-unseal doivent matcher. Un écart, ou un unseal en échec, refuse le login avec `CKR_DEVICE_ERROR` — **lire la note ci-dessous avant d'activer**. |
| `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` | **DEV-ONLY** : bypass de la vérif d'intégrité — INTERDIT en production. |

#### Avant d'activer : le processus du module doit accéder au TPM

`FHSM_TPM_SEALING=1` fait appeler `tpm2` par le module, qui ouvre
`/dev/tpmrm0`. Sur Debian et Ubuntu ce nœud est `crw-rw---- root tss` : le
compte qui exécute l'application PKCS#11 doit donc appartenir au groupe `tss` :

```
id -Gn | tr ' ' '\n' | grep -qx tss || sudo usermod -aG tss "$(id -un)"
```

L'appartenance aux groupes est fixée à l'ouverture de session : une session déjà
ouverte ne la verra pas. `newgrp tss` donne le groupe au shell courant sans
déconnexion.

Ne pas contourner en lançant l'application en root. Les fichiers de token
seraient créés au nom de root et le service aurait ensuite besoin de root pour
chaque opération — une concession plus grande que celle qu'on évite.

Sans le groupe, tout appel TPM échoue sur une erreur de permission TCTI et le
module renvoie `CKR_DEVICE_ERROR` avec `tpm-unseal-failed` dans le journal
d'audit — le même signal que des PCR déplacés. Vérifier le groupe avant de
soupçonner les PCR.

#### Avant d'activer : le TPM doit avoir une cle primaire persistante

Le scellement s'appuie sur une cle primaire persistante au handle `0x81010001`.
**Le module ne la cree pas**, et si elle manque, tout scellement echoue. Rien ne
le disait jusqu'a ce que le chemin de scellement soit exerce pour la premiere
fois sur du vrai materiel ; c'est cet oubli qu'on corrige ici.

```
tpm2 readpublic -c 0x81010001            # presente ? sinon :
tpm2 createprimary -C o -g sha256 -G ecc -c /tmp/primary.ctx
tpm2 evictcontrol  -C o -c /tmp/primary.ctx 0x81010001
```

Le handle est fixe a la compilation (`TPM_PARENT_HANDLE` dans `src/fhsm_tpm.c`).
Un operateur dont le TPM utilise deja `0x81010001` pour autre chose n'a aucun
moyen de le signaler — cela a sa place dans `freehsm.conf`, ou ca n'est pas
encore.

`scripts/validate_tpm_sealing.sh` verifie la presence du handle, propose de le
provisionner, et exerce tout le cycle de scellement sur un TPM reel, y compris
le scenario de changement de PCR decrit ci-dessous. A lancer avant de confier
quoi que ce soit a `FHSM_TPM_SEALING`.

#### Ce qu'un changement de PCR implique pour vous (#109)

Le scellement lie la DEK aux PCR 0 à 7, qui mesurent le firmware et le début du
boot. Une mise à jour BIOS/UEFI, une rotation de clés Secure Boot, un changement
de bootloader ou de noyau en déplace au moins un. Le TPM refuse alors de rendre
la DEK scellée, et **tous les logins sur ce token échouent tant que vous n'agissez
pas**, même avec le bon PIN.

C'est le comportement attendu du boot mesuré, pas une panne. Le code retourné est
`CKR_DEVICE_ERROR`, volontairement distinct de `CKR_PIN_INCORRECT` :

| Retour | Signification | Que faire |
|---|---|---|
| `CKR_PIN_INCORRECT` / `CKR_PIN_LOCKED` | Le PIN était faux. | Gestion normale du PIN. |
| `CKR_DEVICE_ERROR` | Le PIN était bon ; c'est le côté TPM qui a échoué. | Voir ci-dessous. |

Trois causes produisent `CKR_DEVICE_ERROR`, que le journal d'audit distingue :

* `tpm-unseal-failed` — le TPM n'a pas pu libérer la clé. Presque toujours des PCR
  déplacés après une mise à jour de firmware ou de noyau ; aussi observé quand le
  TPM est absent ou que le resource manager ne tourne pas.
* `tpm-dek-mismatch` — le TPM a libéré une clé, mais ce n'est pas celle que
  contient le fichier token. Les deux devraient être identiques. **Traiter comme
  une substitution possible du fichier token ou du blob scellé, et enquêter
  avant d'aller plus loin.**
* `tpm-required-but-missing` — `FHSM_TPM_SEALING=1` mais ce token n'a pas de
  compagnon `.tpm`. Il a été créé sans scellement.

**Récupération après une mise à jour de firmware.** La DEK reste récupérable
depuis le fichier token avec le PIN : le scellement est un second facteur, pas
l'unique copie. Sauvegardez `{slot}.tok` et `{slot}.tok.tpm`, puis soit vous
revenez en arrière sur le firmware pour retrouver les valeurs de PCR scellées,
soit vous re-scellez le token sous les nouvelles mesures. Perdre le seul fichier
`.tpm` ne fait pas perdre le token ; perdre le fichier token, si.

**Un unseal en échec ne consomme plus de tentative de PIN.** Avant la v1.7.0 il en
consommait une, et le throttle s'aggravait avec, si bien qu'une simple mise à jour
de firmware verrouillait définitivement le token d'un opérateur qui n'avait rien
fait de mal. C'était un déni de service, il est corrigé. Un PIN réellement faux
compte, throttle et verrouille toujours comme documenté au §5.

**Faites une sauvegarde avant d'activer `FHSM_TPM_SEALING` sur un token qui
compte.**

### DRBG durci

`fhsm_rng_bytes` route via `fhsm_drbg_bytes` : seed multi-source (getrandom + RDRAND + /dev/urandom + jitter TSC), conditionneur SHA-256, health tests SP 800-90B (RCT + APT + CRNGT), reseed auto tous les 1 MiB ou 1 h. Alarme → ERROR latché. Voir [`RNG.md`](RNG.md).

### Pair-wise consistency check

Chaque `C_GenerateKeyPair` est suivi d'un sign-verify (ou encap-decap) automatique. Échec → ERROR latché. ~5 ms RSA-2048, sub-ms EC, ~50 ms SLH-DSA-128s.

## 8. Actions interdites

Les actions suivantes **invalident** la configuration certifiée et **font perdre** le certificat FIPS / CC :

- Laisser `FHSM_MODE` non défini (= mode legacy) pour un déploiement réclamant la conformité FIPS 140-3.
- Définir `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` en production.
- Définir `fips_strict=false` dans `freehsm.conf`.
- Remplacer `libfreehsm-fips.so` par tout autre binaire, même patché.
- Modifier tout fichier dans `/opt/freehsm/etc/`.
- Charger un provider OpenSSL autre que le provider FIPS validé.
- Désactiver la capacité `mlock` sur l'hôte.
- Désactiver l'audit (`audit_mandatory=false`).
- Opérer l'hôte sans accès physique contrôlé (viole OE.PHYS).
