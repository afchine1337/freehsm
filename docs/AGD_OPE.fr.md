# FreeHSM C — Guide d'utilisation opérationnelle (CC EAL4+ AGD_OPE.1)

> English version: [`AGD_OPE.md`](AGD_OPE.md). In case of discrepancy, the English version prevails.

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
| Chiffrement symétrique au repos          | `CKM_AES_GCM` (IV 96 bits, tag 128 bits)   |
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

Le SO DOIT :

1. Périodiquement (recommandé : hebdomadaire) vérifier la chaîne avec le verifier :
   ```bash
   freehsm-audit-verify /var/lib/freehsm/audit/slot0.audit.log
   ```
2. Investiguer tout `login_fail`, `login_locked`, `login_throttled`, `integrity_fail`.
3. Archiver mensuellement vers stockage immuable.

Une chaîne brisée est un **événement de sécurité critique** : prendre le système offline et suivre la procédure d'incident response (`SECURITY.md`).

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
| `FHSM_TPM_SEALING=1` | À l'init du token, DEK scellée au TPM 2.0 (PCR 0-7). Fichier compagnon `{slot}.tok.tpm`. Au login : PBKDF2-unwrap + TPM-unseal doivent matcher (mismatch silencieux = PIN incorrect). |
| `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` | **DEV-ONLY** : bypass de la vérif d'intégrité — INTERDIT en production. |

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
