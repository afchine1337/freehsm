# FreeHSM C — Procédures préparatoires (CC EAL4+ AGD_PRE.1)

> English version: [`AGD_PRE.md`](AGD_PRE.md). In case of discrepancy, the English version prevails.

**TOE :** FreeHSM Cryptographic Module v1.0.0-FIPS
**Audience :** administrateur système déployant la TOE pour la première fois
**Pré-requis :** accès root sur l'hôte cible ; familiarité avec PKCS#11

Ce document décrit comment recevoir, vérifier, installer et configurer la TOE jusqu'à son état opérationnel sécurisé. Après l'avoir parcouru, l'administrateur peut passer à `AGD_OPE.fr.md` pour l'exploitation quotidienne.

---

## 1. Pré-requis environnement opérationnel (OE)

La Cible de sécurité (`EAL4_PLUS.fr.md` §3.2) liste six objectifs OE. À confirmer **avant** installation :

| Identifiant OE | Exigence                                                       | Vérification                                                       |
|----------------|----------------------------------------------------------------|--------------------------------------------------------------------|
| **OE.OS**      | Linux ≥ 5.4 avec capacité `mlock`                              | `uname -r ; getcap /usr/local/lib/libfreehsm-fips.so`              |
| **OE.STORAGE** | FS local avec `rename` atomique (ext4/xfs)                     | `findmnt -T /var/lib/freehsm -o FSTYPE`                            |
| **OE.OPENSSL** | OpenSSL ≥ 3.0 avec provider FIPS chargé et actif               | `openssl list -providers \| grep -A2 fips`                          |
| **OE.OP**      | Administrateur formé, contrôle des credentials d'authentification | (procédural — voir §6)                                          |
| **OE.PHYS**    | Hôte physiquement protégé (rack verrouillé / accès autorisé)   | (procédural — sécurité du site)                                    |
| **OE.HARDWARE** | CPU avec AES-NI (x86_64) ou ARMv8 Crypto Ext.                 | `grep aes /proc/cpuinfo \| head -1`                                |

Si une vérification échoue, **ne pas continuer** : la TOE n'entrera pas dans son état sécurisé revendiqué.

## 2. Vérification de livraison

La TOE est livrée comme quatre fichiers sur le serveur de distribution (`https://dist.freehsm.example/v1.0.0/`) :

```
libfreehsm-fips.so
libfreehsm-fips.so.sha256       # digest détaché, GPG-signé
freehsm-c-src.tar.xz
freehsm-c-src.tar.xz.sha256     # digest détaché, GPG-signé
RELEASE_NOTES.md
ACCEPTANCE.txt
Dockerfile.build.image-digest
```

### 2.1 Authentification du canal

Téléchargement obligatoire en **HTTPS** TLS 1.3 avec validation du certificat. Refuser les certificats auto-signés.

### 2.2 Authentification de l'origine

Vérifier que chaque `*.sha256` est signé par la clé de release dont l'empreinte est publiée sur le site du projet (et reproduite dans `ALC_CMC.fr.md` §7) :

```bash
gpg --import freehsm-release-pubkey.asc
gpg --verify libfreehsm-fips.so.sha256
# Attendu : Good signature from "FreeHSM Release Manager <release@freehsm.example>"
gpg --verify freehsm-c-src.tar.xz.sha256
```

Refuser la livraison si l'une des signatures ne valide pas.

### 2.3 Vérification d'intégrité

```bash
sha256sum -c libfreehsm-fips.so.sha256
# Attendu : libfreehsm-fips.so: OK

sha256sum -c freehsm-c-src.tar.xz.sha256
# Attendu : freehsm-c-src.tar.xz: OK
```

### 2.4 Optionnel : rebuild depuis sources

L'assurance la plus forte est de rebuilder le binaire depuis l'archive source et confirmer la sortie bit-identique :

```bash
tar xf freehsm-c-src.tar.xz
cd freehsm-c-1.0.0-FIPS
make dist-verify     # rebuild deux fois dans Docker épinglé, assert SHA-256 identiques
```

Le SHA-256 du `libfreehsm-fips.so` résultant DOIT correspondre à la valeur dans `libfreehsm-fips.so.sha256`. Voir `REPRODUCIBLE_BUILD.fr.md`.

## 3. Installation

### 3.1 Arborescence

Créer l'arbre de production sous `/opt/freehsm` :

```bash
sudo install -d -o root -g root -m 755 /opt/freehsm/{lib,bin,etc}
sudo install -d -o freehsm -g freehsm -m 700 \
    /var/lib/freehsm/{tokens,audit,kek}
```

### 3.2 Installation du module

```bash
sudo install -o root -g root -m 0755 libfreehsm-fips.so \
    /opt/freehsm/lib/libfreehsm-fips.so

sudo useradd -r -s /usr/sbin/nologin -d /var/lib/freehsm freehsm
sudo setcap 'cap_ipc_lock=+ep' /opt/freehsm/lib/libfreehsm-fips.so
```

### 3.3 Activation du provider FIPS OpenSSL

```bash
openssl list -providers
# Attendu :
#   fips
#     name: OpenSSL FIPS Provider
#     version: 3.0.13
#     status: active
```

### 3.4 Vérification de l'identité du module

```bash
readelf -p .comment /opt/freehsm/lib/libfreehsm-fips.so
# Attendu : GCC 12.2.0 ; binutils 2.40 ; (match Dockerfile.build)

readelf -S /opt/freehsm/lib/libfreehsm-fips.so | grep .fhsm_digest
# Attendu : section read-only 32-byte
```

Si `.fhsm_digest` est tout à zéro, le module **n'a pas été signé** :

```bash
xxd -s 0x2000 -l 32 /opt/freehsm/lib/libfreehsm-fips.so
# Attendu (signé) : 32 octets hex
# Tout-zéro ⇒ refuser le déploiement.
```

## 4. Configuration initiale

### 4.1 Configuration du module

Créer `/opt/freehsm/etc/freehsm.conf` :

```
[module]
fips_strict      = true
audit_mandatory  = true
secure_heap_kb   = 256

[token]
pin_max_failed         = 5
pin_throttle_base_ms   = 500
pin_throttle_max_ms    = 60000
pbkdf2_iterations      = 200000

[paths]
tokens_dir = /var/lib/freehsm/tokens
audit_dir  = /var/lib/freehsm/audit
```

### 4.2 Vérification d'intégrité au premier démarrage

```bash
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --show-info
```

Si `C_Initialize` retourne `0x00000005` ou `0x80000002` (`INTEGRITY_FAILED`), la POST a échoué — examiner `/var/log/syslog` et `/var/lib/freehsm/audit/boot.log`. **Ne pas** chercher à contourner.

### 4.3 Initialisation du token (bootstrap CO)

```bash
read -s -p "SO PIN > " SO_PIN ; echo

sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --init-token --label "prod-slot-0" --so-pin "$SO_PIN"
unset SO_PIN
```

### 4.4 Initialisation du PIN USER (délégué)

Le SO définit ensuite un PIN utilisateur pour l'opérateur quotidien. Le PIN USER DOIT différer du PIN SO.

```bash
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --so-pin "$SO_PIN" --init-pin --new-pin "$USER_PIN"
```

## 5. Atteindre l'*état opérationnel sécurisé*

La TOE est dans son état opérationnel sécurisé quand **tous** les éléments suivants sont simultanément vrais :

1. `C_Initialize` a retourné `CKR_OK`.
2. `fhsm_kat_results()` rapporte chaque primitive approuvée comme `passed=1`.
3. `fhsm_integrity_is_signed()` retourne 1.
4. L'état module est `INITIALIZED` ou `AUTHENTICATED`.
5. `/var/lib/freehsm/audit/slot0.audit.log` contient un événement `module_init` avec `result=OK`.
6. `fips_strict=true` est défini dans `freehsm.conf`.

## 6. Responsabilités de l'opérateur (procédural)

L'administrateur confirme par écrit (trail d'audit) que :

- Les opérateurs sont formés sur `AGD_OPE.fr.md` avant d'obtenir des credentials.
- Les PINs sont transmis via canal authentifié et jamais écrits.
- Le log d'audit est passé en revue au moins hebdomadairement.
- Les sauvegardes des tokens sont effectuées avec les **mêmes contrôles d'accès** que le store live.

## 7. Portage Debian 13 (gcc-14 / dash / OpenSSL 3.5)

Cette section documente les écarts observés lors du portage d'une station de build Debian 12 / gcc-12 / OpenSSL 3.0 vers une cible Debian 13 / gcc-14 / OpenSSL 3.5. Le module reste reproductible sur les deux distributions ; les ajustements ci-dessous sont déjà incorporés à la branche `main`.

### 7.1 Compilation (gcc-14)

gcc-14 active par défaut plusieurs warnings que gcc-12 traitait silencieusement. La build étant en `-Werror`, chaque catégorie a été levée avec une correction ciblée :

| Warning | Cause | Remédiation |
|---|---|---|
| `-Wmissing-prototypes` sur les `C_*` | Symboles exportés sans déclaration locale | Forward-declarations marquées `FHSM_EXPORT` dans `src/fhsm_pkcs11.c` |
| `-Wstringop-truncation` sur `strncpy(dst, src, n-1); dst[n-1]=0` | gcc-14 refuse même le pattern « manuel sûr » | Remplacement par `snprintf(dst, n, "%s", src)` dans `fhsm_integrity.c` et `fhsm_state.c` |
| `-Werror=array-bounds` sur `memcpy(dst, "literal", 32)` | `_FORTIFY_SOURCE=2` détecte une lecture OOB quand le littéral est plus court que 32 | Helper `fhsm_pack_field(dst, src, n)` qui utilise `strlen()` empêchant l'inférence statique |
| `-Wmisleading-indentation` | Trois instructions sur une ligne dans `fhsm_dispatch_hybrid.c` | Découpage en trois lignes distinctes |
| `-Wredundant-decls` sur `dispatch_reject_fips` | Le générateur de table émettait deux fois la déclaration | Patch `scripts/gen_p11_thunks.py` (skip dans la boucle `extern`) |

### 7.2 Makefile et `dash`

`/bin/sh` pointe sur **`dash`** sur Debian (pas bash). `dash` refuse plusieurs constructions valides ailleurs :

- Heredoc `<<-EOF` multi-lignes combinés avec `if/then/fi` continués par `\`
- Substitution `$(...)` qui dépasse plusieurs lignes physiques

La cible `install` du `Makefile` a été réécrite sans `if/then/fi` ni heredoc, en utilisant `test X || command` et `printf '...\n...\n'` à la place. Aucun changement n'est nécessaire si l'on cible bash explicitement, mais le portage maintient la compatibilité dash pour faciliter le déploiement sur containers minimaux.

### 7.3 Provider FIPS OpenSSL 3.5

OpenSSL 3.5 fournit toujours le provider FIPS mais n'a pas de configuration installée par défaut sur Debian 13. Sans configuration, `OSSL_PROVIDER_load(NULL, "fips")` peut retourner un handle « actif » mais ne servir aucun algorithme — chaque KAT échoue alors et `C_Initialize` retourne `FHSM_RV_KAT_FAILED` (`0x80000001`).

**Activation du provider FIPS sur Debian 13 :**

```bash
# Localiser le module
sudo find / -name "fips.so" 2>/dev/null
# /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so

# Générer fipsmodule.cnf (calcul du MAC d'intégrité du provider)
sudo openssl fipsinstall \
    -out /usr/lib/ssl/fipsmodule.cnf \
    -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so

# Activer dans /etc/ssl/openssl.cnf : décommenter "fips = fips_sect" et
# inclure fipsmodule.cnf au début du fichier.
echo ".include /usr/lib/ssl/fipsmodule.cnf" | sudo tee -a /etc/ssl/openssl.cnf
sudo sed -i 's/^# fips = fips_sect/fips = fips_sect/' /etc/ssl/openssl.cnf

# Vérifier
openssl list -providers | grep -A2 fips
# Attendu :
#   fips
#     name: OpenSSL FIPS Provider
#     status: active
```

### 7.4 PBKDF2 et les seuils FIPS

OpenSSL 3.x FIPS provider applique les seuils NIST SP 800-132 § 5 sur PBKDF2 :

- mot de passe **≥ 14 octets**
- salt **≥ 16 octets** (128 bits)
- itérations ≥ 1000

Les vecteurs KAT du fichier `kat/fhsm_kat_vectors.c` ont été ajustés en conséquence (`"passwordPASSWORDpassword"` / `"saltSALTsaltSALTsalt"` à 200 000 itérations). Tout vecteur PBKDF2 ajouté ultérieurement doit respecter ces seuils sous peine de faire échouer la self-test FIPS.

### 7.5 Variable `FHSM_INTEGRITY_ALLOW_UNSIGNED`

Cette variable d'environnement bypasse `fhsm_integrity_verify()` **uniquement** si la section `.fhsm_digest` est entièrement nulle (build de développement non signé). Sur un build signé (digest non-nul), la variable est ignorée.

**Cas d'usage légitime :** debug d'un build développeur entre `make` et `make integrity`.

**Strictement interdit en production / sur build certifié.** L'opérateur de la TOE confirme à la livraison que la variable n'est définie nulle part dans `/etc/environment`, `/etc/profile.d/`, systemd unit files, ou cgroups :

```bash
sudo grep -r FHSM_INTEGRITY_ALLOW_UNSIGNED /etc/ /lib/systemd/ /usr/lib/systemd/ || \
    echo "OK : variable absente du PATH système"
```

### 7.6 Diagnostic : harnais KAT externalisé

`fhsm_kat_results()` est exporté (`visibility=default`) pour permettre à un harnais externe de lire le rapport KAT après `C_Initialize`, **sans** exposer de matière clé. Exemple d'utilisation à des fins de diagnostic uniquement :

```c
const fhsm_kat_result_t *r = fhsm_kat_results(&n);
for (size_t i = 0; i < n; ++i)
    printf("%-20s %s\n", r[i].algorithm, r[i].passed ? "PASS" : "FAIL");
```

Le binaire de référence (`tests/kat_report.c`) est livré dans la distribution. En production, le rapport est aussi écrit dans le journal d'audit sous l'événement `FHSM_EV_KAT_REPORT` avec une signature HMAC du chaînage — pas besoin d'appeler le harnais.

### 7.7 Compatibilité ABI PKCS#11

Le binding C des structures PKCS#11 utilise `unsigned char` (= `CK_BYTE`) pour chaque champ d'un `CK_VERSION` (1 octet par champ, total 2 octets). Tout code utilisant `unsigned short` (2 octets/champ) provoque un décalage de 2 octets sur tous les champs en aval (`manufacturerID`, `libraryDescription`, etc.), avec pour effet visible que :

- `pkcs11-tool --show-info` affiche `Cryptoki version X.0` au lieu de `X.Y`
- les champs ASCII apparaissent vides parce qu'ils débutent par `\x00`

Cette règle est appliquée par revue de code (CC EAL4+ ALC_DVS.1 § procédure de revue) sur tout PR touchant `src/fhsm_pkcs11.c`.

## 8. Validation cryptographique end-to-end

Cette section décrit la procédure de vérification cryptographique opérationnelle : prouver, par interopérabilité avec une implémentation tierce, que le module produit des artefacts cryptographiques conformes aux standards. C'est l'équivalent du *Functional Acceptance Test* avant mise en production.

### 8.1 Test ECDSA-SHA256 : signature HSM, vérification OpenSSL externe

```bash
# 1. Génération de la paire EC P-256
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --slot 0 --login --pin "$USER_PIN" \
    --keypairgen --key-type EC:secp256r1 --label "val-ecdsa" --id 03

# 2. Signature du message
echo -n "operational validation test" > /tmp/msg.bin
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --slot 0 --login --pin "$USER_PIN" \
    --sign --mechanism ECDSA-SHA256 \
    --input-file /tmp/msg.bin --output-file /tmp/sig.bin \
    --id 03

# 3. Export de la clé publique
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --slot 0 --login --pin "$USER_PIN" \
    --read-object --type pubkey --id 03 \
    --output-file /tmp/pub.der

# 4. Validation par OpenSSL externe (provider default explicite car la
#    config FIPS-only ne charge pas le store loader)
sudo openssl pkeyutl -provider default -verify \
    -pubin -inkey /tmp/pub.der -keyform DER \
    -rawin -in /tmp/msg.bin -sigfile /tmp/sig.bin \
    -digest sha256

# Attendu : "Signature Verified Successfully"
```

### 8.2 Test RSA-PKCS-OAEP : chiffrement OpenSSL externe, déchiffrement HSM

Ce test prouve que la clé privée n'a jamais quitté le HSM en clair et que le module peut consommer un ciphertext produit ailleurs.

```bash
# 1. Génération de la paire RSA-2048
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --slot 0 --login --pin "$USER_PIN" \
    --keypairgen --key-type rsa:2048 --label "val-rsa" --id 04

# 2. Export de la clé publique
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --slot 0 --login --pin "$USER_PIN" \
    --read-object --type pubkey --id 04 \
    --output-file /tmp/pub-rsa.der

# 3. OpenSSL chiffre un payload avec RSA-OAEP-SHA256
echo -n "ultra-secret-payload" > /tmp/plain.bin
openssl pkeyutl -provider default -encrypt \
    -pubin -inkey /tmp/pub-rsa.der -keyform DER \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 \
    -in /tmp/plain.bin -out /tmp/ct.bin

# 4. Le HSM déchiffre
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --slot 0 --login --pin "$USER_PIN" \
    --decrypt --mechanism RSA-PKCS-OAEP --hash-algorithm SHA-256 \
    --input-file /tmp/ct.bin --output-file /tmp/recovered.bin \
    --id 04

# 5. Le plaintext doit être identique
sudo cmp /tmp/plain.bin /tmp/recovered.bin && echo "ROUND-TRIP OK"
```

### 8.3 Critères d'acceptation

Le module est *opérationnellement validé* quand **tous** les critères suivants sont vrais simultanément :

1. `pkcs11-tool --show-info` affiche `Cryptoki version 3.2 / Manufacturer FreeHSM C (FIPS 140-3)`.
2. `pkcs11-tool --list-mechanisms` énumère au moins les 17 mécanismes FIPS-approved wired.
3. Le test §8.1 affiche `Signature Verified Successfully` — preuve qu'un tiers indépendant accepte la signature ECDSA produite par le module.
4. Le test §8.2 affiche `ROUND-TRIP OK` — preuve que la clé privée RSA reste interne au HSM et que le module déchiffre correctement un input externe.
5. `make integrity` rapporte un digest non-nul (= 32 octets hex) dans la section `.fhsm_digest`.
6. `fhsm_kat_results()` après `C_Initialize` rapporte `passed=1` pour les 15 KAT (6 smoke + 9 CAVP SHA-256).
7. Le journal d'audit contient des entrées `module_init/login_ok/sign/encrypt/decrypt` avec chaîne HMAC intacte (vérifiable par `freehsm-audit verify`).

### 8.4 Suite automatisée

Le script `tests/full_crypto_pkcs11.sh` automatise §8.1, §8.2 et étend à AES-GCM, AES-CMAC, SHA-{256,384,512}, HMAC-SHA-256. Lancer :

```bash
sudo install -m 755 tests/full_crypto_pkcs11.sh /tmp/fc.sh
sudo bash /tmp/fc.sh
```

Sortie attendue :
```
SUMMARY : N / N assertions PASS
```

Toute assertion `FAIL` doit être documentée et résolue avant la mise en production. Le préservé `tokens_dir` (path affiché en cas d'échec) permet d'inspecter l'état post-test pour diagnostic.

## 9. Désinstallation

```bash
sudo systemctl stop freehsm-bound-service
sudo shred -uvz /var/lib/freehsm/tokens/*.tok
sudo shred -uvz /var/lib/freehsm/audit/*.audit.log
sudo shred -uvz /var/lib/freehsm/kek/*.kek
sudo rm /opt/freehsm/lib/libfreehsm-fips.so /opt/freehsm/etc/freehsm.conf
sudo rmdir /opt/freehsm/{lib,etc,bin}
sudo userdel freehsm
sudo rm -rf /var/lib/freehsm
```

`shred` est suffisant sur ext4/xfs sans copy-on-write. Sur btrfs / ZFS, faire en plus un trim ou rotation de clé de volume.
