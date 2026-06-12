# FreeHSM C — Build reproductible

> English version: [`REPRODUCIBLE_BUILD.md`](REPRODUCIBLE_BUILD.md). In case of discrepancy, the English version prevails.

Ce document décrit comment reproduire le `libfreehsm-fips.so` **bit-pour-bit identique** livré dans une release donnée. La reproductibilité est requise par **CC EAL4+ ALC_CMC.4** et est l'attente standard des laboratoires FIPS 140-3.

## 1. Vérification rapide

```bash
git clone https://github.com/freehsm/freehsm-c.git
cd freehsm-c
git checkout v1.0.0
make dist-verify
```

`dist-verify` effectue deux builds propres dans l'image Docker épinglée et vérifie que le SHA-256 des deux artefacts est identique.

```
[verify] run A digest : 4f9a3d2c...e15a8b04
[verify] run B digest : 4f9a3d2c...e15a8b04
[verify] OK : builds are bit-identical.
```

## 2. Ce qui est épinglé

| Couche                  | Mécanisme d'épinglage                          |
|-------------------------|------------------------------------------------|
| Image OS de base        | `debian@sha256:b8084b1a...` (digest, pas tag)  |
| Toolchain               | Versions `apt` exactes (`gcc=4:12.2.0-3`, etc.)|
| OpenSSL                 | Source tarball SHA-256 + version (`3.0.13`)    |
| `__DATE__` / `__TIME__` | `SOURCE_DATE_EPOCH=1735689600` + override `-D` |
| Build-id linker         | `-Wl,--build-id=none`                          |
| Archive tar             | `--mtime=@SOURCE_DATE_EPOCH --sort=name --owner=root` |
| Layout hash table       | `-Wl,--hash-style=gnu`                         |
| Seeds aléatoires gcc    | `-frandom-seed=fhsm-1.0.0-FIPS`                |
| Chemins absolus         | `-ffile-prefix-map=$(CURDIR)=`                 |

## 3. Sources de non-déterminisme éliminées

| Source                                  | Défense                                      |
|-----------------------------------------|----------------------------------------------|
| Macros `__DATE__`, `__TIME__`            | `-D__DATE__='"redacted"' -D__TIME__='"redacted"'` |
| Noms d'anonymous-namespace               | `-frandom-seed=fhsm-<version>`               |
| Chemins source dans DWARF / `__FILE__`   | `-ffile-prefix-map`, `-fdebug-prefix-map`    |
| `.note.gnu.build-id` (160 bits aléatoires) | `-Wl,--build-id=none`                      |
| Ordre des tables de hash                 | `-Wl,--hash-style=gnu --sort-common`         |
| Section `.comment` (version toolchain)   | épinglée via le digest de l'image Docker     |
| Timestamps des membres d'archive `ar`    | `SOURCE_DATE_EPOCH` honoré par binutils ≥ 2.27 |
| uid/gid dans `tar`                       | `--owner=root --group=root --numeric-owner` |
| Ordre des fichiers dans `tar`            | `--sort=name`                                |
| Headers étendus PAX (atime/ctime/mtime) | `--pax-option=delete=atime,delete=ctime,delete=mtime` |
| Collation dépendant de la locale        | `LC_ALL=C` dans l'image                      |

## 4. Reproduction manuelle (sans Docker)

Si votre environnement ne peut pas exécuter Docker (labo air-gappé), vous pouvez reproduire manuellement à condition de répliquer la toolchain :

```bash
export SOURCE_DATE_EPOCH=1735689600
export LC_ALL=C TZ=UTC
make clean
make
sha256sum libfreehsm-fips.so   # comparer au digest publié
```

Toute dérive de version de `gcc`, `binutils` ou `libc6-dev` fera diverger le digest. La section `.comment` du `.so` produit embarque la chaîne de version du toolchain ; utiliser `readelf -p .comment libfreehsm-fips.so` pour inspecter.

## 5. Intégration CI

```yaml
jobs:
  reproducibility:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - name: Build A
        run: make repro && mv libfreehsm-fips.so out/run-a.so
      - name: Build B (clean)
        run: docker volume prune -f && make repro
      - name: Assert byte-identical
        run: |
          a=$(sha256sum out/run-a.so | awk '{print $1}')
          b=$(sha256sum libfreehsm-fips.so | awk '{print $1}')
          test "$a" = "$b" || { echo "REPRO FAIL"; exit 1; }
```

La CI utilise `diffoscope` comme fallback quand les digests divergent, exposant les octets différents (noms de sections, offsets, hex dump).

## 6. Mise à jour de l'environnement de build

À chaque release qui exige une mise à jour de toolchain :

1. Mettre à jour `ARG OPENSSL_VERSION` et `ARG OPENSSL_SHA256` dans `Dockerfile.build`.
2. Mettre à jour les pins de version apt (lancer `scripts/freeze_apt_versions.sh` dans un container Debian propre).
3. Bumper `FHSM_VERSION_STRING` dans `include/fhsm_common.h`.
4. Lancer `make dist-verify` localement pour confirmer la reproductibilité sur la nouvelle toolchain.
5. Publier le nouveau digest d'image et le SHA-256 du `libfreehsm-fips.so` résultant dans les release notes.

## 7. Vérification par un évaluateur

Pour les évaluateurs CMVP / CESTI :

1. Télécharger l'archive source publiée : `freehsm-c-src.tar.xz` (et son sidecar `.sha256`).
2. Vérifier que le digest d'archive correspond aux release notes.
3. Lancer `make dist-verify` ; le SHA-256 du `libfreehsm-fips.so` produit DOIT correspondre à celui des release notes et à celui embarqué dans `fhsm_module_integrity_digest[]` signé (voir `FIPS_140_3.fr.md` §6.1).
4. Optionnellement, lancer le même processus sur un second host (distribution différente, vendor CPU différent) pour confirmer l'indépendance du host.

Une correspondance réussie ferme l'exigence de preuve **ALC_CMC.4** pour la release.
