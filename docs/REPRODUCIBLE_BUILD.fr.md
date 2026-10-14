# FreeHSM C — Build reproductible

> English version: [`REPRODUCIBLE_BUILD.md`](REPRODUCIBLE_BUILD.md). In case of discrepancy, the English version prevails.

Ce document décrit comment reproduire le `libfreehsm.so` **bit-pour-bit identique** livré dans une release donnée. La reproductibilité est requise par **CC EAL4+ ALC_CMC.4** et est l'attente standard des laboratoires FIPS 140-3.

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
| Section `.comment` (version toolchain)   | digest de l'image de base et snapshot apt (§6) |
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
sha256sum libfreehsm.so   # comparer au digest publié
```

Toute dérive de version de `gcc`, `binutils` ou `libc6-dev` fera diverger le digest. La section `.comment` du `.so` produit embarque la chaîne de version du toolchain ; utiliser `readelf -p .comment libfreehsm.so` pour inspecter.

## 5. Intégration CI

Trois workflows touchent à la reproductibilité, et ils doivent concorder :

| workflow | construit dans | fait |
|---|---|---|
| `baseline.yml` (à la demande) | `ghcr.io/…/freehsm-c-build:debian13-<date du snapshot>` | construit et signe deux fois, refuse si les deux diffèrent, et donne `dist/refs/vX.Y.Z.sha256` à commiter |
| `release.yml` (sur un tag) | la même image | refuse de publier un build qui ne correspond pas à `dist/refs/` |
| `dist-verify.yml` (sur un tag, ou à la demande) | une image reconstruite à neuf depuis `Dockerfile.build` | `make dist-verify` : le chemin d'un tiers, comparé à `dist/refs/` |

L'image ghcr est elle-même construite depuis `Dockerfile.build`
(`build-image.yml`, dès que ce fichier change sur `main`). Les deux premières
lignes mesurent donc l'image de release ; la troisième mesure si quelqu'un
d'autre, partant du seul dépôt, obtient les mêmes octets.

De v2.2.0 à v2.3.1, ce n'était pas le cas : `dist-verify` a échoué sur chaque
tag pendant que `release.yml` passait. `Dockerfile.build` désignait
`debian:trixie-slim` par son tag et installait ce qu'apt proposait le jour même
: l'image ghcr gardait la toolchain du jour de sa construction — les
reconstructions suivantes venaient du cache de couches d'Actions — et chaque
build à neuf suivait les mises à jour de Debian. Les binaires publiés
correspondaient toujours à leurs références ; une reconstruction indépendante
n'aurait pas pu les retrouver. Épinglé le 2026-10-14, pour v2.4.0 (§6).

## 6. Mise à jour de l'environnement de build

`Dockerfile.build` fixe la toolchain par deux épingles, et rien d'autre ne doit
la faire bouger :

- l'image de base, `debian:trixie-AAAAMMJJ-slim@sha256:…` — le digest de
  l'index multi-architecture d'un tag daté, lu sur Docker Hub ;
- `ARG SNAPSHOT`, un horodatage `snapshot.debian.org` : apt lit l'archive telle
  qu'elle était à cet instant, et toutes les versions de paquets en découlent.

Pour les déplacer, lors d'une mise à jour de la toolchain ou d'OpenSSL :

1. Choisir un tag `trixie-*-slim` daté et son digest d'index, et un `SNAPSHOT`
   à cette date ou après. Changer les deux dans `Dockerfile.build` dans un seul
   commit.
2. La fusion sur `main` reconstruit l'image ghcr (`build-image.yml`). Vérifier
   que la CI est verte sur cette image.
3. Monter la version : une nouvelle toolchain donne de nouveaux octets, et une
   référence n'appartient qu'à une version.
4. Lancer `baseline.yml`, commiter la référence, puis lancer `dist-verify.yml`
   avec `target: head` sur ce commit : il doit concorder avec la référence
   avant le tag, pas après.
5. Indiquer les nouvelles épingles dans les notes de version.

## 7. Vérification par un évaluateur

Pour les évaluateurs CMVP / CESTI :

1. Télécharger l'archive source publiée : `freehsm-c-src.tar.xz` (et son sidecar `.sha256`).
2. Vérifier que le digest d'archive correspond aux release notes.
3. Lancer `make dist-verify` ; le SHA-256 du `libfreehsm.so` produit DOIT correspondre à celui des release notes et à celui embarqué dans `fhsm_module_integrity_digest[]` signé (voir `FIPS_140_3.fr.md` §6.1).
4. Optionnellement, lancer le même processus sur un second host (distribution différente, vendor CPU différent) pour confirmer l'indépendance du host.

Une correspondance réussie ferme l'exigence de preuve **ALC_CMC.4** pour la release.
