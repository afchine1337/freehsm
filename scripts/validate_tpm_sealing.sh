#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
#
# validate_tpm_sealing.sh --- #109 against a REAL TPM 2.0.
#
# WHY THIS EXISTS
# ---------------
# tests/test_tpm drives the module against tests/tpm2-stub.sh, a shell script
# that performs no cryptography. It proves our side of the subprocess boundary
# and nothing about PCR binding, the sealing crypto, or tamper detection --
# there is no TPM behind the stub. docs/ROADMAP.md says so in as many words.
# This script is what closes that gap, and until it has been run and its output
# recorded, "#109 validated" is not a claim anyone should make.
#
# A software-emulated TPM 2.0 (swtpm, or a hypervisor's vTPM) is adequate here
# and in one respect better than discrete hardware: the PCR-change scenario
# needs PCRs 0-7 to move and then return, and in a VM that is an extend plus a
# reboot rather than a firmware update on a machine you depend on. What an
# emulated TPM cannot tell you is anything about the hardware root of trust.
# That is not what #109 is about.
#
# PHASES
# ------
#   setup    provision the parent handle, build, create a sealed token, log in
#   break    extend a PCR, then log in with the CORRECT PIN 8 times
#   recover  run AFTER A REBOOT (which restores PCRs 0-7 to their boot values)
#
# Usage:  sh scripts/validate_tpm_sealing.sh setup
#         sh scripts/validate_tpm_sealing.sh break
#         (reboot)
#         sh scripts/validate_tpm_sealing.sh recover

set -u

STATE_DIR="${FHSM_TPM_VALIDATION_DIR:-$HOME/.freehsm-tpm-validation}"
TOKEN="$STATE_DIR/validation.tok"
SO_PIN="00000000"
USER_PIN="user0000"
PROBE="./tests/tpm_hw_probe"
PARENT_HANDLE="0x81010001"          # must match TPM_PARENT_HANDLE in src/fhsm_tpm.c

CKR_OK=0x00000000
CKR_DEVICE_ERROR=0x00000030
CKR_PIN_INCORRECT=0x000000a0

say()  { printf '%s\n' "$*"; }
head_() { printf '\n=== %s\n' "$*"; }
die()  { printf 'ARRET: %s\n' "$*" >&2; exit 2; }

need_tpm() {
    [ -e /dev/tpmrm0 ] || die "/dev/tpmrm0 absent -- pas de TPM visible (ni resource manager)"
    command -v tpm2 >/dev/null || die "tpm2-tools absent (apt install tpm2-tools)"

    # Le noeud existe : est-il LISIBLE par cet utilisateur ? Sur Debian il
    # appartient au groupe tss, et un utilisateur hors de ce groupe voit toutes
    # les commandes echouer -- ce qui, si on avale stderr, ressemble a "l'objet
    # n'existe pas". Distinguer les deux ici, une fois, plutot que de laisser
    # chaque commande suivante mentir.
    if ! err=$(tpm2 getcap properties-fixed 2>&1 >/dev/null); then
        say "  ECHEC de la premiere commande TPM. Sortie brute :"
        printf '%s\n' "$err" | sed 's/^/    /'
        say ""
        say "  Piste la plus frequente : les droits sur /dev/tpmrm0."
        ls -l /dev/tpmrm0 2>/dev/null | sed 's/^/    /'
        say "    utilisateur courant : $(id -un), groupes : $(id -Gn)"
        say "    si le groupe 'tss' manque :  sudo usermod -aG tss $(id -un)"
        say "    puis ouvrir une nouvelle session (les groupes ne changent pas a chaud)."
        say "    ou, pour un essai immediat : relancer ce script avec sudo."
        die "impossible de dialoguer avec le TPM"
    fi
    tpm2 startup -c >/dev/null 2>&1 || say "  note: 'tpm2 startup -c' non nul (normal si le TPM est deja demarre)"
    say "  TPM accessible : /dev/tpmrm0, tpm2-tools operationnel"
}

# The module seals under a persistent primary at PARENT_HANDLE. Nothing in the
# module creates it and, until this script existed, nothing in the docs told the
# operator to. Without it every seal fails with the parent handle missing.
# Tente une commande en conservant sa sortie d'erreur. Affiche tout en cas
# d'echec : un script de diagnostic qui avale stderr ne diagnostique rien.
try_cmd() {
    _label=$1; shift
    if _err=$("$@" 2>&1 >/dev/null); then
        return 0
    fi
    say "    $_label a echoue :"
    printf '%s\n' "$_err" | sed 's/^/      /'
    return 1
}

need_parent() {
    # Lister les handles persistants plutot que sonder le notre : la difference
    # entre "absent" et "je n'ai pas pu regarder" doit etre visible.
    if ! handles=$(tpm2 getcap handles-persistent 2>&1); then
        say "  impossible de lister les handles persistants :"
        printf '%s\n' "$handles" | sed 's/^/    /'
        die "le TPM repond aux capacites mais pas aux handles -- etat inattendu"
    fi
    if printf '%s' "$handles" | grep -qi "$PARENT_HANDLE"; then
        say "  cle primaire persistante $PARENT_HANDLE : presente"
        return 0
    fi
    say "  cle primaire persistante $PARENT_HANDLE : absente"
    if [ -n "$handles" ]; then
        say "  handles persistants actuellement definis :"
        printf '%s\n' "$handles" | sed 's/^/    /'
    else
        say "  aucun handle persistant defini sur ce TPM"
    fi
    say "  --> provisionnement (modifie l'etat du TPM ; sur un TPM emule, sans consequence)"
    printf '      continuer ? [o/N] '
    read -r ans
    case "$ans" in o|O|y|Y) ;; *) die "provisionnement refuse" ;; esac

    tmpctx=$(mktemp) || die "mktemp"
    # ECC d'abord, RSA en repli : certains TPM emules n'exposent pas les
    # courbes NIST par defaut, et l'algorithme de la primaire nous est
    # indifferent -- elle ne sert que de parent au scellement.
    created=0
    if try_cmd "tpm2 createprimary (ECC)" \
            tpm2 createprimary -C o -g sha256 -G ecc -c "$tmpctx"; then
        created=1; say "    primaire ECC creee"
    elif try_cmd "tpm2 createprimary (RSA2048, repli)" \
            tpm2 createprimary -C o -g sha256 -G rsa2048 -c "$tmpctx"; then
        created=1; say "    primaire RSA-2048 creee (repli)"
    fi
    if [ "$created" -eq 0 ]; then
        rm -f "$tmpctx"
        say ""
        say "  Deux causes usuelles, dans l'ordre de frequence :"
        say "    1. l'autorisation owner n'est pas vide. Verifier :"
        say "         tpm2 changeauth -c owner        (si tu connais l'ancienne)"
        say "       ou, sur un TPM emule jetable, remettre a zero :"
        say "         tpm2 clear -c platform"
        say "    2. le TPM ne supporte pas l'algorithme demande. Voir :"
        say "         tpm2 getcap algorithms"
        die "creation de la cle primaire impossible"
    fi
    if ! try_cmd "tpm2 evictcontrol" \
            tpm2 evictcontrol -C o -c "$tmpctx" "$PARENT_HANDLE"; then
        rm -f "$tmpctx"
        say "    (autorisation owner non vide, ou handle deja occupe)"
        die "persistance de la cle primaire impossible"
    fi
    rm -f "$tmpctx"
    say "  cle primaire persistante $PARENT_HANDLE : creee"
}

need_probe() {
    [ -x "$PROBE" ] || die "$PROBE absent -- lancer d'abord: make tests/tpm_hw_probe"
}

pcr_digest() { tpm2 pcrread sha256:0,1,2,3,4,5,6,7 2>/dev/null | tr -d ' \n'; }

case "${1:-}" in

setup)
    head_ "Phase 1 --- environnement"
    need_tpm
    need_parent
    need_probe
    mkdir -p "$STATE_DIR" || die "mkdir $STATE_DIR"
    rm -f "$TOKEN" "$TOKEN.tpm"
    pcr_digest > "$STATE_DIR/pcr-at-seal.txt"
    say "  empreinte PCR 0-7 enregistree"

    head_ "Phase 2 --- creation d'un token scelle au TPM"
    FHSM_TPM_SEALING=1 FHSM_INTEGRITY_ALLOW_UNSIGNED=1 \
        "$PROBE" init "$TOKEN" "$SO_PIN" "$USER_PIN" "$CKR_OK" || die "creation du token"
    [ -f "$TOKEN.tpm" ] || die "le compagnon $TOKEN.tpm n'a pas ete ecrit -- le scellement n'a pas eu lieu"
    say "  compagnon scelle present : $(wc -c < "$TOKEN.tpm") octets"

    head_ "Phase 3 --- la DEK ne doit avoir touche aucun disque (#109.1)"
    if [ -d /var/lib/freehsm/tpm ]; then
        n=$(find /var/lib/freehsm/tpm -type f 2>/dev/null | wc -l)
        if [ "$n" -eq 0 ]; then
            say "  /var/lib/freehsm/tpm existe et est vide : conforme"
        else
            say "  ATTENTION : $n fichier(s) dans /var/lib/freehsm/tpm --"
            find /var/lib/freehsm/tpm -type f 2>/dev/null | sed 's/^/    /'
            say "  avant le correctif memfd, la DEK y etait ecrite en clair. A examiner."
        fi
    else
        say "  /var/lib/freehsm/tpm inexistant : conforme (plus rien n'y est ecrit)"
    fi

    head_ "Phase 4 --- connexion avec un TPM sain"
    FHSM_TPM_SEALING=1 FHSM_INTEGRITY_ALLOW_UNSIGNED=1 \
        "$PROBE" login-so "$TOKEN" "$SO_PIN" "$CKR_OK" || die "la connexion echoue alors que le TPM est sain"
    say "  connexion OK, descellement verifie"

    say ""
    say "Phase 'setup' terminee. Enchainer avec :  sh $0 break"
    ;;

break)
    head_ "Phase 5 --- deplacement d'un PCR (equivaut a une mise a jour de firmware)"
    need_tpm; need_probe
    [ -f "$TOKEN" ] || die "token absent -- lancer 'setup' d'abord"
    before=$(pcr_digest)
    tpm2 pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000001 \
        >/dev/null 2>&1 || die "tpm2 pcrextend a echoue"
    after=$(pcr_digest)
    [ "$before" != "$after" ] || die "le PCR n'a pas bouge -- le test ne prouverait rien"
    say "  PCR 7 etendu, l'empreinte 0-7 a change"

    head_ "Phase 6 --- 8 connexions avec le BON PIN, TPM casse"
    say "  attendu a chaque fois : CKR_DEVICE_ERROR (0x30), jamais PIN_INCORRECT,"
    say "  PIN_LOCKED ni PIN_THROTTLED. FHSM_PIN_MAX_FAILED vaut 5 : avant le"
    say "  correctif, le token etait verrouille definitivement des la 5e."
    i=1; bad=0
    while [ $i -le 8 ]; do
        printf '  tentative %d : ' $i
        FHSM_TPM_SEALING=1 FHSM_INTEGRITY_ALLOW_UNSIGNED=1 \
            "$PROBE" login-so "$TOKEN" "$SO_PIN" "$CKR_DEVICE_ERROR" || bad=$((bad+1))
        i=$((i+1))
    done
    [ "$bad" -eq 0 ] || die "$bad tentative(s) n'ont pas renvoye CKR_DEVICE_ERROR"
    say "  les 8 tentatives renvoient CKR_DEVICE_ERROR"

    say ""
    say "Phase 'break' terminee."
    say "REDEMARRER LA MACHINE, puis :  sh $0 recover"
    say "(les PCR 0-7 ne se reinitialisent qu'au demarrage -- c'est le propre du boot mesure)"
    ;;

recover)
    head_ "Phase 7 --- apres redemarrage : les PCR sont revenus"
    need_tpm; need_probe
    [ -f "$TOKEN" ] || die "token absent"
    [ -f "$STATE_DIR/pcr-at-seal.txt" ] || die "empreinte de reference absente"
    if [ "$(pcr_digest)" = "$(cat "$STATE_DIR/pcr-at-seal.txt")" ]; then
        say "  empreinte PCR 0-7 identique a celle du scellement"
    else
        say "  ATTENTION : l'empreinte differe encore de celle du scellement."
        say "  Le descellement echouera legitimement. As-tu bien redemarre ?"
    fi

    head_ "Phase 8 --- le token doit se rouvrir : PAS de verrouillage (#109.3)"
    FHSM_TPM_SEALING=1 FHSM_INTEGRITY_ALLOW_UNSIGNED=1 \
        "$PROBE" login-so "$TOKEN" "$SO_PIN" "$CKR_OK" \
        || die "LE TOKEN NE S'OUVRE PLUS -- c'est exactement le deni de service que #109 corrige"
    say "  le token s'ouvre normalement apres 8 echecs TPM : aucun verrouillage"

    head_ "Phase 9 --- un vrai mauvais PIN doit toujours compter"
    say "  retirer le compteur du chemin TPM ne doit pas avoir retire le compteur."
    FHSM_TPM_SEALING=1 FHSM_INTEGRITY_ALLOW_UNSIGNED=1 \
        "$PROBE" login-so "$TOKEN" "mauvaisPIN" "$CKR_PIN_INCORRECT" \
        || die "un mauvais PIN n'est plus rejete comme tel"
    say "  mauvais PIN toujours rejete en CKR_PIN_INCORRECT"

    say ""
    say "======================================================================"
    say "  #109 valide sur TPM reel."
    say "  Coller cette sortie dans docs/PKCS11_CHECK_FINDINGS.md ou ROADMAP,"
    say "  et retirer la mention 'jamais valide sur du vrai materiel'."
    say "======================================================================"
    ;;

*)
    say "usage: $0 setup | break | recover"
    say ""
    say "  setup    provisionne, cree un token scelle, verifie la connexion saine"
    say "  break    deplace un PCR, puis 8 connexions au bon PIN"
    say "  (redemarrer)"
    say "  recover  verifie l'absence de verrouillage et que le compteur de PIN vit encore"
    exit 2
    ;;
esac
