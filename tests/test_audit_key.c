/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * fhsm_audit_key_provision() --- the key that chains the audit log.
 *
 * Scope, stated so nobody reads more into a green run than is there: this
 * covers the file-backed path, which is the default and what every host
 * without FHSM_TPM_SEALING will use. The sealed path goes through
 * fhsm_tpm_seal/unseal, which tests/test_tpm.c already exercises against
 * tests/tpm2-stub.sh through the -DFHSM_TPM_TEST_HOOKS seam -- and that stub
 * performs no cryptography, so it says nothing about PCR binding either.
 *
 * What is being checked is the part that is ours: which file, with which
 * permissions, what happens on the second call, and what happens when the
 * file on disk is not what it should be.
 */
#include "fhsm_audit.h"
#include "fhsm_common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "ECHEC");
    if (!cond) g_fail++;
}

static char g_dir[] = "/tmp/fhsm-audit-key-XXXXXX";
static char g_key[512];

static void kill_key(void) { unlink(g_key); }

int main(void)
{
    printf("Cle de chainage du journal d'audit\n\n");

    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 2; }
    snprintf(g_key, sizeof g_key, "%s/audit.key", g_dir);

    uint8_t a[32], b[32];
    int sealed = -1;

    /* --- premiere utilisation : la cle est creee ------------------------- */
    memset(a, 0, sizeof a);
    fhsm_rv_t rv = fhsm_audit_key_provision(g_dir, a, &sealed);
    ok(rv == FHSM_RV_OK, "la premiere provision reussit");
    ok(sealed == 0, "  et signale que la cle n'est pas scellee (pas de TPM ici)");

    {
        int nonzero = 0;
        for (size_t i = 0; i < sizeof a; i++) if (a[i]) nonzero = 1;
        ok(nonzero, "  la cle n'est pas nulle");
    }

    struct stat st;
    ok(stat(g_key, &st) == 0 && st.st_size == 32,
       "  le fichier audit.key existe et fait 32 octets");
    ok((st.st_mode & (S_IRWXG | S_IRWXO)) == 0,
       "  et n'est lisible par personne d'autre que son proprietaire");

    /* --- deuxieme appel : la meme cle, sinon la chaine casse au demarrage
     *     suivant et toutes les entrees precedentes deviennent invalides --- */
    memset(b, 0, sizeof b);
    rv = fhsm_audit_key_provision(g_dir, b, &sealed);
    ok(rv == FHSM_RV_OK && memcmp(a, b, 32) == 0,
       "un second appel rend exactement la meme cle");

    /* --- deux provisions successives dans deux repertoires differents
     *     doivent donner deux cles differentes ---------------------------- */
    {
        char other[] = "/tmp/fhsm-audit-key2-XXXXXX";
        uint8_t c[32];
        if (mkdtemp(other)) {
            rv = fhsm_audit_key_provision(other, c, NULL);
            ok(rv == FHSM_RV_OK && memcmp(a, c, 32) != 0,
               "un autre repertoire recoit une cle differente");
            char p[512]; snprintf(p, sizeof p, "%s/audit.key", other);
            unlink(p); rmdir(other);
        } else {
            ok(0, "un autre repertoire recoit une cle differente");
        }
    }

    /* --- une cle que le groupe peut lire est refusee ---------------------
     * Continuer produirait un journal qui a l'air authentifie et ne l'est
     * pas -- pire que pas de journal, parce que le premier invite a la
     * confiance. */
    ok(chmod(g_key, 0640) == 0, "on rend la cle lisible par le groupe");
    rv = fhsm_audit_key_provision(g_dir, b, NULL);
    ok(rv != FHSM_RV_OK, "  la provision refuse une cle lisible par le groupe");
    ok(chmod(g_key, 0600) == 0, "on remet 0600");
    rv = fhsm_audit_key_provision(g_dir, b, NULL);
    ok(rv == FHSM_RV_OK && memcmp(a, b, 32) == 0, "  et elle redevient acceptable");

    /* --- une cle tronquee est refusee, pas completee --------------------- */
    {
        kill_key();
        int fd = open(g_key, O_WRONLY | O_CREAT | O_EXCL, 0600);
        ok(fd >= 0 && write(fd, a, 16) == 16, "on ecrit une cle tronquee de 16 octets");
        if (fd >= 0) close(fd);
        rv = fhsm_audit_key_provision(g_dir, b, NULL);
        ok(rv != FHSM_RV_OK, "  la provision refuse une cle de mauvaise taille");
    }

    /* --- arguments ------------------------------------------------------- */
    ok(fhsm_audit_key_provision(NULL, b, NULL) == FHSM_RV_ARGUMENTS_BAD,
       "un repertoire absent est refuse");
    ok(fhsm_audit_key_provision(g_dir, NULL, NULL) == FHSM_RV_ARGUMENTS_BAD,
       "une sortie absente est refusee");
    {
        char loooong[600];
        memset(loooong, 'x', sizeof loooong - 1); loooong[sizeof loooong - 1] = 0;
        ok(fhsm_audit_key_provision(loooong, b, NULL) == FHSM_RV_ARGUMENTS_BAD,
           "un chemin trop long est refuse plutot que tronque");
    }

    kill_key();
    rmdir(g_dir);

    printf("\n%s : %d echec(s)\n", g_fail ? "ECHEC" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
