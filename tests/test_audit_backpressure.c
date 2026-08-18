/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * The audit log's backpressure: what happens when an entry cannot be written.
 *
 * fhsm_audit.h has promised since it was written that "no security-relevant
 * action is allowed without a durable trace" and that a failed write latches
 * the module into ERROR. The code did call fhsm_state_latch_error on every
 * write failure -- but nothing had ever exercised it, because no log was ever
 * opened and fhsm_audit_event returned before reaching the write.
 *
 * A promise no test has ever made fail is a promise, not a control.
 *
 * Making a write fail without root: RLIMIT_FSIZE. Lowering it makes write(2)
 * return EFBIG past the limit and raises SIGXFSZ, which is ignored here. It is
 * not a full disk, but it fails at exactly the point a full disk fails -- the
 * write -- which is the path under test.
 */
#include "fhsm_audit.h"
#include "fhsm_common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-64s %s\n", what, cond ? "OK" : "ECHEC");
    if (!cond) g_fail++;
}

int main(void)
{
    printf("Contre-pression du journal d'audit\n\n");

    char dir[] = "/tmp/fhsm-audit-bp-XXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }

    char logp[512];
    snprintf(logp, sizeof logp, "%s/audit.log", dir);

    uint8_t key[32];
    fhsm_rv_t rv = fhsm_audit_key_provision(dir, key, NULL);
    ok(rv == FHSM_RV_OK, "la cle de chainage est provisionnee");

    rv = fhsm_audit_open(logp, FHSM_SLICE(key, sizeof key));
    ok(rv == FHSM_RV_OK, "le journal s'ouvre");

    /* --- une entree normale passe, et l'etat ne bouge pas --------------- */
    rv = fhsm_audit_event(FHSM_EV_MODULE_INIT, -1, -1, FHSM_ROLE_NONE,
                          FHSM_RV_OK, NULL);
    ok(rv == FHSM_RV_OK, "une entree s'ecrit normalement");
    ok(fhsm_state_get() != FHSM_STATE_ERROR,
       "  et le module n'est pas verrouille");

    struct stat st;
    ok(stat(logp, &st) == 0 && st.st_size > 0, "  le fichier a grossi");
    off_t before = st.st_size;

    /* --- on rend toute ecriture impossible ------------------------------ */
    signal(SIGXFSZ, SIG_IGN);
    struct rlimit rl;
    getrlimit(RLIMIT_FSIZE, &rl);
    struct rlimit small = { (rlim_t)before, rl.rlim_max };
    ok(setrlimit(RLIMIT_FSIZE, &small) == 0,
       "on abaisse RLIMIT_FSIZE a la taille actuelle du journal");

    rv = fhsm_audit_event(FHSM_EV_SIGN, -1, -1, FHSM_ROLE_USER,
                          FHSM_RV_OK, "alg", "essai", NULL);
    ok(rv != FHSM_RV_OK,
       "  l'entree suivante echoue au lieu de reussir en silence");
    ok(fhsm_state_get() == FHSM_STATE_ERROR,
       "  et le module est verrouille en ERREUR");

    /* Le point de tout l'exercice : ne pas signer sans trace. L'etat ERREUR
     * est irreversible, donc plus aucune operation pertinente pour la
     * securite ne passera jusqu'au redemarrage. */
    ok(fhsm_state_set(FHSM_STATE_INITIALIZED) != FHSM_RV_OK,
       "  et le verrou ne se releve pas par un simple changement d'etat");

    setrlimit(RLIMIT_FSIZE, &rl);
    fhsm_audit_close();

    /* --- ce qui reste sur le disque doit rester coherent ---------------- */
    ok(stat(logp, &st) == 0 && st.st_size == before,
       "le journal n'a pas ete allonge par l'ecriture ratee");

    char keyp[512]; snprintf(keyp, sizeof keyp, "%s/audit.key", dir);
    unlink(logp); unlink(keyp); rmdir(dir);

    printf("\n%s : %d echec(s)\n", g_fail ? "ECHEC" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
