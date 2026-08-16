/* Le chemin pre-hache doit etre indiscernable du chemin one-shot.
 * S'il ne l'est pas, une signature produite en flux ne verifie contre rien --
 * et le defaut ne se voit qu'a l'usage, sur un fichier trop gros pour le test. */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "fhsm_composite.h"

#define ALG FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
static int fails = 0;
static void ck(const char *w, int c) { printf("  [%s] %s\n", c?"PASS":"FAIL", w); if(!c) fails++; }

/* SHA-512 par blocs, comme le ferait C_SignUpdate. */
static int stream_digest(const uint8_t *m, size_t n, size_t chunk, uint8_t *out) {
    EVP_MD *md = EVP_MD_fetch(NULL, fhsm_composite_ph_name(ALG), NULL);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned int l = 0;
    int ok = md && c && EVP_DigestInit_ex(c, md, NULL) == 1;
    for (size_t off = 0; ok && off < n; off += chunk) {
        size_t k = (n - off < chunk) ? n - off : chunk;
        ok = EVP_DigestUpdate(c, m + off, k) == 1;
    }
    ok = ok && EVP_DigestFinal_ex(c, out, &l) == 1 && l == 64;
    EVP_MD_CTX_free(c); EVP_MD_free(md);
    return ok;
}

int main(void) {
    static uint8_t priv[FHSM_COMPOSITE_PRIV_MAX], pub[FHSM_COMPOSITE_PUB_MAX];
    size_t pl = sizeof priv, bl = sizeof pub;
    if (fhsm_composite_keygen(ALG, priv, &pl, pub, &bl) != FHSM_RV_OK) {
        printf("keygen a echoue\n"); return 1;
    }

    static uint8_t msg[300000];
    for (size_t i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 31 + 7);
    const uint8_t ctx[] = { 'f','h','s','m','-','s','i','g','n' };

    printf("== M' : les deux chemins ==\n");
    for (size_t cl = 0; cl <= 9; cl += 9) {
        uint8_t a[512], b[512]; size_t la = sizeof a, lb = sizeof b;
        uint8_t ph[64];
        ck("digest par blocs de 4096 calcule", stream_digest(msg, sizeof msg, 4096, ph));
        fhsm_rv_t r1 = fhsm_composite_mprime(ALG, msg, sizeof msg, cl?ctx:NULL, cl, a, &la);
        fhsm_rv_t r2 = fhsm_composite_mprime_prehashed(ALG, ph, 64, cl?ctx:NULL, cl, b, &lb);
        char m[80]; snprintf(m, sizeof m, "M' identique octet pour octet (ctx=%zu)", cl);
        ck(m, r1 == FHSM_RV_OK && r2 == FHSM_RV_OK && la == lb && memcmp(a, b, la) == 0);
    }

    printf("\n== signatures interchangeables ==\n");
    {
        uint8_t ph[64];
        stream_digest(msg, sizeof msg, 1, ph);   /* octet par octet : pire cas */
        static uint8_t s1[FHSM_COMPOSITE_SIG_MAX], s2[FHSM_COMPOSITE_SIG_MAX];
        size_t l1 = sizeof s1, l2 = sizeof s2;
        ck("signature one-shot",
           fhsm_composite_sign(ALG, priv, pl, msg, sizeof msg, ctx, 9, s1, &l1) == FHSM_RV_OK);
        ck("signature pre-hachee",
           fhsm_composite_sign_prehashed(ALG, priv, pl, ph, 64, ctx, 9, s2, &l2) == FHSM_RV_OK);
        /* ML-DSA est randomise : les octets different, c'est attendu. Ce qui
         * doit tenir, c'est la verification croisee dans les deux sens. */
        ck("one-shot verifiee par le chemin pre-hache",
           fhsm_composite_verify_prehashed(ALG, pub, bl, ph, 64, ctx, 9, s1, l1) == FHSM_RV_OK);
        ck("pre-hachee verifiee par le chemin one-shot",
           fhsm_composite_verify(ALG, pub, bl, msg, sizeof msg, ctx, 9, s2, l2) == FHSM_RV_OK);
        ck("un contexte different casse la verification",
           fhsm_composite_verify(ALG, pub, bl, msg, sizeof msg, ctx, 8, s2, l2) != FHSM_RV_OK);
        ph[0] ^= 1;
        ck("un digest modifie casse la verification",
           fhsm_composite_verify_prehashed(ALG, pub, bl, ph, 64, ctx, 9, s1, l1) != FHSM_RV_OK);
    }

    printf("\n== longueur de pre-hachage refusee, pas rattrapee ==\n");
    {
        uint8_t ph[64] = {0}, out[512]; size_t lo = sizeof out;
        ck("63 octets refuses",
           fhsm_composite_mprime_prehashed(ALG, ph, 63, NULL, 0, out, &lo) == FHSM_RV_ARGUMENTS_BAD);
        lo = sizeof out;
        ck("65 octets refuses",
           fhsm_composite_mprime_prehashed(ALG, ph, 65, NULL, 0, out, &lo) == FHSM_RV_ARGUMENTS_BAD);
        lo = sizeof out;
        ck("NULL refuse",
           fhsm_composite_mprime_prehashed(ALG, NULL, 64, NULL, 0, out, &lo) == FHSM_RV_ARGUMENTS_BAD);
        ck("le nom du pre-hachage est SHA512",
           strcmp(fhsm_composite_ph_name(ALG), "SHA512") == 0 && fhsm_composite_ph_len(ALG) == 64);
    }

    printf("\n%s\n", fails ? "ECHECS" : "tout passe");
    return fails ? 1 : 0;
}
