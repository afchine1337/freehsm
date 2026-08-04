/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_composite_mprime.c --- the composite combiner against EXTERNAL
 * vectors (#112).
 *
 *  Reads kat/composite/mprime_appendix_d.txt rather than embedding the hex.
 *  The vectors are the two worked examples of Appendix D of
 *  draft-ietf-lamps-pq-composite-sigs-19 -- somebody else's numbers, which is
 *  the whole point. CKM_HYBRID_ED25519_ML_DSA_65 signed the wrong thing for
 *  months behind self-generated KATs that established only that our verify
 *  accepted our sign, true of any self-consistent construction including an
 *  incorrect one. See docs/COMPOSITE_SIGS_GAP.md.
 *
 *  Keeping the numbers in the file and out of this source is deliberate too:
 *  copying 130 bytes of hex into a C literal is exactly the transcription risk
 *  the file exists to remove.
 *
 *  Appendix D works through id-MLDSA65-ECDSA-P256-SHA512 rather than our
 *  target, so the vector loop drives the combiner with the label named in each
 *  vector. Our own registered algorithm is then checked separately for the
 *  things the vectors cannot cover: its parameters, its length arithmetic, its
 *  field layout, and its argument handling.
 * ========================================================================= */
#include "fhsm_composite.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;

static void ck(const char *what, int ok, const char *detail) {
    printf("  %-58s %s\n", what, ok ? "OK" : "<<< FAIL");
    if (detail && *detail) printf("      %s\n", detail);
    if (!ok) fails++;
}

static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = 0;
    for (const char *p = hex; p[0] && p[1] && n < cap; p += 2) {
        unsigned v; if (sscanf(p, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
    }
    return n;
}

/* Assemble M' with an explicit label, so a vector for an algorithm this module
 * does not register can still exercise the construction. */
static size_t build(const char *label, size_t label_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *ctx, size_t ctx_len,
                     const char *ph, uint8_t *out)
{
    uint8_t *cur = out;
    memcpy(cur, FHSM_COMPOSITE_PREFIX, FHSM_COMPOSITE_PREFIX_LEN);
    cur += FHSM_COMPOSITE_PREFIX_LEN;
    memcpy(cur, label, label_len); cur += label_len;
    *cur++ = (uint8_t)ctx_len;
    if (ctx_len) { memcpy(cur, ctx, ctx_len); cur += ctx_len; }
    unsigned int dlen = 0;
    EVP_MD *md = EVP_MD_fetch(NULL, ph, NULL);
    if (!md) return 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c) { EVP_MD_free(md); return 0; }
    int ok = EVP_DigestInit_ex(c, md, NULL) == 1
          && (msg_len == 0 || EVP_DigestUpdate(c, msg, msg_len) == 1)
          && EVP_DigestFinal_ex(c, cur, &dlen) == 1;
    EVP_MD_CTX_free(c); EVP_MD_free(md);
    return ok ? (size_t)(cur - out) + dlen : 0;
}

/* --- a very small key = value reader for the KAT file -------------------- */
#define MAXV 4096
struct kv { char name[64], label[64], msg[MAXV], ctx[MAXV], ph[32], mp[MAXV]; size_t mplen; };

static void trim(char *s) {
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r' || s[n-1] == ' ')) s[--n] = 0;
}

static int run_vectors(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { ck("open the KAT file", 0, path); return 0; }
    char line[MAXV + 128];
    struct kv v; memset(&v, 0, sizeof v);
    int seen = 0;

    while (1) {
        char *got = fgets(line, sizeof line, f);
        int flush = (!got || strncmp(line, "vector = ", 9) == 0);

        if (flush && v.name[0]) {
            uint8_t msg[MAXV/2], ctx[MAXV/2], want[MAXV/2], out[MAXV/2];
            size_t ml = unhex(v.msg, msg, sizeof msg);
            size_t cl = v.ctx[0] ? unhex(v.ctx, ctx, sizeof ctx) : 0;
            size_t wl = unhex(v.mp, want, sizeof want);
            size_t n  = build(v.label, strlen(v.label), msg, ml,
                               cl ? ctx : NULL, cl, v.ph[0] ? v.ph : "SHA512", out);
            char d[192];
            snprintf(d, sizeof d, "%zu bytes, expected %zu (declared %zu), ctx=%zu",
                     n, wl, v.mplen, cl);
            char label[128];
            snprintf(label, sizeof label, "vector %s", v.name);
            ck(label, n == wl && wl == v.mplen && memcmp(out, want, wl) == 0, d);
            seen++;
            memset(&v, 0, sizeof v);
        }
        if (!got) break;
        trim(line);
        if (line[0] == '#' || line[0] == 0) continue;
        char *eq = strstr(line, " = ");
        if (!eq) continue;
        *eq = 0; const char *k = line; const char *val = eq + 3;
        if      (!strcmp(k, "vector"))      snprintf(v.name,  sizeof v.name,  "%s", val);
        else if (!strcmp(k, "label"))       snprintf(v.label, sizeof v.label, "%s", val);
        else if (!strcmp(k, "message_hex")) snprintf(v.msg,   sizeof v.msg,   "%s", val);
        else if (!strcmp(k, "ctx_hex"))     snprintf(v.ctx,   sizeof v.ctx,   "%s", val);
        else if (!strcmp(k, "ph"))          snprintf(v.ph,    sizeof v.ph,    "%s",
                                                     strcmp(val, "SHA-512") ? val : "SHA512");
        else if (!strcmp(k, "mprime_hex"))  snprintf(v.mp,    sizeof v.mp,    "%s", val);
        else if (!strcmp(k, "mprime_len"))  v.mplen = (size_t)strtoul(val, NULL, 10);
    }
    fclose(f);
    return seen;
}

/* --- our own registered algorithm ---------------------------------------- */
static void test_our_algorithm(void) {
    const fhsm_composite_params_t *p =
        fhsm_composite_params(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512);
    if (!p) { ck("id-MLDSA65-Ed25519-SHA512 is registered", 0, ""); return; }

    ck("OID is 1.3.6.1.5.5.7.6.48",  strcmp(p->oid, "1.3.6.1.5.5.7.6.48") == 0, p->oid);
    ck("label is COMPSIG-MLDSA65-Ed25519-SHA512",
       strcmp(p->label, "COMPSIG-MLDSA65-Ed25519-SHA512") == 0, p->label);
    ck("declared label length matches the string",
       p->label_len == strlen(p->label), "");
    ck("pre-hash is SHA-512, 64 bytes",
       strcmp(p->ph_name, "SHA512") == 0 && p->ph_len == 64, "");

    /* 32 + 30 + 1 + 0 + 64 */
    char d[96];
    size_t n0 = fhsm_composite_mprime_len(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512, 0);
    snprintf(d, sizeof d, "%zu", n0);
    ck("M' is 127 bytes with an empty context", n0 == 127, d);

    size_t n8 = fhsm_composite_mprime_len(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512, 8);
    ck("an 8-byte context adds exactly 8", n8 == 135, "");

    /* Field layout: the assembled M' must agree with an independent assembly
     * using the same published pieces. */
    uint8_t msg[10]; for (int i = 0; i < 10; ++i) msg[i] = (uint8_t)i;
    uint8_t got[256], ref[256];
    size_t glen = sizeof got;
    fhsm_rv_t rv = fhsm_composite_mprime(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                          msg, sizeof msg, NULL, 0, got, &glen);
    size_t rlen = build(p->label, p->label_len, msg, sizeof msg, NULL, 0, "SHA512", ref);
    ck("assembled M' matches an independent assembly",
       rv == FHSM_RV_OK && glen == rlen && glen == 127 && memcmp(got, ref, glen) == 0, "");

    ck("prefix is the first 32 bytes",
       memcmp(got, FHSM_COMPOSITE_PREFIX, 32) == 0, "");
    ck("label follows the prefix",
       memcmp(got + 32, p->label, p->label_len) == 0, "");
    ck("len(ctx) byte is 0 for an empty context", got[32 + p->label_len] == 0, "");

    /* Argument handling. A context over 255 cannot be length-prefixed by a
     * single byte, so it must be refused rather than truncated -- truncating
     * would change what is signed without telling the caller. */
    uint8_t big[300] = {0};
    size_t l = sizeof got;
    ck("a 256-byte context is refused, not truncated",
       fhsm_composite_mprime(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                              msg, sizeof msg, big, 256, got, &l)
           == FHSM_RV_DATA_LEN_RANGE, "");

    l = 10;
    fhsm_rv_t small = fhsm_composite_mprime(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                             msg, sizeof msg, NULL, 0, got, &l);
    ck("a short buffer reports BUFFER_TOO_SMALL and the size needed",
       small == FHSM_RV_BUFFER_TOO_SMALL && l == 127, "");

    l = sizeof got;
    ck("an unknown algorithm is rejected",
       fhsm_composite_mprime((fhsm_composite_alg_t)99, msg, sizeof msg,
                              NULL, 0, got, &l) == FHSM_RV_ARGUMENTS_BAD, "");
}

int main(int argc, char **argv) {
    const char *kat = (argc > 1) ? argv[1] : "kat/composite/mprime_appendix_d.txt";
    printf("=== test_composite_mprime : the combiner against draft Appendix D ===\n\n");

    printf("[external vectors] %s\n", kat);
    int n = run_vectors(kat);
    char d[64]; snprintf(d, sizeof d, "%d vector(s) read", n);
    ck("both Appendix D vectors were present and ran", n == 2, d);

    printf("\n[our registered algorithm] id-MLDSA65-Ed25519-SHA512\n");
    test_our_algorithm();

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
