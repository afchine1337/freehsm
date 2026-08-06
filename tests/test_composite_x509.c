/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_composite_x509.c --- composite SubjectPublicKeyInfo (#112).
 *
 *  The AlgorithmIdentifier in fhsm_composite.c is hand-encoded, because the
 *  composite OID has no NID in OpenSSL 3.5 -- the draft is still in the RFC
 *  Editor queue. Hand-encoded DER is where lengths go wrong: the first version
 *  of that constant declared 0x0B and 0x09 where it needed 0x0A and 0x08, and
 *  reading it did not catch it.
 *
 *  So this test does not compare against a second hand-written copy of the
 *  same bytes -- that would only prove the two typists agreed. It rebuilds the
 *  encoding from the dotted OID string, by the rules, and compares.
 *
 *  It then parses the SPKI the way a third party would, with OpenSSL's own DER
 *  reader, because a structure only we can read is worth nothing to a CA.
 * ========================================================================= */
#include "fhsm_composite.h"

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
static void ck(const char *what, int ok, const char *detail) {
    printf("  %-58s %s\n", what, ok ? "OK" : "<<< FAIL");
    if (detail && *detail) printf("      %s\n", detail);
    if (!ok) fails++;
}

/* Encode a dotted OID to DER content bytes, by the rules, independently of
 * anything in the library. */
static size_t oid_encode(const char *dotted, uint8_t *out, size_t cap) {
    unsigned long arc[16]; int n = 0;
    const char *p = dotted;
    while (*p && n < 16) { arc[n++] = strtoul(p, (char**)&p, 10); if (*p=='.') p++; }
    if (n < 2) return 0;
    size_t k = 0;
    if (k < cap) out[k++] = (uint8_t)(40 * arc[0] + arc[1]);
    for (int i = 2; i < n; ++i) {
        unsigned long v = arc[i]; uint8_t tmp[8]; int t = 0;
        do { tmp[t++] = (uint8_t)(v & 0x7F); v >>= 7; } while (v);
        while (t--) { if (k >= cap) return 0; out[k++] = (uint8_t)(tmp[t] | (t ? 0x80 : 0)); }
    }
    return k;
}

int main(void) {
    printf("=== test_composite_x509 : SubjectPublicKeyInfo composite (#112) ===\n\n");

    printf("[A] the AlgorithmIdentifier, rebuilt from the OID rather than retyped\n");
    uint8_t body[32];
    size_t bn = oid_encode("1.3.6.1.5.5.7.6.48", body, sizeof body);
    uint8_t want[64]; size_t w = 0;
    want[w++] = 0x30; want[w++] = (uint8_t)(2 + bn);
    want[w++] = 0x06; want[w++] = (uint8_t)bn;
    memcpy(want + w, body, bn); w += bn;

    static uint8_t priv[FHSM_COMPOSITE_PRIV_MAX], pub[FHSM_COMPOSITE_PUB_MAX];
    size_t pl = sizeof priv, ql = sizeof pub;
    if (fhsm_composite_keygen(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                               priv, &pl, pub, &ql) != FHSM_RV_OK) {
        ck("keygen (precondition)", 0, ""); return 2;
    }
    static uint8_t spki[8192]; size_t sl = sizeof spki;
    fhsm_rv_t rv = fhsm_composite_spki(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                        pub, ql, spki, &sl);
    char d[160];
    snprintf(d, sizeof d, "%zu bytes", sl);
    ck("fhsm_composite_spki succeeds", rv == FHSM_RV_OK, d);
    if (rv != FHSM_RV_OK) { printf("\nFAIL\n"); return 1; }

    /* The AlgorithmIdentifier sits right after the outer SEQUENCE header. */
    size_t off = 1 + ((spki[1] & 0x80) ? (size_t)(spki[1] & 0x7F) + 1 : 1);
    ck("the AlgorithmIdentifier matches the OID, byte for byte",
       memcmp(spki + off, want, w) == 0, "");

    printf("\n[B] the structure\n");
    uint8_t raw[FHSM_COMPOSITE_RAW_PUB]; size_t rl = sizeof raw;
    rv = fhsm_composite_raw_pub(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                 pub, ql, raw, &rl);
    snprintf(d, sizeof d, "%zu = 1952 (ML-DSA-65) + 32 (Ed25519)", rl);
    ck("the raw public key is 1984 bytes, ML-DSA first",
       rv == FHSM_RV_OK && rl == 1984, d);

    /* §5.1: the BIT STRING carries the raw value with no further encoding. */
    const uint8_t *bs = spki + off + w;
    ck("a BIT STRING follows, with zero unused bits", bs[0] == 0x03, "");
    size_t bl_n = (bs[1] & 0x80) ? (size_t)(bs[1] & 0x7F) : 0;
    const uint8_t *val = bs + 2 + bl_n;
    ck("its first content octet is the unused-bit count, zero", val[0] == 0x00, "");
    ck("the value that follows IS the raw key, unwrapped",
       memcmp(val + 1, raw, rl) == 0, "");

    printf("\n[C] a third party must be able to parse it\n");
    printf("      a structure only we can read is worth nothing to a CA.\n");
    const uint8_t *p = spki;
    X509_PUBKEY *xp = d2i_X509_PUBKEY(NULL, &p, (long)sl);
    ck("OpenSSL's own DER reader accepts the SubjectPublicKeyInfo", xp != NULL, "");
    if (xp) {
        X509_ALGOR *alg = NULL;
        const unsigned char *pk = NULL; int pklen = 0;
        X509_PUBKEY_get0_param(NULL, &pk, &pklen, &alg, xp);
        snprintf(d, sizeof d, "%d bytes recovered", pklen);
        ck("it recovers exactly the 1984-byte key", pklen == (int)rl
           && memcmp(pk, raw, rl) == 0, d);

        const ASN1_OBJECT *o = NULL; int ptype = 0; const void *pval = NULL;
        X509_ALGOR_get0(&o, &ptype, &pval, alg);
        char buf[128] = "";
        OBJ_obj2txt(buf, sizeof buf, o, 1);
        ck("the algorithm OID reads back as 1.3.6.1.5.5.7.6.48",
           strcmp(buf, "1.3.6.1.5.5.7.6.48") == 0, buf);
        /* Parameters ABSENT, not NULL. The ASN.1 module says PARAMS ARE
         * absent; a NULL there is a different encoding that some parsers
         * accept and others reject, and it is a routine way to ship
         * something that looks right and interoperates with nothing. */
        ck("its parameters are ABSENT, not NULL", ptype == V_ASN1_UNDEF,
           ptype == V_ASN1_NULL ? "a NULL was emitted where nothing belongs" : "");
        X509_PUBKEY_free(xp);
    }

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
