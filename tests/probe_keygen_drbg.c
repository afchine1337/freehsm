/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * probe_keygen_drbg --- does a key this module generates draw its material
 * from this module's DRBG?
 *
 * RELEASE_v2.0.0-beta.md said this of composite key generation only. It is
 * true of every key the module generates: EVP_PKEY_Q_keygen(NULL, ...)
 * appears five times in fhsm_pkcs11.c -- RSA, EC, ML-KEM, ML-DSA, SLH-DSA --
 * and a NULL library context means OpenSSL's RAND, not fhsm_drbg.
 *
 * bytes_emitted counts every byte fhsm_drbg_bytes() has returned since init,
 * and it is not enough on its own: it moves, because object ids and blob
 * nonces are drawn around the generation. What answers the question is that it
 * moves by the SAME amount for keys whose randomness needs differ by orders of
 * magnitude. Measured 2026-09-01:
 *
 *     RSA-2048   96      RSA-4096   96      EC P-256   96
 *
 * A fixed cost is not key material. For comparison, a spike routing keygen
 * through a provider-supplied RAND on a private OSSL_LIB_CTX drew
 * 31574 / 77772 / 32 -- tracking key size, which is what using it looks like.
 *
 * This probe is kept so the gap is watched rather than remembered. When it is
 * closed, these numbers stop being equal and this comment is what says so.
 */
#include "fhsm_common.h"
#include "fhsm_drbg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned long CK_ULONG;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } ATTR;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } MECH;

extern CK_ULONG C_Initialize(void *);
extern CK_ULONG C_Finalize(void *);
extern CK_ULONG C_OpenSession(CK_ULONG, CK_ULONG, void *, void *, CK_ULONG *);
extern CK_ULONG C_Login(CK_ULONG, CK_ULONG, unsigned char *, CK_ULONG);
extern CK_ULONG C_InitToken(CK_ULONG, unsigned char *, CK_ULONG, unsigned char *);
extern CK_ULONG C_InitPIN(CK_ULONG, unsigned char *, CK_ULONG);
extern CK_ULONG C_GenerateKeyPair(CK_ULONG, MECH *, ATTR *, CK_ULONG,
                                   ATTR *, CK_ULONG, CK_ULONG *, CK_ULONG *);

static unsigned long long one(CK_ULONG sess, const char *name, CK_ULONG mech,
                ATTR *pub, CK_ULONG npub)
{
    fhsm_drbg_stats_t a, b;
    MECH m = { mech, NULL, 0 };
    CK_ULONG hpub = 0, hpriv = 0;
    fhsm_drbg_get_stats(&a);
    CK_ULONG rv = C_GenerateKeyPair(sess, &m, pub, npub, NULL, 0, &hpub, &hpriv);
    fhsm_drbg_get_stats(&b);
    unsigned long long d = b.bytes_emitted - a.bytes_emitted;
    printf("  %-12s rv=0x%08lx  drbg bytes drawn: %llu\n", name, rv, d);
    return (rv == 0) ? d : (unsigned long long)-1;
}

int main(void)
{
    if (C_Initialize(NULL) != 0) { puts("C_Initialize failed"); return 2; }
    CK_ULONG s = 0;
    if (C_OpenSession(0, 0x00000004UL | 0x00000002UL, NULL, NULL, &s) != 0) {
        puts("C_OpenSession failed"); return 2; }
    const char *so  = getenv("FHSM_SO_PIN"), *pin = getenv("FHSM_PIN");
    if (so)  (void)C_InitToken(0, (unsigned char *)(uintptr_t)so, strlen(so),
                                (unsigned char *)"probe                           ");
    if (so)  (void)C_Login(s, 0UL, (unsigned char *)(uintptr_t)so, strlen(so));
    if (pin) (void)C_InitPIN(s, (unsigned char *)(uintptr_t)pin, strlen(pin));

    CK_ULONG bits = 2048;
    ATTR rsa[1] = { { 0x00000121UL, &bits, sizeof bits } };
    char ps[] = "ML-DSA-65";
    ATTR mldsa[1] = { { 0x00000640UL /* CKA_PARAMETER_SET */, ps, sizeof ps - 1 } };

    /* The counter moving is not the answer. What answers is that it moves by
     * the *same* amount for keys whose randomness needs differ by orders of
     * magnitude: a fixed cost paid around the generation -- object ids, blob
     * nonces -- and not the key material, which comes from
     * EVP_PKEY_Q_keygen(NULL, ...) and therefore from OpenSSL's RAND. */
    CK_ULONG bits4096 = 4096;
    ATTR rsa4[1] = { { 0x00000121UL, &bits4096, sizeof bits4096 } };
    (void)mldsa;
    puts("Bytes drawn from this module's DRBG per generated key pair");
    puts("");
    (void)one(s, "RSA-2048",  0x00000000UL, rsa,   1);
    (void)one(s, "RSA-4096",  0x00000000UL, rsa4,  1);
    (void)one(s, "EC P-256",  0x00001040UL, NULL,  0);
    puts("");
    puts("  An RSA-4096 key needs far more randomness than an RSA-2048 one,");
    puts("  and both need far more than a P-256 scalar. Equal draws mean the");
    puts("  draws are not the key.");
    C_Finalize(NULL);
    return 0;
}
