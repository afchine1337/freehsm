/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_mech_advertise.c --- Coherence guard for mechanism advertisement
 * (#125). C_GetMechanismList and C_GetMechanismInfo are derived from the
 * generated dispatch table ; this test asserts they agree and that the
 * previously-broken cases are fixed :
 *   1. Every advertised mechanism resolves via C_GetMechanismInfo to a
 *      non-CKR_MECHANISM_INVALID result with a non-zero capability flag
 *      (no advertised-but-unusable phantom).
 *   2. The post-quantum signature mechanisms are advertised at their
 *      correct OASIS values (ML-DSA 0x4024, ML-DSA keygen 0x4023,
 *      SLH-DSA keygen 0x4025) with CKF_SIGN, and EdDSA (0x1057) +
 *      HKDF_DERIVE (0x402A) are present.
 *   3. The stale/phantom values (ML-DSA 0x403F, FALCON 0xC0001000) are
 *      NOT advertised.
 *   4. An unknown mechanism yields CKR_MECHANISM_INVALID.
 * Drives the public API via dlopen.
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG, CK_RV, CK_SLOT_ID, CK_FLAGS;
struct CK_MECHANISM_INFO { CK_ULONG mn, mx; CK_FLAGS flags; };
#define CKR_MECHANISM_INVALID 0x70UL
#define CKF_SIGN 0x00000800UL

int main(void) {
    void *h = dlopen("./libfreehsm-fips.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*Init)(void*); *(void**)&Init = dlsym(h,"C_Initialize");
    CK_RV (*GML)(CK_SLOT_ID,CK_ULONG*,CK_ULONG*); *(void**)&GML = dlsym(h,"C_GetMechanismList");
    CK_RV (*GMI)(CK_SLOT_ID,CK_ULONG,void*); *(void**)&GMI = dlsym(h,"C_GetMechanismInfo");
    if (!Init || !GML || !GMI) { fprintf(stderr,"dlsym missing\n"); return 2; }
    Init(NULL);

    CK_ULONG n = 0;
    if (GML(0, NULL, &n) != 0 || n == 0) { fprintf(stderr,"FAIL: empty list\n"); return 1; }
    CK_ULONG *l = calloc(n, sizeof *l);
    if (GML(0, l, &n) != 0) { fprintf(stderr,"FAIL: GML fill\n"); return 1; }
    printf("test_mech_advertise : %lu mechanisms advertised\n", (unsigned long)n);

    /* (1) every advertised mech has coherent, usable info */
    int seen_mldsa = 0, seen_mldsa_kg = 0, seen_slhdsa_kg = 0, seen_eddsa = 0, seen_hkdf = 0;
    for (CK_ULONG i = 0; i < n; ++i) {
        struct CK_MECHANISM_INFO info = {0,0,0};
        CK_RV rv = GMI(0, l[i], &info);
        if (rv == CKR_MECHANISM_INVALID) {
            fprintf(stderr, "FAIL: 0x%04lx advertised but C_GetMechanismInfo INVALID\n", l[i]);
            return 1;
        }
        if (info.flags == 0) {
            fprintf(stderr, "FAIL: 0x%04lx advertised with zero capability flags\n", l[i]);
            return 1;
        }
        if (l[i] == 0x4024) { seen_mldsa = 1; if (!(info.flags & CKF_SIGN)) { fprintf(stderr,"FAIL: ML-DSA no SIGN\n"); return 1; } }
        if (l[i] == 0x4023) seen_mldsa_kg = 1;
        if (l[i] == 0x4025) seen_slhdsa_kg = 1;
        if (l[i] == 0x1057) seen_eddsa = 1;
        if (l[i] == 0x402A) seen_hkdf = 1;
        /* (3) phantoms must not appear */
        if (l[i] == 0x403F || l[i] == 0x403E || l[i] == 0x4040
            || l[i] == 0xC0001000UL || l[i] == 0xC0001001UL) {
            fprintf(stderr, "FAIL: phantom/stale 0x%lx still advertised\n", l[i]);
            return 1;
        }
    }
    /* (2) correct-value PQ + EdDSA + HKDF present */
    if (!seen_mldsa || !seen_mldsa_kg || !seen_slhdsa_kg || !seen_eddsa || !seen_hkdf) {
        fprintf(stderr, "FAIL: missing expected mech (mldsa=%d kg=%d slh=%d eddsa=%d hkdf=%d)\n",
                seen_mldsa, seen_mldsa_kg, seen_slhdsa_kg, seen_eddsa, seen_hkdf);
        return 1;
    }
    /* (4) unknown mechanism -> INVALID */
    struct CK_MECHANISM_INFO junk = {0,0,0};
    if (GMI(0, 0x0000DEADUL, &junk) != CKR_MECHANISM_INVALID) {
        fprintf(stderr, "FAIL: unknown mech not rejected\n"); return 1;
    }
    free(l);
    printf("test_mech_advertise : PASS\n");
    return 0;
}
