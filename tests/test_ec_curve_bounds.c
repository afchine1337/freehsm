/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_ec_curve_bounds.c --- the EC curves accepted are the ones advertised.
 *
 * C_GetMechanismInfo(CKM_EC_KEY_PAIR_GEN) reports 256..521 bits. Until
 * 2026-09-28 an all-mechanisms build accepted any curve in OpenSSL's registry
 * -- 82 on the build host, from secp112r1 to sect571k1 -- because
 * match_curve_ex() handed everything outside its three-entry table to
 * OBJ_obj2nid. The comment there meant brainpool. pkcs11-check found it on the
 * first corpus run of that profile, as a CRITICAL self-contradiction: a key
 * generated on a curve weaker than the minimum the module itself advertises.
 *
 * Profile-adaptive. What must hold in BOTH profiles is the part that was
 * broken: a curve outside what is advertised is refused. What differs is
 * brainpool, which is not NIST-approved and so exists only in all-mechanisms.
 *
 * The OIDs below were produced by `openssl ecparam -name X -outform DER`,
 * not typed from memory.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize; CK_FLAGS flags; } CK_MECHANISM_INFO;

#define CKM_EC_KEY_PAIR_GEN 0x1040UL
#define CKA_EC_PARAMS       0x180UL

static void *H;
#define SY(v,n) (*(void**)&(v) = dlsym(H, n))

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) fails++;
}

static CK_RV (*GKP)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                    CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);

static CK_RV keygen(CK_SESSION_HANDLE s, const char *oid, CK_ULONG len) {
    CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pub[] = { { CKA_EC_PARAMS, (void*)oid, len } };
    CK_OBJECT_HANDLE hpub = 0, hprv = 0;
    return GKP(s, &m, pub, 1, NULL, 0, &hpub, &hprv);
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

int main(void) {
    H = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!H) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    CK_RV (*I)(void*);                                              SY(I,  "C_Initialize");
    CK_RV (*IT)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);          SY(IT, "C_InitToken");
    CK_RV (*OS)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*); SY(OS, "C_OpenSession");
    CK_RV (*LI)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);   SY(LI, "C_Login");
    CK_RV (*IP)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);             SY(IP, "C_InitPIN");
    CK_RV (*GML)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);                 SY(GML,"C_GetMechanismList");
    CK_RV (*GMI)(CK_SLOT_ID, CK_ULONG, CK_MECHANISM_INFO*);         SY(GMI,"C_GetMechanismInfo");
    SY(GKP, "C_GenerateKeyPair");
    if (!I || !GKP || !GMI) { fprintf(stderr, "missing symbols\n"); return 2; }

    I(NULL);
    CK_BYTE so[] = "00000000", us[] = "user0000", lab[32];
    IT(0, so, 8, pad_label(lab, "ecbounds"));
    CK_SESSION_HANDLE s; OS(0, 6, NULL, NULL, &s);
    LI(s, 0, so, 8); IP(s, us, 8);
    /* back to the user role: key generation is a User service */
    { CK_RV (*LO)(CK_SESSION_HANDLE); SY(LO, "C_Logout"); LO(s); }
    LI(s, 1, us, 8);

    CK_ULONG mn = 0; GML(0, NULL, &mn);
    CK_ULONG *ml = calloc(mn ? mn : 1, sizeof *ml); GML(0, ml, &mn);
    int strict = 1;
    for (CK_ULONG i = 0; i < mn; i++) if (ml[i] == 0x1UL) { strict = 0; break; }
    free(ml);
    printf("test_ec_curve_bounds : profile = %s\n",
           strict ? "nist-approved-only" : "all-mechanisms");

    CK_MECHANISM_INFO info = {0};
    ok(GMI(0, CKM_EC_KEY_PAIR_GEN, &info) == 0
       && info.ulMinKeySize == 256 && info.ulMaxKeySize == 521,
       "CKM_EC_KEY_PAIR_GEN advertises 256..521 bits");

    /* In range, NIST: accepted in both profiles. */
    ok(keygen(s, "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", 10) == 0,
       "P-256 is accepted");

    /* Below the advertised minimum: refused in BOTH profiles. This is the
     * case that was accepted by all-mechanisms. */
    ok(keygen(s, "\x06\x05\x2b\x81\x04\x00\x08", 7) != 0,
       "secp160r1 (160 bits, below the advertised minimum) is refused");

    /* In range but a binary field: refused in both. Nothing advertises F2m. */
    ok(keygen(s, "\x06\x05\x2b\x81\x04\x00\x10", 7) != 0,
       "sect283k1 (binary field) is refused");

    /* SM2: prime and 256 bits, so the range check alone would let it through.
     * Excluded by name, in both profiles -- the module has no SM2 mechanism. */
    ok(keygen(s, "\x06\x08\x2a\x81\x1c\xcf\x55\x01\x82\x2d", 10) != 0,
       "SM2 is refused (no SM2 mechanism to use it with)");

    /* Brainpool: the curve the fallback was written for. Present only in
     * all-mechanisms, where it must still work after the fix. */
    CK_RV bp = keygen(s, "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x07", 11);
    if (strict) ok(bp != 0, "brainpoolP256r1 is refused under nist-approved-only");
    else        ok(bp == 0, "brainpoolP256r1 is still accepted under all-mechanisms");

    printf("\ntest_ec_curve_bounds : %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
