/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_fips_digests.c --- Regression test for the FIPS-approved digest and
 * HMAC mechanisms that the dispatch table advertised but the operation
 * path did not implement (#125, pkcs11-check test_mech_flags /
 * test_sha3 / TestSHA512Truncated : CKR_MECHANISM_INVALID).
 *
 *  Wires SHA-224, SHA-512/256, SHA-512/224, SHA3-256/384/512 into
 *  C_DigestInit, and SHA-224/SHA-3 HMACs (+ SHA-384/512 verify) into
 *  C_SignInit / C_VerifyInit. This test asserts the digests match their
 *  published "abc" KATs and that an HMAC sign->verify round-trip
 *  succeeds. Drives the PUBLIC API via dlopen.
 * ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG l; } CK_MECHANISM;

static void *H;
static CK_RV (*DI)(CK_SESSION_HANDLE, CK_MECHANISM*);
static CK_RV (*D)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*SI)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*SG)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*VI)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*V)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
static int fails = 0;

static void hex(const CK_BYTE *b, CK_ULONG n, char *out) {
    for (CK_ULONG i = 0; i < n; i++) sprintf(out + 2*i, "%02x", b[i]);
}
static void kat(CK_SESSION_HANDLE s, CK_ULONG m, const char *name, const char *want) {
    CK_MECHANISM mm = { m, 0, 0 };
    if (DI(s, &mm) != 0) { fprintf(stderr, "FAIL: %s DigestInit\n", name); fails++; return; }
    CK_BYTE out[64]; CK_ULONG ol = 64;
    if (D(s, (CK_BYTE*)"abc", 3, out, &ol) != 0) { fprintf(stderr, "FAIL: %s Digest\n", name); fails++; return; }
    char got[130]; hex(out, ol, got);
    if (strcmp(got, want) != 0) { fprintf(stderr, "FAIL: %s KAT\n  got  %s\n  want %s\n", name, got, want); fails++; }
    else printf("  %-14s KAT : OK\n", name);
}
static void hmac_rt(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k, CK_ULONG m, const char *name) {
    CK_MECHANISM mm = { m, 0, 0 }; CK_BYTE sig[64]; CK_ULONG sl = 64;
    CK_RV a = SI(s, &mm, k); CK_RV b = a ? a : SG(s, (CK_BYTE*)"abc", 3, sig, &sl);
    CK_RV c = VI(s, &mm, k); CK_RV d = c ? c : V(s, (CK_BYTE*)"abc", 3, sig, sl);
    if (b != 0 || d != 0) { fprintf(stderr, "FAIL: %s HMAC sign=0x%lx verify=0x%lx\n", name, (unsigned long)b, (unsigned long)d); fails++; }
    else printf("  %-14s HMAC roundtrip : OK\n", name);
}

/* PKCS#11 v3.2 C.6.4.1 : pLabel is a fixed 32-byte field, blank-padded and
 * NOT NUL-terminated. Passing a short string literal made C_InitToken read
 * past it -- harmless in practice, which is why it survived until the suite
 * was first run under ASan (#125). */
static CK_BYTE *fhsm_pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

int main(void) {
    H = dlopen("./libfreehsm-fips.so", RTLD_NOW);
    if (!H) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*I)(void*); CK_RV (*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*L)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG); CK_RV (*IP)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*GK)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    #define S(n,nm) *(void**)&n = dlsym(H, nm)
    S(I,"C_Initialize"); S(IT,"C_InitToken"); S(OS,"C_OpenSession"); S(L,"C_Login");
    S(IP,"C_InitPIN"); S(GK,"C_GenerateKey"); S(DI,"C_DigestInit"); S(D,"C_Digest");
    S(SI,"C_SignInit"); S(SG,"C_Sign"); S(VI,"C_VerifyInit"); S(V,"C_Verify");

    I(NULL); CK_BYTE so[]="00000000", up[]="user0000";
    IT(0, so, 8, fhsm_pad_label((CK_BYTE[32]){0}, "fips")); CK_SESSION_HANDLE s = 0; OS(0, 6, NULL, NULL, &s);
    L(s, 0, so, 8); IP(s, up, 8); (void)L(s, 1, up, 8);

    /* Digest KATs for "abc" (FIPS 180-4 / 202 published values). */
    kat(s, 0x255, "SHA-224",     "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    kat(s, 0x04C, "SHA-512/256", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
    kat(s, 0x048, "SHA-512/224", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
    kat(s, 0x2B0, "SHA3-256",    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    kat(s, 0x2D0, "SHA3-512",    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

    /* HMAC round-trip (generic secret key). */
    CK_ULONG cls = 4, kt = 0x10, vl = 32;
    CK_ATTRIBUTE at[] = { {0,&cls,8}, {0x100,&kt,8}, {0x161,&vl,8} };
    CK_OBJECT_HANDLE k = 0;
    CK_MECHANISM gen = { 0x350, 0, 0 };   /* CKM_GENERIC_SECRET_KEY_GEN */
    if (GK(s, &gen, at, 3, &k) != 0) { fprintf(stderr, "FAIL: keygen\n"); return 1; }
    hmac_rt(s, k, 0x261, "SHA384");       /* verify was previously broken */
    hmac_rt(s, k, 0x2B1, "SHA3-256");
    hmac_rt(s, k, 0x2D1, "SHA3-512");
    hmac_rt(s, k, 0x256, "SHA224");

    /* Multipart HMAC must equal one-shot (#125 : was hard-coded to
     * SHA-256, so SHA-384/512 multipart diverged from one-shot). */
    { CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
      CK_RV (*C_SignFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
      *(void**)&C_SignUpdate = dlsym(H,"C_SignUpdate");
      *(void**)&C_SignFinal  = dlsym(H,"C_SignFinal");
      CK_ULONG mechs[] = { 0x261, 0x271, 0x2D1 };  /* SHA384/512/SHA3-512 HMAC */
      const char *nm[] = { "SHA384", "SHA512", "SHA3-512" };
      for (int m = 0; m < 3; ++m) {
          CK_MECHANISM mm = { mechs[m], NULL, 0 };
          CK_BYTE a[64]; CK_ULONG al = 64;
          SI(s, &mm, k); SG(s, (CK_BYTE*)"abcdef", 6, a, &al);
          CK_BYTE b[64]; CK_ULONG bl = 64;
          SI(s, &mm, k); C_SignUpdate(s, (CK_BYTE*)"abc", 3);
          C_SignUpdate(s, (CK_BYTE*)"def", 3); C_SignFinal(s, b, &bl);
          if (al != bl || memcmp(a, b, al) != 0) {
              fprintf(stderr, "FAIL: %s multipart != one-shot\n", nm[m]); fails++;
          } else printf("  %-14s multipart == one-shot : OK\n", nm[m]);
      }
    }

    if (fails) { fprintf(stderr, "test_fips_digests : %d FAIL\n", fails); return 1; }
    printf("test_fips_digests : PASS\n");
    return 0;
}
