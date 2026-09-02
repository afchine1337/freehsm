/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/test_composite_p11.c --- Composite ML-DSA through PKCS#11 (#112).
 *
 *  Wiring a mechanism into fhsm_pkcs11.c means touching four places:
 *  C_GenerateKeyPair, C_SignInit, C_VerifyInit, and the C_Sign / C_Verify
 *  bodies. Every defect this project has found in itself has the same shape --
 *  a control present on some of the paths that reach a state and absent from
 *  the rest -- and this file is where they lived. So the profile gate is
 *  checked at each entry point separately rather than once, and under
 *  fips-strict the test asserts refusal at every one of them.
 *
 *  Run under either profile; it detects which one it is looking at and
 *  asserts the matching behaviour. That matters: a test that only passes
 *  under interop would leave the fips-strict half unexercised, which is
 *  precisely how a gate goes missing.
 * ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                      0UL
#define CKR_MECHANISM_INVALID       0x70UL
#define CKR_SIGNATURE_INVALID       0xC0UL
#define CKR_BUFFER_TOO_SMALL        0x150UL
#define CKF_RW                      6UL
#define CKM_COMPOSITE_MLDSA65_ED25519 0x80004202UL
#define CKA_CLASS                   0UL
#define CKA_LABEL                   3UL

static int fails = 0;
static void ck(const char *what, int ok, const char *detail) {
    printf("  %-58s %s\n", what, ok ? "OK" : "<<< FAIL");
    if (detail && *detail) printf("      %s\n", detail);
    if (!ok) fails++;
}
static CK_BYTE *padlbl(CK_BYTE b[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(b, ' ', 32); memcpy(b, s, n); return b;
}

int main(void) {
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_SignFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_InitToken); SYM(C_OpenSession); SYM(C_Login);
    SYM(C_InitPIN); SYM(C_GenerateKeyPair); SYM(C_SignInit); SYM(C_Sign);
    SYM(C_VerifyInit); SYM(C_Verify);
    SYM(C_SignUpdate); SYM(C_SignFinal); SYM(C_VerifyUpdate); SYM(C_VerifyFinal);

    C_Initialize(NULL);
    CK_BYTE so[] = "00000000", up[] = "user0000", lbl[32];
    C_InitToken(0, so, 8, padlbl(lbl, "composite-p11"));
    CK_SESSION_HANDLE s = 0;
    C_OpenSession(0, CKF_RW, NULL, NULL, &s);
    C_Login(s, 0, so, 8); C_InitPIN(s, up, 8); C_Login(s, 1, up, 8);

    CK_MECHANISM m = { CKM_COMPOSITE_MLDSA65_ED25519, NULL, 0 };
    CK_ATTRIBUTE pub_t[]  = { {CKA_LABEL, (void*)"comp-pub",  8} };
    CK_ATTRIBUTE priv_t[] = { {CKA_LABEL, (void*)"comp-priv", 9} };
    CK_OBJECT_HANDLE hpub = 0, hpriv = 0;

    CK_RV gen = C_GenerateKeyPair(s, &m, pub_t, 1, priv_t, 1, &hpub, &hpriv);

    /* Which profile are we in? The answer is the keygen result, and the rest
     * of the run asserts the whole behaviour that follows from it. */
    int strict = (gen == CKR_MECHANISM_INVALID);
    printf("=== test_composite_p11 : Composite ML-DSA via PKCS#11 (#112) ===\n");
    printf("    profile detected: %s\n\n", strict ? "fips-strict" : "interop");

    if (strict) {
        printf("[fips-strict] the mechanism must be refused at EVERY entry point\n");
        ck("C_GenerateKeyPair refuses it", gen == CKR_MECHANISM_INVALID, "");
        /* The Init gates must refuse independently of keygen -- that is the
         * whole point of checking three sites instead of one. A stale handle
         * is fine here: the gate must fire before the key is ever looked at. */
        ck("C_SignInit refuses it",
           C_SignInit(s, &m, 1) == CKR_MECHANISM_INVALID, "");
        ck("C_VerifyInit refuses it",
           C_VerifyInit(s, &m, 1) == CKR_MECHANISM_INVALID, "");
        /* The multipart entry points are reached only through SignInit, so
           they cannot be refused independently -- what must hold is that no
           operation is left active for them to run against. */
        CK_ULONG dummy = 0;
        ck("C_SignUpdate has no operation to continue",
           C_SignUpdate(s, (CK_BYTE*)"x", 1) != CKR_OK, "");
        ck("C_SignFinal has no operation to finish",
           C_SignFinal(s, NULL, &dummy) != CKR_OK, "");
        printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
        return fails ? 1 : 0;
    }

    printf("[interop] full round trip\n");
    char d[128];
    snprintf(d, sizeof d, "rv=0x%lx pub=%lu priv=%lu",
             (unsigned long)gen, (unsigned long)hpub, (unsigned long)hpriv);
    ck("C_GenerateKeyPair produces a composite key pair",
       gen == CKR_OK && hpub && hpriv, d);
    if (gen != CKR_OK) { printf("\nFAIL : %d\n", ++fails); return 1; }

    const CK_BYTE msg[10] = {0,1,2,3,4,5,6,7,8,9};

    /* Size query before signing, as PKCS#11 defines it. */
    ck("C_SignInit accepts the mechanism",
       C_SignInit(s, &m, hpriv) == CKR_OK, "");
    CK_ULONG need = 0;
    CK_RV q = C_Sign(s, (CK_BYTE*)msg, sizeof msg, NULL, &need);
    snprintf(d, sizeof d, "%lu bytes (3309 + 64)", (unsigned long)need);
    ck("a NULL buffer returns the size needed", q == CKR_OK && need == 3373, d);

    CK_BYTE sig[4096]; CK_ULONG slen = 4;
    CK_RV small = C_Sign(s, (CK_BYTE*)msg, sizeof msg, sig, &slen);
    ck("a short buffer returns BUFFER_TOO_SMALL and the size",
       small == CKR_BUFFER_TOO_SMALL && slen == 3373, "");

    slen = sizeof sig;
    CK_RV sg = C_Sign(s, (CK_BYTE*)msg, sizeof msg, sig, &slen);
    ck("C_Sign succeeds", sg == CKR_OK && slen == 3373, "");

    ck("C_VerifyInit accepts the mechanism",
       C_VerifyInit(s, &m, hpub) == CKR_OK, "");
    ck("C_Verify accepts the signature",
       C_Verify(s, (CK_BYTE*)msg, sizeof msg, sig, slen) == CKR_OK, "");

    const CK_BYTE other[10] = {9,8,7,6,5,4,3,2,1,0};
    C_VerifyInit(s, &m, hpub);
    ck("C_Verify rejects it over a different message",
       C_Verify(s, (CK_BYTE*)other, sizeof other, sig, slen) == CKR_SIGNATURE_INVALID, "");

    CK_BYTE bad[4096]; memcpy(bad, sig, slen); bad[0] ^= 0xFF;
    C_VerifyInit(s, &m, hpub);
    ck("C_Verify rejects a corrupted ML-DSA half",
       C_Verify(s, (CK_BYTE*)msg, sizeof msg, bad, slen) == CKR_SIGNATURE_INVALID, "");
    memcpy(bad, sig, slen); bad[slen-1] ^= 0xFF;
    C_VerifyInit(s, &m, hpub);
    ck("C_Verify rejects a corrupted Ed25519 half",
       C_Verify(s, (CK_BYTE*)msg, sizeof msg, bad, slen) == CKR_SIGNATURE_INVALID, "");

    /* The key type must not lie. Signing with the PUBLIC handle, or verifying
     * with the PRIVATE one, has to be refused rather than silently misread. */
    ck("C_SignInit with the public handle is refused",
       C_SignInit(s, &m, hpub) != CKR_OK, "");

    /* ---- multipart (#123) -------------------------------------------------
     * The property that matters is not "multipart works" but "multipart signs
     * the same thing". A streamed signature that only verifies through the
     * streamed path would be a private construction wearing a standard OID.
     * So every check below crosses the two paths. */
    printf("\n[multipart] streaming must sign exactly what one-shot signs\n");

    CK_BYTE mp[100000];
    for (size_t i = 0; i < sizeof mp; i++) mp[i] = (CK_BYTE)(i * 37 + 11);

    /* Signed in awkward pieces on purpose: a 1-byte first chunk, a 0-byte
       chunk, then the rest. Uniform chunking would hide an offset bug. */
    CK_BYTE msig[4096]; CK_ULONG mlen = sizeof msig;
    ck("C_SignInit for multipart", C_SignInit(s, &m, hpriv) == CKR_OK, "");
    ck("C_SignUpdate, 1 byte",      C_SignUpdate(s, mp, 1) == CKR_OK, "");
    ck("C_SignUpdate, 0 bytes",     C_SignUpdate(s, mp + 1, 0) == CKR_OK, "");
    ck("C_SignUpdate, the rest",    C_SignUpdate(s, mp + 1, sizeof mp - 1) == CKR_OK, "");
    CK_ULONG mneed = 0;
    ck("C_SignFinal size query",
       C_SignFinal(s, NULL, &mneed) == CKR_OK && mneed == 3373, "");
    ck("C_SignFinal succeeds",
       C_SignFinal(s, msig, &mlen) == CKR_OK && mlen == 3373, "");

    C_VerifyInit(s, &m, hpub);
    ck("the streamed signature verifies through one-shot C_Verify",
       C_Verify(s, mp, sizeof mp, msig, mlen) == CKR_OK, "");

    /* And the converse: a one-shot signature verified in pieces. */
    CK_BYTE osig[4096]; CK_ULONG olen = sizeof osig;
    C_SignInit(s, &m, hpriv);
    ck("one-shot C_Sign over the same message",
       C_Sign(s, mp, sizeof mp, osig, &olen) == CKR_OK, "");
    ck("C_VerifyInit for multipart", C_VerifyInit(s, &m, hpub) == CKR_OK, "");
    ck("C_VerifyUpdate, 1 byte",     C_VerifyUpdate(s, mp, 1) == CKR_OK, "");
    ck("C_VerifyUpdate, the rest",   C_VerifyUpdate(s, mp + 1, sizeof mp - 1) == CKR_OK, "");
    ck("C_VerifyFinal accepts the one-shot signature",
       C_VerifyFinal(s, osig, olen) == CKR_OK, "");

    /* A single flipped byte in the middle of the stream must break it --
       otherwise the update calls are not actually feeding the digest. */
    mp[sizeof mp / 2] ^= 0x01;
    C_VerifyInit(s, &m, hpub);
    C_VerifyUpdate(s, mp, sizeof mp);
    ck("one flipped byte in the stream breaks verification",
       C_VerifyFinal(s, osig, olen) == CKR_SIGNATURE_INVALID, "");
    mp[sizeof mp / 2] ^= 0x01;

    /* Final with no Update at all is the empty message, and must agree with
       one-shot over zero bytes rather than being an error or a different
       digest. */
    CK_BYTE esig[4096]; CK_ULONG elen = sizeof esig;
    C_SignInit(s, &m, hpriv);
    ck("C_SignFinal with no Update signs the empty message",
       C_SignFinal(s, esig, &elen) == CKR_OK && elen == 3373, "");
    C_VerifyInit(s, &m, hpub);
    ck("and one-shot C_Verify over zero bytes accepts it",
       C_Verify(s, (CK_BYTE*)"", 0, esig, elen) == CKR_OK, "");

    /* An operation must not survive its Final. */
    ck("C_SignUpdate after Final is refused",
       C_SignUpdate(s, mp, 1) != CKR_OK, "");

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
