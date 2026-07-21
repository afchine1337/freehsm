/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_legacy_cipher.c --- Non-FIPS cipher gating (#125 general-purpose).
 *
 *  AES-ECB (0x1081) is FIPS-approved (SP 800-38A) and round-trips in both
 *  profiles. 3DES-CBC (0x133) and 3DES key generation (0x130) are
 *  non-approved: executable only in interop, rejected under fips-strict.
 *  Profile detected via C_GetMechanismList (3DES keygen advertised iff interop).
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG, CK_RV, CK_SLOT_ID, CK_FLAGS, CK_SESSION_HANDLE, CK_OBJECT_HANDLE;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG plen; } CK_MECHANISM;

static void *H;
#define SY(f,n) *(void**)&f = dlsym(H, n)
static CK_RV (*EI)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*EN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV (*DI)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*DE)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);

/* Round-trip a block cipher via handle ko ; returns 0 on success. */
static int roundtrip(CK_SESSION_HANDLE s, CK_MECHANISM *m, CK_OBJECT_HANDLE ko,
                     const char *name) {
    CK_RV rv = EI(s, m, ko);
    if (rv) { fprintf(stderr, "  FAIL %s EncryptInit 0x%lx\n", name, rv); return 1; }
    CK_BYTE pt[16], ct[32], bk[32]; CK_ULONG cl = 32, bl = 32;
    for (int i = 0; i < 16; ++i) pt[i] = (CK_BYTE)(0x20 + i);
    if ((rv = EN(s, pt, 16, ct, &cl))) { fprintf(stderr, "  FAIL %s Encrypt 0x%lx\n", name, rv); return 1; }
    if ((rv = DI(s, m, ko)))           { fprintf(stderr, "  FAIL %s DecryptInit 0x%lx\n", name, rv); return 1; }
    if ((rv = DE(s, ct, cl, bk, &bl))) { fprintf(stderr, "  FAIL %s Decrypt 0x%lx\n", name, rv); return 1; }
    if (bl != 16 || memcmp(bk, pt, 16)) { fprintf(stderr, "  FAIL %s round-trip mismatch\n", name); return 1; }
    printf("  %s round-trip : OK\n", name);
    return 0;
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
    CK_RV (*I)(void*); SY(I,"C_Initialize");
    CK_RV (*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*); SY(IT,"C_InitToken");
    CK_RV (*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*); SY(OS,"C_OpenSession");
    CK_RV (*LI)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG); SY(LI,"C_Login");
    CK_RV (*IP)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG); SY(IP,"C_InitPIN");
    CK_RV (*CO)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*); SY(CO,"C_CreateObject");
    CK_RV (*GK)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*); SY(GK,"C_GenerateKey");
    CK_RV (*GML)(CK_SLOT_ID,CK_ULONG*,CK_ULONG*); SY(GML,"C_GetMechanismList");
    SY(EI,"C_EncryptInit"); SY(EN,"C_Encrypt"); SY(DI,"C_DecryptInit"); SY(DE,"C_Decrypt");

    I(NULL); CK_BYTE so[] = "00000000", us[] = "user0000";
    IT(0, so, 8, fhsm_pad_label((CK_BYTE[32]){0}, "t"));
    CK_SESSION_HANDLE s; OS(0, 4|2, NULL, NULL, &s);
    LI(s, 0, so, 8); IP(s, us, 8); LI(s, 1, us, 8);

    CK_ULONG mn = 0; GML(0, NULL, &mn);
    CK_ULONG *ml = calloc(mn, sizeof *ml); GML(0, ml, &mn);
    /* 3DES key generation (0x130) is non-approved -> advertised only in the
     * interop build ; use it to detect the active profile. AES-ECB is now
     * FIPS-approved (SP 800-38A) and available in both profiles. */
    int strict = 1; for (CK_ULONG i = 0; i < mn; ++i) if (ml[i] == 0x130) { strict = 0; break; }
    free(ml);
    printf("test_legacy_cipher : profile = %s\n", strict ? "fips-strict" : "interop");

    /* AES key for ECB (imported). */
    CK_ULONG cls = 4, kt = 0x1F; CK_BYTE ak[16]; for (int i = 0; i < 16; ++i) ak[i] = (CK_BYTE)i;
    CK_ATTRIBUTE at[] = { {0,&cls,8}, {0x100,&kt,8}, {0x11,ak,16} };
    CK_OBJECT_HANDLE akey = 0; CK_RV rv = CO(s, at, 3, &akey);
    if (rv) { fprintf(stderr, "CreateObject 0x%lx\n", rv); return 2; }

    CK_MECHANISM ecb = { 0x1081, NULL, 0 };
    CK_BYTE iv8[8] = {1,2,3,4,5,6,7,8};
    CK_MECHANISM d3 = { 0x133, iv8, 8 };
    CK_MECHANISM kg = { 0x130, NULL, 0 };

    /* AES-ECB is FIPS-approved and must round-trip in BOTH profiles. */
    int rc = roundtrip(s, &ecb, akey, "AES-ECB");

    if (strict) {
        /* 3DES-CBC at EncryptInit and 3DES keygen must be rejected. */
        if (EI(s, &d3, akey) == 0) { fprintf(stderr, "  FAIL 3DES-CBC not rejected\n"); return 1; }
        printf("  3DES-CBC rejected : OK\n");
        CK_OBJECT_HANDLE dk = 0;
        if (GK(s, &kg, NULL, 0, &dk) == 0) { fprintf(stderr, "  FAIL DES3 keygen not rejected\n"); return 1; }
        printf("  3DES keygen rejected : OK\n");
        if (rc) return 1;
        printf("test_legacy_cipher : PASS\n");
        return 0;
    }

    /* interop : 3DES round-trips too. */
    CK_OBJECT_HANDLE dk = 0;
    if ((rv = GK(s, &kg, NULL, 0, &dk))) { fprintf(stderr, "  FAIL DES3 keygen 0x%lx\n", rv); return 1; }
    printf("  3DES keygen : OK\n");
    rc |= roundtrip(s, &d3, dk, "3DES-CBC");
    if (rc) return 1;
    printf("test_legacy_cipher : PASS\n");
    return 0;
}
