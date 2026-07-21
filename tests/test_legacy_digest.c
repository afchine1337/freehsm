/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_legacy_digest.c --- Non-FIPS digest gating (#125 general-purpose).
 *
 *  Verifies the interop/fips-strict profile gate for the legacy digests
 *  SHA-1 (0x220) and MD5 (0x210), which are executable only in the
 *  general-purpose (interop) build and rejected under fips-strict.
 *  Profile-adaptive: detects the active build via C_GetMechanismList,
 *  then asserts either correct computation (interop) or rejection
 *  (fips-strict). Works unchanged in `make tests` (fips-strict default)
 *  and in a `make PROFILE=interop tests` build.
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG, CK_RV, CK_SLOT_ID, CK_FLAGS, CK_SESSION_HANDLE;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG plen; } CK_MECHANISM;
#define CKR_MECHANISM_INVALID 0x70UL

static int advertised(CK_RV (*GML)(CK_SLOT_ID,CK_ULONG*,CK_ULONG*), CK_ULONG want) {
    CK_ULONG n = 0; GML(0, NULL, &n);
    CK_ULONG *l = calloc(n, sizeof *l); GML(0, l, &n);
    int found = 0;
    for (CK_ULONG i = 0; i < n; ++i) if (l[i] == want) { found = 1; break; }
    free(l); return found;
}

static int check_digest(void *h, CK_SESSION_HANDLE s, unsigned long mech,
                        const char *hexexp, int interop) {
    CK_RV (*DI)(CK_SESSION_HANDLE,CK_MECHANISM*); *(void**)&DI = dlsym(h,"C_DigestInit");
    CK_RV (*DG)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*); *(void**)&DG = dlsym(h,"C_Digest");
    CK_MECHANISM m = { mech, 0, 0 };
    CK_RV rv = DI(s, &m);
    if (!interop) {
        if (rv == CKR_MECHANISM_INVALID) { printf("  0x%lx rejected (fips-strict) : OK\n", mech); return 0; }
        fprintf(stderr, "  FAIL: 0x%lx not rejected under fips-strict (0x%lx)\n", mech, rv); return 1;
    }
    if (rv) { fprintf(stderr, "  FAIL: DigestInit 0x%lx -> 0x%lx\n", mech, rv); return 1; }
    CK_BYTE out[64]; CK_ULONG olen = 64;
    if (DG(s, (CK_BYTE*)"abc", 3, out, &olen)) { fprintf(stderr, "  FAIL: Digest\n"); return 1; }
    char hex[130] = {0};
    for (CK_ULONG i = 0; i < olen; ++i) sprintf(hex + 2*i, "%02x", out[i]);
    if (strcmp(hex, hexexp)) { fprintf(stderr, "  FAIL: 0x%lx digest %s != %s\n", mech, hex, hexexp); return 1; }
    printf("  0x%lx = %s (interop) : OK\n", mech, hex);
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
    void *h = dlopen("./libfreehsm-fips.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*I)(void*); *(void**)&I = dlsym(h,"C_Initialize");
    CK_RV (*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*); *(void**)&IT = dlsym(h,"C_InitToken");
    CK_RV (*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*); *(void**)&OS = dlsym(h,"C_OpenSession");
    CK_RV (*GML)(CK_SLOT_ID,CK_ULONG*,CK_ULONG*); *(void**)&GML = dlsym(h,"C_GetMechanismList");
    I(NULL); CK_BYTE so[] = "00000000"; IT(0, so, 8, fhsm_pad_label((CK_BYTE[32]){0}, "t"));
    CK_SESSION_HANDLE s; OS(0, 4|2, NULL, NULL, &s);

    int interop = advertised(GML, 0x220);   /* SHA-1 advertised iff interop */
    printf("test_legacy_digest : profile = %s\n", interop ? "interop" : "fips-strict");
    int rc = 0;
    rc |= check_digest(h, s, 0x220, "a9993e364706816aba3e25717850c26c9cd0d89d", interop); /* SHA-1 */
    rc |= check_digest(h, s, 0x210, "900150983cd24fb0d6963f7d28e17f72", interop);         /* MD5   */
    if (rc) return 1;
    printf("test_legacy_digest : PASS\n");
    return 0;
}
