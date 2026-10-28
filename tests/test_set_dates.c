/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_set_dates.c --- CKA_START_DATE / CKA_END_DATE, and a data object's
 * CKA_APPLICATION, through C_SetAttributeValue.
 *
 * Both were stored since the v3 object record and settable at creation, but
 * C_SetAttributeValue had no arm for them and answered
 * CKR_ATTRIBUTE_TYPE_INVALID. Checked here: a key's dates change and read
 * back; an empty date clears one; a malformed date is refused and changes
 * nothing; a template that fails on another row leaves the dates as they
 * were; a data object, which has no dates, refuses them; and the change
 * survives C_Finalize / C_Initialize, which is what the setter's own write
 * is for.
 * ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG l; } CK_MECHANISM;

#define CKA_CLASS       0x000UL
#define CKA_TOKEN       0x001UL
#define CKA_LABEL       0x003UL
#define CKA_VALUE       0x011UL
#define CKA_KEY_TYPE    0x100UL
#define CKA_START_DATE  0x110UL
#define CKA_END_DATE    0x111UL
#define CKA_VALUE_LEN   0x161UL
#define CKA_APPLICATION 0x010UL

static CK_RV (*GA)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*SA)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static int fails = 0;
static char D_2026[] = "20261101", D_2027[] = "20271101", D_2030[] = "20300101",
            D_BAD[] = "2026-11-", HELLO[] = "hello", APP[] = "billing-service",
            APPDATA[] = "appdata", LONG65[66] =
            "0123456789012345678901234567890123456789012345678901234567890123X";

static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

/* Does `a` on `k` read back as exactly `want` (n bytes, n may be 0)? */
static int reads(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k, CK_ULONG a,
                 const char *want, size_t n) {
    CK_BYTE buf[80]; CK_ATTRIBUTE t = { a, buf, sizeof buf };
    if (GA(s, k, &t, 1) != 0 || t.ulValueLen != n) return 0;
    return n == 0 || memcmp(buf, want, n) == 0;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

int main(void) {
    void *H = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!H) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*I)(void*); CK_RV (*F)(void*);
    CK_RV (*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*L)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*LO)(CK_SESSION_HANDLE);
    CK_RV (*IP)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*GK)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*CO)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*FI)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
    CK_RV (*FO)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
    CK_RV (*FF)(CK_SESSION_HANDLE);
    #define S(n,nm) *(void**)&n = dlsym(H, nm)
    S(I,"C_Initialize"); S(F,"C_Finalize"); S(IT,"C_InitToken"); S(OS,"C_OpenSession");
    S(L,"C_Login"); S(LO,"C_Logout"); S(IP,"C_InitPIN"); S(GK,"C_GenerateKey");
    S(CO,"C_CreateObject"); S(GA,"C_GetAttributeValue"); S(SA,"C_SetAttributeValue");
    S(FI,"C_FindObjectsInit"); S(FO,"C_FindObjects"); S(FF,"C_FindObjectsFinal");

    printf("CKA_START_DATE / CKA_END_DATE through C_SetAttributeValue\n\n");

    I(NULL); CK_BYTE so[] = "00000000", up[] = "user0000";
    IT(0, so, 8, pad_label((CK_BYTE[32]){0}, "dates"));
    CK_SESSION_HANDLE s = 0; OS(0, 6, NULL, NULL, &s);
    L(s, 0, so, 8); IP(s, up, 8); LO(s);
    if (L(s, 1, up, 8) != 0) { fprintf(stderr, "cannot log in\n"); return 2; }

    /* A token AES key, labelled, so it can be found again after a reload. */
    CK_ULONG cls = 4, kt = 0x1F, vl = 32; CK_BYTE T = 1;
    char label[] = "dated";
    CK_ATTRIBUTE at[] = { {CKA_CLASS,&cls,8}, {CKA_KEY_TYPE,&kt,8}, {CKA_VALUE_LEN,&vl,8},
                          {CKA_TOKEN,&T,1}, {CKA_LABEL,label,sizeof label - 1} };
    CK_OBJECT_HANDLE k = 0; CK_MECHANISM gen = { 0x1080, 0, 0 };
    if (GK(s, &gen, at, 5, &k) != 0) { fprintf(stderr, "FAIL keygen\n"); return 1; }

    CK_ATTRIBUTE both[] = { {CKA_START_DATE,D_2026,8}, {CKA_END_DATE,D_2027,8} };
    ok(SA(s, k, both, 2) == 0, "a key's start and end dates are set");
    ok(reads(s, k, CKA_START_DATE, "20261101", 8) && reads(s, k, CKA_END_DATE, "20271101", 8),
       "and read back");

    CK_ATTRIBUTE bad = { CKA_START_DATE, D_BAD, 8 };
    ok(SA(s, k, &bad, 1) == 0x13UL, "a malformed date: CKR_ATTRIBUTE_VALUE_INVALID");
    ok(reads(s, k, CKA_START_DATE, "20261101", 8), "and the date is unchanged");

    CK_ULONG other = 3;
    CK_ATTRIBUTE mixed[] = { {CKA_START_DATE,D_2030,8}, {CKA_CLASS,&other,8} };
    ok(SA(s, k, mixed, 2) == 0x10UL, "a template failing on CKA_CLASS: CKR_ATTRIBUTE_READ_ONLY");
    ok(reads(s, k, CKA_START_DATE, "20261101", 8), "and its valid date row is not applied");

    CK_ATTRIBUTE clear = { CKA_END_DATE, NULL, 0 };
    ok(SA(s, k, &clear, 1) == 0, "an empty end date is accepted");
    ok(reads(s, k, CKA_END_DATE, NULL, 0) && reads(s, k, CKA_START_DATE, "20261101", 8),
       "and clears that date only");

    CK_ULONG dcls = 0; CK_BYTE Fb = 0;
    CK_ATTRIBUTE dt[] = { {CKA_CLASS,&dcls,8}, {CKA_TOKEN,&Fb,1}, {CKA_VALUE,HELLO,5} };
    CK_OBJECT_HANDLE d = 0;
    if (CO(s, dt, 3, &d) != 0) { fprintf(stderr, "FAIL data object\n"); return 1; }
    CK_ATTRIBUTE dd = { CKA_START_DATE, D_2026, 8 };
    ok(SA(s, d, &dd, 1) == 0x12UL, "a data object has no dates: CKR_ATTRIBUTE_TYPE_INVALID");

    /* CKA_APPLICATION: a data object's, settable; a key has none. */
    CK_ATTRIBUTE pt_[] = { {CKA_CLASS,&dcls,8}, {CKA_TOKEN,&T,1}, {CKA_VALUE,HELLO,5},
                           {CKA_LABEL,APPDATA,sizeof APPDATA - 1} };
    CK_OBJECT_HANDLE pd = 0;
    if (CO(s, pt_, 4, &pd) != 0) { fprintf(stderr, "FAIL token data object\n"); return 1; }
    CK_ATTRIBUTE app = { CKA_APPLICATION, APP, sizeof APP - 1 };
    ok(SA(s, pd, &app, 1) == 0 && reads(s, pd, CKA_APPLICATION, APP, sizeof APP - 1),
       "a data object's CKA_APPLICATION is set and reads back");
    CK_ATTRIBUTE toolong = { CKA_APPLICATION, LONG65, 65 };
    ok(SA(s, pd, &toolong, 1) == 0x13UL && reads(s, pd, CKA_APPLICATION, APP, sizeof APP - 1),
       "65 bytes: CKR_ATTRIBUTE_VALUE_INVALID, value unchanged");
    ok(SA(s, k, &app, 1) == 0x12UL, "a key has no CKA_APPLICATION: CKR_ATTRIBUTE_TYPE_INVALID");

    /* The change is on disk, not only in this process's memory. */
    F(NULL); I(NULL);
    OS(0, 6, NULL, NULL, &s);
    if (L(s, 1, up, 8) != 0) { fprintf(stderr, "cannot log in again\n"); return 2; }
    CK_ATTRIBUTE ft = { CKA_LABEL, label, sizeof label - 1 };
    CK_OBJECT_HANDLE found = 0; CK_ULONG nf = 0;
    FI(s, &ft, 1); FO(s, &found, 1, &nf); FF(s);
    ok(nf == 1 && reads(s, found, CKA_START_DATE, "20261101", 8)
              && reads(s, found, CKA_END_DATE, NULL, 0),
       "after C_Finalize and C_Initialize, the dates are as set");
    CK_ATTRIBUTE fa = { CKA_LABEL, APPDATA, sizeof APPDATA - 1 };
    nf = 0; FI(s, &fa, 1); FO(s, &found, 1, &nf); FF(s);
    ok(nf == 1 && reads(s, found, CKA_APPLICATION, APP, sizeof APP - 1),
       "and so is CKA_APPLICATION");
    CK_ATTRIBUTE noapp = { CKA_APPLICATION, NULL, 0 };
    ok(nf == 1 && SA(s, found, &noapp, 1) == 0 && reads(s, found, CKA_APPLICATION, NULL, 0),
       "an empty CKA_APPLICATION clears it");
    F(NULL);

    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
