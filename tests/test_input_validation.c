/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_input_validation.c --- Regression test for parameter/attribute
 * validation hardening (#125, pkcs11-check security cluster:
 * test_mechanism_param_invalid, TestGcmIvWeakness, TestRsaExponent,
 * test_scalar_attr_length_extended). Each probe must be REJECTED, not
 * silently accepted. Uses a fresh session per probe so a prior
 * successful C_*Init does not mask the next with CKR_OPERATION_ACTIVE.
 * ========================================================================= */
#include <stdio.h>
#include <dlfcn.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID, CK_FLAGS;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG l; } CK_MECHANISM;

#define CKR_OK 0UL
#define CKR_ATTRIBUTE_VALUE_INVALID  0x13UL
#define CKR_MECHANISM_PARAM_INVALID  0x71UL

static void *H;
static CK_RV (*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*CS)(CK_SESSION_HANDLE);
static CK_RV (*L)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*EI)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV (*GK)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*GKP)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_OBJECT_HANDLE AESK;
static CK_BYTE up[] = "user0000";
static int fails = 0;

static CK_SESSION_HANDLE fresh(void) { CK_SESSION_HANDLE s; OS(0,6,NULL,NULL,&s); L(s,1,up,8); return s; }
static void expect(CK_RV got, CK_RV want, const char *name) {
    if (got != want) { fprintf(stderr, "FAIL: %s -> 0x%lx (want 0x%lx)\n", name, (unsigned long)got, (unsigned long)want); fails++; }
    else printf("  %-38s -> 0x%lx : OK\n", name, (unsigned long)want);
}
static CK_RV gcm(CK_SESSION_HANDLE s, CK_ULONG ivlen) {
    CK_BYTE iv[16] = {0};
    struct { void *pIv; CK_ULONG il, ib; void *pAAD; CK_ULONG al, tb; } g = { iv, ivlen, ivlen*8, NULL, 0, 128 };
    CK_MECHANISM m = { 0x1087, &g, sizeof g };
    return EI(s, &m, AESK);
}

int main(void) {
    H = dlopen("./libfreehsm-fips.so", RTLD_NOW);
    if (!H) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*I)(void*); CK_RV (*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*); CK_RV (*IP)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    #define S(n,nm) *(void**)&n = dlsym(H, nm)
    S(I,"C_Initialize"); S(IT,"C_InitToken"); S(OS,"C_OpenSession"); S(CS,"C_CloseSession");
    S(L,"C_Login"); S(IP,"C_InitPIN"); S(EI,"C_EncryptInit"); S(GK,"C_GenerateKey"); S(GKP,"C_GenerateKeyPair");

    I(NULL); CK_BYTE so[] = "00000000";
    IT(0, so, 8, (CK_BYTE*)"val"); CK_SESSION_HANDLE s0; OS(0,6,NULL,NULL,&s0);
    L(s0,0,so,8); IP(s0,up,8); (void)L(s0,1,up,8);
    CK_ULONG cls=4, kt=0x1F, vl=32;
    CK_ATTRIBUTE at[] = { {0,&cls,8}, {0x100,&kt,8}, {0x161,&vl,8} };
    GK(s0, &(CK_MECHANISM){0x1080,0,0}, at, 3, &AESK);

    /* AES-CBC IV length */
    { CK_SESSION_HANDLE s=fresh(); CK_BYTE iv8[8]={0}; expect(EI(s,&(CK_MECHANISM){0x1082,iv8,8},AESK), CKR_MECHANISM_PARAM_INVALID, "EncryptInit CBC 8-byte IV"); CS(s); }
    { CK_SESSION_HANDLE s=fresh(); CK_BYTE iv16[16]={0}; expect(EI(s,&(CK_MECHANISM){0x1082,iv16,16},AESK), CKR_OK, "EncryptInit CBC 16-byte IV"); CS(s); }
    /* AES-GCM weak IV */
    { CK_SESSION_HANDLE s=fresh(); expect(gcm(s,0),  CKR_MECHANISM_PARAM_INVALID, "EncryptInit GCM 0-byte IV"); CS(s); }
    { CK_SESSION_HANDLE s=fresh(); expect(gcm(s,4),  CKR_MECHANISM_PARAM_INVALID, "EncryptInit GCM 4-byte IV"); CS(s); }
    { CK_SESSION_HANDLE s=fresh(); expect(gcm(s,12), CKR_OK,                      "EncryptInit GCM 12-byte IV"); CS(s); }
    /* RSA public exponent */
    { CK_ULONG mb=2048; CK_BYTE e4[]={4}; CK_ATTRIBUTE pub[]={{0x121,&mb,8},{0x122,e4,1}}; CK_OBJECT_HANDLE a,b;
      expect(GKP(s0,&(CK_MECHANISM){0,0,0},pub,2,NULL,0,&a,&b), CKR_ATTRIBUTE_VALUE_INVALID, "GenKeyPair RSA e=4"); }
    { CK_ULONG mb=2048; CK_BYTE e1[]={1}; CK_ATTRIBUTE pub[]={{0x121,&mb,8},{0x122,e1,1}}; CK_OBJECT_HANDLE a,b;
      expect(GKP(s0,&(CK_MECHANISM){0,0,0},pub,2,NULL,0,&a,&b), CKR_ATTRIBUTE_VALUE_INVALID, "GenKeyPair RSA e=1"); }
    { CK_ULONG mb=2048; CK_BYTE e[]={1,0,1}; CK_ATTRIBUTE pub[]={{0x121,&mb,8},{0x122,e,3}}; CK_OBJECT_HANDLE a,b;
      expect(GKP(s0,&(CK_MECHANISM){0,0,0},pub,2,NULL,0,&a,&b), CKR_OK, "GenKeyPair RSA e=65537"); }
    /* Boolean attribute overlong (CK_ULONG-sized CKA_ENCRYPT) */
    { CK_ULONG big=1; CK_ATTRIBUTE t[]={{0,&(CK_ULONG){4},8},{0x100,&(CK_ULONG){0x1F},8},{0x161,&(CK_ULONG){32},8},{0x104,&big,8}};
      CK_OBJECT_HANDLE k; expect(GK(s0,&(CK_MECHANISM){0x1080,0,0},t,4,&k), CKR_ATTRIBUTE_VALUE_INVALID, "GenerateKey overlong CKA_ENCRYPT"); }

    if (fails) { fprintf(stderr, "test_input_validation : %d FAIL\n", fails); return 1; }
    printf("test_input_validation : PASS\n");
    return 0;
}
