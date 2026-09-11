/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * probe_ecdh_curves.c --- which stage of an ECDH agreement fails, per curve.
 *
 * 7,185 Wycheproof vectors report "advertised ECDH derive is not operational:
 * CKR_FUNCTION_FAILED", concentrated on secp384r1, secp521r1 and the
 * brainpool curves, while secp256r1 passes. The aggregate says which curves
 * and says CKR_FUNCTION_FAILED; it does not say which call produced it, and
 * C_DeriveKey's ECDH path has five places that return exactly that.
 *
 * This is a probe, not a conformance test. It walks one curve at a time
 * through generate -> read the public point -> derive, and prints the CKR of
 * each stage, so the failing step is named rather than inferred.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG kdf; CK_ULONG ulSharedDataLen; void *pSharedData;
                 CK_ULONG ulPublicDataLen; void *pPublicData; } CK_ECDH1_DERIVE_PARAMS;

#define CKR_OK              0UL
#define CKF_RW              6UL
#define CKA_CLASS           0UL
#define CKA_KEY_TYPE        0x100UL
#define CKA_EC_PARAMS       0x180UL
#define CKA_EC_POINT        0x181UL
#define CKA_DERIVE          0x10CUL
#define CKA_VALUE_LEN       0x161UL
#define CKA_EXTRACTABLE     0x162UL
#define CKA_SENSITIVE       0x103UL
#define CKO_SECRET_KEY      4UL
#define CKK_EC              3UL
#define CKK_GENERIC_SECRET  0x10UL
#define CKM_EC_KEY_PAIR_GEN 0x1040UL
#define CKM_ECDH1_DERIVE    0x1050UL
#define CKD_NULL            1UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                                   CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);

/* d_len is the curve's private-scalar size. The scalar itself is built as
 * 0x01 followed by an increasing pattern, which is comfortably below every
 * group order here and needs no per-curve constant. */
static int fails = 0;

static const struct { const char *name; const CK_BYTE *oid; CK_ULONG oid_len;
                      CK_ULONG d_len; } CURVES[] = {
    { "secp256r1 (P-256)", (const CK_BYTE*)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07", 10, 32 },
    { "secp384r1 (P-384)", (const CK_BYTE*)"\x06\x05\x2B\x81\x04\x00\x22",              7, 48 },
    { "secp521r1 (P-521)", (const CK_BYTE*)"\x06\x05\x2B\x81\x04\x00\x23",              7, 66 },
};

static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_GenerateKeyPair);
    SYM(C_GetAttributeValue); SYM(C_DeriveKey); SYM(C_CreateObject);
    if (!C_GenerateKeyPair || !C_DeriveKey) { fprintf(stderr,"missing symbols\n"); return 2; }

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"ecdhprobe",9);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"C_Login SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_Login USER\n"); return 2; }

    printf("%-20s  %-8s  %-18s  %-8s  %-10s  %s\n",
           "curve", "keygen", "CKA_EC_POINT", "derive", "import d", "derive(imp)");
    printf("%-20s  %-8s  %-18s  %-8s  %-10s  %s\n",
           "-----", "------", "------------", "------", "--------", "-----------");

    for (size_t c = 0; c < sizeof CURVES / sizeof CURVES[0]; ++c) {
        CK_BYTE t_true = 1, t_false = 0;
        CK_ATTRIBUTE pub_t[] = {
            { CKA_EC_PARAMS, (void*)CURVES[c].oid, CURVES[c].oid_len },
            { CKA_DERIVE,    &t_true, 1 },
        };
        CK_ATTRIBUTE prv_t[] = {
            { CKA_DERIVE,      &t_true, 1 },
            { CKA_EXTRACTABLE, &t_true, 1 },
        };
        CK_MECHANISM kg = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE pub = 0, prv = 0;
        CK_RV rv_gen = C_GenerateKeyPair(s, &kg, pub_t, 2, prv_t, 2, &pub, &prv);

        /* Wide enough for "OK (" + a 20-digit size_t + " bytes)", which is
         * what -Wformat-truncation counts rather than the lengths that
         * actually occur. */
        char pt_s[48] = "-", drv_s[24] = "-";
        CK_BYTE point[256];
        CK_ULONG point_len = 0;
        CK_RV rv_pt = 0xFFFF, rv_drv = 0xFFFF;

        if (rv_gen == CKR_OK) {
            CK_ATTRIBUTE q[] = { { CKA_EC_POINT, point, sizeof point } };
            rv_pt = C_GetAttributeValue(s, pub, q, 1);
            point_len = q[0].ulValueLen;
            if (rv_pt == CKR_OK && point_len != (CK_ULONG)-1)
                snprintf(pt_s, sizeof pt_s, "OK (%lu bytes)", (unsigned long)point_len);
            else
                snprintf(pt_s, sizeof pt_s, "0x%lx", (unsigned long)rv_pt);

            if (rv_pt == CKR_OK && point_len != (CK_ULONG)-1) {
                CK_ECDH1_DERIVE_PARAMS p = { CKD_NULL, 0, NULL, point_len, point };
                CK_MECHANISM m = { CKM_ECDH1_DERIVE, &p, sizeof p };
                CK_ULONG vl = 32;
                CK_ATTRIBUTE out_t[] = {
                    { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
                    { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
                    { CKA_VALUE_LEN,   &vl, sizeof(CK_ULONG) },
                    { CKA_EXTRACTABLE, &t_true,  1 },
                    { CKA_SENSITIVE,   &t_false, 1 },
                };
                CK_OBJECT_HANDLE out = 0;
                rv_drv = C_DeriveKey(s, &m, prv, out_t, 5, &out);
                snprintf(drv_s, sizeof drv_s,
                         rv_drv == CKR_OK ? "OK" : "0x%lx", (unsigned long)rv_drv);
            }
        }
        /* The standards-conforming import: CKA_VALUE is the X9.62 private
         * value d, CKA_EC_PARAMS the curve. This is what an application that
         * holds its own key material sends, and what the Wycheproof vectors
         * send, and it is not what key generation produces. */
        char imp_s[24] = "-", drv2_s[24] = "-";
        if (rv_pt == CKR_OK && point_len != (CK_ULONG)-1) {
            CK_BYTE d[72];
            for (CK_ULONG i = 0; i < CURVES[c].d_len; ++i)
                d[i] = (CK_BYTE)(i == 0 ? 1 : i);
            CK_ATTRIBUTE imp_t[] = {
                { CKA_CLASS,     &(CK_ULONG){3UL /* CKO_PRIVATE_KEY */}, sizeof(CK_ULONG) },
                { CKA_KEY_TYPE,  &(CK_ULONG){CKK_EC},                    sizeof(CK_ULONG) },
                { CKA_EC_PARAMS, (void*)CURVES[c].oid, CURVES[c].oid_len },
                { 0x11UL /* CKA_VALUE */, d, CURVES[c].d_len },
                { CKA_DERIVE,    &t_true, 1 },
            };
            CK_OBJECT_HANDLE imported = 0;
            CK_RV rv_imp = C_CreateObject(s, imp_t, 5, &imported);
            snprintf(imp_s, sizeof imp_s,
                     rv_imp == CKR_OK ? "OK" : "0x%lx", (unsigned long)rv_imp);
            if (rv_imp == CKR_OK) {
                CK_ECDH1_DERIVE_PARAMS p = { CKD_NULL, 0, NULL, point_len, point };
                CK_MECHANISM m = { CKM_ECDH1_DERIVE, &p, sizeof p };
                CK_ULONG vl = 32;
                CK_ATTRIBUTE out_t[] = {
                    { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
                    { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
                    { CKA_VALUE_LEN,   &vl, sizeof(CK_ULONG) },
                    { CKA_EXTRACTABLE, &t_true,  1 },
                    { CKA_SENSITIVE,   &t_false, 1 },
                };
                CK_OBJECT_HANDLE out2 = 0;
                CK_RV r2 = C_DeriveKey(s, &m, imported, out_t, 5, &out2);
                snprintf(drv2_s, sizeof drv2_s,
                         r2 == CKR_OK ? "OK" : "0x%lx", (unsigned long)r2);
            }
        }

        printf("%-20s  0x%-6lx  %-18s  %-8s  %-10s  %s\n",
               CURVES[c].name, (unsigned long)rv_gen, pt_s, drv_s, imp_s, drv2_s);

        /* Every stage must succeed on every curve. The table above is for a
         * human reading a failure; this is what makes the file a test. */
        if (rv_gen != CKR_OK || rv_pt != CKR_OK || rv_drv != CKR_OK
            || strcmp(imp_s, "OK") != 0 || strcmp(drv2_s, "OK") != 0)
            fails++;
    }

    printf("\n0x0=OK  0x5=FUNCTION_FAILED  0x13=ATTRIBUTE_VALUE_INVALID"
           "  0x63=KEY_TYPE_INCONSISTENT  0x70=MECHANISM_INVALID\n");
    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
