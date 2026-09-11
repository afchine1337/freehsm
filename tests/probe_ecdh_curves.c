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
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize; CK_FLAGS flags; } CK_MECHANISM_INFO;

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
static CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID,CK_ULONG,CK_MECHANISM_INFO*);

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_GenerateKeyPair);
    SYM(C_GetAttributeValue); SYM(C_DeriveKey); SYM(C_CreateObject);
    SYM(C_GetMechanismInfo);
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

    /* X25519 agreement, which has no X9.62 point and no CKA_EC_POINT to read:
     * the peer's public key is 32 raw bytes. Two key pairs are generated and
     * each derives against the other's public key; the two shared secrets
     * must be equal, which is the property the mechanism exists for and the
     * only one worth asserting here. */
    {
        CK_BYTE t_true = 1, t_false = 0;
        CK_BYTE x_oid[] = { 0x06,0x03,0x2B,0x65,0x6E };   /* id-X25519 */
        CK_ATTRIBUTE pub_t[] = {
            { CKA_EC_PARAMS, x_oid, sizeof x_oid },
            { CKA_DERIVE,    &t_true, 1 },
        };
        CK_ATTRIBUTE prv_t[] = {
            { CKA_DERIVE,      &t_true, 1 },
            { CKA_EXTRACTABLE, &t_true, 1 },
        };
        /* Ask the module whether it has the mechanism at all rather than
         * assuming. A fips-strict build does not: the OpenSSL FIPS provider
         * has no X25519, so the three Montgomery mechanisms are interop-only.
         * Skipping on the module's own answer is also what keeps this probe
         * honest if that ever changes. */
        CK_MECHANISM_INFO mi;
        if (!C_GetMechanismInfo
            || C_GetMechanismInfo(0, 0x1056UL, &mi) != CKR_OK) {
            printf("\n%-20s  not advertised in this profile -- skipped\n", "X25519");
            goto done_x25519;
        }
        CK_MECHANISM kg = { 0x1056UL /* CKM_EC_MONTGOMERY_KEY_PAIR_GEN */, NULL, 0 };
        CK_OBJECT_HANDLE pubA = 0, prvA = 0, pubB = 0, prvB = 0;
        CK_RV ga = C_GenerateKeyPair(s, &kg, pub_t, 2, prv_t, 2, &pubA, &prvA);
        CK_RV gb = C_GenerateKeyPair(s, &kg, pub_t, 2, prv_t, 2, &pubB, &prvB);
        printf("\n%-20s  keygen A=0x%lx B=0x%lx\n", "X25519",
               (unsigned long)ga, (unsigned long)gb);
        if (ga != CKR_OK || gb != CKR_OK) { fails++; }
        else {
            CK_BYTE ptA[64], ptB[64];
            CK_ATTRIBUTE qa[] = { { CKA_EC_POINT, ptA, sizeof ptA } };
            CK_ATTRIBUTE qb[] = { { CKA_EC_POINT, ptB, sizeof ptB } };
            CK_RV ra = C_GetAttributeValue(s, pubA, qa, 1);
            CK_RV rb = C_GetAttributeValue(s, pubB, qb, 1);
            printf("%-20s  CKA_EC_POINT A=0x%lx (%lu) B=0x%lx (%lu)\n", "",
                   (unsigned long)ra, (unsigned long)qa[0].ulValueLen,
                   (unsigned long)rb, (unsigned long)qb[0].ulValueLen);
            /* The raw 32 bytes, however the module chose to present them. */
            CK_BYTE *rawA = ptA, *rawB = ptB;
            CK_ULONG rawAl = qa[0].ulValueLen, rawBl = qb[0].ulValueLen;
            if (rawAl == 34 && rawA[0] == 0x04) { rawA += 2; rawAl = 32; }
            if (rawBl == 34 && rawB[0] == 0x04) { rawB += 2; rawBl = 32; }

            CK_BYTE zA[64], zB[64];
            CK_ULONG zAl = sizeof zA, zBl = sizeof zB;
            CK_ULONG vl = 32;
            CK_ATTRIBUTE out_t[] = {
                { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
                { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
                { CKA_VALUE_LEN,   &vl, sizeof(CK_ULONG) },
                { CKA_EXTRACTABLE, &t_true,  1 },
                { CKA_SENSITIVE,   &t_false, 1 },
            };
            CK_ECDH1_DERIVE_PARAMS pa = { CKD_NULL, 0, NULL, rawBl, rawB };
            CK_ECDH1_DERIVE_PARAMS pb = { CKD_NULL, 0, NULL, rawAl, rawA };
            CK_MECHANISM ma = { 0x1052UL, &pa, sizeof pa };
            CK_MECHANISM mb = { 0x1052UL, &pb, sizeof pb };
            CK_OBJECT_HANDLE kA = 0, kB = 0;
            CK_RV da = C_DeriveKey(s, &ma, prvA, out_t, 5, &kA);
            CK_RV db = C_DeriveKey(s, &mb, prvB, out_t, 5, &kB);
            printf("%-20s  derive A=0x%lx B=0x%lx\n", "",
                   (unsigned long)da, (unsigned long)db);
            int agree = 0;
            if (da == CKR_OK && db == CKR_OK) {
                CK_ATTRIBUTE va[] = { { 0x11UL /* CKA_VALUE */, zA, zAl } };
                CK_ATTRIBUTE vb[] = { { 0x11UL, zB, zBl } };
                if (C_GetAttributeValue(s, kA, va, 1) == CKR_OK
                    && C_GetAttributeValue(s, kB, vb, 1) == CKR_OK
                    && va[0].ulValueLen == vb[0].ulValueLen
                    && memcmp(zA, zB, va[0].ulValueLen) == 0)
                    agree = 1;
            }
            printf("%-20s  both parties agree on Z: %s\n", "", agree ? "OK" : "FAIL");
            if (!agree) fails++;
        }
    done_x25519: ;
    }

    printf("\n0x0=OK  0x5=FUNCTION_FAILED  0x13=ATTRIBUTE_VALUE_INVALID"
           "  0x63=KEY_TYPE_INCONSISTENT  0x70=MECHANISM_INVALID\n");
    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
