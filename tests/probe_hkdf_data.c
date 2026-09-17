/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * probe_hkdf_data.c --- why the corpus reports
 *
 *     advertised but rejected a canonical op (1): CKM_HKDF_DATA
 *
 * That line is set algebra: advertised, cleanly refused at least once, and
 * never accepted anywhere. It says the module refuses something; it does not
 * say what, and the two candidates are a missing CKA_VALUE_LEN and the
 * CKA_DERIVE usage gate on the base key. Rather than reason about which,
 * this asks.
 *
 * The shapes below are the harness's own, read from
 * pkcs11-check/src/pkcs11_check/testcases/test_hkdf_extended.py: base key
 * CKK_GENERIC_SECRET with CKA_DERIVE, then C_DeriveKey with
 * CKA_CLASS=CKO_SECRET_KEY, CKA_KEY_TYPE=CKK_GENERIC_SECRET, extract and
 * expand both set, and no CKA_VALUE_LEN. Its _hkdf_derive and
 * _hkdf_data_derive helpers carry identical templates, so case B is here to
 * show whether CKM_HKDF_DERIVE is refused too -- it escapes the gap list only
 * because some other test accepts it.
 *
 * This prints; it does not assert, and it always exits 0. It answered its
 * question -- the answer is in docs/PKCS11_CHECK_FINDINGS.md -- and is kept
 * because the next HKDF discrepancy will ask the same one: which rule, of the
 * several that can refuse a derivation, actually refused this one. A return
 * code in a report names the mechanism, not the rule.
 *
 *   make tests/probe_hkdf_data
 *   FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$(mktemp -d) \
 *       OPENSSL_CONF=/dev/null ./tests/probe_hkdf_data
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

typedef struct {
    CK_BYTE          bExtract;
    CK_BYTE          bExpand;
    CK_ULONG         prfHashMechanism;
    CK_ULONG         ulSaltType;
    void            *pSalt;
    CK_ULONG         ulSaltLen;
    CK_OBJECT_HANDLE hSaltKey;
    void            *pInfo;
    CK_ULONG         ulInfoLen;
} CK_HKDF_PARAMS;

#define CKF_RW                        6UL
#define CKA_CLASS                     0UL
#define CKA_VALUE                     0x11UL
#define CKA_KEY_TYPE                  0x100UL
#define CKA_SENSITIVE                 0x103UL
#define CKA_DERIVE                    0x10CUL
#define CKA_VALUE_LEN                 0x161UL
#define CKA_EXTRACTABLE               0x162UL
#define CKO_SECRET_KEY                4UL
#define CKK_GENERIC_SECRET            0x10UL
#define CKM_HKDF_DERIVE               0x402AUL
#define CKM_HKDF_DATA                 0x402BUL
#define CKM_SHA256                    0x250UL
#define CKF_HKDF_SALT_DATA            2UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*);
static CK_RV (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);

static const char *ckr(CK_RV rv) {
    switch (rv) {
        case 0x000UL: return "CKR_OK";
        case 0x007UL: return "CKR_ARGUMENTS_BAD";
        case 0x010UL: return "CKR_ATTRIBUTE_READ_ONLY";
        case 0x011UL: return "CKR_ATTRIBUTE_SENSITIVE";
        case 0x012UL: return "CKR_ATTRIBUTE_TYPE_INVALID";
        case 0x013UL: return "CKR_ATTRIBUTE_VALUE_INVALID";
        case 0x060UL: return "CKR_KEY_HANDLE_INVALID";
        case 0x062UL: return "CKR_KEY_SIZE_RANGE";
        case 0x063UL: return "CKR_KEY_TYPE_INCONSISTENT";
        case 0x068UL: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
        case 0x070UL: return "CKR_MECHANISM_INVALID";
        case 0x071UL: return "CKR_MECHANISM_PARAM_INVALID";
        case 0x0D0UL: return "CKR_TEMPLATE_INCOMPLETE";
        case 0x0D1UL: return "CKR_TEMPLATE_INCONSISTENT";
        case 0x101UL: return "CKR_USER_NOT_LOGGED_IN";
        default:      return "(see include/fhsm_common.h)";
    }
}

/* The harness's base key: generic secret, CKA_DERIVE decided by the caller. */
static CK_OBJECT_HANDLE base_key(CK_SESSION_HANDLE s, int allow_derive) {
    CK_BYTE ikm[22]; memset(ikm, 0x0b, sizeof ikm);
    CK_BYTE yes = 1, no = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_VALUE,       ikm, sizeof ikm },
        { CKA_DERIVE,      allow_derive ? &yes : &no, 1 },
        { CKA_EXTRACTABLE, &yes, 1 },
        { CKA_SENSITIVE,   &no,  1 },
    };
    CK_OBJECT_HANDLE h = 0;
    CK_RV rv = C_CreateObject(s, tmpl, 6, &h);
    if (rv != 0) { printf("  (base key C_CreateObject -> 0x%lx)\n", (unsigned long)rv); return 0; }
    return h;
}

/* One derivation, reported rather than asserted. value_len < 0 means the
 * template carries no CKA_VALUE_LEN -- which is the harness's shape. */
static void attempt(const char *what, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE bk,
                    CK_ULONG mech, int extract, int expand, long value_len) {
    CK_BYTE salt[13]; for (int i = 0; i < 13; ++i) salt[i] = (CK_BYTE)i;
    CK_BYTE info[10]; for (int i = 0; i < 10; ++i) info[i] = (CK_BYTE)(0xf0 + i);
    CK_HKDF_PARAMS p;
    memset(&p, 0, sizeof p);
    p.bExtract = (CK_BYTE)extract;
    p.bExpand  = (CK_BYTE)expand;
    p.prfHashMechanism = CKM_SHA256;
    p.ulSaltType = CKF_HKDF_SALT_DATA;
    p.pSalt = salt; p.ulSaltLen = sizeof salt;
    p.pInfo = info; p.ulInfoLen = sizeof info;
    CK_MECHANISM m = { mech, &p, sizeof p };

    CK_BYTE t_true = 1, t_false = 0;
    CK_ULONG vl = (value_len < 0) ? 0 : (CK_ULONG)value_len;
    CK_ATTRIBUTE tmpl[5] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
        { CKA_SENSITIVE,   &t_false, 1 },
        { CKA_EXTRACTABLE, &t_true,  1 },
        { CKA_VALUE_LEN,   &vl, sizeof(CK_ULONG) },
    };
    CK_ULONG n = (value_len < 0) ? 4 : 5;

    CK_OBJECT_HANDLE out = 0;
    CK_RV rv = C_DeriveKey(s, &m, bk, tmpl, n, &out);
    printf("  %-52s 0x%-5lx %s", what, (unsigned long)rv, ckr(rv));
    if (rv == 0 && out) {
        CK_BYTE got[128]; CK_ATTRIBUTE q[] = { { CKA_VALUE, got, sizeof got } };
        if (C_GetAttributeValue(s, out, q, 1) == 0)
            printf("  (%lu bytes)", (unsigned long)q[0].ulValueLen);
    }
    printf("\n");
}

int main(void)
{
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_CreateObject); SYM(C_DeriveKey);
    SYM(C_GetAttributeValue);
    if (!C_DeriveKey || !C_CreateObject) { fprintf(stderr,"missing symbols\n"); return 2; }

    CK_BYTE label[32]; memset(label,' ',32); memcpy(label,"hkdfprobe",9);
    if (C_Initialize(NULL)) { fprintf(stderr,"C_Initialize\n"); return 2; }
    if (C_InitToken(0,(CK_BYTE*)SO_PIN,strlen(SO_PIN),label)) { fprintf(stderr,"C_InitToken\n"); return 2; }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0,CKF_RW,NULL,NULL,&s)) { fprintf(stderr,"C_OpenSession\n"); return 2; }
    if (C_Login(s,0,(CK_BYTE*)SO_PIN,strlen(SO_PIN))) { fprintf(stderr,"C_Login SO\n"); return 2; }
    if (C_InitPIN(s,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_InitPIN\n"); return 2; }
    if (C_Login(s,1,(CK_BYTE*)USER_PIN,strlen(USER_PIN))) { fprintf(stderr,"C_Login USER\n"); return 2; }

    printf("What the module answers to the harness's HKDF shapes\n\n");

    CK_OBJECT_HANDLE bk = base_key(s, 1);
    if (!bk) { fprintf(stderr, "no base key\n"); return 2; }

    printf("base key: CKK_GENERIC_SECRET, CKA_DERIVE=TRUE\n");
    attempt("A  HKDF_DATA   extract+expand, no CKA_VALUE_LEN",
            s, bk, CKM_HKDF_DATA,   1, 1, -1);
    attempt("B  HKDF_DERIVE extract+expand, no CKA_VALUE_LEN",
            s, bk, CKM_HKDF_DERIVE, 1, 1, -1);
    attempt("C  HKDF_DATA   extract+expand, CKA_VALUE_LEN=32",
            s, bk, CKM_HKDF_DATA,   1, 1, 32);
    attempt("D  HKDF_DATA   extract only,   no CKA_VALUE_LEN",
            s, bk, CKM_HKDF_DATA,   1, 0, -1);
    attempt("E  HKDF_DATA   expand only,    CKA_VALUE_LEN=32",
            s, bk, CKM_HKDF_DATA,   0, 1, 32);

    /* Wycheproof hkdf_sha256_test.json tc1, as pkcs11-check packs it.
     *
     * The corpus reports this one vector failing with
     * CKR_MECHANISM_PARAM_INVALID while the other 82 valid vectors in the same
     * file pass -- and tc1 is RFC 5869 A.1, which tests/test_derive_hkdf.c
     * case (1) derives correctly and compares byte for byte against OpenSSL.
     * The same vector therefore succeeds through one call shape and fails
     * through another, so the difference is in the call.
     *
     * What differs, read from testcases/wycheproof/test_wycheproof_hkdf.py:
     * the template carries CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_SENSITIVE,
     * CKA_EXTRACTABLE and CKA_TOKEN -- and NO CKA_CLASS, which our own test
     * always supplies. That is the only structural difference found by
     * reading, which is exactly the kind of claim that should be measured
     * instead. */
    {
        static const CK_BYTE tc1_ikm[22] = {
            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b };
        static const CK_BYTE tc1_salt[13] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c };
        static const CK_BYTE tc1_info[10] = {
            0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9 };
        static const CK_BYTE tc1_okm[42] = {
            0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,
            0xd0,0x36,0x2f,0x2a,0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
            0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,0x34,0x00,0x72,0x08,
            0xd5,0xb8,0x87,0x18,0x58,0x65 };

        CK_BYTE yes = 1, no = 0;
        CK_ATTRIBUTE ikm_t[] = {
            { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY},     sizeof(CK_ULONG) },
            { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
            { CKA_VALUE,       (void*)tc1_ikm, sizeof tc1_ikm },
            { CKA_DERIVE,      &yes, 1 },
            { CKA_EXTRACTABLE, &yes, 1 },
            { CKA_SENSITIVE,   &no,  1 },
        };
        CK_OBJECT_HANDLE ikm_h = 0;
        CK_RV crv = C_CreateObject(s, ikm_t, 6, &ikm_h);
        printf("\nWycheproof hkdf_sha256 tc1 (RFC 5869 A.1), harness shape\n");
        if (crv != 0) {
            printf("  IKM import refused: 0x%lx %s\n", (unsigned long)crv, ckr(crv));
        } else {
            CK_HKDF_PARAMS p;
            memset(&p, 0, sizeof p);
            p.bExtract = 1; p.bExpand = 1;
            p.prfHashMechanism = CKM_SHA256;
            p.ulSaltType = 2 /* CKF_HKDF_SALT_DATA */;
            p.pSalt = (void*)tc1_salt; p.ulSaltLen = sizeof tc1_salt;
            p.pInfo = (void*)tc1_info; p.ulInfoLen = sizeof tc1_info;
            CK_MECHANISM m = { CKM_HKDF_DERIVE, &p, sizeof p };
            CK_ULONG vl = 42;
            /* No CKA_CLASS, exactly as the harness sends it. */
            CK_ATTRIBUTE out_t[] = {
                { CKA_KEY_TYPE,    &(CK_ULONG){CKK_GENERIC_SECRET}, sizeof(CK_ULONG) },
                { CKA_VALUE_LEN,   &vl, sizeof(CK_ULONG) },
                { CKA_SENSITIVE,   &no,  1 },
                { CKA_EXTRACTABLE, &yes, 1 },
            };
            CK_OBJECT_HANDLE out = 0;
            CK_RV rv = C_DeriveKey(s, &m, ikm_h, out_t, 4, &out);
            printf("  G  derive, template without CKA_CLASS       0x%-5lx %s\n",
                   (unsigned long)rv, ckr(rv));
            if (rv == 0 && out) {
                CK_BYTE got[64]; CK_ATTRIBUTE q[] = { { CKA_VALUE, got, sizeof got } };
                if (C_GetAttributeValue(s, out, q, 1) == 0) {
                    printf("     %lu bytes, %s the RFC 5869 A.1 OKM\n",
                           (unsigned long)q[0].ulValueLen,
                           (q[0].ulValueLen == 42 && memcmp(got, tc1_okm, 42) == 0)
                             ? "matching" : "NOT matching");
                }
            }
        }
    }

    CK_OBJECT_HANDLE bk_noderive = base_key(s, 0);
    if (bk_noderive) {
        printf("\nbase key: CKA_DERIVE=FALSE (isolates the usage gate)\n");
        attempt("F  HKDF_DATA   extract+expand, CKA_VALUE_LEN=32",
                s, bk_noderive, CKM_HKDF_DATA, 1, 1, 32);
    }

    printf("\nReading: A and B must agree -- they are the same code path, and a\n"
           "report naming only one of them is naming the mechanism that had no\n"
           "second test, not the one that behaved differently. A through E are\n"
           "expected to succeed since 2026-09-17: PKCS#11 v3.2 6.62.3 says\n"
           "CKA_VALUE_LEN 'should' be set for expand, so its absence is met with\n"
           "the hash length rather than CKR_TEMPLATE_INCOMPLETE. F is the\n"
           "CKA_DERIVE usage gate and is expected to refuse; it is here so that a\n"
           "future refusal can be told apart from that one.\n");

    if (C_Finalize) C_Finalize(NULL);
    return 0;
}
