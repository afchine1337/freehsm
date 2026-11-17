/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_tls12_kdf.c --- the TLS 1.2 mechanisms (2.8.0):
 * CKM_TLS12_MASTER_KEY_DERIVE, CKM_TLS12_MASTER_KEY_DERIVE_DH, their
 * RFC 7627 forms CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE(_DH),
 * CKM_TLS12_KEY_AND_MAC_DERIVE, CKM_TLS12_KEY_SAFE_DERIVE, CKM_TLS_MAC,
 * CKM_TLS_KDF and the aliases CKM_TLS12_MAC and CKM_TLS12_KDF.
 *
 * Every output is checked against the TLS 1.2 PRF of RFC 5246 5 computed
 * here, P_hash from C_Sign with CKM_SHA256_HMAC or CKM_SHA384_HMAC under a
 * key holding the same secret -- another path of the module than the one
 * under test.
 *   (M) the master secret, SHA-256: its value, the version from the
 *       pre-master secret, and the CKA_ALLOWED_MECHANISMS the mechanism
 *       contributes; the DH form from a 32-byte secret, pVersion NULL.
 *       Refused where NIST's rules apply.
 *   (X) the extended master secret, SHA-384, both forms, in both builds.
 *   (K) the key block from the (X) master secret, AES-128 with HMAC-SHA-256
 *       sizes: four keys and two IVs, their types and usages, phKey NULL.
 *   (S) the same without IVs: the caller's buffers are left alone.
 *   (F) refusals: bIsExport, a template asking another protection than the
 *       base key's, a master secret of 32 bytes, a 47-byte pre-master,
 *       SHA-1 as the PRF hash, and a master secret used by a mechanism
 *       outside its CKA_ALLOWED_MECHANISMS.
 *   (T) the Finished MAC under the (X) master secret, one-shot and in
 *       parts, signed and verified, the alias with the server's label and
 *       32 bytes; a changed tag, a short one, a bad side or length.
 *   (E) the exporter, with and without context, and its alias; a template
 *       without a length. Refused where NIST's rules apply.
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
typedef struct { CK_BYTE major, minor; } CK_VERSION;
typedef struct { CK_BYTE *pClientRandom; CK_ULONG ulClientRandomLen;
                 CK_BYTE *pServerRandom; CK_ULONG ulServerRandomLen; } CK_SSL3_RANDOM_DATA;
typedef struct { CK_OBJECT_HANDLE hClientMacSecret, hServerMacSecret, hClientKey, hServerKey;
                 CK_BYTE *pIVClient, *pIVServer; } CK_SSL3_KEY_MAT_OUT;
typedef struct { CK_SSL3_RANDOM_DATA RandomInfo; CK_VERSION *pVersion;
                 CK_ULONG prfHashMechanism; } CK_TLS12_MASTER_KEY_DERIVE_PARAMS;
typedef struct { CK_ULONG prfHashMechanism; CK_BYTE *pSessionHash; CK_ULONG ulSessionHashLen;
                 CK_VERSION *pVersion; } CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS;
typedef struct { CK_ULONG ulMacSizeInBits, ulKeySizeInBits, ulIVSizeInBits; CK_BYTE bIsExport;
                 CK_SSL3_RANDOM_DATA RandomInfo; CK_SSL3_KEY_MAT_OUT *pReturnedKeyMaterial;
                 CK_ULONG prfHashMechanism; } CK_TLS12_KEY_MAT_PARAMS;
typedef struct { void *pData; CK_ULONG ulLen; } CK_KEY_DERIVATION_STRING_DATA;
typedef struct { CK_ULONG prfHashMechanism, ulMacLength, ulServerOrClient; } CK_TLS_MAC_PARAMS;
typedef struct { CK_ULONG prfMechanism; CK_BYTE *pLabel; CK_ULONG ulLabelLength;
                 CK_SSL3_RANDOM_DATA RandomInfo; CK_BYTE *pContextData;
                 CK_ULONG ulContextDataLength; } CK_TLS_KDF_PARAMS;

#define CKR_OK                         0x000UL
#define CKR_KEY_SIZE_RANGE             0x062UL
#define CKR_MECHANISM_INVALID          0x070UL
#define CKR_MECHANISM_PARAM_INVALID    0x071UL
#define CKR_SIGNATURE_INVALID          0x0C0UL
#define CKR_SIGNATURE_LEN_RANGE        0x0C1UL
#define CKR_TEMPLATE_INCOMPLETE        0x0D0UL
#define CKR_TEMPLATE_INCONSISTENT      0x0D1UL
#define CKF_RW                         6UL
#define CKO_SECRET_KEY                 4UL
#define CKK_GENERIC_SECRET             0x10UL
#define CKK_AES                        0x1FUL
#define CKA_CLASS                      0x000UL
#define CKA_TOKEN                      0x001UL
#define CKA_VALUE                      0x011UL
#define CKA_KEY_TYPE                   0x100UL
#define CKA_SENSITIVE                  0x103UL
#define CKA_ENCRYPT                    0x104UL
#define CKA_SIGN                       0x108UL
#define CKA_VERIFY                     0x10AUL
#define CKA_DERIVE                     0x10CUL
#define CKA_VALUE_LEN                  0x161UL
#define CKA_EXTRACTABLE                0x162UL
#define CKA_ALLOWED_MECHANISMS         0x40000600UL
#define CKM_RSA_PKCS                   0x0001UL
#define CKM_TLS12_EXT_MASTER           0x0056UL
#define CKM_TLS12_EXT_MASTER_DH        0x0057UL
#define CKM_SHA_1                      0x0220UL
#define CKM_SHA256                     0x0250UL
#define CKM_SHA256_HMAC                0x0251UL
#define CKM_SHA384                     0x0260UL
#define CKM_SHA384_HMAC                0x0261UL
#define CKM_CONCATENATE_BASE_AND_DATA  0x0362UL
#define CKM_TLS12_MASTER               0x03E0UL
#define CKM_TLS12_KEY_AND_MAC          0x03E1UL
#define CKM_TLS12_MASTER_DH            0x03E2UL
#define CKM_TLS12_KEY_SAFE             0x03E3UL
#define CKM_TLS_MAC                    0x03E4UL
#define CKM_TLS_KDF                    0x03E5UL
#define CKM_TLS12_MAC                  0x03D8UL
#define CKM_TLS12_KDF                  0x03D9UL
#define CKM_TLS_PRF                    0x0378UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static CK_RV (*C_Initialize)(void*), (*C_Finalize)(void*);
static CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE*, CK_ULONG, CK_BYTE*);
static CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
static CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
static CK_RV (*C_Logout)(CK_SESSION_HANDLE);
static CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);
static CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
static CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*,
                            CK_ULONG, CK_OBJECT_HANDLE*);
static CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG);
static CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG*);
static CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
static CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);

static int fails;
static void ok(int cond, const char *what) {
    printf("  %-72s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_SESSION_HANDLE s;
static CK_BYTE yes = 1, no = 0;

static int listed(CK_ULONG mech) {
    CK_ULONG n = 0; C_GetMechanismList(0, NULL, &n);
    CK_ULONG *ml = calloc(n ? n : 1, sizeof *ml);
    C_GetMechanismList(0, ml, &n);
    int found = 0;
    for (CK_ULONG i = 0; i < n; i++) if (ml[i] == mech) found = 1;
    free(ml);
    return found;
}

/* A generic secret that derives (or signs, for the HMAC of P_hash), its
 * value readable. */
static CK_OBJECT_HANDLE secret(const CK_BYTE *v, CK_ULONG vl, CK_ULONG usage) {
    CK_ULONG cls = CKO_SECRET_KEY, kt = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                         { CKA_TOKEN, &no, 1 }, { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 },
                         { usage, &yes, 1 }, { CKA_VALUE, (void*)v, vl } };
    CK_OBJECT_HANDLE h = 0;
    return C_CreateObject(s, t, 7, &h) == CKR_OK ? h : 0;
}

static CK_ULONG value_of(CK_OBJECT_HANDLE h, CK_BYTE *buf, CK_ULONG cap) {
    CK_ATTRIBUTE a = { CKA_VALUE, buf, cap };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? a.ulValueLen : 0;
}

static CK_ULONG ulong_attr(CK_OBJECT_HANDLE h, CK_ULONG type) {
    CK_ULONG v = (CK_ULONG)-1;
    CK_ATTRIBUTE a = { type, &v, sizeof v };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? v : (CK_ULONG)-1;
}

static int bool_attr(CK_OBJECT_HANDLE h, CK_ULONG type) {
    CK_BYTE v = 0xFF;
    CK_ATTRIBUTE a = { type, &v, 1 };
    return C_GetAttributeValue(s, h, &a, 1) == CKR_OK ? v : -1;
}

/* RFC 5246 5: P_hash(secret, label || seed), out_len bytes, the HMAC from
 * C_Sign under hk, a key holding the secret. */
static int p_hash(CK_ULONG hmac, CK_OBJECT_HANDLE hk, const char *label,
                  const CK_BYTE *s1, CK_ULONG l1, const CK_BYTE *s2, CK_ULONG l2,
                  CK_BYTE *out, CK_ULONG out_len) {
    CK_BYTE seed[256], a[64], buf[64 + 256], h[64];
    CK_ULONG ll = (CK_ULONG)strlen(label), sl = ll + l1 + l2, al, hl, done = 0;
    memcpy(seed, label, ll); memcpy(seed + ll, s1, l1);
    if (l2) memcpy(seed + ll + l1, s2, l2);
    CK_MECHANISM m = { hmac, NULL, 0 };
    al = sizeof a;
    if (C_SignInit(s, &m, hk) || C_Sign(s, seed, sl, a, &al)) return 0;   /* A(1) */
    while (done < out_len) {
        memcpy(buf, a, al); memcpy(buf + al, seed, sl);
        hl = sizeof h;
        if (C_SignInit(s, &m, hk) || C_Sign(s, buf, al + sl, h, &hl)) return 0;
        CK_ULONG n = out_len - done < hl ? out_len - done : hl;
        memcpy(out + done, h, n); done += n;
        CK_ULONG nl = sizeof h;
        if (C_SignInit(s, &m, hk) || C_Sign(s, a, al, h, &nl)) return 0;  /* A(i+1) */
        memcpy(a, h, nl); al = nl;
    }
    return 1;
}

int main(void) {
    void *lib = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    #define SYM(n) *(void**)&n = dlsym(lib, #n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GetMechanismList);
    SYM(C_CreateObject); SYM(C_GetAttributeValue); SYM(C_DeriveKey);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_SignUpdate); SYM(C_SignFinal);
    SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_DeriveKey || !C_Sign || !C_SignFinal || !C_Verify) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("TLS 1.2 key derivation\n\n");
    CK_BYTE label[32]; memset(label, ' ', 32); memcpy(label, "tls12", 5);
    if (C_Initialize(NULL)) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), label)) { fprintf(stderr, "C_InitToken\n"); return 2; }
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s)) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN))) { fprintf(stderr, "SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN))) { fprintf(stderr, "USER\n"); return 2; }

    const char *mode = getenv("FHSM_MODE");
    const int nist = !listed(CKM_RSA_PKCS)
                     || (mode && (!strcmp(mode, "strict") || !strcmp(mode, "fips")));

    /* The pre-master secret of an RSA suite: TLS 1.2 (3,3) then 46 bytes;
     * a 32-byte (EC)DH one; the randoms and a session hash. */
    CK_BYTE pms[48], dh[32], cr[32], sr[32], sh[48];
    pms[0] = 3; pms[1] = 3;
    for (int i = 2; i < 48; i++) pms[i] = (CK_BYTE)(0x40 + i * 7);
    for (int i = 0; i < 32; i++) { dh[i] = (CK_BYTE)(0x91 ^ i * 5); cr[i] = (CK_BYTE)i;
                                   sr[i] = (CK_BYTE)(0xFF - i); }
    for (int i = 0; i < 48; i++) sh[i] = (CK_BYTE)(0x33 + i);
    CK_OBJECT_HANDLE kp = secret(pms, 48, CKA_DERIVE), kd = secret(dh, 32, CKA_DERIVE);
    CK_OBJECT_HANDLE hp = secret(pms, 48, CKA_SIGN),   hd = secret(dh, 32, CKA_SIGN);
    if (!kp || !kd || !hp || !hd) { fprintf(stderr, "base keys\n"); return 2; }

    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE mt[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_TOKEN, &no, 1 },
                          { CKA_SENSITIVE, &no, 1 }, { CKA_EXTRACTABLE, &yes, 1 },
                          { CKA_DERIVE, &yes, 1 }, { CKA_SIGN, &yes, 1 }, { CKA_VERIFY, &yes, 1 } };
    CK_SSL3_RANDOM_DATA rnd = { cr, 32, sr, 32 };
    CK_BYTE got[64], want[160];
    char what[160];

    /* --- (M) the master secret ------------------------------------------ */
    {
        CK_VERSION v = { 0, 0 };
        CK_TLS12_MASTER_KEY_DERIVE_PARAMS mp = { rnd, &v, CKM_SHA256 };
        CK_MECHANISM m = { CKM_TLS12_MASTER, &mp, sizeof mp };
        CK_OBJECT_HANDLE ms = 0;
        CK_RV rv = C_DeriveKey(s, &m, kp, mt, 7, &ms);
        if (nist) {
            snprintf(what, sizeof what, "(M) CKM_TLS12_MASTER_KEY_DERIVE refused: 0x%lx", rv);
            ok(rv == CKR_MECHANISM_INVALID, what);
        } else {
            snprintf(what, sizeof what, "(M) CKM_TLS12_MASTER_KEY_DERIVE, SHA-256: 0x%lx", rv);
            ok(rv == CKR_OK && listed(CKM_TLS12_MASTER), what);
            ok(value_of(ms, got, sizeof got) == 48
               && p_hash(CKM_SHA256_HMAC, hp, "master secret", cr, 32, sr, 32, want, 48)
               && !memcmp(got, want, 48), "(M) the value is PRF(pms, \"master secret\", cr || sr)");
            ok(v.major == 3 && v.minor == 3, "(M) pVersion receives 3.3 from the pre-master secret");
            CK_ULONG al[8] = { 0 };
            CK_ATTRIBUTE a = { CKA_ALLOWED_MECHANISMS, al, sizeof al };
            CK_RV ar = C_GetAttributeValue(s, ms, &a, 1);
            int has = 0;
            for (CK_ULONG i = 0; i < a.ulValueLen / sizeof(CK_ULONG); i++)
                if (al[i] == CKM_TLS12_KEY_AND_MAC || al[i] == CKM_TLS12_KEY_SAFE) has++;
            snprintf(what, sizeof what, "(M) CKA_ALLOWED_MECHANISMS contributed (0x%lx, %lu entries)",
                     ar, a.ulValueLen / sizeof(CK_ULONG));
            ok(ar == CKR_OK && a.ulValueLen == 6 * sizeof(CK_ULONG) && has == 2, what);

            CK_TLS12_MASTER_KEY_DERIVE_PARAMS dp = { rnd, &v, CKM_SHA256 };
            CK_MECHANISM dm = { CKM_TLS12_MASTER_DH, &dp, sizeof dp };
            CK_RV r1 = C_DeriveKey(s, &dm, kd, mt, 7, &ms);
            dp.pVersion = NULL;
            CK_RV r2 = C_DeriveKey(s, &dm, kd, mt, 7, &ms);
            snprintf(what, sizeof what, "(M) _DH: pVersion set refused, NULL accepted (0x%lx 0x%lx)", r1, r2);
            ok(r1 == CKR_MECHANISM_PARAM_INVALID && r2 == CKR_OK, what);
            ok(r2 == CKR_OK && value_of(ms, got, sizeof got) == 48
               && p_hash(CKM_SHA256_HMAC, hd, "master secret", cr, 32, sr, 32, want, 48)
               && !memcmp(got, want, 48), "(M) _DH: the value from a 32-byte pre-master secret");
        }
    }

    /* --- (X) the extended master secret --------------------------------- */
    CK_OBJECT_HANDLE xms = 0;
    CK_BYTE xv[48];
    {
        CK_VERSION v = { 0, 0 };
        CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS xp = { CKM_SHA384, sh, 48, &v };
        CK_MECHANISM m = { CKM_TLS12_EXT_MASTER, &xp, sizeof xp };
        CK_RV rv = C_DeriveKey(s, &m, kp, mt, 7, &xms);
        snprintf(what, sizeof what, "(X) CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE, SHA-384: 0x%lx", rv);
        ok(rv == CKR_OK && listed(CKM_TLS12_EXT_MASTER), what);
        ok(value_of(xms, xv, sizeof xv) == 48
           && p_hash(CKM_SHA384_HMAC, hp, "extended master secret", sh, 48, NULL, 0, want, 48)
           && !memcmp(xv, want, 48), "(X) the value is PRF(pms, \"extended master secret\", hash)");
        ok(v.major == 3 && v.minor == 3, "(X) pVersion receives 3.3");
        ok(ulong_attr(xms, CKA_VALUE_LEN) == 48 && ulong_attr(xms, CKA_KEY_TYPE) == CKK_GENERIC_SECRET,
           "(X) a 48-byte generic secret");

        CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS dp = { CKM_SHA384, sh, 48, NULL };
        CK_MECHANISM dm = { CKM_TLS12_EXT_MASTER_DH, &dp, sizeof dp };
        CK_OBJECT_HANDLE h = 0;
        rv = C_DeriveKey(s, &dm, kd, mt, 7, &h);
        snprintf(what, sizeof what, "(X) _DH from a 32-byte pre-master secret: 0x%lx", rv);
        ok(rv == CKR_OK && value_of(h, got, sizeof got) == 48
           && p_hash(CKM_SHA384_HMAC, hd, "extended master secret", sh, 48, NULL, 0, want, 48)
           && !memcmp(got, want, 48), what);
    }

    /* --- (K) the key block ----------------------------------------------- */
    CK_ULONG aes = CKK_AES;
    CK_ATTRIBUTE kt[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &aes, sizeof aes },
                          { CKA_TOKEN, &no, 1 } };
    CK_BYTE blk[128];
    int have_blk = 0;
    if (xms) {
        /* The PRF under the master secret's value, from a signing copy. */
        CK_OBJECT_HANDLE hx = secret(xv, 48, CKA_SIGN);
        have_blk = hx && p_hash(CKM_SHA384_HMAC, hx, "key expansion", sr, 32, cr, 32, blk, 128);
        CK_BYTE ivc[16], ivs[16];
        CK_SSL3_KEY_MAT_OUT out = { 0, 0, 0, 0, ivc, ivs };
        CK_TLS12_KEY_MAT_PARAMS kp2 = { 256, 128, 128, 0, rnd, &out, CKM_SHA384 };
        CK_MECHANISM m = { CKM_TLS12_KEY_AND_MAC, &kp2, sizeof kp2 };
        CK_RV rv = C_DeriveKey(s, &m, xms, kt, 3, NULL);
        snprintf(what, sizeof what, "(K) CKM_TLS12_KEY_AND_MAC_DERIVE, phKey NULL: 0x%lx", rv);
        ok(rv == CKR_OK && listed(CKM_TLS12_KEY_AND_MAC), what);
        if (rv == CKR_OK && have_blk) {
            const CK_OBJECT_HANDLE hs[4] = { out.hClientMacSecret, out.hServerMacSecret,
                                             out.hClientKey, out.hServerKey };
            const CK_ULONG off[4] = { 0, 32, 64, 80 }, len[4] = { 32, 32, 16, 16 };
            int same = 1;
            for (int i = 0; i < 4; i++)
                same &= value_of(hs[i], got, sizeof got) == len[i] && !memcmp(got, blk + off[i], len[i]);
            ok(same, "(K) client and server MAC keys and keys are the key block, in order");
            ok(!memcmp(ivc, blk + 96, 16) && !memcmp(ivs, blk + 112, 16), "(K) the two IVs follow");
            ok(ulong_attr(hs[0], CKA_KEY_TYPE) == CKK_GENERIC_SECRET && bool_attr(hs[1], CKA_SIGN) == 1,
               "(K) the MAC keys: generic secrets that sign");
            ok(ulong_attr(hs[2], CKA_KEY_TYPE) == CKK_AES && bool_attr(hs[3], CKA_ENCRYPT) == 1,
               "(K) the keys: AES, as the template says, and encrypt");
            ok(bool_attr(hs[2], CKA_SENSITIVE) == 0 && bool_attr(hs[0], CKA_EXTRACTABLE) == 1,
               "(K) the base key's CKA_SENSITIVE and CKA_EXTRACTABLE");
        } else ok(0, "(K) the key block");

        /* --- (S) no IVs --------------------------------------------------- */
        memset(ivc, 0xEE, 16); memset(ivs, 0xEE, 16);
        CK_SSL3_KEY_MAT_OUT out2 = { 0, 0, 0, 0, ivc, ivs };
        kp2.pReturnedKeyMaterial = &out2;
        CK_MECHANISM sm = { CKM_TLS12_KEY_SAFE, &kp2, sizeof kp2 };
        CK_OBJECT_HANDLE ph = 7;
        rv = C_DeriveKey(s, &sm, xms, kt, 3, &ph);
        snprintf(what, sizeof what, "(S) CKM_TLS12_KEY_SAFE_DERIVE: 0x%lx", rv);
        ok(rv == CKR_OK && ph == 0, what);
        int untouched = 1;
        for (int i = 0; i < 16; i++) untouched &= ivc[i] == 0xEE && ivs[i] == 0xEE;
        ok(untouched, "(S) the IV buffers are left alone");
        ok(rv == CKR_OK && have_blk && value_of(out2.hServerKey, got, sizeof got) == 16
           && !memcmp(got, blk + 80, 16), "(S) the server key as under (K)");

        /* --- (F) refusals --------------------------------------------------- */
        kp2.bIsExport = 1;
        CK_RV r1 = C_DeriveKey(s, &m, xms, kt, 3, NULL);
        kp2.bIsExport = 0;
        CK_ATTRIBUTE st[] = { { CKA_KEY_TYPE, &aes, sizeof aes }, { CKA_SENSITIVE, &yes, 1 } };
        CK_RV r2 = C_DeriveKey(s, &m, xms, st, 2, NULL);
        CK_OBJECT_HANDLE sm32 = secret(xv, 32, CKA_DERIVE);
        CK_RV r3 = C_DeriveKey(s, &m, sm32, kt, 3, NULL);
        CK_BYTE data[4] = { 1, 2, 3, 4 };
        CK_KEY_DERIVATION_STRING_DATA sd = { data, 4 };
        CK_MECHANISM cm = { CKM_CONCATENATE_BASE_AND_DATA, &sd, sizeof sd };
        CK_OBJECT_HANDLE h = 0;
        CK_RV r4 = C_DeriveKey(s, &cm, xms, mt, 7, &h);
        snprintf(what, sizeof what,
                 "(F) export, other protection, 32-byte master, not allowed (0x%lx 0x%lx 0x%lx 0x%lx)",
                 r1, r2, r3, r4);
        ok(r1 == CKR_MECHANISM_PARAM_INVALID && r2 == CKR_TEMPLATE_INCONSISTENT
           && r3 == CKR_KEY_SIZE_RANGE && r4 == CKR_MECHANISM_INVALID, what);
    }
    {
        CK_BYTE p47[47]; memcpy(p47, pms, 47);
        CK_OBJECT_HANDLE k47 = secret(p47, 47, CKA_DERIVE);
        CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS xp = { CKM_SHA384, sh, 48, NULL };
        CK_MECHANISM m = { CKM_TLS12_EXT_MASTER, &xp, sizeof xp };
        CK_OBJECT_HANDLE h = 0;
        CK_RV r1 = C_DeriveKey(s, &m, k47, mt, 7, &h);
        xp.prfHashMechanism = CKM_SHA_1;
        CK_RV r2 = C_DeriveKey(s, &m, kp, mt, 7, &h);
        xp.prfHashMechanism = CKM_SHA384;
        CK_ULONG l32 = 32;
        CK_ATTRIBUTE lt[] = { { CKA_VALUE_LEN, &l32, sizeof l32 } };
        CK_RV r3 = C_DeriveKey(s, &m, kp, lt, 1, &h);
        snprintf(what, sizeof what, "(F) 47-byte pre-master, SHA-1, CKA_VALUE_LEN 32 (0x%lx 0x%lx 0x%lx)",
                 r1, r2, r3);
        ok(r1 == CKR_KEY_SIZE_RANGE && r2 == CKR_MECHANISM_PARAM_INVALID
           && r3 == CKR_TEMPLATE_INCONSISTENT, what);
    }

    /* --- (T) the Finished MAC --------------------------------------------- */
    CK_OBJECT_HANDLE hx = xms ? secret(xv, 48, CKA_SIGN) : 0;
    if (xms && hx) {
        CK_TLS_MAC_PARAMS tp = { CKM_SHA384, 12, 2 };
        CK_MECHANISM m = { CKM_TLS_MAC, &tp, sizeof tp };
        CK_BYTE tag[64], tag2[64];
        CK_ULONG tl = sizeof tag, tl2 = sizeof tag2;
        CK_RV r1 = C_SignInit(s, &m, xms);
        if (r1 == CKR_OK) r1 = C_Sign(s, sh, 48, tag, &tl);
        snprintf(what, sizeof what, "(T) CKM_TLS_MAC, client, 12 bytes: 0x%lx", r1);
        ok(r1 == CKR_OK && tl == 12 && listed(CKM_TLS_MAC), what);
        ok(p_hash(CKM_SHA384_HMAC, hx, "client finished", sh, 48, NULL, 0, want, 12)
           && !memcmp(tag, want, 12), "(T) PRF(master, \"client finished\", hash)");
        CK_RV r2 = C_SignInit(s, &m, xms);
        if (r2 == CKR_OK) r2 = C_SignUpdate(s, sh, 20);
        if (r2 == CKR_OK) r2 = C_SignUpdate(s, sh + 20, 28);
        if (r2 == CKR_OK) r2 = C_SignFinal(s, tag2, &tl2);
        snprintf(what, sizeof what, "(T) in parts, the same tag: 0x%lx", r2);
        ok(r2 == CKR_OK && tl2 == 12 && !memcmp(tag, tag2, 12), what);
        CK_RV v1 = C_VerifyInit(s, &m, xms);
        if (v1 == CKR_OK) v1 = C_Verify(s, sh, 48, tag, 12);
        tag[0] ^= 1;
        CK_RV v2 = C_VerifyInit(s, &m, xms);
        if (v2 == CKR_OK) v2 = C_Verify(s, sh, 48, tag, 12);
        CK_RV v3 = C_VerifyInit(s, &m, xms);
        if (v3 == CKR_OK) v3 = C_Verify(s, sh, 48, tag, 11);
        snprintf(what, sizeof what, "(T) verified; changed, short refused (0x%lx 0x%lx 0x%lx)", v1, v2, v3);
        ok(v1 == CKR_OK && v2 == CKR_SIGNATURE_INVALID && v3 == CKR_SIGNATURE_LEN_RANGE, what);

        CK_TLS_MAC_PARAMS sp = { CKM_SHA384, 32, 1 };
        CK_MECHANISM am = { CKM_TLS12_MAC, &sp, sizeof sp };
        tl = sizeof tag;
        CK_RV r3 = C_SignInit(s, &am, xms);
        if (r3 == CKR_OK) r3 = C_Sign(s, sh, 48, tag, &tl);
        snprintf(what, sizeof what, "(T) CKM_TLS12_MAC, server, 32 bytes: 0x%lx", r3);
        ok(r3 == CKR_OK && tl == 32
           && p_hash(CKM_SHA384_HMAC, hx, "server finished", sh, 48, NULL, 0, want, 32)
           && !memcmp(tag, want, 32), what);

        CK_TLS_MAC_PARAMS b1 = { CKM_SHA384, 12, 3 }, b2 = { CKM_SHA384, 11, 2 },
                          b3 = { CKM_TLS_PRF, 16, 2 };
        CK_MECHANISM bm = { CKM_TLS_MAC, &b1, sizeof b1 };
        CK_RV f1 = C_SignInit(s, &bm, xms);
        bm.pParameter = &b2;
        CK_RV f2 = C_SignInit(s, &bm, xms);
        bm.pParameter = &b3;
        CK_RV f3 = C_SignInit(s, &bm, xms);
        snprintf(what, sizeof what, "(T) side 3, 11 bytes, TLS 1.0 PRF of 16 refused (0x%lx 0x%lx 0x%lx)",
                 f1, f2, f3);
        ok(f1 == CKR_MECHANISM_PARAM_INVALID && f2 == CKR_MECHANISM_PARAM_INVALID
           && f3 == CKR_MECHANISM_PARAM_INVALID, what);
    } else ok(0, "(T) no master secret to MAC with");

    /* --- (E) the exporter ---------------------------------------------------- */
    if (xms && hx) {
        CK_BYTE el[] = "EXPORTER-test", ctx[3] = { 'c', 't', 'x' }, sfx[64 + 5];
        CK_ULONG l40 = 40;
        CK_ATTRIBUTE et[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_TOKEN, &no, 1 },
                              { CKA_VALUE_LEN, &l40, sizeof l40 } };
        CK_TLS_KDF_PARAMS ep = { CKM_SHA384, el, 13, rnd, ctx, 3 };
        CK_MECHANISM m = { CKM_TLS_KDF, &ep, sizeof ep };
        CK_OBJECT_HANDLE h = 0;
        CK_RV rv = C_DeriveKey(s, &m, xms, et, 3, &h);
        if (nist) {
            snprintf(what, sizeof what, "(E) CKM_TLS_KDF refused: 0x%lx", rv);
            ok(rv == CKR_MECHANISM_INVALID, what);
        } else {
            memcpy(sfx, sr, 32); sfx[32] = 0; sfx[33] = 3; memcpy(sfx + 34, ctx, 3);
            snprintf(what, sizeof what, "(E) CKM_TLS_KDF with context, 40 bytes: 0x%lx", rv);
            ok(rv == CKR_OK && value_of(h, got, sizeof got) == 40
               && p_hash(CKM_SHA384_HMAC, hx, "EXPORTER-test", cr, 32, sfx, 37, want, 40)
               && !memcmp(got, want, 40), what);
            ok(bool_attr(h, CKA_EXTRACTABLE) == 1 && bool_attr(h, CKA_SENSITIVE) == 0,
               "(E) the base key's protection where the template says nothing");
            ep.pContextData = NULL; ep.ulContextDataLength = 0;
            m.mechanism = CKM_TLS12_KDF;
            rv = C_DeriveKey(s, &m, xms, et, 3, &h);
            snprintf(what, sizeof what, "(E) CKM_TLS12_KDF without context: 0x%lx", rv);
            ok(rv == CKR_OK && value_of(h, got, sizeof got) == 40
               && p_hash(CKM_SHA384_HMAC, hx, "EXPORTER-test", cr, 32, sr, 32, want, 40)
               && !memcmp(got, want, 40), what);
            rv = C_DeriveKey(s, &m, xms, et, 2, &h);
            snprintf(what, sizeof what, "(E) no CKA_VALUE_LEN: 0x%lx", rv);
            ok(rv == CKR_TEMPLATE_INCOMPLETE, what);
        }
    }

    C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
