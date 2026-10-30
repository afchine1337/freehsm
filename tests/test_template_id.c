/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_template_id.c --- a key created from computed bytes keeps the CKA_ID
 * its template gave it.
 *
 * C_UnwrapKey, C_DeriveKey, C_EncapsulateKey and C_DecapsulateKey built the
 * new key without the template's CKA_ID; only C_GenerateKey kept it. A caller
 * that unwraps a key under an id and looks it up by that id found nothing --
 * OpenSC's test-pkcs11-tool-unwrap-wrap-test.sh, --application-id, 2026-10-29.
 *
 * What is asserted: the key is created, reads back the id, and a
 * C_FindObjects on CKA_ID finds exactly it, for
 *   (1) C_UnwrapKey, CKM_AES_KEY_WRAP
 *   (2) C_EncapsulateKey and (3) C_DecapsulateKey, CKM_ML_KEM (ML-KEM-768),
 *       where the build has ML-KEM
 *   (4) AES-CBC and AES-CBC-PAD wrap and unwrap a key, the unwrapped key
 *       equal to the original and found by its CKA_ID -- where the build
 *       and mode offer them
 *   (5) an RSA private key: wrapped only if generated CKA_EXTRACTABLE=TRUE,
 *       as PKCS#8 under AES-KWP, and unwrapped into a sensitive private key
 *       of the type the blob holds, which signs for the original public key
 * C_DeriveKey goes through the same helper and is not exercised here.
 * ========================================================================= */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                    0UL
#define CKA_CLASS                 0x000UL
#define CKA_TOKEN                 0x001UL
#define CKA_VALUE                 0x011UL
#define CKA_ID                    0x102UL
#define CKA_KEY_TYPE              0x100UL
#define CKA_SENSITIVE             0x103UL
#define CKA_ENCRYPT               0x104UL
#define CKA_WRAP                  0x106UL
#define CKA_UNWRAP                0x107UL
#define CKA_EXTRACTABLE           0x162UL
#define CKA_VALUE_LEN             0x161UL
#define CKA_ENCAPSULATE           0x633UL
#define CKA_DECAPSULATE           0x634UL
#define CKA_PARAMETER_SET         0x61DUL
#define CKO_SECRET_KEY            4UL
#define CKK_AES                   0x1FUL
#define CKK_GENERIC_SECRET        0x10UL
#define CKM_AES_KEY_GEN           0x1080UL
#define CKM_AES_KEY_WRAP          0x2109UL
#define CKM_AES_KEY_WRAP_KWP      0x210BUL
#define CKA_VERIFY                0x10AUL
#define CKA_SIGN                  0x108UL
#define CKA_MODULUS_BITS          0x121UL
#define CKM_ML_KEM_KEY_PAIR_GEN   0x0FUL
#define CKM_ML_KEM                0x17UL
#define CKP_ML_KEM_768            0x2UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

static CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV (*C_FindObjects)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);

/* 1 when `h` reads back `id` and a search on that id finds `h` alone. */
static int has_id(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_BYTE *id, CK_ULONG idl) {
    CK_BYTE buf[32]; CK_ATTRIBUTE a = { CKA_ID, buf, sizeof buf };
    if (C_GetAttributeValue(s, h, &a, 1) != CKR_OK
        || a.ulValueLen != idl || memcmp(buf, id, idl) != 0) return 0;
    CK_ATTRIBUTE f = { CKA_ID, id, idl };
    CK_OBJECT_HANDLE found[4]; CK_ULONG n = 0;
    if (C_FindObjectsInit(s, &f, 1) != CKR_OK) return 0;
    C_FindObjects(s, found, 4, &n);
    C_FindObjectsFinal(s);
    return n == 1 && found[0] == h;
}

int main(void)
{
    void *hl = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!hl) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*C_Initialize)(void*); CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                               CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
    CK_RV (*C_WrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,
                       CK_BYTE*,CK_ULONG*);
    CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG,
                         CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_EncapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,
                              CK_ULONG,CK_BYTE*,CK_ULONG*,CK_OBJECT_HANDLE*);
    CK_RV (*C_DecapsulateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_ATTRIBUTE*,
                              CK_ULONG,CK_BYTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    #define SYM(n) *(void**)&n = dlsym(hl,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKey);
    SYM(C_GenerateKeyPair); SYM(C_WrapKey); SYM(C_UnwrapKey);
    SYM(C_EncapsulateKey); SYM(C_DecapsulateKey); SYM(C_GetAttributeValue);
    SYM(C_FindObjectsInit); SYM(C_FindObjects); SYM(C_FindObjectsFinal);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);

    printf("CKA_ID on keys created from computed bytes\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "tmplid")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    C_OpenSession(0, 6, NULL, NULL, &s);
    C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN));
    C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN));
    C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login\n"); return 2; }

    CK_BYTE yes = 1, no = 0;
    CK_ULONG cls = CKO_SECRET_KEY, aes = CKK_AES, gen = CKK_GENERIC_SECRET, len32 = 32;
    CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };

    /* (1) C_UnwrapKey */
    CK_ATTRIBUTE kek_t[] = { { CKA_TOKEN, &no, 1 }, { CKA_VALUE_LEN, &len32, sizeof len32 },
                             { CKA_WRAP, &yes, 1 }, { CKA_UNWRAP, &yes, 1 } };
    CK_ATTRIBUTE tgt_t[] = { { CKA_TOKEN, &no, 1 }, { CKA_VALUE_LEN, &len32, sizeof len32 },
                             { CKA_EXTRACTABLE, &yes, 1 }, { CKA_ENCRYPT, &yes, 1 },
                             { CKA_SENSITIVE, &no, 1 } };
    CK_OBJECT_HANDLE kek = 0, tgt = 0, uw = 0;
    CK_BYTE wrapped[64]; CK_ULONG wl = sizeof wrapped;
    CK_MECHANISM kw = { CKM_AES_KEY_WRAP, NULL, 0 };
    if (C_GenerateKey(s, &kg, kek_t, 4, &kek) != CKR_OK
        || C_GenerateKey(s, &kg, tgt_t, 5, &tgt) != CKR_OK
        || C_WrapKey(s, &kw, kek, tgt, wrapped, &wl) != CKR_OK) {
        fprintf(stderr, "key wrap setup\n"); return 2;
    }
    CK_BYTE id1[] = { 0x95 };
    CK_ATTRIBUTE uw_t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &aes, sizeof aes },
                            { CKA_TOKEN, &no, 1 }, { CKA_ID, id1, sizeof id1 } };
    CK_RV rv = C_UnwrapKey(s, &kw, kek, wrapped, wl, uw_t, 4, &uw);
    ok(rv == CKR_OK && has_id(s, uw, id1, sizeof id1), "(1) C_UnwrapKey keeps CKA_ID, found by it");

    /* (4) AES-CBC and AES-CBC-PAD wrap and unwrap the same 32-byte key, where
     * the build and mode run them (all-mechanisms, permissive). */
    {
        CK_BYTE iv[16] = { 0 };
        CK_ULONG mechs[2] = { 0x1082UL /* CKM_AES_CBC */, 0x1085UL /* CKM_AES_CBC_PAD */ };
        const char *names[2] = { "CKM_AES_CBC", "CKM_AES_CBC_PAD" };
        for (int k = 0; k < 2; ++k) {
            CK_MECHANISM cm = { mechs[k], iv, sizeof iv };
            CK_BYTE w[64]; CK_ULONG wlen = sizeof w;
            CK_BYTE idc[] = { 0x40, (CK_BYTE)k };
            CK_ATTRIBUTE c_t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &aes, sizeof aes },
                                   { CKA_TOKEN, &no, 1 }, { CKA_ID, idc, sizeof idc },
                                   { CKA_EXTRACTABLE, &yes, 1 }, { CKA_SENSITIVE, &no, 1 } };
            CK_OBJECT_HANDLE cu = 0;
            char what[96];
            rv = C_WrapKey(s, &cm, kek, tgt, w, &wlen);
            if (rv == 0x70UL /* CKR_MECHANISM_INVALID */) {
                printf("  (4) %s wrapping not offered in this build or mode, skipped\n", names[k]);
                continue;
            }
            snprintf(what, sizeof what, "(4) %s wraps (rv 0x%lx, %lu bytes)", names[k], rv, wlen);
            ok(rv == CKR_OK && wlen == (k ? 48UL : 32UL), what);
            rv = C_UnwrapKey(s, &cm, kek, w, wlen, c_t, 6, &cu);
            CK_BYTE v1[32], v2[32];
            CK_ATTRIBUTE a1 = { CKA_VALUE, v1, sizeof v1 }, a2 = { CKA_VALUE, v2, sizeof v2 };
            snprintf(what, sizeof what, "(4) %s unwraps the same key, under its CKA_ID", names[k]);
            ok(rv == CKR_OK && has_id(s, cu, idc, sizeof idc)
               && C_GetAttributeValue(s, tgt, &a1, 1) == CKR_OK
               && C_GetAttributeValue(s, cu, &a2, 1) == CKR_OK
               && a1.ulValueLen == 32 && a2.ulValueLen == 32 && memcmp(v1, v2, 32) == 0, what);
        }
    }

    /* (5) A private key: wrapped as PKCS#8, unwrapped into a private key. */
    {
        CK_ULONG bits = 2048, priv_cls = 3 /* CKO_PRIVATE_KEY */, rsa = 0 /* CKK_RSA */;
        CK_ULONG ec = 3 /* CKK_EC */;
        CK_ATTRIBUTE pu[] = { { CKA_TOKEN, &no, 1 }, { CKA_VERIFY, &yes, 1 },
                              { CKA_MODULUS_BITS, &bits, sizeof bits } };
        CK_ATTRIBUTE pe[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 },
                              { CKA_EXTRACTABLE, &yes, 1 } };
        CK_ATTRIBUTE pn[] = { { CKA_TOKEN, &no, 1 }, { CKA_SIGN, &yes, 1 } };
        CK_MECHANISM rg = { 0UL /* CKM_RSA_PKCS_KEY_PAIR_GEN */, NULL, 0 };
        CK_MECHANISM kwp = { CKM_AES_KEY_WRAP_KWP, NULL, 0 };
        CK_MECHANISM sg = { 0x40UL /* CKM_SHA256_RSA_PKCS */, NULL, 0 };
        CK_OBJECT_HANDLE rpub = 0, rpriv = 0, npub = 0, npriv = 0, up = 0, bad = 0;
        CK_BYTE w[4096]; CK_ULONG wlen = sizeof w;
        CK_BYTE idp[] = { 0x50 }, msg[] = "wrapped as PKCS#8", sig[256], sens = 0;
        CK_ULONG sl = sizeof sig;
        if (C_GenerateKeyPair(s, &rg, pu, 3, pe, 3, &rpub, &rpriv) != CKR_OK
            || C_GenerateKeyPair(s, &rg, pu, 3, pn, 2, &npub, &npriv) != CKR_OK) {
            fprintf(stderr, "RSA key generation\n"); return 2;
        }
        rv = C_WrapKey(s, &kwp, kek, npriv, w, &wlen);
        ok(rv == 0x6AUL, "(5) a private key not asked extractable is not wrapped");
        wlen = sizeof w;
        rv = C_WrapKey(s, &kwp, kek, rpriv, w, &wlen);
        ok(rv == CKR_OK, "(5) CKA_EXTRACTABLE=TRUE at generation: it is wrapped");
        CK_ATTRIBUTE up_t[] = { { CKA_CLASS, &priv_cls, sizeof priv_cls },
                                { CKA_KEY_TYPE, &rsa, sizeof rsa }, { CKA_TOKEN, &no, 1 },
                                { CKA_ID, idp, sizeof idp }, { CKA_SIGN, &yes, 1 },
                                { CKA_SENSITIVE, &no, 1 } };
        CK_ATTRIBUTE ec_t[] = { { CKA_CLASS, &priv_cls, sizeof priv_cls },
                                { CKA_KEY_TYPE, &ec, sizeof ec }, { CKA_TOKEN, &no, 1 } };
        ok(C_UnwrapKey(s, &kwp, kek, w, wlen, ec_t, 3, &bad) == 0x63UL,
           "(5) unwrapped as CKK_EC: CKR_KEY_TYPE_INCONSISTENT");
        rv = C_UnwrapKey(s, &kwp, kek, w, wlen, up_t, 6, &up);
        ok(rv == CKR_OK && has_id(s, up, idp, sizeof idp),
           "(5) unwrapped as CKK_RSA, found by its CKA_ID");
        CK_ATTRIBUTE sa = { CKA_SENSITIVE, &sens, 1 };
        ok(C_GetAttributeValue(s, up, &sa, 1) == CKR_OK && sens == 1,
           "(5) sensitive, though the template said FALSE");
        ok(C_SignInit(s, &sg, up) == CKR_OK
           && C_Sign(s, msg, sizeof msg - 1, sig, &sl) == CKR_OK
           && C_VerifyInit(s, &sg, rpub) == CKR_OK
           && C_Verify(s, msg, sizeof msg - 1, sig, sl) == CKR_OK,
           "(5) it signs, and the original public key verifies");
    }

    /* (2) and (3): ML-KEM */
    CK_ULONG pset = CKP_ML_KEM_768;
    CK_ATTRIBUTE kp_pub[] = { { CKA_TOKEN, &no, 1 }, { CKA_ENCAPSULATE, &yes, 1 },
                              { CKA_PARAMETER_SET, &pset, sizeof pset } };
    CK_ATTRIBUTE kp_priv[] = { { CKA_TOKEN, &no, 1 }, { CKA_DECAPSULATE, &yes, 1 } };
    CK_MECHANISM kpg = { CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    if (!C_EncapsulateKey || !C_DecapsulateKey
        || C_GenerateKeyPair(s, &kpg, kp_pub, 3, kp_priv, 2, &pub, &priv) != CKR_OK) {
        printf("  (2)(3) ML-KEM not available in this build, skipped\n");
    } else {
        CK_MECHANISM kem = { CKM_ML_KEM, NULL, 0 };
        CK_BYTE id2[] = { 0x12, 0x34 }, id3[] = { 0x56 };
        CK_ATTRIBUTE e_t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &gen, sizeof gen },
                               { CKA_TOKEN, &no, 1 }, { CKA_ID, id2, sizeof id2 } };
        CK_ATTRIBUTE d_t[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &gen, sizeof gen },
                               { CKA_TOKEN, &no, 1 }, { CKA_ID, id3, sizeof id3 } };
        CK_BYTE ct[2048]; CK_ULONG ctl = sizeof ct;
        CK_OBJECT_HANDLE ek = 0, dk = 0;
        rv = C_EncapsulateKey(s, &kem, pub, e_t, 4, ct, &ctl, &ek);
        ok(rv == CKR_OK && has_id(s, ek, id2, sizeof id2),
           "(2) C_EncapsulateKey keeps CKA_ID, found by it");
        rv = rv == CKR_OK ? C_DecapsulateKey(s, &kem, priv, d_t, 4, ct, ctl, &dk) : rv;
        ok(rv == CKR_OK && has_id(s, dk, id3, sizeof id3),
           "(3) C_DecapsulateKey keeps CKA_ID, found by it");
    }

    C_Finalize(NULL);
    printf("\n%s : %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
