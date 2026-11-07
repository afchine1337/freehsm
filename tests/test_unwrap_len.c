/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_unwrap_len.c --- C_UnwrapKey must bound the wrapped blob before
 * decrypting it (found 2026-09-07 by pkcs11-check, Wycheproof AES-KW), and
 * since #29 holds the plaintext in the secure heap, without a fixed ceiling.
 *
 * C_UnwrapKey decrypted into `uint8_t pt[256]` on the stack. EVP_DecryptUpdate
 * takes no output-capacity argument -- the caller guarantees the buffer -- and
 * nothing checked ulWrappedKeyLen against sizeof(pt). AES-KW yields
 * ulWrappedKeyLen - 8 bytes, so any blob over 264 bytes wrote past the buffer.
 *
 * It was found as an abort rather than as corruption because the module is
 * built with _FORTIFY_SOURCE and a stack canary: the guard fired, pytest
 * reported "Fatal Python error: Aborted", and the harness spent four rounds of
 * adaptive isolation narrowing it to test_aes_key_wrap. Both protections are
 * build flags, and issue #7 established that distributions do not all apply
 * the same ones. A build without them takes the write instead of the abort,
 * on data that arrives from outside by the very purpose of key wrapping.
 *
 * The sibling defect this also covers: C_WrapKey validates the wrapping-key
 * size, with a comment saying a bad size must not "silently fall through to
 * the 256-bit cipher name". C_UnwrapKey did exactly that -- a 20-byte key
 * selected AES-256-WRAP. The fix had been applied to one of the two paths that
 * reach the same state.
 *
 * #29: the buffer grew to 4 KiB, still on the stack, which is not locked and
 * refused ML-DSA-87 private keys (about 4.9 KiB as PKCS#8). It is now
 * allocated in the secure heap at the size the mechanism can write, and the
 * only bound left that is not a mechanism's is the store's own value cap,
 * FHSM_OBJ_VALUE_MAX in include/fhsm_token.h. VALUE_MAX below is a second
 * copy of it, which (2) pins: if the two part, (2) fails.
 *
 * Run twice. Without arguments, against the default arena. With --tiny,
 * against a 256 KiB arena (FHSM_CONF set by the Makefile), where a blob that
 * the default arena decrypts must be answered CKR_DEVICE_MEMORY -- and a
 * round trip afterwards must still work, so the refused call left nothing
 * allocated behind it.
 *
 * Case (4) is there so that a pass means something: with every length
 * refused, the length cases would also pass against a module that had
 * stopped unwrapping altogether.
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                        0UL
#define CKR_WRAPPED_KEY_INVALID       0x110UL
#define CKR_WRAPPED_KEY_LEN_RANGE     0x112UL
#define CKR_WRAPPING_KEY_SIZE_RANGE   0x114UL
#define CKR_DEVICE_MEMORY             0x131UL
#define CKF_RW                        6UL
#define CKM_ML_DSA_KEY_PAIR_GEN       0x1CUL
#define CKM_ML_DSA                    0x1DUL
#define CKM_AES_KEY_GEN               0x1080UL
#define CKM_AES_KEY_WRAP              0x2109UL
#define CKM_AES_KEY_WRAP_KWP          0x210BUL
#define CKA_CLASS                     0UL
#define CKA_TOKEN                     1UL
#define CKA_KEY_TYPE                  0x100UL
#define CKA_WRAP                      0x106UL
#define CKA_UNWRAP                    0x107UL
#define CKA_SIGN                      0x108UL
#define CKA_VERIFY                    0x10AUL
#define CKA_VALUE_LEN                 0x161UL
#define CKA_EXTRACTABLE               0x162UL
#define CKA_PARAMETER_SET             0x61DUL
#define CKO_PRIVATE_KEY               3UL
#define CKO_SECRET_KEY                4UL
#define CKK_AES                       0x1FUL
#define CKK_ML_DSA                    0x4AUL
#define CKP_ML_DSA_87                 3UL

/* FHSM_OBJ_VALUE_MAX, include/fhsm_token.h. */
#define VALUE_MAX   (2UL * 1024UL * 1024UL)
/* Decrypted by the default 8 MiB arena, too large for the 256 KiB one. */
#define ARENA_PROBE (512UL * 1024UL)

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}
static void ok_rv(CK_RV rv, CK_RV want, const char *what) {
    char line[128];
    if (rv == want) snprintf(line, sizeof line, "%s", what);
    else snprintf(line, sizeof line, "%s (0x%lx)", what, rv);
    ok(rv == want, line);
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

/* VALUE_MAX + 8 bytes: one semiblock past the cap. Static, not on the stack. */
static CK_BYTE big[VALUE_MAX + 8];

int main(int argc, char **argv)
{
    int tiny = (argc > 1 && strcmp(argv[1], "--tiny") == 0);

    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,
                               CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);
    CK_RV (*C_WrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKey);
    SYM(C_GenerateKeyPair); SYM(C_WrapKey); SYM(C_UnwrapKey);
    SYM(C_SignInit); SYM(C_Sign); SYM(C_VerifyInit); SYM(C_Verify);
    if (!C_UnwrapKey || !C_WrapKey || !C_GenerateKeyPair || !C_Sign || !C_Verify) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("C_UnwrapKey bounds the wrapped blob%s\n\n",
           tiny ? " (256 KiB secure arena)" : "");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "unwraplen")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    /* SO and USER cannot hold the token at once (CKR_USER_ANOTHER_ALREADY_LOGGED_IN) */
    if (C_Logout) (void)C_Logout(s);
    /* C_InitPIN leaves the session in the SO role; key generation needs USER.
     * Same sequence as tests/test_op_state.c:83. */
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    /* A 256-bit AES key that may wrap and unwrap.
     *
     * CKA_WRAP / CKA_UNWRAP / CKA_EXTRACTABLE are CK_BBOOL -- one byte, not a
     * CK_ULONG. Passing sizeof(CK_ULONG) makes C_GenerateKey refuse the
     * template, which is correct of it. tests/mlkem_e2e.c has it right. */
    CK_ULONG len32 = 32;
    CK_BYTE  t_true = 1, t_false = 0;
    CK_ATTRIBUTE kek_tmpl[] = {
        { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY}, sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,    &(CK_ULONG){CKK_AES},        sizeof(CK_ULONG) },
        { CKA_VALUE_LEN,   &len32,                      sizeof(CK_ULONG) },
        { CKA_WRAP,        &t_true,                     1 },
        { CKA_UNWRAP,      &t_true,                     1 },
    };
    CK_MECHANISM keygen = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE kek = 0;
    if (C_GenerateKey(s, &keygen, kek_tmpl, 5, &kek) != CKR_OK) {
        fprintf(stderr, "C_GenerateKey (KEK)\n"); return 2;
    }

    CK_MECHANISM kw = { CKM_AES_KEY_WRAP, NULL, 0 };
    CK_MECHANISM kwp = { CKM_AES_KEY_WRAP_KWP, NULL, 0 };
    CK_ATTRIBUTE out_tmpl[] = {
        { CKA_CLASS,    &(CK_ULONG){CKO_SECRET_KEY}, sizeof(CK_ULONG) },
        { CKA_KEY_TYPE, &(CK_ULONG){CKK_AES},        sizeof(CK_ULONG) },
    };
    CK_OBJECT_HANDLE out = 0;
    CK_RV rv;
    memset(big, 0xA5, sizeof big);

    /* (2) The store's cap, checked before anything is allocated: one semiblock
     *     past it is a length error in either arena, never CKR_DEVICE_MEMORY. */
    rv = C_UnwrapKey(s, &kw, kek, big, VALUE_MAX + 8, out_tmpl, 2, &out);
    ok_rv(rv, CKR_WRAPPED_KEY_LEN_RANGE, "(2) blob past the store's value cap refused by length");

    if (!tiny) {
        /* (1) The case that aborted, and 8192 is now a length the module takes:
         *     it decrypts into the secure heap and fails the integrity check.
         *     Reaching the next line at all is most of what this asserts. */
        rv = C_UnwrapKey(s, &kw, kek, big, 8192, out_tmpl, 2, &out);
        ok_rv(rv, CKR_WRAPPED_KEY_INVALID, "(1) 8192-byte garbage blob: decrypted, integrity fails");

        /* (2) And exactly at the cap: accepted by length, refused by AES-KW. */
        rv = C_UnwrapKey(s, &kw, kek, big, VALUE_MAX, out_tmpl, 2, &out);
        ok_rv(rv, CKR_WRAPPED_KEY_INVALID, "(2) blob at the store's value cap: length accepted");

        /* (6) The arena probe the --tiny run turns into CKR_DEVICE_MEMORY. */
        rv = C_UnwrapKey(s, &kw, kek, big, ARENA_PROBE, out_tmpl, 2, &out);
        ok_rv(rv, CKR_WRAPPED_KEY_INVALID, "(6) 512 KiB blob decrypted in the default arena");

        /* (3) Malformed lengths RFC 3394 cannot produce. */
        rv = C_UnwrapKey(s, &kw, kek, big, 20, out_tmpl, 2, &out);
        ok_rv(rv, CKR_WRAPPED_KEY_LEN_RANGE, "(3) non-multiple-of-8 blob refused");
        rv = C_UnwrapKey(s, &kw, kek, big, 16, out_tmpl, 2, &out);
        ok_rv(rv, CKR_WRAPPED_KEY_LEN_RANGE, "(3) under-length blob refused (KW)");
    } else {
        /* (6) Arena exhaustion: the module's answer when storing an object
         *     value finds the arena full, and no fallback to pageable memory. */
        rv = C_UnwrapKey(s, &kw, kek, big, ARENA_PROBE, out_tmpl, 2, &out);
        ok_rv(rv, CKR_DEVICE_MEMORY, "(6) 512 KiB blob, 256 KiB arena: CKR_DEVICE_MEMORY");
    }

    /* (4) A real round trip still works, so that a pass means something. In
     *     the --tiny run it also shows the refused call released its block. */
    {
        CK_ATTRIBUTE dek_tmpl[] = {
            { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY}, sizeof(CK_ULONG) },
            { CKA_KEY_TYPE,    &(CK_ULONG){CKK_AES},        sizeof(CK_ULONG) },
            { CKA_VALUE_LEN,   &len32,                      sizeof(CK_ULONG) },
            { CKA_EXTRACTABLE, &t_true,                     1 },
        };
        CK_OBJECT_HANDLE dek = 0;
        if (C_GenerateKey(s, &keygen, dek_tmpl, 4, &dek) != CKR_OK) {
            ok(0, "(4) round trip: C_GenerateKey (DEK)");
        } else {
            CK_BYTE wrapped[128];
            CK_ULONG wlen = sizeof wrapped;
            rv = C_WrapKey(s, &kw, kek, dek, wrapped, &wlen);
            ok_rv(rv, CKR_OK, "(4) round trip: C_WrapKey");
            if (rv == CKR_OK) {
                rv = C_UnwrapKey(s, &kw, kek, wrapped, wlen, out_tmpl, 2, &out);
                ok(rv == CKR_OK && out != 0, "(4) round trip: C_UnwrapKey accepts it");
            }
        }
    }

    /* (5) An ML-DSA-87 private key, wrapped as PKCS#8 under AES-KWP and
     *     unwrapped. Its plaintext is larger than the 4 KiB stack buffer
     *     held, which refused it with CKR_WRAPPED_KEY_LEN_RANGE. The unwrapped
     *     key must sign, and the original public key verify. */
    if (!tiny) {
        CK_ULONG pset = CKP_ML_DSA_87;
        CK_ATTRIBUTE pub_t[]  = { { CKA_TOKEN, &t_false, 1 }, { CKA_VERIFY, &t_true, 1 },
                                  { CKA_PARAMETER_SET, &pset, sizeof pset } };
        CK_ATTRIBUTE priv_t[] = { { CKA_TOKEN, &t_false, 1 }, { CKA_SIGN, &t_true, 1 },
                                  { CKA_EXTRACTABLE, &t_true, 1 } };
        CK_MECHANISM kpg = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE pub = 0, priv = 0, up = 0;
        rv = C_GenerateKeyPair(s, &kpg, pub_t, 3, priv_t, 3, &pub, &priv);
        ok_rv(rv, CKR_OK, "(5) ML-DSA-87 key pair, private key extractable");
        if (rv == CKR_OK) {
            static CK_BYTE w[16384];
            CK_ULONG wlen = sizeof w;
            rv = C_WrapKey(s, &kwp, kek, priv, w, &wlen);
            ok_rv(rv, CKR_OK, "(5) C_WrapKey (AES-KWP)");
            if (rv == CKR_OK) {
                char what[96];
                snprintf(what, sizeof what,
                         "(5) wrapped plaintext %lu bytes, past the old 4096", wlen - 8);
                ok(wlen - 8 > 4096, what);
                CK_ATTRIBUTE up_t[] = {
                    { CKA_CLASS,    &(CK_ULONG){CKO_PRIVATE_KEY}, sizeof(CK_ULONG) },
                    { CKA_KEY_TYPE, &(CK_ULONG){CKK_ML_DSA},      sizeof(CK_ULONG) },
                    { CKA_TOKEN,    &t_false, 1 },
                    { CKA_SIGN,     &t_true,  1 },
                };
                rv = C_UnwrapKey(s, &kwp, kek, w, wlen, up_t, 4, &up);
                ok_rv(rv, CKR_OK, "(5) C_UnwrapKey of the ML-DSA-87 private key");
                if (rv == CKR_OK) {
                    CK_MECHANISM sg = { CKM_ML_DSA, NULL, 0 };
                    CK_BYTE msg[] = "unwrapped from the secure heap";
                    static CK_BYTE sig[8192];
                    CK_ULONG sl = sizeof sig;
                    ok(C_SignInit(s, &sg, up) == CKR_OK
                       && C_Sign(s, msg, sizeof msg - 1, sig, &sl) == CKR_OK
                       && C_VerifyInit(s, &sg, pub) == CKR_OK
                       && C_Verify(s, msg, sizeof msg - 1, sig, sl) == CKR_OK,
                       "(5) it signs, and the original public key verifies");
                }
            }
        }
    }

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
