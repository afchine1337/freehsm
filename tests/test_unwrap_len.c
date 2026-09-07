/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_unwrap_len.c --- C_UnwrapKey must bound the wrapped blob before
 * decrypting it (found 2026-09-07 by pkcs11-check, Wycheproof AES-KW).
 *
 * C_UnwrapKey decrypts into `uint8_t pt[256]` on the stack. EVP_DecryptUpdate
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
 * Case 4 is there so that a pass means something: with every length refused,
 * cases 1-3 would also pass against a module that had stopped unwrapping
 * altogether.
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
#define CKR_WRAPPED_KEY_LEN_RANGE     0x112UL
#define CKR_WRAPPING_KEY_SIZE_RANGE   0x114UL
#define CKF_RW                        6UL
#define CKM_AES_KEY_GEN               0x1080UL
#define CKM_AES_KEY_WRAP              0x2109UL
#define CKA_CLASS                     0UL
#define CKA_TOKEN                     1UL
#define CKA_KEY_TYPE                  0x100UL
#define CKA_WRAP                      0x106UL
#define CKA_UNWRAP                    0x107UL
#define CKA_VALUE_LEN                 0x161UL
#define CKA_EXTRACTABLE               0x162UL
#define CKO_SECRET_KEY                4UL
#define CKK_AES                       0x1FUL

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %-58s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) fails++;
}

static CK_BYTE *pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

int main(void)
{
    void *h = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_InitToken)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
    CK_RV (*C_Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    CK_RV (*C_WrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE,CK_BYTE*,CK_ULONG,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_InitPIN); SYM(C_GenerateKey);
    SYM(C_WrapKey); SYM(C_UnwrapKey);
    if (!C_UnwrapKey || !C_WrapKey) { fprintf(stderr, "missing symbols\n"); return 2; }

    printf("C_UnwrapKey bounds the wrapped blob\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "unwraplen")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    /* C_InitPIN leaves the session in the SO role; key generation needs USER.
     * Same sequence as tests/test_op_state.c:83. */
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    /* A 256-bit AES key that may wrap and unwrap.
     *
     * CKA_WRAP / CKA_UNWRAP / CKA_EXTRACTABLE are CK_BBOOL -- one byte, not a
     * CK_ULONG. Passing sizeof(CK_ULONG) makes C_GenerateKey refuse the
     * template, which is correct of it. tests/mlkem_e2e.c has it right. */
    CK_ULONG len32 = 32;
    CK_BYTE  t_true = 1;
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
    CK_ATTRIBUTE out_tmpl[] = {
        { CKA_CLASS,    &(CK_ULONG){CKO_SECRET_KEY}, sizeof(CK_ULONG) },
        { CKA_KEY_TYPE, &(CK_ULONG){CKK_AES},        sizeof(CK_ULONG) },
    };
    CK_OBJECT_HANDLE out = 0;
    CK_RV rv;

    /* (1) The case that aborted: a blob whose plaintext exceeds pt[256].
     *     512 bytes is well past the 264-byte ceiling. Reaching the next line
     *     at all is most of what this test asserts. */
    {
        CK_BYTE blob[512];
        memset(blob, 0xA5, sizeof blob);
        rv = C_UnwrapKey(s, &kw, kek, blob, sizeof blob, out_tmpl, 2, &out);
        ok(rv == CKR_WRAPPED_KEY_LEN_RANGE, "512-byte blob refused, no abort");
    }

    /* (2) Exactly one semiblock past the ceiling: 272 - 8 = 264 > 256. */
    {
        CK_BYTE blob[272];
        memset(blob, 0xA5, sizeof blob);
        rv = C_UnwrapKey(s, &kw, kek, blob, sizeof blob, out_tmpl, 2, &out);
        ok(rv == CKR_WRAPPED_KEY_LEN_RANGE, "272-byte blob refused (boundary)");
    }

    /* (3) Malformed lengths RFC 3394 cannot produce. */
    {
        CK_BYTE blob[64];
        memset(blob, 0xA5, sizeof blob);
        rv = C_UnwrapKey(s, &kw, kek, blob, 20, out_tmpl, 2, &out);
        ok(rv == CKR_WRAPPED_KEY_LEN_RANGE, "non-multiple-of-8 blob refused");
        rv = C_UnwrapKey(s, &kw, kek, blob, 16, out_tmpl, 2, &out);
        ok(rv == CKR_WRAPPED_KEY_LEN_RANGE, "under-length blob refused (KW)");
    }

    /* (4) And a real round trip still works, so that a pass means something. */
    {
        CK_ATTRIBUTE dek_tmpl[] = {
            { CKA_CLASS,       &(CK_ULONG){CKO_SECRET_KEY}, sizeof(CK_ULONG) },
            { CKA_KEY_TYPE,    &(CK_ULONG){CKK_AES},        sizeof(CK_ULONG) },
            { CKA_VALUE_LEN,   &len32,                      sizeof(CK_ULONG) },
            { CKA_EXTRACTABLE, &t_true,                     1 },
        };
        CK_OBJECT_HANDLE dek = 0;
        if (C_GenerateKey(s, &keygen, dek_tmpl, 4, &dek) != CKR_OK) {
            ok(0, "round trip: C_GenerateKey (DEK)");
        } else {
            CK_BYTE wrapped[128];
            CK_ULONG wlen = sizeof wrapped;
            rv = C_WrapKey(s, &kw, kek, dek, wrapped, &wlen);
            ok(rv == CKR_OK, "round trip: C_WrapKey");
            if (rv == CKR_OK) {
                rv = C_UnwrapKey(s, &kw, kek, wrapped, wlen, out_tmpl, 2, &out);
                ok(rv == CKR_OK && out != 0, "round trip: C_UnwrapKey accepts it");
            }
        }
    }

    if (C_Finalize) C_Finalize(NULL);
    printf("\n%s\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
