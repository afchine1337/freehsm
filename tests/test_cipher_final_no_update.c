/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_cipher_final_no_update.c --- C_EncryptInit then C_EncryptFinal, with
 * no C_EncryptUpdate in between, is zero bytes of input.
 *
 * The multipart cipher context was built by the first Update. Final found it
 * missing and answered CKR_OPERATION_NOT_INITIALIZED -- after a C_EncryptInit
 * that had returned CKR_OK. C_DecryptFinal did the same; its guard existed to
 * keep EVP_DecryptFinal_ex off a NULL context (#125), and stopped the call
 * instead of building the context. pkcs11-check 0.2.3 found the encrypt half
 * as TestZeroDataFinal::test_encrypt_final_no_update (AES-ECB).
 *
 * What each mechanism is asserted on:
 *   (1) EncryptFinal after Init alone returns CKR_OK
 *   (2) with the output the mode defines for empty input: nothing for ECB
 *       and CBC, one padding block for CBC-PAD -- equal to the one-shot
 *       C_Encrypt of "" when the module answers that
 *   (3) a canary buffer is untouched past what was reported
 *   (4) the operation is over afterwards
 *   (5) DecryptFinal after Init alone: CKR_OK with nothing for ECB and CBC;
 *       for CBC-PAD an error, since "" is not a padded ciphertext -- and the
 *       operation is over either way
 * ======================================================================== */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
                      CK_OBJECT_HANDLE, CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKR_OK                        0UL
#define CKR_MECHANISM_INVALID         0x70UL
#define CKR_OPERATION_NOT_INITIALIZED 0x91UL
#define CKF_RW                        6UL
#define CKA_CLASS                     0UL
#define CKA_KEY_TYPE                  0x100UL
#define CKA_ENCRYPT                   0x104UL
#define CKA_DECRYPT                   0x105UL
#define CKA_VALUE_LEN                 0x161UL
#define CKO_SECRET_KEY                4UL
#define CKK_AES                       0x1FUL
#define CKM_AES_KEY_GEN               0x1080UL

#define SO_PIN   "sopin1234"
#define USER_PIN "userpin1234"

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

/* empty_out: what Final emits for zero bytes of plaintext.
 * dec_ok: whether zero bytes of ciphertext is a valid ciphertext. */
static const struct {
    CK_ULONG ckm; const char *name; int has_iv; CK_ULONG empty_out; int dec_ok;
} MECHS[] = {
    { 0x1081UL, "AES_ECB",     0,  0, 1 },
    { 0x1082UL, "AES_CBC",     1,  0, 1 },
    { 0x1085UL, "AES_CBC_PAD", 1, 16, 0 },
};
#define NMECH (sizeof MECHS / sizeof MECHS[0])

int main(void)
{
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
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG*);
    #define SYM(n) *(void**)&n = dlsym(h,#n)
    SYM(C_Initialize); SYM(C_Finalize); SYM(C_InitToken); SYM(C_OpenSession);
    SYM(C_Login); SYM(C_Logout); SYM(C_InitPIN); SYM(C_GenerateKey);
    SYM(C_EncryptInit); SYM(C_Encrypt); SYM(C_EncryptFinal);
    SYM(C_DecryptInit); SYM(C_DecryptFinal);
    if (!C_EncryptFinal || !C_DecryptFinal || !C_Logout) {
        fprintf(stderr, "missing symbols\n"); return 2;
    }

    printf("multipart cipher: Final straight after Init is empty input\n\n");

    CK_BYTE label[32];
    if (C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize\n"); return 2; }
    if (C_InitToken(0, (CK_BYTE*)SO_PIN, strlen(SO_PIN), pad_label(label, "finalnoupd")) != CKR_OK) {
        fprintf(stderr, "C_InitToken\n"); return 2;
    }
    CK_SESSION_HANDLE s = 0;
    if (C_OpenSession(0, CKF_RW, NULL, NULL, &s) != CKR_OK) { fprintf(stderr, "C_OpenSession\n"); return 2; }
    if (C_Login(s, 0, (CK_BYTE*)SO_PIN, strlen(SO_PIN)) != CKR_OK) { fprintf(stderr, "C_Login SO\n"); return 2; }
    if (C_InitPIN(s, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_InitPIN\n"); return 2; }
    (void)C_Logout(s);
    if (C_Login(s, 1, (CK_BYTE*)USER_PIN, strlen(USER_PIN)) != CKR_OK) { fprintf(stderr, "C_Login USER\n"); return 2; }

    /* CKA_ENCRYPT / CKA_DECRYPT are CK_BBOOL, one byte. */
    CK_ULONG len32 = 32;
    CK_BYTE  t_true = 1;
    CK_ATTRIBUTE key_tmpl[] = {
        { CKA_CLASS,     &(CK_ULONG){CKO_SECRET_KEY}, sizeof(CK_ULONG) },
        { CKA_KEY_TYPE,  &(CK_ULONG){CKK_AES},        sizeof(CK_ULONG) },
        { CKA_VALUE_LEN, &len32,                      sizeof(CK_ULONG) },
        { CKA_ENCRYPT,   &t_true,                     1 },
        { CKA_DECRYPT,   &t_true,                     1 },
    };
    CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = 0;
    if (C_GenerateKey(s, &kg, key_tmpl, 5, &key) != CKR_OK) {
        fprintf(stderr, "C_GenerateKey AES-256\n"); return 2;
    }

    CK_BYTE iv[16];
    memset(iv, 0x42, sizeof iv);

    for (size_t i = 0; i < NMECH; ++i) {
        CK_MECHANISM m = { MECHS[i].ckm, MECHS[i].has_iv ? iv : NULL,
                           MECHS[i].has_iv ? sizeof iv : 0 };
        char what[96];
        printf("%s\n", MECHS[i].name);

        CK_RV rv = C_EncryptInit(s, &m, key);
        if (rv == CKR_MECHANISM_INVALID) { printf("  not in this build, skipped\n"); continue; }
        snprintf(what, sizeof what, "C_EncryptInit");
        ok(rv == CKR_OK, what);
        if (rv != CKR_OK) continue;

        CK_BYTE out[64];
        memset(out, 0xA5, sizeof out);
        CK_ULONG out_len = sizeof out;
        rv = C_EncryptFinal(s, out, &out_len);
        snprintf(what, sizeof what, "(1) C_EncryptFinal with no Update -> CKR_OK (rv=0x%lx)", rv);
        ok(rv == CKR_OK, what);
        snprintf(what, sizeof what, "(2) %lu byte(s) out, expected %lu",
                 rv == CKR_OK ? out_len : 0UL, MECHS[i].empty_out);
        ok(rv == CKR_OK && out_len == MECHS[i].empty_out, what);

        int clean = 1;
        for (size_t j = (rv == CKR_OK ? out_len : 0); j < sizeof out; ++j)
            if (out[j] != 0xA5) clean = 0;
        ok(clean, "(3) canary untouched past the reported length");

        if (rv == CKR_OK && out_len > 0) {
            /* The same thing asked in one shot, where the module answers it. */
            CK_BYTE one[64]; CK_ULONG one_len = sizeof one;
            if (C_EncryptInit(s, &m, key) == CKR_OK &&
                C_Encrypt(s, (CK_BYTE*)"", 0, one, &one_len) == CKR_OK) {
                ok(one_len == out_len && memcmp(one, out, out_len) == 0,
                   "(2) equal to one-shot C_Encrypt of \"\"");
            }
        }

        CK_ULONG again = sizeof out;
        rv = C_EncryptFinal(s, out, &again);
        ok(rv == CKR_OPERATION_NOT_INITIALIZED, "(4) a second C_EncryptFinal finds no operation");

        rv = C_DecryptInit(s, &m, key);
        ok(rv == CKR_OK, "C_DecryptInit");
        if (rv != CKR_OK) continue;
        CK_ULONG dlen = sizeof out;
        rv = C_DecryptFinal(s, out, &dlen);
        if (MECHS[i].dec_ok) {
            snprintf(what, sizeof what, "(5) C_DecryptFinal with no Update -> CKR_OK, 0 bytes (rv=0x%lx)", rv);
            ok(rv == CKR_OK && dlen == 0, what);
        } else {
            snprintf(what, sizeof what, "(5) C_DecryptFinal of \"\" is refused (rv=0x%lx)", rv);
            ok(rv != CKR_OK && rv != CKR_OPERATION_NOT_INITIALIZED, what);
        }
        dlen = sizeof out;
        rv = C_DecryptFinal(s, out, &dlen);
        ok(rv == CKR_OPERATION_NOT_INITIALIZED, "(5) a second C_DecryptFinal finds no operation");
    }

    C_Finalize(NULL);
    printf("\n%s (%d failure%s)\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
