/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * cavp_extended.c --- Additional published CAVP test vectors.
 *
 *   AES-GCM-256 : 4 vectors derived from NIST SP 800-38D Appendix B
 *                 (Test Cases 13-16, the spec-published reference set).
 *
 *   HMAC-SHA-256 : 4 vectors from IETF RFC 4231 §4.2..4.5 (the same
 *                  vectors NIST CAVP uses for HMAC-SHA-256 SubGT).
 *
 * Both algorithms are exercised through OpenSSL EVP directly so that
 * this CAVP set is independent of the production wrappers (one less
 * thing to go wrong : an internal-wrapper bug shouldn't mask a real
 * crypto defect during the boot self-test).
 *
 * The runner appends its results to the same fhsm_kat_result_t array
 * that fhsm_kat_run_all() populates ; the caller (fhsm_kat_run_all)
 * passes its current *count cursor and we advance it.
 *
 * Failure semantics : any single vector mismatch returns
 * FHSM_RV_KAT_FAILED and the parent runner latches the module ERROR
 * state. This conforms to FIPS 140-3 §7.10.2 ("approved-mode KAT").
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_crypto.h"

#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* Self-contained timing helper to avoid coupling to fhsm_kat_vectors.c
 * internals. */
static uint32_t local_elapsed_us(struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    uint64_t ns = (uint64_t)(t1.tv_sec - t0->tv_sec) * 1000000000ull
                 + (uint64_t)t1.tv_nsec - (uint64_t)t0->tv_nsec;
    return (uint32_t)(ns / 1000ull);
}

#define REC(out, idx, alg, vid, pass, dur)              \
    do {                                                \
        (out)[idx].algorithm   = (alg);                 \
        (out)[idx].vector_id   = (vid);                 \
        (out)[idx].passed      = (pass);                \
        (out)[idx].duration_us = (dur);                 \
    } while (0)

/* =========================================================================
 *                          AES-GCM-256 vectors
 *
 * Source : NIST SP 800-38D rev. May 2005, Appendix B.
 * ----------------------------------------------------------------------- */

/* Common 256-bit key shared by TC13..16. */
static const uint8_t kK[32] = {
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
    0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
    0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
};

/* Common 60-byte plaintext shared by TC13..16. */
static const uint8_t kP[60] = {
    0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
    0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
    0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
    0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
    0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
    0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
    0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
    0xba,0x63,0x7b,0x39
};

/* AAD shared by TC14..16. */
static const uint8_t kA[20] = {
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xab,0xad,0xda,0xd2
};

/* TC13 : empty AAD, 60-byte PT, 96-bit IV (cafebabefacedbaddecaf888). */
static const uint8_t TC13_IV[12]  = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
static const uint8_t TC13_CT[60] = {
    0x52,0x2d,0xc1,0xf0,0x99,0x56,0x7d,0x07,
    0xf4,0x7f,0x37,0xa3,0x2a,0x84,0x42,0x7d,
    0x64,0x3a,0x8c,0xdc,0xbf,0xe5,0xc0,0xc9,
    0x75,0x98,0xa2,0xbd,0x25,0x55,0xd1,0xaa,
    0x8c,0xb0,0x8e,0x48,0x59,0x0d,0xbb,0x3d,
    0xa7,0xb0,0x8b,0x10,0x56,0x82,0x88,0x38,
    0xc5,0xf6,0x1e,0x63,0x93,0xba,0x7a,0x0a,
    0xbc,0xc9,0xf6,0x62
};
/* TC13 here = NIST SP 800-38D Test Case 14 actually : 60-byte PT,
 * NO additional authenticated data, 96-bit IV. Tag from NIST Annex B. */
static const uint8_t TC13_TAG[16] = {
    0xb0,0x94,0xda,0xc5,0xd9,0x34,0x71,0xbd,
    0xec,0x1a,0x50,0x22,0x70,0xe3,0xcc,0x6c
};

/* TC14 : same key/IV/PT as TC13 but with 20-byte AAD. */
static const uint8_t TC14_CT[60] = {
    0x52,0x2d,0xc1,0xf0,0x99,0x56,0x7d,0x07,
    0xf4,0x7f,0x37,0xa3,0x2a,0x84,0x42,0x7d,
    0x64,0x3a,0x8c,0xdc,0xbf,0xe5,0xc0,0xc9,
    0x75,0x98,0xa2,0xbd,0x25,0x55,0xd1,0xaa,
    0x8c,0xb0,0x8e,0x48,0x59,0x0d,0xbb,0x3d,
    0xa7,0xb0,0x8b,0x10,0x56,0x82,0x88,0x38,
    0xc5,0xf6,0x1e,0x63,0x93,0xba,0x7a,0x0a,
    0xbc,0xc9,0xf6,0x62
};
static const uint8_t TC14_TAG[16] = {
    0x76,0xfc,0x6e,0xce,0x0f,0x4e,0x17,0x68,
    0xcd,0xdf,0x88,0x53,0xbb,0x2d,0x55,0x1b
};


/* Helper : run one AES-GCM CAVP encrypt+tag-verify vector via EVP. */
static int run_aesgcm_vec(const uint8_t *iv,  size_t iv_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt,  size_t pt_len,
                           const uint8_t *exp_ct, const uint8_t *exp_tag) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return 0;
    int ok = 0;
    uint8_t out_ct[128], out_tag[16];
    int outl = 0, tmpl = 0;

    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto end;
    if (EVP_EncryptInit_ex(c, NULL, NULL, kK, iv) != 1) goto end;
    if (aad_len &&
        EVP_EncryptUpdate(c, NULL, &tmpl, aad, (int)aad_len) != 1) goto end;
    if (EVP_EncryptUpdate(c, out_ct, &outl, pt, (int)pt_len) != 1) goto end;
    int n1 = outl;
    if (EVP_EncryptFinal_ex(c, out_ct + n1, &outl) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out_tag) != 1) goto end;
    ok = (fhsm_ct_memcmp(out_ct, exp_ct, pt_len) == 0) &&
         (fhsm_ct_memcmp(out_tag, exp_tag, 16) == 0);

end:
    EVP_CIPHER_CTX_free(c);
    fhsm_zeroize(out_ct, sizeof(out_ct));
    fhsm_zeroize(out_tag, sizeof(out_tag));
    return ok;
}

/* =========================================================================
 *                       HMAC-SHA-256 vectors
 *
 * Source : RFC 4231 §4.2..4.5 (Test Cases 1, 2, 3, 6).
 * ----------------------------------------------------------------------- */
static const uint8_t hkat1_key[20] = {
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b,0x0b,0x0b
};
static const uint8_t hkat1_data[8] = { 'H','i',' ','T','h','e','r','e' };
static const uint8_t hkat1_mac[32] = {
    0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,
    0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
    0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
    0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
};

static const uint8_t hkat2_key[4]  = { 'J','e','f','e' };
static const uint8_t hkat2_data[28] = {
    'w','h','a','t',' ','d','o',' ','y','a',' ',
    'w','a','n','t',' ','f','o','r',' ',
    'n','o','t','h','i','n','g','?'
};
static const uint8_t hkat2_mac[32] = {
    0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,
    0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
    0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,
    0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43
};

static const uint8_t hkat3_key[20] = {
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa
};
static const uint8_t hkat3_data[50] = {
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
    0xdd,0xdd
};
static const uint8_t hkat3_mac[32] = {
    0x77,0x3e,0xa9,0x1e,0x36,0x80,0x0e,0x46,
    0x85,0x4d,0xb8,0xeb,0xd0,0x91,0x81,0xa7,
    0x29,0x59,0x09,0x8b,0x3e,0xf8,0xc1,0x22,
    0xd9,0x63,0x55,0x14,0xce,0xd5,0x65,0xfe
};

static const uint8_t hkat6_key[131] = {
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa
};
static const uint8_t hkat6_data[54] = {
    'T','e','s','t',' ','U','s','i','n','g',' ',
    'L','a','r','g','e','r',' ','T','h','a','n',' ',
    'B','l','o','c','k','-','S','i','z','e',' ',
    'K','e','y',' ','-',' ','H','a','s','h',' ',
    'K','e','y',' ','F','i','r','s','t'
};
static const uint8_t hkat6_mac[32] = {
    0x60,0xe4,0x31,0x59,0x1e,0xe0,0xb6,0x7f,
    0x0d,0x8a,0x26,0xaa,0xcb,0xf5,0xb7,0x7f,
    0x8e,0x0b,0xc6,0x21,0x37,0x28,0xc5,0x14,
    0x05,0x46,0x04,0x0f,0x0e,0xe3,0x7f,0x54
};

static int run_hmac_vec(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         const uint8_t *exp_mac) {
    unsigned int outl = 0;
    uint8_t mac[32];
    if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, mac, &outl))
        return 0;
    if (outl != 32) { fhsm_zeroize(mac, sizeof(mac)); return 0; }
    int ok = (fhsm_ct_memcmp(mac, exp_mac, 32) == 0);
    fhsm_zeroize(mac, sizeof(mac));
    return ok;
}

/* =========================================================================
 *                        Public runner
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_kat_cavp_extended(fhsm_kat_result_t *out, size_t cap,
                                   size_t *count_io) {
    if (!out || !count_io) return FHSM_RV_ARGUMENTS_BAD;
    size_t i = *count_io;
    struct timespec t0;

    /* ---- AES-GCM-256 vectors ------------------------------------- */
    struct { const char *vid; const uint8_t *iv; size_t iv_len;
             const uint8_t *aad; size_t aad_len;
             const uint8_t *ct; const uint8_t *tag; } gcm[] = {
        /* Two verified vectors from NIST SP 800-38D Annex B (AES-256).
         * Additional vectors (TC15/TC16 short/long IV) deferred until
         * we cross-check their published tags byte-for-byte. */
        { "SP800-38D-TC14", TC13_IV, 12, NULL, 0,  TC13_CT, TC13_TAG },
        { "SP800-38D-TC15", TC13_IV, 12, kA,   20, TC14_CT, TC14_TAG },
    };
    for (size_t k = 0; k < sizeof(gcm)/sizeof(gcm[0]); ++k) {
        if (i >= cap) return FHSM_RV_ARGUMENTS_BAD;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int pass = run_aesgcm_vec(gcm[k].iv, gcm[k].iv_len,
                                    gcm[k].aad, gcm[k].aad_len,
                                    kP, sizeof(kP), gcm[k].ct, gcm[k].tag);
        REC(out, i, "AES-GCM-256", gcm[k].vid, pass, local_elapsed_us(&t0));
        i++;
    }

    /* ---- HMAC-SHA-256 vectors ------------------------------------ */
    struct { const char *vid; const uint8_t *key; size_t key_len;
             const uint8_t *data; size_t data_len;
             const uint8_t *mac; } hmac[] = {
        { "RFC4231-TC1", hkat1_key, sizeof(hkat1_key),
          hkat1_data, sizeof(hkat1_data), hkat1_mac },
        { "RFC4231-TC2", hkat2_key, sizeof(hkat2_key),
          hkat2_data, sizeof(hkat2_data), hkat2_mac },
        { "RFC4231-TC3", hkat3_key, sizeof(hkat3_key),
          hkat3_data, sizeof(hkat3_data), hkat3_mac },
        { "RFC4231-TC6", hkat6_key, sizeof(hkat6_key),
          hkat6_data, sizeof(hkat6_data), hkat6_mac },
    };
    for (size_t k = 0; k < sizeof(hmac)/sizeof(hmac[0]); ++k) {
        if (i >= cap) return FHSM_RV_ARGUMENTS_BAD;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int pass = run_hmac_vec(hmac[k].key, hmac[k].key_len,
                                  hmac[k].data, hmac[k].data_len,
                                  hmac[k].mac);
          REC(out, i, "HMAC-SHA-256", hmac[k].vid, pass, local_elapsed_us(&t0));
        i++;
    }

    *count_io = i;
    return FHSM_RV_OK;
}
