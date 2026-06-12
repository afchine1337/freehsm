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
 * fhsm_dispatch_aes.c --- AES handlers.
 *
 *  AES-GCM        : uses fhsm_aes_gcm_encrypt() (already FIPS-wrapped).
 *  AES-CBC/CTR/CCM/KW/KWP : delegate to EVP_CIPHER directly.
 *  AES-CMAC       : EVP_MAC with "CMAC" name + "AES-256-CBC" cipher.
 *  AES-KEY_GEN    : fhsm_rng_bytes() returns the raw key bytes.
 *
 *  Params TLV layout (all symmetric encrypt/decrypt handlers):
 *     KEY  (mandatory)
 *     IV   (mandatory for CBC/CTR/GCM/CCM/KW)
 *     AAD  (optional, AEAD only)
 *     TAG  (decrypt only --- caller-supplied AEAD tag)
 *
 *  Direction (encrypt vs decrypt):
 *     The dispatcher selects via fhsm_dispatch_table entry .operation
 *     "encrypt" or "decrypt". For now, every encrypt-direction handler
 *     here assumes encrypt; the decrypt mirror is wired in a follow-up.
 * ========================================================================= */

#include "fhsm_dispatch_common.h"
#include "fhsm_crypto.h"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <string.h>

/* ---- AES-KEY_GEN : returns a raw 128/192/256-bit key in *out. ---- */
fhsm_rv_t dispatch_aes_keygen(unsigned long session, unsigned long key,
                                const void *params, size_t plen,
                                fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key; (void)in;
    if (out == NULL || outlen == NULL) return FHSM_RV_ARGUMENTS_BAD;

    /* Key size in bits, as a 2-byte big-endian field in params (TLV
     * type FHSM_TLV_KEY_BITS). Defaults to 256. */
    size_t bits = 256;
    fhsm_slice_t hint;
    if (fhsm_tlv_find(params, plen, FHSM_TLV_KEY_BITS, &hint) == FHSM_RV_OK
        && hint.len == 2) {
        bits = ((size_t)hint.data[0] << 8) | hint.data[1];
    }
    if (bits != 128 && bits != 192 && bits != 256) return FHSM_RV_KEY_SIZE_RANGE;
    size_t bytes = bits / 8;
    if (*outlen < bytes) return FHSM_RV_ARGUMENTS_BAD;
    *outlen = bytes;
    return fhsm_rng_bytes(out, bytes);
}

/* ---- AES-GCM (delegates to fhsm_aes_gcm_encrypt). ---- */
fhsm_rv_t dispatch_aes_gcm(unsigned long session, unsigned long key,
                            const void *params, size_t plen,
                            fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    if (out == NULL || outlen == NULL) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_slice_t k, iv, aad;
    fhsm_rv_t rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k)) != FHSM_RV_OK) return rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_IV,  &iv)) != FHSM_RV_OK) return rv;
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_AAD, &aad);

    /* GCM ciphertext length equals plaintext length; the 16-byte tag
     * is appended to *out. Caller must therefore pass *outlen >= in.len + 16. */
    if (*outlen < in.len + 16) return FHSM_RV_ARGUMENTS_BAD;
    size_t ct_len = in.len;
    uint8_t tag[16];
    rv = fhsm_aes_gcm_encrypt(k, iv, aad, in, out, &ct_len, tag);
    if (rv == FHSM_RV_OK) {
        memcpy(out + ct_len, tag, 16);
        *outlen = ct_len + 16;
    }
    fhsm_zeroize(tag, sizeof(tag));
    return rv;
}

/* ---- Generic EVP_CIPHER one-shot ---- */
static fhsm_rv_t evp_cipher_oneshot(const EVP_CIPHER *cipher,
                                      fhsm_slice_t k, fhsm_slice_t iv,
                                      fhsm_slice_t in,
                                      uint8_t *out, size_t *outlen,
                                      int padding)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return FHSM_RV_HOST_MEMORY;

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    int outl = 0;
    size_t produced = 0;
    if (EVP_EncryptInit_ex2(ctx, cipher, k.data,
                             iv.len ? iv.data : NULL, NULL) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(ctx, padding);
    if (EVP_EncryptUpdate(ctx, out, &outl, in.data, (int)in.len) != 1) goto out;
    produced = (size_t)outl;
    if (EVP_EncryptFinal_ex(ctx, out + produced, &outl) != 1) goto out;
    produced += (size_t)outl;
    *outlen = produced;
    rv = FHSM_RV_OK;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rv;
}

static const EVP_CIPHER *aes_cipher(size_t keylen,
                                      const EVP_CIPHER *(*p128)(void),
                                      const EVP_CIPHER *(*p192)(void),
                                      const EVP_CIPHER *(*p256)(void))
{
    switch (keylen) {
        case 16: return p128();
        case 24: return p192();
        case 32: return p256();
        default: return NULL;
    }
}

/* ---- AES-CBC (no padding) ---- */
fhsm_rv_t dispatch_aes_cbc(unsigned long session, unsigned long key,
                            const void *params, size_t plen,
                            fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    fhsm_slice_t k, iv;
    fhsm_rv_t rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k)) != FHSM_RV_OK) return rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_IV,  &iv)) != FHSM_RV_OK) return rv;
    if (iv.len != 16 || in.len % 16) return FHSM_RV_ARGUMENTS_BAD;
    if (*outlen < in.len) return FHSM_RV_ARGUMENTS_BAD;
    const EVP_CIPHER *c = aes_cipher(k.len, EVP_aes_128_cbc,
                                      EVP_aes_192_cbc, EVP_aes_256_cbc);
    if (!c) return FHSM_RV_KEY_SIZE_RANGE;
    return evp_cipher_oneshot(c, k, iv, in, out, outlen, 0);
}

/* ---- AES-CBC-PAD (PKCS#7) ---- */
fhsm_rv_t dispatch_aes_cbc_pad(unsigned long session, unsigned long key,
                                const void *params, size_t plen,
                                fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    fhsm_slice_t k, iv;
    fhsm_rv_t rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k)) != FHSM_RV_OK) return rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_IV,  &iv)) != FHSM_RV_OK) return rv;
    if (iv.len != 16) return FHSM_RV_ARGUMENTS_BAD;
    /* PKCS#7 expands plaintext by up to a full block. */
    if (*outlen < in.len + 16) return FHSM_RV_ARGUMENTS_BAD;
    const EVP_CIPHER *c = aes_cipher(k.len, EVP_aes_128_cbc,
                                      EVP_aes_192_cbc, EVP_aes_256_cbc);
    if (!c) return FHSM_RV_KEY_SIZE_RANGE;
    return evp_cipher_oneshot(c, k, iv, in, out, outlen, 1);
}

/* ---- AES-CTR ---- */
fhsm_rv_t dispatch_aes_ctr(unsigned long session, unsigned long key,
                            const void *params, size_t plen,
                            fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    fhsm_slice_t k, iv;
    fhsm_rv_t rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k)) != FHSM_RV_OK) return rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_IV,  &iv)) != FHSM_RV_OK) return rv;
    if (iv.len != 16) return FHSM_RV_ARGUMENTS_BAD;
    if (*outlen < in.len) return FHSM_RV_ARGUMENTS_BAD;
    const EVP_CIPHER *c = aes_cipher(k.len, EVP_aes_128_ctr,
                                      EVP_aes_192_ctr, EVP_aes_256_ctr);
    if (!c) return FHSM_RV_KEY_SIZE_RANGE;
    return evp_cipher_oneshot(c, k, iv, in, out, outlen, 0);
}

/* ---------------------------------------------------------------------------
 * AES-CCM (SP 800-38C). The OpenSSL EVP_CIPHER interface for CCM
 * requires a strict init sequence : set IV-length and tag-length
 * before keying, then declare the total plaintext length via
 * EVP_EncryptUpdate(NULL, ...) before feeding AAD and plaintext.
 * The 12-byte IV + 16-byte tag pair is the FIPS-approved baseline ;
 * shorter tags are rejected at the dispatcher level.
 * ----------------------------------------------------------------------- */
fhsm_rv_t dispatch_aes_ccm(unsigned long session, unsigned long key,
                            const void *params, size_t plen,
                            fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    fhsm_slice_t k, iv, aad;
    fhsm_rv_t rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k)) != FHSM_RV_OK) return rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_IV,  &iv)) != FHSM_RV_OK) return rv;
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_AAD, &aad);
    if (iv.len < 7 || iv.len > 13) return FHSM_RV_ARGUMENTS_BAD;
    if (*outlen < in.len + 16) return FHSM_RV_ARGUMENTS_BAD;

    const EVP_CIPHER *cipher = aes_cipher(k.len, EVP_aes_128_ccm,
                                            EVP_aes_192_ccm, EVP_aes_256_ccm);
    if (!cipher) return FHSM_RV_KEY_SIZE_RANGE;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return FHSM_RV_HOST_MEMORY;

    rv = FHSM_RV_FUNCTION_FAILED;
    int outl = 0;
    uint8_t tag[16];

    /* Pass 1: configure cipher with NULL key/iv to set IV/tag length. */
    if (EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, (int)iv.len, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL) != 1) goto out;
    /* Pass 2: real key/iv. */
    if (EVP_EncryptInit_ex2(ctx, NULL, k.data, iv.data, NULL) != 1) goto out;
    /* Declare plaintext length up-front (mandatory for CCM). */
    if (EVP_EncryptUpdate(ctx, NULL, &outl, NULL, (int)in.len) != 1) goto out;
    if (aad.len) {
        if (EVP_EncryptUpdate(ctx, NULL, &outl, aad.data, (int)aad.len) != 1) goto out;
    }
    if (EVP_EncryptUpdate(ctx, out, &outl, in.data, (int)in.len) != 1) goto out;
    size_t produced = (size_t)outl;
    if (EVP_EncryptFinal_ex(ctx, out + produced, &outl) != 1) goto out;
    produced += (size_t)outl;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, tag) != 1) goto out;
    memcpy(out + produced, tag, 16);
    *outlen = produced + 16;
    rv = FHSM_RV_OK;

out:
    fhsm_zeroize(tag, sizeof(tag));
    EVP_CIPHER_CTX_free(ctx);
    return rv;
}

/* ---------------------------------------------------------------------------
 * AES-KW (RFC 3394, SP 800-38F §6.2). Plaintext must be a multiple of
 * 8 octets and at least 16 octets long. Output is 8 octets longer than
 * input (the integrity check value).
 * ----------------------------------------------------------------------- */
static fhsm_rv_t aes_keywrap_oneshot(const EVP_CIPHER *cipher,
                                       fhsm_slice_t k, fhsm_slice_t in,
                                       uint8_t *out, size_t *outlen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return FHSM_RV_HOST_MEMORY;
    /* Wrap modes require an explicit set_flags to enable wrap operation. */
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    int outl = 0;
    size_t produced = 0;
    /* AES-KW uses the default RFC 3394 IV (a6a6a6a6a6a6a6a6) when iv=NULL. */
    if (EVP_EncryptInit_ex2(ctx, cipher, k.data, NULL, NULL) != 1) goto out;
    if (EVP_EncryptUpdate(ctx, out, &outl, in.data, (int)in.len) != 1) goto out;
    produced = (size_t)outl;
    if (EVP_EncryptFinal_ex(ctx, out + produced, &outl) != 1) goto out;
    produced += (size_t)outl;
    *outlen = produced;
    rv = FHSM_RV_OK;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rv;
}

fhsm_rv_t dispatch_aes_kw(unsigned long session, unsigned long key,
                           const void *params, size_t plen,
                           fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    fhsm_slice_t k;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k);
    if (rv != FHSM_RV_OK) return rv;
    /* RFC 3394 mandates : plaintext multiple of 8, >= 16 octets. */
    if (in.len < 16 || in.len % 8 != 0) return FHSM_RV_ARGUMENTS_BAD;
    if (*outlen < in.len + 8) return FHSM_RV_ARGUMENTS_BAD;
    const EVP_CIPHER *c = aes_cipher(k.len, EVP_aes_128_wrap,
                                      EVP_aes_192_wrap, EVP_aes_256_wrap);
    if (!c) return FHSM_RV_KEY_SIZE_RANGE;
    return aes_keywrap_oneshot(c, k, in, out, outlen);
}

/* ---------------------------------------------------------------------------
 * AES-KWP (RFC 5649, SP 800-38F §6.3). Same as KW but with an integrity-
 * preserving padding scheme allowing any plaintext length >= 1.
 * ----------------------------------------------------------------------- */
fhsm_rv_t dispatch_aes_kwp(unsigned long session, unsigned long key,
                            const void *params, size_t plen,
                            fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    fhsm_slice_t k;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k);
    if (rv != FHSM_RV_OK) return rv;
    if (in.len == 0) return FHSM_RV_ARGUMENTS_BAD;
    /* KWP output : ceil(len/8)*8 + 8 octets. */
    size_t need = ((in.len + 7) & ~(size_t)7) + 8;
    if (*outlen < need) return FHSM_RV_ARGUMENTS_BAD;
    const EVP_CIPHER *c = aes_cipher(k.len, EVP_aes_128_wrap_pad,
                                      EVP_aes_192_wrap_pad, EVP_aes_256_wrap_pad);
    if (!c) return FHSM_RV_KEY_SIZE_RANGE;
    return aes_keywrap_oneshot(c, k, in, out, outlen);
}

/* ---------------------------------------------------------------------------
 * AES-CMAC (SP 800-38B). Uses the modern EVP_MAC interface ("CMAC")
 * with the underlying cipher selected by key length.
 * ----------------------------------------------------------------------- */
fhsm_rv_t dispatch_aes_cmac(unsigned long session, unsigned long key,
                             const void *params, size_t plen,
                             fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    fhsm_slice_t k;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k);
    if (rv != FHSM_RV_OK) return rv;
    if (k.len != 16 && k.len != 24 && k.len != 32) return FHSM_RV_KEY_SIZE_RANGE;
    if (*outlen < 16) return FHSM_RV_ARGUMENTS_BAD;

    const char *cipher = (k.len == 16) ? "AES-128-CBC"
                          : (k.len == 24) ? "AES-192-CBC"
                                            : "AES-256-CBC";
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) return FHSM_RV_MECHANISM_INVALID;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) { EVP_MAC_free(mac); return FHSM_RV_HOST_MEMORY; }

    OSSL_PARAM mac_params[2] = {
        OSSL_PARAM_construct_utf8_string("cipher", (char*)cipher, 0),
        OSSL_PARAM_construct_end()
    };
    rv = FHSM_RV_FUNCTION_FAILED;
    size_t mac_out = 0;
    if (EVP_MAC_init(ctx, k.data, k.len, mac_params) == 1 &&
        EVP_MAC_update(ctx, in.data, in.len) == 1 &&
        EVP_MAC_final(ctx, out, &mac_out, *outlen) == 1) {
        *outlen = mac_out;   /* always 16 for AES-CMAC */
        rv = FHSM_RV_OK;
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return rv;
}
