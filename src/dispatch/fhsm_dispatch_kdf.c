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
 * fhsm_dispatch_kdf.c --- Key derivation function handlers.
 *
 *  - PBKDF2 (CKM_PKCS5_PBKD2)             SP 800-132
 *  - HKDF   (CKM_HKDF_DERIVE/DATA/KEYGEN) SP 800-56C rev. 2
 *  - SP 800-108 PRF KDF (CKM_NIST_PRF_KDF, stub)
 *  - Generic secret keygen                SP 800-133 rev. 2
 *
 *  Common TLV inputs (varies per mechanism):
 *     PASSWORD   --- PBKDF2 only
 *     KEY        --- HKDF only ("IKM" in RFC 5869)
 *     SALT       --- PBKDF2, HKDF
 *     INFO       --- HKDF only ("context" in SP 800-56C)
 *     ITERATIONS --- PBKDF2 (4 BE bytes; minimum 200_000)
 *     HASH_ALG   --- fhsm_hash_t (1 byte; SHA-256 / 384 / 512 only)
 * ========================================================================= */

#include "fhsm_dispatch_common.h"
#include "fhsm_crypto.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

#include <string.h>

static fhsm_hash_t parse_hash_alg(const fhsm_slice_t *s) {
    if (!s || s->len != 1) return FHSM_HASH_SHA256;  /* default */
    switch (s->data[0]) {
        case FHSM_HASH_SHA384: return FHSM_HASH_SHA384;
        case FHSM_HASH_SHA512: return FHSM_HASH_SHA512;
        default:               return FHSM_HASH_SHA256;
    }
}

static const char *hash_oqs_name(fhsm_hash_t h) {
    switch (h) {
        case FHSM_HASH_SHA384: return "SHA2-384";
        case FHSM_HASH_SHA512: return "SHA2-512";
        default:               return "SHA2-256";
    }
}

/* ---- PBKDF2 ---- */
fhsm_rv_t dispatch_pbkdf2(unsigned long session, unsigned long key,
                            const void *params, size_t plen,
                            fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key; (void)in;
    fhsm_slice_t pw, salt, iter_s, alg_s;
    fhsm_rv_t rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_PASSWORD,   &pw))   != FHSM_RV_OK) return rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_SALT,       &salt)) != FHSM_RV_OK) return rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_ITERATIONS, &iter_s)) != FHSM_RV_OK) return rv;
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_HASH_ALG, &alg_s);
    if (iter_s.len != 4) return FHSM_RV_ARGUMENTS_BAD;
    uint32_t iter = ((uint32_t)iter_s.data[0] << 24) |
                    ((uint32_t)iter_s.data[1] << 16) |
                    ((uint32_t)iter_s.data[2] << 8)  |
                     (uint32_t)iter_s.data[3];
    fhsm_hash_t h = parse_hash_alg(alg_s.len ? &alg_s : NULL);
    if (out == NULL || outlen == NULL) return FHSM_RV_ARGUMENTS_BAD;
    return fhsm_pbkdf2(h, pw, salt, iter, out, *outlen);
}

/* ---- HKDF (EVP_KDF "HKDF") ---- */
static fhsm_rv_t hkdf_run(int mode_flag /* 1=extract+expand, 0=expand only */,
                            fhsm_slice_t key_, fhsm_slice_t salt,
                            fhsm_slice_t info, fhsm_hash_t h,
                            uint8_t *out, size_t out_len)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return FHSM_RV_MECHANISM_INVALID;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx) { EVP_KDF_free(kdf); return FHSM_RV_HOST_MEMORY; }

    int mode = mode_flag ? EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
                          : EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    OSSL_PARAM params[6];
    int p = 0;
    params[p++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                    (char*)hash_oqs_name(h), 0);
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                    (void*)key_.data, key_.len);
    if (salt.len) {
        params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                        (void*)salt.data, salt.len);
    }
    if (info.len) {
        params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                        (void*)info.data, info.len);
    }
    params[p] = OSSL_PARAM_construct_end();

    fhsm_rv_t rv = (EVP_KDF_derive(ctx, out, out_len, params) == 1)
                    ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return rv;
}

fhsm_rv_t dispatch_hkdf(unsigned long session, unsigned long key,
                         const void *params, size_t plen,
                         fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key; (void)in;
    fhsm_slice_t k, salt, info, alg;
    fhsm_rv_t rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k)) != FHSM_RV_OK) return rv;
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_SALT,     &salt);
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_INFO,     &info);
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_HASH_ALG, &alg);
    fhsm_hash_t h = parse_hash_alg(alg.len ? &alg : NULL);
    if (out == NULL || outlen == NULL) return FHSM_RV_ARGUMENTS_BAD;
    return hkdf_run(1, k, salt, info, h, out, *outlen);
}

fhsm_rv_t dispatch_hkdf_data(unsigned long session, unsigned long key,
                               const void *params, size_t plen,
                               fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    /* HKDF-DATA = same as HKDF but the output is a data object, not a key.
     * Implementation is identical; the dispatcher tags the object class.   */
    return dispatch_hkdf(session, key, params, plen, in, out, outlen);
}

fhsm_rv_t dispatch_hkdf_keygen(unsigned long session, unsigned long key,
                                const void *params, size_t plen,
                                fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    /* HKDF-KEY_GEN = generate a random IKM, then derive. Equivalent to
     * fhsm_rng_bytes + hkdf. Returns the IKM in *out (the dispatcher
     * stores it as the object's CKA_VALUE). */
    (void)session; (void)key; (void)params; (void)plen; (void)in;
    if (out == NULL || outlen == NULL) return FHSM_RV_ARGUMENTS_BAD;
    return fhsm_rng_bytes(out, *outlen);
}

/* ---- SP 800-108 PRF KDF (KBKDF counter mode with HMAC-SHA-2 PRF) ---- */
fhsm_rv_t dispatch_nist_prf_kdf(unsigned long session, unsigned long key,
                                  const void *params, size_t plen,
                                  fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key; (void)in;
    fhsm_slice_t Ki, info, alg;
    fhsm_rv_t rv;
    /* Ki = key derivation key (CKK_HMAC). */
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &Ki)) != FHSM_RV_OK) return rv;
    /* info = fixed input data (SP 800-108 §5.1 : Label || 0x00 || Context || L). */
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_INFO, &info);
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_HASH_ALG, &alg);
    fhsm_hash_t h = parse_hash_alg(alg.len ? &alg : NULL);
    if (out == NULL || outlen == NULL || *outlen == 0) return FHSM_RV_ARGUMENTS_BAD;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    if (!kdf) return FHSM_RV_MECHANISM_INVALID;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx) { EVP_KDF_free(kdf); return FHSM_RV_HOST_MEMORY; }

    char mode[] = "counter";
    char mac[]  = "HMAC";
    OSSL_PARAM p[7];
    int pi = 0;
    p[pi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE,   mode, 0);
    p[pi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC,    mac,  0);
    p[pi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                    (char*)hash_oqs_name(h), 0);
    p[pi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                    (void*)Ki.data, Ki.len);
    if (info.len) {
        p[pi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                        (void*)info.data, info.len);
    }
    p[pi] = OSSL_PARAM_construct_end();

    rv = (EVP_KDF_derive(ctx, out, *outlen, p) == 1)
          ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return rv;
}

/* ---- Generic secret keygen ---- */
fhsm_rv_t dispatch_generic_secret_keygen(unsigned long session, unsigned long key,
                                            const void *params, size_t plen,
                                            fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key; (void)params; (void)plen; (void)in;
    if (out == NULL || outlen == NULL || *outlen == 0) return FHSM_RV_ARGUMENTS_BAD;
    return fhsm_rng_bytes(out, *outlen);
}
