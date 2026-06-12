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
 * fhsm_pairwise.c --- Pair-wise consistency check post-keygen.
 *
 *  See header for rationale. Each family is checked by a single round-
 *  trip operation. The fixed plaintext / message / digest is hard-coded
 *  rather than randomized to keep the check deterministic and audit-
 *  loggable without leaking RNG state across operations.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_pairwise.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>      /* RSA_PKCS1_PADDING + EVP_PKEY_CTX_set_rsa_padding */

/* Fixed plaintexts / messages used by the pair-wise checks. Their
 * content is not security-sensitive --- any 32-byte value would do.
 * The fixed values let the operator reproduce the exact computation in
 * a debugger if a check ever fails. */
static const uint8_t s_msg[32] = {
    'F','H','S','M',' ','p','a','i','r','-','w','i','s','e',' ','c',
    'o','n','s','i','s','t','e','n','c','y',' ','c','h','e','c','k'
};
static const uint8_t s_digest_sha256[32] = {
    /* SHA-256 of "FHSM pair-wise consistency check" (32-byte ASCII). */
    0x5B,0x7C,0x10,0xBA,0xCC,0x68,0xA0,0xF7,
    0xDF,0xBE,0x4E,0x53,0x4C,0x88,0xD8,0xD2,
    0x97,0x62,0x9F,0x35,0xD6,0xE9,0x82,0xC2,
    0xB6,0xF5,0xC4,0xF6,0xEB,0xCC,0x14,0x66
};

/* ---------------------------------------------------------------------------
 * RSA : public encrypt + private decrypt round trip.
 * Uses PKCS#1 v1.5 padding for simplicity (any padding works for this
 * test, but PKCS#1 v1.5 is the minimum baseline).
 * ----------------------------------------------------------------------- */
static fhsm_rv_t pairwise_rsa(EVP_PKEY *pkey) {
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    EVP_PKEY_CTX *enc = NULL, *dec = NULL;
    uint8_t ct[1024], pt[1024];
    size_t  ct_len = sizeof(ct), pt_len = sizeof(pt);

    enc = EVP_PKEY_CTX_new(pkey, NULL);
    if (!enc) goto done;
    if (EVP_PKEY_encrypt_init(enc) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(enc, RSA_PKCS1_PADDING) <= 0) goto done;
    if (EVP_PKEY_encrypt(enc, ct, &ct_len, s_msg, sizeof(s_msg)) <= 0) goto done;

    dec = EVP_PKEY_CTX_new(pkey, NULL);
    if (!dec) goto done;
    if (EVP_PKEY_decrypt_init(dec) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(dec, RSA_PKCS1_PADDING) <= 0) goto done;
    if (EVP_PKEY_decrypt(dec, pt, &pt_len, ct, ct_len) <= 0) goto done;

    if (pt_len != sizeof(s_msg)) goto done;
    if (memcmp(pt, s_msg, pt_len) != 0) goto done;
    rv = FHSM_RV_OK;

done:
    EVP_PKEY_CTX_free(enc);
    EVP_PKEY_CTX_free(dec);
    return rv;
}

/* ---------------------------------------------------------------------------
 * EC : ECDSA sign-then-verify the precomputed SHA-256 digest.
 * ----------------------------------------------------------------------- */
static fhsm_rv_t pairwise_ec(EVP_PKEY *pkey) {
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    EVP_PKEY_CTX *s = NULL, *v = NULL;
    uint8_t sig[256];
    size_t  sig_len = sizeof(sig);

    s = EVP_PKEY_CTX_new(pkey, NULL);
    if (!s) goto done;
    if (EVP_PKEY_sign_init(s) <= 0) goto done;
    if (EVP_PKEY_sign(s, sig, &sig_len, s_digest_sha256,
                       sizeof(s_digest_sha256)) <= 0) goto done;

    v = EVP_PKEY_CTX_new(pkey, NULL);
    if (!v) goto done;
    if (EVP_PKEY_verify_init(v) <= 0) goto done;
    if (EVP_PKEY_verify(v, sig, sig_len, s_digest_sha256,
                         sizeof(s_digest_sha256)) != 1) goto done;
    rv = FHSM_RV_OK;

done:
    EVP_PKEY_CTX_free(s);
    EVP_PKEY_CTX_free(v);
    return rv;
}

/* ---------------------------------------------------------------------------
 * ML-DSA / SLH-DSA : EVP_DigestSign with hash=NULL (pre-hash disabled).
 * Same path that the application uses. We re-derive the verify ctx from
 * the same pkey to avoid serializing through DER.
 * ----------------------------------------------------------------------- */
static fhsm_rv_t pairwise_pq_sign(EVP_PKEY *pkey) {
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    EVP_MD_CTX *s = NULL, *v = NULL;
    uint8_t sig[16384];   /* enough for SLH-DSA-SHA2-128s (~8k) */
    size_t  sig_len = sizeof(sig);

    s = EVP_MD_CTX_new();
    if (!s) goto done;
    if (EVP_DigestSignInit(s, NULL, NULL, NULL, pkey) <= 0) goto done;
    if (EVP_DigestSign(s, sig, &sig_len, s_msg, sizeof(s_msg)) <= 0) goto done;

    v = EVP_MD_CTX_new();
    if (!v) goto done;
    if (EVP_DigestVerifyInit(v, NULL, NULL, NULL, pkey) <= 0) goto done;
    if (EVP_DigestVerify(v, sig, sig_len, s_msg, sizeof(s_msg)) != 1) goto done;
    rv = FHSM_RV_OK;

done:
    EVP_MD_CTX_free(s);
    EVP_MD_CTX_free(v);
    return rv;
}

/* ---------------------------------------------------------------------------
 * ML-KEM : encapsulate + decapsulate ; compare shared secrets.
 * ----------------------------------------------------------------------- */
static fhsm_rv_t pairwise_mlkem(EVP_PKEY *pkey) {
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    EVP_PKEY_CTX *e = NULL, *d = NULL;
    uint8_t ct[2048], ss1[64], ss2[64];
    size_t  ct_len = sizeof(ct), ss1_len = sizeof(ss1), ss2_len = sizeof(ss2);

    e = EVP_PKEY_CTX_new(pkey, NULL);
    if (!e) goto done;
    if (EVP_PKEY_encapsulate_init(e, NULL) <= 0) goto done;
    if (EVP_PKEY_encapsulate(e, ct, &ct_len, ss1, &ss1_len) <= 0) goto done;

    d = EVP_PKEY_CTX_new(pkey, NULL);
    if (!d) goto done;
    if (EVP_PKEY_decapsulate_init(d, NULL) <= 0) goto done;
    if (EVP_PKEY_decapsulate(d, ss2, &ss2_len, ct, ct_len) <= 0) goto done;

    if (ss1_len != ss2_len) goto done;
    if (ss1_len == 0) goto done;
    if (memcmp(ss1, ss2, ss1_len) != 0) goto done;
    rv = FHSM_RV_OK;

done:
    EVP_PKEY_CTX_free(e);
    EVP_PKEY_CTX_free(d);
    return rv;
}

/* ---------------------------------------------------------------------------
 * Public entry point.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_pairwise_check(EVP_PKEY *pkey, fhsm_pairwise_family_t family) {
    if (!pkey) return FHSM_RV_ARGUMENTS_BAD;
    switch (family) {
    case FHSM_PAIRWISE_RSA:     return pairwise_rsa(pkey);
    case FHSM_PAIRWISE_EC:      return pairwise_ec(pkey);
    case FHSM_PAIRWISE_ML_KEM:  return pairwise_mlkem(pkey);
    case FHSM_PAIRWISE_ML_DSA:  return pairwise_pq_sign(pkey);
    case FHSM_PAIRWISE_SLH_DSA: return pairwise_pq_sign(pkey);
    default:                    return FHSM_RV_ARGUMENTS_BAD;
    }
}
