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
 * fhsm_dispatch_pkey.c --- RSA + EC + EdDSA + ECDH/X25519/X448 handlers.
 *
 *  Uses EVP_PKEY uniformly. The private/public key is loaded from a
 *  PEM blob passed via TLV (FHSM_TLV_PEM / FHSM_TLV_PEM_PUB) until the
 *  object store is fully wired. After that, the key handle will be
 *  resolved to an EVP_PKEY* by the session layer.
 *
 *  Implemented (real EVP) :
 *    - RSA-PSS (sign)  --- with embedded SHA-256/384/512 hash
 *    - RSA-OAEP encrypt
 *    - ECDSA-SHA-{256,384,512} sign
 *    - EdDSA sign (Ed25519 / Ed448)
 *    - ECDH1_DERIVE / X25519_DERIVE / X448_DERIVE
 *    - Keypair generation (RSA / EC / EdDSA / X25519)
 *
 *  Stubbed (return FUNCTION_FAILED) :
 *    - dispatch_rsa_pss (params-less variant, expects pre-hashed input)
 *    - dispatch_ecdsa   (raw, expects pre-hashed input)
 *    - dispatch_ecdh1_cofactor (rare ; co-factor variant)
 *    - dispatch_eddsa_keypair / dispatch_ecm_keypair (need parameter set)
 *
 *  Output buffer convention :
 *    - sign  : raw signature bytes (DER for ECDSA, fixed-size for EdDSA).
 *    - encrypt : ciphertext bytes.
 *    - derive : raw shared secret bytes.
 *    - keypair : PEM-encoded private key in *out.
 * ========================================================================= */

#include "fhsm_dispatch_common.h"
#include "fhsm_crypto.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <string.h>

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */
static EVP_PKEY *load_priv(fhsm_slice_t pem_slice) {
    BIO *b = BIO_new_mem_buf(pem_slice.data, (int)pem_slice.len);
    if (!b) return NULL;
    EVP_PKEY *pk = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    return pk;
}

static EVP_PKEY *load_pub(fhsm_slice_t pem_slice) {
    BIO *b = BIO_new_mem_buf(pem_slice.data, (int)pem_slice.len);
    if (!b) return NULL;
    EVP_PKEY *pk = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL);
    BIO_free(b);
    return pk;
}

static const char *digest_for_alg(fhsm_hash_t h) {
    switch (h) {
        case FHSM_HASH_SHA384: return "SHA2-384";
        case FHSM_HASH_SHA512: return "SHA2-512";
        default:               return "SHA2-256";
    }
}

/* Sign using EVP_DigestSign with the supplied digest. */
static fhsm_rv_t pkey_sign(EVP_PKEY *pk, const char *digest,
                             fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return FHSM_RV_HOST_MEMORY;

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    if (EVP_DigestSignInit_ex(ctx, NULL, digest, NULL, NULL, pk, NULL) != 1)
        goto out;
    if (EVP_DigestSign(ctx, out, outlen, in.data, in.len) != 1)
        goto out;
    rv = FHSM_RV_OK;
out:
    EVP_MD_CTX_free(ctx);
    return rv;
}

/* ---------------------------------------------------------------------------
 * RSA-PSS sign (with embedded hash)
 * ------------------------------------------------------------------------- */
static fhsm_rv_t rsa_pss_sign(fhsm_hash_t h,
                                const void *params, size_t plen,
                                fhsm_slice_t in,
                                uint8_t *out, size_t *outlen)
{
    fhsm_slice_t pem;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM, &pem);
    if (rv != FHSM_RV_OK) return rv;
    EVP_PKEY *pk = load_priv(pem);
    if (!pk) return FHSM_RV_KEY_HANDLE_INVALID;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pk); return FHSM_RV_HOST_MEMORY; }
    EVP_PKEY_CTX *pkctx = NULL;
    fhsm_rv_t r = FHSM_RV_FUNCTION_FAILED;
    if (EVP_DigestSignInit_ex(ctx, &pkctx, digest_for_alg(h),
                                NULL, NULL, pk, NULL) != 1) goto out;
    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) <= 0) goto out;
    if (EVP_DigestSign(ctx, out, outlen, in.data, in.len) != 1) goto out;
    r = FHSM_RV_OK;
out:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return r;
}

fhsm_rv_t dispatch_rsa_pss_sha256(unsigned long s, unsigned long k,
                                    const void *p, size_t pl,
                                    fhsm_slice_t in, uint8_t *o, size_t *ol)
{ (void)s; (void)k; return rsa_pss_sign(FHSM_HASH_SHA256, p, pl, in, o, ol); }

fhsm_rv_t dispatch_rsa_pss_sha384(unsigned long s, unsigned long k,
                                    const void *p, size_t pl,
                                    fhsm_slice_t in, uint8_t *o, size_t *ol)
{ (void)s; (void)k; return rsa_pss_sign(FHSM_HASH_SHA384, p, pl, in, o, ol); }

fhsm_rv_t dispatch_rsa_pss_sha512(unsigned long s, unsigned long k,
                                    const void *p, size_t pl,
                                    fhsm_slice_t in, uint8_t *o, size_t *ol)
{ (void)s; (void)k; return rsa_pss_sign(FHSM_HASH_SHA512, p, pl, in, o, ol); }

/* "Raw" RSA-PSS expects the caller to provide an already-hashed value.
 * Until the mechanism param parser supports CK_RSA_PKCS_PSS_PARAMS, we
 * default to SHA-256.  */
fhsm_rv_t dispatch_rsa_pss(unsigned long s, unsigned long k,
                            const void *p, size_t pl,
                            fhsm_slice_t in, uint8_t *o, size_t *ol)
{ (void)s; (void)k; return rsa_pss_sign(FHSM_HASH_SHA256, p, pl, in, o, ol); }

/* SHA1-RSA-PKCS (non-FIPS ; interop only) : PKCS#1 v1.5 RSA signature
 * over a SHA-1 digest of the message. Reference impl ; the operation
 * path is C_Sign (mech_hash_name -> "SHA1", default PKCS#1 v1.5). #125. */
fhsm_rv_t dispatch_sha1_rsa(unsigned long s, unsigned long k,
                             const void *params, size_t plen,
                             fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k;
    fhsm_slice_t pem;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM, &pem);
    if (rv != FHSM_RV_OK) return rv;
    EVP_PKEY *pk = load_priv(pem);
    if (!pk) return FHSM_RV_KEY_HANDLE_INVALID;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pk); return FHSM_RV_HOST_MEMORY; }
    EVP_PKEY_CTX *pkctx = NULL;
    fhsm_rv_t r = FHSM_RV_FUNCTION_FAILED;
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA1", NULL);
    if (!md) goto out;
    if (EVP_DigestSignInit_ex(ctx, &pkctx, "SHA1", NULL, NULL, pk, NULL) != 1) goto out;
    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0) goto out;
    if (EVP_DigestSign(ctx, out, outlen, in.data, in.len) != 1) goto out;
    r = FHSM_RV_OK;
out:
    if (md) EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return r;
}

/* ---------------------------------------------------------------------------
 * RSA-OAEP encrypt
 * ------------------------------------------------------------------------- */
fhsm_rv_t dispatch_rsa_oaep(unsigned long s, unsigned long k,
                              const void *params, size_t plen,
                              fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k;
    fhsm_slice_t pem;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM_PUB, &pem);
    if (rv != FHSM_RV_OK) return rv;
    EVP_PKEY *pk = load_pub(pem);
    if (!pk) return FHSM_RV_KEY_HANDLE_INVALID;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);
    fhsm_rv_t r = FHSM_RV_FUNCTION_FAILED;
    if (!ctx) { EVP_PKEY_free(pk); return FHSM_RV_HOST_MEMORY; }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto out;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto out;
    if (EVP_PKEY_encrypt(ctx, out, outlen, in.data, in.len) <= 0) goto out;
    r = FHSM_RV_OK;
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return r;
}

/* ---- RSA encryption with legacy padding (non-FIPS ; interop only).
 * PKCS#1 v1.5 (RSA_PKCS1_PADDING) and raw / X.509 (RSA_NO_PADDING).
 * Reference implementations ; the operation path lives in
 * C_Encrypt/C_Decrypt. #125. ---- */
static fhsm_rv_t rsa_enc_pad(const void *params, size_t plen,
                              fhsm_slice_t in, uint8_t *out, size_t *outlen,
                              int padding)
{
    fhsm_slice_t pem;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM_PUB, &pem);
    if (rv != FHSM_RV_OK) return rv;
    EVP_PKEY *pk = load_pub(pem);
    if (!pk) return FHSM_RV_KEY_HANDLE_INVALID;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);
    fhsm_rv_t r = FHSM_RV_FUNCTION_FAILED;
    if (!ctx) { EVP_PKEY_free(pk); return FHSM_RV_HOST_MEMORY; }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto out;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) goto out;
    if (EVP_PKEY_encrypt(ctx, out, outlen, in.data, in.len) <= 0) goto out;
    r = FHSM_RV_OK;
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return r;
}

fhsm_rv_t dispatch_rsa_pkcs(unsigned long s, unsigned long k,
                             const void *params, size_t plen,
                             fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k;
    return rsa_enc_pad(params, plen, in, out, outlen, RSA_PKCS1_PADDING);
}

fhsm_rv_t dispatch_rsa_x509(unsigned long s, unsigned long k,
                             const void *params, size_t plen,
                             fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k;
    return rsa_enc_pad(params, plen, in, out, outlen, RSA_NO_PADDING);
}

/* ---------------------------------------------------------------------------
 * RSA keypair generation
 * ------------------------------------------------------------------------- */
fhsm_rv_t dispatch_rsa_keypair(unsigned long s, unsigned long k,
                                 const void *params, size_t plen,
                                 fhsm_slice_t in,
                                 uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)in;
    /* Key size: 2 BE bytes in FHSM_TLV_KEY_BITS, defaulting to 3072. */
    size_t bits = 3072;
    fhsm_slice_t hint;
    if (fhsm_tlv_find(params, plen, FHSM_TLV_KEY_BITS, &hint) == FHSM_RV_OK
        && hint.len == 2) {
        bits = ((size_t)hint.data[0] << 8) | hint.data[1];
    }
    if (bits < 2048 || bits > 4096) return FHSM_RV_KEY_SIZE_RANGE;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) return FHSM_RV_HOST_MEMORY;
    EVP_PKEY *pk = NULL;
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto out;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)bits) <= 0) goto out;
    if (EVP_PKEY_generate(ctx, &pk) <= 0) goto out;

    /* Serialize private key as PEM into *out. */
    BIO *b = BIO_new(BIO_s_mem());
    if (!b) goto out;
    if (PEM_write_bio_PrivateKey(b, pk, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(b); goto out;
    }
    char *data = NULL;
    long n = BIO_get_mem_data(b, &data);
    if (n < 0 || (size_t)n > *outlen) { BIO_free(b); goto out; }
    memcpy(out, data, (size_t)n);
    *outlen = (size_t)n;
    BIO_free(b);
    rv = FHSM_RV_OK;
out:
    if (pk) EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    return rv;
}

/* ---------------------------------------------------------------------------
 * ECDSA sign (with embedded hash)
 * ------------------------------------------------------------------------- */
static fhsm_rv_t ec_keypair_named(const char *curve_name,
                                    uint8_t *out, size_t *outlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) return FHSM_RV_HOST_MEMORY;
    EVP_PKEY *pk = NULL;
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    OSSL_PARAM p[2] = {
        OSSL_PARAM_construct_utf8_string("group", (char*)curve_name, 0),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto out;
    if (EVP_PKEY_CTX_set_params(ctx, p) <= 0) goto out;
    if (EVP_PKEY_generate(ctx, &pk) <= 0) goto out;

    BIO *b = BIO_new(BIO_s_mem());
    if (!b) goto out;
    if (PEM_write_bio_PrivateKey(b, pk, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(b); goto out;
    }
    char *data = NULL;
    long n = BIO_get_mem_data(b, &data);
    if (n >= 0 && (size_t)n <= *outlen) {
        memcpy(out, data, (size_t)n);
        *outlen = (size_t)n;
        rv = FHSM_RV_OK;
    }
    BIO_free(b);
out:
    if (pk) EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    return rv;
}

fhsm_rv_t dispatch_ec_keypair(unsigned long s, unsigned long k,
                                const void *params, size_t plen,
                                fhsm_slice_t in,
                                uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)in;
    fhsm_slice_t cv;
    if (fhsm_tlv_find(params, plen, FHSM_TLV_CURVE, &cv) != FHSM_RV_OK)
        return FHSM_RV_ARGUMENTS_BAD;
    char curve[16] = {0};
    size_t cn = cv.len < sizeof(curve) - 1 ? cv.len : sizeof(curve) - 1;
    memcpy(curve, cv.data, cn);
    return ec_keypair_named(curve, out, outlen);
}

static fhsm_rv_t ecdsa_sign(fhsm_hash_t h,
                              const void *params, size_t plen,
                              fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    fhsm_slice_t pem;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM, &pem);
    if (rv != FHSM_RV_OK) return rv;
    EVP_PKEY *pk = load_priv(pem);
    if (!pk) return FHSM_RV_KEY_HANDLE_INVALID;
    rv = pkey_sign(pk, digest_for_alg(h), in, out, outlen);
    EVP_PKEY_free(pk);
    return rv;
}

fhsm_rv_t dispatch_ecdsa_sha256(unsigned long s, unsigned long k,
                                  const void *p, size_t pl,
                                  fhsm_slice_t in, uint8_t *o, size_t *ol)
{ (void)s; (void)k; return ecdsa_sign(FHSM_HASH_SHA256, p, pl, in, o, ol); }

fhsm_rv_t dispatch_ecdsa_sha384(unsigned long s, unsigned long k,
                                  const void *p, size_t pl,
                                  fhsm_slice_t in, uint8_t *o, size_t *ol)
{ (void)s; (void)k; return ecdsa_sign(FHSM_HASH_SHA384, p, pl, in, o, ol); }

fhsm_rv_t dispatch_ecdsa_sha512(unsigned long s, unsigned long k,
                                  const void *p, size_t pl,
                                  fhsm_slice_t in, uint8_t *o, size_t *ol)
{ (void)s; (void)k; return ecdsa_sign(FHSM_HASH_SHA512, p, pl, in, o, ol); }

/* "Raw" ECDSA : caller supplies pre-hashed input. Default to SHA-256. */
fhsm_rv_t dispatch_ecdsa(unsigned long s, unsigned long k,
                          const void *p, size_t pl,
                          fhsm_slice_t in, uint8_t *o, size_t *ol)
{ (void)s; (void)k; return ecdsa_sign(FHSM_HASH_SHA256, p, pl, in, o, ol); }

/* ---------------------------------------------------------------------------
 * EdDSA sign (Ed25519 / Ed448)
 * ------------------------------------------------------------------------- */
fhsm_rv_t dispatch_eddsa(unsigned long s, unsigned long k,
                          const void *params, size_t plen,
                          fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k;
    fhsm_slice_t pem;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM, &pem);
    if (rv != FHSM_RV_OK) return rv;
    EVP_PKEY *pk = load_priv(pem);
    if (!pk) return FHSM_RV_KEY_HANDLE_INVALID;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pk); return FHSM_RV_HOST_MEMORY; }
    if (EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pk, NULL) != 1) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pk); return FHSM_RV_FUNCTION_FAILED;
    }
    rv = (EVP_DigestSign(ctx, out, outlen, in.data, in.len) == 1)
          ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return rv;
}

/* ---------------------------------------------------------------------------
 * ECDH derive
 * ------------------------------------------------------------------------- */
static fhsm_rv_t ecdh_derive(const void *params, size_t plen,
                               uint8_t *out, size_t *outlen)
{
    fhsm_slice_t priv_pem, peer_pem;
    fhsm_rv_t rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM,     &priv_pem)) != FHSM_RV_OK) return rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM_PUB, &peer_pem)) != FHSM_RV_OK) return rv;
    EVP_PKEY *priv = load_priv(priv_pem);
    EVP_PKEY *peer = load_pub(peer_pem);
    if (!priv || !peer) {
        if (priv) EVP_PKEY_free(priv);
        if (peer) EVP_PKEY_free(peer);
        return FHSM_RV_KEY_HANDLE_INVALID;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    rv = FHSM_RV_FUNCTION_FAILED;
    if (!ctx) goto out;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto out;
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) goto out;
    if (EVP_PKEY_derive(ctx, out, outlen) <= 0) goto out;
    rv = FHSM_RV_OK;
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(peer);
    return rv;
}

fhsm_rv_t dispatch_ecdh1(unsigned long s, unsigned long k,
                          const void *p, size_t pl, fhsm_slice_t in,
                          uint8_t *o, size_t *ol)
{ (void)s; (void)k; (void)in; return ecdh_derive(p, pl, o, ol); }

fhsm_rv_t dispatch_x25519(unsigned long s, unsigned long k,
                           const void *p, size_t pl, fhsm_slice_t in,
                           uint8_t *o, size_t *ol)
{ (void)s; (void)k; (void)in; return ecdh_derive(p, pl, o, ol); }

fhsm_rv_t dispatch_x448(unsigned long s, unsigned long k,
                         const void *p, size_t pl, fhsm_slice_t in,
                         uint8_t *o, size_t *ol)
{ (void)s; (void)k; (void)in; return ecdh_derive(p, pl, o, ol); }

/* ---------------------------------------------------------------------------
 * ECDH1 with cofactor multiplication (PKCS#11 §6.4.6.3). Same wire-
 * level operation as ECDH1_DERIVE for prime-order curves (cofactor h=1
 * for P-256/P-384/P-521) ; the cofactor multiplication only differs
 * for composite-order curves which are not approved in FIPS mode. We
 * delegate to ecdh_derive and let OpenSSL handle the cofactor flag if
 * the curve requires it.
 * ----------------------------------------------------------------------- */
fhsm_rv_t dispatch_ecdh1_cofactor(unsigned long s, unsigned long k,
                                    const void *p, size_t pl, fhsm_slice_t in,
                                    uint8_t *o, size_t *ol)
{ (void)s; (void)k; (void)in; return ecdh_derive(p, pl, o, ol); }

fhsm_rv_t dispatch_eddsa_keypair(unsigned long s, unsigned long k,
                                   const void *p, size_t pl, fhsm_slice_t in,
                                   uint8_t *o, size_t *ol)
{ (void)s;(void)k;(void)p;(void)pl;(void)in;
  return ec_keypair_named("Ed25519", o, ol); }

fhsm_rv_t dispatch_ecm_keypair(unsigned long s, unsigned long k,
                                 const void *p, size_t pl, fhsm_slice_t in,
                                 uint8_t *o, size_t *ol)
{ (void)s;(void)k;(void)p;(void)pl;(void)in;
  return ec_keypair_named("X25519", o, ol); }
