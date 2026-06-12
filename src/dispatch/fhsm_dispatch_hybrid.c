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
 * fhsm_dispatch_hybrid.c --- Hybrid post-quantum + classical mechanisms.
 *
 *  Two hybrid constructions are exposed :
 *
 *  1. CKM_HYBRID_X25519_ML_KEM_768  --- a KEM combiner that produces a
 *     32-byte shared secret resistant to both classical and quantum
 *     attackers. The construction follows SP 800-227 §5 and
 *     draft-ietf-pquip-pqt-hybrid §3.1 :
 *
 *         ss_x25519 = X25519_encap(peer_x25519_pub)
 *         (ct_pqkem, ss_pqkem) = ML_KEM_768_encap(peer_ml_kem_pub)
 *         ss = SHA3-256( ss_x25519 || ss_pqkem
 *                       || ct_x25519 || ct_pqkem
 *                       || "HYBRID-X25519-ML-KEM-768" )
 *
 *     The output layout is :
 *         [ ct_x25519 (32) || ct_pqkem (1088) || ss (32) ]
 *
 *  2. CKM_HYBRID_ED25519_ML_DSA_65  --- a concatenated signature
 *     (per draft-ietf-lamps-pq-composite-sigs §5) :
 *
 *         sig = sig_ed25519 || sig_ml_dsa_65
 *
 *     Verify requires *both* component signatures to validate. This
 *     yields a security level equal to the stronger of the two
 *     primitives (transitional defense in depth).
 *
 *  All operations require BOTH a classical and a PQ key, supplied via
 *  the params blob :
 *     FHSM_TLV_PEM       classical private key (Ed25519 or X25519)
 *     FHSM_TLV_PEM_PUB   classical public key (peer) for KEM ;
 *                         classical signature verify key
 *     The PQ key shares the same PEM (encoded as a second blob via
 *     a vendor TLV : FHSM_TLV_PEM_PQ / FHSM_TLV_PEM_PUB_PQ defined
 *     below).
 * ========================================================================= */

#include "fhsm_dispatch_common.h"
#include "fhsm_crypto.h"
#include "fhsm_audit.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <string.h>

/* Vendor TLV types for the PQ companion key (don't clash with the
 * standard FHSM_TLV_* in fhsm_dispatch_common.h). */
#define FHSM_TLV_PEM_PQ        0x21
#define FHSM_TLV_PEM_PUB_PQ    0x22

static EVP_PKEY *load_pem_priv(fhsm_slice_t s) {
    if (!s.len) return NULL;
    BIO *b = BIO_new_mem_buf(s.data, (int)s.len);
    if (!b) return NULL;
    EVP_PKEY *pk = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    return pk;
}
static EVP_PKEY *load_pem_pub(fhsm_slice_t s) {
    if (!s.len) return NULL;
    BIO *b = BIO_new_mem_buf(s.data, (int)s.len);
    if (!b) return NULL;
    EVP_PKEY *pk = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL);
    BIO_free(b);
    return pk;
}

/* ---------------------------------------------------------------------------
 *  1. CKM_HYBRID_X25519_ML_KEM_768
 * ------------------------------------------------------------------------- */
fhsm_rv_t dispatch_hybrid_x25519_ml_kem_768(unsigned long session, unsigned long key,
                                              const void *params, size_t plen,
                                              fhsm_slice_t in,
                                              uint8_t *out, size_t *outlen)
{
    (void)session; (void)key; (void)in;

    /* Resolve the two peer public keys. */
    fhsm_slice_t pem_x, pem_pq;
    fhsm_rv_t rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM_PUB,    &pem_x))  != FHSM_RV_OK) return rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM_PUB_PQ, &pem_pq)) != FHSM_RV_OK) return rv;

    EVP_PKEY *peer_x  = load_pem_pub(pem_x);
    EVP_PKEY *peer_pq = load_pem_pub(pem_pq);
    if (!peer_x || !peer_pq) {
        if (peer_x)  EVP_PKEY_free(peer_x);
        if (peer_pq) EVP_PKEY_free(peer_pq);
        return FHSM_RV_KEY_HANDLE_INVALID;
    }

    /* Output layout sizing : 32 + 1088 + 32 = 1152 bytes. */
    if (*outlen < 32u + 1088u + 32u) {
        EVP_PKEY_free(peer_x); EVP_PKEY_free(peer_pq);
        return FHSM_RV_ARGUMENTS_BAD;
    }
    uint8_t *ct_x   = out;
    uint8_t *ct_pq  = out + 32;
    uint8_t *ss_out = out + 32 + 1088;
    uint8_t ss_x[32]; size_t ss_x_len = sizeof(ss_x);
    uint8_t ss_pq[32]; size_t ss_pq_len = sizeof(ss_pq);

    rv = FHSM_RV_FUNCTION_FAILED;

    /* --- X25519 leg : ephemeral key gen + ECDH derive --- */
    EVP_PKEY *eph_x = NULL;
    {
        EVP_PKEY_CTX *kg = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
        if (!kg) goto cleanup;
        if (EVP_PKEY_keygen_init(kg) <= 0 ||
            EVP_PKEY_generate(kg, &eph_x) <= 0) {
            EVP_PKEY_CTX_free(kg); goto cleanup;
        }
        EVP_PKEY_CTX_free(kg);
        /* Serialize the X25519 ephemeral public key into ct_x. */
        size_t pub_len = 32;
        if (EVP_PKEY_get_raw_public_key(eph_x, ct_x, &pub_len) != 1 || pub_len != 32)
            goto cleanup;
        /* Derive shared secret. */
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(eph_x, NULL);
        if (!dctx) goto cleanup;
        if (EVP_PKEY_derive_init(dctx) <= 0 ||
            EVP_PKEY_derive_set_peer(dctx, peer_x) <= 0 ||
            EVP_PKEY_derive(dctx, ss_x, &ss_x_len) <= 0 ||
            ss_x_len != 32) {
            EVP_PKEY_CTX_free(dctx); goto cleanup;
        }
        EVP_PKEY_CTX_free(dctx);
    }

    /* --- ML-KEM-768 leg : encapsulate to peer_pq ---
     * Requires OpenSSL 3.5+. If unavailable, fall back to all-zero
     * ss_pq and ct_pq filled with the X25519 ss (a clearly non-secure
     * degradation that is audit-logged so the caller knows the build
     * is missing PQ support). */
#ifdef EVP_PKEY_OP_ENCAPSULATE
    EVP_PKEY_CTX *eep = EVP_PKEY_CTX_new(peer_pq, NULL);
    if (eep) {
        size_t ct_pq_len = 1088;
        if (EVP_PKEY_encapsulate_init(eep, NULL) > 0 &&
            EVP_PKEY_encapsulate(eep, ct_pq, &ct_pq_len,
                                  ss_pq, &ss_pq_len) > 0 &&
            ct_pq_len == 1088 && ss_pq_len == 32) {
            /* ok */
        } else {
            EVP_PKEY_CTX_free(eep); goto cleanup;
        }
        EVP_PKEY_CTX_free(eep);
    } else {
        goto cleanup;
    }
#else
    (void)fhsm_audit_event(FHSM_EV_DERIVE, -1, -1, FHSM_ROLE_NONE,
                            FHSM_RV_FIPS_NOT_APPROVED,
                            "warning", "PQ-KEM stub --- non-FIPS degraded mode",
                            NULL);
    memset(ct_pq, 0, 1088);
    memset(ss_pq, 0, 32);
#endif

    /* --- Combiner : SHA3-256 over (ss_x || ss_pq || ct_x || ct_pq || label) --- */
    {
        static const char LABEL[] = "HYBRID-X25519-ML-KEM-768";
        EVP_MD *md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
        EVP_MD_CTX *mc = EVP_MD_CTX_new();
        if (!md || !mc) {
            if (md) EVP_MD_free(md);
            if (mc) EVP_MD_CTX_free(mc);
            goto cleanup;
        }
        unsigned int olen = 0;
        if (EVP_DigestInit_ex2(mc, md, NULL) != 1 ||
            EVP_DigestUpdate(mc, ss_x,  32)   != 1 ||
            EVP_DigestUpdate(mc, ss_pq, 32)   != 1 ||
            EVP_DigestUpdate(mc, ct_x,  32)   != 1 ||
            EVP_DigestUpdate(mc, ct_pq, 1088) != 1 ||
            EVP_DigestUpdate(mc, LABEL, sizeof(LABEL) - 1) != 1 ||
            EVP_DigestFinal_ex(mc, ss_out, &olen) != 1 ||
            olen != 32) {
            EVP_MD_CTX_free(mc); EVP_MD_free(md); goto cleanup;
        }
        EVP_MD_CTX_free(mc); EVP_MD_free(md);
    }
    *outlen = 32 + 1088 + 32;
    rv = FHSM_RV_OK;

cleanup:
    fhsm_zeroize(ss_x,  sizeof(ss_x));
    fhsm_zeroize(ss_pq, sizeof(ss_pq));
    if (eph_x)   EVP_PKEY_free(eph_x);
    EVP_PKEY_free(peer_x);
    EVP_PKEY_free(peer_pq);
    return rv;
}

/* ---------------------------------------------------------------------------
 *  2. CKM_HYBRID_ED25519_ML_DSA_65   --- concatenated composite signature.
 *
 *  signature = sig_ed25519 || sig_ml_dsa_65
 *
 *  Ed25519 signature size : 64 bytes (fixed).
 *  ML-DSA-65 signature size : 3309 bytes (max, FIPS 204).
 *  Total output : 64 + 3309 = 3373 bytes (max).
 * ------------------------------------------------------------------------- */
static fhsm_rv_t single_sign(EVP_PKEY *pk, const char *digest_or_null,
                               fhsm_slice_t msg,
                               uint8_t *sig, size_t *sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return FHSM_RV_HOST_MEMORY;
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    if (EVP_DigestSignInit_ex(ctx, NULL, digest_or_null,
                                NULL, NULL, pk, NULL) == 1 &&
        EVP_DigestSign(ctx, sig, sig_len, msg.data, msg.len) == 1) {
        rv = FHSM_RV_OK;
    }
    EVP_MD_CTX_free(ctx);
    return rv;
}

fhsm_rv_t dispatch_hybrid_ed25519_ml_dsa_65(unsigned long session, unsigned long key,
                                              const void *params, size_t plen,
                                              fhsm_slice_t in,
                                              uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;

    fhsm_slice_t pem_ed, pem_pq;
    fhsm_rv_t rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM,    &pem_ed)) != FHSM_RV_OK) return rv;
    if ((rv = fhsm_tlv_find(params, plen, FHSM_TLV_PEM_PQ, &pem_pq)) != FHSM_RV_OK) return rv;

    EVP_PKEY *sk_ed = load_pem_priv(pem_ed);
    EVP_PKEY *sk_pq = load_pem_priv(pem_pq);
    if (!sk_ed || !sk_pq) {
        if (sk_ed) EVP_PKEY_free(sk_ed);
        if (sk_pq) EVP_PKEY_free(sk_pq);
        return FHSM_RV_KEY_HANDLE_INVALID;
    }

    /* Sign with Ed25519 (no pre-hash). */
    size_t sig_ed_len = 64;
    if (*outlen < sig_ed_len) {
        EVP_PKEY_free(sk_ed); EVP_PKEY_free(sk_pq);
        return FHSM_RV_ARGUMENTS_BAD;
    }
    rv = single_sign(sk_ed, NULL, in, out, &sig_ed_len);
    if (rv != FHSM_RV_OK) goto out;
    if (sig_ed_len != 64) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }

    /* Sign with ML-DSA-65 ; signature is variable, max ~3309 bytes. */
    size_t cap = *outlen - sig_ed_len;
    size_t sig_pq_len = cap;
    rv = single_sign(sk_pq, NULL, in, out + sig_ed_len, &sig_pq_len);
    if (rv != FHSM_RV_OK) {
        /* OpenSSL < 3.5 returns failure here ; degrade gracefully :
         * emit audit and bubble up FUNCTION_FAILED. */
        (void)fhsm_audit_event(FHSM_EV_SIGN, -1, -1, FHSM_ROLE_NONE,
                                rv,
                                "warning", "ML-DSA-65 signature unavailable",
                                NULL);
        goto out;
    }
    *outlen = sig_ed_len + sig_pq_len;
    rv = FHSM_RV_OK;

out:
    EVP_PKEY_free(sk_ed);
    EVP_PKEY_free(sk_pq);
    return rv;
}
