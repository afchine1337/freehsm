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
 * fhsm_dispatch_pq.c --- Post-quantum handlers (ML-KEM, ML-DSA, SLH-DSA).
 *
 *  These mechanisms require either :
 *    - OpenSSL >= 3.5 with the FIPS provider that implements
 *      FIPS 203 / 204 / 205 directly (preferred), OR
 *    - liboqs + a small adapter layer (fallback).
 *
 *  Until the build pipeline pins one of those, the handlers below
 *  perform parameter validation and then return FHSM_RV_FUNCTION_FAILED
 *  with an audit-log entry that flags "PQ provider unavailable". The
 *  signature is finalized so that the integration is a drop-in patch.
 *
 *  Parameter set selection :
 *     ML-KEM-512 / 768 / 1024     (via FHSM_TLV_PARAM_SET ASCII)
 *     ML-DSA-44 / 65 / 87
 *     SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}
 *
 *  Once the provider is wired, each handler becomes:
 *     EVP_PKEY_CTX_new_from_name(NULL, "<param-set>", NULL);
 *     EVP_PKEY_keygen_init / generate
 *     EVP_PKEY_encapsulate / decapsulate / sign / verify
 *  exactly as in fhsm_dispatch_pkey.c.
 * ========================================================================= */

#include "fhsm_dispatch_common.h"
#include "fhsm_crypto.h"
#include "fhsm_audit.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <string.h>

/* Probe the FIPS provider for a named PQ algorithm. Returns 1 if
 * EVP_PKEY_CTX_new_from_name succeeds, 0 otherwise. The probe is
 * cached per call site --- not strictly necessary, since OpenSSL
 * caches algorithm lookups internally, but it keeps the audit trail
 * compact. */
static int pq_alg_available(const char *name) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (!ctx) return 0;
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

static fhsm_rv_t pq_unavailable(fhsm_audit_event_t ev, const char *family)
{
    char fam[16];
    size_t n = strlen(family);
    if (n >= sizeof(fam)) n = sizeof(fam) - 1;
    memcpy(fam, family, n);
    fam[n] = '\0';
    (void)fhsm_audit_event(ev, -1, -1, FHSM_ROLE_NONE,
                            FHSM_RV_FUNCTION_FAILED,
                            "family", fam,
                            "reason", "PQ provider unavailable",
                            NULL);
    return FHSM_RV_FUNCTION_FAILED;
}

/* Generate a PQ keypair using EVP_PKEY interface. Returns the private
 * key as PEM bytes in *out. The provider implements the corresponding
 * algorithm and parameter set as a named EVP_PKEY type. */
static fhsm_rv_t pq_keypair_named(const char *name,
                                    uint8_t *out, size_t *outlen)
{
    if (!pq_alg_available(name)) return FHSM_RV_FUNCTION_FAILED;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (!ctx) return FHSM_RV_HOST_MEMORY;
    EVP_PKEY *pk = NULL;
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto out;
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

/* Resolve a parameter set slice to its FIPS provider name. */
static int param_set_to_name(const fhsm_slice_t *ps, char *out, size_t cap) {
    if (!ps || ps->len == 0 || ps->len >= cap) return 0;
    memcpy(out, ps->data, ps->len);
    out[ps->len] = '\0';
    return 1;
}

static int param_set_valid(const fhsm_slice_t *ps,
                            const char * const *allowed, size_t n)
{
    if (!ps || ps->len == 0) return 0;
    for (size_t i = 0; i < n; ++i) {
        size_t al = strlen(allowed[i]);
        if (ps->len == al && memcmp(ps->data, allowed[i], al) == 0) return 1;
    }
    return 0;
}

/* ---- ML-KEM ---------------------------------------------------------- */
static const char *const ML_KEM_SETS[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

fhsm_rv_t dispatch_ml_kem_keypair(unsigned long s, unsigned long k,
                                    const void *params, size_t plen,
                                    fhsm_slice_t in,
                                    uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)in;
    fhsm_slice_t ps;
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_PARAM_SET, &ps);
    if (ps.len == 0) return FHSM_RV_ARGUMENTS_BAD;
    if (!param_set_valid(&ps, ML_KEM_SETS, 3)) return FHSM_RV_MECHANISM_INVALID;
    char name[32];
    if (!param_set_to_name(&ps, name, sizeof(name))) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_rv_t rv = pq_keypair_named(name, out, outlen);
    if (rv != FHSM_RV_OK) return pq_unavailable(FHSM_EV_GENERATE_KEYPAIR, "ML-KEM");
    return rv;
}

/* Load a PEM-encoded PQ public/private key from a TLV record. */
static EVP_PKEY *pq_load_pub(const void *params, size_t plen) {
    fhsm_slice_t pem;
    if (fhsm_tlv_find(params, plen, FHSM_TLV_PEM_PUB, &pem) != FHSM_RV_OK) return NULL;
    BIO *b = BIO_new_mem_buf(pem.data, (int)pem.len);
    if (!b) return NULL;
    EVP_PKEY *pk = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL);
    BIO_free(b);
    return pk;
}
static EVP_PKEY *pq_load_priv(const void *params, size_t plen) {
    fhsm_slice_t pem;
    if (fhsm_tlv_find(params, plen, FHSM_TLV_PEM, &pem) != FHSM_RV_OK) return NULL;
    BIO *b = BIO_new_mem_buf(pem.data, (int)pem.len);
    if (!b) return NULL;
    EVP_PKEY *pk = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    return pk;
}

/* ML-KEM encapsulation. The PEM-encoded public key carries the
 * parameter set via the EVP_PKEY's algorithm OID, so no FHSM_TLV_PARAM_SET
 * is needed at this layer.
 *
 * Output buffer layout: [ciphertext(N) || shared_secret(32)] concatenated,
 * with the dispatcher writing the boundary as the caller-supplied
 * *outlen on entry / actual lengths on exit. */
fhsm_rv_t dispatch_ml_kem_encap(unsigned long s, unsigned long k,
                                  const void *params, size_t plen,
                                  fhsm_slice_t in,
                                  uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)in;
    EVP_PKEY *pk = pq_load_pub(params, plen);
    if (!pk) return pq_unavailable(FHSM_EV_DERIVE, "ML-KEM");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    if (!ctx) { EVP_PKEY_free(pk); return FHSM_RV_HOST_MEMORY; }

    /* OpenSSL 3.5+ exposes EVP_PKEY_encapsulate / decapsulate for the
     * KEM family. If unavailable at compile time, the call returns
     * an error and we degrade gracefully. */
#ifdef EVP_PKEY_OP_ENCAPSULATE
    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) goto out;
    size_t ct_len = *outlen, ss_len = 32;
    if (EVP_PKEY_encapsulate(ctx, out, &ct_len,
                               out + ct_len, &ss_len) <= 0) goto out;
    *outlen = ct_len + ss_len;
    rv = FHSM_RV_OK;
#else
    rv = pq_unavailable(FHSM_EV_DERIVE, "ML-KEM");
#endif

out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return rv;
}

/* ---- ML-DSA ---------------------------------------------------------- */
static const char *const ML_DSA_SETS[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };

fhsm_rv_t dispatch_ml_dsa_keypair(unsigned long s, unsigned long k,
                                    const void *params, size_t plen,
                                    fhsm_slice_t in,
                                    uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)in;
    fhsm_slice_t ps;
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_PARAM_SET, &ps);
    if (ps.len == 0) return FHSM_RV_ARGUMENTS_BAD;
    if (!param_set_valid(&ps, ML_DSA_SETS, 3)) return FHSM_RV_MECHANISM_INVALID;
    char name[32];
    if (!param_set_to_name(&ps, name, sizeof(name))) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_rv_t rv = pq_keypair_named(name, out, outlen);
    if (rv != FHSM_RV_OK) return pq_unavailable(FHSM_EV_GENERATE_KEYPAIR, "ML-DSA");
    return rv;
}

/* Generic PQ sign : load the private key, dispatch to EVP_DigestSign
 * with the requested message digest (NULL = raw / pre-hashed input). */
static fhsm_rv_t pq_sign(const void *params, size_t plen,
                           const char *digest,
                           fhsm_slice_t in, uint8_t *out, size_t *outlen,
                           const char *family)
{
    EVP_PKEY *pk = pq_load_priv(params, plen);
    if (!pk) return pq_unavailable(FHSM_EV_SIGN, family);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    if (!ctx) { EVP_PKEY_free(pk); return FHSM_RV_HOST_MEMORY; }
    if (EVP_DigestSignInit_ex(ctx, NULL, digest, NULL, NULL, pk, NULL) != 1) {
        rv = pq_unavailable(FHSM_EV_SIGN, family);
        goto out;
    }
    if (EVP_DigestSign(ctx, out, outlen, in.data, in.len) != 1) goto out;
    rv = FHSM_RV_OK;
out:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return rv;
}

fhsm_rv_t dispatch_ml_dsa(unsigned long s, unsigned long k,
                           const void *p, size_t pl, fhsm_slice_t in,
                           uint8_t *o, size_t *ol)
{ (void)s; (void)k; return pq_sign(p, pl, NULL,       in, o, ol, "ML-DSA"); }


/* ---- SLH-DSA --------------------------------------------------------- */
static const char *const SLH_SETS[] = {
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s","SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s","SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s","SLH-DSA-SHAKE-256f",
};

fhsm_rv_t dispatch_slh_dsa_keypair(unsigned long s, unsigned long k,
                                     const void *params, size_t plen,
                                     fhsm_slice_t in,
                                     uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)in;
    fhsm_slice_t ps;
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_PARAM_SET, &ps);
    if (ps.len == 0) return FHSM_RV_ARGUMENTS_BAD;
    if (!param_set_valid(&ps, SLH_SETS,
                          sizeof(SLH_SETS)/sizeof(SLH_SETS[0])))
        return FHSM_RV_MECHANISM_INVALID;
    char name[32];
    if (!param_set_to_name(&ps, name, sizeof(name))) return FHSM_RV_ARGUMENTS_BAD;
    fhsm_rv_t rv = pq_keypair_named(name, out, outlen);
    if (rv != FHSM_RV_OK) return pq_unavailable(FHSM_EV_GENERATE_KEYPAIR, "SLH-DSA");
    return rv;
}

fhsm_rv_t dispatch_slh_dsa(unsigned long s, unsigned long k,
                            const void *p, size_t pl, fhsm_slice_t in,
                            uint8_t *o, size_t *ol)
{ (void)s; (void)k; return pq_sign(p, pl, NULL, in, o, ol, "SLH-DSA"); }
