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
 * fhsm_dispatch_digest.c --- Hash handlers (SHA-2, SHA-3, SHAKE).
 *
 * Approved family in §4 of the Security Policy.
 *
 * All handlers are thin wrappers over fhsm_hash_oneshot() from
 * fhsm_crypto.c, which in turn calls the OpenSSL FIPS provider via
 * EVP_DigestInit/Update/Final.
 *
 * Convention for SHAKE128/256 :
 *   The caller MUST encode the requested output length in *outlen on
 *   entry. The handler honors it as long as it does not exceed the
 *   buffer size, which is the standard PKCS#11 v3.2 §6.7.5 contract.
 *
 * No key, no params : the params buffer is ignored.
 * ========================================================================= */

#include "fhsm_dispatch_common.h"
#include "fhsm_crypto.h"

#include <openssl/evp.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Generic EVP digest one-shot for digests not exposed by fhsm_hash_oneshot.
 * Loads the named algorithm from the FIPS provider (default in approved
 * mode) and computes the digest in a single pass.
 * ----------------------------------------------------------------------- */
static fhsm_rv_t evp_md_oneshot(const char *name,
                                  fhsm_slice_t in,
                                  uint8_t *out, size_t *outlen)
{
    EVP_MD *md = EVP_MD_fetch(NULL, name, NULL);
    if (!md) return FHSM_RV_MECHANISM_INVALID;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_MD_free(md); return FHSM_RV_HOST_MEMORY; }

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    unsigned int n = 0;
    if (EVP_DigestInit_ex2(ctx, md, NULL) == 1 &&
        EVP_DigestUpdate(ctx, in.data, in.len) == 1 &&
        EVP_DigestFinal_ex(ctx, out, &n) == 1) {
        *outlen = n;
        rv = FHSM_RV_OK;
    }
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return rv;
}

/* SHAKE oneshot --- the XOF variant : uses EVP_DigestFinalXOF to emit a
 * caller-defined number of output bytes. */
static fhsm_rv_t evp_shake_oneshot(const char *name,
                                     fhsm_slice_t in,
                                     uint8_t *out, size_t outlen)
{
    EVP_MD *md = EVP_MD_fetch(NULL, name, NULL);
    if (!md) return FHSM_RV_MECHANISM_INVALID;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_MD_free(md); return FHSM_RV_HOST_MEMORY; }

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    if (EVP_DigestInit_ex2(ctx, md, NULL) == 1 &&
        EVP_DigestUpdate(ctx, in.data, in.len) == 1 &&
        EVP_DigestFinalXOF(ctx, out, outlen) == 1) {
        rv = FHSM_RV_OK;
    }
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return rv;
}

#define HASH_HANDLER(name, alg)                                               \
    fhsm_rv_t name(unsigned long session, unsigned long key,                  \
                    const void *params, size_t plen,                          \
                    fhsm_slice_t in, uint8_t *out, size_t *outlen)            \
    {                                                                         \
        (void)session; (void)key; (void)params; (void)plen;                   \
        if (out == NULL || outlen == NULL) return FHSM_RV_ARGUMENTS_BAD;      \
        size_t cap = *outlen;                                                 \
        size_t need = fhsm_hash_size(alg);                                    \
        if (cap < need) return FHSM_RV_ARGUMENTS_BAD;                         \
        *outlen = need;                                                       \
        return fhsm_hash_oneshot(alg, in, out, outlen);                       \
    }

HASH_HANDLER(dispatch_sha256,   FHSM_HASH_SHA256)
HASH_HANDLER(dispatch_sha384,   FHSM_HASH_SHA384)
HASH_HANDLER(dispatch_sha512,   FHSM_HASH_SHA512)
HASH_HANDLER(dispatch_sha3_256, FHSM_HASH_SHA3_256)
HASH_HANDLER(dispatch_sha3_384, FHSM_HASH_SHA3_384)
HASH_HANDLER(dispatch_sha3_512, FHSM_HASH_SHA3_512)

/* SHA-224 / SHA-512/224 / SHA-512/256 --- now real EVP fetches. The
 * names "SHA2-224", "SHA2-512/224", "SHA2-512/256" match the OpenSSL
 * FIPS provider's algorithm registry (FIPS 180-4). */
fhsm_rv_t dispatch_sha224(unsigned long s, unsigned long k,
                           const void *params, size_t plen,
                           fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)params; (void)plen;
    if (out == NULL || outlen == NULL || *outlen < 28) return FHSM_RV_ARGUMENTS_BAD;
    return evp_md_oneshot("SHA2-224", in, out, outlen);
}

fhsm_rv_t dispatch_sha512_224(unsigned long s, unsigned long k,
                               const void *params, size_t plen,
                               fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)params; (void)plen;
    if (out == NULL || outlen == NULL || *outlen < 28) return FHSM_RV_ARGUMENTS_BAD;
    return evp_md_oneshot("SHA2-512/224", in, out, outlen);
}

fhsm_rv_t dispatch_sha512_256(unsigned long s, unsigned long k,
                               const void *params, size_t plen,
                               fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)params; (void)plen;
    if (out == NULL || outlen == NULL || *outlen < 32) return FHSM_RV_ARGUMENTS_BAD;
    return evp_md_oneshot("SHA2-512/256", in, out, outlen);
}

/* ---------------------------------------------------------------------------
 * Non-FIPS legacy digests (general-purpose / interop profile only).
 * SHA-1 (disallowed as a standalone digest under fips-strict) and MD5
 * (never FIPS-approved). Both live in the OpenSSL default provider. In
 * the fips-strict build these mechanisms are rewritten to
 * dispatch_reject_fips by the generator ; these handlers are only
 * reachable in the interop (general-purpose) profile. #125.
 * ------------------------------------------------------------------------- */
fhsm_rv_t dispatch_sha1(unsigned long s, unsigned long k,
                         const void *params, size_t plen,
                         fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)params; (void)plen;
    if (out == NULL || outlen == NULL || *outlen < 20) return FHSM_RV_ARGUMENTS_BAD;
    return evp_md_oneshot("SHA1", in, out, outlen);
}

fhsm_rv_t dispatch_md5(unsigned long s, unsigned long k,
                        const void *params, size_t plen,
                        fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)params; (void)plen;
    if (out == NULL || outlen == NULL || *outlen < 16) return FHSM_RV_ARGUMENTS_BAD;
    return evp_md_oneshot("MD5", in, out, outlen);
}

/* SHAKE128 / SHAKE256 --- variable-length XOF. The caller MUST set
 * *outlen on entry to the requested output length in octets. PKCS#11
 * v3.2 §6.7.5 leaves the length to the caller; we honor it verbatim. */
fhsm_rv_t dispatch_shake128(unsigned long s, unsigned long k,
                             const void *params, size_t plen,
                             fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)params; (void)plen;
    if (out == NULL || outlen == NULL || *outlen == 0) return FHSM_RV_ARGUMENTS_BAD;
    return evp_shake_oneshot("SHAKE-128", in, out, *outlen);
}

fhsm_rv_t dispatch_shake256(unsigned long s, unsigned long k,
                             const void *params, size_t plen,
                             fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)s; (void)k; (void)params; (void)plen;
    if (out == NULL || outlen == NULL || *outlen == 0) return FHSM_RV_ARGUMENTS_BAD;
    return evp_shake_oneshot("SHAKE-256", in, out, *outlen);
}
