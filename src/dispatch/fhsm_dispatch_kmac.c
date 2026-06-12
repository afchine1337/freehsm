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
 * fhsm_dispatch_kmac.c --- KMAC128 / KMAC256 handlers (SP 800-185 §4).
 *
 *  KMAC is a SHAKE-based keyed message authentication code with a
 *  customization string. The PKCS#11 v3.2 §6.22 mechanism passes the
 *  customization string and requested MAC length via the params blob ;
 *  the key is FHSM_TLV_KEY, the optional customization is
 *  FHSM_TLV_INFO, and the requested output length is *outlen on entry.
 *
 *  EVP_MAC("KMAC-128" / "KMAC-256") supports streaming naturally :
 *  the same code path serves the one-shot dispatch and the multi-part
 *  C_SignUpdate / C_VerifyUpdate flows. Multi-part is wired in
 *  src/fhsm_session.c via an active-op object that retains the
 *  EVP_MAC_CTX between Update calls.
 *
 *  Approved variants : KMAC128 (security strength 128 bits) and
 *  KMAC256 (256 bits). Both per SP 800-185 §4 and SP 800-131A rev. 2.
 * ========================================================================= */

#include "fhsm_dispatch_common.h"
#include "fhsm_crypto.h"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <string.h>

static fhsm_rv_t kmac_oneshot(const char *name,
                                const void *params, size_t plen,
                                fhsm_slice_t in,
                                uint8_t *out, size_t *outlen)
{
    fhsm_slice_t k, custom;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &k);
    if (rv != FHSM_RV_OK) return rv;
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_INFO, &custom);
    if (out == NULL || outlen == NULL || *outlen == 0) return FHSM_RV_ARGUMENTS_BAD;
    /* SP 800-185 mandates keylen >= 112 bits for KMAC128, >= 128 for KMAC256. */
    size_t min_key = (strcmp(name, "KMAC-128") == 0) ? 14 : 16;
    if (k.len < min_key) return FHSM_RV_KEY_SIZE_RANGE;

    EVP_MAC *mac = EVP_MAC_fetch(NULL, name, NULL);
    if (!mac) return FHSM_RV_MECHANISM_INVALID;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) { EVP_MAC_free(mac); return FHSM_RV_HOST_MEMORY; }

    /* Two OSSL_PARAM slots : customization string + requested output
     * size. The KMAC EVP_MAC accepts "custom" as octet string and
     * "size" as size_t. */
    OSSL_PARAM p[3];
    int pi = 0;
    size_t requested = *outlen;
    if (custom.len) {
        p[pi++] = OSSL_PARAM_construct_octet_string("custom",
                        (void*)custom.data, custom.len);
    }
    p[pi++] = OSSL_PARAM_construct_size_t("size", &requested);
    p[pi]   = OSSL_PARAM_construct_end();

    rv = FHSM_RV_FUNCTION_FAILED;
    size_t mac_out = 0;
    if (EVP_MAC_init(ctx, k.data, k.len, p) == 1 &&
        EVP_MAC_update(ctx, in.data, in.len) == 1 &&
        EVP_MAC_final(ctx, out, &mac_out, *outlen) == 1) {
        *outlen = mac_out;
        rv = FHSM_RV_OK;
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return rv;
}

fhsm_rv_t dispatch_kmac128(unsigned long s, unsigned long k,
                            const void *p, size_t pl, fhsm_slice_t in,
                            uint8_t *o, size_t *ol)
{ (void)s; (void)k; return kmac_oneshot("KMAC-128", p, pl, in, o, ol); }

fhsm_rv_t dispatch_kmac256(unsigned long s, unsigned long k,
                            const void *p, size_t pl, fhsm_slice_t in,
                            uint8_t *o, size_t *ol)
{ (void)s; (void)k; return kmac_oneshot("KMAC-256", p, pl, in, o, ol); }
