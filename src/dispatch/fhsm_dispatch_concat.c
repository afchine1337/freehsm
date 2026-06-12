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
 * fhsm_dispatch_concat.c --- Concatenation-based KDFs (PKCS#11 v3.2 §6.20).
 *
 *  These mechanisms derive a new symmetric key from a "base key" and a
 *  "data" argument (or another key) using bytewise concatenation or
 *  XOR. They are commonly used in TLS-like compositions and in
 *  hybrid-KEM defense-in-depth, where the post-quantum and classical
 *  shared secrets are joined before being fed to a stronger KDF.
 *
 *  The base key bytes are passed via FHSM_TLV_KEY ; the data via
 *  fhsm_slice_t `in`. The output is written verbatim to *out, with
 *  *outlen set to the new key length.
 *
 *  Mechanism semantics (per PKCS#11 v3.2) :
 *
 *      CKM_CONCATENATE_BASE_AND_KEY    new = base || other_key
 *      CKM_CONCATENATE_BASE_AND_DATA   new = base || data
 *      CKM_CONCATENATE_DATA_AND_BASE   new = data || base
 *      CKM_XOR_BASE_AND_DATA           new = base XOR data
 *
 *  None of these mechanisms are an approved KDF in the strict NIST
 *  SP 800-56C sense ; they are listed as approved here because they
 *  are PKCS#11 v3.2 standard mechanisms and are used as the
 *  *combiner* step inside an SP 800-56C-compliant hybrid construction
 *  (see fhsm_dispatch_hybrid.c).
 * ========================================================================= */

#include "fhsm_dispatch_common.h"
#include "fhsm_crypto.h"

#include <string.h>

/* CKM_CONCATENATE_BASE_AND_KEY : new = base || other_key.
 * The "other key" is also passed as FHSM_TLV_KEY ... but we already
 * use that for the base. The convention is :
 *    base       <- FHSM_TLV_KEY
 *    other key  <- fhsm_slice_t in  (caller materialised it)
 * The dispatcher in fhsm_pkcs11.c is responsible for materialising
 * the second key handle into `in` before invocation. */
fhsm_rv_t dispatch_concat_base_and_key(unsigned long session, unsigned long key,
                                         const void *params, size_t plen,
                                         fhsm_slice_t in,
                                         uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    fhsm_slice_t base;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &base);
    if (rv != FHSM_RV_OK) return rv;
    if (out == NULL || outlen == NULL) return FHSM_RV_ARGUMENTS_BAD;
    size_t need = base.len + in.len;
    if (*outlen < need) return FHSM_RV_ARGUMENTS_BAD;
    memcpy(out,             base.data, base.len);
    memcpy(out + base.len,  in.data,   in.len);
    *outlen = need;
    return FHSM_RV_OK;
}

fhsm_rv_t dispatch_concat_base_and_data(unsigned long session, unsigned long key,
                                          const void *params, size_t plen,
                                          fhsm_slice_t in,
                                          uint8_t *out, size_t *outlen)
{
    /* Identical layout to base+key from the runtime perspective ; the
     * difference is purely an object-class concern (PKCS#11 marks the
     * result as CKO_DATA for base_and_data, CKO_SECRET_KEY for
     * base_and_key). */
    return dispatch_concat_base_and_key(session, key, params, plen, in, out, outlen);
}

fhsm_rv_t dispatch_concat_data_and_base(unsigned long session, unsigned long key,
                                          const void *params, size_t plen,
                                          fhsm_slice_t in,
                                          uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    fhsm_slice_t base;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &base);
    if (rv != FHSM_RV_OK) return rv;
    if (out == NULL || outlen == NULL) return FHSM_RV_ARGUMENTS_BAD;
    size_t need = in.len + base.len;
    if (*outlen < need) return FHSM_RV_ARGUMENTS_BAD;
    memcpy(out,           in.data,   in.len);
    memcpy(out + in.len,  base.data, base.len);
    *outlen = need;
    return FHSM_RV_OK;
}

fhsm_rv_t dispatch_xor_base_and_data(unsigned long session, unsigned long key,
                                       const void *params, size_t plen,
                                       fhsm_slice_t in,
                                       uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;
    fhsm_slice_t base;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_KEY, &base);
    if (rv != FHSM_RV_OK) return rv;
    if (out == NULL || outlen == NULL) return FHSM_RV_ARGUMENTS_BAD;
    /* PKCS#11 §6.20.4: data length determines output length; if
     * base is shorter, the trailing bytes of data are copied verbatim. */
    size_t n = in.len;
    if (*outlen < n) return FHSM_RV_ARGUMENTS_BAD;
    for (size_t i = 0; i < n; ++i) {
        uint8_t b = (i < base.len) ? base.data[i] : 0;
        out[i] = b ^ in.data[i];
    }
    *outlen = n;
    return FHSM_RV_OK;
}
