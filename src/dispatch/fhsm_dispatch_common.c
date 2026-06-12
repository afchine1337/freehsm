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
 * fhsm_dispatch_common.c --- TLV parameter parser shared by all handlers.
 * ========================================================================= */

#include "fhsm_dispatch_common.h"

#include <string.h>

fhsm_rv_t fhsm_tlv_find(const void *params, size_t plen,
                         uint8_t type, fhsm_slice_t *out)
{
    if (out == NULL) return FHSM_RV_ARGUMENTS_BAD;
    out->data = NULL;
    out->len  = 0;
    if (params == NULL || plen == 0) return FHSM_RV_ARGUMENTS_BAD;

    const uint8_t *p = (const uint8_t *)params;
    size_t off = 0;
    while (off + 5 <= plen) {
        uint8_t  t = p[off];
        uint32_t l = ((uint32_t)p[off + 1] << 24) |
                     ((uint32_t)p[off + 2] << 16) |
                     ((uint32_t)p[off + 3] << 8)  |
                      (uint32_t)p[off + 4];
        off += 5;
        if (l > plen - off) return FHSM_RV_ARGUMENTS_BAD;  /* malformed */
        if (t == type) {
            out->data = p + off;
            out->len  = (size_t)l;
            return FHSM_RV_OK;
        }
        off += l;
    }
    return FHSM_RV_ARGUMENTS_BAD;
}

void fhsm_tlv_find_optional(const void *params, size_t plen,
                              uint8_t type, fhsm_slice_t *out)
{
    if (out == NULL) return;
    fhsm_slice_t s;
    if (fhsm_tlv_find(params, plen, type, &s) == FHSM_RV_OK) {
        *out = s;
    } else {
        out->data = NULL;
        out->len  = 0;
    }
}
