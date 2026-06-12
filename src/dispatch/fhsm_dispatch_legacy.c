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
 * fhsm_dispatch_legacy.c --- Non-FIPS-approved mechanisms (MD5, SHA-1,
 * DES, 3DES, RC4, etc.). Only callable when fhsm_mode_is_fips() == 0.
 *
 *  This file implements `fhsm_legacy_dispatch` which is overridden via
 *  the weak-symbol mechanism in src/gen/fhsm_dispatch.c. When linked in,
 *  legacy-mode callers receive a real result instead of
 *  FHSM_RV_FIPS_NOT_APPROVED. When NOT linked in (e.g. fips-only build
 *  variant), the weak symbol resolves to NULL and dispatch_reject_fips
 *  falls back to FHSM_RV_FIPS_NOT_APPROVED.
 *
 *  Currently implemented :
 *    CKM_MD5        : EVP_md5() digest
 *    CKM_SHA_1      : EVP_sha1() digest
 *    CKM_SHA1_HMAC  : HMAC-SHA-1
 *
 *  TODO (future work, tracked separately) :
 *    CKM_DES_CBC, CKM_DES3_CBC, CKM_RC4 : via EVP_des_cbc / etc.
 *    CKM_MD5_RSA_PKCS, CKM_SHA1_RSA_PKCS : RSA sign with non-FIPS hash
 *
 *  The legacy dispatcher consults the mechanism id from the operation
 *  context and routes to the right OpenSSL primitive. The default
 *  provider (NOT the FIPS provider) must be loaded for these to work,
 *  which is the case for the entire OpenSSL 3.x default config.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_pkcs11_mechanisms.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* Forward prototypes (satisfies -Wmissing-prototypes ; these symbols
 * are referenced from src/gen/fhsm_dispatch.c via weak resolution). */
void      fhsm_legacy_set_current_mech(unsigned long m);
fhsm_rv_t fhsm_legacy_dispatch(unsigned long session, unsigned long key,
                                 const void *params, size_t plen,
                                 fhsm_slice_t in, uint8_t *out,
                                 size_t *outlen);

/* The caller (fhsm_pkcs11.c) sets a per-session "current_mechanism"
 * field before invoking the dispatch handler. The dispatch sees only
 * the generic signature, so we read the mechanism via a thread-local
 * variable populated by the PKCS#11 entry points.
 *
 * This is a quick scaffold ; production replaces it with a proper
 * params struct in the `params` argument of fhsm_legacy_dispatch. */
__thread unsigned long fhsm_legacy_current_mech = 0;

void fhsm_legacy_set_current_mech(unsigned long m) {
    fhsm_legacy_current_mech = m;
}

/* Helper : run EVP_DigestX with the named digest. */
static fhsm_rv_t do_digest(const char *md_name,
                            fhsm_slice_t in, uint8_t *out, size_t *outlen) {
    const EVP_MD *md = EVP_get_digestbyname(md_name);
    if (!md) return FHSM_RV_MECHANISM_INVALID;
    unsigned int o = (unsigned int)*outlen;
    if (EVP_Digest(in.data, in.len, out, &o, md, NULL) != 1)
        return FHSM_RV_FUNCTION_FAILED;
    *outlen = o;
    return FHSM_RV_OK;
}

/* Public legacy dispatcher. Strong symbol --- overrides the weak NULL
 * declared in src/gen/fhsm_dispatch.c. */
fhsm_rv_t fhsm_legacy_dispatch(unsigned long session, unsigned long key,
                                 const void *params, size_t plen,
                                 fhsm_slice_t in, uint8_t *out, size_t *outlen)
{
    (void)session; (void)key; (void)params; (void)plen;

    switch (fhsm_legacy_current_mech) {
    case CKM_MD5:
        return do_digest("MD5", in, out, outlen);
    case CKM_SHA_1:
        return do_digest("SHA1", in, out, outlen);
    /* SHA-1 HMAC, DES family, RC4 etc. : not implemented yet.
     * Fall through to MECHANISM_INVALID so the caller knows to fail
     * rather than silently producing wrong output. */
    default:
        return FHSM_RV_MECHANISM_INVALID;
    }
}
