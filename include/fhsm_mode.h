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
 * fhsm_mode.h --- Runtime mode selector (legacy vs FIPS strict).
 *
 *  Default mode is **legacy** : every mechanism declared in
 *  g_mech_list is callable, including non-FIPS-approved ones (MD5,
 *  SHA-1 outside HMAC, DES, 3DES, RC4, plain RSA-X.509, etc.).
 *
 *  FIPS strict mode is enabled by exporting :
 *    FHSM_MODE=fips        (recommended)
 *  or
 *    FHSM_MODE=strict
 *  or by writing
 *    mode = fips
 *  in /etc/freehsm/freehsm.conf. The fhsm_mode module reads the
 *  environment variable first and falls back to the config file.
 *
 *  When fhsm_mode_is_fips() returns 1, every non-FIPS-approved
 *  mechanism dispatched via dispatch_reject_fips returns
 *  FHSM_RV_FIPS_NOT_APPROVED (maps to CKR_MECHANISM_INVALID).
 *  When it returns 0, the legacy dispatch path is used (currently a
 *  placeholder that returns FHSM_RV_FUNCTION_FAILED ; production
 *  implementations of MD5/SHA-1/DES live in src/dispatch/fhsm_dispatch_legacy.c).
 *
 *  The value is cached after first lookup --- callers can safely
 *  invoke fhsm_mode_is_fips() in hot paths.
 * ========================================================================= */

#ifndef FHSM_MODE_H
#define FHSM_MODE_H

#include "fhsm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 1 if FHSM is in FIPS strict mode, 0 if in legacy/interop mode.
 * Cached after first call. */
int fhsm_mode_is_fips(void);

/* Force a re-read of the env / config (useful for tests). */
void fhsm_mode_reset_cache(void);

/* Human-readable mode string : "fips" or "legacy". */
const char *fhsm_mode_string(void);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_MODE_H */
