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
 * fhsm_kat_rsp.h --- NIST CAVP .rsp file parser & runner.
 *
 *  The CAVP (Cryptographic Algorithm Validation Program) publishes
 *  reference test vectors as a tree of ZIP archives, one per
 *  algorithm. After extraction each algorithm exposes one or more
 *  .rsp ("response") files in the standard NIST format described in
 *  https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
 *
 *  Wire format of a .rsp file (simplified) :
 *
 *      # comment line (ignored)
 *      [SectionHeader = value]            // algorithm-wide parameter
 *
 *      Count = 0
 *      Key   = 00112233...
 *      IV    = aabbccdd...
 *      PT    = deadbeef...
 *      CT    = 1a2b3c4d...
 *      Tag   = e5f60718...
 *                                          // blank line = end of vector
 *      Count = 1
 *      ...
 *
 *  Bracketed sections set persistent context (algorithm variant, key
 *  length, hash function...) that applies to every vector until the
 *  next bracketed section.
 *
 *  Each algorithm has its own field naming convention (Msg/MD for hashes,
 *  Key/Msg/Mac for HMAC, Key/IV/PT/AAD/CT/Tag for AES-GCM, etc.). We
 *  parse generically into a record of name->hex-bytes pairs and let
 *  the per-algorithm handler pick what it needs.
 *
 *  Records are streamed --- we never buffer the entire file. The
 *  largest CAVP file in the FIPS 140-3 baseline is ~30 MiB (SHA Monte
 *  Carlo); streaming keeps the validator memory-bounded.
 *
 *  This header is included by the KAT runner only. It is NOT part of
 *  the TSFI (no symbol exposed in libfreehsm-fips.so).
 * ========================================================================= */

#ifndef FHSM_KAT_RSP_H
#define FHSM_KAT_RSP_H

#include "fhsm_common.h"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FHSM_RSP_MAX_FIELDS   16
#define FHSM_RSP_MAX_VALUE    1024   /* longest hex value in CAVP corpus */
#define FHSM_RSP_MAX_KEY      32     /* longest field name ("Plaintext", etc.) */

/* A parsed name=value pair. Value is raw bytes (after hex decode). */
typedef struct fhsm_rsp_pair_s {
    char    key[FHSM_RSP_MAX_KEY];
    uint8_t value[FHSM_RSP_MAX_VALUE];
    size_t  value_len;
} fhsm_rsp_pair_t;

/* A single test vector --- accumulated from successive lines until
 * the next blank line. The "section" sub-struct mirrors the most
 * recent bracketed line, so context is preserved across vectors. */
typedef struct fhsm_rsp_record_s {
    fhsm_rsp_pair_t  fields[FHSM_RSP_MAX_FIELDS];
    size_t           field_count;
    fhsm_rsp_pair_t  section[FHSM_RSP_MAX_FIELDS];
    size_t           section_count;
} fhsm_rsp_record_t;

/* Callback invoked once per parsed record. Return non-zero to abort
 * parsing (e.g. on KAT mismatch). ctx is forwarded from the caller. */
typedef int (*fhsm_rsp_visitor_t)(const fhsm_rsp_record_t *rec, void *ctx);

/* Parse a .rsp file end-to-end. Returns FHSM_RV_OK on success or
 * FHSM_RV_FUNCTION_FAILED if any vector parse fails. The visitor's
 * abort return code is propagated as FHSM_RV_KAT_FAILED. */
fhsm_rv_t fhsm_rsp_parse(FILE *fp, fhsm_rsp_visitor_t visit, void *ctx);

/* Convenience : open then parse. */
fhsm_rv_t fhsm_rsp_parse_file(const char *path,
                                fhsm_rsp_visitor_t visit, void *ctx);

/* Field lookup inside a record. Returns NULL on miss. Case-insensitive
 * comparison so "MSG"/"Msg"/"msg" all match. */
const fhsm_rsp_pair_t *fhsm_rsp_get(const fhsm_rsp_record_t *rec,
                                      const char *key);

/* Section field lookup --- searches only the most recent bracketed
 * section. Convenient for variant parameters such as [Keylen = 256]. */
const fhsm_rsp_pair_t *fhsm_rsp_section(const fhsm_rsp_record_t *rec,
                                          const char *key);

/* ---------------------------------------------------------------------------
 * Per-algorithm runners. Each consumes one .rsp file and validates
 * every vector by recomputing the expected output and comparing with
 * fhsm_ct_memcmp(). Returns the number of vectors that passed and
 * fails fast on the first mismatch (after which the module ERROR
 * state is latched by the caller).
 * ----------------------------------------------------------------------- */
typedef struct fhsm_rsp_report_s {
    size_t  total;
    size_t  passed;
    size_t  skipped;     /* unsupported variant in this build */
    char    first_failure[128];
} fhsm_rsp_report_t;

fhsm_rv_t fhsm_rsp_run_sha2(const char *path, fhsm_rsp_report_t *out);
fhsm_rv_t fhsm_rsp_run_sha3(const char *path, fhsm_rsp_report_t *out);
fhsm_rv_t fhsm_rsp_run_hmac(const char *path, fhsm_rsp_report_t *out);
fhsm_rv_t fhsm_rsp_run_aes_gcm(const char *path, fhsm_rsp_report_t *out);
fhsm_rv_t fhsm_rsp_run_pbkdf2(const char *path, fhsm_rsp_report_t *out);
fhsm_rv_t fhsm_rsp_run_ctr_drbg(const char *path, fhsm_rsp_report_t *out);

/* Walk a directory (e.g. kat/cavp/) and route every .rsp file to its
 * corresponding runner based on filename prefix. Used by the top-level
 * KAT entry point fhsm_kat_run_full(). */
fhsm_rv_t fhsm_rsp_run_directory(const char *dirpath,
                                   fhsm_rsp_report_t *out_summary);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_KAT_RSP_H */
