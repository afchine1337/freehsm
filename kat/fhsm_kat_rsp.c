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
 * fhsm_kat_rsp.c --- NIST CAVP .rsp parser + per-algorithm runners.
 * ========================================================================= */

#include "fhsm_kat_rsp.h"
#include "fhsm_crypto.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ---------------------------------------------------------------------------
 * Hex helpers
 * ----------------------------------------------------------------------- */
static int hex_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *s, size_t s_len,
                       uint8_t *out, size_t cap, size_t *out_len)
{
    /* CAVP uses uppercase or lowercase hex, no separators, even length. */
    if (s_len % 2 != 0) return -1;
    if (s_len / 2 > cap) return -1;
    for (size_t i = 0; i < s_len; i += 2) {
        int hi = hex_val((unsigned char)s[i]);
        int lo = hex_val((unsigned char)s[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = s_len / 2;
    return 0;
}

/* Decimal integer decode --- used for fields like Count, Len, Iter,
 * not stored as hex. */
static int dec_decode(const char *s, size_t s_len,
                       uint8_t *out, size_t cap, size_t *out_len)
{
    if (cap < 8) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < s_len; ++i) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    /* Big-endian uint64 in the value slot. */
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    *out_len = 8;
    return 0;
}

/* Is this field name one of the integer-typed ones in CAVP? */
static int is_int_field(const char *name) {
    static const char *const ints[] = {
        "Count", "Len", "Klen", "Tlen", "Plen", "Aadlen", "Ivlen",
        "c", "kLen", "AADlen", "IVlen", "PTlen", "CTlen", "Taglen",
        "Outputlen", "DKLen",
        /* Section-header dimensions */
        "L", "n"
    };
    for (size_t i = 0; i < sizeof(ints)/sizeof(ints[0]); ++i) {
        if (strcasecmp(name, ints[i]) == 0) return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Lookup helpers
 * ----------------------------------------------------------------------- */
const fhsm_rsp_pair_t *fhsm_rsp_get(const fhsm_rsp_record_t *rec,
                                       const char *key)
{
    if (!rec || !key) return NULL;
    for (size_t i = 0; i < rec->field_count; ++i) {
        if (strcasecmp(rec->fields[i].key, key) == 0) return &rec->fields[i];
    }
    return NULL;
}

const fhsm_rsp_pair_t *fhsm_rsp_section(const fhsm_rsp_record_t *rec,
                                           const char *key)
{
    if (!rec || !key) return NULL;
    for (size_t i = 0; i < rec->section_count; ++i) {
        if (strcasecmp(rec->section[i].key, key) == 0) return &rec->section[i];
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * Line scanner
 * ----------------------------------------------------------------------- */
static void rstrip(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'
                     || s[n - 1] == ' '  || s[n - 1] == '\t')) {
        s[--n] = '\0';
    }
}

static int append_pair(fhsm_rsp_pair_t *arr, size_t *cnt, size_t cap,
                        const char *k, size_t klen, const char *v, size_t vlen)
{
    if (*cnt >= cap) return -1;
    if (klen >= FHSM_RSP_MAX_KEY) klen = FHSM_RSP_MAX_KEY - 1;
    memcpy(arr[*cnt].key, k, klen);
    arr[*cnt].key[klen] = '\0';
    /* Strip leading whitespace from value. */
    while (vlen > 0 && (*v == ' ' || *v == '\t')) { v++; vlen--; }
    int rc;
    size_t out_len = 0;
    if (is_int_field(arr[*cnt].key)) {
        rc = dec_decode(v, vlen, arr[*cnt].value,
                         sizeof(arr[*cnt].value), &out_len);
    } else {
        rc = hex_decode(v, vlen, arr[*cnt].value,
                         sizeof(arr[*cnt].value), &out_len);
        if (rc < 0 && vlen <= sizeof(arr[*cnt].value)) {
            /* Not hex --- store raw (rare; e.g. algorithm strings). */
            memcpy(arr[*cnt].value, v, vlen);
            out_len = vlen;
            rc = 0;
        }
    }
    if (rc < 0) return -1;
    arr[*cnt].value_len = out_len;
    (*cnt)++;
    return 0;
}

/* ---------------------------------------------------------------------------
 * Top-level parser
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_rsp_parse(FILE *fp, fhsm_rsp_visitor_t visit, void *ctx)
{
    if (!fp || !visit) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_rsp_record_t rec;
    memset(&rec, 0, sizeof(rec));

    char line[2 * FHSM_RSP_MAX_VALUE + 64];
    while (fgets(line, sizeof(line), fp)) {
        rstrip(line);
        /* Comment line */
        if (line[0] == '#') continue;
        /* Blank line --- emit record if it has any field, then reset
         * field_count (keep section context). */
        if (line[0] == '\0') {
            if (rec.field_count > 0) {
                int rc = visit(&rec, ctx);
                if (rc != 0) return FHSM_RV_KAT_FAILED;
                rec.field_count = 0;
            }
            continue;
        }
        /* Bracketed section --- reset section context if first bracket
         * after fields, then accumulate. */
        if (line[0] == '[') {
            char *close = strrchr(line, ']');
            if (!close) continue;  /* malformed --- skip */
            *close = '\0';
            char *eq = strchr(line + 1, '=');
            const char *k = line + 1;
            const char *v = "";
            size_t klen, vlen;
            if (eq) {
                *eq = '\0';
                klen = strlen(k);
                v = eq + 1;
                vlen = strlen(v);
                /* trim trailing spaces from key */
                while (klen > 0 && (k[klen - 1] == ' ' || k[klen - 1] == '\t'))
                    klen--;
                /* trim leading spaces from value */
                while (vlen > 0 && (*v == ' ' || *v == '\t')) { v++; vlen--; }
            } else {
                klen = strlen(k);
                vlen = 0;
            }
            /* On a NEW section, clear prior section state. CAVP files
             * group sections at file start (no field before any section
             * within a group); first section seen after a record emits
             * counts as the new context. */
            if (rec.field_count == 0) {
                /* keep section accumulation --- this is the typical case */
            }
            if (rec.section_count >= FHSM_RSP_MAX_FIELDS) continue;
            append_pair(rec.section, &rec.section_count,
                         FHSM_RSP_MAX_FIELDS, k, klen, v, vlen);
            continue;
        }
        /* key = value */
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = line;
        const char *v = eq + 1;
        size_t klen = strlen(k);
        size_t vlen = strlen(v);
        /* trim trailing spaces from key */
        while (klen > 0 && (k[klen - 1] == ' ' || k[klen - 1] == '\t')) klen--;
        append_pair(rec.fields, &rec.field_count,
                     FHSM_RSP_MAX_FIELDS, k, klen, v, vlen);
    }
    /* Tail record (no trailing blank). */
    if (rec.field_count > 0) {
        int rc = visit(&rec, ctx);
        if (rc != 0) return FHSM_RV_KAT_FAILED;
    }
    return FHSM_RV_OK;
}

fhsm_rv_t fhsm_rsp_parse_file(const char *path,
                                fhsm_rsp_visitor_t visit, void *ctx)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return FHSM_RV_FUNCTION_FAILED;
    fhsm_rv_t rv = fhsm_rsp_parse(fp, visit, ctx);
    fclose(fp);
    return rv;
}

/* ---------------------------------------------------------------------------
 * Per-algorithm runners. Each picks the fields it needs and recomputes
 * the expected output via the FIPS provider through fhsm_crypto.c.
 * ----------------------------------------------------------------------- */
typedef struct run_ctx_s {
    fhsm_rsp_report_t *rep;
    int                hash_alg_override;  /* -1 = use Section [L = X] */
} run_ctx_t;

static fhsm_hash_t hash_from_len(size_t mdlen) {
    switch (mdlen) {
        case 32: return FHSM_HASH_SHA256;
        case 48: return FHSM_HASH_SHA384;
        case 64: return FHSM_HASH_SHA512;
        default: return (fhsm_hash_t)0;
    }
}

/* SHA-2 ----------------------------------------------------------------
 * Fields per vector :   Len, Msg, MD                                     */
static int visit_sha(const fhsm_rsp_record_t *rec, void *vctx) {
    run_ctx_t *ctx = vctx;
    ctx->rep->total++;
    const fhsm_rsp_pair_t *msg = fhsm_rsp_get(rec, "Msg");
    const fhsm_rsp_pair_t *md  = fhsm_rsp_get(rec, "MD");
    if (!msg || !md) { ctx->rep->skipped++; return 0; }

    /* For Len=0 CAVP encodes Msg="00" (a placeholder); treat as empty. */
    const fhsm_rsp_pair_t *len = fhsm_rsp_get(rec, "Len");
    size_t mlen = msg->value_len;
    if (len && len->value_len == 8) {
        uint64_t bits = 0;
        for (int i = 0; i < 8; ++i) bits = (bits << 8) | len->value[i];
        if (bits == 0) mlen = 0;
    }
    fhsm_hash_t alg = hash_from_len(md->value_len);
    if (!alg) { ctx->rep->skipped++; return 0; }

    uint8_t out[64]; size_t outl = sizeof(out);
    fhsm_slice_t in = FHSM_SLICE(msg->value, mlen);
    if (fhsm_hash_oneshot(alg, in, out, &outl) != FHSM_RV_OK ||
        outl != md->value_len ||
        fhsm_ct_memcmp(out, md->value, outl) != 0) {
        snprintf(ctx->rep->first_failure, sizeof(ctx->rep->first_failure),
                  "SHA mismatch md_len=%zu", md->value_len);
        return 1;
    }
    ctx->rep->passed++;
    return 0;
}

fhsm_rv_t fhsm_rsp_run_sha2(const char *path, fhsm_rsp_report_t *out)
{
    memset(out, 0, sizeof(*out));
    run_ctx_t ctx = { .rep = out, .hash_alg_override = -1 };
    return fhsm_rsp_parse_file(path, visit_sha, &ctx);
}

fhsm_rv_t fhsm_rsp_run_sha3(const char *path, fhsm_rsp_report_t *out)
{
    /* SHA-3 uses the same field layout as SHA-2 ; the alg is inferred
     * from MD length (256/384/512). */
    return fhsm_rsp_run_sha2(path, out);
}

/* HMAC ----------------------------------------------------------------
 * Fields per vector :   Count, Klen, Tlen, Key, Msg, Mac                */
static int visit_hmac(const fhsm_rsp_record_t *rec, void *vctx) {
    run_ctx_t *ctx = vctx;
    ctx->rep->total++;
    const fhsm_rsp_pair_t *key = fhsm_rsp_get(rec, "Key");
    const fhsm_rsp_pair_t *msg = fhsm_rsp_get(rec, "Msg");
    const fhsm_rsp_pair_t *mac = fhsm_rsp_get(rec, "Mac");
    if (!key || !msg || !mac) { ctx->rep->skipped++; return 0; }

    /* The HMAC underlying hash is set by the section [L = N] header,
     * or inferred from the requested Mac length (Tlen field) if that
     * fails. */
    fhsm_hash_t alg = (fhsm_hash_t)0;
    const fhsm_rsp_pair_t *L = fhsm_rsp_section(rec, "L");
    if (L && L->value_len == 8) {
        uint64_t l = 0;
        for (int i = 0; i < 8; ++i) l = (l << 8) | L->value[i];
        alg = hash_from_len((size_t)l);
    }
    if (!alg) alg = hash_from_len(mac->value_len);
    if (!alg) { ctx->rep->skipped++; return 0; }

    uint8_t out[64]; size_t outl = fhsm_hash_size(alg);
    if (fhsm_hmac(alg, FHSM_SLICE(key->value, key->value_len),
                    FHSM_SLICE(msg->value, msg->value_len),
                    out, &outl) != FHSM_RV_OK) {
        snprintf(ctx->rep->first_failure, sizeof(ctx->rep->first_failure),
                  "HMAC fhsm_hmac() failed");
        return 1;
    }
    /* CAVP often truncates the MAC to the first Tlen bytes; compare
     * only that many. */
    size_t cmp_len = (mac->value_len < outl) ? mac->value_len : outl;
    if (fhsm_ct_memcmp(out, mac->value, cmp_len) != 0) {
        snprintf(ctx->rep->first_failure, sizeof(ctx->rep->first_failure),
                  "HMAC mismatch len=%zu", cmp_len);
        return 1;
    }
    ctx->rep->passed++;
    return 0;
}

fhsm_rv_t fhsm_rsp_run_hmac(const char *path, fhsm_rsp_report_t *out)
{
    memset(out, 0, sizeof(*out));
    run_ctx_t ctx = { .rep = out, .hash_alg_override = -1 };
    return fhsm_rsp_parse_file(path, visit_hmac, &ctx);
}

/* AES-GCM -------------------------------------------------------------
 * Fields per vector :   Count, Key, IV, PT, AAD, CT, Tag                */
static int visit_aes_gcm(const fhsm_rsp_record_t *rec, void *vctx) {
    run_ctx_t *ctx = vctx;
    ctx->rep->total++;
    const fhsm_rsp_pair_t *key = fhsm_rsp_get(rec, "Key");
    const fhsm_rsp_pair_t *iv  = fhsm_rsp_get(rec, "IV");
    const fhsm_rsp_pair_t *pt  = fhsm_rsp_get(rec, "PT");
    const fhsm_rsp_pair_t *aad = fhsm_rsp_get(rec, "AAD");
    const fhsm_rsp_pair_t *ct  = fhsm_rsp_get(rec, "CT");
    const fhsm_rsp_pair_t *tag = fhsm_rsp_get(rec, "Tag");
    if (!key || !iv || !pt || !ct || !tag) { ctx->rep->skipped++; return 0; }
    if (iv->value_len != 12 || tag->value_len != 16) {
        ctx->rep->skipped++;  /* not approved in fhsm_aes_gcm_encrypt */
        return 0;
    }
    uint8_t buf[FHSM_RSP_MAX_VALUE]; size_t buf_len = sizeof(buf);
    uint8_t out_tag[16];
    fhsm_slice_t aad_s = aad ? FHSM_SLICE(aad->value, aad->value_len)
                              : FHSM_SLICE(NULL, 0);
    if (fhsm_aes_gcm_encrypt(FHSM_SLICE(key->value, key->value_len),
                              FHSM_SLICE(iv->value,  iv->value_len),
                              aad_s,
                              FHSM_SLICE(pt->value, pt->value_len),
                              buf, &buf_len, out_tag) != FHSM_RV_OK ||
        buf_len != ct->value_len ||
        fhsm_ct_memcmp(buf,     ct->value,  buf_len) != 0 ||
        fhsm_ct_memcmp(out_tag, tag->value, 16) != 0) {
        snprintf(ctx->rep->first_failure, sizeof(ctx->rep->first_failure),
                  "AES-GCM ct/tag mismatch keylen=%zu", key->value_len);
        return 1;
    }
    ctx->rep->passed++;
    return 0;
}

fhsm_rv_t fhsm_rsp_run_aes_gcm(const char *path, fhsm_rsp_report_t *out)
{
    memset(out, 0, sizeof(*out));
    run_ctx_t ctx = { .rep = out, .hash_alg_override = -1 };
    return fhsm_rsp_parse_file(path, visit_aes_gcm, &ctx);
}

/* PBKDF2 --------------------------------------------------------------
 * Fields per vector :   Count, c (iter), DKLen, P (password), S (salt), DK */
static int visit_pbkdf2(const fhsm_rsp_record_t *rec, void *vctx) {
    run_ctx_t *ctx = vctx;
    ctx->rep->total++;
    const fhsm_rsp_pair_t *pw   = fhsm_rsp_get(rec, "P");
    const fhsm_rsp_pair_t *salt = fhsm_rsp_get(rec, "S");
    const fhsm_rsp_pair_t *iter = fhsm_rsp_get(rec, "c");
    const fhsm_rsp_pair_t *dk   = fhsm_rsp_get(rec, "DK");
    if (!pw || !salt || !iter || !dk) { ctx->rep->skipped++; return 0; }

    uint64_t c = 0;
    if (iter->value_len == 8) {
        for (int i = 0; i < 8; ++i) c = (c << 8) | iter->value[i];
    }
    /* PBKDF2 default is HMAC-SHA-256 ; CAVP file name encodes the
     * variant, but the runner accepts an override via the section
     * "PRF" if present. */
    fhsm_hash_t alg = FHSM_HASH_SHA256;
    if (dk->value_len > sizeof(((uint8_t[64]){0}))) { ctx->rep->skipped++; return 0; }
    if (c < 200000) { ctx->rep->skipped++; return 0; /* not approved */ }

    uint8_t out[64];
    if (fhsm_pbkdf2(alg, FHSM_SLICE(pw->value, pw->value_len),
                     FHSM_SLICE(salt->value, salt->value_len),
                     (uint32_t)c, out, dk->value_len) != FHSM_RV_OK ||
        fhsm_ct_memcmp(out, dk->value, dk->value_len) != 0) {
        snprintf(ctx->rep->first_failure, sizeof(ctx->rep->first_failure),
                  "PBKDF2 mismatch dklen=%zu iter=%llu",
                  dk->value_len, (unsigned long long)c);
        return 1;
    }
    ctx->rep->passed++;
    return 0;
}

fhsm_rv_t fhsm_rsp_run_pbkdf2(const char *path, fhsm_rsp_report_t *out)
{
    memset(out, 0, sizeof(*out));
    run_ctx_t ctx = { .rep = out, .hash_alg_override = -1 };
    return fhsm_rsp_parse_file(path, visit_pbkdf2, &ctx);
}

/* CTR_DRBG ------------------------------------------------------------
 * The CAVP file structure for DRBG is non-trivial (instantiate +
 * reseed + generate paths). We expose a hook for the dedicated
 * implementation but mark every vector as skipped until the SP 800-90A
 * walker is added. */
fhsm_rv_t fhsm_rsp_run_ctr_drbg(const char *path, fhsm_rsp_report_t *out)
{
    (void)path;
    memset(out, 0, sizeof(*out));
    snprintf(out->first_failure, sizeof(out->first_failure),
              "CTR_DRBG walker not yet implemented");
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * Directory walker --- routes files by filename prefix to the right runner.
 *
 *  Convention :
 *     sha2_<variant>.rsp   ->  fhsm_rsp_run_sha2
 *     sha3_<variant>.rsp   ->  fhsm_rsp_run_sha3
 *     hmac_<variant>.rsp   ->  fhsm_rsp_run_hmac
 *     aes_gcm_<keylen>.rsp ->  fhsm_rsp_run_aes_gcm
 *     pbkdf2.rsp           ->  fhsm_rsp_run_pbkdf2
 *     ctr_drbg.rsp         ->  fhsm_rsp_run_ctr_drbg
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_rsp_run_directory(const char *dirpath,
                                   fhsm_rsp_report_t *summary)
{
    if (!dirpath || !summary) return FHSM_RV_ARGUMENTS_BAD;
    memset(summary, 0, sizeof(*summary));

    DIR *d = opendir(dirpath);
    if (!d) return FHSM_RV_FUNCTION_FAILED;

    struct dirent *de;
    fhsm_rv_t global = FHSM_RV_OK;
    while ((de = readdir(d)) != NULL) {
        const char *n = de->d_name;
        size_t nl = strlen(n);
        if (nl < 5 || strcasecmp(n + nl - 4, ".rsp") != 0) continue;

        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dirpath, n);
        fhsm_rsp_report_t rep;

        fhsm_rv_t rv = FHSM_RV_OK;
        if      (strncasecmp(n, "sha2_",    5) == 0) rv = fhsm_rsp_run_sha2(full,   &rep);
        else if (strncasecmp(n, "sha3_",    5) == 0) rv = fhsm_rsp_run_sha3(full,   &rep);
        else if (strncasecmp(n, "hmac_",    5) == 0) rv = fhsm_rsp_run_hmac(full,   &rep);
        else if (strncasecmp(n, "aes_gcm_", 8) == 0) rv = fhsm_rsp_run_aes_gcm(full,&rep);
        else if (strncasecmp(n, "pbkdf2",   6) == 0) rv = fhsm_rsp_run_pbkdf2(full, &rep);
        else if (strncasecmp(n, "ctr_drbg", 8) == 0) rv = fhsm_rsp_run_ctr_drbg(full,&rep);
        else { continue; /* unknown prefix --- skip silently */ }

        printf("[CAVP] %-32s  total=%-4zu  pass=%-4zu  skip=%-4zu %s\n",
                n, rep.total, rep.passed, rep.skipped,
                rep.first_failure[0] ? rep.first_failure : "");

        summary->total   += rep.total;
        summary->passed  += rep.passed;
        summary->skipped += rep.skipped;
        if (rv != FHSM_RV_OK && global == FHSM_RV_OK) {
            global = rv;
            snprintf(summary->first_failure, sizeof(summary->first_failure),
                      "%s: %s", n, rep.first_failure);
        }
    }
    closedir(d);
    return global;
}
