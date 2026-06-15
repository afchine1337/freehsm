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
 * fhsm_crypto.c --- FIPS-approved cryptographic primitives.
 *
 * Wrappers around OpenSSL 3.x with the FIPS provider explicitly loaded
 * (no fallback to the default provider in approved mode). Each entry
 * point validates parameters, traces the call to the audit log, and
 * zeroizes intermediate state on return.
 *
 * Algorithm self-test (Known Answer Tests, KAT) runs from
 * fhsm_crypto_init() before any service is exposed to callers. The
 * KAT table is in kat/fhsm_kat_vectors.c (CAVP-derived test vectors).
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_crypto.h"
#include "fhsm_integrity.h"
#include "fhsm_drbg.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* OpenSSL FIPS provider handle. Loaded on crypto_init, unloaded on
 * crypto_finalize. The default provider is NOT loaded in approved mode
 * --- this ensures every algorithm fetch goes through the validated
 * FIPS provider only. */
static OSSL_PROVIDER *g_fips_prov = NULL;
static OSSL_PROVIDER *g_base_prov = NULL;  /* needed for encoders only */

static pthread_once_t  g_crypto_once = PTHREAD_ONCE_INIT;
static fhsm_rv_t       g_crypto_init_rv = FHSM_RV_FUNCTION_FAILED;

/* KAT results, populated by fhsm_kat_run(). Read by fhsm_kat_results(). */
#define FHSM_KAT_MAX  32
static fhsm_kat_result_t g_kat[FHSM_KAT_MAX];
static size_t            g_kat_count = 0;

/* ---------------------------------------------------------------------------
 * Forward decls --- KAT vectors live in their own translation unit
 * (kat/fhsm_kat_vectors.c) so the evaluator can review them in
 * isolation against the CAVP source ZIP.
 * ----------------------------------------------------------------------- */
/* fhsm_kat_run_all : prototype now in include/fhsm_crypto.h */

/* ---------------------------------------------------------------------------
 * Subsystem lifecycle.
 * ----------------------------------------------------------------------- */
static void crypto_init_once(void) {
    /* FIPS 140-3 §7.10.2 : the integrity self-test runs BEFORE any
     * approved crypto service is exposed, even before the provider
     * load. We use OpenSSL EVP_DigestSign internally, which is
     * already FIPS-conformant via libcrypto's default boot path, so
     * it is safe to invoke at this stage. Failure latches ERROR. */
    if (fhsm_integrity_verify() != FHSM_RV_OK
        && getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED") == NULL) {
        g_crypto_init_rv = FHSM_RV_INTEGRITY_FAILED;
        /* fhsm_state_latch_error already called from inside verify */
        return;
    }

    /* Load the FIPS provider. The provider config (typically
     * /usr/local/ssl/fipsmodule.cnf) MUST list the module's integrity
     * MAC. The OpenSSL FIPS provider runs its own integrity self-test
     * on load --- if that fails, OSSL_PROVIDER_load returns NULL and
     * we latch the module ERROR state. */
    g_fips_prov = OSSL_PROVIDER_load(NULL, "fips");
    if (g_fips_prov == NULL) {
        /* In a dev build (test_smoke) the FIPS provider config may not be
         * accessible. Allow opt-in fall-back to the default provider so
         * the harness can still exercise KAT vectors. Production runs
         * MUST have the FIPS provider configured. */
        if (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED") == NULL) {
            fhsm_state_latch_error("OpenSSL FIPS provider load failed");
            return;
        }
        /* fall through : continue without FIPS provider in dev mode */
    }

    /* Base provider provides only PEM/DER encoders/decoders --- no
     * primitives. Required to serialize keys to disk. */
    g_base_prov = OSSL_PROVIDER_load(NULL, "base");
    if (g_base_prov == NULL) {
        if (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED") == NULL) {
            if (g_fips_prov) OSSL_PROVIDER_unload(g_fips_prov);
            g_fips_prov = NULL;
            fhsm_state_latch_error("OpenSSL base provider load failed");
            return;
        }
    }

    /* Force FIPS as the default property --- any EVP_*_fetch with no
     * explicit property goes through the FIPS provider only. */
    if (EVP_default_properties_enable_fips(NULL, 1) != 1) {
        OSSL_PROVIDER_unload(g_base_prov);
        OSSL_PROVIDER_unload(g_fips_prov);
        g_base_prov = NULL;
        g_fips_prov = NULL;
        g_crypto_init_rv = FHSM_RV_FIPS_NOT_APPROVED;
        fhsm_state_latch_error("FIPS default property failed");
        return;
    }

    /* Initialise the hardened DRBG layer (multi-source seed +
     * SP 800-90B health tests). Must precede the KAT run because some
     * KATs consume DRBG output. */
    fhsm_rv_t drbg_rv = fhsm_drbg_init();
    if (drbg_rv != FHSM_RV_OK) {
        OSSL_PROVIDER_unload(g_base_prov);
        OSSL_PROVIDER_unload(g_fips_prov);
        g_base_prov = NULL;
        g_fips_prov = NULL;
        g_crypto_init_rv = drbg_rv;
        fhsm_state_latch_error("DRBG init failed");
        return;
    }

    /* Run KAT before declaring init success. Any KAT failure latches
     * the module ERROR state and propagates FHSM_RV_KAT_FAILED.
     *
     * DEV-ONLY BYPASS : when BOTH FHSM_INTEGRITY_ALLOW_UNSIGNED=1 and
     * FHSM_KAT_ALLOW_FAIL=1 are set, we report KAT failures to stderr
     * but continue init so external test harnesses (Wycheproof, fuzz,
     * etc.) can still exercise the module. This is STRICTLY forbidden
     * in any deployment claiming FIPS 140-3 conformance --- both env
     * vars are unset in the AGD_PRE-mandated systemd unit. */
    fhsm_rv_t kat_rv = fhsm_kat_run_all(g_kat, FHSM_KAT_MAX, &g_kat_count);
    if (kat_rv != FHSM_RV_OK) {
        int dev_bypass = (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED") != NULL)
                      && (getenv("FHSM_KAT_ALLOW_FAIL") != NULL);
        if (!dev_bypass) {
            OSSL_PROVIDER_unload(g_base_prov);
            OSSL_PROVIDER_unload(g_fips_prov);
            g_base_prov = NULL;
            g_fips_prov = NULL;
            g_crypto_init_rv = FHSM_RV_KAT_FAILED;
            fhsm_state_latch_error("KAT failed at module init");
            return;
        }
        /* Dev bypass : list which KATs failed on stderr but do NOT
         * latch ERROR. The KAT report is still readable via
         * fhsm_kat_results() so a harness can inspect it. */
        fprintf(stderr,
            "[freehsm-c] WARNING : FHSM_KAT_ALLOW_FAIL active --- "
            "module exposes services WITHOUT a passing KAT. This is "
            "INVALID for any FIPS 140-3 / CC EAL4+ deployment.\n");
        for (size_t i = 0; i < g_kat_count; i++) {
            if (!g_kat[i].passed) {
                fprintf(stderr, "[freehsm-c]   KAT FAIL : %s / %s\n",
                        g_kat[i].algorithm, g_kat[i].vector_id);
            }
        }
    }

    g_crypto_init_rv = FHSM_RV_OK;
}

fhsm_rv_t fhsm_crypto_init(void) {
    pthread_once(&g_crypto_once, crypto_init_once);
    return g_crypto_init_rv;
}

void fhsm_crypto_finalize(void) {
    if (g_base_prov) { OSSL_PROVIDER_unload(g_base_prov); g_base_prov = NULL; }
    if (g_fips_prov) { OSSL_PROVIDER_unload(g_fips_prov); g_fips_prov = NULL; }
    fhsm_zeroize(g_kat, sizeof(g_kat));
    g_kat_count = 0;
}

int fhsm_fips_mode(void) { return FHSM_FIPS_ONLY ? 1 : 0; }

/* Exported with default visibility so an external diagnostic harness
 * can read the KAT report after C_Initialize. In a shipping FIPS build
 * this is consumed only by the test harness; in production it is still
 * safe to expose because it only reveals the pass/fail bit and the
 * vector identifier --- no key material. */
__attribute__((visibility("default")))
const fhsm_kat_result_t *fhsm_kat_results(size_t *count) {
    if (count) *count = g_kat_count;
    return g_kat;
}

/* ---------------------------------------------------------------------------
 * DRBG. We use OpenSSL's RAND_bytes after the FIPS provider is loaded,
 * which routes to the FIPS-validated CTR_DRBG-AES-256. The seed source
 * is /dev/urandom (Linux >= 5.6 via getrandom(GRND_RANDOM) under the
 * hood), or the platform-equivalent secure source.
 *
 * FIPS 140-3 §7.10.3.b : continuous random number generator test.
 * We keep the previous 16-byte (128-bit) output block in static memory
 * and compare every new 16-byte block against it. A repeated block
 * indicates a catastrophic DRBG failure (stuck output) and is latched
 * into the module ERROR state. False positives are 1 in 2^128 per call
 * --- effectively impossible. The first call has no prior block, so
 * the test is bypassed for the first 16 bytes only.
 * ----------------------------------------------------------------------- */
/* Thin wrapper : delegate to the hardened DRBG layer which runs
 * multi-source seeding, RCT, APT and CRNGT health tests on every
 * output. See src/fhsm_drbg.c for the full pipeline. */
fhsm_rv_t fhsm_rng_bytes(uint8_t *out, size_t n) {
    return fhsm_drbg_bytes(out, n);
}

fhsm_rv_t fhsm_rng_reseed(fhsm_slice_t personalization) {
    /* RAND_status() returns 1 if the DRBG is seeded and ready,
     * 0 otherwise. Available since OpenSSL 1.1.0 (vs RAND_status()
     * which only appeared in 3.2+ and is not portable). */
    if (RAND_status() == 0) {
        return FHSM_RV_RNG_FAILURE;
    }
    if (personalization.len > 0) {
        /* RAND_add() feeds entropy + personalization. The entropy
         * estimate (3rd arg) is conservatively 0 since the caller may
         * inject any string --- the DRBG must not rely on it. */
        RAND_add(personalization.data, (int)personalization.len, 0.0);
    }
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * AES-256-GCM wrapper.
 * ----------------------------------------------------------------------- */
size_t fhsm_hash_size(fhsm_hash_t h) {
    switch (h) {
        case FHSM_HASH_SHA256: case FHSM_HASH_SHA3_256: return 32;
        case FHSM_HASH_SHA384: case FHSM_HASH_SHA3_384: return 48;
        case FHSM_HASH_SHA512: case FHSM_HASH_SHA3_512: return 64;
        default: return 0;
    }
}

static const char *hash_name(fhsm_hash_t h) {
    switch (h) {
        case FHSM_HASH_SHA256:   return "SHA2-256";
        case FHSM_HASH_SHA384:   return "SHA2-384";
        case FHSM_HASH_SHA512:   return "SHA2-512";
        case FHSM_HASH_SHA3_256: return "SHA3-256";
        case FHSM_HASH_SHA3_384: return "SHA3-384";
        case FHSM_HASH_SHA3_512: return "SHA3-512";
        default:                 return NULL;
    }
}

fhsm_rv_t fhsm_aes_gcm_encrypt(fhsm_slice_t key,
                                fhsm_slice_t iv,
                                fhsm_slice_t aad,
                                fhsm_slice_t plaintext,
                                uint8_t      *ciphertext,
                                size_t       *ciphertext_len,
                                uint8_t       tag[16]) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (key.len != 16 && key.len != 24 && key.len != 32) return FHSM_RV_KEY_SIZE_RANGE;
    if (iv.len != 12) return FHSM_RV_ARGUMENTS_BAD;
    if (ciphertext_len == NULL || tag == NULL) return FHSM_RV_ARGUMENTS_BAD;
    if (*ciphertext_len < plaintext.len) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return FHSM_RV_HOST_MEMORY;

    const EVP_CIPHER *cipher = NULL;
    switch (key.len) {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
    }

    if (EVP_EncryptInit_ex2(ctx, cipher, key.data, iv.data, NULL) != 1) goto out;

    int outl = 0;
    if (aad.len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &outl, aad.data, (int)aad.len) != 1) goto out;
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext.data, (int)plaintext.len) != 1) goto out;
    size_t produced = (size_t)outl;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + produced, &outl) != 1) goto out;
    produced += (size_t)outl;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto out;

    *ciphertext_len = produced;
    rv = FHSM_RV_OK;

out:
    EVP_CIPHER_CTX_free(ctx);
    return rv;
}

fhsm_rv_t fhsm_aes_gcm_decrypt(fhsm_slice_t key,
                                fhsm_slice_t iv,
                                fhsm_slice_t aad,
                                fhsm_slice_t ciphertext,
                                const uint8_t tag[16],
                                uint8_t      *plaintext,
                                size_t       *plaintext_len) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (key.len != 16 && key.len != 24 && key.len != 32) return FHSM_RV_KEY_SIZE_RANGE;
    if (iv.len != 12) return FHSM_RV_ARGUMENTS_BAD;
    if (plaintext_len == NULL || tag == NULL) return FHSM_RV_ARGUMENTS_BAD;
    if (*plaintext_len < ciphertext.len) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return FHSM_RV_HOST_MEMORY;

    const EVP_CIPHER *cipher = NULL;
    switch (key.len) {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
    }

    if (EVP_DecryptInit_ex2(ctx, cipher, key.data, iv.data, NULL) != 1) goto out;

    int outl = 0;
    if (aad.len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &outl, aad.data, (int)aad.len) != 1) goto out;
    }
    if (EVP_DecryptUpdate(ctx, plaintext, &outl, ciphertext.data, (int)ciphertext.len) != 1) goto out;
    size_t produced = (size_t)outl;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) goto out;
    if (EVP_DecryptFinal_ex(ctx, plaintext + produced, &outl) != 1) {
        /* Tag mismatch --- per FIPS 140-3 §7.10.4 we MUST zeroize the
         * (potentially partial) plaintext before returning. */
        fhsm_zeroize(plaintext, *plaintext_len);
        rv = FHSM_RV_ENCRYPTED_DATA_INVALID;
        goto out;
    }
    produced += (size_t)outl;
    *plaintext_len = produced;
    rv = FHSM_RV_OK;

out:
    EVP_CIPHER_CTX_free(ctx);
    return rv;
}

/* ---------------------------------------------------------------------------
 * HMAC and hash.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_hash_oneshot(fhsm_hash_t alg, fhsm_slice_t data,
                             uint8_t *out, size_t *out_len) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    const char *name = hash_name(alg);
    if (!name || out == NULL || out_len == NULL) return FHSM_RV_ARGUMENTS_BAD;
    size_t expected = fhsm_hash_size(alg);
    if (*out_len < expected) return FHSM_RV_ARGUMENTS_BAD;

    EVP_MD *md = EVP_MD_fetch(NULL, name, NULL);
    if (!md) return FHSM_RV_MECHANISM_INVALID;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    if (!ctx) { EVP_MD_free(md); return FHSM_RV_HOST_MEMORY; }

    unsigned int n = 0;
    if (EVP_DigestInit_ex2(ctx, md, NULL) == 1 &&
        EVP_DigestUpdate(ctx, data.data, data.len) == 1 &&
        EVP_DigestFinal_ex(ctx, out, &n) == 1) {
        *out_len = n;
        rv = FHSM_RV_OK;
    }

    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return rv;
}

fhsm_rv_t fhsm_hmac(fhsm_hash_t alg, fhsm_slice_t key, fhsm_slice_t data,
                     uint8_t *mac, size_t *mac_len) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    const char *name = hash_name(alg);
    if (!name) return FHSM_RV_ARGUMENTS_BAD;
    size_t expected = fhsm_hash_size(alg);
    if (*mac_len < expected) return FHSM_RV_ARGUMENTS_BAD;

    /* Use the modern EVP_MAC interface (HMAC via EVP_MAC_fetch). The
     * legacy HMAC_* API is deprecated in OpenSSL 3.x and not part of
     * the FIPS provider's approved interface in some builds. */
    EVP_MAC *mac_alg = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac_alg) return FHSM_RV_MECHANISM_INVALID;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac_alg);
    if (!ctx) { EVP_MAC_free(mac_alg); return FHSM_RV_HOST_MEMORY; }

    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string("digest", (char*)name, 0),
        OSSL_PARAM_construct_end()
    };

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    size_t out_n = 0;
    if (EVP_MAC_init(ctx, key.data, key.len, params) == 1 &&
        EVP_MAC_update(ctx, data.data, data.len) == 1 &&
        EVP_MAC_final(ctx, mac, &out_n, *mac_len) == 1) {
        *mac_len = out_n;
        rv = FHSM_RV_OK;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac_alg);
    return rv;
}

/* ---------------------------------------------------------------------------
 * PBKDF2 --- NIST SP 800-132 with minimum 200_000 iterations.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_pbkdf2(fhsm_hash_t alg, fhsm_slice_t password, fhsm_slice_t salt,
                       uint32_t iterations, uint8_t *out, size_t out_len) {
    if (fhsm_state_get() == FHSM_STATE_ERROR) return FHSM_RV_FUNCTION_FAILED;
    if (iterations < 200000) return FHSM_RV_FIPS_NOT_APPROVED;
    if (out_len == 0 || out_len > 64) return FHSM_RV_ARGUMENTS_BAD;
    const char *name = hash_name(alg);
    if (!name) return FHSM_RV_ARGUMENTS_BAD;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (!kdf) return FHSM_RV_MECHANISM_INVALID;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx) { EVP_KDF_free(kdf); return FHSM_RV_HOST_MEMORY; }

    OSSL_PARAM params[5];
    int p = 0;
    params[p++] = OSSL_PARAM_construct_utf8_string("digest", (char*)name, 0);
    params[p++] = OSSL_PARAM_construct_octet_string("pass",
                    (void*)password.data, password.len);
    params[p++] = OSSL_PARAM_construct_octet_string("salt",
                    (void*)salt.data, salt.len);
    params[p++] = OSSL_PARAM_construct_uint32("iter", &iterations);
    params[p]   = OSSL_PARAM_construct_end();

    fhsm_rv_t rv = (EVP_KDF_derive(ctx, out, out_len, params) == 1)
                    ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;

    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return rv;
}
