/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * probe_digestsign_stream.c --- which signature algorithms accept
 * EVP_DigestSignUpdate on THIS OpenSSL?
 *
 * C_SignInit accepts every signature mechanism, because C_Sign needs it to.
 * C_SignUpdate and C_SignFinal implement HMAC and the composite mechanism
 * only, so a caller who initialises CKM_SHA256_RSA_PKCS and then calls
 * C_SignUpdate is refused at Final with CKR_MECHANISM_INVALID. Closing that
 * gap has two possible shapes per mechanism:
 *
 *   - stream: EVP_DigestSignInit / Update / Final, no message buffered
 *   - buffer: accumulate the message and call the one-shot path at Final
 *
 * Buffering is memory proportional to the message, which is the thing
 * multipart exists to avoid; streaming is only available where the algorithm
 * and the provider both allow it. Ed25519 is one-shot by construction
 * (RFC 8032 hashes the message twice), and the ML-DSA / SLH-DSA
 * implementations in OpenSSL 3.5 are recent enough that their streaming
 * support is a question about this build rather than about the standard.
 *
 * So this probe asks the library instead of assuming. It links against
 * OpenSSL directly, not against the module: what is being measured is the
 * provider's capability, and putting the module in between would only add a
 * way for the answer to be wrong.
 *
 * Output is a table. It decides which branch each mechanism family gets in
 * C_SignUpdate, and the result belongs in a comment there so the next reader
 * does not have to re-run this to know why.
 * ========================================================================= */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

static EVP_PKEY *keygen(const char *alg, const char *group) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *k = NULL;
    if (!c) return NULL;
    if (EVP_PKEY_keygen_init(c) > 0) {
        if (group) {
            OSSL_PARAM p[2] = {
                OSSL_PARAM_construct_utf8_string("group", (char *)group, 0),
                OSSL_PARAM_construct_end()
            };
            if (EVP_PKEY_CTX_set_params(c, p) <= 0) { EVP_PKEY_CTX_free(c); return NULL; }
        }
        (void)EVP_PKEY_generate(c, &k);
    }
    EVP_PKEY_CTX_free(c);
    return k;
}

/* Returns 1 if Init+Update+Update+Final produced a signature. */
static int try_stream(EVP_PKEY *k, const char *mdname, size_t *siglen_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    int ok = 0;
    unsigned char sig[8192];
    size_t sl = sizeof sig;
    ERR_clear_error();
    if (EVP_DigestSignInit_ex(ctx, NULL, mdname, NULL, NULL, k, NULL) == 1
        && EVP_DigestSignUpdate(ctx, "multipart ", 10) == 1
        && EVP_DigestSignUpdate(ctx, "message", 7) == 1
        && EVP_DigestSignFinal(ctx, sig, &sl) == 1) {
        ok = 1;
        if (siglen_out) *siglen_out = sl;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* Returns 1 if the one-shot EVP_DigestSign works, which is the fallback
 * shape: buffer the parts, sign the concatenation at Final. */
static int try_oneshot(EVP_PKEY *k, const char *mdname) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    int ok = 0;
    unsigned char sig[8192];
    size_t sl = sizeof sig;
    ERR_clear_error();
    if (EVP_DigestSignInit_ex(ctx, NULL, mdname, NULL, NULL, k, NULL) == 1
        && EVP_DigestSign(ctx, sig, &sl,
                          (const unsigned char *)"multipart message", 17) == 1)
        ok = 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static void row(const char *label, const char *alg, const char *group,
                const char *mdname) {
    EVP_PKEY *k = keygen(alg, group);
    if (!k) {
        printf("  %-22s %-10s %-10s  (key generation failed)\n", label, "-", "-");
        return;
    }
    size_t sl = 0;
    int s = try_stream(k, mdname, &sl);
    int o = try_oneshot(k, mdname);
    printf("  %-22s %-10s %-10s  %s\n", label,
           s ? "stream" : "no", o ? "one-shot" : "no",
           s ? "" : "-> must buffer the message");
    EVP_PKEY_free(k);
}

int main(void) {
    printf("probe_digestsign_stream : OpenSSL %s\n", OpenSSL_version(OPENSSL_VERSION_STRING));
    printf("  %-22s %-10s %-10s\n", "mechanism family", "Update", "one-shot");
    printf("  %-22s %-10s %-10s\n", "----------------", "------", "--------");

    row("RSA + SHA-256",        "RSA",         NULL,    "SHA256");
    row("RSA-PSS + SHA-256",    "RSA-PSS",     NULL,    "SHA256");
    row("ECDSA P-256 + SHA-256","EC",          "P-256", "SHA256");
    row("Ed25519",              "ED25519",     NULL,    NULL);
    row("Ed448",                "ED448",       NULL,    NULL);
    row("ML-DSA-65",            "ML-DSA-65",   NULL,    NULL);
    row("SLH-DSA-SHA2-128s",    "SLH-DSA-SHA2-128s", NULL, NULL);

    printf("\n  Read: 'stream' means C_SignUpdate can feed EVP directly.\n");
    printf("  'must buffer' means C_SignFinal has to sign an accumulated\n");
    printf("  message, at a memory cost proportional to its length.\n");
    return 0;
}
