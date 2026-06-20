/* diag_rsa_oaep.c
 *
 * Reproduces kat/cavp_extended.c::run_rsa_oaep_roundtrip exactly with
 * a print + ERR_print_errors at every potential failure point, so we
 * can see which EVP call fails and what OpenSSL error chain it produces.
 *
 * Also runs the PSS roundtrip first for comparison (since PSS passes
 * in dev mode but OAEP fails).
 *
 * Build : cc disabled/diag_rsa_oaep.c -lcrypto -o /tmp/diag_oaep
 * Run   : /tmp/diag_oaep
 *
 * License : Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

static const unsigned char msg[16] = "FreeHSM RSA KAT!";

static void dump_err(const char *who) {
    fprintf(stderr, "  [%s] FAIL\n", who);
    fprintf(stderr, "  OpenSSL error chain :\n");
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\n");
}

static EVP_PKEY *gen_rsa_2048(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) { dump_err("EVP_PKEY_CTX_new_id(RSA)"); return NULL; }
    if (EVP_PKEY_keygen_init(ctx) <= 0) { dump_err("keygen_init"); goto end; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        dump_err("set_keygen_bits"); goto end;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        dump_err("EVP_PKEY_keygen"); pkey = NULL; goto end;
    }
end:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int do_pss_roundtrip(EVP_PKEY *pkey) {
    printf("\n=== PSS roundtrip ===\n");
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pkctx = NULL;
    unsigned char sig[512];
    size_t sig_len = sizeof(sig);

    if (EVP_DigestSignInit(mdctx, &pkctx, EVP_sha256(), NULL, pkey) != 1) {
        dump_err("EVP_DigestSignInit(SHA256, PSS)"); EVP_MD_CTX_free(mdctx); return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        dump_err("set_rsa_padding(PSS)"); EVP_MD_CTX_free(mdctx); return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        dump_err("set_rsa_pss_saltlen(DIGEST)"); EVP_MD_CTX_free(mdctx); return 0;
    }
    if (EVP_DigestSign(mdctx, sig, &sig_len, msg, sizeof(msg)) != 1) {
        dump_err("EVP_DigestSign(PSS)"); EVP_MD_CTX_free(mdctx); return 0;
    }
    printf("  PSS sign OK : sig_len=%zu\n", sig_len);
    EVP_MD_CTX_free(mdctx);
    return 1;
}

static int do_oaep_roundtrip(EVP_PKEY *pkey) {
    printf("\n=== OAEP roundtrip ===\n");
    EVP_PKEY_CTX *enc = NULL, *dec = NULL;
    unsigned char ct[512], pt[64];
    size_t ct_len = sizeof(ct), pt_len = sizeof(pt);
    int ret = 0;

    enc = EVP_PKEY_CTX_new(pkey, NULL);
    if (!enc) { dump_err("EVP_PKEY_CTX_new(enc)"); goto end; }
    printf("  [1/9] EVP_PKEY_CTX_new(enc) OK\n");

    if (EVP_PKEY_encrypt_init(enc) <= 0) {
        dump_err("EVP_PKEY_encrypt_init"); goto end;
    }
    printf("  [2/9] EVP_PKEY_encrypt_init OK\n");

    if (EVP_PKEY_CTX_set_rsa_padding(enc, RSA_PKCS1_OAEP_PADDING) <= 0) {
        dump_err("set_rsa_padding(OAEP)"); goto end;
    }
    printf("  [3/9] set_rsa_padding(OAEP) OK\n");

    if (EVP_PKEY_CTX_set_rsa_oaep_md(enc, EVP_sha256()) <= 0) {
        dump_err("set_rsa_oaep_md(SHA256)"); goto end;
    }
    printf("  [4/9] set_rsa_oaep_md(SHA256) OK\n");

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(enc, EVP_sha256()) <= 0) {
        dump_err("set_rsa_mgf1_md(SHA256)"); goto end;
    }
    printf("  [5/9] set_rsa_mgf1_md(SHA256) OK\n");

    if (EVP_PKEY_encrypt(enc, ct, &ct_len, msg, sizeof(msg)) <= 0) {
        dump_err("EVP_PKEY_encrypt"); goto end;
    }
    printf("  [6/9] EVP_PKEY_encrypt OK : ct_len=%zu\n", ct_len);

    dec = EVP_PKEY_CTX_new(pkey, NULL);
    if (!dec) { dump_err("EVP_PKEY_CTX_new(dec)"); goto end; }
    if (EVP_PKEY_decrypt_init(dec) <= 0) {
        dump_err("EVP_PKEY_decrypt_init"); goto end;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(dec, RSA_PKCS1_OAEP_PADDING) <= 0) {
        dump_err("set_rsa_padding(OAEP) dec"); goto end;
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(dec, EVP_sha256()) <= 0) {
        dump_err("set_rsa_oaep_md(SHA256) dec"); goto end;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(dec, EVP_sha256()) <= 0) {
        dump_err("set_rsa_mgf1_md(SHA256) dec"); goto end;
    }
    if (EVP_PKEY_decrypt(dec, pt, &pt_len, ct, ct_len) <= 0) {
        dump_err("EVP_PKEY_decrypt"); goto end;
    }
    printf("  [7/9] EVP_PKEY_decrypt OK : pt_len=%zu\n", pt_len);

    if (pt_len != sizeof(msg)) {
        printf("  [8/9] pt_len mismatch : got %zu, want %zu\n", pt_len, sizeof(msg));
        goto end;
    }
    if (memcmp(pt, msg, sizeof(msg)) != 0) {
        printf("  [9/9] PT content mismatch !\n");
        goto end;
    }
    printf("  [9/9] OAEP round trip OK : message recovered byte-for-byte\n");
    ret = 1;

end:
    EVP_PKEY_CTX_free(enc);
    EVP_PKEY_CTX_free(dec);
    return ret;
}

int main(void) {
    printf("OpenSSL : %s\n", OpenSSL_version(OPENSSL_VERSION));

    EVP_PKEY *pkey = gen_rsa_2048();
    if (!pkey) {
        fprintf(stderr, "RSA keygen failed.\n");
        return 1;
    }
    printf("RSA-2048 keypair generated (bits=%d)\n", EVP_PKEY_get_bits(pkey));

    int pss = do_pss_roundtrip(pkey);
    printf("PSS result : %s\n", pss ? "PASS" : "FAIL");

    int oaep = do_oaep_roundtrip(pkey);
    printf("\nOAEP result : %s\n", oaep ? "PASS" : "FAIL");

    EVP_PKEY_free(pkey);
    return (pss && oaep) ? 0 : 2;
}
