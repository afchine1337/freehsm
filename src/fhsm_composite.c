/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm_composite.c --- Composite ML-DSA signature combiner (#112).
 *
 *  M' = Prefix || Label || len(ctx) || ctx || PH( M )
 *
 *  draft-ietf-lamps-pq-composite-sigs-19 §2.2 and §3.2. Validated against the
 *  worked examples of Appendix D, which are in the tree as
 *  kat/composite/mprime_appendix_d.txt and were reproduced before this file
 *  was written. See docs/COMPOSITE_SIGS_GAP.md for why that ordering matters.
 * ========================================================================= */

#include "fhsm_composite.h"
#include "fhsm_pkcs11_mechanisms.h"

/* src/fhsm_pkcs11.c redefines mechanism constants locally -- the file's
 * convention, since it does not include the generated header. A value copied
 * by hand into a second place drifts eventually, so the two are tied together
 * here, where both are visible, and a mismatch becomes a build failure rather
 * than a mechanism that dispatches to the wrong handler. */
#define FHSM_LOCAL_CKM_COMPOSITE_MLDSA65_ED25519 0x80004202UL
_Static_assert(FHSM_LOCAL_CKM_COMPOSITE_MLDSA65_ED25519
                 == CKM_COMPOSITE_MLDSA65_ED25519,
               "the mechanism constant copied into src/fhsm_pkcs11.c has "
               "drifted from the generated table");

#include <openssl/evp.h>
#include <string.h>

/* Parameters from draft §6, which pulls them in from src/algParams.md upstream.
 *
 * The label is ASCII. §6: "Labels are represented here as ASCII strings, but
 * implementers MUST convert them to byte strings according to their ASCII
 * values prior to concatenating them with other byte values." The plausible
 * wrong reading is a DER encoding of the OID; it is not that. */
static const fhsm_composite_params_t g_params[] = {
    {
        .alg       = FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
        .name      = "id-MLDSA65-Ed25519-SHA512",
        .oid       = "1.3.6.1.5.5.7.6.48",
        .label     = "COMPSIG-MLDSA65-Ed25519-SHA512",
        .label_len = 30,
        .ph_name   = "SHA512",
        .ph_len    = 64,
    },
};

const fhsm_composite_params_t *fhsm_composite_params(fhsm_composite_alg_t alg) {
    for (size_t i = 0; i < sizeof(g_params) / sizeof(g_params[0]); ++i) {
        if (g_params[i].alg == alg) return &g_params[i];
    }
    return NULL;
}

size_t fhsm_composite_mprime_len(fhsm_composite_alg_t alg, size_t ctx_len) {
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    if (!p || ctx_len > FHSM_COMPOSITE_CTX_MAX) return 0;
    return FHSM_COMPOSITE_PREFIX_LEN + p->label_len + 1u + ctx_len + p->ph_len;
}

fhsm_rv_t fhsm_composite_mprime(fhsm_composite_alg_t alg,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *ctx, size_t ctx_len,
                                 uint8_t *out, size_t *out_len)
{
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    if (!p || !out || !out_len)          return FHSM_RV_ARGUMENTS_BAD;
    if (!msg && msg_len)                 return FHSM_RV_ARGUMENTS_BAD;
    if (!ctx && ctx_len)                 return FHSM_RV_ARGUMENTS_BAD;

    /* §3.2 step 1, and the reason len(ctx) is a single byte in §2.2. This is a
     * hard refusal, not a truncation: silently shortening an application's
     * context would change what gets signed without telling anyone. */
    if (ctx_len > FHSM_COMPOSITE_CTX_MAX) return FHSM_RV_DATA_LEN_RANGE;

    const size_t need = fhsm_composite_mprime_len(alg, ctx_len);
    if (need == 0)                       return FHSM_RV_ARGUMENTS_BAD;
    if (*out_len < need)                 { *out_len = need; return FHSM_RV_BUFFER_TOO_SMALL; }

    /* PH( M ). Computed straight into its final position so the digest is not
     * copied around; the layout below is written in draft order so the code
     * reads like the specification. */
    uint8_t *cur = out;

    memcpy(cur, FHSM_COMPOSITE_PREFIX, FHSM_COMPOSITE_PREFIX_LEN);
    cur += FHSM_COMPOSITE_PREFIX_LEN;

    memcpy(cur, p->label, p->label_len);
    cur += p->label_len;

    *cur++ = (uint8_t)ctx_len;              /* single unsigned byte, §2.2 */

    if (ctx_len) { memcpy(cur, ctx, ctx_len); cur += ctx_len; }

    unsigned int dlen = 0;
    EVP_MD *md = EVP_MD_fetch(NULL, p->ph_name, NULL);
    if (!md) return FHSM_RV_FUNCTION_FAILED;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_MD_free(md); return FHSM_RV_HOST_MEMORY; }

    int ok = EVP_DigestInit_ex(mdctx, md, NULL) == 1
          && (msg_len == 0 || EVP_DigestUpdate(mdctx, msg, msg_len) == 1)
          && EVP_DigestFinal_ex(mdctx, cur, &dlen) == 1;

    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);

    if (!ok || dlen != p->ph_len) {
        /* Leave nothing half-built behind: a partially written M' that a
         * caller ignored the return code on would sign the wrong thing. */
        memset(out, 0, need);
        return FHSM_RV_FUNCTION_FAILED;
    }

    *out_len = need;
    return FHSM_RV_OK;
}

/* ===========================================================================
 * Keys, signing and verification.
 * ========================================================================= */

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/x509.h>

/* Component algorithm names as OpenSSL knows them, per composite algorithm. */
static int component_names(fhsm_composite_alg_t alg,
                            const char **pq, const char **trad) {
    switch (alg) {
        case FHSM_COMPOSITE_MLDSA65_ED25519_SHA512:
            *pq = "ML-DSA-65"; *trad = "ED25519"; return 1;
        default:
            return 0;
    }
}

/* --- the local blob ------------------------------------------------------ */

static fhsm_rv_t blob_pack(fhsm_composite_alg_t alg,
                            const uint8_t *pq,  size_t pq_len,
                            const uint8_t *trad, size_t trad_len,
                            uint8_t *out, size_t *out_len)
{
    const size_t need = 4 + 1 + 1 + 2 + pq_len + 2 + trad_len;
    if (pq_len > 0xFFFF || trad_len > 0xFFFF) return FHSM_RV_FUNCTION_FAILED;
    if (*out_len < need) { *out_len = need; return FHSM_RV_BUFFER_TOO_SMALL; }
    uint8_t *c = out;
    memcpy(c, FHSM_COMPOSITE_BLOB_MAGIC, 4); c += 4;
    *c++ = (uint8_t)FHSM_COMPOSITE_BLOB_VERSION;
    *c++ = (uint8_t)alg;
    *c++ = (uint8_t)(pq_len & 0xFF); *c++ = (uint8_t)(pq_len >> 8);
    memcpy(c, pq, pq_len); c += pq_len;
    *c++ = (uint8_t)(trad_len & 0xFF); *c++ = (uint8_t)(trad_len >> 8);
    memcpy(c, trad, trad_len); c += trad_len;
    *out_len = (size_t)(c - out);
    return FHSM_RV_OK;
}

static fhsm_rv_t blob_unpack(fhsm_composite_alg_t alg,
                              const uint8_t *in, size_t in_len,
                              const uint8_t **pq, size_t *pq_len,
                              const uint8_t **trad, size_t *trad_len)
{
    if (in_len < 10) return FHSM_RV_ARGUMENTS_BAD;
    if (memcmp(in, FHSM_COMPOSITE_BLOB_MAGIC, 4) != 0) return FHSM_RV_ARGUMENTS_BAD;
    if (in[4] != FHSM_COMPOSITE_BLOB_VERSION)          return FHSM_RV_ARGUMENTS_BAD;
    if (in[5] != (uint8_t)alg)                          return FHSM_RV_KEY_TYPE_INCONSISTENT;
    size_t off = 6;
    size_t n1 = (size_t)in[off] | ((size_t)in[off + 1] << 8); off += 2;
    if (off + n1 + 2 > in_len) return FHSM_RV_ARGUMENTS_BAD;
    *pq = in + off; *pq_len = n1; off += n1;
    size_t n2 = (size_t)in[off] | ((size_t)in[off + 1] << 8); off += 2;
    if (off + n2 != in_len) return FHSM_RV_ARGUMENTS_BAD;
    *trad = in + off; *trad_len = n2;
    return FHSM_RV_OK;
}

/* --- key generation ------------------------------------------------------ */

static EVP_PKEY *gen_one(const char *name) {
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (!c) return NULL;
    if (EVP_PKEY_keygen_init(c) <= 0 || EVP_PKEY_keygen(c, &k) <= 0) k = NULL;
    EVP_PKEY_CTX_free(c);
    return k;
}

fhsm_rv_t fhsm_composite_keygen(fhsm_composite_alg_t alg,
                                 uint8_t *priv, size_t *priv_len,
                                 uint8_t *pub,  size_t *pub_len)
{
    const char *pq_name, *trad_name;
    if (!component_names(alg, &pq_name, &trad_name)) return FHSM_RV_ARGUMENTS_BAD;
    if (!priv || !priv_len || !pub || !pub_len)      return FHSM_RV_ARGUMENTS_BAD;

    /* §3.1: both components MUST be freshly generated. They are generated
     * right here, from nothing, and no caller can substitute an existing key
     * because no parameter offers the opportunity. */
    EVP_PKEY *kpq = gen_one(pq_name);
    EVP_PKEY *ktr = gen_one(trad_name);
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    uint8_t *dpq = NULL, *dtr = NULL, *ppq = NULL, *ptr_ = NULL;
    int lpq = 0, ltr = 0, lppq = 0, lptr = 0;

    if (!kpq || !ktr) goto out;

    /* §3.1: "If one of the component KeyGen() routines returns an error, then
     * the Composite-ML-DSA.KeyGen() routine MUST also return an error." No
     * half-composite is ever produced. */
    lpq = i2d_PrivateKey(kpq, &dpq);
    ltr = i2d_PrivateKey(ktr, &dtr);
    lppq = i2d_PUBKEY(kpq, &ppq);
    lptr = i2d_PUBKEY(ktr, &ptr_);
    if (lpq <= 0 || ltr <= 0 || lppq <= 0 || lptr <= 0) goto out;

    rv = blob_pack(alg, dpq, (size_t)lpq, dtr, (size_t)ltr, priv, priv_len);
    if (rv != FHSM_RV_OK) goto out;
    rv = blob_pack(alg, ppq, (size_t)lppq, ptr_, (size_t)lptr, pub, pub_len);

out:
    if (dpq)  { OPENSSL_cleanse(dpq, (size_t)(lpq > 0 ? lpq : 0)); OPENSSL_free(dpq); }
    if (dtr)  { OPENSSL_cleanse(dtr, (size_t)(ltr > 0 ? ltr : 0)); OPENSSL_free(dtr); }
    OPENSSL_free(ppq); OPENSSL_free(ptr_);
    EVP_PKEY_free(kpq); EVP_PKEY_free(ktr);
    return rv;
}

/* --- sign / verify ------------------------------------------------------- */

/* The Label is handed to ML-DSA as its FIPS 204 context string (§3.2 step 4,
 * `mldsa_ctx = Label`). This is the Label's SECOND role -- it is already
 * inside M' -- and it is the one an implementer forgets. Verified against
 * OpenSSL 3.5.6: a signature made with this context fails verification under
 * any other context and under none. */
static int sign_component(EVP_PKEY *k, const char *ctx_label,
                           const uint8_t *m, size_t mlen,
                           uint8_t *sig, size_t *slen)
{
    OSSL_PARAM p[2]; const OSSL_PARAM *pp = NULL;
    if (ctx_label) {
        p[0] = OSSL_PARAM_construct_octet_string(
                   OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                   (void *)(uintptr_t)ctx_label, strlen(ctx_label));
        p[1] = OSSL_PARAM_construct_end();
        pp = p;
    }
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c) return 0;
    EVP_PKEY_CTX *sc = NULL;
    int r = EVP_DigestSignInit_ex(c, &sc, NULL, NULL, NULL, k, pp) > 0
         && EVP_DigestSign(c, sig, slen, m, mlen) > 0;
    EVP_MD_CTX_free(c);
    return r;
}

static int verify_component(EVP_PKEY *k, const char *ctx_label,
                             const uint8_t *m, size_t mlen,
                             const uint8_t *sig, size_t slen)
{
    OSSL_PARAM p[2]; const OSSL_PARAM *pp = NULL;
    if (ctx_label) {
        p[0] = OSSL_PARAM_construct_octet_string(
                   OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                   (void *)(uintptr_t)ctx_label, strlen(ctx_label));
        p[1] = OSSL_PARAM_construct_end();
        pp = p;
    }
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c) return 0;
    EVP_PKEY_CTX *vc = NULL;
    int r = EVP_DigestVerifyInit_ex(c, &vc, NULL, NULL, NULL, k, pp) > 0
         && EVP_DigestVerify(c, sig, slen, m, mlen) == 1;
    EVP_MD_CTX_free(c);
    return r;
}

fhsm_rv_t fhsm_composite_split(fhsm_composite_alg_t alg,
                                const uint8_t *sig, size_t sig_len,
                                size_t *pq_len, size_t *trad_len)
{
    /* Ed25519 signatures are fixed at 64 bytes and ML-DSA-65 at 3309, so the
     * boundary is arithmetic rather than parsing. A combination with a
     * variable-length traditional component (ECDSA) would need the component
     * encodings inspected; there is no such combination registered yet, and
     * this returns an error rather than guessing if one appears. */
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512 || !sig || !pq_len || !trad_len)
        return FHSM_RV_ARGUMENTS_BAD;
    const size_t ed = 64, pq = 3309;
    if (sig_len != pq + ed) return FHSM_RV_ARGUMENTS_BAD;
    *pq_len = pq; *trad_len = ed;
    return FHSM_RV_OK;
}

fhsm_rv_t fhsm_composite_sign(fhsm_composite_alg_t alg,
                               const uint8_t *priv, size_t priv_len,
                               const uint8_t *msg,  size_t msg_len,
                               const uint8_t *ctx,  size_t ctx_len,
                               uint8_t *sig, size_t *sig_len)
{
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    const char *pq_name, *trad_name;
    if (!p || !component_names(alg, &pq_name, &trad_name)) return FHSM_RV_ARGUMENTS_BAD;
    if (!priv || !sig || !sig_len)                          return FHSM_RV_ARGUMENTS_BAD;

    const uint8_t *dpq, *dtr; size_t lpq, ltr;
    fhsm_rv_t rv = blob_unpack(alg, priv, priv_len, &dpq, &lpq, &dtr, &ltr);
    if (rv != FHSM_RV_OK) return rv;

    uint8_t mprime[512];
    size_t mplen = sizeof mprime;
    rv = fhsm_composite_mprime(alg, msg, msg_len, ctx, ctx_len, mprime, &mplen);
    if (rv != FHSM_RV_OK) return rv;

    const uint8_t *q = dpq;
    EVP_PKEY *kpq = d2i_PrivateKey_ex(EVP_PKEY_NONE, NULL, &q, (long)lpq, NULL, NULL);
    const uint8_t *t = dtr;
    EVP_PKEY *ktr = d2i_PrivateKey_ex(EVP_PKEY_NONE, NULL, &t, (long)ltr, NULL, NULL);
    rv = FHSM_RV_KEY_HANDLE_INVALID;
    if (!kpq || !ktr) goto out;

    size_t spq = *sig_len, str_ = 0;
    rv = FHSM_RV_FUNCTION_FAILED;
    if (!sign_component(kpq, p->label, mprime, mplen, sig, &spq)) goto out;
    str_ = (*sig_len > spq) ? *sig_len - spq : 0;
    /* The traditional component signs M' too, and takes no context: §3.2 notes
     * that even where EdDSA exposes one, Composite ML-DSA does not use it. */
    if (!sign_component(ktr, NULL, mprime, mplen, sig + spq, &str_)) goto out;

    *sig_len = spq + str_;      /* mldsaSig || tradSig, draft order */
    rv = FHSM_RV_OK;
out:
    OPENSSL_cleanse(mprime, sizeof mprime);
    EVP_PKEY_free(kpq); EVP_PKEY_free(ktr);
    return rv;
}

fhsm_rv_t fhsm_composite_verify(fhsm_composite_alg_t alg,
                                 const uint8_t *pub, size_t pub_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *ctx, size_t ctx_len,
                                 const uint8_t *sig, size_t sig_len)
{
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    const char *pq_name, *trad_name;
    if (!p || !component_names(alg, &pq_name, &trad_name)) return FHSM_RV_ARGUMENTS_BAD;
    if (!pub || !sig)                                       return FHSM_RV_ARGUMENTS_BAD;

    size_t spq, str_;
    fhsm_rv_t rv = fhsm_composite_split(alg, sig, sig_len, &spq, &str_);
    if (rv != FHSM_RV_OK) return rv;

    const uint8_t *ppq, *ptr_; size_t lpq, ltr;
    rv = blob_unpack(alg, pub, pub_len, &ppq, &lpq, &ptr_, &ltr);
    if (rv != FHSM_RV_OK) return rv;

    uint8_t mprime[512];
    size_t mplen = sizeof mprime;
    rv = fhsm_composite_mprime(alg, msg, msg_len, ctx, ctx_len, mprime, &mplen);
    if (rv != FHSM_RV_OK) return rv;

    const uint8_t *q = ppq; EVP_PKEY *kpq = d2i_PUBKEY(NULL, &q, (long)lpq);
    const uint8_t *t = ptr_; EVP_PKEY *ktr = d2i_PUBKEY(NULL, &t, (long)ltr);
    rv = FHSM_RV_KEY_HANDLE_INVALID;
    if (!kpq || !ktr) goto out;

    /* §3.3: valid if and only if ALL component signatures validate. */
    rv = (verify_component(kpq, p->label, mprime, mplen, sig, spq)
       && verify_component(ktr, NULL, mprime, mplen, sig + spq, str_))
         ? FHSM_RV_OK : FHSM_RV_SIGNATURE_INVALID;
out:
    OPENSSL_cleanse(mprime, sizeof mprime);
    EVP_PKEY_free(kpq); EVP_PKEY_free(ktr);
    return rv;
}
