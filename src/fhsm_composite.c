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

/* The layout of M', and the only place it is written. fhsm_composite_mprime
 * computes PH(M) and calls this; the prehashed entry point calls it directly.
 * Two independent assemblies of the same structure would be the recurring
 * defect of this project in miniature -- a change applied to one path and not
 * the other -- and here the two paths must agree byte for byte or a streamed
 * signature verifies against nothing. */
static fhsm_rv_t mprime_layout(const fhsm_composite_params_t *p,
                                const uint8_t *ph, size_t ph_len,
                                const uint8_t *ctx, size_t ctx_len,
                                uint8_t *out, size_t *out_len)
{
    if (!ctx && ctx_len)                 return FHSM_RV_ARGUMENTS_BAD;
    if (!ph || ph_len != p->ph_len)      return FHSM_RV_ARGUMENTS_BAD;

    /* §3.2 step 1, and the reason len(ctx) is a single byte in §2.2. This is a
     * hard refusal, not a truncation: silently shortening an application's
     * context would change what gets signed without telling anyone. */
    if (ctx_len > FHSM_COMPOSITE_CTX_MAX) return FHSM_RV_DATA_LEN_RANGE;

    const size_t need = FHSM_COMPOSITE_PREFIX_LEN + p->label_len + 1
                      + ctx_len + p->ph_len;
    if (*out_len < need)                 { *out_len = need; return FHSM_RV_BUFFER_TOO_SMALL; }

    /* Written in draft order so the code reads like the specification. */
    uint8_t *cur = out;
    memcpy(cur, FHSM_COMPOSITE_PREFIX, FHSM_COMPOSITE_PREFIX_LEN);
    cur += FHSM_COMPOSITE_PREFIX_LEN;
    memcpy(cur, p->label, p->label_len);
    cur += p->label_len;
    *cur++ = (uint8_t)ctx_len;              /* single unsigned byte, §2.2 */
    if (ctx_len) { memcpy(cur, ctx, ctx_len); cur += ctx_len; }
    memcpy(cur, ph, p->ph_len);
    cur += p->ph_len;

    *out_len = (size_t)(cur - out);
    return (*out_len == need) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

const char *fhsm_composite_ph_name(fhsm_composite_alg_t alg) {
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    return p ? p->ph_name : NULL;
}

size_t fhsm_composite_ph_len(fhsm_composite_alg_t alg) {
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    return p ? p->ph_len : 0;
}

fhsm_rv_t fhsm_composite_mprime_prehashed(fhsm_composite_alg_t alg,
                                           const uint8_t *ph,  size_t ph_len,
                                           const uint8_t *ctx, size_t ctx_len,
                                           uint8_t *out, size_t *out_len)
{
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    if (!p || !out || !out_len) return FHSM_RV_ARGUMENTS_BAD;
    return mprime_layout(p, ph, ph_len, ctx, ctx_len, out, out_len);
}

fhsm_rv_t fhsm_composite_mprime(fhsm_composite_alg_t alg,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *ctx, size_t ctx_len,
                                 uint8_t *out, size_t *out_len)
{
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    if (!p || !out || !out_len)          return FHSM_RV_ARGUMENTS_BAD;
    if (!msg && msg_len)                 return FHSM_RV_ARGUMENTS_BAD;

    /* Size query and context bound answered before hashing, so a caller
     * probing for the length does not pay for a digest. */
    if (ctx_len > FHSM_COMPOSITE_CTX_MAX) return FHSM_RV_DATA_LEN_RANGE;
    const size_t need = fhsm_composite_mprime_len(alg, ctx_len);
    if (need == 0)                       return FHSM_RV_ARGUMENTS_BAD;
    if (*out_len < need)                 { *out_len = need; return FHSM_RV_BUFFER_TOO_SMALL; }

    uint8_t ph[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_MD *md = EVP_MD_fetch(NULL, p->ph_name, NULL);
    if (!md) return FHSM_RV_FUNCTION_FAILED;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_MD_free(md); return FHSM_RV_HOST_MEMORY; }

    int ok = EVP_DigestInit_ex(mdctx, md, NULL) == 1
          && (msg_len == 0 || EVP_DigestUpdate(mdctx, msg, msg_len) == 1)
          && EVP_DigestFinal_ex(mdctx, ph, &dlen) == 1;

    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);

    if (!ok || dlen != p->ph_len) {
        OPENSSL_cleanse(ph, sizeof ph);
        /* Leave nothing half-built behind: a partially written M' that a
         * caller ignored the return code on would sign the wrong thing. */
        memset(out, 0, need);
        return FHSM_RV_FUNCTION_FAILED;
    }

    fhsm_rv_t rv = mprime_layout(p, ph, dlen, ctx, ctx_len, out, out_len);
    OPENSSL_cleanse(ph, sizeof ph);
    if (rv != FHSM_RV_OK) memset(out, 0, need);
    return rv;
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

/* Sign an already-assembled M'. The only place the two components are driven,
 * so the one-shot and streamed paths cannot drift in what they sign or in
 * which order they concatenate. */
static fhsm_rv_t sign_mprime(fhsm_composite_alg_t alg,
                              const uint8_t *priv, size_t priv_len,
                              const uint8_t *mprime, size_t mplen,
                              uint8_t *sig, size_t *sig_len)
{
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    const char *pq_name, *trad_name;
    if (!p || !component_names(alg, &pq_name, &trad_name)) return FHSM_RV_ARGUMENTS_BAD;

    const uint8_t *dpq, *dtr; size_t lpq, ltr;
    fhsm_rv_t rv = blob_unpack(alg, priv, priv_len, &dpq, &lpq, &dtr, &ltr);
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
    EVP_PKEY_free(kpq); EVP_PKEY_free(ktr);
    return rv;
}

fhsm_rv_t fhsm_composite_sign(fhsm_composite_alg_t alg,
                               const uint8_t *priv, size_t priv_len,
                               const uint8_t *msg,  size_t msg_len,
                               const uint8_t *ctx,  size_t ctx_len,
                               uint8_t *sig, size_t *sig_len)
{
    if (!priv || !sig || !sig_len) return FHSM_RV_ARGUMENTS_BAD;
    uint8_t mprime[512];
    size_t mplen = sizeof mprime;
    fhsm_rv_t rv = fhsm_composite_mprime(alg, msg, msg_len, ctx, ctx_len, mprime, &mplen);
    if (rv != FHSM_RV_OK) return rv;
    rv = sign_mprime(alg, priv, priv_len, mprime, mplen, sig, sig_len);
    OPENSSL_cleanse(mprime, sizeof mprime);
    return rv;
}

fhsm_rv_t fhsm_composite_sign_prehashed(fhsm_composite_alg_t alg,
                                         const uint8_t *priv, size_t priv_len,
                                         const uint8_t *ph,   size_t ph_len,
                                         const uint8_t *ctx,  size_t ctx_len,
                                         uint8_t *sig, size_t *sig_len)
{
    if (!priv || !sig || !sig_len) return FHSM_RV_ARGUMENTS_BAD;
    uint8_t mprime[512];
    size_t mplen = sizeof mprime;
    fhsm_rv_t rv = fhsm_composite_mprime_prehashed(alg, ph, ph_len, ctx, ctx_len,
                                                    mprime, &mplen);
    if (rv != FHSM_RV_OK) return rv;
    rv = sign_mprime(alg, priv, priv_len, mprime, mplen, sig, sig_len);
    OPENSSL_cleanse(mprime, sizeof mprime);
    return rv;
}

/* Verify against an already-assembled M'. Single site, same reason as
 * sign_mprime. */
static fhsm_rv_t verify_mprime(fhsm_composite_alg_t alg,
                                const uint8_t *pub, size_t pub_len,
                                const uint8_t *mprime, size_t mplen,
                                const uint8_t *sig, size_t sig_len)
{
    const fhsm_composite_params_t *p = fhsm_composite_params(alg);
    const char *pq_name, *trad_name;
    if (!p || !component_names(alg, &pq_name, &trad_name)) return FHSM_RV_ARGUMENTS_BAD;

    size_t spq, str_;
    fhsm_rv_t rv = fhsm_composite_split(alg, sig, sig_len, &spq, &str_);
    if (rv != FHSM_RV_OK) return rv;

    const uint8_t *ppq, *ptr_; size_t lpq, ltr;
    rv = blob_unpack(alg, pub, pub_len, &ppq, &lpq, &ptr_, &ltr);
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
    EVP_PKEY_free(kpq); EVP_PKEY_free(ktr);
    return rv;
}

fhsm_rv_t fhsm_composite_verify(fhsm_composite_alg_t alg,
                                 const uint8_t *pub, size_t pub_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *ctx, size_t ctx_len,
                                 const uint8_t *sig, size_t sig_len)
{
    if (!pub || !sig) return FHSM_RV_ARGUMENTS_BAD;
    uint8_t mprime[512];
    size_t mplen = sizeof mprime;
    fhsm_rv_t rv = fhsm_composite_mprime(alg, msg, msg_len, ctx, ctx_len, mprime, &mplen);
    if (rv != FHSM_RV_OK) return rv;
    rv = verify_mprime(alg, pub, pub_len, mprime, mplen, sig, sig_len);
    OPENSSL_cleanse(mprime, sizeof mprime);
    return rv;
}

fhsm_rv_t fhsm_composite_verify_prehashed(fhsm_composite_alg_t alg,
                                           const uint8_t *pub, size_t pub_len,
                                           const uint8_t *ph,  size_t ph_len,
                                           const uint8_t *ctx, size_t ctx_len,
                                           const uint8_t *sig, size_t sig_len)
{
    if (!pub || !sig) return FHSM_RV_ARGUMENTS_BAD;
    uint8_t mprime[512];
    size_t mplen = sizeof mprime;
    fhsm_rv_t rv = fhsm_composite_mprime_prehashed(alg, ph, ph_len, ctx, ctx_len,
                                                    mprime, &mplen);
    if (rv != FHSM_RV_OK) return rv;
    rv = verify_mprime(alg, pub, pub_len, mprime, mplen, sig, sig_len);
    OPENSSL_cleanse(mprime, sizeof mprime);
    return rv;
}

/* ===========================================================================
 * X.509 encoding.
 * ========================================================================= */

/* DER of the AlgorithmIdentifier for id-MLDSA65-Ed25519-SHA512:
 *
 *   SEQUENCE (0x30) len 0x0B
 *     OBJECT IDENTIFIER (0x06) len 0x09  1.3.6.1.5.5.7.6.48
 *
 * Parameters are ABSENT, not NULL. The ASN.1 module says `PARAMS ARE absent`;
 * emitting a NULL instead is a different encoding, accepted by some parsers
 * and rejected by others, and it is a routine way to produce a structure that
 * looks right and interoperates with nothing. Hand-encoded rather than built
 * through OBJ_txt2obj because the OID has no NID in OpenSSL 3.5 -- the draft
 * is still in the RFC Editor queue. */
static const uint8_t ALGID_MLDSA65_ED25519[] = {
    0x30, 0x0A,                                     /* SEQUENCE, 10 bytes   */
    0x06, 0x08,                                     /* OID, 8 bytes         */
    0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x30  /* 1.3.6.1.5.5.7.6.48   */
};
/* The lengths above were wrong on the first attempt -- 0x0B and 0x09, one too
 * many each -- and eyeballing did not catch it. tests/test_composite_x509
 * recomputes the whole encoding from the dotted OID and compares, so a
 * hand-written constant cannot drift from the OID it claims to be. */

/* Write a DER length. Returns bytes written, 0 if it does not fit. */
static size_t der_len(size_t n, uint8_t *out, size_t cap) {
    if (n < 0x80)      { if (cap < 1) return 0; out[0] = (uint8_t)n; return 1; }
    if (n <= 0xFF)     { if (cap < 2) return 0; out[0] = 0x81; out[1] = (uint8_t)n; return 2; }
    if (n <= 0xFFFF)   { if (cap < 3) return 0; out[0] = 0x82;
                         out[1] = (uint8_t)(n >> 8); out[2] = (uint8_t)n; return 3; }
    if (n <= 0xFFFFFF) { if (cap < 4) return 0; out[0] = 0x83;
                         out[1] = (uint8_t)(n >> 16); out[2] = (uint8_t)(n >> 8);
                         out[3] = (uint8_t)n; return 4; }
    return 0;
    /* The three-octet form is here for revocation lists, which are the only
     * structure in this module that grows without bound: a CA that has been
     * running for years accumulates entries, and 64 KiB is about two thousand
     * of them. Certificates and requests never come close. */
}

fhsm_rv_t fhsm_composite_raw_pub(fhsm_composite_alg_t alg,
                                  const uint8_t *pub, size_t pub_len,
                                  uint8_t *out, size_t *out_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512 || !pub || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;

    const uint8_t *dpq, *dtr; size_t lpq, ltr;
    fhsm_rv_t rv = blob_unpack(alg, pub, pub_len, &dpq, &lpq, &dtr, &ltr);
    if (rv != FHSM_RV_OK) return rv;

    if (*out_len < FHSM_COMPOSITE_RAW_PUB) {
        *out_len = FHSM_COMPOSITE_RAW_PUB;
        return FHSM_RV_BUFFER_TOO_SMALL;
    }

    const uint8_t *q = dpq; EVP_PKEY *kpq = d2i_PUBKEY(NULL, &q, (long)lpq);
    const uint8_t *t = dtr; EVP_PKEY *ktr = d2i_PUBKEY(NULL, &t, (long)ltr);
    rv = FHSM_RV_KEY_HANDLE_INVALID;
    if (!kpq || !ktr) goto out;

    /* §4.1: output mldsaPK || tradPK. The sizes are fixed for this
     * combination and checked rather than trusted -- a component of the wrong
     * length would otherwise produce a structure of the right shape carrying
     * the wrong key. */
    size_t n1 = FHSM_COMPOSITE_RAW_PQ_PUB, n2 = FHSM_COMPOSITE_RAW_TRAD_PUB;
    rv = FHSM_RV_FUNCTION_FAILED;
    if (EVP_PKEY_get_raw_public_key(kpq, out, &n1) != 1
        || n1 != FHSM_COMPOSITE_RAW_PQ_PUB) goto out;
    if (EVP_PKEY_get_raw_public_key(ktr, out + n1, &n2) != 1
        || n2 != FHSM_COMPOSITE_RAW_TRAD_PUB) goto out;

    *out_len = n1 + n2;
    rv = FHSM_RV_OK;
out:
    EVP_PKEY_free(kpq); EVP_PKEY_free(ktr);
    return rv;
}

fhsm_rv_t fhsm_composite_spki(fhsm_composite_alg_t alg,
                               const uint8_t *pub, size_t pub_len,
                               uint8_t *out, size_t *out_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512 || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;

    uint8_t raw[FHSM_COMPOSITE_RAW_PUB];
    size_t rawlen = sizeof raw;
    fhsm_rv_t rv = fhsm_composite_raw_pub(alg, pub, pub_len, raw, &rawlen);
    if (rv != FHSM_RV_OK) return rv;

    /* BIT STRING content is one leading "unused bits" octet, then the value. */
    const size_t bs_content = 1 + rawlen;
    uint8_t bs_len[4]; size_t bs_len_n = der_len(bs_content, bs_len, sizeof bs_len);
    if (!bs_len_n) return FHSM_RV_FUNCTION_FAILED;

    const size_t seq_content = sizeof(ALGID_MLDSA65_ED25519)
                              + 1 + bs_len_n + bs_content;
    uint8_t sq_len[4]; size_t sq_len_n = der_len(seq_content, sq_len, sizeof sq_len);
    if (!sq_len_n) return FHSM_RV_FUNCTION_FAILED;

    const size_t total = 1 + sq_len_n + seq_content;
    if (*out_len < total) { *out_len = total; return FHSM_RV_BUFFER_TOO_SMALL; }

    uint8_t *c = out;
    *c++ = 0x30; memcpy(c, sq_len, sq_len_n); c += sq_len_n;
    memcpy(c, ALGID_MLDSA65_ED25519, sizeof ALGID_MLDSA65_ED25519);
    c += sizeof ALGID_MLDSA65_ED25519;
    *c++ = 0x03; memcpy(c, bs_len, bs_len_n); c += bs_len_n;
    *c++ = 0x00;                       /* unused bits */
    memcpy(c, raw, rawlen); c += rawlen;

    *out_len = (size_t)(c - out);
    return (*out_len == total) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

/* ===========================================================================
 * PKCS#10.
 * ========================================================================= */

fhsm_rv_t fhsm_composite_algid(fhsm_composite_alg_t alg,
                                const uint8_t **der, size_t *der_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512 || !der || !der_len)
        return FHSM_RV_ARGUMENTS_BAD;
    *der = ALGID_MLDSA65_ED25519;
    *der_len = sizeof ALGID_MLDSA65_ED25519;
    return FHSM_RV_OK;
}

/* Parse "/C=FR/O=Simorgh Labs/CN=example" into an X509_NAME. Deliberately
 * strict: an unknown attribute type or an empty value is refused rather than
 * skipped, because a CSR that silently drops half the subject it was asked
 * for is worse than one that fails. */
static X509_NAME *name_from_oneline(const char *s) {
    if (!s || *s != '/') return NULL;
    X509_NAME *n = X509_NAME_new();
    if (!n) return NULL;
    const char *p = s + 1;
    while (*p) {
        const char *eq = strchr(p, '=');
        if (!eq) goto bad;
        char field[32];
        size_t fl = (size_t)(eq - p);
        if (fl == 0 || fl >= sizeof field) goto bad;
        memcpy(field, p, fl); field[fl] = '\0';
        const char *val = eq + 1;
        const char *end = strchr(val, '/');
        size_t vl = end ? (size_t)(end - val) : strlen(val);
        if (vl == 0) goto bad;
        if (X509_NAME_add_entry_by_txt(n, field, MBSTRING_UTF8,
                                        (const unsigned char *)val,
                                        (int)vl, -1, 0) != 1) goto bad;
        if (!end) break;
        p = end + 1;
    }
    if (X509_NAME_entry_count(n) == 0) goto bad;
    return n;
bad:
    X509_NAME_free(n);
    return NULL;
}

fhsm_rv_t fhsm_composite_csr(fhsm_composite_alg_t alg,
                              const char *subject,
                              const uint8_t *pub, size_t pub_len,
                              fhsm_composite_sign_cb sign, void *sign_ctx,
                              uint8_t *out, size_t *out_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
        || !subject || !pub || !sign || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    X509_REQ  *req  = X509_REQ_new();
    X509_NAME *name = name_from_oneline(subject);
    X509_ALGOR *sa  = NULL;
    ASN1_BIT_STRING *bs = NULL;
    uint8_t *tbs = NULL, *sig = NULL;
    uint8_t spki[8192];

    if (!req || !name) { rv = FHSM_RV_ARGUMENTS_BAD; goto out; }
    if (X509_REQ_set_version(req, 0) != 1) goto out;      /* v1 == INTEGER 0 */
    if (X509_REQ_set_subject_name(req, name) != 1) goto out;

    /* Public key. X509_REQ_set_pubkey wants an EVP_PKEY and a composite key is
     * not one -- that is the whole reason this path exists -- and there is no
     * X509_REQ_set_X509_PUBKEY. So the request's own X509_PUBKEY is filled in
     * place with X509_PUBKEY_set0_param, which is the documented way to carry
     * an algorithm OpenSSL has no provider for.
     *
     * ptype is V_ASN1_UNDEF: parameters absent, per the ASN.1 module. Passing
     * V_ASN1_NULL here would compile, encode, and interoperate with roughly
     * half of everything. */
    size_t sl = sizeof spki;
    rv = fhsm_composite_spki(alg, pub, pub_len, spki, &sl);
    if (rv != FHSM_RV_OK) goto out;
    {
        uint8_t raw[FHSM_COMPOSITE_RAW_PUB];
        size_t rl = sizeof raw;
        rv = fhsm_composite_raw_pub(alg, pub, pub_len, raw, &rl);
        if (rv != FHSM_RV_OK) goto out;

        X509_PUBKEY *slot = X509_REQ_get_X509_PUBKEY(req);
        if (!slot) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }

        ASN1_OBJECT *oid = OBJ_txt2obj(FHSM_COMPOSITE_OID_MLDSA65_ED25519, 1);
        uint8_t *penc = OPENSSL_memdup(raw, rl);
        if (!oid || !penc) {
            ASN1_OBJECT_free(oid); OPENSSL_free(penc);
            rv = FHSM_RV_HOST_MEMORY; goto out;
        }
        /* Takes ownership of oid and penc on success. */
        if (X509_PUBKEY_set0_param(slot, oid, V_ASN1_UNDEF, NULL,
                                    penc, (int)rl) != 1) {
            ASN1_OBJECT_free(oid); OPENSSL_free(penc);
            rv = FHSM_RV_FUNCTION_FAILED; goto out;
        }
    }

    /* signatureAlgorithm: same OID as the key, parameters absent. §6 registers
     * a single OID that serves both roles. */
    {
        const uint8_t *ad; size_t adl;
        rv = fhsm_composite_algid(alg, &ad, &adl);
        if (rv != FHSM_RV_OK) goto out;
        const uint8_t *p = ad;
        sa = d2i_X509_ALGOR(NULL, &p, (long)adl);
        if (!sa) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }
        if (X509_REQ_set1_signature_algo(req, sa) != 1) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }
    }

    /* The signature covers the DER of CertificationRequestInfo, and nothing
     * else. i2d_re_X509_REQ_tbs re-encodes it rather than returning a cached
     * copy, so what is signed is what will be emitted. */
    int tbs_len = i2d_re_X509_REQ_tbs(req, &tbs);
    if (tbs_len <= 0) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }

    sig = OPENSSL_malloc(FHSM_COMPOSITE_SIG_MAX);
    if (!sig) { rv = FHSM_RV_HOST_MEMORY; goto out; }
    size_t sig_len = FHSM_COMPOSITE_SIG_MAX;
    rv = sign(sign_ctx, tbs, (size_t)tbs_len, sig, &sig_len);
    if (rv != FHSM_RV_OK) goto out;

    bs = ASN1_BIT_STRING_new();
    if (!bs) { rv = FHSM_RV_HOST_MEMORY; goto out; }
    if (ASN1_BIT_STRING_set(bs, sig, (int)sig_len) != 1) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }
    /* A signature is an integral number of octets: no unused bits, and the
     * DER encoder must not try to strip trailing zeros. */
    bs->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    bs->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    X509_REQ_set0_signature(req, bs);
    bs = NULL;                              /* owned by req now */

    {
        uint8_t *der = NULL;
        int n = i2d_X509_REQ(req, &der);
        if (n <= 0) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }
        if (*out_len < (size_t)n) { *out_len = (size_t)n; OPENSSL_free(der);
                                     rv = FHSM_RV_BUFFER_TOO_SMALL; goto out; }
        memcpy(out, der, (size_t)n);
        *out_len = (size_t)n;
        OPENSSL_free(der);
        rv = FHSM_RV_OK;
    }
out:
    if (tbs) OPENSSL_free(tbs);
    if (sig) { OPENSSL_cleanse(sig, FHSM_COMPOSITE_SIG_MAX); OPENSSL_free(sig); }
    ASN1_BIT_STRING_free(bs);
    X509_ALGOR_free(sa);
    X509_NAME_free(name);
    X509_REQ_free(req);
    return rv;
}

/* ===========================================================================
 * Self-signed root certificate.
 * ========================================================================= */

#include <openssl/x509v3.h>
#include <openssl/cms.h>

/* Put the composite SubjectPublicKeyInfo into an X509_PUBKEY slot. Shared by
 * the CSR and the certificate: one place that knows the trick, so a change to
 * it cannot apply to one and not the other. */
static fhsm_rv_t fill_pubkey_slot(fhsm_composite_alg_t alg,
                                   X509_PUBKEY *slot,
                                   const uint8_t *pub, size_t pub_len)
{
    if (!slot) return FHSM_RV_ARGUMENTS_BAD;
    uint8_t raw[FHSM_COMPOSITE_RAW_PUB]; size_t rl = sizeof raw;
    fhsm_rv_t rv = fhsm_composite_raw_pub(alg, pub, pub_len, raw, &rl);
    if (rv != FHSM_RV_OK) return rv;

    ASN1_OBJECT *oid = OBJ_txt2obj(FHSM_COMPOSITE_OID_MLDSA65_ED25519, 1);
    uint8_t *penc = OPENSSL_memdup(raw, rl);
    if (!oid || !penc) { ASN1_OBJECT_free(oid); OPENSSL_free(penc);
                          return FHSM_RV_HOST_MEMORY; }
    /* ptype V_ASN1_UNDEF: parameters absent, per the ASN.1 module. */
    if (X509_PUBKEY_set0_param(slot, oid, V_ASN1_UNDEF, NULL,
                                penc, (int)rl) != 1) {
        ASN1_OBJECT_free(oid); OPENSSL_free(penc);
        return FHSM_RV_FUNCTION_FAILED;
    }
    return FHSM_RV_OK;
}

/* Set an X509_ALGOR to the composite OID with absent parameters. */
static int set_composite_algor(X509_ALGOR *a) {
    ASN1_OBJECT *o = OBJ_txt2obj(FHSM_COMPOSITE_OID_MLDSA65_ED25519, 1);
    if (!o) return 0;
    if (X509_ALGOR_set0(a, o, V_ASN1_UNDEF, NULL) != 1) {
        ASN1_OBJECT_free(o); return 0;
    }
    return 1;
}

fhsm_rv_t fhsm_composite_selfsigned(fhsm_composite_alg_t alg,
                                     const char *subject,
                                     long serial, int days,
                                     const uint8_t *pub, size_t pub_len,
                                     fhsm_composite_sign_cb sign, void *sign_ctx,
                                     uint8_t *out, size_t *out_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
        || !subject || !pub || !sign || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;
    /* Serial 0 is malformed and serial < 0 encodes as negative, which RFC 5280
     * §4.1.2.2 forbids. Refuse rather than silently correct: a caller that
     * asked for a specific serial and got a different one has a worse problem
     * than one whose call failed. */
    if (serial <= 0 || days <= 0) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    X509      *x    = X509_new();
    X509_NAME *name = name_from_oneline(subject);
    ASN1_BIT_STRING *sigbs = NULL;
    uint8_t *tbs = NULL, *sig = NULL, *der = NULL;

    if (!x || !name) { rv = FHSM_RV_ARGUMENTS_BAD; goto out; }
    if (X509_set_version(x, 2) != 1) goto out;          /* v3 == INTEGER 2 */
    if (ASN1_INTEGER_set(X509_get_serialNumber(x), serial) != 1) goto out;
    if (!X509_gmtime_adj(X509_getm_notBefore(x), 0)) goto out;
    if (!X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 86400L)) goto out;
    /* Self-signed: issuer and subject are the same name. */
    if (X509_set_subject_name(x, name) != 1) goto out;
    if (X509_set_issuer_name(x, name) != 1) goto out;

    rv = fill_pubkey_slot(alg, X509_get_X509_PUBKEY(x), pub, pub_len);
    if (rv != FHSM_RV_OK) goto out;
    rv = FHSM_RV_FUNCTION_FAILED;

    /* Extensions. A root that does not say it is a CA is a root nothing will
     * chain to, and the ASN.1 module permits exactly keyCertSign and cRLSign
     * among the signing usages for a CA. */
    {
        X509_EXTENSION *bc = X509V3_EXT_conf_nid(NULL, NULL,
                                NID_basic_constraints, "critical,CA:TRUE");
        X509_EXTENSION *ku = X509V3_EXT_conf_nid(NULL, NULL,
                                NID_key_usage, "critical,keyCertSign,cRLSign");
        int ok = bc && ku
              && X509_add_ext(x, bc, -1) == 1
              && X509_add_ext(x, ku, -1) == 1;
        X509_EXTENSION_free(bc); X509_EXTENSION_free(ku);
        if (!ok) goto out;
    }
    /* subjectKeyIdentifier. X509V3_EXT_conf_nid with "hash" would ask OpenSSL
     * to digest a public key it cannot load, so it is computed here: SHA-1 of
     * the raw composite key, which is the RFC 5280 §4.2.1.2 method (1). */
    {
        uint8_t raw[FHSM_COMPOSITE_RAW_PUB]; size_t rl = sizeof raw;
        if (fhsm_composite_raw_pub(alg, pub, pub_len, raw, &rl) != FHSM_RV_OK) goto out;
        uint8_t md[20]; unsigned int mdlen = 0;
        EVP_MD *sha1 = EVP_MD_fetch(NULL, "SHA1", NULL);
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        int ok = sha1 && c && EVP_DigestInit_ex(c, sha1, NULL) == 1
              && EVP_DigestUpdate(c, raw, rl) == 1
              && EVP_DigestFinal_ex(c, md, &mdlen) == 1 && mdlen == 20;
        EVP_MD_CTX_free(c); EVP_MD_free(sha1);
        if (!ok) goto out;
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
        if (!os) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        ok = ASN1_OCTET_STRING_set(os, md, (int)mdlen) == 1;
        /* X509V3_EXT_i2d, not X509_EXTENSION_create_by_NID. The extension
         * VALUE is the DER encoding of the extension's own ASN.1 type, so a
         * subjectKeyIdentifier must be `04 14 <20 bytes>` and not the 20 bytes
         * on their own. create_by_NID takes the octet-string object and stores
         * its content verbatim, which produced a 20-byte value here and a
         * malformed extension.
         *
         * The failure mode is worth remembering: OpenSSL flagged the whole
         * certificate invalid and abandoned its extension cache, so keyUsage
         * -- correctly encoded as 03 02 01 06 -- also read back as absent. One
         * malformed extension hid a sound one, and only dumping the raw
         * extension bytes showed which was which. */
        X509_EXTENSION *ski = ok ? X509V3_EXT_i2d(NID_subject_key_identifier,
                                                   0, os)
                                 : NULL;
        ok = ski && X509_add_ext(x, ski, -1) == 1;
        X509_EXTENSION_free(ski); ASN1_OCTET_STRING_free(os);
        if (!ok) goto out;
    }

    /* Both AlgorithmIdentifiers. RFC 5280 §4.1.1.2: the outer
     * signatureAlgorithm MUST equal the signature field inside the TBS. They
     * are two separate fields and are set separately, so the test checks they
     * agree rather than trusting that this code did. */
    if (!set_composite_algor((X509_ALGOR *)X509_get0_tbs_sigalg(x))) goto out;
    {
        const ASN1_BIT_STRING *cs = NULL; const X509_ALGOR *ca = NULL;
        X509_get0_signature(&cs, &ca, x);
        if (!cs || !ca) goto out;
        if (!set_composite_algor((X509_ALGOR *)ca)) goto out;
        sigbs = (ASN1_BIT_STRING *)cs;      /* owned by x, not freed here */
    }

    {
        int tbs_len = i2d_re_X509_tbs(x, &tbs);
        if (tbs_len <= 0) goto out;
        sig = OPENSSL_malloc(FHSM_COMPOSITE_SIG_MAX);
        if (!sig) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        size_t sig_len = FHSM_COMPOSITE_SIG_MAX;
        rv = sign(sign_ctx, tbs, (size_t)tbs_len, sig, &sig_len);
        if (rv != FHSM_RV_OK) goto out;
        rv = FHSM_RV_FUNCTION_FAILED;
        if (ASN1_BIT_STRING_set(sigbs, sig, (int)sig_len) != 1) goto out;
        sigbs->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        sigbs->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    }

    {
        int n = i2d_X509(x, &der);
        if (n <= 0) goto out;
        if (*out_len < (size_t)n) { *out_len = (size_t)n;
                                     rv = FHSM_RV_BUFFER_TOO_SMALL; goto out; }
        memcpy(out, der, (size_t)n);
        *out_len = (size_t)n;
        rv = FHSM_RV_OK;
    }
out:
    if (der) OPENSSL_free(der);
    if (tbs) OPENSSL_free(tbs);
    if (sig) { OPENSSL_cleanse(sig, FHSM_COMPOSITE_SIG_MAX); OPENSSL_free(sig); }
    X509_NAME_free(name);
    X509_free(x);
    return rv;
}

/* ===========================================================================
 * Certificate issuance.
 * ========================================================================= */

#include <openssl/rand.h>

fhsm_rv_t fhsm_composite_pub_from_raw(fhsm_composite_alg_t alg,
                                       const uint8_t *raw, size_t raw_len,
                                       uint8_t *pub, size_t *pub_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512 || !raw || !pub || !pub_len)
        return FHSM_RV_ARGUMENTS_BAD;
    /* Length is checked, not assumed: a short or long value here would produce
     * component keys built from the wrong bytes, and the failure would surface
     * much later as a signature that simply never verifies. */
    if (raw_len != FHSM_COMPOSITE_RAW_PUB) return FHSM_RV_ARGUMENTS_BAD;

    EVP_PKEY *kq = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-65", NULL,
                                                   raw, FHSM_COMPOSITE_RAW_PQ_PUB);
    EVP_PKEY *kt = EVP_PKEY_new_raw_public_key_ex(NULL, "ED25519", NULL,
                                                   raw + FHSM_COMPOSITE_RAW_PQ_PUB,
                                                   FHSM_COMPOSITE_RAW_TRAD_PUB);
    uint8_t *dq = NULL, *dt = NULL;
    int lq = 0, lt = 0;
    fhsm_rv_t rv = FHSM_RV_KEY_HANDLE_INVALID;
    if (!kq || !kt) goto out;
    lq = i2d_PUBKEY(kq, &dq);
    lt = i2d_PUBKEY(kt, &dt);
    rv = FHSM_RV_FUNCTION_FAILED;
    if (lq <= 0 || lt <= 0) goto out;
    rv = blob_pack(alg, dq, (size_t)lq, dt, (size_t)lt, pub, pub_len);
out:
    OPENSSL_free(dq); OPENSSL_free(dt);
    EVP_PKEY_free(kq); EVP_PKEY_free(kt);
    return rv;
}

/* Pull the composite public key out of an X509_PUBKEY slot, checking that it
 * really is one rather than trusting the caller's context. */
static fhsm_rv_t pub_from_slot(fhsm_composite_alg_t alg, X509_PUBKEY *xp,
                                uint8_t *pub, size_t *pub_len,
                                const uint8_t **raw_out, size_t *raw_len_out)
{
    const unsigned char *pk = NULL; int pkl = 0;
    X509_ALGOR *a = NULL;
    if (!xp || X509_PUBKEY_get0_param(NULL, &pk, &pkl, &a, xp) != 1)
        return FHSM_RV_ARGUMENTS_BAD;

    const ASN1_OBJECT *o = NULL; int ptype = 0; const void *pval = NULL;
    X509_ALGOR_get0(&o, &ptype, &pval, a);
    char buf[128] = "";
    OBJ_obj2txt(buf, sizeof buf, o, 1);
    if (strcmp(buf, FHSM_COMPOSITE_OID_MLDSA65_ED25519) != 0)
        return FHSM_RV_KEY_TYPE_INCONSISTENT;

    fhsm_rv_t rv = fhsm_composite_pub_from_raw(alg, pk, (size_t)pkl, pub, pub_len);
    if (rv != FHSM_RV_OK) return rv;
    if (raw_out) *raw_out = pk;
    if (raw_len_out) *raw_len_out = (size_t)pkl;
    return FHSM_RV_OK;
}

/* SHA-1 over the raw key: RFC 5280 §4.2.1.2 method (1). */
static int key_id(const uint8_t *raw, size_t n, uint8_t md[20]) {
    unsigned int l = 0;
    EVP_MD *h = EVP_MD_fetch(NULL, "SHA1", NULL);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int ok = h && c && EVP_DigestInit_ex(c, h, NULL) == 1
          && EVP_DigestUpdate(c, raw, n) == 1
          && EVP_DigestFinal_ex(c, md, &l) == 1 && l == 20;
    EVP_MD_CTX_free(c); EVP_MD_free(h);
    return ok;
}

/* Parse one "TYPE:value" item into a GENERAL_NAME. Returns NULL on anything
 * it does not recognise or cannot encode -- the caller turns that into a
 * refusal rather than skipping the entry. Dropping a name the operator asked
 * for is worse than failing: they would ship a certificate believing it covers
 * a host it does not. */
static GENERAL_NAME *san_one(const char *item, size_t len) {
    char buf[512];
    if (len == 0 || len >= sizeof buf) return NULL;
    memcpy(buf, item, len); buf[len] = '\0';
    char *colon = strchr(buf, ':');
    if (!colon || colon == buf || colon[1] == '\0') return NULL;
    *colon = '\0';
    const char *type = buf, *val = colon + 1;

    GENERAL_NAME *gn = GENERAL_NAME_new();
    if (!gn) return NULL;

    if (!strcmp(type, "DNS") || !strcmp(type, "email") || !strcmp(type, "URI")) {
        ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
        if (!ia5 || ASN1_STRING_set(ia5, val, -1) != 1) {
            ASN1_IA5STRING_free(ia5); GENERAL_NAME_free(gn); return NULL;
        }
        GENERAL_NAME_set0_value(gn, !strcmp(type,"DNS")   ? GEN_DNS
                                   : !strcmp(type,"email") ? GEN_EMAIL
                                                           : GEN_URI, ia5);
        return gn;
    }
    if (!strcmp(type, "IP")) {
        /* a2i_IPADDRESS handles v4 and v6 and returns NULL on anything that is
         * not an address, which is exactly the validation wanted here. Private
         * and loopback ranges are deliberately not filtered -- see the header. */
        ASN1_OCTET_STRING *ip = a2i_IPADDRESS(val);
        if (!ip) { GENERAL_NAME_free(gn); return NULL; }
        GENERAL_NAME_set0_value(gn, GEN_IPADD, ip);
        return gn;
    }
    GENERAL_NAME_free(gn);
    return NULL;
}

/* Build the subjectAltName extension from the operator's list. */
static fhsm_rv_t san_extension(const char *san, X509_EXTENSION **out_ext) {
    GENERAL_NAMES *gens = GENERAL_NAMES_new();
    if (!gens) return FHSM_RV_HOST_MEMORY;
    fhsm_rv_t rv = FHSM_RV_ARGUMENTS_BAD;
    const char *p = san;
    int n = 0;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        while (len && (*p == ' ' || *p == '\t')) { ++p; --len; }
        while (len && (p[len-1] == ' ' || p[len-1] == '\t')) --len;
        GENERAL_NAME *gn = san_one(p, len);
        if (!gn) goto out;                    /* refuse, do not skip */
        if (!sk_GENERAL_NAME_push(gens, gn)) { GENERAL_NAME_free(gn);
                                                rv = FHSM_RV_HOST_MEMORY; goto out; }
        ++n;
        if (!comma) break;
        p = comma + 1;
    }
    if (n == 0) goto out;                     /* an empty SAN is malformed */
    *out_ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
    rv = *out_ext ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
out:
    GENERAL_NAMES_free(gens);
    return rv;
}

/* One cRLDistributionPoints URI, or 0 for anything refused. The reasoning
 * behind each refusal is in the header; this only enforces it. */
static int crldp_uri_ok(const char *u) {
    for (const unsigned char *c = (const unsigned char *)u; *c; ++c)
        if (*c < 0x20 || *c > 0x7e) return 0;      /* IA5String is ASCII */

    if (!strncmp(u, "http://", 7))
        return u[7] != '\0';

    if (!strncmp(u, "ldap://", 7)) {
        const char *q = strchr(u + 7, '?');
        return q != NULL && q[1] != '\0';          /* an attribute, any one */
    }
    return 0;                                       /* https:// lands here */
}

/* cRLDistributionPoints: one DistributionPoint, every URI inside it. */
static fhsm_rv_t crldp_extension(const char *const *urls, size_t n,
                                  X509_EXTENSION **out_ext) {
    CRL_DIST_POINTS *cdp   = NULL;
    DIST_POINT      *dp    = NULL;
    GENERAL_NAMES   *names = NULL;
    fhsm_rv_t rv = FHSM_RV_HOST_MEMORY;

    if (n == 0) return FHSM_RV_ARGUMENTS_BAD;

    if (!(cdp = CRL_DIST_POINTS_new()))            goto out;
    if (!(dp  = DIST_POINT_new()))                 goto out;
    if (!(dp->distpoint = DIST_POINT_NAME_new()))  goto out;
    if (!(names = GENERAL_NAMES_new()))            goto out;

    for (size_t i = 0; i < n; ++i) {
        if (!urls[i] || !crldp_uri_ok(urls[i])) {
            rv = FHSM_RV_ARGUMENTS_BAD; goto out;   /* refuse, do not skip */
        }
        GENERAL_NAME   *gn  = GENERAL_NAME_new();
        ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
        if (!gn || !ia5 || ASN1_STRING_set(ia5, urls[i], -1) != 1) {
            ASN1_IA5STRING_free(ia5); GENERAL_NAME_free(gn); goto out;
        }
        GENERAL_NAME_set0_value(gn, GEN_URI, ia5);
        if (!sk_GENERAL_NAME_push(names, gn)) { GENERAL_NAME_free(gn); goto out; }
    }

    dp->distpoint->type          = 0;               /* fullName */
    dp->distpoint->name.fullname = names;
    names = NULL;                                   /* dp owns it now */
    if (!sk_DIST_POINT_push(cdp, dp)) goto out;
    dp = NULL;                                      /* cdp owns it now */

    *out_ext = X509V3_EXT_i2d(NID_crl_distribution_points, 0, cdp);
    rv = *out_ext ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
out:
    GENERAL_NAMES_free(names);
    DIST_POINT_free(dp);
    CRL_DIST_POINTS_free(cdp);
    return rv;
}

fhsm_rv_t fhsm_composite_issue(fhsm_composite_alg_t alg,
                                const uint8_t *ca_cert, size_t ca_cert_len,
                                const uint8_t *csr, size_t csr_len,
                                const char *subject_override,
                                const char *san,
                                const char *const *crl_urls, size_t n_crl_urls,
                                int days,
                                fhsm_composite_sign_cb sign, void *sign_ctx,
                                fhsm_composite_rng_cb rng, void *rng_ctx,
                                uint8_t *out, size_t *out_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
        || !ca_cert || !csr || !sign || !rng || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;
    if (days <= 0) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    X509     *ca  = NULL, *x = NULL;
    X509_REQ *req = NULL;
    X509_NAME *subj = NULL;
    uint8_t *tbs = NULL, *sig = NULL, *der = NULL, *req_tbs = NULL;
    static uint8_t reqpub[FHSM_COMPOSITE_PUB_MAX];

    {
        const uint8_t *p = ca_cert;  ca  = d2i_X509(NULL, &p, (long)ca_cert_len);
        const uint8_t *q = csr;      req = d2i_X509_REQ(NULL, &q, (long)csr_len);
    }
    if (!ca || !req) { rv = FHSM_RV_ARGUMENTS_BAD; goto out; }

    /* ---- Proof of possession, before anything else -------------------
     * The request's signature, checked against the key the request carries.
     * Without this the CA certifies a key the applicant may not hold: anyone
     * could lift a public key from an existing certificate and obtain a new
     * one for it. This is the difference between a CA and a rubber stamp, and
     * it is the reason issuance has a single entry point. */
    {
        size_t rl = sizeof reqpub;
        const uint8_t *raw = NULL; size_t rawl = 0;
        rv = pub_from_slot(alg, X509_REQ_get_X509_PUBKEY(req), reqpub, &rl,
                            &raw, &rawl);
        if (rv != FHSM_RV_OK) goto out;

        const ASN1_BIT_STRING *rsig = NULL; const X509_ALGOR *ralg = NULL;
        X509_REQ_get0_signature(req, &rsig, &ralg);
        const ASN1_OBJECT *o = NULL; int pt = 0; const void *pv = NULL;
        X509_ALGOR_get0(&o, &pt, &pv, ralg);
        char b[128] = ""; OBJ_obj2txt(b, sizeof b, o, 1);
        if (strcmp(b, FHSM_COMPOSITE_OID_MLDSA65_ED25519) != 0) {
            rv = FHSM_RV_MECHANISM_INVALID; goto out;
        }
        int rtl = i2d_re_X509_REQ_tbs(req, &req_tbs);
        if (rtl <= 0) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }
        rv = fhsm_composite_verify(alg, reqpub, rl, req_tbs, (size_t)rtl, NULL, 0,
                                    ASN1_STRING_get0_data((const ASN1_STRING *)rsig),
                                    (size_t)ASN1_STRING_length((const ASN1_STRING *)rsig));
        if (rv != FHSM_RV_OK) { rv = FHSM_RV_SIGNATURE_INVALID; goto out; }
    }

    x = X509_new();
    if (!x) { rv = FHSM_RV_HOST_MEMORY; goto out; }
    if (X509_set_version(x, 2) != 1) goto out;

    /* ---- Serial: 20 random octets, top bit cleared ------------------- */
    {
        uint8_t sn[20];
        /* From the caller's source, because this function runs in two places
         * with different right answers -- see fhsm_composite_rng_cb. Serials
         * are load-bearing: they are what makes the to-be-signed bytes
         * unpredictable against a chosen-prefix attack on the signature hash,
         * so where they come from is not an implementation detail.
         *
         * An earlier attempt called fhsm_rng_bytes directly. That was wrong
         * twice over: it dragged fhsm_drbg, the integrity check and the KATs
         * into every tool that links this file -- breaking the build of all
         * four -- and even linked, it would have drawn from the tool's own
         * generator rather than the module's, which is the opposite of what
         * it was meant to fix. */
        if (rng(rng_ctx, sn, sizeof sn) != FHSM_RV_OK) goto out;
        sn[0] &= 0x7F;                 /* positive INTEGER (RFC 5280 §4.1.2.2) */
        if (sn[0] == 0) sn[0] = 1;     /* and never a leading zero octet */
        BIGNUM *bn = BN_bin2bn(sn, (int)sizeof sn, NULL);
        if (!bn) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        ASN1_INTEGER *ai = BN_to_ASN1_INTEGER(bn, NULL);
        BN_free(bn);
        if (!ai) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        int ok = X509_set_serialNumber(x, ai) == 1;
        ASN1_INTEGER_free(ai);
        if (!ok) goto out;
    }

    if (!X509_gmtime_adj(X509_getm_notBefore(x), 0)) goto out;
    if (!X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 86400L)) goto out;

    /* Issuer is the CA's subject. Subject is the request's, unless the
     * operator replaced it. */
    if (X509_set_issuer_name(x, X509_get_subject_name(ca)) != 1) goto out;
    if (subject_override) {
        subj = name_from_oneline(subject_override);
        if (!subj) { rv = FHSM_RV_ARGUMENTS_BAD; goto out; }
        if (X509_set_subject_name(x, subj) != 1) goto out;
    } else {
        if (X509_set_subject_name(x, X509_REQ_get_subject_name(req)) != 1) goto out;
    }

    /* The requester's key, copied across verbatim. */
    {
        const unsigned char *pk = NULL; int pkl = 0;
        X509_PUBKEY_get0_param(NULL, &pk, &pkl, NULL, X509_REQ_get_X509_PUBKEY(req));
        ASN1_OBJECT *oid = OBJ_txt2obj(FHSM_COMPOSITE_OID_MLDSA65_ED25519, 1);
        uint8_t *penc = OPENSSL_memdup(pk, (size_t)pkl);
        if (!oid || !penc) { ASN1_OBJECT_free(oid); OPENSSL_free(penc);
                              rv = FHSM_RV_HOST_MEMORY; goto out; }
        if (X509_PUBKEY_set0_param(X509_get_X509_PUBKEY(x), oid, V_ASN1_UNDEF,
                                    NULL, penc, pkl) != 1) {
            ASN1_OBJECT_free(oid); OPENSSL_free(penc); goto out;
        }
    }

    /* ---- Extensions: the CA's, not the applicant's -------------------
     * Whatever the request asked for is not read. CA:FALSE is the one that
     * matters: an applicant that could obtain CA:TRUE could issue for any
     * name in the world under this root. */
    {
        X509_EXTENSION *bc = X509V3_EXT_conf_nid(NULL, NULL,
                                NID_basic_constraints, "critical,CA:FALSE");
        X509_EXTENSION *ku = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
                                "critical,digitalSignature,nonRepudiation");
        int ok = bc && ku && X509_add_ext(x, bc, -1) == 1
                        && X509_add_ext(x, ku, -1) == 1;
        X509_EXTENSION_free(bc); X509_EXTENSION_free(ku);
        if (!ok) goto out;
    }
    /* subjectKeyIdentifier over the applicant's key; authorityKeyIdentifier
     * from the CA's own, so a verifier can find the issuer without guessing. */
    {
        const unsigned char *pk = NULL; int pkl = 0;
        X509_PUBKEY_get0_param(NULL, &pk, &pkl, NULL, X509_REQ_get_X509_PUBKEY(req));
        uint8_t md[20];
        if (!key_id(pk, (size_t)pkl, md)) goto out;
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
        if (!os) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        int ok = ASN1_OCTET_STRING_set(os, md, 20) == 1;
        X509_EXTENSION *e = ok ? X509V3_EXT_i2d(NID_subject_key_identifier, 0, os)
                               : NULL;
        ok = e && X509_add_ext(x, e, -1) == 1;
        X509_EXTENSION_free(e); ASN1_OCTET_STRING_free(os);
        if (!ok) goto out;

        const ASN1_OCTET_STRING *caskid = X509_get0_subject_key_id(ca);
        if (caskid) {
            AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
            if (!akid) { rv = FHSM_RV_HOST_MEMORY; goto out; }
            akid->keyid = ASN1_OCTET_STRING_dup(caskid);
            X509_EXTENSION *ae = akid->keyid
                ? X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid) : NULL;
            ok = ae && X509_add_ext(x, ae, -1) == 1;
            X509_EXTENSION_free(ae); AUTHORITY_KEYID_free(akid);
            if (!ok) goto out;
        }
    }

    /* subjectAltName, from the operator's list. Non-critical: the subject is
     * always present here, and RFC 5280 §4.2.1.6 only requires criticality
     * when it is empty. */
    if (san) {
        X509_EXTENSION *e = NULL;
        rv = san_extension(san, &e);
        if (rv != FHSM_RV_OK) goto out;
        int ok = X509_add_ext(x, e, -1) == 1;
        X509_EXTENSION_free(e);
        if (!ok) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }
        rv = FHSM_RV_FUNCTION_FAILED;
    }

    /* cRLDistributionPoints, from the operator's list. Non-critical: RFC 5280
     * §4.2.1.13 says a CA SHOULD mark it so, and a client that cannot read it
     * must still be able to use the certificate. */
    if (crl_urls && n_crl_urls) {
        X509_EXTENSION *e = NULL;
        rv = crldp_extension(crl_urls, n_crl_urls, &e);
        if (rv != FHSM_RV_OK) goto out;
        int ok = X509_add_ext(x, e, -1) == 1;
        X509_EXTENSION_free(e);
        if (!ok) { rv = FHSM_RV_FUNCTION_FAILED; goto out; }
        rv = FHSM_RV_FUNCTION_FAILED;
    }

    if (!set_composite_algor((X509_ALGOR *)X509_get0_tbs_sigalg(x))) goto out;
    {
        const ASN1_BIT_STRING *cs = NULL; const X509_ALGOR *cala = NULL;
        X509_get0_signature(&cs, &cala, x);
        if (!cs || !cala) goto out;
        if (!set_composite_algor((X509_ALGOR *)cala)) goto out;

        int tl = i2d_re_X509_tbs(x, &tbs);
        if (tl <= 0) goto out;
        sig = OPENSSL_malloc(FHSM_COMPOSITE_SIG_MAX);
        if (!sig) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        size_t sl = FHSM_COMPOSITE_SIG_MAX;
        rv = sign(sign_ctx, tbs, (size_t)tl, sig, &sl);
        if (rv != FHSM_RV_OK) goto out;
        rv = FHSM_RV_FUNCTION_FAILED;
        ASN1_BIT_STRING *bs = (ASN1_BIT_STRING *)cs;
        if (ASN1_BIT_STRING_set(bs, sig, (int)sl) != 1) goto out;
        bs->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        bs->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    }

    {
        int n = i2d_X509(x, &der);
        if (n <= 0) goto out;
        if (*out_len < (size_t)n) { *out_len = (size_t)n;
                                     rv = FHSM_RV_BUFFER_TOO_SMALL; goto out; }
        memcpy(out, der, (size_t)n);
        *out_len = (size_t)n;
        rv = FHSM_RV_OK;
    }
out:
    OPENSSL_free(der); OPENSSL_free(tbs); OPENSSL_free(req_tbs);
    if (sig) { OPENSSL_cleanse(sig, FHSM_COMPOSITE_SIG_MAX); OPENSSL_free(sig); }
    X509_NAME_free(subj);
    X509_free(x); X509_free(ca); X509_REQ_free(req);
    return rv;
}

/* ===========================================================================
 * Revocation lists.
 *
 * See the commentary in fhsm_composite.h for why the TBSCertList is assembled
 * here instead of by OpenSSL. In short: there is no CRL equivalent of
 * X509_get0_tbs_sigalg, so the inner AlgorithmIdentifier cannot be set and
 * i2d_re_X509_CRL_tbs refuses to encode.
 *
 * The rule followed below is that nothing here decides how a value is
 * encoded -- only where it goes. Names, times, integers and extensions all
 * arrive already encoded by OpenSSL. What is written here is versions, tags
 * and lengths, and tests/test_composite_crl compares every byte of it against
 * OpenSSL's own output.
 * ========================================================================= */

/* v2. RFC 5280 5.1.2.1: a conforming CRL carrying extensions must be v2, and
 * this one always carries crlNumber. Written unconditionally so the field can
 * never be silently dropped along with the extensions. */
static const uint8_t CRL_VERSION_V2[] = { 0x02, 0x01, 0x01 };

fhsm_rv_t fhsm_composite_crl_tbs(const uint8_t *algid,    size_t algid_len,
                                  const uint8_t *issuer,   size_t issuer_len,
                                  const uint8_t *this_upd, size_t this_upd_len,
                                  const uint8_t *next_upd, size_t next_upd_len,
                                  const uint8_t *revoked,  size_t revoked_len,
                                  const uint8_t *exts,     size_t exts_len,
                                  uint8_t *out, size_t *out_len)
{
    if (!algid || !algid_len || !issuer || !issuer_len
        || !this_upd || !this_upd_len || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;

    /* A pointer without a length, or a length without a pointer, is a caller
     * bug that would otherwise encode a truncated field or skip a present
     * one. Neither is detectable downstream. */
    if ((next_upd == NULL) != (next_upd_len == 0)) return FHSM_RV_ARGUMENTS_BAD;
    if ((revoked  == NULL) != (revoked_len  == 0)) return FHSM_RV_ARGUMENTS_BAD;
    if ((exts     == NULL) != (exts_len     == 0)) return FHSM_RV_ARGUMENTS_BAD;

    /* Each part must start with the tag its position requires. This is the
     * cheap check that catches two buffers passed in the wrong order -- an
     * error that produces structurally valid DER describing something else
     * entirely, which no later stage would notice. */
    if (algid[0]  != 0x30) return FHSM_RV_ARGUMENTS_BAD;   /* SEQUENCE      */
    if (issuer[0] != 0x30) return FHSM_RV_ARGUMENTS_BAD;   /* RDNSequence   */
    if (this_upd[0] != 0x17 && this_upd[0] != 0x18)        /* UTC / Gen.    */
        return FHSM_RV_ARGUMENTS_BAD;
    if (next_upd && next_upd[0] != 0x17 && next_upd[0] != 0x18)
        return FHSM_RV_ARGUMENTS_BAD;
    if (revoked && revoked[0] != 0x30) return FHSM_RV_ARGUMENTS_BAD;
    if (exts    && exts[0]    != 0x30) return FHSM_RV_ARGUMENTS_BAD;

    /* crlExtensions is [0] EXPLICIT: the Extensions SEQUENCE goes inside a
     * context tag, it does not replace it. */
    uint8_t ext_hdr[4]; size_t ext_hdr_n = 0, ext_total = 0;
    if (exts) {
        ext_hdr_n = der_len(exts_len, ext_hdr, sizeof ext_hdr);
        if (!ext_hdr_n) return FHSM_RV_FUNCTION_FAILED;
        ext_total = 1 + ext_hdr_n + exts_len;
    }

    const size_t content = sizeof CRL_VERSION_V2 + algid_len + issuer_len
                         + this_upd_len + next_upd_len + revoked_len + ext_total;

    uint8_t sq[4]; size_t sq_n = der_len(content, sq, sizeof sq);
    if (!sq_n) return FHSM_RV_FUNCTION_FAILED;

    const size_t total = 1 + sq_n + content;
    if (*out_len < total) { *out_len = total; return FHSM_RV_BUFFER_TOO_SMALL; }

    uint8_t *c = out;
    *c++ = 0x30; memcpy(c, sq, sq_n); c += sq_n;
    memcpy(c, CRL_VERSION_V2, sizeof CRL_VERSION_V2); c += sizeof CRL_VERSION_V2;
    memcpy(c, algid, algid_len);         c += algid_len;
    memcpy(c, issuer, issuer_len);       c += issuer_len;
    memcpy(c, this_upd, this_upd_len);   c += this_upd_len;
    if (next_upd) { memcpy(c, next_upd, next_upd_len); c += next_upd_len; }
    if (revoked)  { memcpy(c, revoked, revoked_len);   c += revoked_len; }
    if (exts) {
        *c++ = 0xA0; memcpy(c, ext_hdr, ext_hdr_n); c += ext_hdr_n;
        memcpy(c, exts, exts_len); c += exts_len;
    }

    *out_len = (size_t)(c - out);
    return (*out_len == total) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

/* Wrap already-encoded content in a tag. Returns total bytes written, 0 if it
 * does not fit. */
static size_t tag_wrap(uint8_t tag, const uint8_t *content, size_t n,
                        uint8_t *out, size_t cap)
{
    uint8_t l[4]; size_t ln = der_len(n, l, sizeof l);
    if (!ln || cap < 1 + ln + n) return 0;
    out[0] = tag;
    memcpy(out + 1, l, ln);
    memcpy(out + 1 + ln, content, n);
    return 1 + ln + n;
}

/* Encode one revoked entry. OpenSSL builds the structure; this only hands it
 * the pieces. The serial arrives as an unsigned magnitude, so BN_bin2bn is
 * used to turn it into an INTEGER -- that adds the leading zero octet when
 * the top bit is set, which is what keeps a serial from being read as a
 * negative number by the verifier. */
static fhsm_rv_t revoked_one(const fhsm_composite_revoked_t *r,
                              uint8_t **der, int *der_len_out)
{
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    X509_REVOKED *x = X509_REVOKED_new();
    ASN1_INTEGER *sn = NULL;
    ASN1_TIME    *rd = NULL;
    BIGNUM       *bn = NULL;

    if (!x) return FHSM_RV_HOST_MEMORY;
    if (!r->serial || r->serial_len == 0) { rv = FHSM_RV_ARGUMENTS_BAD; goto out; }

    bn = BN_bin2bn(r->serial, (int)r->serial_len, NULL);
    if (!bn) { rv = FHSM_RV_HOST_MEMORY; goto out; }
    sn = BN_to_ASN1_INTEGER(bn, NULL);
    rd = ASN1_TIME_set(NULL, (time_t)r->date);
    if (!sn || !rd) { rv = FHSM_RV_HOST_MEMORY; goto out; }

    if (X509_REVOKED_set_serialNumber(x, sn) != 1) goto out;
    if (X509_REVOKED_set_revocationDate(x, rd) != 1) goto out;

    /* A reason is optional and stays optional. RFC 5280 5.3.1 gives the
     * codes; anything outside them would be a value a verifier cannot read,
     * so it is refused rather than written. removeFromCRL (8) belongs to
     * delta CRLs, which this does not produce. */
    if (r->reason >= 0) {
        if (r->reason == 7 || r->reason == 8 || r->reason > 10) {
            rv = FHSM_RV_ARGUMENTS_BAD; goto out;
        }
        ASN1_ENUMERATED *e = ASN1_ENUMERATED_new();
        X509_EXTENSION  *ext = NULL;
        int good = e && ASN1_ENUMERATED_set(e, r->reason) == 1
                && (ext = X509V3_EXT_i2d(NID_crl_reason, 0, e)) != NULL
                && X509_REVOKED_add_ext(x, ext, -1) == 1;
        X509_EXTENSION_free(ext); ASN1_ENUMERATED_free(e);
        if (!good) goto out;
    }

    *der = NULL;
    *der_len_out = i2d_X509_REVOKED(x, der);
    rv = (*der_len_out > 0) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
out:
    BN_free(bn); ASN1_INTEGER_free(sn); ASN1_TIME_free(rd);
    X509_REVOKED_free(x);
    return rv;
}

fhsm_rv_t fhsm_composite_crl(fhsm_composite_alg_t alg,
                              const uint8_t *ca_cert, size_t ca_cert_len,
                              const fhsm_composite_revoked_t *revoked,
                              size_t n_revoked,
                              uint64_t crl_number,
                              int days,
                              fhsm_composite_sign_cb sign, void *sign_ctx,
                              uint8_t *out, size_t *out_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
        || !ca_cert || !sign || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;
    if (days <= 0) return FHSM_RV_ARGUMENTS_BAD;
    if (n_revoked && !revoked) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    X509      *ca = NULL;
    ASN1_TIME *t1 = NULL, *t2 = NULL;
    uint8_t   *issuer = NULL, *this_u = NULL, *next_u = NULL;
    uint8_t   *rev_buf = NULL, *rev_seq = NULL;
    uint8_t   *ext_seq = NULL;
    uint8_t   *tbs = NULL, *sig = NULL;
    int issuer_n = 0, this_n = 0, next_n = 0;
    size_t rev_seq_n = 0, ext_seq_n = 0, tbs_n = 0;

    {
        const uint8_t *p = ca_cert;
        ca = d2i_X509(NULL, &p, (long)ca_cert_len);
    }
    if (!ca) return FHSM_RV_ARGUMENTS_BAD;

    /* ---- issuer and validity ------------------------------------------
     * The issuer of a CRL is the subject of the certificate that signs it.
     * Taking it from anywhere else would produce a list no verifier ties
     * back to this CA. */
    issuer_n = i2d_X509_NAME(X509_get_subject_name(ca), &issuer);
    if (issuer_n <= 0) goto out;

    {
        time_t now = time(NULL);
        t1 = ASN1_TIME_set(NULL, now);
        t2 = ASN1_TIME_set(NULL, now + (time_t)days * 86400);
        if (!t1 || !t2) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        this_n = i2d_ASN1_TIME(t1, &this_u);
        next_n = i2d_ASN1_TIME(t2, &next_u);
        if (this_n <= 0 || next_n <= 0) goto out;
    }

    /* ---- the revoked entries ------------------------------------------
     * Absent, not empty, when there is nothing to list: RFC 5280 5.1.2.6.
     * An empty SEQUENCE is a different encoding and some verifiers reject
     * it. */
    if (n_revoked) {
        size_t cap = 0, used = 0;
        for (size_t i = 0; i < n_revoked; i++) {
            uint8_t *d = NULL; int n = 0;
            rv = revoked_one(&revoked[i], &d, &n);
            if (rv != FHSM_RV_OK) { OPENSSL_free(d); goto out; }
            if (used + (size_t)n > cap) {
                size_t want = (used + (size_t)n) * 2 + 256;
                uint8_t *grown = OPENSSL_realloc(rev_buf, want);
                if (!grown) { OPENSSL_free(d); rv = FHSM_RV_HOST_MEMORY; goto out; }
                rev_buf = grown; cap = want;
            }
            memcpy(rev_buf + used, d, (size_t)n);
            used += (size_t)n;
            OPENSSL_free(d);
        }
        rv = FHSM_RV_FUNCTION_FAILED;
        rev_seq = OPENSSL_malloc(used + 8);
        if (!rev_seq) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        rev_seq_n = tag_wrap(0x30, rev_buf, used, rev_seq, used + 8);
        if (!rev_seq_n) goto out;
    }

    /* ---- crlExtensions: authorityKeyIdentifier and crlNumber -----------
     * crlNumber is what lets a verifier tell a newer list from an older one.
     * Without it, replaying yesterday's list hides today's revocations. */
    {
        uint8_t buf[512]; size_t used = 0;
        const ASN1_OCTET_STRING *skid = X509_get0_subject_key_id(ca);
        X509_EXTENSION *e1 = NULL, *e2 = NULL;
        AUTHORITY_KEYID *akid = NULL;
        ASN1_INTEGER *num = ASN1_INTEGER_new();
        int good = num != NULL;

        if (good && skid) {
            akid = AUTHORITY_KEYID_new();
            good = akid && (akid->keyid = ASN1_OCTET_STRING_dup(skid)) != NULL
                && (e1 = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid)) != NULL;
        }
        if (good)
            good = ASN1_INTEGER_set_uint64(num, crl_number) == 1
                && (e2 = X509V3_EXT_i2d(NID_crl_number, 0, num)) != NULL;

        X509_EXTENSION *both[2]; both[0] = e1; both[1] = e2;
        for (int i = 0; good && i < 2; i++) {
            if (!both[i]) continue;
            uint8_t *d = NULL;
            int n = i2d_X509_EXTENSION(both[i], &d);
            good = n > 0 && used + (size_t)n <= sizeof buf;
            if (good) { memcpy(buf + used, d, (size_t)n); used += (size_t)n; }
            OPENSSL_free(d);
        }
        X509_EXTENSION_free(e1); X509_EXTENSION_free(e2);
        AUTHORITY_KEYID_free(akid); ASN1_INTEGER_free(num);
        if (!good) goto out;

        ext_seq = OPENSSL_malloc(used + 8);
        if (!ext_seq) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        ext_seq_n = tag_wrap(0x30, buf, used, ext_seq, used + 8);
        if (!ext_seq_n) goto out;
    }

    /* ---- the TBSCertList ----------------------------------------------- */
    {
        /* Size query. The assembler refuses a NULL output -- rightly, since a
         * NULL there is a caller bug everywhere else -- so the probe is a
         * real buffer of length zero. */
        uint8_t probe[1]; size_t need = 0;
        rv = fhsm_composite_crl_tbs(ALGID_MLDSA65_ED25519,
                                     sizeof ALGID_MLDSA65_ED25519,
                                     issuer, (size_t)issuer_n,
                                     this_u, (size_t)this_n,
                                     next_u, (size_t)next_n,
                                     rev_seq, rev_seq_n,
                                     ext_seq, ext_seq_n,
                                     probe, &need);
        /* A NULL output with a zero size is the size query; anything other
         * than "too small" here means the parts themselves are wrong. */
        if (rv != FHSM_RV_BUFFER_TOO_SMALL) { if (rv == FHSM_RV_OK) rv = FHSM_RV_FUNCTION_FAILED; goto out; }
        tbs = OPENSSL_malloc(need);
        if (!tbs) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        tbs_n = need;
        rv = fhsm_composite_crl_tbs(ALGID_MLDSA65_ED25519,
                                     sizeof ALGID_MLDSA65_ED25519,
                                     issuer, (size_t)issuer_n,
                                     this_u, (size_t)this_n,
                                     next_u, (size_t)next_n,
                                     rev_seq, rev_seq_n,
                                     ext_seq, ext_seq_n,
                                     tbs, &tbs_n);
        if (rv != FHSM_RV_OK) goto out;
    }

    /* ---- sign, then the outer CertificateList --------------------------
     * Assembled here rather than through X509_CRL for the same reason the
     * TBSCertList is: the outer AlgorithmIdentifier would have to be a
     * composite one, and setting it through the API leaves the inner one
     * empty. Both are the same twelve bytes, and they must match -- a
     * verifier that finds them different is looking at a substituted
     * algorithm. */
    sig = OPENSSL_malloc(FHSM_COMPOSITE_SIG_MAX);
    if (!sig) { rv = FHSM_RV_HOST_MEMORY; goto out; }
    {
        size_t sl = FHSM_COMPOSITE_SIG_MAX;
        rv = sign(sign_ctx, tbs, tbs_n, sig, &sl);
        if (rv != FHSM_RV_OK) goto out;
        rv = FHSM_RV_FUNCTION_FAILED;

        /* BIT STRING: one "unused bits" octet, then the signature. */
        uint8_t bs_hdr[5]; size_t bs_content = 1 + sl;
        size_t bs_hdr_n = der_len(bs_content, bs_hdr, sizeof bs_hdr);
        if (!bs_hdr_n) goto out;

        const size_t content = tbs_n + sizeof ALGID_MLDSA65_ED25519
                             + 1 + bs_hdr_n + bs_content;
        uint8_t sq[5]; size_t sq_n = der_len(content, sq, sizeof sq);
        if (!sq_n) goto out;

        const size_t total = 1 + sq_n + content;
        if (*out_len < total) { *out_len = total; rv = FHSM_RV_BUFFER_TOO_SMALL; goto out; }

        uint8_t *c = out;
        *c++ = 0x30; memcpy(c, sq, sq_n); c += sq_n;
        memcpy(c, tbs, tbs_n); c += tbs_n;
        memcpy(c, ALGID_MLDSA65_ED25519, sizeof ALGID_MLDSA65_ED25519);
        c += sizeof ALGID_MLDSA65_ED25519;
        *c++ = 0x03; memcpy(c, bs_hdr, bs_hdr_n); c += bs_hdr_n;
        *c++ = 0x00;
        memcpy(c, sig, sl); c += sl;

        *out_len = (size_t)(c - out);
        rv = (*out_len == total) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
    }
out:
    OPENSSL_free(issuer); OPENSSL_free(this_u); OPENSSL_free(next_u);
    OPENSSL_free(rev_buf); OPENSSL_free(rev_seq);
    OPENSSL_free(ext_seq); OPENSSL_free(tbs);
    if (sig) { OPENSSL_cleanse(sig, FHSM_COMPOSITE_SIG_MAX); OPENSSL_free(sig); }
    ASN1_TIME_free(t1); ASN1_TIME_free(t2);
    X509_free(ca);
    return rv;
}

/* ===========================================================================
 * OCSP (RFC 6960), assembled by hand.
 *
 * Same reason as the CRL and the CMS: OCSP_basic_sign wants a key OpenSSL can
 * sign with, and a composite key is not one. It signs Ed25519 perfectly well,
 * which is what makes the differential test possible -- the reference and this
 * encoder are compared on the one algorithm both can produce.
 *
 * One difference from the CRL, and it shapes the test: i2d_re_X509_CRL_tbs is
 * public, i2d_OCSP_RESPDATA is not. OCSP_RESPDATA is opaque, declared only in
 * crypto/ocsp/ocsp_local.h. The test therefore slices tbsResponseData out of
 * the DER -- it is the first inner TLV of BasicOCSPResponse, which is by
 * construction exactly what OpenSSL signed. No private header, no symbol that
 * could disappear between releases.
 * ========================================================================= */

fhsm_rv_t fhsm_composite_ocsp_single(const fhsm_composite_ocsp_single_t *s,
                                      uint8_t *out, size_t *out_len)
{
    if (!s || !out || !out_len) return FHSM_RV_ARGUMENTS_BAD;
    if (!s->cert_id || !s->cert_id_len)   return FHSM_RV_ARGUMENTS_BAD;
    if (!s->this_upd || !s->this_upd_len) return FHSM_RV_ARGUMENTS_BAD;
    if (s->cert_id[0]  != 0x30) return FHSM_RV_ARGUMENTS_BAD;  /* CertID SEQ  */
    if (s->this_upd[0] != 0x18) return FHSM_RV_ARGUMENTS_BAD;  /* GeneralizedTime */
    if ((s->next_upd == NULL) != (s->next_upd_len == 0)) return FHSM_RV_ARGUMENTS_BAD;
    if (s->next_upd && s->next_upd[0] != 0x18) return FHSM_RV_ARGUMENTS_BAD;

    /* A revocation time belongs to a revoked certificate and to no other. The
     * structure cannot express "good, revoked at 3pm", so the contradiction is
     * refused here rather than silently dropped -- an operator who passes a
     * time expects it to appear. */
    if (s->status == FHSM_OCSP_REVOKED) {
        if (!s->revoked_at || !s->revoked_at_len) return FHSM_RV_ARGUMENTS_BAD;
        if (s->revoked_at[0] != 0x18)             return FHSM_RV_ARGUMENTS_BAD;
    } else if (s->status == FHSM_OCSP_GOOD || s->status == FHSM_OCSP_UNKNOWN) {
        if (s->revoked_at || s->revoked_at_len)   return FHSM_RV_ARGUMENTS_BAD;
        if (s->reason >= 0)                       return FHSM_RV_ARGUMENTS_BAD;
    } else {
        return FHSM_RV_ARGUMENTS_BAD;
    }

    /* ---- CertStatus ----------------------------------------------------
     * IMPLICIT tagging replaces the tag but keeps the constructed bit of the
     * type underneath. That is the whole subtlety here, and it splits the
     * three cases two ways:
     *
     *   good     [0] IMPLICIT NULL         -> 0x80, NULL is primitive
     *   revoked  [1] IMPLICIT RevokedInfo  -> 0xA1, SEQUENCE is constructed
     *   unknown  [2] IMPLICIT UnknownInfo  -> 0x82, UnknownInfo is NULL
     *
     * Writing 0xA0 and 0xA2 for good and unknown -- which is what you get by
     * assuming context tags are always constructed -- produces DER that looks
     * right, has the correct length, and that no OCSP parser will accept: the
     * CHOICE matches on the tag, and 0xA0 is not one of its alternatives. The
     * differential test caught exactly this, on the two cases whose underlying
     * type is primitive, while the revoked cases passed. */
    uint8_t st[32]; size_t st_n = 0;
    if (s->status == FHSM_OCSP_GOOD)    { st[0] = 0x80; st[1] = 0x00; st_n = 2; }
    if (s->status == FHSM_OCSP_UNKNOWN) { st[0] = 0x82; st[1] = 0x00; st_n = 2; }
    if (s->status == FHSM_OCSP_REVOKED) {
        uint8_t inner[32]; size_t in_n = 0;
        if (s->revoked_at_len > sizeof inner - 8) return FHSM_RV_ARGUMENTS_BAD;
        memcpy(inner, s->revoked_at, s->revoked_at_len); in_n = s->revoked_at_len;
        if (s->reason >= 0) {
            /* revocationReason is [0] EXPLICIT CRLReason: an ENUMERATED
             * inside the context tag. */
            if (s->reason > 10) return FHSM_RV_ARGUMENTS_BAD;
            inner[in_n++] = 0xA0; inner[in_n++] = 0x03;
            inner[in_n++] = 0x0A; inner[in_n++] = 0x01;
            inner[in_n++] = (uint8_t)s->reason;
        }
        st_n = tag_wrap(0xA1, inner, in_n, st, sizeof st);
        if (!st_n) return FHSM_RV_FUNCTION_FAILED;
    }

    /* nextUpdate is [0] EXPLICIT: the GeneralizedTime goes inside the tag. */
    uint8_t nu_hdr[4]; size_t nu_hdr_n = 0, nu_total = 0;
    if (s->next_upd) {
        nu_hdr_n = der_len(s->next_upd_len, nu_hdr, sizeof nu_hdr);
        if (!nu_hdr_n) return FHSM_RV_FUNCTION_FAILED;
        nu_total = 1 + nu_hdr_n + s->next_upd_len;
    }

    const size_t content = s->cert_id_len + st_n + s->this_upd_len + nu_total;
    uint8_t sq[5]; size_t sq_n = der_len(content, sq, sizeof sq);
    if (!sq_n) return FHSM_RV_FUNCTION_FAILED;

    const size_t total = 1 + sq_n + content;
    if (*out_len < total) { *out_len = total; return FHSM_RV_BUFFER_TOO_SMALL; }

    uint8_t *c = out;
    *c++ = 0x30; memcpy(c, sq, sq_n); c += sq_n;
    memcpy(c, s->cert_id, s->cert_id_len);   c += s->cert_id_len;
    memcpy(c, st, st_n);                     c += st_n;
    memcpy(c, s->this_upd, s->this_upd_len); c += s->this_upd_len;
    if (s->next_upd) {
        *c++ = 0xA0; memcpy(c, nu_hdr, nu_hdr_n); c += nu_hdr_n;
        memcpy(c, s->next_upd, s->next_upd_len);  c += s->next_upd_len;
    }

    *out_len = (size_t)(c - out);
    return (*out_len == total) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

fhsm_rv_t fhsm_composite_ocsp_tbs(const uint8_t *responder_id, size_t responder_id_len,
                                   const uint8_t *produced_at,  size_t produced_at_len,
                                   const uint8_t *responses,    size_t responses_len,
                                   const uint8_t *exts,         size_t exts_len,
                                   uint8_t *out, size_t *out_len)
{
    if (!responder_id || !responder_id_len || !produced_at || !produced_at_len
        || !responses || !responses_len || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;
    if ((exts == NULL) != (exts_len == 0)) return FHSM_RV_ARGUMENTS_BAD;

    /* Same positional tag check as the CRL, for the same reason: two buffers
     * swapped produce valid DER describing something else. */
    if (responder_id[0] != 0xA1 && responder_id[0] != 0xA2)
        return FHSM_RV_ARGUMENTS_BAD;                       /* byName / byKey */
    if (produced_at[0] != 0x18) return FHSM_RV_ARGUMENTS_BAD;
    if (responses[0]   != 0x30) return FHSM_RV_ARGUMENTS_BAD;
    if (exts && exts[0] != 0x30) return FHSM_RV_ARGUMENTS_BAD;

    uint8_t ext_hdr[5]; size_t ext_hdr_n = 0, ext_total = 0;
    if (exts) {
        ext_hdr_n = der_len(exts_len, ext_hdr, sizeof ext_hdr);
        if (!ext_hdr_n) return FHSM_RV_FUNCTION_FAILED;
        ext_total = 1 + ext_hdr_n + exts_len;               /* [1] EXPLICIT */
    }

    const size_t content = responder_id_len + produced_at_len
                         + responses_len + ext_total;
    uint8_t sq[5]; size_t sq_n = der_len(content, sq, sizeof sq);
    if (!sq_n) return FHSM_RV_FUNCTION_FAILED;

    const size_t total = 1 + sq_n + content;
    if (*out_len < total) { *out_len = total; return FHSM_RV_BUFFER_TOO_SMALL; }

    uint8_t *c = out;
    *c++ = 0x30; memcpy(c, sq, sq_n); c += sq_n;
    memcpy(c, responder_id, responder_id_len); c += responder_id_len;
    memcpy(c, produced_at, produced_at_len);   c += produced_at_len;
    memcpy(c, responses, responses_len);       c += responses_len;
    if (exts) {
        *c++ = 0xA1; memcpy(c, ext_hdr, ext_hdr_n); c += ext_hdr_n;
        memcpy(c, exts, exts_len); c += exts_len;
    }

    *out_len = (size_t)(c - out);
    return (*out_len == total) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

fhsm_rv_t fhsm_composite_ocsp(fhsm_composite_alg_t alg,
                               const uint8_t *responder_cert, size_t responder_cert_len,
                               const uint8_t *produced_at, size_t produced_at_len,
                               const fhsm_composite_ocsp_single_t *singles, size_t n,
                               const uint8_t *exts, size_t exts_len,
                               fhsm_composite_sign_cb sign, void *sign_ctx,
                               uint8_t *out, size_t *out_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
        || !responder_cert || !responder_cert_len
        || !produced_at || !produced_at_len
        || !singles || !n || !sign || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;
    if ((exts == NULL) != (exts_len == 0)) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    X509    *rc  = NULL;
    uint8_t *nm  = NULL, *rid = NULL, *sr = NULL, *sr_seq = NULL;
    uint8_t *tbs = NULL, *sig = NULL;
    int nm_n = 0;
    size_t rid_n = 0, sr_seq_n = 0, tbs_n = 0;

    {
        const uint8_t *p = responder_cert;
        rc = d2i_X509(NULL, &p, (long)responder_cert_len);
    }
    if (!rc) return FHSM_RV_ARGUMENTS_BAD;

    /* ---- responderID -----------------------------------------------------
     * byName, taken from the subject of the certificate that signs. Deriving
     * it from anywhere else would let the name and the key disagree, and a
     * client matching one against the other would be right to refuse.
     *
     * The CHOICE is EXPLICIT, so the Name SEQUENCE goes inside [1] rather
     * than having its tag replaced. */
    nm_n = i2d_X509_NAME(X509_get_subject_name(rc), &nm);
    if (nm_n <= 0) goto out;
    rid = OPENSSL_malloc((size_t)nm_n + 8);
    if (!rid) { rv = FHSM_RV_HOST_MEMORY; goto out; }
    rid_n = tag_wrap(0xA1, nm, (size_t)nm_n, rid, (size_t)nm_n + 8);
    if (!rid_n) goto out;

    /* ---- the SingleResponses --------------------------------------------- */
    {
        size_t cap = 0, used = 0;
        for (size_t i = 0; i < n; i++) {
            size_t need = 0;
            uint8_t probe[1];
            rv = fhsm_composite_ocsp_single(&singles[i], probe, &need);
            if (rv != FHSM_RV_BUFFER_TOO_SMALL) {
                if (rv == FHSM_RV_OK) rv = FHSM_RV_FUNCTION_FAILED;
                goto out;
            }
            if (used + need > cap) {
                size_t want = (used + need) * 2 + 256;
                uint8_t *grown = OPENSSL_realloc(sr, want);
                if (!grown) { rv = FHSM_RV_HOST_MEMORY; goto out; }
                sr = grown; cap = want;
            }
            size_t got = cap - used;
            rv = fhsm_composite_ocsp_single(&singles[i], sr + used, &got);
            if (rv != FHSM_RV_OK) goto out;
            used += got;
        }
        rv = FHSM_RV_FUNCTION_FAILED;
        sr_seq = OPENSSL_malloc(used + 8);
        if (!sr_seq) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        sr_seq_n = tag_wrap(0x30, sr, used, sr_seq, used + 8);
        if (!sr_seq_n) goto out;
    }

    /* ---- tbsResponseData -------------------------------------------------- */
    {
        uint8_t probe[1]; size_t need = 0;
        rv = fhsm_composite_ocsp_tbs(rid, rid_n, produced_at, produced_at_len,
                                      sr_seq, sr_seq_n, exts, exts_len, probe, &need);
        if (rv != FHSM_RV_BUFFER_TOO_SMALL) {
            if (rv == FHSM_RV_OK) rv = FHSM_RV_FUNCTION_FAILED;
            goto out;
        }
        tbs = OPENSSL_malloc(need);
        if (!tbs) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        tbs_n = need;
        rv = fhsm_composite_ocsp_tbs(rid, rid_n, produced_at, produced_at_len,
                                      sr_seq, sr_seq_n, exts, exts_len, tbs, &tbs_n);
        if (rv != FHSM_RV_OK) goto out;
    }

    /* ---- sign, then the BasicOCSPResponse --------------------------------
     * certs [0] carries the responder certificate. RFC 6960 §4.2.2.2 lets a
     * client accept a response signed by a delegate the CA designated, and it
     * can only check that if the certificate travels with the response. For a
     * composite responder it matters twice over: nothing else on the client's
     * disk holds a key it can parse. */
    sig = OPENSSL_malloc(FHSM_COMPOSITE_SIG_MAX);
    if (!sig) { rv = FHSM_RV_HOST_MEMORY; goto out; }
    {
        size_t sl = FHSM_COMPOSITE_SIG_MAX;
        rv = sign(sign_ctx, tbs, tbs_n, sig, &sl);
        if (rv != FHSM_RV_OK) goto out;
        rv = FHSM_RV_FUNCTION_FAILED;

        uint8_t bs_hdr[5]; size_t bs_content = 1 + sl;
        size_t bs_hdr_n = der_len(bs_content, bs_hdr, sizeof bs_hdr);
        if (!bs_hdr_n) goto out;

        /* certs [0] EXPLICIT SEQUENCE OF Certificate -- two wrappers, and
         * both are needed: the inner SEQUENCE is the list, the outer tag says
         * which optional field the list is. */
        uint8_t inner_hdr[5], outer_hdr[5];
        size_t inner_hdr_n = der_len(responder_cert_len, inner_hdr, sizeof inner_hdr);
        if (!inner_hdr_n) goto out;
        size_t inner_total = 1 + inner_hdr_n + responder_cert_len;
        size_t outer_hdr_n = der_len(inner_total, outer_hdr, sizeof outer_hdr);
        if (!outer_hdr_n) goto out;
        size_t certs_total = 1 + outer_hdr_n + inner_total;

        const size_t content = tbs_n + sizeof ALGID_MLDSA65_ED25519
                             + 1 + bs_hdr_n + bs_content + certs_total;
        uint8_t sq[5]; size_t sq_n = der_len(content, sq, sizeof sq);
        if (!sq_n) goto out;

        const size_t total = 1 + sq_n + content;
        if (*out_len < total) { *out_len = total; rv = FHSM_RV_BUFFER_TOO_SMALL; goto out; }

        uint8_t *c = out;
        *c++ = 0x30; memcpy(c, sq, sq_n); c += sq_n;
        memcpy(c, tbs, tbs_n); c += tbs_n;
        memcpy(c, ALGID_MLDSA65_ED25519, sizeof ALGID_MLDSA65_ED25519);
        c += sizeof ALGID_MLDSA65_ED25519;
        *c++ = 0x03; memcpy(c, bs_hdr, bs_hdr_n); c += bs_hdr_n;
        *c++ = 0x00; memcpy(c, sig, sl); c += sl;
        *c++ = 0xA0; memcpy(c, outer_hdr, outer_hdr_n); c += outer_hdr_n;
        *c++ = 0x30; memcpy(c, inner_hdr, inner_hdr_n); c += inner_hdr_n;
        memcpy(c, responder_cert, responder_cert_len); c += responder_cert_len;

        *out_len = (size_t)(c - out);
        rv = (*out_len == total) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
    }

out:
    OPENSSL_free(nm); OPENSSL_free(rid);
    OPENSSL_free(sr); OPENSSL_free(sr_seq);
    OPENSSL_free(tbs);
    if (sig) { OPENSSL_cleanse(sig, FHSM_COMPOSITE_SIG_MAX); OPENSSL_free(sig); }
    X509_free(rc);
    return rv;
}

/* ===========================================================================
 * CMS SignedData (RFC 5652), detached, signed attributes.
 *
 * See the header for why this is assembled by hand. In short: OpenSSL builds
 * the envelope but refuses the SignerInfo, because CMS_add1_signer needs a
 * public key it cannot load from a composite certificate.
 * ========================================================================= */

/* id-signedData 1.2.840.113549.1.7.2, as a complete OID TLV. */
static const uint8_t OID_SIGNED_DATA[] = {
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
};
/* id-data 1.2.840.113549.1.7.1 -- the eContentType of a plain signature. */
static const uint8_t OID_DATA[] = {
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
};

/* CMSVersion 1: the version that goes with the issuerAndSerialNumber form of
 * SignerIdentifier (RFC 5652 §5.3). Using subjectKeyIdentifier would make it
 * 3, so the two cannot be chosen independently. */
static const uint8_t CMS_VERSION_1[] = { 0x02, 0x01, 0x01 };

fhsm_rv_t fhsm_composite_cms_signerinfo(const uint8_t *issuer, size_t issuer_len,
                                         const uint8_t *serial, size_t serial_len,
                                         const uint8_t *digalg, size_t digalg_len,
                                         const uint8_t *sattrs, size_t sattrs_len,
                                         const uint8_t *sigalg, size_t sigalg_len,
                                         const uint8_t *sig,    size_t sig_len,
                                         uint8_t *out, size_t *out_len)
{
    if (!issuer || !issuer_len || !serial || !serial_len || !digalg || !digalg_len
        || !sattrs || !sattrs_len || !sigalg || !sigalg_len || !sig || !sig_len
        || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;

    /* Shape checks, same reasoning as the TBSCertList assembler: two buffers
     * passed in the wrong order produce valid DER describing something else,
     * which nothing downstream would notice. */
    if (issuer[0] != 0x30) return FHSM_RV_ARGUMENTS_BAD;   /* Name           */
    if (serial[0] != 0x02) return FHSM_RV_ARGUMENTS_BAD;   /* INTEGER        */
    if (digalg[0] != 0x30) return FHSM_RV_ARGUMENTS_BAD;   /* AlgorithmId    */
    if (sigalg[0] != 0x30) return FHSM_RV_ARGUMENTS_BAD;
    /* And the one that matters most: the attributes must arrive in the form
     * that was signed, not the form that is transmitted. Accepting 0xA0 here
     * would silently sign one encoding and send another. */
    if (sattrs[0] != 0x31) return FHSM_RV_ARGUMENTS_BAD;   /* SET OF         */

    /* IssuerAndSerialNumber ::= SEQUENCE { Name, CertificateSerialNumber } */
    const size_t ias_content = issuer_len + serial_len;
    uint8_t ias_l[5]; size_t ias_ln = der_len(ias_content, ias_l, sizeof ias_l);
    if (!ias_ln) return FHSM_RV_FUNCTION_FAILED;
    const size_t ias_total = 1 + ias_ln + ias_content;

    /* signature is an OCTET STRING here, not a BIT STRING -- CMS differs from
     * X.509 on this and the two are easy to confuse. */
    uint8_t sig_l[5]; size_t sig_ln = der_len(sig_len, sig_l, sizeof sig_l);
    if (!sig_ln) return FHSM_RV_FUNCTION_FAILED;
    const size_t sig_total = 1 + sig_ln + sig_len;

    /* The retag: same content, same length, [0] IMPLICIT instead of SET OF.
     * Only the identifier octet changes, which is what "IMPLICIT" means. */
    const size_t attr_total = sattrs_len;

    const size_t content = sizeof CMS_VERSION_1 + ias_total + digalg_len
                         + attr_total + sigalg_len + sig_total;
    uint8_t sq[5]; size_t sq_n = der_len(content, sq, sizeof sq);
    if (!sq_n) return FHSM_RV_FUNCTION_FAILED;
    const size_t total = 1 + sq_n + content;
    if (*out_len < total) { *out_len = total; return FHSM_RV_BUFFER_TOO_SMALL; }

    uint8_t *c = out;
    *c++ = 0x30; memcpy(c, sq, sq_n); c += sq_n;
    memcpy(c, CMS_VERSION_1, sizeof CMS_VERSION_1); c += sizeof CMS_VERSION_1;
    *c++ = 0x30; memcpy(c, ias_l, ias_ln); c += ias_ln;
    memcpy(c, issuer, issuer_len); c += issuer_len;
    memcpy(c, serial, serial_len); c += serial_len;
    memcpy(c, digalg, digalg_len); c += digalg_len;
    memcpy(c, sattrs, sattrs_len); c += sattrs_len;
    c[-(ptrdiff_t)sattrs_len] = 0xA0;            /* SET OF -> [0] IMPLICIT */
    memcpy(c, sigalg, sigalg_len); c += sigalg_len;
    *c++ = 0x04; memcpy(c, sig_l, sig_ln); c += sig_ln;
    memcpy(c, sig, sig_len); c += sig_len;

    *out_len = (size_t)(c - out);
    return (*out_len == total) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

fhsm_rv_t fhsm_composite_cms_wrap(const uint8_t *digalg, size_t digalg_len,
                                   const uint8_t *certs,  size_t certs_len,
                                   const uint8_t *signerinfo, size_t si_len,
                                   uint8_t *out, size_t *out_len)
{
    if (!digalg || !digalg_len || !signerinfo || !si_len || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;
    if (digalg[0] != 0x30 || signerinfo[0] != 0x30) return FHSM_RV_ARGUMENTS_BAD;
    if ((certs == NULL) != (certs_len == 0)) return FHSM_RV_ARGUMENTS_BAD;
    if (certs && certs[0] != 0x31) return FHSM_RV_ARGUMENTS_BAD;  /* SET OF */

    /* digestAlgorithms ::= SET OF, one entry. */
    uint8_t da_l[5]; size_t da_ln = der_len(digalg_len, da_l, sizeof da_l);
    if (!da_ln) return FHSM_RV_FUNCTION_FAILED;
    const size_t da_total = 1 + da_ln + digalg_len;

    /* EncapsulatedContentInfo with eContent absent -- this is what makes the
     * signature detached, and it is one omitted field rather than a flag. */
    uint8_t ec_l[5]; size_t ec_ln = der_len(sizeof OID_DATA, ec_l, sizeof ec_l);
    if (!ec_ln) return FHSM_RV_FUNCTION_FAILED;
    const size_t ec_total = 1 + ec_ln + sizeof OID_DATA;

    /* certificates [0] IMPLICIT CertificateSet: the SET OF retagged, again
     * only the identifier octet. */
    const size_t certs_total = certs ? certs_len : 0;

    uint8_t si_l[5]; size_t si_ln = der_len(si_len, si_l, sizeof si_l);
    if (!si_ln) return FHSM_RV_FUNCTION_FAILED;
    const size_t sis_total = 1 + si_ln + si_len;      /* SET OF SignerInfo */

    const size_t sd_content = sizeof CMS_VERSION_1 + da_total + ec_total
                            + certs_total + sis_total;
    uint8_t sd_l[5]; size_t sd_ln = der_len(sd_content, sd_l, sizeof sd_l);
    if (!sd_ln) return FHSM_RV_FUNCTION_FAILED;
    const size_t sd_total = 1 + sd_ln + sd_content;

    /* content [0] EXPLICIT SignedData -- EXPLICIT here, unlike the two
     * IMPLICIT retags above, so the SEQUENCE stays inside its context tag. */
    uint8_t c0_l[5]; size_t c0_ln = der_len(sd_total, c0_l, sizeof c0_l);
    if (!c0_ln) return FHSM_RV_FUNCTION_FAILED;
    const size_t c0_total = 1 + c0_ln + sd_total;

    const size_t ci_content = sizeof OID_SIGNED_DATA + c0_total;
    uint8_t ci_l[5]; size_t ci_ln = der_len(ci_content, ci_l, sizeof ci_l);
    if (!ci_ln) return FHSM_RV_FUNCTION_FAILED;
    const size_t total = 1 + ci_ln + ci_content;
    if (*out_len < total) { *out_len = total; return FHSM_RV_BUFFER_TOO_SMALL; }

    uint8_t *c = out;
    *c++ = 0x30; memcpy(c, ci_l, ci_ln); c += ci_ln;
    memcpy(c, OID_SIGNED_DATA, sizeof OID_SIGNED_DATA); c += sizeof OID_SIGNED_DATA;
    *c++ = 0xA0; memcpy(c, c0_l, c0_ln); c += c0_ln;
    *c++ = 0x30; memcpy(c, sd_l, sd_ln); c += sd_ln;
    memcpy(c, CMS_VERSION_1, sizeof CMS_VERSION_1); c += sizeof CMS_VERSION_1;
    *c++ = 0x31; memcpy(c, da_l, da_ln); c += da_ln;
    memcpy(c, digalg, digalg_len); c += digalg_len;
    *c++ = 0x30; memcpy(c, ec_l, ec_ln); c += ec_ln;
    memcpy(c, OID_DATA, sizeof OID_DATA); c += sizeof OID_DATA;
    if (certs) {
        memcpy(c, certs, certs_len); c += certs_len;
        c[-(ptrdiff_t)certs_len] = 0xA0;         /* SET OF -> [0] IMPLICIT */
    }
    *c++ = 0x31; memcpy(c, si_l, si_ln); c += si_ln;
    memcpy(c, signerinfo, si_len); c += si_len;

    *out_len = (size_t)(c - out);
    return (*out_len == total) ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

/* Build the two signed attributes RFC 5652 §5.3 requires when signedAttrs is
 * present -- contentType and messageDigest -- as a DER SET OF, the form that
 * gets signed.
 *
 * OpenSSL encodes each attribute; the SET OF ordering is done here because
 * i2d_ASN1_SET_OF_X509_ATTRIBUTE is not public in OpenSSL 3. X.690 §11.6
 * requires the members of a SET OF to appear in ascending order of their
 * encodings, compared as octet strings. Getting that wrong produces a
 * structure that encodes and parses and simply is not DER -- and since the
 * signature covers these exact bytes, a verifier that re-sorts them computes
 * a different digest and rejects a signature that was never wrong.
 *
 * With two members the sort is one comparison, written out rather than hidden
 * in a qsort so the rule is visible next to the code that depends on it.
 */
static int der_setof_before(const uint8_t *a, size_t na,
                             const uint8_t *b, size_t nb) {
    size_t n = na < nb ? na : nb;
    int c = memcmp(a, b, n);
    if (c) return c < 0;
    return na < nb;          /* a prefix sorts before what extends it */
}

static fhsm_rv_t cms_signed_attrs(const uint8_t *digest, size_t digest_len,
                                   uint8_t **out, int *out_len)
{
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    X509_ATTRIBUTE *a_ct = X509_ATTRIBUTE_new();
    X509_ATTRIBUTE *a_md = X509_ATTRIBUTE_new();
    ASN1_OCTET_STRING *md = ASN1_OCTET_STRING_new();
    uint8_t *e_ct = NULL, *e_md = NULL, *buf = NULL;
    int n_ct = 0, n_md = 0;

    if (!a_ct || !a_md || !md) { rv = FHSM_RV_HOST_MEMORY; goto out; }
    if (ASN1_OCTET_STRING_set(md, digest, (int)digest_len) != 1) goto out;

    if (X509_ATTRIBUTE_set1_object(a_ct, OBJ_nid2obj(NID_pkcs9_contentType)) != 1)
        goto out;
    if (X509_ATTRIBUTE_set1_data(a_ct, V_ASN1_OBJECT,
                                  OBJ_nid2obj(NID_pkcs7_data), -1) != 1) goto out;
    if (X509_ATTRIBUTE_set1_object(a_md, OBJ_nid2obj(NID_pkcs9_messageDigest)) != 1)
        goto out;
    if (X509_ATTRIBUTE_set1_data(a_md, V_ASN1_OCTET_STRING,
                                  ASN1_STRING_get0_data((ASN1_STRING *)md),
                                  ASN1_STRING_length((ASN1_STRING *)md)) != 1)
        goto out;

    n_ct = i2d_X509_ATTRIBUTE(a_ct, &e_ct);
    n_md = i2d_X509_ATTRIBUTE(a_md, &e_md);
    if (n_ct <= 0 || n_md <= 0) goto out;

    const uint8_t *first = e_ct, *second = e_md;
    size_t nf = (size_t)n_ct, ns = (size_t)n_md;
    if (!der_setof_before(e_ct, (size_t)n_ct, e_md, (size_t)n_md)) {
        first = e_md; nf = (size_t)n_md;
        second = e_ct; ns = (size_t)n_ct;
    }

    const size_t content = nf + ns;
    uint8_t l[5]; size_t ln = der_len(content, l, sizeof l);
    if (!ln) goto out;
    buf = OPENSSL_malloc(1 + ln + content);
    if (!buf) { rv = FHSM_RV_HOST_MEMORY; goto out; }
    buf[0] = 0x31; memcpy(buf + 1, l, ln);
    memcpy(buf + 1 + ln, first, nf);
    memcpy(buf + 1 + ln + nf, second, ns);

    *out = buf; buf = NULL;
    *out_len = (int)(1 + ln + content);
    rv = FHSM_RV_OK;
out:
    OPENSSL_free(e_ct); OPENSSL_free(e_md); OPENSSL_free(buf);
    X509_ATTRIBUTE_free(a_ct); X509_ATTRIBUTE_free(a_md);
    ASN1_OCTET_STRING_free(md);
    return rv;
}

fhsm_rv_t fhsm_composite_cms(fhsm_composite_alg_t alg,
                              const uint8_t *cert, size_t cert_len,
                              const uint8_t *digest, size_t digest_len,
                              fhsm_composite_sign_cb sign, void *sign_ctx,
                              uint8_t *out, size_t *out_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
        || !cert || !digest || !sign || !out || !out_len)
        return FHSM_RV_ARGUMENTS_BAD;
    /* The digest must be the algorithm's pre-hash length. A shorter one is a
     * caller who hashed with something else, and the messageDigest attribute
     * would then attest to a digest no verifier recomputes. */
    if (digest_len != fhsm_composite_ph_len(alg)) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    X509 *x = NULL;
    uint8_t *attrs = NULL, *d_iss = NULL, *d_ser = NULL, *d_cert = NULL;
    uint8_t *sig = NULL, *si = NULL;
    int n_attrs = 0, n_iss = 0, n_ser = 0, n_cert = 0;

    { const uint8_t *p = cert; x = d2i_X509(NULL, &p, (long)cert_len); }
    if (!x) return FHSM_RV_ARGUMENTS_BAD;

    rv = cms_signed_attrs(digest, digest_len, &attrs, &n_attrs);
    if (rv != FHSM_RV_OK) goto out;
    rv = FHSM_RV_FUNCTION_FAILED;

    /* The signature covers the attributes, not the content -- which is why a
     * file of any size costs one digest pass. RFC 5652 §5.4: the SET OF
     * encoding is what is signed, and that is exactly what
     * i2d_ASN1_SET_OF_X509_ATTRIBUTE just produced. */
    sig = OPENSSL_malloc(FHSM_COMPOSITE_SIG_MAX);
    if (!sig) { rv = FHSM_RV_HOST_MEMORY; goto out; }
    size_t slen = FHSM_COMPOSITE_SIG_MAX;
    rv = sign(sign_ctx, attrs, (size_t)n_attrs, sig, &slen);
    if (rv != FHSM_RV_OK) goto out;
    rv = FHSM_RV_FUNCTION_FAILED;

    n_iss  = i2d_X509_NAME(X509_get_issuer_name(x), &d_iss);
    n_ser  = i2d_ASN1_INTEGER(X509_get_serialNumber(x), &d_ser);
    n_cert = i2d_X509(x, &d_cert);
    if (n_iss <= 0 || n_ser <= 0 || n_cert <= 0) goto out;

    /* SHA-512 as the digestAlgorithm, which is the composite pre-hash: a
     * verifier recomputing the messageDigest has to use the same function,
     * and this field is where it learns which. */
    uint8_t digalg[16];
    {
        X509_ALGOR *a = X509_ALGOR_new();
        if (!a) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        int okalg = X509_ALGOR_set0(a, OBJ_nid2obj(NID_sha512), V_ASN1_UNDEF, NULL);
        uint8_t *d = NULL; int n = okalg ? i2d_X509_ALGOR(a, &d) : -1;
        if (n > 0 && (size_t)n <= sizeof digalg) memcpy(digalg, d, (size_t)n);
        OPENSSL_free(d); X509_ALGOR_free(a);
        if (n <= 0 || (size_t)n > sizeof digalg) goto out;

        /* certificates [0]: the signer's own, as a SET OF of one. */
        uint8_t cs_l[5]; size_t cs_ln = der_len((size_t)n_cert, cs_l, sizeof cs_l);
        if (!cs_ln) goto out;
        const size_t cs_total = 1 + cs_ln + (size_t)n_cert;
        uint8_t *certs = OPENSSL_malloc(cs_total);
        if (!certs) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        certs[0] = 0x31; memcpy(certs + 1, cs_l, cs_ln);
        memcpy(certs + 1 + cs_ln, d_cert, (size_t)n_cert);

        si = OPENSSL_malloc(16384);
        if (!si) { OPENSSL_free(certs); rv = FHSM_RV_HOST_MEMORY; goto out; }
        size_t si_len = 16384;
        rv = fhsm_composite_cms_signerinfo(d_iss, (size_t)n_iss,
                                            d_ser, (size_t)n_ser,
                                            digalg, (size_t)n,
                                            attrs, (size_t)n_attrs,
                                            ALGID_MLDSA65_ED25519,
                                            sizeof ALGID_MLDSA65_ED25519,
                                            sig, slen, si, &si_len);
        if (rv == FHSM_RV_OK)
            rv = fhsm_composite_cms_wrap(digalg, (size_t)n, certs, cs_total,
                                          si, si_len, out, out_len);
        OPENSSL_free(certs);
    }
out:
    OPENSSL_free(attrs); OPENSSL_free(d_iss); OPENSSL_free(d_ser);
    OPENSSL_free(d_cert); OPENSSL_free(si);
    if (sig) { OPENSSL_cleanse(sig, FHSM_COMPOSITE_SIG_MAX); OPENSSL_free(sig); }
    X509_free(x);
    return rv;
}

/* ---------------------------------------------------------------------------
 * A minimal DER reader, for reaching the signed attributes inside a CMS.
 * i2d_CMS_SignerInfo does not exist -- only CMS_ContentInfo has ASN.1
 * functions -- so there is no supported route to those bytes except walking
 * to them. Definite lengths only, which is all DER produces.
 * ------------------------------------------------------------------------- */
typedef struct { const uint8_t *p; size_t len; uint8_t tag;
                 const uint8_t *val; size_t vlen; } fhsm_tlv_t;

static int tlv_at(const uint8_t *p, size_t avail, fhsm_tlv_t *t) {
    if (avail < 2) return 0;
    t->p = p; t->tag = p[0];
    size_t hl = 2, n = p[1];
    if (n & 0x80) {
        size_t k = n & 0x7F;
        if (k == 0 || k > 4 || avail < 2 + k) return 0;
        n = 0;
        for (size_t i = 0; i < k; i++) n = (n << 8) | p[2 + i];
        hl = 2 + k;
    }
    if (avail < hl + n) return 0;
    t->val = p + hl; t->vlen = n; t->len = hl + n;
    return 1;
}

static int tlv_child(const fhsm_tlv_t *parent, size_t idx, fhsm_tlv_t *out) {
    const uint8_t *p = parent->val; size_t left = parent->vlen;
    for (size_t i = 0; ; i++) {
        fhsm_tlv_t t;
        if (!left || !tlv_at(p, left, &t)) return 0;
        if (i == idx) { *out = t; return 1; }
        p += t.len; left -= t.len;
    }
}

/* ContentInfo -> [0] -> SignedData -> trailing SET OF -> first SignerInfo */
static int cms_find_signerinfo(const uint8_t *der, size_t len, fhsm_tlv_t *out) {
    fhsm_tlv_t ci, c0, sd, last;
    memset(&last, 0, sizeof last);
    int have = 0;
    if (!tlv_at(der, len, &ci))        return 0;
    if (!tlv_child(&ci, 1, &c0))       return 0;
    if (!tlv_at(c0.val, c0.vlen, &sd)) return 0;
    const uint8_t *p = sd.val; size_t left = sd.vlen;
    while (left) {
        fhsm_tlv_t t;
        if (!tlv_at(p, left, &t)) return 0;
        last = t; have = 1;
        p += t.len; left -= t.len;
    }
    if (!have || last.tag != 0x31) return 0;
    return tlv_child(&last, 0, out);
}

fhsm_rv_t fhsm_composite_cms_verify(fhsm_composite_alg_t alg,
                                     const uint8_t *cms, size_t cms_len,
                                     const uint8_t *digest, size_t digest_len)
{
    if (alg != FHSM_COMPOSITE_MLDSA65_ED25519_SHA512 || !cms || !digest)
        return FHSM_RV_ARGUMENTS_BAD;
    if (digest_len != fhsm_composite_ph_len(alg)) return FHSM_RV_ARGUMENTS_BAD;

    fhsm_rv_t rv = FHSM_RV_ARGUMENTS_BAD;
    CMS_ContentInfo *ci = NULL;
    STACK_OF(X509) *certs = NULL;
    uint8_t *re = NULL, *attrs = NULL;
    static uint8_t pubblob[FHSM_COMPOSITE_PUB_MAX];

    { const uint8_t *p = cms; ci = d2i_CMS_ContentInfo(NULL, &p, (long)cms_len);
      if (!ci || (size_t)(p - cms) != cms_len) goto out; }

    STACK_OF(CMS_SignerInfo) *sis = CMS_get0_SignerInfos(ci);
    if (sk_CMS_SignerInfo_num(sis) != 1) goto out;
    CMS_SignerInfo *si = sk_CMS_SignerInfo_value(sis, 0);

    /* The algorithm, before anything else: a structure claiming another one
     * is not something to half-check. */
    {
        X509_ALGOR *sa = NULL;
        CMS_SignerInfo_get0_algs(si, NULL, NULL, NULL, &sa);
        const ASN1_OBJECT *o = NULL; int pt = 0; const void *pv = NULL;
        X509_ALGOR_get0(&o, &pt, &pv, sa);
        char b[128] = ""; OBJ_obj2txt(b, sizeof b, o, 1);
        if (strcmp(b, FHSM_COMPOSITE_OID_MLDSA65_ED25519) != 0) goto out;
        if (pt != V_ASN1_UNDEF) goto out;
    }

    /* The messageDigest must agree with the content the caller hashed. This
     * is what ties the signature to the data at all: the signature itself
     * covers only the attributes. */
    {
        int loc = CMS_signed_get_attr_by_NID(si, NID_pkcs9_messageDigest, -1);
        if (loc < 0) goto out;
        X509_ATTRIBUTE *at = CMS_signed_get_attr(si, loc);
        ASN1_TYPE *v = at ? X509_ATTRIBUTE_get0_type(at, 0) : NULL;
        if (!v || v->type != V_ASN1_OCTET_STRING) goto out;
        if ((size_t)ASN1_STRING_length(v->value.octet_string) != digest_len) {
            rv = FHSM_RV_SIGNATURE_INVALID; goto out;
        }
        if (memcmp(ASN1_STRING_get0_data(v->value.octet_string),
                    digest, digest_len) != 0) {
            rv = FHSM_RV_SIGNATURE_INVALID; goto out;
        }
    }

    /* The signer's public key, from the certificate the structure carries. */
    {
        certs = CMS_get1_certs(ci);
        if (!certs || sk_X509_num(certs) != 1) goto out;
        X509 *x = sk_X509_value(certs, 0);
        const unsigned char *pk = NULL; int pkl = 0;
        X509_PUBKEY_get0_param(NULL, &pk, &pkl, NULL, X509_get_X509_PUBKEY(x));
        if (!pk || pkl != (int)FHSM_COMPOSITE_RAW_PUB) goto out;
        size_t bl = sizeof pubblob;
        if (fhsm_composite_pub_from_raw(alg, pk, (size_t)pkl, pubblob, &bl)
            != FHSM_RV_OK) goto out;

        /* Re-encode and verify over the attributes as they appear there --
         * verifying over the bytes we were given would only prove we agree
         * with ourselves. */
        int re_n = i2d_CMS_ContentInfo(ci, &re);
        if (re_n <= 0) goto out;
        fhsm_tlv_t s2, at;
        int found = 0;
        if (cms_find_signerinfo(re, (size_t)re_n, &s2))
            for (size_t k = 0; tlv_child(&s2, k, &at); k++)
                if (at.tag == 0xA0) { found = 1; break; }
        if (!found) goto out;

        attrs = OPENSSL_malloc(at.len);
        if (!attrs) { rv = FHSM_RV_HOST_MEMORY; goto out; }
        memcpy(attrs, at.p, at.len);
        attrs[0] = 0x31;                     /* [0] IMPLICIT -> SET OF */

        ASN1_OCTET_STRING *sg = CMS_SignerInfo_get0_signature(si);
        if (!sg) goto out;
        rv = fhsm_composite_verify(alg, pubblob, bl, attrs, at.len, NULL, 0,
                                    ASN1_STRING_get0_data((const ASN1_STRING *)sg),
                                    (size_t)ASN1_STRING_length((const ASN1_STRING *)sg));
    }
out:
    OPENSSL_free(re); OPENSSL_free(attrs);
    sk_X509_pop_free(certs, X509_free);
    CMS_ContentInfo_free(ci);
    return rv;
}
