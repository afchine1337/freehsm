/* ===========================================================================
 * src/fhsm_ecdsa_raw.c
 *
 * ECDSA signature format conversion : implementation. See the header
 * fhsm_ecdsa_raw.h for the rationale.
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#include "fhsm_ecdsa_raw.h"

#include <string.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/crypto.h>

int fhsm_mech_is_ecdsa(uint32_t mech) {
    return mech == CKM_ECDSA
        || mech == CKM_ECDSA_SHA256
        || mech == CKM_ECDSA_SHA384
        || mech == CKM_ECDSA_SHA512;
}

size_t fhsm_ecdsa_der_to_raw(const uint8_t *der, size_t der_len,
                              size_t nlen,
                              uint8_t *out, size_t out_cap) {
    if (out_cap < 2 * nlen) return 0;
    const uint8_t *p = der;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
    if (!sig) return 0;
    const BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);
    if (!r || !s) { ECDSA_SIG_free(sig); return 0; }
    memset(out, 0, 2 * nlen);
    int rlen = BN_num_bytes(r);
    int slen = BN_num_bytes(s);
    if (rlen > (int)nlen || slen > (int)nlen) {
        ECDSA_SIG_free(sig); return 0;
    }
    BN_bn2bin(r, out + (nlen - (size_t)rlen));
    BN_bn2bin(s, out + nlen + (nlen - (size_t)slen));
    ECDSA_SIG_free(sig);
    return 2 * nlen;
}

size_t fhsm_ecdsa_raw_to_der(const uint8_t *raw, size_t raw_len,
                              size_t nlen, uint8_t **out_der) {
    if (raw_len != 2 * nlen) return 0;
    BIGNUM *r = BN_bin2bn(raw,         (int)nlen, NULL);
    BIGNUM *s = BN_bin2bn(raw + nlen,  (int)nlen, NULL);
    if (!r || !s) { BN_free(r); BN_free(s); return 0; }
    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) { BN_free(r); BN_free(s); return 0; }
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r); BN_free(s); ECDSA_SIG_free(sig); return 0;
    }
    /* set0 transfers ownership ; do NOT free r/s after this point. */
    uint8_t *buf = NULL;
    int len = i2d_ECDSA_SIG(sig, &buf);
    ECDSA_SIG_free(sig);
    if (len <= 0) { OPENSSL_free(buf); return 0; }
    *out_der = buf;
    return (size_t)len;
}
