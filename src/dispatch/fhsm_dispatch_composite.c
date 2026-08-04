/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm_dispatch_composite.c --- Composite ML-DSA dispatch (#112).
 *
 *  Thin: everything cryptographic lives in src/fhsm_composite.c, which is
 *  covered by the draft's own Appendix D vectors and by a test that
 *  demonstrates non-separability. This file only unpacks the TLV parameters
 *  and hands over.
 *
 *  The key arrives as one opaque blob in a vendor TLV, never as two. That is
 *  the whole point of the representation chosen for #112: a composite key
 *  cannot be assembled from two component keys, because no interface offers
 *  the opportunity. Draft §3.1 forbids reusing component key material, and a
 *  prohibition enforced by a check has to be wired to every path that could
 *  violate it -- ten object-creation sites in fhsm_pkcs11.c alone. Here there
 *  is nothing to wire, because there is nothing to refuse.
 * ========================================================================= */

#include "fhsm_dispatch_common.h"
#include "fhsm_composite.h"

#include <string.h>

/* Vendor TLVs, in the same space as the hybrid module's 0x21. */
#define FHSM_TLV_COMPOSITE_PRIV  0x30  /* opaque composite private key blob */
#define FHSM_TLV_COMPOSITE_PUB   0x31  /* opaque composite public key blob  */
#define FHSM_TLV_COMPOSITE_CTX   0x32  /* application context, 0-255 bytes  */

/* The generated dispatch table declares the sign handler; the verify one is
 * not a mechanism of its own, so it is declared here. It is reachable only
 * once the PKCS#11 layer routes C_Verify to it -- until then it is built and
 * tested but not exposed, which is deliberate: an unreachable function that
 * compiles and is covered is easier to wire up correctly later than one that
 * has to be written under the pressure of wiring. */
fhsm_rv_t dispatch_composite_mldsa65_ed25519_verify(unsigned long session,
                                                      unsigned long key,
                                                      const void *params,
                                                      size_t plen,
                                                      fhsm_slice_t in,
                                                      uint8_t *out,
                                                      size_t *outlen);

/* Signature generation. `in` is the message; the application context is
 * optional and defaults to empty, which is what X.509 uses. */
fhsm_rv_t dispatch_composite_mldsa65_ed25519(unsigned long session,
                                               unsigned long key,
                                               const void *params, size_t plen,
                                               fhsm_slice_t in,
                                               uint8_t *out, size_t *outlen)
{
    (void)session; (void)key;

    fhsm_slice_t priv, ctx;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_COMPOSITE_PRIV, &priv);
    if (rv != FHSM_RV_OK) return rv;
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_COMPOSITE_CTX, &ctx);

    return fhsm_composite_sign(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                priv.data, priv.len,
                                in.data, in.len,
                                ctx.len ? ctx.data : NULL, ctx.len,
                                out, outlen);
}

/* Verification. The signature to check arrives appended to the message in the
 * caller's buffer would be ambiguous, so it comes in its own TLV instead. */
#define FHSM_TLV_COMPOSITE_SIG   0x33

fhsm_rv_t dispatch_composite_mldsa65_ed25519_verify(unsigned long session,
                                                      unsigned long key,
                                                      const void *params,
                                                      size_t plen,
                                                      fhsm_slice_t in,
                                                      uint8_t *out,
                                                      size_t *outlen)
{
    (void)session; (void)key; (void)out;

    fhsm_slice_t pub, sig, ctx;
    fhsm_rv_t rv = fhsm_tlv_find(params, plen, FHSM_TLV_COMPOSITE_PUB, &pub);
    if (rv != FHSM_RV_OK) return rv;
    rv = fhsm_tlv_find(params, plen, FHSM_TLV_COMPOSITE_SIG, &sig);
    if (rv != FHSM_RV_OK) return rv;
    fhsm_tlv_find_optional(params, plen, FHSM_TLV_COMPOSITE_CTX, &ctx);

    rv = fhsm_composite_verify(FHSM_COMPOSITE_MLDSA65_ED25519_SHA512,
                                pub.data, pub.len,
                                in.data, in.len,
                                ctx.len ? ctx.data : NULL, ctx.len,
                                sig.data, sig.len);
    if (outlen) *outlen = 0;
    return rv;
}
