/* ===========================================================================
 * include/fhsm_pq_params.h
 *
 * CK_ML_DSA_PARAMS / CK_SLH_DSA_PARAMS parser.
 *
 * PKCS#11 v3.2 §6.18 (ML-DSA, FIPS 204) and §6.19 (SLH-DSA, FIPS 205)
 * both define the same mech-parameter struct :
 *
 *   { CK_ULONG     hedgeVariant ;
 *     CK_BYTE_PTR  pContext ;
 *     CK_ULONG     ulContextLen }
 *
 * which is 24 bytes on a 64-bit ABI (3 * sizeof(CK_ULONG)) with
 * pContext encoded as a CK_BYTE_PTR (= 8 bytes, same size as CK_ULONG).
 * The parser handles both structs through a single code path because
 * the wire layout is bit-identical.
 *
 * The context string (the data pContext points to, ulContextLen long)
 * is forwarded verbatim to OpenSSL via
 * OSSL_SIGNATURE_PARAM_CONTEXT_STRING in C_Sign / C_Verify.
 *
 * Extracted out of src/fhsm_pkcs11.c::op_init in v1.1.14 as a
 * prerequisite for the libFuzzer harness on this parser (#191).
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#ifndef FHSM_PQ_PARAMS_H
#define FHSM_PQ_PARAMS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Parse a CK_ML_DSA_PARAMS or CK_SLH_DSA_PARAMS mech-parameter block.
 *
 *   param_ptr, param_len  Pointer to the CK_MECHANISM.pParameter and
 *                         .ulParameterLen pair. May be NULL/0, in which
 *                         case *out_have is set to 0 and the function
 *                         returns immediately (no parameter == default
 *                         empty context).
 *   out_ctx               Caller-provided buffer to receive the
 *                         context bytes if any.
 *   out_ctx_cap           Capacity of out_ctx. FIPS 204 §5.2.1 and
 *                         FIPS 205 §5.2.1 both bound the context at
 *                         255 octets ; an ulContextLen above
 *                         out_ctx_cap is treated as "no parameter"
 *                         (*out_have = 0) so OpenSSL itself rejects
 *                         the eventual sign/verify, matching the
 *                         original behavior.
 *
 *   *out_ctx_len          (out) actual number of bytes written into
 *                         out_ctx. 0 if no parameter, explicit empty
 *                         context, or rejection.
 *   *out_have             (out) non-zero iff the parameter block was
 *                         successfully parsed (including the explicit-
 *                         empty-context case). Zero iff no parameter,
 *                         malformed (too short), or rejected (oversize
 *                         or null pointer with positive length).
 *   *out_hedge_variant    (out) the hedgeVariant ulong. Only meaningful
 *                         when *out_have != 0. Recorded for future use
 *                         but not applied by this parser ; OpenSSL's
 *                         default policy (hedged when entropy is
 *                         available) matches CKH_HEDGE_PREFERRED.
 *
 * The function does not allocate, does not log, does not touch any
 * global state, and does not call into OpenSSL or any system service.
 * It is pure and re-entrant : the only side effects are writes through
 * the three out-pointers and (optionally) the out_ctx buffer.
 *
 * The function does dereference a pointer encoded in the parameter
 * block (pContext). The caller is responsible for ensuring that
 * pointer is valid for at least ulContextLen bytes ; in normal
 * PKCS#11 usage it comes from a trusted application local buffer.
 * Fuzz harnesses must construct param blocks where the pointer field
 * is either NULL or points to a harness-owned buffer ; otherwise the
 * memcpy below will trigger SEGV on adversarial inputs without
 * exercising the parser logic itself. */
void fhsm_parse_pq_params(const void *param_ptr, size_t param_len,
                          uint8_t *out_ctx, size_t out_ctx_cap,
                          size_t *out_ctx_len, int *out_have,
                          unsigned long *out_hedge_variant);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_PQ_PARAMS_H */
