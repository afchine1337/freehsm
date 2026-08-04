/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm_composite.h --- Composite ML-DSA signature combiner (#112).
 *
 *  Implements the message-representative construction of
 *  draft-ietf-lamps-pq-composite-sigs-19 (RFC Editor queue at the time of
 *  writing) :
 *
 *      M' = Prefix || Label || len(ctx) || ctx || PH( M )
 *
 *  This header exposes the combiner alone. It is the piece the existing
 *  CKM_HYBRID_ED25519_ML_DSA_65 mechanism lacks entirely -- that one signs the
 *  bare message with both keys, which is why its Ed25519 half is a valid
 *  standalone signature that can be lifted out of the concatenation. See
 *  docs/COMPOSITE_SIGS_GAP.md.
 *
 *  Deliberately separate from the signing path. The combiner is pure, has no
 *  keys, no OpenSSL objects and no error modes beyond argument checking, and
 *  it is the part with published test vectors (Appendix D, imported as
 *  kat/composite/mprime_appendix_d.txt). Getting it right and proving it right
 *  is a self-contained job; wiring it into a mechanism is the next one.
 * ========================================================================= */
#ifndef FHSM_COMPOSITE_H
#define FHSM_COMPOSITE_H

#include "fhsm_common.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The fixed prefix, common to every composite algorithm: the ASCII bytes of
 * "CompositeAlgorithmSignatures2025". 32 bytes, no NUL. */
#define FHSM_COMPOSITE_PREFIX      "CompositeAlgorithmSignatures2025"
#define FHSM_COMPOSITE_PREFIX_LEN  32u

/* The application context is length-prefixed with a single unsigned byte, so
 * it cannot exceed 255 octets (draft §2.2, §3.2 step 1). */
#define FHSM_COMPOSITE_CTX_MAX     255u

/* The composite algorithms this module knows about.
 *
 * Only one for now, and it is the draft's own recommendation: §10.4 names
 * id-MLDSA65-Ed25519-SHA512 as the combination to focus implementation effort
 * on where the signature primitive must provide SUF-CMA. Both its component
 * primitives are already in this module. */
typedef enum {
    FHSM_COMPOSITE_MLDSA65_ED25519_SHA512 = 1
} fhsm_composite_alg_t;

/* Per-algorithm parameters, from draft §6 (src/algParams.md upstream).
 *
 * `label` is an ASCII string. §6 is explicit that labels are written as ASCII
 * in the document and implementations MUST convert them to their ASCII byte
 * values before concatenation -- not to a DER encoding of the OID, which is
 * the plausible wrong guess. */
typedef struct {
    fhsm_composite_alg_t alg;
    const char *name;        /* "id-MLDSA65-Ed25519-SHA512"                  */
    const char *oid;         /* "1.3.6.1.5.5.7.6.48", dotted form            */
    const char *label;       /* "COMPSIG-MLDSA65-Ed25519-SHA512", ASCII      */
    size_t      label_len;
    const char *ph_name;     /* OpenSSL digest name for PH, e.g. "SHA512"    */
    size_t      ph_len;      /* digest output length in bytes                */
} fhsm_composite_params_t;

/* Look up the parameters for an algorithm. Returns NULL if unknown. */
const fhsm_composite_params_t *fhsm_composite_params(fhsm_composite_alg_t alg);

/* Exact size of M' for a given algorithm and context length, so a caller can
 * size a buffer without guessing. Returns 0 on bad arguments. */
size_t fhsm_composite_mprime_len(fhsm_composite_alg_t alg, size_t ctx_len);

/* Build the message representative.
 *
 *   M' = Prefix || Label || len(ctx) || ctx || PH( M )
 *
 * `ctx` may be NULL when `ctx_len` is 0 (the default, and what X.509 uses).
 * `*out_len` is in/out: the caller's capacity on entry, the bytes written on
 * return. Fails with FHSM_RV_BUFFER_TOO_SMALL rather than truncating.
 *
 * Note for the caller that will wire this up: the same `label` is needed a
 * second time, as the FIPS 204 context string passed to the ML-DSA component
 * (draft §3.2 step 4, `mldsa_ctx = Label`). Two roles, both mandatory; the
 * second is the one an implementer is most likely to drop.
 */
fhsm_rv_t fhsm_composite_mprime(fhsm_composite_alg_t alg,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *ctx, size_t ctx_len,
                                 uint8_t *out, size_t *out_len);

/* ---------------------------------------------------------------------------
 * Keys.
 *
 * A composite key is ONE object holding both components. They are never
 * separately addressable, and there is deliberately no way to assemble a
 * composite from two existing key handles.
 *
 * That is not ergonomics, it is how §3.1's requirement is met. The draft says
 * an invocation of KeyGen "MUST perform, or otherwise guarantee, fresh
 * generation of the key material for both underlying algorithms and MUST NOT
 * reuse existing key material" (§9.3 explains what reuse costs). A rule like
 * that, enforced by a check, has to be wired to every path that can create an
 * object -- there are ten such call sites in fhsm_pkcs11.c, and this project
 * has already found seven defects of exactly the form "a control wired to some
 * of the paths that reach a state and not the rest". So the rule is made
 * structurally true instead: if the only way a composite key can come into
 * existence is fhsm_composite_keygen(), which generates both halves itself,
 * reuse is not prevented, it is unrepresentable.
 *
 * The serialization below is local, not the interoperable §4.2 format. §3.1.1
 * permits that explicitly where private keys need not leave the module. It can
 * be upgraded later without changing the design above.
 * ----------------------------------------------------------------------- */

/* Local key blob: "FCMP" | ver(1) | alg(1) | len_pq(2 LE) | pq | len_trad(2 LE) | trad
 * Components are DER (PKCS#8 for private, SubjectPublicKeyInfo for public). */
#define FHSM_COMPOSITE_BLOB_MAGIC   "FCMP"
#define FHSM_COMPOSITE_BLOB_VERSION 1u

/* Comfortable ceilings for ML-DSA-65 + Ed25519. */
#define FHSM_COMPOSITE_PRIV_MAX  8192u
#define FHSM_COMPOSITE_PUB_MAX   4096u
#define FHSM_COMPOSITE_SIG_MAX   4096u   /* 3309 (ML-DSA-65) + 64 (Ed25519) */

/* Generate a fresh composite key pair. Both components are generated here and
 * nowhere else -- see the note above. */
fhsm_rv_t fhsm_composite_keygen(fhsm_composite_alg_t alg,
                                 uint8_t *priv, size_t *priv_len,
                                 uint8_t *pub,  size_t *pub_len);

/* Composite-ML-DSA.Sign (§3.2). Builds M', signs it with both components --
 * the ML-DSA one receiving the Label as its FIPS 204 context -- and emits
 * mldsaSig || tradSig, in that order. */
fhsm_rv_t fhsm_composite_sign(fhsm_composite_alg_t alg,
                               const uint8_t *priv, size_t priv_len,
                               const uint8_t *msg,  size_t msg_len,
                               const uint8_t *ctx,  size_t ctx_len,
                               uint8_t *sig, size_t *sig_len);

/* Composite-ML-DSA.Verify (§3.3). True only if BOTH components verify. */
fhsm_rv_t fhsm_composite_verify(fhsm_composite_alg_t alg,
                                 const uint8_t *pub, size_t pub_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *ctx, size_t ctx_len,
                                 const uint8_t *sig, size_t sig_len);

/* Length of the ML-DSA component within a composite signature, so a caller
 * that needs to split one knows where the boundary is. */
fhsm_rv_t fhsm_composite_split(fhsm_composite_alg_t alg,
                                const uint8_t *sig, size_t sig_len,
                                size_t *pq_len, size_t *trad_len);

#ifdef __cplusplus
}
#endif
#endif /* FHSM_COMPOSITE_H */
