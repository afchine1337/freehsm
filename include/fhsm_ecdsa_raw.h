/* ===========================================================================
 * include/fhsm_ecdsa_raw.h
 *
 * ECDSA signature format conversion : DER ECDSA-Sig-Value <-> raw r||s.
 *
 * PKCS#11 v3.2 §6.13 specifies that the CKM_ECDSA family of mechanisms
 * encodes the signature as raw r||s on the wire (each component padded to
 * curve_size octets, so 2 * curve_size total). OpenSSL's EVP_DigestSign /
 * EVP_DigestVerify produce / expect a DER ECDSA-Sig-Value
 * (SEQUENCE { r INTEGER, s INTEGER }) by default. The two helpers below
 * bridge between the two forms so the rest of the module can stay in
 * PKCS#11 wire format while OpenSSL stays in DER.
 *
 * Extracted out of src/fhsm_pkcs11.c in v1.1.14 as a prerequisite for
 * structured fuzzing (#191) : a separate translation unit makes the
 * helpers reachable from a libFuzzer harness without dragging the whole
 * module.
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#ifndef FHSM_ECDSA_RAW_H
#define FHSM_ECDSA_RAW_H

#include <stddef.h>
#include <stdint.h>

/* PKCS#11 v3.2 CKM_ECDSA family identifiers. Duplicated as plain macros
 * because the PKCS#11 v3.2 header is not yet upstreamed into a canonical
 * location ; once it is, these will move to the canonical header and
 * this block will collapse to a single #include. */
#ifndef CKM_ECDSA
#define CKM_ECDSA                 0x00001041UL
#endif
#ifndef CKM_ECDSA_SHA256
#define CKM_ECDSA_SHA256          0x00001044UL
#endif
#ifndef CKM_ECDSA_SHA384
#define CKM_ECDSA_SHA384          0x00001045UL
#endif
#ifndef CKM_ECDSA_SHA512
#define CKM_ECDSA_SHA512          0x00001046UL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Return non-zero iff the mechanism identifier is one of the CKM_ECDSA
 * family that uses the raw r||s wire format. */
int fhsm_mech_is_ecdsa(uint32_t mech);

/* Convert a DER ECDSA_SIG (SEQUENCE { r INTEGER, s INTEGER }) into the
 * raw r||s wire format expected by PKCS#11 v3.2 §6.13.
 *
 *   der, der_len : input DER bytes.
 *   nlen         : curve order length in octets (32 for P-256, 48 for
 *                  P-384, 66 for P-521).
 *   out          : output buffer, written as r (nlen bytes) || s (nlen).
 *   out_cap      : capacity of out ; must be >= 2 * nlen.
 *
 * Returns the number of bytes written (always 2 * nlen on success) or 0
 * on any failure (bad DER, r/s wider than nlen, output too small, etc.). */
size_t fhsm_ecdsa_der_to_raw(const uint8_t *der, size_t der_len,
                              size_t nlen,
                              uint8_t *out, size_t out_cap);

/* Convert raw r||s (2 * nlen bytes) into a DER ECDSA_SIG.
 *
 *   raw, raw_len : input raw bytes ; raw_len must equal 2 * nlen.
 *   nlen         : curve order length in octets.
 *   out_der      : on success, *out_der points to a newly-allocated DER
 *                  buffer of length = returned value. Caller MUST free
 *                  it with OPENSSL_free() (it was allocated by OpenSSL
 *                  inside i2d_ECDSA_SIG). On failure *out_der is
 *                  unchanged.
 *
 * Returns the DER length on success, 0 on failure. */
size_t fhsm_ecdsa_raw_to_der(const uint8_t *raw, size_t raw_len,
                              size_t nlen, uint8_t **out_der);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_ECDSA_RAW_H */
