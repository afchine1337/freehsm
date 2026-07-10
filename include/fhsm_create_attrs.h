/* ===========================================================================
 * include/fhsm_create_attrs.h
 *
 * Pure parser for the CK_ATTRIBUTE[] template passed to C_CreateObject.
 * Extracted from src/fhsm_pkcs11.c in v1.2.0 as part of the
 * C_CreateObject decomposition (#191 follow-up).
 *
 * Design intent : the parser is **pure C**, takes attribute templates
 * as input, and emits a typed struct describing what the caller wants
 * to create. No OpenSSL dependency, no token I/O, no global state.
 * This makes the parser directly reachable from a libFuzzer harness
 * (fuzz/fuzz_create_attrs.c) without dragging in the rest of the
 * module ; previously the fuzz harness exercised an inline mirror that
 * could drift from the production code.
 *
 * The "builder" half of C_CreateObject (constructing EVP_PKEYs and
 * serializing as SPKI DER) stays in src/fhsm_pkcs11.c because it is
 * intrinsically tied to the OpenSSL EVP API.
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#ifndef FHSM_CREATE_ATTRS_H
#define FHSM_CREATE_ATTRS_H

#include <stddef.h>
#include <stdint.h>

#include "fhsm_attr_utils.h"   /* fhsm_attr_t : layout-compatible CK_ATTRIBUTE */

#ifdef __cplusplus
extern "C" {
#endif

/* Resolution path : the parser determines which builder branch the
 * C_CreateObject caller is targeting based on (CKO_CLASS, CKK_KEY_TYPE)
 * and what attributes are present in the template. */
typedef enum {
    FHSM_CREATE_PATH_INVALID = 0,
    /* CKO_SECRET_KEY (any CKK_) ; CKO_PRIVATE_KEY (any CKK_) ; or
     * CKO_PUBLIC_KEY + CKK_ML_DSA. CKA_VALUE is stored verbatim. */
    FHSM_CREATE_PATH_VERBATIM,
    /* CKO_PUBLIC_KEY + CKK_EC. CKA_EC_PARAMS = curve OID DER,
     * CKA_EC_POINT = OCTET STRING wrapped SEC1 uncompressed point. */
    FHSM_CREATE_PATH_EC_PUB,
    /* CKO_PUBLIC_KEY + CKK_EC_EDWARDS, Ed25519 variant. */
    FHSM_CREATE_PATH_ED25519_PUB,
    /* CKO_PUBLIC_KEY + CKK_EC_EDWARDS, Ed448 variant. */
    FHSM_CREATE_PATH_ED448_PUB,
    /* CKO_PUBLIC_KEY + CKK_RSA. CKA_MODULUS + CKA_PUBLIC_EXPONENT. */
    FHSM_CREATE_PATH_RSA_PUB,
    /* CKO_CERTIFICATE + CKA_CERTIFICATE_TYPE = CKC_X_509 (#110).
     * CKA_VALUE = complete X.509 certificate, DER. CKA_KEY_TYPE is NOT
     * required for this class (PKCS#11 v3.2 par. 4.6.3) ; cert_type
     * below carries the CKA_CERTIFICATE_TYPE value instead. */
    FHSM_CREATE_PATH_CERT_X509,
} fhsm_create_path_t;

/* All data parsed from the template. Pointer fields (id_data, value_data,
 * ec_point, rsa_*) point into the input pTemplate's pValue buffers and
 * MUST NOT be dereferenced after the template owner releases them. The
 * label is a copy into the struct's internal buffer (max 63 chars, NUL-
 * terminated, padded with '\0'). */
typedef struct fhsm_create_attrs_s {
    fhsm_create_path_t  path;
    unsigned long       cko;        /* CKA_CLASS value */
    unsigned long       ckk;        /* CKA_KEY_TYPE value (0 for certificates) */
    unsigned long       cert_type;  /* CKA_CERTIFICATE_TYPE (cert path only) */

    char                label[64];  /* CKA_LABEL, NUL-terminated, may be "" */

    const uint8_t      *id_data;    /* CKA_ID (may be NULL if absent) */
    size_t              id_len;

    /* === Verbatim path === */
    const uint8_t      *value_data;     /* CKA_VALUE */
    size_t              value_len;

    /* === EC / Ed public key path === */
    /* Group name : "P-256", "P-384", "P-521". For Ed25519/Ed448 paths
     * this is NULL and the path enum carries the curve identity. */
    const char         *ec_group;
    /* Point payload, already DER OCTET STRING wrapper-stripped. For
     * Ed25519/Ed448 this is the raw 32/57-byte public key. For EC this
     * is the SEC1 uncompressed point (0x04 || X || Y). */
    const uint8_t      *ec_point;
    size_t              ec_point_len;

    /* === RSA public key path === */
    const uint8_t      *rsa_modulus;
    size_t              rsa_modulus_len;
    const uint8_t      *rsa_exponent;
    size_t              rsa_exponent_len;
} fhsm_create_attrs_t;

/* Return codes match the subset of FHSM_RV / CKR codes that C_CreateObject
 * is allowed to return. The full FHSM_RV enum is not pulled into this
 * header to keep the dependency surface minimal ; the caller in
 * fhsm_pkcs11.c maps these to its own type. */
typedef enum {
    FHSM_PARSE_OK = 0,
    /* CKR_TEMPLATE_INCOMPLETE : a required attribute is missing or
     * shorter than expected. */
    FHSM_PARSE_TEMPLATE_INCOMPLETE,
    /* CKR_TEMPLATE_INCONSISTENT : (CKO_, CKK_) combination is not one
     * of the supported create paths. */
    FHSM_PARSE_TEMPLATE_INCONSISTENT,
    /* FHSM_RV_ATTRIBUTE_VALUE_INVALID : an attribute value is malformed
     * (e.g. unknown curve OID, missing OCTET STRING wrapper, etc.). */
    FHSM_PARSE_ATTRIBUTE_VALUE_INVALID,
} fhsm_parse_rv_t;

/* Parse a C_CreateObject template into a typed `fhsm_create_attrs_t`.
 *
 *   pTemplate, ulCount  Input attribute array, exactly as passed to
 *                       C_CreateObject. Read-only.
 *   attrs               (out) Filled on success ; valid until the
 *                       caller releases pTemplate (pointer fields alias
 *                       into pValue buffers).
 *
 * Returns FHSM_PARSE_OK on success ; one of the FHSM_PARSE_* error
 * codes on failure. The function is pure : it does not allocate, log,
 * or touch any external state. It is safe to call repeatedly with
 * arbitrary inputs (which is what the libFuzzer harness does). */
fhsm_parse_rv_t fhsm_parse_create_attrs(
    const fhsm_attr_t *pTemplate, unsigned long ulCount,
    fhsm_create_attrs_t *attrs);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_CREATE_ATTRS_H */
