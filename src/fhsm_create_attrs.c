/* ===========================================================================
 * src/fhsm_create_attrs.c
 *
 * Pure parser for the CK_ATTRIBUTE[] template passed to C_CreateObject.
 * See include/fhsm_create_attrs.h for the contract.
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#include "fhsm_create_attrs.h"
#include "fhsm_attr_utils.h"   /* fhsm_find_attr + fhsm_strip_octet_string_inline */

#include <string.h>

/* ---------------------------------------------------------------------------
 * PKCS#11 v3.2 numeric constants used by the parser. Defined locally to keep
 * this TU free of any PKCS#11 header dependency ; the values are byte-stable
 * across spec revisions for the constants used here.
 * ----------------------------------------------------------------------- */
#define FHSM_CKA_CLASS              0x00000000UL
#define FHSM_CKA_KEY_TYPE           0x00000100UL
#define FHSM_CKA_LABEL              0x00000003UL
#define FHSM_CKA_ID                 0x00000102UL
#define FHSM_CKA_VALUE              0x00000011UL
#define FHSM_CKA_EC_PARAMS          0x00000180UL
#define FHSM_CKA_EC_POINT           0x00000181UL
#define FHSM_CKA_MODULUS            0x00000120UL
#define FHSM_CKA_PUBLIC_EXPONENT    0x00000122UL

#define FHSM_CKO_CERTIFICATE        0x00000001UL
#define FHSM_CKO_PUBLIC_KEY         0x00000002UL
#define FHSM_CKO_PRIVATE_KEY        0x00000003UL
#define FHSM_CKO_SECRET_KEY         0x00000004UL

#define FHSM_CKA_CERTIFICATE_TYPE   0x00000080UL
#define FHSM_CKC_X_509              0x00000000UL

#define FHSM_CKK_RSA                0x00000000UL
#define FHSM_CKK_EC                 0x00000003UL
#define FHSM_CKK_EC_EDWARDS         0x00000040UL
#define FHSM_CKK_ML_DSA             0x0000004AUL

/* ---------------------------------------------------------------------------
 * Curve OID -> group-name lookup. Three NIST curves only, hardcoded for
 * predictability ; same logic as fhsm_ec_oid_to_group() in fhsm_pkcs11.c.
 * Public for the harness ; small enough to duplicate without harm.
 * ----------------------------------------------------------------------- */
static const struct { const uint8_t oid[10]; size_t oid_len; const char *group; } k_ec_oids[] = {
    /* P-256 : 1.2.840.10045.3.1.7   -> DER 06 08 2A 86 48 CE 3D 03 01 07 */
    { { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }, 10, "P-256" },
    /* P-384 : 1.3.132.0.34          -> DER 06 05 2B 81 04 00 22 */
    { { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 },                    7, "P-384" },
    /* P-521 : 1.3.132.0.35          -> DER 06 05 2B 81 04 00 23 */
    { { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 },                    7, "P-521" },
};

static const char *ec_oid_to_group(const uint8_t *oid, size_t oid_len) {
    for (size_t i = 0; i < sizeof(k_ec_oids) / sizeof(k_ec_oids[0]); ++i) {
        if (k_ec_oids[i].oid_len == oid_len
            && memcmp(k_ec_oids[i].oid, oid, oid_len) == 0)
            return k_ec_oids[i].group;
    }
    return NULL;
}

/* Ed25519/Ed448 OID DER blobs. */
static const uint8_t k_ed25519_oid[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };
static const uint8_t k_ed448_oid[]   = { 0x06, 0x03, 0x2b, 0x65, 0x71 };

/* ---------------------------------------------------------------------------
 * Read a CK_ULONG from an attribute's pValue, assuming the value is at
 * least sizeof(unsigned long) bytes. Returns 0 on failure.
 * ----------------------------------------------------------------------- */
static int read_attr_ulong(const fhsm_attr_t *t, unsigned long n,
                            unsigned long attr_type, unsigned long *out) {
    long idx = fhsm_find_attr(t, n, attr_type);
    if (idx < 0) return 0;
    if (t[idx].ulValueLen < sizeof(unsigned long)) return 0;
    memcpy(out, t[idx].pValue, sizeof(unsigned long));
    return 1;
}

/* Copy CKA_LABEL into a fixed-size buffer (max sizeof(out)-1 chars, NUL-
 * terminated). No-op if CKA_LABEL is absent ; the buffer is pre-zeroed
 * by the caller. */
static void copy_label(const fhsm_attr_t *t, unsigned long n,
                        char *out, size_t out_cap) {
    long idx = fhsm_find_attr(t, n, FHSM_CKA_LABEL);
    if (idx < 0) return;
    size_t copy = t[idx].ulValueLen;
    if (copy >= out_cap) copy = out_cap - 1;
    if (copy > 0) memcpy(out, t[idx].pValue, copy);
    out[copy] = '\0';
}

/* ---------------------------------------------------------------------------
 * Sub-parsers for each create path. Each one assumes the (cko, ckk) gate
 * has already been validated by the dispatch logic in
 * fhsm_parse_create_attrs() below.
 * ----------------------------------------------------------------------- */

static fhsm_parse_rv_t parse_verbatim(
    const fhsm_attr_t *t, unsigned long n,
    fhsm_create_attrs_t *attrs) {
    long iv = fhsm_find_attr(t, n, FHSM_CKA_VALUE);
    if (iv < 0) return FHSM_PARSE_TEMPLATE_INCOMPLETE;
    attrs->value_data = (const uint8_t *)t[iv].pValue;
    attrs->value_len  = (size_t)t[iv].ulValueLen;
    attrs->path = FHSM_CREATE_PATH_VERBATIM;
    return FHSM_PARSE_OK;
}

static fhsm_parse_rv_t parse_ec_pub(
    const fhsm_attr_t *t, unsigned long n,
    fhsm_create_attrs_t *attrs) {
    long ip  = fhsm_find_attr(t, n, FHSM_CKA_EC_PARAMS);
    long ipt = fhsm_find_attr(t, n, FHSM_CKA_EC_POINT);
    if (ip < 0 || ipt < 0) return FHSM_PARSE_TEMPLATE_INCOMPLETE;

    const char *group = ec_oid_to_group(
        (const uint8_t *)t[ip].pValue, (size_t)t[ip].ulValueLen);
    if (!group) return FHSM_PARSE_ATTRIBUTE_VALUE_INVALID;
    attrs->ec_group = group;

    /* CKA_EC_POINT is a DER OCTET STRING wrapper around 0x04 || X || Y. */
    const uint8_t *point = NULL;
    size_t point_len = 0;
    if (!fhsm_strip_octet_string_inline(
            (const uint8_t *)t[ipt].pValue, (size_t)t[ipt].ulValueLen,
            &point, &point_len))
        return FHSM_PARSE_ATTRIBUTE_VALUE_INVALID;
    attrs->ec_point     = point;
    attrs->ec_point_len = point_len;

    attrs->path = FHSM_CREATE_PATH_EC_PUB;
    return FHSM_PARSE_OK;
}

static fhsm_parse_rv_t parse_ed_pub(
    const fhsm_attr_t *t, unsigned long n,
    fhsm_create_attrs_t *attrs) {
    long ip  = fhsm_find_attr(t, n, FHSM_CKA_EC_PARAMS);
    long ipt = fhsm_find_attr(t, n, FHSM_CKA_EC_POINT);
    if (ip < 0 || ipt < 0) return FHSM_PARSE_TEMPLATE_INCOMPLETE;

    const uint8_t *oid = (const uint8_t *)t[ip].pValue;
    size_t oid_len = (size_t)t[ip].ulValueLen;
    fhsm_create_path_t ed_path = FHSM_CREATE_PATH_INVALID;
    if (oid_len == sizeof(k_ed25519_oid)
        && memcmp(oid, k_ed25519_oid, oid_len) == 0)
        ed_path = FHSM_CREATE_PATH_ED25519_PUB;
    else if (oid_len == sizeof(k_ed448_oid)
             && memcmp(oid, k_ed448_oid, oid_len) == 0)
        ed_path = FHSM_CREATE_PATH_ED448_PUB;
    else
        return FHSM_PARSE_ATTRIBUTE_VALUE_INVALID;

    const uint8_t *point = NULL;
    size_t point_len = 0;
    if (!fhsm_strip_octet_string_inline(
            (const uint8_t *)t[ipt].pValue, (size_t)t[ipt].ulValueLen,
            &point, &point_len))
        return FHSM_PARSE_ATTRIBUTE_VALUE_INVALID;
    attrs->ec_point     = point;
    attrs->ec_point_len = point_len;
    attrs->ec_group     = NULL;     /* curve identity carried by the path */
    attrs->path         = ed_path;
    return FHSM_PARSE_OK;
}

static fhsm_parse_rv_t parse_rsa_pub(
    const fhsm_attr_t *t, unsigned long n,
    fhsm_create_attrs_t *attrs) {
    long im = fhsm_find_attr(t, n, FHSM_CKA_MODULUS);
    long ie = fhsm_find_attr(t, n, FHSM_CKA_PUBLIC_EXPONENT);
    if (im < 0 || ie < 0) return FHSM_PARSE_TEMPLATE_INCOMPLETE;
    attrs->rsa_modulus      = (const uint8_t *)t[im].pValue;
    attrs->rsa_modulus_len  = (size_t)t[im].ulValueLen;
    attrs->rsa_exponent     = (const uint8_t *)t[ie].pValue;
    attrs->rsa_exponent_len = (size_t)t[ie].ulValueLen;
    attrs->path = FHSM_CREATE_PATH_RSA_PUB;
    return FHSM_PARSE_OK;
}

/* ---------------------------------------------------------------------------
 * Public entry point. Reads CKA_CLASS / CKA_KEY_TYPE / CKA_LABEL / CKA_ID
 * then dispatches to the right sub-parser based on (cko, ckk).
 * ----------------------------------------------------------------------- */
fhsm_parse_rv_t fhsm_parse_create_attrs(
    const fhsm_attr_t *pTemplate, unsigned long ulCount,
    fhsm_create_attrs_t *attrs) {

    /* Pre-zero the output so caller code that switches on attrs->path can
     * see consistent defaults even on failure. */
    memset(attrs, 0, sizeof(*attrs));

    if (!pTemplate || ulCount == 0) return FHSM_PARSE_TEMPLATE_INCOMPLETE;

    if (!read_attr_ulong(pTemplate, ulCount, FHSM_CKA_CLASS, &attrs->cko))
        return FHSM_PARSE_TEMPLATE_INCOMPLETE;

    /* Validate class is one of the supported ones. */
    if (attrs->cko != FHSM_CKO_PUBLIC_KEY
        && attrs->cko != FHSM_CKO_PRIVATE_KEY
        && attrs->cko != FHSM_CKO_SECRET_KEY
        && attrs->cko != FHSM_CKO_CERTIFICATE)
        return FHSM_PARSE_TEMPLATE_INCONSISTENT;

    /* Optional attributes : label + id. */
    copy_label(pTemplate, ulCount, attrs->label, sizeof(attrs->label));
    long idx_id = fhsm_find_attr(pTemplate, ulCount, FHSM_CKA_ID);
    if (idx_id >= 0) {
        attrs->id_data = (const uint8_t *)pTemplate[idx_id].pValue;
        attrs->id_len  = (size_t)pTemplate[idx_id].ulValueLen;
    }

    /* Certificates (#110) : CKA_KEY_TYPE is NOT part of the class
     * (PKCS#11 v3.2 par. 4.6.3) ; CKA_CERTIFICATE_TYPE gates instead.
     * Only CKC_X_509 is supported ; the DER certificate travels in
     * CKA_VALUE, stored verbatim (the module never parses X.509 ---
     * that is the PKI layer's job). */
    if (attrs->cko == FHSM_CKO_CERTIFICATE) {
        if (!read_attr_ulong(pTemplate, ulCount, FHSM_CKA_CERTIFICATE_TYPE,
                              &attrs->cert_type))
            return FHSM_PARSE_TEMPLATE_INCOMPLETE;
        if (attrs->cert_type != FHSM_CKC_X_509)
            return FHSM_PARSE_TEMPLATE_INCONSISTENT;
        long iv = fhsm_find_attr(pTemplate, ulCount, FHSM_CKA_VALUE);
        if (iv < 0 || pTemplate[iv].ulValueLen == 0)
            return FHSM_PARSE_TEMPLATE_INCOMPLETE;
        attrs->value_data = (const uint8_t *)pTemplate[iv].pValue;
        attrs->value_len  = (size_t)pTemplate[iv].ulValueLen;
        attrs->path = FHSM_CREATE_PATH_CERT_X509;
        return FHSM_PARSE_OK;
    }

    if (!read_attr_ulong(pTemplate, ulCount, FHSM_CKA_KEY_TYPE, &attrs->ckk))
        return FHSM_PARSE_TEMPLATE_INCOMPLETE;

    /* Dispatch on (cko, ckk). */
    /* An EC private key with no CKA_EC_PARAMS is under-specified : the
     * curve is unknown, so subsequent sign/derive would be undefined.
     * Reject rather than store a curveless key (#125 TestEcMissingParams). */
    if (attrs->cko == FHSM_CKO_PRIVATE_KEY && attrs->ckk == FHSM_CKK_EC
        && fhsm_find_attr(pTemplate, ulCount, FHSM_CKA_EC_PARAMS) < 0)
        return FHSM_PARSE_TEMPLATE_INCONSISTENT;

    if (attrs->cko == FHSM_CKO_SECRET_KEY
        || attrs->cko == FHSM_CKO_PRIVATE_KEY
        || (attrs->cko == FHSM_CKO_PUBLIC_KEY
            && attrs->ckk == FHSM_CKK_ML_DSA))
        return parse_verbatim(pTemplate, ulCount, attrs);

    if (attrs->cko == FHSM_CKO_PUBLIC_KEY && attrs->ckk == FHSM_CKK_EC)
        return parse_ec_pub(pTemplate, ulCount, attrs);

    if (attrs->cko == FHSM_CKO_PUBLIC_KEY
        && attrs->ckk == FHSM_CKK_EC_EDWARDS)
        return parse_ed_pub(pTemplate, ulCount, attrs);

    if (attrs->cko == FHSM_CKO_PUBLIC_KEY && attrs->ckk == FHSM_CKK_RSA)
        return parse_rsa_pub(pTemplate, ulCount, attrs);

    return FHSM_PARSE_TEMPLATE_INCONSISTENT;
}
