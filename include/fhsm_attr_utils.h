/* ===========================================================================
 * include/fhsm_attr_utils.h
 *
 * Inline helpers shared between src/fhsm_pkcs11.c (which has its own
 * local equivalents under different names, since the file is not yet
 * decomposed) and the libFuzzer harnesses on the PKCS#11 attribute
 * template parser and the DER OCTET STRING wrapper parser.
 *
 * The two helpers below are layout-compatible mirrors of the static
 * functions in src/fhsm_pkcs11.c (find_attr and fhsm_strip_octet_string).
 * Until C_CreateObject itself is decomposed, the fuzzer exercises these
 * inline copies. The implementations are character-for-character
 * identical to the ones inside fhsm_pkcs11.c, so a finding here lands
 * on the production code path by inspection.
 *
 * Extracted in v1.1.14 as step 3 of the fuzzing prep refactor (#191).
 *
 * License : Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------- */
#ifndef FHSM_ATTR_UTILS_H
#define FHSM_ATTR_UTILS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal PKCS#11 CK_ATTRIBUTE shape : layout-compatible with the v3.2
 * spec and bit-identical to the typedef in src/fhsm_pkcs11.c. The
 * three fields are 8 + 8 + 8 = 24 bytes on a 64-bit ABI, with the
 * pValue field expected to point at a buffer the caller owns for
 * ulValueLen bytes.
 *
 * The fuzzer constructs arrays of this struct from raw fuzz bytes and
 * passes them to fhsm_find_attr. The harness must ensure pValue is
 * either NULL or points to a harness-owned buffer ; otherwise a
 * downstream memcpy would SEGV on every input without exercising the
 * parser logic itself. */
typedef struct fhsm_attr {
    unsigned long  type;        /* CK_ATTRIBUTE_TYPE in PKCS#11 */
    void          *pValue;      /* CK_VOID_PTR        in PKCS#11 */
    unsigned long  ulValueLen;  /* CK_ULONG           in PKCS#11 */
} fhsm_attr_t;

/* Find the first attribute in `t[0..n-1]` whose `type` field equals
 * `type`. Returns the index if found, -1 otherwise.
 *
 * The implementation is a single linear scan ; PKCS#11 templates are
 * small (typically < 16 entries) so the O(n) cost is negligible.
 *
 * Fuzz targets : integer overflow on `n`, out-of-bounds read on `t[i]`
 * when `n` exceeds the actual array length, type confusion. */
static inline long fhsm_find_attr(const fhsm_attr_t *t,
                                   unsigned long n,
                                   unsigned long type) {
    for (unsigned long i = 0; i < n; ++i) {
        if (t[i].type == type) return (long)i;
    }
    return -1;
}

/* DER OCTET STRING wrapper stripper.
 *
 * PKCS#11 CKA_EC_POINT carries the SEC1 uncompressed point inside a
 * DER OCTET STRING wrapper : 0x04 || length || value. The length
 * encoding can be short-form (1 byte, length <= 127), long-form 1
 * (0x81 || 1 byte length, length 128..255), or long-form 2 (0x82 ||
 * 2 bytes BE length, length 256..65535). PKCS#11 v3.2 §A.5 allows
 * any of these encodings.
 *
 *   in, in_len    Input buffer.
 *   *out          On success, points into in (no allocation) at the
 *                 start of the OCTET STRING payload.
 *   *out_len      On success, the payload length.
 *   Return        1 on success, 0 if the OCTET STRING shape is wrong
 *                 (which includes the case where the caller passed the
 *                 raw point with no wrapper).
 *
 * Fuzz targets : adversarial length bytes that overflow size_t,
 * length values that point past the end of the buffer, integer
 * underflow on (l + 4 == in_len), accept-with-wrong-shape on
 * malformed inputs. */
static inline int fhsm_strip_octet_string_inline(const uint8_t *in, size_t in_len,
                                                  const uint8_t **out,
                                                  size_t *out_len) {
    if (in_len > 2 && in[0] == 0x04 && in[1] != 0x04
        && (size_t)in[1] + 2 == in_len) {
        *out = in + 2;
        *out_len = in_len - 2;
        return 1;
    }
    if (in_len > 3 && in[0] == 0x04 && in[1] == 0x81
        && (size_t)in[2] + 3 == in_len) {
        *out = in + 3;
        *out_len = in_len - 3;
        return 1;
    }
    if (in_len > 4 && in[0] == 0x04 && in[1] == 0x82) {
        size_t l = ((size_t)in[2] << 8) | in[3];
        if (l + 4 == in_len) {
            *out = in + 4;
            *out_len = l;
            return 1;
        }
    }
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* FHSM_ATTR_UTILS_H */
