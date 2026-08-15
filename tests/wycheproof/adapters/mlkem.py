#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/mlkem.py --- ML-KEM (FIPS 203) decapsulation verification
# against Google Wycheproof's mlkem_*_semi_expanded_decaps_test.json
# corpus.
#
# Strategy :
#   1. Import the raw FIPS 203 decapsulation key dk as a private object
#      (CKO_PRIVATE_KEY + CKK_ML_KEM + CKA_VALUE = raw dk bytes).
#      The module's C_DecapsulateKey path first tries
#      d2i_AutoPrivateKey() on the value blob ; if that fails, it
#      detects ML-KEM-{512,768,1024} by the canonical dk length
#      (1632 / 2400 / 3168) and re-imports through EVP_PKEY_fromdata
#      with OSSL_PKEY_PARAM_PRIV_KEY. This is symmetric with the way
#      the RSA / ECDSA adapters import their PKCS#8 envelopes.
#
#   2. Call C_DecapsulateKey(CKM_ML_KEM_OP, dk_handle, ct) ; the
#      module returns a fresh CKO_SECRET_KEY (CKK_GENERIC_SECRET)
#      holding the shared secret as CKA_VALUE.
#
#   3. C_GetAttributeValue(new_handle, CKA_VALUE) to read the SS bytes
#      back into the harness, then compare against the test's K field.
#
#   4. Outcome decision :
#         expected=valid    -> match iff (rv==OK and ss==K)
#         expected=invalid  -> match iff (rv!=OK or implicit-reject
#                                          gives a deterministic SS != K)
#      ML-KEM Decaps NEVER signals failure to the caller for malformed
#      ciphertext : FIPS 203 §7.3 mandates implicit rejection
#      (a deterministic pseudo-random SS derived from z || c). So for
#      'invalid' tests with a well-sized ct, the right check is
#      ss != K (the test K field carries the expected real SS that
#      the decaps would have produced on a clean ct). For wrong-length
#      ct or wrong-length dk, the module returns FUNCTION_FAILED before
#      reaching decaps proper, and we accept that as the rejection.
# ===========================================================================

from __future__ import annotations

from run_wycheproof import Adapter  # type: ignore

import _p11
from _p11 import A, P11Module, P11Error  # type: ignore


# Canonical FIPS 203 decapsulation key length, by parameter set.
DK_LEN = {
    "ML-KEM-512":  1632,
    "ML-KEM-768":  2400,
    "ML-KEM-1024": 3168,
}

# Canonical ciphertext length, by parameter set (FIPS 203 §8).
CT_LEN = {
    "ML-KEM-512":   768,
    "ML-KEM-768":  1088,
    "ML-KEM-1024": 1568,
}

# CKA_VALUE attribute identifier (PKCS#11 v3.0 §10.2.x).
CKA_VALUE = 0x00000011


class MlkemAdapter(Adapter):
    name = "mlkem"
    algorithms = ("ML-KEM",)
    schemas = (
        "mlkem_semi_expanded_decaps_test_schema.json",
        "mlkem_semi_expanded_decaps_test_schema_v1.json",
    )

    def __init__(self, module_path: str):
        super().__init__(module_path)
        self._logged_symbols: set = set()
        self.diag = {
            "param_set_512":         0,
            "param_set_768":         0,
            "param_set_1024":        0,
            "key_import_failed":     0,
            "decaps_rv_nonzero":     0,
            "ss_read_failed":        0,
            "unsupported_param_set": 0,
        }
        try:
            self.module = P11Module(module_path)
            self.session = self.module.open_session()
            self.ready = True
        except (P11Error, OSError) as exc:
            print(f"[mlkem] init failed : {exc!r}")
            self.module = None
            self.session = None
            self.ready = False

    def _log_missing_symbol(self, exc: AttributeError) -> None:
        msg = str(exc)
        if msg not in self._logged_symbols:
            self._logged_symbols.add(msg)
            print(f"[mlkem] missing symbol -> {msg}")

    def __del__(self):
        try:
            if self.session is not None:
                self.session.close()
            if self.module is not None:
                self.module.close()
        except Exception:
            pass

    # --- main per-test logic ------------------------------------------

    def run(self, group: dict, test: dict) -> str:
        if not self.ready:
            return "skip"

        param_set = group.get("parameterSet", "")
        if param_set not in DK_LEN:
            self.diag["unsupported_param_set"] += 1
            return "skip"

        if   param_set == "ML-KEM-512":  self.diag["param_set_512"]  += 1
        elif param_set == "ML-KEM-768":  self.diag["param_set_768"]  += 1
        else:                             self.diag["param_set_1024"] += 1

        dk = bytes.fromhex(test.get("dk", ""))
        ct = bytes.fromhex(test.get("c",  ""))
        expected = test.get("result", "")

        # Wycheproof tcId=1 ("valid") files have no K field ; the
        # corpus only ships test vectors here for the validation
        # variants (length checks + invalid-key checks). The "valid"
        # test asserts that a properly formed (dk, ct) pair survives
        # the full decapsulation path without raising. We compare the
        # derived shared secret against the optional 'K' field when
        # present ; otherwise we just require that the call succeeds.
        K_hex = test.get("K", "")
        expected_ss = bytes.fromhex(K_hex) if K_hex else None

        # Import the raw FIPS 203 dk as a CKO_PRIVATE_KEY. The module
        # auto-detects the parameter set from the value length and
        # routes to EVP_PKEY_fromdata when it is not a PKCS#8 envelope.
        try:
            dk_handle = self.session.create_object([
                A.CLASS(A.CKO_PRIVATE_KEY),
                A.KEY_TYPE(_p11.CKK_ML_KEM),
                A.TOKEN(False),
                A.VALUE(dk),
            ])
        except P11Error:
            # Module refused the import. For 'invalid' result with the
            # InvalidDecapsulationKey / IncorrectDecapsulationKeyLength
            # flag this is the correct early rejection.
            self.diag["key_import_failed"] += 1
            return "match" if expected == "invalid" else "violation"
        except AttributeError as exc:
            self._log_missing_symbol(exc)
            return "skip"

        # Build the CKM_ML_KEM_OP mechanism (no parameters per
        # PKCS#11 v3.0 §6.13).
        mech = A.MECH(_p11.CKM_ML_KEM_OP)

        # Run decapsulation. Output is a fresh CKO_SECRET_KEY whose
        # CKA_VALUE carries the 32-byte shared secret.
        rv = None
        new_h = 0
        verify_err = None
        try:
            rv, new_h = self.session.decapsulate(
                dk_handle, mech, ct,
                template=[
                    A.CLASS(A.CKO_SECRET_KEY),
                    A.KEY_TYPE(A.CKK_GENERIC_SECRET),
                    A.TOKEN(False),
                    A.EXTRACTABLE(True),
                ],
            )
        except AttributeError as exc:
            verify_err = exc

        if verify_err is not None:
            try:
                self.session.destroy(dk_handle)
            except AttributeError:
                pass
            self._log_missing_symbol(verify_err)
            return "skip"

        ss = b""
        if rv == _p11.CKR_OK and new_h:
            try:
                ss = self.session.get_attribute_value(new_h, CKA_VALUE)
            except AttributeError as exc:
                self._log_missing_symbol(exc)
                ss = b""
                if not ss:
                    self.diag["ss_read_failed"] += 1
            try:
                self.session.destroy(new_h)
            except AttributeError:
                pass

        try:
            self.session.destroy(dk_handle)
        except AttributeError:
            pass

        if rv != _p11.CKR_OK:
            self.diag["decaps_rv_nonzero"] += 1

        # Outcome rules : see header.
        if expected == "valid":
            if rv != _p11.CKR_OK:
                return "violation"
            if expected_ss is not None and ss != expected_ss:
                return "violation"
            return "match"

        if expected == "invalid":
            # Acceptable rejections :
            #   - module returned non-OK (length / structural reject)
            #   - decaps succeeded but produced an SS that is NOT the
            #     stated K (implicit reject path, FIPS 203 §7.3)
            if rv != _p11.CKR_OK:
                return "match"
            if expected_ss is None:
                # No K provided ; any non-error is a violation.
                return "violation"
            return "match" if ss != expected_ss else "violation"

        # "acceptable" or unknown : count as match.
        return "match"


ADAPTER = MlkemAdapter
