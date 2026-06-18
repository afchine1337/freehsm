#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/mldsa.py --- ML-DSA (FIPS 204, Dilithium) signature verification
# against Google Wycheproof's mldsa_{44,65,87}_verify_test.json corpus.
#
# Strategy :
#   1. Import the verification key as CKO_PUBLIC_KEY + CKK_ML_DSA with
#      CKA_VALUE = the corpus's `publicKeyDer` field. This is the
#      standard SPKI DER (SEQUENCE { algId(id-ml-dsa-N), BIT STRING { raw } })
#      and decodes directly through d2i_PUBKEY without needing the raw
#      bytes fallback. The raw pubkey is exposed in the `publicKey`
#      field but we prefer the SPKI form here because it is the same
#      shape PKCS#11 v3.2 callers will use in production.
#   2. C_VerifyInit(CKM_ML_DSA_OP, pubkey_handle).
#   3. C_Verify(msg, sig) -> CKR_OK iff sig is a valid ML-DSA signature.
#
# Outcome :
#   - expected=valid   : rv == CKR_OK  -> match
#   - expected=invalid : rv != CKR_OK  -> match
#   - mismatch the other way            -> violation
#
# Limitations (tracked for the next release) :
#   * FIPS 204 context string : tests with a non-empty `ctx` are
#     skipped because the module's C_VerifyInit does not yet parse
#     CK_ML_DSA_PARAMS to forward the context through
#     OSSL_SIGNATURE_PARAM_CONTEXT_STRING. Tests with ctx absent or
#     ctx="" run normally.
#   * HashML-DSA (FIPS 204 §5.4 pre-hash variant) is not exercised
#     here ; the verify_test corpus is the "pure" ML-DSA path.
# ===========================================================================

from __future__ import annotations

from run_wycheproof import Adapter  # type: ignore

import _p11
from _p11 import A, P11Module, P11Error  # type: ignore


# Canonical SPKI-stripped raw FIPS 204 verification key length, by
# parameter set. Used for diagnostics only ; we feed the SPKI DER blob
# (publicKeyDer) into C_CreateObject, not the raw bytes.
RAW_PUBKEY_LEN = {
    "ML-DSA-44": 1312,
    "ML-DSA-65": 1952,
    "ML-DSA-87": 2592,
}


class MldsaAdapter(Adapter):
    name = "mldsa"
    algorithms = tuple(RAW_PUBKEY_LEN.keys())
    schemas = (
        "mldsa_verify_schema.json",
        "mldsa_verify_schema_v1.json",
    )

    def __init__(self, module_path: str):
        super().__init__(module_path)
        self._logged_symbols: set = set()
        self.diag = {
            "ml_dsa_44_seen":         0,
            "ml_dsa_65_seen":         0,
            "ml_dsa_87_seen":         0,
            "ctx_empty":              0,
            "ctx_nonempty_skip":      0,
            "key_import_failed":      0,
            "no_pubkey_der":          0,
            "unsupported_param_set":  0,
        }
        try:
            self.module = P11Module(module_path)
            self.session = self.module.open_session()
            self.ready = True
        except (P11Error, OSError) as exc:
            print(f"[mldsa] init failed : {exc!r}")
            self.module = None
            self.session = None
            self.ready = False

    def _log_missing_symbol(self, exc: AttributeError) -> None:
        msg = str(exc)
        if msg not in self._logged_symbols:
            self._logged_symbols.add(msg)
            print(f"[mldsa] missing symbol -> {msg}")

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

        # The file-level 'algorithm' carries the parameter set
        # (ML-DSA-44 / 65 / 87). The runner injects it as
        # `_algorithm` on the test dict ; fall back to the group.
        algo = test.get("_algorithm") or group.get("_algorithm")
        if algo not in RAW_PUBKEY_LEN:
            self.diag["unsupported_param_set"] += 1
            return "skip"

        if   algo == "ML-DSA-44": self.diag["ml_dsa_44_seen"] += 1
        elif algo == "ML-DSA-65": self.diag["ml_dsa_65_seen"] += 1
        else:                      self.diag["ml_dsa_87_seen"] += 1

        # FIPS 204 context : skip tests with a non-empty ctx for now ;
        # the module's C_VerifyInit does not yet parse
        # CK_ML_DSA_PARAMS. Tests with ctx absent or ctx="" run
        # through the default empty-context path.
        ctx_hex = test.get("ctx", "")
        if ctx_hex:
            self.diag["ctx_nonempty_skip"] += 1
            return "skip"
        self.diag["ctx_empty"] += 1

        # Prefer the SPKI DER form (publicKeyDer) over the raw bytes
        # so that d2i_PUBKEY decodes directly without falling back to
        # EVP_PKEY_fromdata. Both forms exist in the corpus.
        pk_der_hex = group.get("publicKeyDer", "")
        if not pk_der_hex:
            self.diag["no_pubkey_der"] += 1
            return "skip"
        pk_der = bytes.fromhex(pk_der_hex)

        msg = bytes.fromhex(test.get("msg", ""))
        sig = bytes.fromhex(test.get("sig", ""))
        expected = test.get("result", "")

        # Import the ML-DSA public key as a PUBLIC_KEY object with the
        # SPKI DER carried verbatim in CKA_VALUE.
        try:
            keyh = self.session.create_object([
                A.CLASS(A.CKO_PUBLIC_KEY),
                A.KEY_TYPE(_p11.CKK_ML_DSA),
                A.TOKEN(False),
                A.VERIFY(True),
                A.VALUE(pk_der),
            ])
        except P11Error:
            self.diag["key_import_failed"] += 1
            return "violation" if expected == "valid" else "match"
        except AttributeError as exc:
            self._log_missing_symbol(exc)
            return "skip"

        # Verify the signature.
        mech = A.MECH(_p11.CKM_ML_DSA_OP)
        rv = None
        verify_err = None
        try:
            rv = self.session.verify(keyh, mech, msg, sig)
        except AttributeError as exc:
            verify_err = exc

        try:
            self.session.destroy(keyh)
        except AttributeError:
            pass

        if verify_err is not None:
            self._log_missing_symbol(verify_err)
            return "skip"

        if expected == "valid":
            return "match" if rv == _p11.CKR_OK else "violation"
        if expected == "invalid":
            return "match" if rv != _p11.CKR_OK else "violation"
        return "match"  # "acceptable"


ADAPTER = MldsaAdapter
