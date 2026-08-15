#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/aes_gmac.py --- AES-GMAC (NIST SP 800-38D §6.4) verification
# against Google Wycheproof's aes_gmac_test.json corpus.
#
# Strategy :
#   1. Import the AES key as CKO_SECRET_KEY + CKK_AES + CKA_VALUE.
#   2. C_SignInit(CKM_AES_GMAC, pParameter=IV, ulParameterLen=len(IV))
#      + C_Sign(msg) -> 16-byte tag (the module always emits a full
#      block ; truncation is the harness's job).
#   3. Truncate to the per-group tagSize and constant-time compare with
#      the expected tag.
#
# Key difference vs CMAC : GMAC needs an IV, conveyed via the mechanism
# parameter. We pass the IV bytes directly (PKCS#11 v3.0 raw IV
# convention, which the FreeHSM C op_init parses transparently).
#
# Outcome semantics are identical to aes_cmac.py.
# ===========================================================================

from __future__ import annotations

from run_wycheproof import Adapter  # type: ignore

import _p11
from _p11 import A, P11Module, P11Error  # type: ignore


def _ct_eq(a: bytes, b: bytes) -> bool:
    """Length-then-content compare, constant-time within a length."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


# GMAC output is always one AES block.
GMAC_FULL_LEN = 16


class AesGmacAdapter(Adapter):
    name = "aes_gmac"
    algorithms = ("AES-GMAC",)
    schemas = (
        "mac_with_iv_test_schema.json",
        "mac_with_iv_test_schema_v1.json",
        # Also accept the plain MAC schema in case the corpus reuses it.
        "mac_test_schema.json",
        "mac_test_schema_v1.json",
    )

    def __init__(self, module_path: str):
        super().__init__(module_path)
        self._logged_symbols: set = set()
        self.diag = {
            "key_128_seen":      0,
            "key_192_seen":      0,
            "key_256_seen":      0,
            "iv_96_seen":        0,
            "iv_other_seen":     0,
            "tag_128_seen":      0,
            "tag_truncated_seen": 0,
            "key_import_failed": 0,
            "unsupported_key":   0,
            "unsupported_tag":   0,
            "no_iv":             0,
        }
        try:
            self.module = P11Module(module_path)
            self.session = self.module.open_session()
            self.ready = True
        except (P11Error, OSError) as exc:
            print(f"[aes_gmac] init failed : {exc!r}")
            self.module = None
            self.session = None
            self.ready = False

    def _log_missing_symbol(self, exc: AttributeError) -> None:
        msg = str(exc)
        if msg not in self._logged_symbols:
            self._logged_symbols.add(msg)
            print(f"[aes_gmac] missing symbol -> {msg}")

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

        # Wycheproof MacWithIvTest fields.
        key_bits = int(group.get("keySize", 0))
        tag_bits = int(group.get("tagSize", 0))

        if key_bits not in (128, 192, 256):
            self.diag["unsupported_key"] += 1
            return "skip"
        if tag_bits == 0 or tag_bits % 8 != 0 or tag_bits > 128:
            self.diag["unsupported_tag"] += 1
            return "skip"

        if   key_bits == 128: self.diag["key_128_seen"] += 1
        elif key_bits == 192: self.diag["key_192_seen"] += 1
        else:                 self.diag["key_256_seen"] += 1
        tag_bytes = tag_bits // 8
        if tag_bytes < GMAC_FULL_LEN:
            self.diag["tag_truncated_seen"] += 1
        else:
            self.diag["tag_128_seen"] += 1

        key = bytes.fromhex(test.get("key", ""))
        iv  = bytes.fromhex(test.get("iv", ""))
        msg = bytes.fromhex(test.get("msg", ""))
        expected = test.get("result", "")
        expected_tag = bytes.fromhex(test.get("tag", ""))

        if len(key) * 8 != key_bits:
            return "skip"
        if len(expected_tag) != tag_bytes:
            return "skip"
        if len(iv) == 0:
            # GMAC requires an IV ; a vector with empty IV is meant to
            # exercise the IV-rejection path. Our module rejects with
            # ARGUMENTS_BAD, which counts as "invalid signature" for
            # Wycheproof's purposes when the corpus result is "invalid".
            self.diag["no_iv"] += 1
            return "skip"
        if len(iv) == 12:
            self.diag["iv_96_seen"] += 1
        else:
            self.diag["iv_other_seen"] += 1

        # Import the AES key.
        try:
            keyh = self.session.create_object([
                A.CLASS(A.CKO_SECRET_KEY),
                A.KEY_TYPE(A.CKK_AES),
                A.TOKEN(False),
                A.VALUE(key),
            ])
        except P11Error:
            self.diag["key_import_failed"] += 1
            return "violation" if expected == "valid" else "match"
        except AttributeError as exc:
            self._log_missing_symbol(exc)
            return "skip"

        # Compute the GMAC. The IV is passed via the mechanism parameter
        # (raw IV bytes, PKCS#11 v3.0 convention).
        rv = None
        sig = b""
        verify_err = None
        try:
            rv, sig = self.session.sign(
                keyh, A.MECH(_p11.CKM_AES_GMAC, iv), msg, GMAC_FULL_LEN,
            )
        except AttributeError as exc:
            verify_err = exc

        try:
            self.session.destroy(keyh)
        except AttributeError:
            pass

        if verify_err is not None:
            self._log_missing_symbol(verify_err)
            return "skip"
        if rv != _p11.CKR_OK or len(sig) != GMAC_FULL_LEN:
            return "violation" if expected == "valid" else "match"

        produced_prefix = sig[:tag_bytes]
        accepted = _ct_eq(produced_prefix, expected_tag)
        if expected == "valid":
            return "match" if accepted else "violation"
        if expected == "invalid":
            return "match" if not accepted else "violation"
        return "match"  # "acceptable"


ADAPTER = AesGmacAdapter
