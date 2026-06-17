#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/hmac.py --- HMAC-SHA-{256,384,512} verification against Wycheproof.
#
# Strategy :
#   1. Import the HMAC key as a CKO_SECRET_KEY + CKK_GENERIC_SECRET object
#      with CKA_VALUE = raw key bytes (any length the underlying HMAC
#      accepts).
#   2. C_SignInit + C_Sign with the matching CKM_SHA{256,384,512}_HMAC
#      mechanism to compute the full-length MAC.
#   3. Truncate to the test's tagSize and constant-time compare with the
#      expected tag.
#
# Outcome :
#   - expected=valid   : produced MAC prefix == expected tag -> match
#   - expected=invalid : MAC prefix != expected tag           -> match
#   - mismatch the other way                                  -> violation
# ===========================================================================

from __future__ import annotations

# WARNING : this file is named hmac.py so `import hmac` would shadow the
# stdlib module from within this module's namespace. Use secrets.compare_
# digest for the constant-time comparison --- same primitive, no name
# collision.
import secrets

from run_wycheproof import Adapter  # type: ignore

import _p11
from _p11 import A, P11Module, P11Error  # type: ignore


# Wycheproof "algorithm" -> (CKM_SHAxxx_HMAC, full digest length in bytes).
ALG_TO_MECH = {
    "HMACSHA256": (_p11.CKM_SHA256_HMAC, 32),
    "HMACSHA384": (_p11.CKM_SHA384_HMAC, 48),
    "HMACSHA512": (_p11.CKM_SHA512_HMAC, 64),
}


class HmacAdapter(Adapter):
    name = "hmac"
    algorithms = tuple(ALG_TO_MECH.keys())
    schemas = (
        "mac_test_schema.json",
        "mac_test_schema_v1.json",
    )

    def __init__(self, module_path: str):
        super().__init__(module_path)
        self._logged_symbols: set = set()
        self.diag = {
            "hmac_sha256_seen":   0,
            "hmac_sha384_seen":   0,
            "hmac_sha512_seen":   0,
            "tag_truncated_seen": 0,
            "tag_full_seen":      0,
            "key_import_failed":  0,
        }
        try:
            self.module = P11Module(module_path)
            self.session = self.module.open_session()
            self.ready = True
        except (P11Error, OSError) as exc:
            print(f"[hmac] init failed : {exc!r}")
            self.module = None
            self.session = None
            self.ready = False

    def _log_missing_symbol(self, exc: AttributeError) -> None:
        msg = str(exc)
        if msg not in self._logged_symbols:
            self._logged_symbols.add(msg)
            print(f"[hmac] missing symbol -> {msg}")

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

        # Wycheproof MacTest carries algorithm at the file level ; we
        # have it via the adapter's algorithms tuple already. The hash
        # selection therefore comes from the file's algorithm string,
        # not from any per-group field.
        algorithm = getattr(self, "_current_algorithm", None)
        # The adapter receives the algorithm via the file's top-level
        # 'algorithm' field passed to the Adapter through run_file. We
        # can't easily reach it here from `group` ; tag size is per
        # group though.
        key_bits = int(group.get("keySize", 0))
        tag_bits = int(group.get("tagSize", 0))
        if tag_bits == 0 or tag_bits % 8 != 0:
            return "skip"

        # Resolve the file-level algorithm via a per-test attribute set
        # by run_file_hook (see below) ; fall back to inspecting the
        # mac size if not available.
        algo = test.get("_algorithm")
        if not algo:
            algo = group.get("_algorithm")
        if algo not in ALG_TO_MECH:
            return "skip"
        mech_id, full_len = ALG_TO_MECH[algo]

        # Diagnostics
        if algo == "HMACSHA256":
            self.diag["hmac_sha256_seen"] += 1
        elif algo == "HMACSHA384":
            self.diag["hmac_sha384_seen"] += 1
        else:
            self.diag["hmac_sha512_seen"] += 1
        tag_bytes = tag_bits // 8
        if tag_bytes < full_len:
            self.diag["tag_truncated_seen"] += 1
        else:
            self.diag["tag_full_seen"] += 1

        key = bytes.fromhex(test.get("key", ""))
        msg = bytes.fromhex(test.get("msg", ""))
        expected = test.get("result", "")
        expected_tag = bytes.fromhex(test.get("tag", ""))

        if len(key) * 8 != key_bits:
            return "skip"

        # Import the HMAC key.
        try:
            keyh = self.session.create_object([
                A.CLASS(A.CKO_SECRET_KEY),
                A.KEY_TYPE(A.CKK_GENERIC_SECRET),
                A.TOKEN(False),
                A.VALUE(key),
            ])
        except P11Error:
            self.diag["key_import_failed"] += 1
            return "violation" if expected == "valid" else "match"
        except AttributeError as exc:
            self._log_missing_symbol(exc)
            return "skip"

        # Compute the MAC.
        rv = None
        sig = b""
        verify_err = None
        try:
            rv, sig = self.session.sign(keyh, A.MECH(mech_id), msg, full_len)
        except AttributeError as exc:
            verify_err = exc

        try:
            self.session.destroy(keyh)
        except AttributeError:
            pass

        if verify_err is not None:
            self._log_missing_symbol(verify_err)
            return "skip"
        if rv != _p11.CKR_OK or len(sig) != full_len:
            return "violation" if expected == "valid" else "match"

        produced_prefix = sig[:tag_bytes]
        accepted = secrets.compare_digest(produced_prefix, expected_tag)
        if expected == "valid":
            return "match" if accepted else "violation"
        if expected == "invalid":
            return "match" if not accepted else "violation"
        return "match"  # "acceptable"


ADAPTER = HmacAdapter
