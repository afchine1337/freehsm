#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/eddsa.py --- Ed25519 / Ed448 verification against Wycheproof.
#
# Strategy mirrors the ECDSA / RSA-PSS adapters :
#   1. Import the EdDSA public key (raw 32 or 57 bytes) via C_CreateObject
#      with CKO_PUBLIC_KEY + CKK_EC_EDWARDS + EC_PARAMS (curve OID DER) +
#      EC_POINT (OCTET STRING wrapping the raw pubkey bytes).
#   2. C_VerifyInit + C_Verify with CKM_EDDSA. The mechanism's pParameter
#      is NULL for pure Ed25519 / Ed448 (no pre-hash, no context string).
#   3. The signature is raw 64 bytes (Ed25519) or 114 bytes (Ed448).
# ===========================================================================

from __future__ import annotations

from run_wycheproof import Adapter  # type: ignore

import _p11
from _p11 import A, P11Module, P11Error  # type: ignore
from _der import encode_octet_string  # type: ignore


# Curve name (Wycheproof) -> (OpenSSL/PKCS#11 curve OID DER, sig length).
CURVE_OID_DER = {
    "edwards25519": bytes.fromhex("06032b6570"),   # 1.3.101.112
    "edwards448":   bytes.fromhex("06032b6571"),   # 1.3.101.113
}
SIG_LEN = {
    "edwards25519": 64,
    "edwards448":  114,
}


class EddsaAdapter(Adapter):
    name = "eddsa"
    algorithms = ("EDDSA", "EdDSA")
    schemas = (
        "eddsa_verify_schema.json",
        "eddsa_verify_schema_v1.json",
        "ed25519_verify_schema.json",
        "ed25519_verify_schema_v1.json",
    )

    def __init__(self, module_path: str):
        super().__init__(module_path)
        self._logged_symbols: set = set()
        self.diag = {
            "ed25519_seen":       0,
            "ed448_seen":         0,
            "unsupported_curve":  0,
            "key_import_failed":  0,
        }
        try:
            self.module = P11Module(module_path)
            self.session = self.module.open_session()
            self.ready = True
        except (P11Error, OSError) as exc:
            print(f"[eddsa] init failed : {exc!r}")
            self.module = None
            self.session = None
            self.ready = False

    def _log_missing_symbol(self, exc: AttributeError) -> None:
        msg = str(exc)
        if msg not in self._logged_symbols:
            self._logged_symbols.add(msg)
            print(f"[eddsa] missing symbol -> {msg}")

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

        pub = group.get("publicKey") or group.get("key") or {}
        curve = pub.get("curve", "")
        if curve == "ed25519":
            curve = "edwards25519"
        elif curve == "ed448":
            curve = "edwards448"
        if curve not in CURVE_OID_DER:
            self.diag["unsupported_curve"] += 1
            return "skip"

        if curve == "edwards25519":
            self.diag["ed25519_seen"] += 1
        else:
            self.diag["ed448_seen"] += 1

        # Wycheproof exposes the raw public key under "pk" (hex) for
        # EdDSA. Fallback names just in case the schema rev evolves.
        pk_hex = (
            pub.get("pk")
            or pub.get("publicKey")
            or pub.get("uncompressed")
            or ""
        )
        if not pk_hex:
            return "skip"

        pk_bytes = bytes.fromhex(pk_hex)
        msg = bytes.fromhex(test.get("msg", ""))
        sig = bytes.fromhex(test.get("sig", ""))
        expected = test.get("result", "")  # "valid" / "invalid" / "acceptable"

        # Quick early reject : EdDSA signatures are a fixed size, so
        # anything else is structurally invalid.
        if len(sig) != SIG_LEN[curve]:
            return "violation" if expected == "valid" else "match"

        # Import the pubkey as a session object.
        ec_point = encode_octet_string(pk_bytes)
        try:
            pubkey = self.session.create_object([
                A.CLASS(A.CKO_PUBLIC_KEY),
                A.KEY_TYPE(A.CKK_EC_EDWARDS),
                A.TOKEN(False),
                A.VERIFY(True),
                A.EC_PARAMS(CURVE_OID_DER[curve]),
                A.EC_POINT(ec_point),
            ])
        except P11Error:
            self.diag["key_import_failed"] += 1
            return "violation" if expected == "valid" else "match"
        except AttributeError as exc:
            self._log_missing_symbol(exc)
            return "skip"

        # Verify (and destroy the key whatever happens).
        rv = None
        verify_err = None
        try:
            rv = self.session.verify(
                pubkey, A.MECH(A.CKM_EDDSA), msg, sig,
            )
        except AttributeError as exc:
            verify_err = exc

        try:
            self.session.destroy(pubkey)
        except AttributeError:
            pass

        if verify_err is not None:
            self._log_missing_symbol(verify_err)
            return "skip"

        accepted = (rv == _p11.CKR_OK)
        if expected == "valid":
            return "match" if accepted else "violation"
        if expected == "invalid":
            return "match" if not accepted else "violation"
        return "match"  # "acceptable"


ADAPTER = EddsaAdapter
