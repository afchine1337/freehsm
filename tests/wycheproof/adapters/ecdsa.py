#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/ecdsa.py --- ECDSA signature verification against Wycheproof.
#
# For each Wycheproof EcdsaVerify test we :
#   1. Hash the message ourselves with the schema's `sha` digest.
#   2. Decode the DER signature {SEQ {INT r} {INT s}} to raw r||s.
#   3. Import the public key as a SESSION public-key object
#      (CKO_PUBLIC_KEY, CKK_EC, EC_PARAMS=curve OID, EC_POINT=DER-wrapped
#      uncompressed SEC1 point).
#   4. Call C_VerifyInit + C_Verify with mechanism CKM_ECDSA (raw, since
#      we pre-hashed the message ourselves).
#   5. Compare the CKR_* return code with the Wycheproof expected result.
#
# Note on pre-hashing : we use the pure CKM_ECDSA mechanism rather than
# CKM_ECDSA_SHAxxx because (a) it keeps the adapter independent of which
# digest mechanisms the module exposes, (b) Wycheproof publishes the
# expected hash in the schema, so we can pre-hash deterministically.
# ===========================================================================

from __future__ import annotations

import hashlib

from run_wycheproof import Adapter  # type: ignore

# Local imports : adapters/ is on sys.path (set by run_wycheproof.py).
import _p11
from _p11 import A, P11Module, P11Error  # type: ignore
from _der import (  # type: ignore
    DERError, encode_octet_string, parse_ecdsa_sig_to_raw,
)

# Curve OID encoded as DER (TAG=OID, the value bytes come from RFC 5480 / SEC 2).
CURVE_OID_DER = {
    "secp256r1": bytes.fromhex("06082a8648ce3d030107"),
    "secp384r1": bytes.fromhex("06052b81040022"),
    "secp521r1": bytes.fromhex("06052b81040023"),
}

# Curve scalar byte size, used for DER signature -> raw r||s padding.
CURVE_BYTES = {
    "secp256r1": 32,
    "secp384r1": 48,
    "secp521r1": 66,
}

# Map Wycheproof "sha" field to a Python hashlib name.
HASHLIB_NAME = {
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
}


class EcdsaAdapter(Adapter):
    name = "ecdsa"
    algorithms = ("ECDSA",)

    def __init__(self, module_path: str):
        super().__init__(module_path)
        try:
            self.module = P11Module(module_path)
            self.session = self.module.open_session()
            self.ready = True
        except (P11Error, OSError) as exc:
            # Bail out gracefully -- the orchestrator will count this as
            # an init-failure equivalent to "skip" for every vector.
            print(f"[ecdsa] init failed : {exc!r}")
            self.module = None
            self.session = None
            self.ready = False

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
        curve = pub.get("curve")
        if curve not in CURVE_OID_DER:
            return "skip"

        hash_name = HASHLIB_NAME.get(group.get("sha", ""))
        if hash_name is None:
            return "skip"

        uncompressed = pub.get("uncompressed") or pub.get("publicKey")
        if not uncompressed:
            return "skip"

        msg = bytes.fromhex(test.get("msg", ""))
        sig_der = bytes.fromhex(test.get("sig", ""))
        expected = test.get("result", "")  # "valid"/"invalid"/"acceptable"

        # 1. Pre-hash the message.
        digest = hashlib.new(hash_name, msg).digest()

        # 2. DER signature -> raw r||s. A decode failure on an "invalid"
        # test vector counts as a correct rejection ; on a "valid" test
        # it counts as a violation (the signature is supposed to parse).
        try:
            sig_raw = parse_ecdsa_sig_to_raw(sig_der, CURVE_BYTES[curve])
        except (DERError, IndexError, ValueError):
            if expected == "valid":
                return "violation"
            return "match"  # invalid / acceptable : rejection is fine.

        # 3. Import the public key as a session object.
        point_bytes = bytes.fromhex(uncompressed)
        ec_point = encode_octet_string(point_bytes)

        try:
            pubkey = self.session.create_object([
                A.CLASS(A.CKO_PUBLIC_KEY),
                A.KEY_TYPE(A.CKK_EC),
                A.TOKEN(False),
                A.VERIFY(True),
                A.EC_PARAMS(CURVE_OID_DER[curve]),
                A.EC_POINT(ec_point),
            ])
        except P11Error:
            # Module refused the key import : if Wycheproof expected
            # "valid", that is a violation. Otherwise it is fine.
            return "violation" if expected == "valid" else "match"

        # 4. Verify.
        try:
            rv = self.session.verify(
                pubkey, A.MECH(A.CKM_ECDSA), digest, sig_raw,
            )
        finally:
            self.session.destroy(pubkey)

        # 5. Cross-check result.
        accepted = (rv == _p11.CKR_OK)
        if expected == "valid":
            return "match" if accepted else "violation"
        if expected == "invalid":
            return "match" if not accepted else "violation"
        # "acceptable" : either outcome is allowed.
        return "match"


ADAPTER = EcdsaAdapter
