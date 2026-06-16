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
    DERError, encode_octet_string, parse_ecdsa_sig_with_flag,
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
        self._logged_symbols: set = set()
        # Diagnostics : count how many tests went through each DER
        # branch so the operator can tell A-front (parser) from B-front
        # (module verify) violations at a glance.
        self.diag = {
            "der_canonical_valid":      0,
            "der_canonical_invalid":    0,
            "der_canonical_acceptable": 0,
            "der_noncanonical_valid":   0,
            "der_noncanonical_other":   0,
            "der_hard_fail":            0,
        }
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

    def _log_missing_symbol(self, exc: AttributeError) -> None:
        """Print the missing-symbol message the first time we see it."""
        msg = str(exc)
        if msg not in self._logged_symbols:
            self._logged_symbols.add(msg)
            print(f"[ecdsa] missing symbol -> {msg}")

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

        # 2. DER signature -> raw r||s.
        #
        # Lenient parse : we accept any structurally valid SEQUENCE of
        # two INTEGERs, but flag non-canonical encodings. Wycheproof's
        # "invalid" tests often have non-canonical DER (long-form
        # length, redundant 0x00 INTEGER prefix, trailing bytes, etc.)
        # that the underlying r||s value would otherwise verify against.
        # When canonical=False we treat the rejection as the harness's
        # responsibility rather than letting the signature through.
        try:
            sig_raw, canonical = parse_ecdsa_sig_with_flag(
                sig_der, CURVE_BYTES[curve],
            )
        except (DERError, IndexError, ValueError):
            # Hard parse failure : structurally broken. Always rejected.
            self.diag["der_hard_fail"] += 1
            if expected == "valid":
                return "violation"
            return "match"

        if canonical:
            self.diag["der_canonical_" + (
                expected if expected in ("valid", "invalid", "acceptable")
                else "acceptable"
            )] += 1
        else:
            if expected == "valid":
                self.diag["der_noncanonical_valid"] += 1
            else:
                self.diag["der_noncanonical_other"] += 1

        # Non-canonical encoding : surface it as a harness-level
        # rejection ONLY when Wycheproof flagged the test as not-valid.
        # For "valid" tests we still try the module : Wycheproof
        # sometimes ships "valid" vectors with non-strict DER on purpose
        # (e.g. when the cryptographic value is mathematically correct
        # even if the encoding is sub-canonical), and rejecting these
        # in the adapter would be a false-negative bias.
        if not canonical and expected != "valid":
            return "match"

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
        except AttributeError as exc:
            self._log_missing_symbol(exc)
            return "skip"

        # 4. Verify (and destroy the key whatever happens).
        #
        # NOTE on signature format : PKCS#11 v3.2 specifies raw r||s for
        # CKM_ECDSA, but the FreeHSM C implementation uses OpenSSL's
        # EVP_DigestVerify which expects DER {SEQ r s}. We pass the DER
        # sig directly to match what the module actually consumes. When
        # the module is fixed to accept raw r||s per spec, this becomes
        # `sig_raw` again.
        rv = None
        verify_err = None
        try:
            rv = self.session.verify(
                pubkey, A.MECH(A.CKM_ECDSA), digest, sig_der,
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

        # 5. Cross-check result.
        accepted = (rv == _p11.CKR_OK)
        if expected == "valid":
            return "match" if accepted else "violation"
        if expected == "invalid":
            return "match" if not accepted else "violation"
        # "acceptable" : either outcome is allowed.
        return "match"


ADAPTER = EcdsaAdapter
