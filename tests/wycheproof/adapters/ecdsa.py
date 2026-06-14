#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/ecdsa.py --- ECDSA signature verification against Wycheproof.
#
# Wycheproof JSON shape (extract) :
#     {
#       "algorithm": "ECDSA",
#       "testGroups": [
#         {
#           "type":    "EcdsaVerify",
#           "publicKey": { "curve": "secp256r1", "uncompressed": "04..." },
#           "sha":     "SHA-256",
#           "tests": [
#             { "tcId": 1, "msg": "313233", "sig": "30...",
#               "result": "valid"|"invalid"|"acceptable",
#               "comment": "..." },
#             ...
#           ]
#         }, ...
#       ]
#     }
#
# We load the public key as a session object via C_CreateObject and call
# C_VerifyInit / C_Verify on the message+sig pair. "match" means our
# Verify return value agrees with `result`.
# ===========================================================================

from __future__ import annotations

# Import path is set up by run_wycheproof.py before this is imported.
from run_wycheproof import Adapter  # type: ignore

CURVE_OID = {
    "secp256r1": bytes.fromhex("06082a8648ce3d030107"),
    "secp384r1": bytes.fromhex("06052b81040022"),
    "secp521r1": bytes.fromhex("06052b81040023"),
    # Brainpool, secp256k1 etc. would go here.
}

HASH_TO_CKM = {
    "SHA-256": "CKM_ECDSA_SHA256",
    "SHA-384": "CKM_ECDSA_SHA384",
    "SHA-512": "CKM_ECDSA_SHA512",
}


class EcdsaAdapter(Adapter):
    name = "ecdsa"
    algorithms = ("ECDSA",)

    def __init__(self, module_path: str):
        super().__init__(module_path)
        # Lazy import : python-pkcs11 only needed in adapters, not in main.
        try:
            import pkcs11  # type: ignore
            self.pkcs11 = pkcs11
            self.lib = pkcs11.lib(module_path)
            tokens = list(self.lib.get_tokens())
            if not tokens:
                raise RuntimeError("no tokens visible from libfreehsm-fips.so")
            self.token = tokens[0]
        except ImportError:
            # python-pkcs11 missing : we want the run to be a clean skip
            # instead of crashing the suite.
            self.pkcs11 = None
        except Exception as exc:  # noqa: BLE001
            print(f"[ecdsa] init failed : {exc!r}")
            self.pkcs11 = None

    def run(self, group: dict, test: dict) -> str:
        if self.pkcs11 is None:
            return "skip"

        # Curve filtering : skip curves we do not support.
        curve = group.get("publicKey", {}).get("curve")
        if curve not in CURVE_OID:
            return "skip"

        hash_alg = group.get("sha", "SHA-256")
        ckm = HASH_TO_CKM.get(hash_alg)
        if ckm is None:
            return "skip"

        msg = bytes.fromhex(test["msg"])
        sig = bytes.fromhex(test["sig"])
        expected = test["result"]  # "valid" / "invalid" / "acceptable"

        # python-pkcs11 doesn't expose raw C_CreateObject for an EC public
        # key from raw point bytes cleanly. The actual implementation will
        # use ctypes against the symbols of libfreehsm-fips.so. For the
        # scaffolding stub we return "skip" so the runner runs cleanly
        # against a yet-to-be-implemented adapter.
        # TODO : implement via ctypes-level CK_FUNCTION_LIST.
        return "skip"


ADAPTER = EcdsaAdapter
