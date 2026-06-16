#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/rsa_pss.py --- RSASSA-PSS verification against Wycheproof.
#
# Strategy mirrors the ECDSA adapter :
#   1. Import the RSA public key (n, e) via C_CreateObject (CKO_PUBLIC_KEY
#      + CKK_RSA + CKA_MODULUS + CKA_PUBLIC_EXPONENT). C_CreateObject
#      normalises this into a SubjectPublicKeyInfo blob the verify path
#      can read with d2i_PUBKEY.
#   2. C_VerifyInit + C_Verify with CKM_SHA{256,384,512}_RSA_PKCS_PSS and
#      the raw message. The module hashes inside EVP_DigestVerify and
#      sets the PSS padding with the salt length equal to the digest
#      length (per its current hard-coded policy --- see fhsm_pkcs11.c
#      `mech_is_pss`).
#
# Salt-length caveat : the module uses `EVP_PKEY_CTX_set_rsa_pss_saltlen(-1)`
# which means "salt length equals digest length". Wycheproof ships files
# with various salt lengths in the filename (e.g. "mgf1_28"). We surface
# the salt length in the diag block so the operator can tell which
# subset is covered ; tests with `sLen != hashLen` currently flow
# through the same verify call and will FN until the module accepts a
# per-call salt-length parameter.
# ===========================================================================

from __future__ import annotations

from run_wycheproof import Adapter  # type: ignore

import _p11
from _p11 import A, P11Module, P11Error  # type: ignore


# Wycheproof "sha" -> (CKM_SHAxxx_RSA_PKCS_PSS, hash length in bytes).
HASH_TO_PSS = {
    "SHA-256": (_p11.CKM_SHA256_RSA_PKCS_PSS, 32),
    "SHA-384": (_p11.CKM_SHA384_RSA_PKCS_PSS, 48),
    "SHA-512": (_p11.CKM_SHA512_RSA_PKCS_PSS, 64),
}


class RsaPssAdapter(Adapter):
    name = "rsa_pss"
    algorithms = ("RSASSA-PSS",)
    # Wycheproof schemas (v0 + v1) for RSASSA-PSS verification.
    schemas = (
        "rsassa_pss_verify_schema.json",
        "rsassa_pss_verify_schema_v1.json",
    )

    def __init__(self, module_path: str):
        super().__init__(module_path)
        self._logged_symbols: set = set()
        self.diag = {
            "salt_eq_hashlen":    0,
            "salt_neq_hashlen":   0,
            "unsupported_sha":    0,
            "unsupported_mgf":    0,
            "key_import_failed":  0,
        }
        try:
            self.module = P11Module(module_path)
            self.session = self.module.open_session()
            self.ready = True
        except (P11Error, OSError) as exc:
            print(f"[rsa_pss] init failed : {exc!r}")
            self.module = None
            self.session = None
            self.ready = False

    def _log_missing_symbol(self, exc: AttributeError) -> None:
        msg = str(exc)
        if msg not in self._logged_symbols:
            self._logged_symbols.add(msg)
            print(f"[rsa_pss] missing symbol -> {msg}")

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

        sha_name = group.get("sha", "")
        pss = HASH_TO_PSS.get(sha_name)
        if not pss:
            self.diag["unsupported_sha"] += 1
            return "skip"
        mech_id, hash_len = pss

        # Only MGF1 with the same hash as the signature hash is supported
        # by the module's hard-coded PSS init. Anything else -> skip.
        mgf = group.get("mgf", "MGF1")
        mgf_sha = group.get("mgfSha", sha_name)
        if mgf != "MGF1" or mgf_sha != sha_name:
            self.diag["unsupported_mgf"] += 1
            return "skip"

        # Salt length classification (we still try every test ; the diag
        # just records the distribution).
        s_len = group.get("sLen", hash_len)
        if s_len == hash_len:
            self.diag["salt_eq_hashlen"] += 1
        else:
            self.diag["salt_neq_hashlen"] += 1

        # RsassaPssVerify groups place the key under publicKey :
        #   group["publicKey"]["modulus"] (hex)
        #   group["publicKey"]["publicExponent"] (hex)
        # Older Wycheproof revisions kept them at the top level ; we
        # accept both layouts.
        pubkey_dict = group.get("publicKey") or {}
        n_hex = (
            pubkey_dict.get("modulus")
            or pubkey_dict.get("n")
            or group.get("n")
            or group.get("modulus")
            or ""
        )
        e_hex = (
            pubkey_dict.get("publicExponent")
            or pubkey_dict.get("e")
            or group.get("e")
            or group.get("publicExponent")
            or ""
        )
        if not n_hex or not e_hex:
            return "skip"

        n_bytes = bytes.fromhex(n_hex)
        e_bytes = bytes.fromhex(e_hex)

        msg = bytes.fromhex(test.get("msg", ""))
        sig = bytes.fromhex(test.get("sig", ""))
        expected = test.get("result", "")  # "valid"/"invalid"/"acceptable"

        # Import the RSA pubkey as a session object.
        try:
            pubkey = self.session.create_object([
                A.CLASS(A.CKO_PUBLIC_KEY),
                A.KEY_TYPE(A.CKK_RSA),
                A.TOKEN(False),
                A.VERIFY(True),
                A.MODULUS(n_bytes),
                A.PUBLIC_EXPONENT(e_bytes),
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
                pubkey, A.MECH(mech_id), msg, sig,
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


ADAPTER = RsaPssAdapter
