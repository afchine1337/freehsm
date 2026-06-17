#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/rsa_oaep.py --- RSA-OAEP decrypt verification against Wycheproof.
#
# Strategy :
#   1. Import the private key as a PKCS#8 PrivateKeyInfo DER blob via
#      C_CreateObject (CKO_PRIVATE_KEY + CKK_RSA + CKA_VALUE). The module
#      stores the bytes verbatim ; the asymmetric decrypt path then runs
#      d2i_AutoPrivateKey on them, which accepts both PKCS#8 and the
#      PKCS#1 RSAPrivateKey shape.
#   2. Pack a CK_RSA_PKCS_OAEP_PARAMS struct (5 CK_ULONG-sized words,
#      40 bytes on a 64-bit ABI) carrying the test's hashAlg, mgf,
#      source and (optional) label.
#   3. C_DecryptInit(CKM_RSA_PKCS_OAEP, params), C_Decrypt(ct) -> msg.
#   4. Compare the produced plaintext with the expected message and
#      cross-check with the 'result' field.
# ===========================================================================

from __future__ import annotations

import ctypes
from ctypes import (
    Structure, byref, cast, c_ubyte, c_ulong, c_void_p, sizeof,
)

from run_wycheproof import Adapter  # type: ignore

import _p11
from _p11 import A, P11Module, P11Error  # type: ignore


# Wycheproof "sha" -> CKM_SHAxxx mechanism identifier used in
# CK_RSA_PKCS_OAEP_PARAMS.hashAlg.
HASH_TO_CKM = {
    "SHA-1":   _p11.CKM_SHA_1,
    "SHA-256": _p11.CKM_SHA256,
    "SHA-384": _p11.CKM_SHA384,
    "SHA-512": _p11.CKM_SHA512,
}

# Wycheproof "mgfSha" (or "sha" when mgfSha is absent) -> CKG_MGF1_SHAxxx
# value used in CK_RSA_PKCS_OAEP_PARAMS.mgf.
HASH_TO_MGF = {
    "SHA-1":   _p11.CKG_MGF1_SHA1,
    "SHA-256": _p11.CKG_MGF1_SHA256,
    "SHA-384": _p11.CKG_MGF1_SHA384,
    "SHA-512": _p11.CKG_MGF1_SHA512,
}

# CK_RSA_PKCS_OAEP_SOURCE_TYPE : CKZ_DATA_SPECIFIED = 1.
CKZ_DATA_SPECIFIED = 0x00000001


class CK_RSA_PKCS_OAEP_PARAMS(Structure):
    _fields_ = [
        ("hashAlg",         c_ulong),
        ("mgf",             c_ulong),
        ("source",          c_ulong),
        ("pSourceData",     c_void_p),
        ("ulSourceDataLen", c_ulong),
    ]


def _build_oaep_mech(hash_alg: int, mgf: int, label: bytes):
    """Returns (CK_MECHANISM, keepalive-list)."""
    if label:
        label_buf = (c_ubyte * len(label))(*label)
        label_ptr = cast(label_buf, c_void_p).value
        label_len = len(label)
    else:
        label_buf = None
        label_ptr = 0
        label_len = 0
    p = CK_RSA_PKCS_OAEP_PARAMS()
    p.hashAlg         = c_ulong(hash_alg)
    p.mgf             = c_ulong(mgf)
    p.source          = c_ulong(CKZ_DATA_SPECIFIED)
    p.pSourceData     = label_ptr
    p.ulSourceDataLen = c_ulong(label_len)
    mech = _p11.CK_MECHANISM(
        _p11.CKM_RSA_PKCS_OAEP,
        cast(byref(p), c_void_p),
        c_ulong(sizeof(p)),
    )
    return mech, [label_buf, p]


class RsaOaepAdapter(Adapter):
    name = "rsa_oaep"
    algorithms = ("RSAES-OAEP",)
    schemas = (
        "rsaes_oaep_decrypt_schema.json",
        "rsaes_oaep_decrypt_schema_v1.json",
    )

    def __init__(self, module_path: str):
        super().__init__(module_path)
        self._logged_symbols: set = set()
        self.diag = {
            "sha256_seen":         0,
            "sha384_seen":         0,
            "sha512_seen":         0,
            "sha1_seen":           0,
            "label_empty":         0,
            "label_nonempty":      0,
            "key_import_failed":   0,
            "unsupported_sha":     0,
            "unsupported_mgf":     0,
        }
        try:
            self.module = P11Module(module_path)
            self.session = self.module.open_session()
            self.ready = True
        except (P11Error, OSError) as exc:
            print(f"[rsa_oaep] init failed : {exc!r}")
            self.module = None
            self.session = None
            self.ready = False

    def _log_missing_symbol(self, exc: AttributeError) -> None:
        msg = str(exc)
        if msg not in self._logged_symbols:
            self._logged_symbols.add(msg)
            print(f"[rsa_oaep] missing symbol -> {msg}")

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

        sha = group.get("sha", "")
        mgf_sha = group.get("mgfSha", sha)
        if sha not in HASH_TO_CKM:
            self.diag["unsupported_sha"] += 1
            return "skip"
        if group.get("mgf", "MGF1") != "MGF1" or mgf_sha not in HASH_TO_MGF:
            self.diag["unsupported_mgf"] += 1
            return "skip"

        # Stats counters
        if sha == "SHA-1":
            self.diag["sha1_seen"] += 1
        elif sha == "SHA-256":
            self.diag["sha256_seen"] += 1
        elif sha == "SHA-384":
            self.diag["sha384_seen"] += 1
        else:
            self.diag["sha512_seen"] += 1

        priv_hex = (group.get("privateKeyPkcs8")
                    or group.get("privateKey", {}).get("pkcs8")
                    or "")
        if not priv_hex:
            return "skip"
        priv_der = bytes.fromhex(priv_hex)

        ct  = bytes.fromhex(test.get("ct",  ""))
        msg = bytes.fromhex(test.get("msg", ""))
        label = bytes.fromhex(test.get("label", ""))
        expected = test.get("result", "")

        if label:
            self.diag["label_nonempty"] += 1
        else:
            self.diag["label_empty"] += 1

        # Import the RSA private key (PKCS#8 DER stored verbatim, the
        # module's decrypt path will d2i_AutoPrivateKey it).
        try:
            keyh = self.session.create_object([
                A.CLASS(A.CKO_PRIVATE_KEY),
                A.KEY_TYPE(A.CKK_RSA),
                A.TOKEN(False),
                A.VALUE(priv_der),
            ])
        except P11Error:
            self.diag["key_import_failed"] += 1
            return "violation" if expected == "valid" else "match"
        except AttributeError as exc:
            self._log_missing_symbol(exc)
            return "skip"

        # Build CK_RSA_PKCS_OAEP_PARAMS and decrypt.
        mech, _keep = _build_oaep_mech(
            HASH_TO_CKM[sha], HASH_TO_MGF[mgf_sha], label,
        )
        rv = None
        verify_err = None
        plaintext = b""
        try:
            rv, plaintext = self.session.decrypt(keyh, mech, ct)
        except AttributeError as exc:
            verify_err = exc

        try:
            self.session.destroy(keyh)
        except AttributeError:
            pass

        if verify_err is not None:
            self._log_missing_symbol(verify_err)
            return "skip"

        accepted = (rv == _p11.CKR_OK) and (plaintext == msg)
        outcome_violation = (
            (expected == "valid" and not accepted)
            or (expected == "invalid" and accepted)
        )
        if outcome_violation and self.diag.get("_logged_viols", 0) < 6:
            self.diag["_logged_viols"] = self.diag.get("_logged_viols", 0) + 1
            ptmatch = (plaintext == msg)
            print(
                f"[rsa_oaep] viol tcId={test.get('tcId')} sha={sha} "
                f"mgfSha={mgf_sha} label_len={len(label)} ct_len={len(ct)} "
                f"comment={test.get('comment', '')[:40]!r} "
                f"expected={expected} rv=0x{rv:08x} "
                f"pt_len={len(plaintext)} pt_match={ptmatch}"
            )
        if expected == "valid":
            return "match" if accepted else "violation"
        if expected == "invalid":
            return "match" if not accepted else "violation"
        return "match"  # "acceptable"


ADAPTER = RsaOaepAdapter
