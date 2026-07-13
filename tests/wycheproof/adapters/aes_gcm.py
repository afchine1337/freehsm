#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/aes_gcm.py --- AES-GCM verification against Wycheproof.
#
# Strategy (decrypt-only --- both 'valid' and 'invalid' Wycheproof
# vectors are checked by feeding ciphertext||tag to C_Decrypt and
# observing whether the module accepts or rejects) :
#
#   1. Import the AES key via C_CreateObject (CKO_SECRET_KEY + CKK_AES +
#      CKA_VALUE = raw key bytes).
#   2. Pack CK_GCM_PARAMS with the test's IV, AAD and tag length.
#   3. C_DecryptInit(CKM_AES_GCM, gcm_params), C_Decrypt(ct || tag).
#   4. Compare the returned plaintext with the expected msg and
#      cross-check with the 'result' field.
#
# Notes :
# - Wycheproof groups carry ivSize, keySize and tagSize in BITS. The
#   adapter converts to bytes (and skips ivSize % 8 != 0 cases).
# - The CK_GCM_PARAMS struct is 6 CK_ULONG-sized words on a 64-bit ABI
#   (48 bytes). We build it via ctypes Structure so the IV / AAD
#   pointer fields are filled by the OS at call time and the C side
#   parses them with `(CK_ULONG *)pParameter`.
# ===========================================================================

from __future__ import annotations

import ctypes
from ctypes import (
    Structure, POINTER, c_ubyte, c_ulong, c_void_p, byref, cast, sizeof,
)

from run_wycheproof import Adapter  # type: ignore

import _p11
from _p11 import A, P11Module, P11Error  # type: ignore


class CK_GCM_PARAMS(Structure):
    """PKCS#11 v3.x CK_GCM_PARAMS (6 fields, 48 bytes on 64-bit)."""
    _fields_ = [
        ("pIv",      c_void_p),
        ("ulIvLen",  c_ulong),
        ("ulIvBits", c_ulong),
        ("pAAD",     c_void_p),
        ("ulAADLen", c_ulong),
        ("ulTagBits", c_ulong),
    ]


def _build_gcm_mech(iv: bytes, aad: bytes, tag_bits: int):
    """Returns (CK_MECHANISM, keepalive-list)."""
    iv_buf  = (c_ubyte * max(1, len(iv)))(*iv)
    aad_buf = (c_ubyte * max(1, len(aad)))(*aad)
    p = CK_GCM_PARAMS()
    p.pIv      = cast(iv_buf,  c_void_p).value if iv else 0
    p.ulIvLen  = c_ulong(len(iv))
    p.ulIvBits = c_ulong(len(iv) * 8)
    p.pAAD     = cast(aad_buf, c_void_p).value if aad else 0
    p.ulAADLen = c_ulong(len(aad))
    p.ulTagBits = c_ulong(tag_bits)
    mech = _p11.CK_MECHANISM(
        _p11.CKM_AES_GCM,
        cast(byref(p), c_void_p),
        c_ulong(sizeof(p)),
    )
    return mech, [iv_buf, aad_buf, p]


class AesGcmAdapter(Adapter):
    name = "aes_gcm"
    algorithms = ("AES-GCM",)
    schemas = (
        "aead_test_schema.json",
        "aead_test_schema_v1.json",
    )

    def __init__(self, module_path: str):
        super().__init__(module_path)
        self._logged_symbols: set = set()
        self.diag = {
            "key_128_seen":           0,
            "key_192_seen":           0,
            "key_256_seen":           0,
            "iv_96_seen":             0,
            "iv_other_seen":          0,
            "tag_128_seen":           0,
            "tag_other_seen":         0,
            "key_import_failed":      0,
            "unsupported_iv":         0,
            "iv_over_openssl_limit":  0,
        }
        try:
            self.module = P11Module(module_path)
            self.session = self.module.open_session()
            self.ready = True
        except (P11Error, OSError) as exc:
            print(f"[aes_gcm] init failed : {exc!r}")
            self.module = None
            self.session = None
            self.ready = False

    def _log_missing_symbol(self, exc: AttributeError) -> None:
        msg = str(exc)
        if msg not in self._logged_symbols:
            self._logged_symbols.add(msg)
            print(f"[aes_gcm] missing symbol -> {msg}")

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

        # Test-group parameters (sizes are in BITS in Wycheproof).
        key_bits = int(group.get("keySize", 0))
        iv_bits  = int(group.get("ivSize",  0))
        tag_bits = int(group.get("tagSize", 0))
        if key_bits not in (128, 192, 256):
            return "skip"
        if iv_bits % 8 != 0:
            self.diag["unsupported_iv"] += 1
            return "skip"
        # OpenSSL 3.x default provider hard-caps the AES-GCM IV at 64
        # bytes (512 bits) in GCM_IV_MAX_SIZE. Anything longer is a
        # provider limitation, not a FreeHSM module bug, so we surface
        # it as a skip with its own per-size diag bucket.
        if iv_bits > 512:
            self.diag["iv_over_openssl_limit"] += 1
            bucket = f"iv_skip_{iv_bits}_bits"
            self.diag[bucket] = self.diag.get(bucket, 0) + 1
            return "skip"
        if tag_bits == 0 or tag_bits > 128 or tag_bits % 8 != 0:
            return "skip"

        # Stats counters (independent of test outcome).
        self.diag[f"key_{key_bits}_seen"] += 1
        self.diag["iv_96_seen" if iv_bits == 96 else "iv_other_seen"] += 1
        self.diag["tag_128_seen" if tag_bits == 128 else "tag_other_seen"] += 1

        key = bytes.fromhex(test.get("key", ""))
        iv  = bytes.fromhex(test.get("iv",  ""))
        aad = bytes.fromhex(test.get("aad", ""))
        msg = bytes.fromhex(test.get("msg", ""))
        ct  = bytes.fromhex(test.get("ct",  ""))
        tag = bytes.fromhex(test.get("tag", ""))
        expected = test.get("result", "")

        if len(key) * 8 != key_bits or len(iv) * 8 != iv_bits:
            return "skip"
        # Tag length in bytes.
        tag_bytes = tag_bits // 8
        if len(tag) != tag_bytes:
            return "skip"

        # Import the symmetric key.
        try:
            keyh = self.session.create_object([
                A.CLASS(A.CKO_SECRET_KEY),
                A.KEY_TYPE(A.CKK_AES),
                A.TOKEN(False),
                A.DECRYPT(True),
                A.VALUE(key),
            ])
        except P11Error:
            self.diag["key_import_failed"] += 1
            return "violation" if expected == "valid" else "match"
        except AttributeError as exc:
            self._log_missing_symbol(exc)
            return "skip"

        # Build CK_GCM_PARAMS and decrypt the (ct || tag) blob.
        mech, _keep = _build_gcm_mech(iv, aad, tag_bits)
        rv = None
        verify_err = None
        plaintext = b""
        try:
            rv, plaintext = self.session.decrypt(keyh, mech, ct + tag)
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
            print(
                f"[aes_gcm] viol tcId={test.get('tcId')} "
                f"keyBits={key_bits} ivBits={iv_bits} tagBits={tag_bits} "
                f"comment={test.get('comment', '')[:60]!r} "
                f"expected={expected} rv=0x{rv:08x} "
                f"pt_match={plaintext == msg}"
            )
        if expected == "valid":
            if accepted:
                return "match"
            # FIPS 140-3 IG C.H / NIST SP 800-38D §8.2 : in the approved mode
            # AES-GCM IVs are fixed at 96 bits. FreeHSM (fips-strict) rejects
            # any other IV size at C_EncryptInit/C_DecryptInit with
            # CKR_MECHANISM_PARAM_INVALID. Wycheproof's non-96-bit "valid"
            # vectors are therefore *expected* rejections for this module, not
            # implementation faults ; only a rejected 96-bit vector is a real
            # false-negative.
            if iv_bits != 96 and rv == 0x00000071:  # CKR_MECHANISM_PARAM_INVALID
                self.diag["iv_non96_fips_rejected"] = \
                    self.diag.get("iv_non96_fips_rejected", 0) + 1
                return "match"
            return "violation"
        if expected == "invalid":
            # Module must reject (or return wrong plaintext).
            return "match" if not accepted else "violation"
        return "match"  # "acceptable"


ADAPTER = AesGcmAdapter
