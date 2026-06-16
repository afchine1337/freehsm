#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/_p11.py --- minimal PKCS#11 v3.x ctypes binding shared by all
# Wycheproof adapters in this directory. Exposes just what the adapters
# need : module load + initialize, session open/close, generic
# C_CreateObject with an attribute template, mechanism wrapping,
# Verify, and graceful zeroize on close.
#
# We bind to the symbol C_<Name> directly on the SO instead of going
# through C_GetFunctionList because (a) freehsm-fips exports every
# function and (b) the ctypes plumbing for the function-list struct is
# substantial and offers no benefit here.
#
# Quick usage :
#     from _p11 import P11Module, A
#     m = P11Module("/path/to/libfreehsm-fips.so")
#     sess = m.open_session()
#     pubkey = sess.create_object([
#         A.CLASS(A.CKO_PUBLIC_KEY),
#         A.KEY_TYPE(A.CKK_EC),
#         A.TOKEN(False),
#         A.VERIFY(True),
#         A.EC_PARAMS(curve_oid_der),
#         A.EC_POINT(point_der_octet_string),
#     ])
#     ok = sess.verify(pubkey, A.MECH(A.CKM_ECDSA), data_hashed, signature_raw)
#     sess.destroy(pubkey)
#     sess.close()
#     m.close()
# ===========================================================================

from __future__ import annotations

import ctypes
import os
from ctypes import (
    CDLL, RTLD_GLOBAL, POINTER, Structure, byref, cast, sizeof,
    c_char, c_ubyte, c_uint8, c_ulong, c_void_p,
)

# --- Type aliases --------------------------------------------------------

CK_BBOOL = c_ubyte
CK_BYTE = c_ubyte
CK_ULONG = c_ulong
CK_VOID_P = c_void_p
CK_BYTE_P = POINTER(c_ubyte)


# --- Common return codes ------------------------------------------------

CKR_OK = 0x00000000
CKR_GENERAL_ERROR = 0x00000005
CKR_FUNCTION_FAILED = 0x00000006
CKR_DATA_INVALID = 0x00000020
CKR_DATA_LEN_RANGE = 0x00000021
CKR_KEY_HANDLE_INVALID = 0x00000060
CKR_MECHANISM_INVALID = 0x00000070
CKR_OBJECT_HANDLE_INVALID = 0x00000082
CKR_SIGNATURE_INVALID = 0x000000C0
CKR_SIGNATURE_LEN_RANGE = 0x000000C1
CKR_TEMPLATE_INCONSISTENT = 0x000000D1
CKR_TEMPLATE_INCOMPLETE = 0x000000D0


# --- Object class / key type / attribute / mechanism constants ----------

CKO_DATA = 0x00000000
CKO_CERTIFICATE = 0x00000001
CKO_PUBLIC_KEY = 0x00000002
CKO_PRIVATE_KEY = 0x00000003
CKO_SECRET_KEY = 0x00000004

CKK_RSA = 0x00000000
CKK_EC = 0x00000003
CKK_AES = 0x0000001F
CKK_GENERIC_SECRET = 0x00000010
CKK_EC_EDWARDS = 0x00000040

CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_KEY_TYPE = 0x00000100
CKA_SENSITIVE = 0x00000103
CKA_VERIFY = 0x0000010A
CKA_EC_PARAMS = 0x00000180
CKA_EC_POINT = 0x00000181

CKM_RSA_PKCS = 0x00000001
CKM_RSA_PKCS_OAEP = 0x00000009
CKM_RSA_PKCS_PSS = 0x0000000D
CKM_SHA256_RSA_PKCS_PSS = 0x00000043
CKM_SHA384_RSA_PKCS_PSS = 0x00000044
CKM_SHA512_RSA_PKCS_PSS = 0x00000045
CKM_ECDSA = 0x00001041
CKM_ECDSA_SHA256 = 0x00001044
CKM_ECDSA_SHA384 = 0x00001045
CKM_ECDSA_SHA512 = 0x00001046

# Hash mechanism identifiers used inside CK_RSA_PKCS_PSS_PARAMS.hashAlg.
CKM_SHA256 = 0x00000250
CKM_SHA384 = 0x00000260
CKM_SHA512 = 0x00000270

# MGF identifiers.
CKG_MGF1_SHA256 = 0x00000002
CKG_MGF1_SHA384 = 0x00000003
CKG_MGF1_SHA512 = 0x00000004

# Attribute types for RSA public-key import.
CKA_MODULUS = 0x00000120
CKA_PUBLIC_EXPONENT = 0x00000122
CKM_EDDSA = 0x00001057
CKM_AES_GCM = 0x00001087
CKM_SHA256_HMAC = 0x00000251

CKF_SERIAL_SESSION = 0x00000004
CKF_RW_SESSION = 0x00000002

CKU_SO = 0x00000000
CKU_USER = 0x00000001

CKR_TOKEN_NOT_PRESENT = 0x000000E0
CKR_USER_PIN_NOT_INITIALIZED = 0x000000A0

# Wycheproof bootstrap defaults --- must match the dev token bootstrap
# documented in tests/full_crypto_pkcs11.sh. The label is arbitrary, the
# PINs are dev-only and never leave the test container.
BOOTSTRAP_SO_PIN = b"00000000"
BOOTSTRAP_USER_PIN = b"user0000"
BOOTSTRAP_LABEL = b"wycheproof".ljust(32, b" ")  # PKCS#11 label is 32 bytes


# --- Native PKCS#11 structures ------------------------------------------

class CK_ATTRIBUTE(Structure):
    _fields_ = [
        ("type", CK_ULONG),
        ("pValue", CK_VOID_P),
        ("ulValueLen", CK_ULONG),
    ]


class CK_MECHANISM(Structure):
    _fields_ = [
        ("mechanism", CK_ULONG),
        ("pParameter", CK_VOID_P),
        ("ulParameterLen", CK_ULONG),
    ]


# --- Attribute builder ---------------------------------------------------
#
# A handful of small constructors that take a Python value and return a
# tuple (CK_ATTRIBUTE struct, owning buffer) -- the owning buffer keeps
# pValue alive until C_CreateObject returns.
# ---------------------------------------------------------------------------

class _AttrBuilder:
    """Tiny DSL: A.CLASS(A.CKO_PUBLIC_KEY) -> (attr, keepalive)."""

    # Re-export constants for the DSL.
    CKO_PUBLIC_KEY = CKO_PUBLIC_KEY
    CKO_PRIVATE_KEY = CKO_PRIVATE_KEY
    CKK_EC = CKK_EC
    CKK_RSA = CKK_RSA
    CKK_EC_EDWARDS = CKK_EC_EDWARDS
    CKM_ECDSA = CKM_ECDSA
    CKM_ECDSA_SHA256 = CKM_ECDSA_SHA256
    CKM_ECDSA_SHA384 = CKM_ECDSA_SHA384
    CKM_ECDSA_SHA512 = CKM_ECDSA_SHA512
    CKM_EDDSA = CKM_EDDSA

    @staticmethod
    def _ulong(attr_type, value):
        buf = CK_ULONG(value)
        return (CK_ATTRIBUTE(attr_type, cast(byref(buf), CK_VOID_P),
                             CK_ULONG(sizeof(buf))), buf)

    @staticmethod
    def _bbool(attr_type, value):
        buf = CK_BBOOL(1 if value else 0)
        return (CK_ATTRIBUTE(attr_type, cast(byref(buf), CK_VOID_P),
                             CK_ULONG(sizeof(buf))), buf)

    @staticmethod
    def _bytes(attr_type, value: bytes):
        buf = (c_ubyte * len(value))(*value)
        return (CK_ATTRIBUTE(attr_type, cast(buf, CK_VOID_P),
                             CK_ULONG(len(value))), buf)

    @classmethod
    def CLASS(cls, v): return cls._ulong(CKA_CLASS, v)
    @classmethod
    def KEY_TYPE(cls, v): return cls._ulong(CKA_KEY_TYPE, v)
    @classmethod
    def TOKEN(cls, v): return cls._bbool(CKA_TOKEN, v)
    @classmethod
    def VERIFY(cls, v): return cls._bbool(CKA_VERIFY, v)
    @classmethod
    def EC_PARAMS(cls, v: bytes): return cls._bytes(CKA_EC_PARAMS, v)
    @classmethod
    def EC_POINT(cls, v: bytes): return cls._bytes(CKA_EC_POINT, v)
    @classmethod
    def MODULUS(cls, v: bytes): return cls._bytes(CKA_MODULUS, v)
    @classmethod
    def PUBLIC_EXPONENT(cls, v: bytes): return cls._bytes(CKA_PUBLIC_EXPONENT, v)

    @staticmethod
    def MECH(mech_type, param: bytes | None = None) -> CK_MECHANISM:
        if param is None:
            return CK_MECHANISM(mech_type, None, CK_ULONG(0))
        buf = (c_ubyte * len(param))(*param)
        m = CK_MECHANISM(mech_type, cast(buf, CK_VOID_P), CK_ULONG(len(param)))
        m._keep = buf  # keep alive
        return m


A = _AttrBuilder  # short alias for callers


# --- Module / session wrappers ------------------------------------------

class P11Error(RuntimeError):
    def __init__(self, fn: str, rv: int):
        super().__init__(f"{fn} failed : 0x{rv:08x}")
        self.fn = fn
        self.rv = rv


class P11Module:
    def __init__(self, path: str):
        # Allow integrity bypass for the smoke / test binary -- the
        # embedded digest is not patched at build time. The Wycheproof
        # harness is dev-only ; both env vars are forbidden in any
        # FIPS 140-3 deployment (see AGD_PRE §7.5 / §7.5bis).
        os.environ.setdefault("FHSM_INTEGRITY_ALLOW_UNSIGNED", "1")
        os.environ.setdefault("FHSM_KAT_ALLOW_FAIL", "1")
        # Some FreeHSM-build OpenSSL installs ship an openssl.cnf that
        # forces fips=yes on every EVP fetch. In dev mode we want the
        # default provider to serve fetches with no FIPS bias.
        os.environ.setdefault("OPENSSL_CONF", "/dev/null")
        # Default token store under /tmp so the harness is self-
        # contained and re-runnable. The runner cleans this up.
        os.environ.setdefault(
            "FHSM_TOKENS_DIR",
            os.path.join("/tmp", "freehsm-wycheproof"),
        )
        os.makedirs(os.environ["FHSM_TOKENS_DIR"], mode=0o700, exist_ok=True)
        self.lib = CDLL(path, mode=RTLD_GLOBAL)

        for name in (
            "C_Initialize", "C_Finalize",
            "C_OpenSession", "C_CloseSession",
            "C_InitToken", "C_InitPIN", "C_Login", "C_Logout",
            "C_CreateObject", "C_DestroyObject",
            "C_VerifyInit", "C_Verify",
        ):
            try:
                getattr(self.lib, name).restype = CK_ULONG
            except AttributeError:
                pass  # symbol absent -- caller will get a clear error later

        rv = self.lib.C_Initialize(None)
        if rv != CKR_OK:
            raise P11Error("C_Initialize", rv)
        self._closed = False

        # Bootstrap slot 0 token if absent. Wycheproof verify tests do
        # not need a USER login (pubkey objects are SESSION-only and
        # CKA_PRIVATE=false), but C_OpenSession on an uninitialized
        # token returns CKR_TOKEN_NOT_PRESENT. We do C_InitToken+InitPIN
        # idempotently so re-runs are safe.
        self._bootstrap_token(slot_id=0)

    def _bootstrap_token(self, slot_id: int) -> None:
        """Ensure slot N has a token initialized with the dev PINs."""
        # Try a quick C_OpenSession ; if it works, the token is already
        # there from a previous run -- just close and continue.
        probe = CK_ULONG()
        probe_rv = self.lib.C_OpenSession(
            CK_ULONG(slot_id),
            CK_ULONG(CKF_SERIAL_SESSION | CKF_RW_SESSION),
            None, None, byref(probe),
        )
        if probe_rv == CKR_OK:
            self.lib.C_CloseSession(probe)
            return

        if probe_rv != CKR_TOKEN_NOT_PRESENT:
            raise P11Error("C_OpenSession (probe)", probe_rv)

        # Token absent : run C_InitToken with the dev SO PIN.
        so_pin = (c_ubyte * len(BOOTSTRAP_SO_PIN))(*BOOTSTRAP_SO_PIN)
        label = (c_ubyte * len(BOOTSTRAP_LABEL))(*BOOTSTRAP_LABEL)
        rv = self.lib.C_InitToken(
            CK_ULONG(slot_id),
            so_pin, CK_ULONG(len(BOOTSTRAP_SO_PIN)),
            label,
        )
        if rv != CKR_OK:
            raise P11Error("C_InitToken (bootstrap)", rv)

        # SO login + InitPIN to set the user PIN. Without this, future
        # C_Login(USER) calls would fail, but verify itself does not
        # need it ; we still do it to make the token consistent for any
        # follow-up adapter that needs USER (private-key import).
        sess = CK_ULONG()
        rv = self.lib.C_OpenSession(
            CK_ULONG(slot_id),
            CK_ULONG(CKF_SERIAL_SESSION | CKF_RW_SESSION),
            None, None, byref(sess),
        )
        if rv != CKR_OK:
            raise P11Error("C_OpenSession (post-init)", rv)
        rv = self.lib.C_Login(sess, CK_ULONG(CKU_SO),
                              so_pin, CK_ULONG(len(BOOTSTRAP_SO_PIN)))
        if rv != CKR_OK:
            self.lib.C_CloseSession(sess)
            raise P11Error("C_Login (SO bootstrap)", rv)
        user_pin = (c_ubyte * len(BOOTSTRAP_USER_PIN))(*BOOTSTRAP_USER_PIN)
        rv = self.lib.C_InitPIN(sess, user_pin, CK_ULONG(len(BOOTSTRAP_USER_PIN)))
        # On a fresh token InitPIN succeeds ; if the token already had a
        # USER PIN we ignore CKR_USER_PIN_NOT_INITIALIZED (race / re-init).
        if rv != CKR_OK and rv != CKR_USER_PIN_NOT_INITIALIZED:
            self.lib.C_Logout(sess)
            self.lib.C_CloseSession(sess)
            raise P11Error("C_InitPIN (bootstrap)", rv)
        self.lib.C_Logout(sess)
        self.lib.C_CloseSession(sess)

    def open_session(self, slot_id: int = 0) -> "P11Session":
        h = CK_ULONG()
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        rv = self.lib.C_OpenSession(
            CK_ULONG(slot_id), CK_ULONG(flags),
            None, None, byref(h),
        )
        if rv != CKR_OK:
            raise P11Error("C_OpenSession", rv)
        return P11Session(self, h.value)

    def close(self) -> None:
        if not self._closed:
            self.lib.C_Finalize(None)
            self._closed = True

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


class P11Session:
    def __init__(self, mod: P11Module, h: int):
        self.mod = mod
        self.h = h
        self._closed = False

    def create_object(self, attrs: list) -> int:
        """Pass [(CK_ATTRIBUTE, keepalive), ...]; returns object handle."""
        n = len(attrs)
        tmpl = (CK_ATTRIBUTE * n)(*(a for a, _ in attrs))
        keep = [k for _, k in attrs]  # noqa: F841 -- keep buffers alive
        obj = CK_ULONG()
        rv = self.mod.lib.C_CreateObject(
            CK_ULONG(self.h), tmpl, CK_ULONG(n), byref(obj),
        )
        if rv != CKR_OK:
            raise P11Error("C_CreateObject", rv)
        return obj.value

    def destroy(self, obj_handle: int) -> None:
        self.mod.lib.C_DestroyObject(CK_ULONG(self.h), CK_ULONG(obj_handle))

    def verify(self, key: int, mech: CK_MECHANISM,
               data: bytes, signature: bytes) -> int:
        """Returns the raw CKR_* code from C_Verify."""
        rv = self.mod.lib.C_VerifyInit(CK_ULONG(self.h), byref(mech),
                                       CK_ULONG(key))
        if rv != CKR_OK:
            return rv
        d = (c_ubyte * len(data))(*data) if data else None
        s = (c_ubyte * len(signature))(*signature) if signature else None
        rv = self.mod.lib.C_Verify(
            CK_ULONG(self.h),
            d, CK_ULONG(len(data) if data else 0),
            s, CK_ULONG(len(signature) if signature else 0),
        )
        return rv

    def close(self) -> None:
        if not self._closed:
            self.mod.lib.C_CloseSession(CK_ULONG(self.h))
            self._closed = True

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
