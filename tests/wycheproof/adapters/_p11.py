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
CKK_ML_KEM = 0x00000049  # official PKCS#11 v3.2 (OASIS); was 0x3C draft
CKM_ML_KEM_OP = 0x00000017
CKK_ML_DSA = 0x0000004A  # official PKCS#11 v3.2 (OASIS); was 0x3E draft
CKM_ML_DSA_OP = 0x0000001d

CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_VALUE = 0x00000011
CKA_KEY_TYPE = 0x00000100
CKA_SENSITIVE = 0x00000103
CKA_VERIFY = 0x0000010A
CKA_EC_PARAMS = 0x00000180
CKA_EC_POINT = 0x00000181

CKM_RSA_PKCS = 0x00000001
CKM_RSA_PKCS_OAEP = 0x00000009
# CKM_SHA1/256/384/512 used both as standalone digest mechanisms and
# as the hashAlg / mgf-hash identifier inside CK_RSA_PKCS_OAEP_PARAMS.
CKM_SHA_1 = 0x00000220
# Wycheproof RSA-OAEP MGF identifiers (CK_RSA_PKCS_MGF_TYPE).
CKG_MGF1_SHA1 = 0x00000001
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
CKM_AES_GMAC = 0x0000108A
CKM_AES_CMAC = 0x0000108C
CKM_SHA256_HMAC = 0x00000251
CKM_SHA384_HMAC = 0x00000261
CKM_SHA512_HMAC = 0x00000271
CKK_GENERIC_SECRET = 0x00000010

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
    CKO_SECRET_KEY = CKO_SECRET_KEY
    CKM_RSA_PKCS_OAEP = CKM_RSA_PKCS_OAEP
    CKK_EC = CKK_EC
    CKK_RSA = CKK_RSA
    CKK_EC_EDWARDS = CKK_EC_EDWARDS
    CKK_AES = CKK_AES
    CKK_GENERIC_SECRET = CKK_GENERIC_SECRET
    CKM_ECDSA = CKM_ECDSA
    CKM_SHA256_HMAC = CKM_SHA256_HMAC
    CKM_SHA384_HMAC = CKM_SHA384_HMAC
    CKM_SHA512_HMAC = CKM_SHA512_HMAC
    CKM_ECDSA_SHA256 = CKM_ECDSA_SHA256
    CKM_ECDSA_SHA384 = CKM_ECDSA_SHA384
    CKM_ECDSA_SHA512 = CKM_ECDSA_SHA512
    CKM_EDDSA = CKM_EDDSA
    CKM_AES_GCM = CKM_AES_GCM
    CKM_AES_GMAC = CKM_AES_GMAC
    CKM_AES_CMAC = CKM_AES_CMAC

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
    @classmethod
    def VALUE(cls, v: bytes): return cls._bytes(CKA_VALUE, v)
    @classmethod
    def DECRYPT(cls, v): return cls._bbool(0x00000105, v)  # CKA_DECRYPT
    @classmethod
    def EXTRACTABLE(cls, v): return cls._bbool(0x00000162, v)  # CKA_EXTRACTABLE
    @classmethod
    def SENSITIVE(cls, v): return cls._bbool(0x00000103, v)  # CKA_SENSITIVE

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
    # Singleton-by-path : PKCS#11 mandates a single C_Initialize per
    # process. When multiple adapters share the same .so, we hand them
    # the existing instance instead of trying to re-initialize.
    _instances: dict = {}

    def __new__(cls, path: str):
        inst = cls._instances.get(path)
        if inst is not None:
            return inst
        inst = super().__new__(cls)
        cls._instances[path] = inst
        return inst

    def __init__(self, path: str):
        # Skip re-init when the singleton was already constructed.
        if getattr(self, "_init_done", False):
            return
        self._init_done = True
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
            "C_EncryptInit", "C_Encrypt",
            "C_DecryptInit", "C_Decrypt",
            "C_SignInit", "C_Sign",
            "C_DecapsulateKey", "C_EncapsulateKey",
            "C_GetAttributeValue",
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
        # USER login : fhsm_token_object_add() requires a loaded DEK
        # (set on USER login). On a fresh /tmp the bootstrap path
        # implicitly loaded a DEK via SO_Login + InitPIN, but on a
        # re-run with a persisted token the probe short-circuits and
        # the DEK stays NULL. Logging in here is idempotent and is
        # safe for verify-only adapters too (USER role does not
        # restrict any operation we perform).
        user_pin = (c_ubyte * len(BOOTSTRAP_USER_PIN))(*BOOTSTRAP_USER_PIN)
        rv = self.lib.C_Login(h, CK_ULONG(CKU_USER),
                              user_pin, CK_ULONG(len(BOOTSTRAP_USER_PIN)))
        # CKR_USER_ALREADY_LOGGED_IN (0x100) is harmless ; any other
        # non-OK indicates a token state we cannot recover from.
        if rv != CKR_OK and rv != 0x00000100:
            self.lib.C_CloseSession(h)
            raise P11Error("C_Login (USER, open_session)", rv)
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

    def sign(self, key: int, mech: CK_MECHANISM,
             data: bytes, out_size: int) -> tuple[int, bytes]:
        """Returns (CKR_*, signature bytes). On failure signature is empty."""
        rv = self.mod.lib.C_SignInit(CK_ULONG(self.h), byref(mech),
                                      CK_ULONG(key))
        if rv != CKR_OK:
            return rv, b""
        d = (c_ubyte * len(data))(*data) if data else None
        out_buf = (c_ubyte * max(1, out_size))()
        out_len = CK_ULONG(out_size)
        rv = self.mod.lib.C_Sign(
            CK_ULONG(self.h),
            d, CK_ULONG(len(data) if data else 0),
            out_buf, byref(out_len),
        )
        if rv != CKR_OK:
            return rv, b""
        return rv, bytes(out_buf[:out_len.value])

    def decrypt(self, key: int, mech: CK_MECHANISM,
                ciphertext: bytes) -> tuple[int, bytes]:
        """Returns (CKR_*, plaintext bytes). On failure plaintext is empty."""
        rv = self.mod.lib.C_DecryptInit(CK_ULONG(self.h), byref(mech),
                                         CK_ULONG(key))
        if rv != CKR_OK:
            return rv, b""
        ct = (c_ubyte * len(ciphertext))(*ciphertext) if ciphertext else None
        # Generous buffer : Wycheproof uses moduli up to 4096 bits =
        # 512 bytes ; pad to 8 KB so any plaintext size query reported
        # by the underlying primitive fits without triggering
        # CKR_BUFFER_TOO_SMALL.
        buf_size = max(8192, len(ciphertext) or 1)
        out_buf = (c_ubyte * buf_size)()
        out_len = CK_ULONG(buf_size)
        rv = self.mod.lib.C_Decrypt(
            CK_ULONG(self.h),
            ct, CK_ULONG(len(ciphertext) if ciphertext else 0),
            out_buf, byref(out_len),
        )
        if rv != CKR_OK:
            return rv, b""
        return rv, bytes(out_buf[:out_len.value])

    def decapsulate(self, priv_key: int, mech: CK_MECHANISM,
                    ciphertext: bytes,
                    template: list | None = None) -> tuple[int, int]:
        """C_DecapsulateKey(hSession, mech, hPrivKey, tmpl, ulCount,
                            &phNewKey, pCt, ulCtLen).

        Returns (CKR_*, new_key_handle). New key handle is 0 on failure.
        The shared secret is stored as a CKO_SECRET_KEY (CKK_GENERIC_SECRET)
        with the SS as CKA_VALUE ; read it back via get_attribute_value().
        """
        attrs = template or []
        n = len(attrs)
        tmpl = (CK_ATTRIBUTE * max(1, n))(*(a for a, _ in attrs))
        keep = [k for _, k in attrs]  # noqa: F841
        new_key = CK_ULONG(0)
        ct = (c_ubyte * len(ciphertext))(*ciphertext) if ciphertext else \
             (c_ubyte * 1)()
        rv = self.mod.lib.C_DecapsulateKey(
            CK_ULONG(self.h), byref(mech), CK_ULONG(priv_key),
            tmpl, CK_ULONG(n),
            byref(new_key),
            ct, CK_ULONG(len(ciphertext) if ciphertext else 0),
        )
        return rv, new_key.value

    def get_attribute_value(self, obj_handle: int,
                            attr_type: int, buf_size: int = 4096) -> bytes:
        """Single-attribute C_GetAttributeValue. Returns the raw bytes
        of the requested attribute, or b"" on failure."""
        attr = CK_ATTRIBUTE()
        attr.type = CK_ULONG(attr_type)
        buf = (c_ubyte * max(1, buf_size))()
        attr.pValue = cast(buf, c_void_p)
        attr.ulValueLen = CK_ULONG(buf_size)
        rv = self.mod.lib.C_GetAttributeValue(
            CK_ULONG(self.h), CK_ULONG(obj_handle), byref(attr), CK_ULONG(1),
        )
        if rv != CKR_OK:
            return b""
        return bytes(buf[:attr.ulValueLen])

    def close(self) -> None:
        if not self._closed:
            self.mod.lib.C_CloseSession(CK_ULONG(self.h))
            self._closed = True

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
