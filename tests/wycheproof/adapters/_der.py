#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# adapters/_der.py --- tiny DER (ASN.1) encoder / decoder shared by the
# Wycheproof adapters. Just the subset needed to :
#
#   - wrap a SEC1 EC point in an OCTET STRING (PKCS#11 v3 CKA_EC_POINT)
#   - decode a DER-encoded ECDSA signature {SEQ {INT r} {INT s}} into
#     the raw r || s concatenation that PKCS#11 expects.
#
# No dependency on cryptography / pyasn1 -- pure stdlib.
# ===========================================================================

from __future__ import annotations


def encode_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def encode_octet_string(payload: bytes) -> bytes:
    """OCTET STRING ::= 0x04 LL payload."""
    return b"\x04" + encode_length(len(payload)) + payload


# --- DER decode ----------------------------------------------------------

class DERError(ValueError):
    pass


def _read_length_strict(buf: bytes, offset: int) -> tuple[int, int]:
    """Strict DER length parse. Rejects :
        - indefinite form
        - long form for lengths < 128 (must be short form)
        - long form with leading 0x00 padding (must be minimal)
        - truncated length field
    """
    if offset >= len(buf):
        raise DERError("truncated length field")
    first = buf[offset]
    if first < 0x80:
        return first, offset + 1
    n = first & 0x7F
    if n == 0:
        raise DERError("indefinite length not supported")
    if n > 4:
        raise DERError(f"length field too large : {n} bytes")
    if offset + 1 + n > len(buf):
        raise DERError("truncated length field")
    raw = buf[offset + 1 : offset + 1 + n]
    if raw[0] == 0x00:
        raise DERError("non-minimal length encoding (leading 0x00)")
    length = int.from_bytes(raw, "big")
    if length < 128:
        raise DERError("non-minimal length encoding (long form for <128)")
    return length, offset + 1 + n


def _read_strict_integer(buf: bytes, offset: int) -> tuple[bytes, int]:
    """Strict DER INTEGER parse. Returns (sign-stripped value, next offset).
    Rejects :
        - tag != 0x02
        - zero length
        - leading 0x00 byte that is not required for sign disambiguation
        - negative INTEGER (high bit of first byte set without 0x00 prefix)
    """
    if offset >= len(buf):
        raise DERError("truncated INTEGER tag")
    if buf[offset] != 0x02:
        raise DERError(f"expected INTEGER tag : 0x{buf[offset]:02x}")
    length, next_off = _read_length_strict(buf, offset + 1)
    if length == 0:
        raise DERError("zero-length INTEGER")
    if next_off + length > len(buf):
        raise DERError("INTEGER truncated")
    raw = buf[next_off : next_off + length]

    # Negative INTEGER : high bit of first byte set without a 0x00 sign
    # prefix is forbidden for ECDSA r/s (must be positive).
    if raw[0] & 0x80:
        raise DERError("negative INTEGER (high bit set without 0x00 prefix)")

    # Non-minimal : leading 0x00 byte while next byte's high bit is 0.
    if length >= 2 and raw[0] == 0x00 and (raw[1] & 0x80) == 0:
        raise DERError("non-minimal INTEGER (unnecessary leading 0x00)")

    # Strip the legitimate 0x00 sign-byte, if any.
    if raw[0] == 0x00:
        raw = raw[1:]
    return raw, next_off + length


def parse_ecdsa_sig_to_raw(der: bytes, curve_bytes: int) -> bytes:
    """Strict DER decode of an ECDSA signature -> raw r||s.

    Enforces every Wycheproof-relevant DER rule so vectors flagged
    "invalid" purely because of DER strictness (long-form length,
    leading 0x00 in INTEGER, trailing bytes, etc.) are rejected before
    the signature even reaches the module.

    Args:
        der: DER-encoded `SEQUENCE { INTEGER r, INTEGER s }`.
        curve_bytes: byte length of the curve scalar (e.g. 32 for P-256).

    Returns:
        bytes of exactly `2 * curve_bytes` length.
    """
    if not der:
        raise DERError("empty signature")
    if der[0] != 0x30:
        raise DERError(f"not a SEQUENCE : tag=0x{der[0]:02x}")
    seq_len, off = _read_length_strict(der, 1)
    if off + seq_len != len(der):
        # Strict : no trailing bytes after the SEQUENCE content, and no
        # truncation.
        raise DERError(
            f"trailing bytes / truncated : seq_end={off + seq_len} "
            f"total={len(der)}"
        )

    r_bytes, off = _read_strict_integer(der, off)
    s_bytes, off = _read_strict_integer(der, off)

    if off != len(der):
        raise DERError("trailing bytes after second INTEGER")

    if len(r_bytes) > curve_bytes or len(s_bytes) > curve_bytes:
        raise DERError(
            f"r/s longer than curve : r={len(r_bytes)} s={len(s_bytes)} "
            f"curve_bytes={curve_bytes}"
        )

    # After sign-strip, an INTEGER of value zero is now an empty bytes
    # object. ECDSA requires both r > 0 and s > 0.
    if not r_bytes or not s_bytes:
        raise DERError("r or s is zero")

    r_padded = r_bytes.rjust(curve_bytes, b"\x00")
    s_padded = s_bytes.rjust(curve_bytes, b"\x00")
    return r_padded + s_padded
