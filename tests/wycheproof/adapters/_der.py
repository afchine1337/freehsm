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


def _read_length(buf: bytes, offset: int) -> tuple[int, int]:
    first = buf[offset]
    if first < 0x80:
        return first, offset + 1
    n = first & 0x7F
    if n == 0:
        raise DERError("indefinite length not supported")
    if offset + 1 + n > len(buf):
        raise DERError("truncated length field")
    length = int.from_bytes(buf[offset + 1 : offset + 1 + n], "big")
    return length, offset + 1 + n


def parse_ecdsa_sig_to_raw(der: bytes, curve_bytes: int) -> bytes:
    """Decode DER ECDSA signature, return raw r||s padded to curve_bytes each.

    Args:
        der: DER-encoded `SEQUENCE { INTEGER r, INTEGER s }`.
        curve_bytes: byte length of the curve scalar (e.g. 32 for P-256).

    Returns:
        bytes of exactly `2 * curve_bytes` length.
    """
    if not der or der[0] != 0x30:
        raise DERError(f"not a SEQUENCE : tag=0x{der[0] if der else 0:02x}")
    seq_len, off = _read_length(der, 1)
    if off + seq_len > len(der):
        raise DERError("SEQUENCE truncated")

    # First INTEGER
    if der[off] != 0x02:
        raise DERError(f"r tag mismatch : 0x{der[off]:02x}")
    r_len, off = _read_length(der, off + 1)
    r_bytes = der[off : off + r_len]
    off += r_len

    # Second INTEGER
    if der[off] != 0x02:
        raise DERError(f"s tag mismatch : 0x{der[off]:02x}")
    s_len, off = _read_length(der, off + 1)
    s_bytes = der[off : off + s_len]

    # Strip the leading 0x00 byte that ASN.1 INTEGER adds when the high
    # bit is set (so the value is read as positive).
    r_bytes = r_bytes.lstrip(b"\x00") or b"\x00"
    s_bytes = s_bytes.lstrip(b"\x00") or b"\x00"

    if len(r_bytes) > curve_bytes or len(s_bytes) > curve_bytes:
        # Invalid signature : r or s longer than the curve order. The
        # underlying module will (rightly) reject such signatures, but
        # we cannot pass them raw to PKCS#11 either. Return a sentinel
        # that the adapter can detect.
        raise DERError(
            f"r/s longer than curve : r={len(r_bytes)} s={len(s_bytes)} "
            f"curve_bytes={curve_bytes}"
        )

    r_padded = r_bytes.rjust(curve_bytes, b"\x00")
    s_padded = s_bytes.rjust(curve_bytes, b"\x00")
    return r_padded + s_padded
