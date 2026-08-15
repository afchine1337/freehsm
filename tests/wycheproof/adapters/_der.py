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


def _encode_length_minimal(length: int) -> bytes:
    """Canonical DER length encoding."""
    if length < 128:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _read_length_lenient(buf: bytes, offset: int) -> tuple[int, int, bool]:
    """Lenient DER length parse. Accepts any structurally well-formed
    length encoding. Returns (length, next_offset, is_canonical).
    Raises DERError only on truncation or indefinite form (which we
    cannot recover from)."""
    if offset >= len(buf):
        raise DERError("truncated length field")
    first = buf[offset]
    if first < 0x80:
        # Short form : always canonical.
        return first, offset + 1, True
    n = first & 0x7F
    if n == 0:
        # Indefinite form : not valid for DER and we cannot recover.
        raise DERError("indefinite length not supported")
    if n > 4:
        raise DERError(f"length field too large : {n} bytes")
    if offset + 1 + n > len(buf):
        raise DERError("truncated length field")
    raw = buf[offset + 1 : offset + 1 + n]
    length = int.from_bytes(raw, "big")
    canonical = (raw[0] != 0x00) and (length >= 128)
    return length, offset + 1 + n, canonical


def _read_lenient_integer(buf: bytes, offset: int) -> tuple[bytes, int, bool]:
    """Lenient DER INTEGER parse. Returns (sign-stripped value, next
    offset, is_canonical). Strict rules surfaced as canonical=False
    rather than DERError so the caller can decide what to do."""
    if offset >= len(buf):
        raise DERError("truncated INTEGER tag")
    if buf[offset] != 0x02:
        raise DERError(f"expected INTEGER tag : 0x{buf[offset]:02x}")
    length, next_off, len_canonical = _read_length_lenient(buf, offset + 1)
    if length == 0:
        # Zero-length INTEGER : impossible to convert to a value.
        raise DERError("zero-length INTEGER")
    if next_off + length > len(buf):
        raise DERError("INTEGER truncated")
    raw = buf[next_off : next_off + length]

    int_canonical = True

    # Negative INTEGER : high bit of first byte set without 0x00 prefix.
    # ECDSA r and s are positive, so this is always non-canonical.
    if raw[0] & 0x80:
        int_canonical = False

    # Non-minimal : leading 0x00 byte while next byte's high bit is 0.
    if length >= 2 and raw[0] == 0x00 and (raw[1] & 0x80) == 0:
        int_canonical = False

    # Strip the legitimate 0x00 sign-byte, if any.
    if raw[0] == 0x00:
        raw = raw[1:]
    return raw, next_off + length, len_canonical and int_canonical


def parse_ecdsa_sig_to_raw(der: bytes, curve_bytes: int) -> bytes:
    """Strict DER decode (back-compat). Raises DERError on any non-
    canonical encoding. Prefer parse_ecdsa_sig_with_flag() for the
    Wycheproof harness so non-canonical encodings can be classified
    separately from genuine cryptographic failures."""
    raw, canonical = parse_ecdsa_sig_with_flag(der, curve_bytes)
    if not canonical:
        raise DERError("non-canonical DER encoding")
    return raw


def parse_ecdsa_sig_with_flag(der: bytes, curve_bytes: int) -> tuple[bytes, bool]:
    """Lenient parse of an ECDSA signature DER -> (raw r||s, is_canonical).

    Always returns r||s padded to curve_bytes each when the structure
    parses successfully ; raises DERError only when the bytes cannot be
    interpreted as a SEQUENCE of two INTEGERs at all.

    `is_canonical` is True iff the input is *exactly* the canonical DER
    encoding for the (r, s) value pair (minimal length forms, no
    leading 0x00 padding except for sign disambiguation, no trailing
    bytes after the SEQUENCE).
    """
    if not der:
        raise DERError("empty signature")
    if der[0] != 0x30:
        raise DERError(f"not a SEQUENCE : tag=0x{der[0]:02x}")
    seq_len, off, seq_len_canonical = _read_length_lenient(der, 1)
    seq_canonical = seq_len_canonical
    if off + seq_len > len(der):
        raise DERError(f"SEQUENCE truncated : end={off + seq_len} "
                       f"total={len(der)}")
    if off + seq_len != len(der):
        # Trailing bytes after SEQUENCE : non-canonical, but recoverable
        # (we still parse the SEQUENCE content).
        seq_canonical = False

    seq_end = off + seq_len
    r_bytes, off, r_canonical = _read_lenient_integer(der, off)
    s_bytes, off, s_canonical = _read_lenient_integer(der, off)

    if off != seq_end:
        # Bytes inside the SEQUENCE that are not part of r/s.
        seq_canonical = False

    if len(r_bytes) > curve_bytes or len(s_bytes) > curve_bytes:
        raise DERError(
            f"r/s longer than curve : r={len(r_bytes)} s={len(s_bytes)} "
            f"curve_bytes={curve_bytes}"
        )

    # An INTEGER of value zero would have been stripped to empty bytes.
    # ECDSA requires both r > 0 and s > 0. We still surface the structure
    # as parseable, but the adapter will need to know.
    if not r_bytes or not s_bytes:
        raise DERError("r or s is zero")

    r_padded = r_bytes.rjust(curve_bytes, b"\x00")
    s_padded = s_bytes.rjust(curve_bytes, b"\x00")
    return r_padded + s_padded, (seq_canonical and r_canonical and s_canonical)
