#!/usr/bin/env python3
"""
verify_ecdsa_p521_rfc6979.py

Cross-validates the ECDSA-P521-SHA512 RFC 6979 §A.2.7 KAT vector against
three independent code paths :

  1. Python cryptography (cffi to OpenSSL) — verifies the source's sig
     against the source's pubkey and the message "sample". If pass : the
     source's sig is internally consistent with itself.

  2. pycryptodome (autonomous ECDSA) — same verify. Independent code.

  3. python-ecdsa (pure Python, supports RFC 6979) — generates the
     canonical deterministic signature from the RFC 6979 §A.2.7
     published private key. The output is what the KAT *should*
     contain.

If (1) and (2) both pass : source pubkey + sig are internally consistent ;
the C verify path has a bug.
If (1) and (2) both fail : source has wrong sig ; replace with (3)'s output.
If (1) and (2) disagree : libcrypto vs pycryptodome divergence, rare.

Run :
    pip3 install --user --break-system-packages cryptography pycryptodome ecdsa
    python3 disabled/verify_ecdsa_p521_rfc6979.py
"""
import binascii

# ============================================================
# KAT inputs from kat/cavp_extended.c
# ============================================================

# Uncompressed point : 0x04 || Ux(66) || Uy(66)
PUB_SRC = bytes.fromhex(
    "04"
    # Ux (66 bytes)
    "01894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd"
    "371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f50"
    "23a4"
    # Uy (66 bytes)
    "00493101c962cd4d2fddf782285e6458"
    "4139c2f91b47f87ff82354d6630f746a"
    "28a0db25741b5b34a828008b22acc23f"
    "924faafbd4d33f81ea66956dfeaa2bfd"
    "fcf5"
)

# DER SEQUENCE { r INTEGER (66 bytes), s INTEGER (66 bytes) }
SIG_SRC = bytes.fromhex(
    "30818b"
    "0242"
        "00c328fafcbd79dd77850370c46325d9"
        "87cb525569fb63c5d3bc53950e6d4c5f"
        "174e25a1ee9017b5d450606add152b53"
        "4931d7d4e8455cc91f9b15bf05ec36e3"
        "77fa"
    "0243"
        "00617cce7cf5064806c467f678d3b408"
        "0d6f1cc50af26ca2094173082" "81b68af"
        "28262" "3eaa63e5b5c0723d8b8c37ff077"
        "7b1a20f8ccb1dccc43997f1ee0e44da4"
        "a67a"
)

MSG = b"sample"

# Print src details
print(f"PUB_SRC length : {len(PUB_SRC)} bytes (expect 133)")
print(f"SIG_SRC length : {len(SIG_SRC)} bytes (expect 143)")
print(f"MSG            : {MSG!r}")
print()


def header(s):
    print("=" * 64)
    print(s)
    print("=" * 64)


# ============================================================
# Cross-check 1 : Python cryptography
# ============================================================
header("Cross-check 1 : Python cryptography (cffi binding to OpenSSL)")

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey, EllipticCurvePublicNumbers, SECP521R1, ECDSA
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    # Reconstruct pubkey from Ux / Uy (skipping the 0x04 prefix)
    ux = int.from_bytes(PUB_SRC[1:67], "big")
    uy = int.from_bytes(PUB_SRC[67:], "big")
    pub_num = EllipticCurvePublicNumbers(ux, uy, SECP521R1())
    pubkey = pub_num.public_key()

    try:
        pubkey.verify(SIG_SRC, MSG, ECDSA(hashes.SHA512()))
        print("  Verify : PASS — source sig is valid for source pubkey + msg")
    except InvalidSignature:
        print("  Verify : FAIL — source sig is NOT valid for source pubkey + msg")
        print("           Source data is inconsistent ; we need the correct sig.")
except ImportError:
    print("  cryptography not installed.")
except Exception as e:
    print(f"  Error : {type(e).__name__} : {e}")
print()


# ============================================================
# Cross-check 2 : pycryptodome
# ============================================================
header("Cross-check 2 : pycryptodome (autonomous ECDSA, no OpenSSL link)")

try:
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS
    from Crypto.Hash import SHA512

    # Build pubkey from Ux / Uy
    pubkey2 = ECC.construct(curve="P-521",
                             point_x=int.from_bytes(PUB_SRC[1:67], "big"),
                             point_y=int.from_bytes(PUB_SRC[67:], "big"))
    verifier = DSS.new(pubkey2, "fips-186-3")  # FIPS 186-3 = DER-encoded
    h = SHA512.new(MSG)
    try:
        verifier.verify(h, SIG_SRC)
        print("  Verify : PASS — source sig is valid (DER mode)")
    except ValueError as e:
        print(f"  Verify FAILED in DER mode : {e}")
        # Try also raw r||s mode just in case
        # Extract r||s manually from DER
        # SIG_SRC = 30 81 8b 02 42 <66 r-bytes> 02 43 <67 s-bytes-with-leading-zero>
        try:
            # Manual DER parse
            # Skip outer SEQUENCE tag + length (3 bytes)
            # Skip INTEGER tag + length (2 bytes), read 66 bytes for r
            # Skip INTEGER tag + length (2 bytes), read 67 bytes for s
            r_start = 5
            r_bytes = SIG_SRC[r_start:r_start + 66]
            s_start = r_start + 66 + 2
            s_bytes = SIG_SRC[s_start:s_start + 67]
            # If s has the DER leading-zero byte, strip it for raw form
            if len(s_bytes) == 67 and s_bytes[0] == 0x00:
                s_bytes = s_bytes[1:]
            # Pad both to 66 bytes for raw r||s
            r_pad = r_bytes.rjust(66, b'\x00') if len(r_bytes) < 66 else r_bytes[-66:]
            s_pad = s_bytes.rjust(66, b'\x00') if len(s_bytes) < 66 else s_bytes[-66:]
            raw_sig = r_pad + s_pad
            print(f"  Trying raw r||s mode (raw_sig len = {len(raw_sig)})...")
            verifier2 = DSS.new(pubkey2, "fips-186-3", encoding="binary")
            verifier2.verify(SHA512.new(MSG), raw_sig)
            print("  Verify : PASS in raw r||s mode")
        except ValueError as e2:
            print(f"  Verify FAILED in raw mode too : {e2}")
            print("  >>> Source sig is NOT valid for source pubkey + msg. <<<")
except ImportError:
    print("  pycryptodome not installed.")
except Exception as e:
    print(f"  Error : {type(e).__name__} : {e}")
print()


# ============================================================
# Cross-check 3 : python-ecdsa with RFC 6979 deterministic sign
# ============================================================
header("Cross-check 3 : python-ecdsa with RFC 6979 §A.2.7 private key")

try:
    import ecdsa
    from ecdsa import SigningKey, NIST521p
    import hashlib

    # RFC 6979 §A.2.7 published private key for P-521
    PRIV_RFC_6979 = bytes.fromhex(
        "00fad06daa62ba3b25d2fb40133da7572"
        "05de67f5bb0018fee8c86e1b68c7e75c"
        "aa896eb32f1f47c70855836a6d16fcc1"
        "466f6d8fbec67db89ec0c08b0e996b83"
        "538"
    )
    print(f"  PRIV_RFC_6979 length : {len(PRIV_RFC_6979)} bytes (expect 66)")

    sk = SigningKey.from_string(PRIV_RFC_6979, curve=NIST521p,
                                  hashfunc=hashlib.sha512)
    # Sign deterministically (RFC 6979)
    sig_canonical_der = sk.sign_deterministic(
        MSG, hashfunc=hashlib.sha512,
        sigencode=ecdsa.util.sigencode_der
    )
    print(f"  Canonical sig length : {len(sig_canonical_der)} bytes")
    print(f"  Canonical sig DER    : {sig_canonical_der.hex()}")
    print()
    print(f"  Source sig length    : {len(SIG_SRC)} bytes")
    print(f"  Source sig DER       : {SIG_SRC.hex()}")
    print()
    if sig_canonical_der == SIG_SRC:
        print("  >>> Source sig MATCHES the canonical RFC 6979 §A.2.7 sig. <<<")
        print("  If the verify above failed, the bug is in our C verify path.")
    else:
        print("  >>> Source sig DIFFERS from canonical RFC 6979 §A.2.7 sig. <<<")
        print("  Replace the source value with the canonical sig.")
        # Also print as raw r||s for easy inspection
        sig_raw = sk.sign_deterministic(
            MSG, hashfunc=hashlib.sha512,
            sigencode=ecdsa.util.sigencode_string
        )
        print(f"\n  Canonical raw r||s : {sig_raw.hex()}")
        print(f"  r (66 bytes) : {sig_raw[:66].hex()}")
        print(f"  s (66 bytes) : {sig_raw[66:].hex()}")
except ImportError:
    print("  ecdsa not installed. Install : pip3 install --user --break-system-packages ecdsa")
except Exception as e:
    print(f"  Error : {type(e).__name__} : {e}")
print()


# ============================================================
# Verdict
# ============================================================
header("Verdict")
print("""
  Read the three cross-checks above and combine :

  If cross-check 3 prints "MATCHES" but cross-check 1 says "FAIL" :
    -> The source data is what RFC 6979 publishes, but Python cryptography
       fails to verify it. Investigate Python crypto / source pubkey
       encoding.

  If cross-check 3 prints "DIFFERS" :
    -> The source has a wrong sig. The canonical bytes printed above
       are what should be in kat/cavp_extended.c.

  If 1 + 2 both PASS but our C boot KAT fails :
    -> Bug in our C verify path. Investigate ecdsa_pubkey_from_raw or
       EVP_DigestVerify.

  In all cases the canonical sig from cross-check 3 is the source of
  truth ; it's derived deterministically from the RFC 6979 published
  private key.
""")
