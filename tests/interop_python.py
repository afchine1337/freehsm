#!/usr/bin/env python3
"""
interop_python.py --- Interop test using python-pkcs11 as an alternative
client (not OpenSC pkcs11-tool). Demonstrates that the module is correctly
wired against multiple PKCS#11 implementations, not just one.

Pre-requisites :
    pip install python-pkcs11 cryptography

Or with apt :
    sudo apt install python3-pkcs11 python3-cryptography

Test flow :
    1. Connect to libfreehsm-fips.so via python-pkcs11
    2. Open session, login as USER
    3. Generate an EC P-256 key pair
    4. Sign a message with ECDSA-SHA256
    5. Validate the signature with OpenSSL's cryptography module
       (independent of any PKCS#11 binding)

Success criterion : the validation step prints "Verified OK".

Note : python-pkcs11 must be installed in a virtualenv that has access
to the freehsm user environment OR the script must be run as freehsm with
explicit FHSM_TOKENS_DIR.
"""
import os
import sys
import tempfile

MODULE   = os.environ.get("MODULE",     "/opt/freehsm/lib/libfreehsm-fips.so")
TOKEN    = os.environ.get("TOKEN",      "prod-slot0")
USER_PIN = os.environ.get("USER_PIN",   "user0000")
MSG      = b"interop check via python-pkcs11"

try:
    import pkcs11
    from pkcs11 import KeyType, Mechanism, Attribute, ObjectClass
    from pkcs11.util.ec import encode_named_curve_parameters
except ImportError as e:
    print(f"SKIP: python-pkcs11 not installed ({e})", file=sys.stderr)
    print("Install : sudo apt install python3-pkcs11", file=sys.stderr)
    sys.exit(2)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import \
        decode_dss_signature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature
except ImportError as e:
    print(f"SKIP: cryptography not installed ({e})", file=sys.stderr)
    print("Install : sudo apt install python3-cryptography", file=sys.stderr)
    sys.exit(2)


def main():
    print(f"[interop] module = {MODULE}")
    print(f"[interop] token  = {TOKEN}")

    # ---- 1. Connect & login ----
    lib = pkcs11.lib(MODULE)
    token = lib.get_token(token_label=TOKEN)
    print(f"[interop] connected to {token}")

    with token.open(user_pin=USER_PIN) as session:
        print(f"[interop] session opened, logged in as USER")

        # ---- 2. Generate EC P-256 pair ----
        params = encode_named_curve_parameters("secp256r1")
        pub, priv = session.generate_keypair(
            KeyType.EC,
            ec_params=params,
            label="interop-ec",
            id_=b"\xAA",
            store=False,             # session-only ; not persisted
        )
        print(f"[interop] generated EC P-256 pair")

        # ---- 3. Sign the message ----
        sig = priv.sign(MSG, mechanism=Mechanism.ECDSA_SHA256)
        print(f"[interop] signed message ({len(sig)} bytes)")
        # python-pkcs11 returns the raw r || s concatenation (64 bytes).
        # For OpenSSL we need DER-encoded ECDSA.
        if len(sig) == 64:
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            from cryptography.hazmat.primitives.asymmetric.utils import \
                encode_dss_signature
            sig_der = encode_dss_signature(r, s)
        else:
            sig_der = sig
        print(f"[interop] DER sig = {len(sig_der)} bytes")

        # ---- 4. Export public key ----
        # python-pkcs11 returns the EC_POINT octet string (uncompressed
        # point). Wrap as an X.509 SubjectPublicKeyInfo for cryptography.
        ec_point = pub[Attribute.EC_POINT]
        # Strip the DER OCTET STRING wrapper (0x04 LEN || ...) to get
        # the raw uncompressed point 0x04 || X || Y.
        if ec_point[0] == 0x04 and ec_point[1] in (0x41, 0x81):
            # 0x04 0x41 || 65 bytes  OR  0x04 0x81 0x41 || 65 bytes
            offset = 3 if ec_point[1] == 0x81 else 2
            raw_point = ec_point[offset:]
        else:
            raw_point = ec_point
        if len(raw_point) != 65 or raw_point[0] != 0x04:
            print(f"[interop] FAIL: unexpected EC_POINT format "
                  f"({len(raw_point)} bytes, first={raw_point[0]:#x})")
            return 1

        # ---- 5. Build a cryptography EllipticCurvePublicKey ----
        from cryptography.hazmat.primitives.asymmetric.ec import \
            EllipticCurvePublicKey, SECP256R1
        pubkey = EllipticCurvePublicKey.from_encoded_point(
            SECP256R1(), raw_point)
        print(f"[interop] reconstructed public key from EC_POINT")

        # ---- 6. Verify the signature externally ----
        try:
            pubkey.verify(sig_der, MSG, ec.ECDSA(hashes.SHA256()))
            print("[interop] PASS : external verify SUCCESS")
            print("[interop]        the HSM-produced ECDSA signature was")
            print("[interop]        independently validated by cryptography")
            return 0
        except InvalidSignature:
            print("[interop] FAIL : external verify failed")
            return 1


if __name__ == "__main__":
    sys.exit(main())
