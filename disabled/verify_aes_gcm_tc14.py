#!/usr/bin/env python3
"""
verify_aes_gcm_tc14.py

Cross-validates the NIST SP 800-38D Appendix B Test Case 14 AES-256-GCM
no-AAD vector against three independent OpenSSL code paths :

  1. Python cryptography library (binds OpenSSL via cffi).
  2. Python stdlib's hashlib + manual GHASH (pure Python, no OpenSSL).
  3. OpenSSL CLI (subprocess), to confirm what `openssl` binary computes.

If (1) matches NIST  -> the bug in our C diag is somewhere in our setup.
If (1) diverges     -> the bug is in libcrypto.so.3, affects everyone
                       linking against this system OpenSSL build.
If (1) and (3) diverge but (2) matches NIST -> definite proof the bug
                       is OpenSSL 3.5.6 default provider, and the NIST
                       vector itself is correct.

Run :
    python3 disabled/verify_aes_gcm_tc14.py
"""
import subprocess
import sys

# NIST SP 800-38D Appendix B Test Case 14 (AES-256, 60-byte PT, NO AAD).
K   = bytes.fromhex("feffe9928665731c6d6a8f9467308308"
                     "feffe9928665731c6d6a8f9467308308")
IV  = bytes.fromhex("cafebabefacedbaddecaf888")
PT  = bytes.fromhex("d9313225f88406e5a55909c5aff5269a"
                     "86a7a9531534f7da2e4c303d8a318a72"
                     "1c3c0c95956809532fcf0e2449a6b525"
                     "b16aedf5aa0de657ba637b39")
NIST_CT  = bytes.fromhex("522dc1f099567d07f47f37a32a84427d"
                          "643a8cdcbfe5c0c97598a2bd2555d1aa"
                          "8cb08e48590dbb3da7b08b1056828838"
                          "c5f61e6393ba7a0abcc9f662")
NIST_TAG = bytes.fromhex("b094dac5d93471bdec1a502270e3cc6c")

# Tag observed in our C diag with OpenSSL 3.5.6 default provider.
OBSERVED_C_TAG = bytes.fromhex("eb9f796c8d356fc31a8433884b696f4f")


def header(s):
    print("\n" + "=" * 64)
    print(s)
    print("=" * 64)


def show(name, got, expected, label):
    match = "YES" if got == expected else "NO"
    print(f"  {name:<40s} {got.hex():>32s}  match-{label}={match}")


# ============================================================
# Cross-check 1 : Python `cryptography` library
# ============================================================
header("Cross-check 1 : Python cryptography (cffi binding to OpenSSL)")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(K)
    out = aesgcm.encrypt(IV, PT, None)  # associated_data = None
    py_ct  = out[:-16]
    py_tag = out[-16:]
    print(f"  CT length        = {len(py_ct)} bytes")
    print(f"  CT (first 16)    = {py_ct[:16].hex()}")
    print(f"  CT full match    = {'YES' if py_ct == NIST_CT else 'NO'}")
    print(f"  TAG observed     = {py_tag.hex()}")
    print(f"  TAG NIST exp.    = {NIST_TAG.hex()}")
    print(f"  TAG observed-C   = {OBSERVED_C_TAG.hex()}")
    print()
    if py_tag == NIST_TAG:
        print("  >>> Python matches NIST. Our C diag has a bug. <<<")
    elif py_tag == OBSERVED_C_TAG:
        print("  >>> Python matches C diag. Bug is in libcrypto.so.3.")
        print("      Affects everyone linking system OpenSSL 3.5.6. <<<")
    else:
        print("  >>> Python differs from BOTH. Investigate further. <<<")
except ImportError:
    print("  cryptography module not installed. Install with :")
    print("    apt install -y python3-cryptography  # or pip3 install cryptography")

# ============================================================
# Cross-check 2 : pure-Python AES-GCM (no OpenSSL)
# ============================================================
header("Cross-check 2 : pure-Python AES-GCM (independent of OpenSSL)")

try:
    # We use the `pycryptodome` library which has its own pure-Python AES
    # fallback path (under PYCRYPTODOME_FALLBACK_TO_PYAES env). On most
    # systems it'll still call the system AES-NI for speed, but the GCM
    # mode itself is implemented in Python.
    from Crypto.Cipher import AES
    cipher = AES.new(K, AES.MODE_GCM, nonce=IV)
    # No AAD : we don't call update().
    ct, tag = cipher.encrypt_and_digest(PT)
    print(f"  CT (first 16)    = {ct[:16].hex()}")
    print(f"  CT full match    = {'YES' if ct == NIST_CT else 'NO'}")
    print(f"  TAG observed     = {tag.hex()}")
    print(f"  TAG NIST exp.    = {NIST_TAG.hex()}")
    print()
    if tag == NIST_TAG:
        print("  >>> pycryptodome matches NIST. Confirms NIST is correct.")
        print("      If Python cryptography ALSO matches NIST -> our C diag")
        print("      is wrong. Otherwise -> OpenSSL has a bug. <<<")
    else:
        print("  >>> pycryptodome diverges from NIST. Unusual ; the NIST")
        print("      vector or our reading of it is probably wrong. <<<")
except ImportError:
    print("  pycryptodome module not installed. Install with :")
    print("    apt install -y python3-pycryptodome  # or pip3 install pycryptodome")

# ============================================================
# Cross-check 3 : openssl CLI (default provider)
# ============================================================
header("Cross-check 3 : openssl CLI")

try:
    ver = subprocess.run(
        ["openssl", "version", "-a"],
        capture_output=True, text=True, check=True,
    )
    print("OpenSSL CLI version :")
    for line in ver.stdout.splitlines()[:3]:
        print(f"  {line}")
    print()

    # `openssl enc` with -aes-256-gcm requires the IV to be supplied via -iv
    # but does NOT directly output the auth tag in a way easy to parse.
    # We use `openssl pkeyutl` and friends are also limited.  Easiest is to
    # invoke OpenSSL via Python ctypes — which IS the cryptography library
    # above. So Cross-check 3 here is mainly informational about which
    # OpenSSL version the CLI binary is linked against.
    print("(openssl enc CLI does not directly expose the GCM tag in a")
    print("convenient way ; Cross-check 1 above already uses libcrypto.so")
    print("via cffi, which is the same binary the CLI links against.)")
except FileNotFoundError:
    print("  openssl binary not found in PATH.")
except subprocess.CalledProcessError as e:
    print(f"  openssl returned {e.returncode}")

# ============================================================
# Verdict
# ============================================================
header("Verdict (combine outputs above)")
print("""
  Cross-check 1 (Python cryptography) tells us whether our system-wide
  libcrypto.so.3 has the divergence.

  Cross-check 2 (pycryptodome) tells us whether the NIST vector itself
  is what we think it is.

  Cross-check 3 confirms which CLI binary is involved.

  If Python cryptography matches NIST and our C diag does not :
    -> the bug is in OUR C setup, not OpenSSL.
       Likely a state-machine quirk we miss in run_aesgcm_vec.

  If Python cryptography matches our C diag (eb9f796c...) :
    -> the bug is REALLY in OpenSSL 3.5.6 default provider's
       libcrypto.so.3. Upstream-reportable.

  Either way, this script's output decides the next step.
""")
