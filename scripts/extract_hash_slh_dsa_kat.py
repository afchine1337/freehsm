#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
"""Extract HashSLH-DSA known-answer vectors from NIST's ACVP-Server JSON.

The preHash groups of SLH-DSA-sigGen-FIPS205 and SLH-DSA-sigVer-FIPS205,
external interface, as PKCS#11 reaches them (CKM_HASH_SLH_DSA_<hash> and the
generic CKM_HASH_SLH_DSA). What HashSLH-DSA adds to SLH-DSA is M' -- the
context, the hash OID and PH(M) -- which does not depend on the parameter
set, and tests/test_slh_dsa_kat.c already covers all twelve sets. So the
subset keeps every hash on the 128s sets, whose signatures are the shortest
(7 856 bytes), alternating SHA2-128s and SHAKE-128s:

  G  deterministic generation, one per hash. The test compares the signature
     byte for byte.
  V  verification on the 128s sets, one per hash with a rejected case
     preferred, plus every accepted case those sets have.

One vector per line, fields separated by single spaces, `-` for an empty
field, the same shape as tests/vectors/hash_ml_dsa_kat.txt:

  G <set> <hash> <context> <message> <sk> <signature>
  V <set> <hash> <context> <message> <pk> <signature> <1 accepted|0 rejected>

<set> is the FIPS 205 name without the "SLH-DSA-" prefix.

Usage, with a checkout of usnistgov/ACVP-Server or pkcs11-check's pinned copy:

  python3 scripts/extract_hash_slh_dsa_kat.py \\
      <ACVP-Server>/gen-val/json-files > tests/vectors/hash_slh_dsa_kat.txt
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_slh_dsa_kat import hx, load, short_set  # noqa: E402

HASHES = ["SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224",
          "SHA2-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
          "SHAKE-128", "SHAKE-256"]
SETS = ["SHA2-128s", "SHAKE-128s"]


def prehash_external(g: dict) -> bool:
    return str(g.get("signatureInterface", "")).lower() == "external" \
        and str(g.get("preHash", "")).lower() == "prehash"


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    base = sys.argv[1]
    gen = load(os.path.join(base, "SLH-DSA-sigGen-FIPS205"))
    ver = load(os.path.join(base, "SLH-DSA-sigVer-FIPS205"))

    by: dict[tuple[str, str], dict] = {}
    for g in gen:
        if not g.get("deterministic") or not prehash_external(g):
            continue
        ps = short_set(g)
        if ps not in SETS:
            continue
        for t in g["tests"]:
            if hx(t, "sk") == "-" or hx(t, "signature") == "-":
                continue
            k = (ps, t.get("hashAlg", ""))
            if k not in by or len(t.get("message", "")) < len(by[k].get("message", "")):
                by[k] = t

    out: list[str] = []
    for i, h in enumerate(HASHES):
        ps = SETS[i % 2]
        t = by.get((ps, h)) or by.get((SETS[(i + 1) % 2], h))
        if t is None:
            continue
        ps = ps if (ps, h) in by else SETS[(i + 1) % 2]
        out.append(" ".join(["G", ps, h, hx(t, "context"), hx(t, "message"),
                             hx(t, "sk"), hx(t, "signature")]))

    rejected: dict[str, str] = {}
    accepted: list[str] = []
    for g in ver:
        ps = short_set(g)
        if not prehash_external(g) or ps not in SETS:
            continue
        for t in g["tests"]:
            h = t.get("hashAlg", "")
            if h not in HASHES or hx(t, "pk") == "-" or hx(t, "signature") == "-":
                continue
            passed = bool(t.get("testPassed"))
            line = " ".join(["V", ps, h, hx(t, "context"), hx(t, "message"),
                             hx(t, "pk"), hx(t, "signature"), "1" if passed else "0"])
            if passed:
                accepted.append(line)
            elif h not in rejected:
                rejected[h] = line
    out.extend(rejected[h] for h in HASHES if h in rejected)
    out.extend(accepted)

    gens = sum(1 for l in out if l[0] == "G")
    vers = len(out) - gens
    print(f"# HashSLH-DSA known answers: {gens} generations, {vers} verifications.")
    print("# Extracted by scripts/extract_hash_slh_dsa_kat.py from NIST ACVP-Server")
    print("# SLH-DSA-sigGen-FIPS205 and SLH-DSA-sigVer-FIPS205, preHash, external.")
    print("# Format: see the script. NIST test vectors are public domain.")
    for l in out:
        print(l)
    sys.stderr.write(f"{gens} sigGen, {vers} sigVer vectors\n")
    return 0 if gens == len(HASHES) and vers else 1


if __name__ == "__main__":
    sys.exit(main())
