#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
"""Extract a small set of HashML-DSA known-answer vectors from NIST's
ACVP-Server JSON (docs/hash-ml-dsa-plan.md).

The full sets are megabytes; tests/vectors/hash_ml_dsa_kat.txt keeps what the
test needs to catch a wrong M':

  G  deterministic, external-interface, preHash signature generation: every
     hash for ML-DSA-44, and one case each for ML-DSA-65 and ML-DSA-87. The
     test compares the signature byte for byte -- a signature that merely
     verifies against the module's own verify proves nothing about M'.
  V  preHash signature verification, one case per hash for ML-DSA-44, a
     rejected one preferred, since accepting is the easy half.

One vector per line, fields separated by single spaces, `-` for an empty
field:

  G <set> <hash> <context> <message> <sk> <signature>
  V <set> <hash> <context> <message> <pk> <signature> <1 accepted|0 rejected>

Usage, in the VM where pkcs11-check keeps its pinned copy:

  python3 scripts/extract_hash_mldsa_kat.py \\
      ~/.local/share/pkcs11-check/data/acvp/gen-val/json-files > tests/vectors/hash_ml_dsa_kat.txt
"""
from __future__ import annotations

import json
import os
import sys

# ACVP writes SHA2-256 or SHA-256, SHAKE-128 or SHAKE128 depending on the
# set and its revision; the test file uses one spelling.
HASHES = {
    "SHA2-224": "SHA2-224", "SHA-224": "SHA2-224",
    "SHA2-256": "SHA2-256", "SHA-256": "SHA2-256",
    "SHA2-384": "SHA2-384", "SHA-384": "SHA2-384",
    "SHA2-512": "SHA2-512", "SHA-512": "SHA2-512",
    "SHA2-512/224": "SHA2-512/224", "SHA-512/224": "SHA2-512/224",
    "SHA2-512/256": "SHA2-512/256", "SHA-512/256": "SHA2-512/256",
    "SHA3-224": "SHA3-224", "SHA3-256": "SHA3-256",
    "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512",
    "SHAKE-128": "SHAKE-128", "SHAKE128": "SHAKE-128",
    "SHAKE-256": "SHAKE-256", "SHAKE256": "SHAKE-256",
}


def load(dirpath: str) -> list[dict]:
    """The test groups, each test carrying every field it has: from
    internalProjection.json when present, else prompt + expectedResults."""
    ip = os.path.join(dirpath, "internalProjection.json")
    if os.path.exists(ip):
        with open(ip) as f:
            return json.load(f)["testGroups"]
    with open(os.path.join(dirpath, "prompt.json")) as f:
        prompt = json.load(f)
    with open(os.path.join(dirpath, "expectedResults.json")) as f:
        expected = json.load(f)
    if isinstance(prompt, list):     # some revisions wrap the vector set in a list
        prompt = prompt[-1]
    if isinstance(expected, list):
        expected = expected[-1]
    results = {(g["tgId"], t["tcId"]): t for g in expected["testGroups"] for t in g["tests"]}
    for g in prompt["testGroups"]:
        for t in g["tests"]:
            t.update(results.get((g["tgId"], t["tcId"]), {}))
    return prompt["testGroups"]


def field(t: dict, g: dict, *names: str) -> str:
    for n in names:
        for src in (t, g):
            v = src.get(n)
            if isinstance(v, str):
                return v.lower() if v else "-"
    return ""


def is_prehash(g: dict, t: dict) -> bool:
    return str(g.get("preHash", t.get("preHash", ""))).lower() == "prehash"


def external(g: dict) -> bool:
    return str(g.get("signatureInterface", "external")).lower() == "external" \
        and not g.get("externalMu", False)


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser(
        "~/.local/share/pkcs11-check/data/acvp/gen-val/json-files")
    gen = load(os.path.join(base, "ML-DSA-sigGen-FIPS204"))
    ver = load(os.path.join(base, "ML-DSA-sigVer-FIPS204"))
    out: list[str] = []

    seen: set[tuple[str, str]] = set()
    for g in gen:
        if not g.get("deterministic") or not external(g):
            continue
        pset = g.get("parameterSet", "")
        for t in g["tests"]:
            if not is_prehash(g, t):
                continue
            h = HASHES.get(t.get("hashAlg", g.get("hashAlg", "")))
            if not h:
                continue
            # every hash for ML-DSA-44; one case for each other set
            key = (pset, h if pset == "ML-DSA-44" else "*")
            if key in seen:
                continue
            sk, sig = field(t, g, "sk"), field(t, g, "signature")
            if not sk or not sig or sk == "-":
                continue
            seen.add(key)
            out.append(" ".join(["G", pset, h, field(t, g, "context") or "-",
                                 field(t, g, "message") or "-", sk, sig]))

    best: dict[str, str] = {}
    for g in ver:
        if not external(g) or g.get("parameterSet") != "ML-DSA-44":
            continue
        for t in g["tests"]:
            if not is_prehash(g, t):
                continue
            h = HASHES.get(t.get("hashAlg", g.get("hashAlg", "")))
            pk, sig = field(t, g, "pk"), field(t, g, "signature")
            if not h or not pk or not sig or pk == "-":
                continue
            passed = bool(t.get("testPassed"))
            line = " ".join(["V", "ML-DSA-44", h, field(t, g, "context") or "-",
                             field(t, g, "message") or "-", pk, sig, "1" if passed else "0"])
            if h not in best or (not passed and best[h].endswith(" 1")):
                best[h] = line
    out.extend(best[h] for h in sorted(best))

    gens = sum(1 for l in out if l[0] == "G")
    vers = len(out) - gens
    print(f"# HashML-DSA known answers: {gens} generations, {vers} verifications.")
    print("# Extracted by scripts/extract_hash_mldsa_kat.py from NIST ACVP-Server")
    print("# ML-DSA-sigGen-FIPS204 and ML-DSA-sigVer-FIPS204, as pinned by pkcs11-check.")
    print("# Format: see the script. NIST test vectors are public domain.")
    for l in out:
        print(l)
    sys.stderr.write(f"{gens} sigGen, {vers} sigVer vectors\n")
    return 0 if gens and vers else 1


if __name__ == "__main__":
    sys.exit(main())
