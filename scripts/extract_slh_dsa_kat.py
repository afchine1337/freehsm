#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
"""Extract SLH-DSA known-answer vectors from NIST's ACVP-Server JSON.

Wycheproof has no SLH-DSA vectors; NIST's SLH-DSA-sigGen-FIPS205 and
SLH-DSA-sigVer-FIPS205 do. They are tens of megabytes and an SLH-DSA-256f
signature is 49 856 bytes, so tests/vectors/slh_dsa_kat.txt keeps a pinned
subset. Only what PKCS#11 can reach is taken: the external interface, pure
(CKM_SLH_DSA with CK_SIGN_ADDITIONAL_CONTEXT), and for generation the
deterministic vectors (CKH_DETERMINISTIC_REQUIRED). The internal interface,
preHash (HashSLH-DSA) and hedged generation, whose randomness cannot be
injected, are left out.

  G  per parameter set, the deterministic vector with the shortest message;
     for SHA2-128s and SHAKE-128s also one with an empty context. The test
     compares the signature byte for byte, then verifies NIST's signature
     with the vector's public key.
  V  for SHA2-128s and SHAKE-128s, the shortest vector of each kind NIST
     lists: valid, modified message, modified R, SIGFORS or SIGHT, and a
     signature too small or too large.

One vector per line, fields separated by single spaces, `-` for an empty
field:

  G <set> <context> <message> <sk> <pk> <signature>
  V <set> <context> <message> <pk> <signature> <1 accepted|0 rejected> <kind>

<set> is the FIPS 205 name without the "SLH-DSA-" prefix, e.g. SHA2-128s.

Usage, with a checkout of usnistgov/ACVP-Server or pkcs11-check's pinned copy:

  python3 scripts/extract_slh_dsa_kat.py \\
      <ACVP-Server>/gen-val/json-files > tests/vectors/slh_dsa_kat.txt
"""
from __future__ import annotations

import json
import os
import sys

# PKCS#11 v3.2 CKP_SLH_DSA_* order; the test uses the same.
SETS = ["SHA2-128s", "SHAKE-128s", "SHA2-128f", "SHAKE-128f",
        "SHA2-192s", "SHAKE-192s", "SHA2-192f", "SHAKE-192f",
        "SHA2-256s", "SHAKE-256s", "SHA2-256f", "SHAKE-256f"]
VERIFY_SETS = ["SHA2-128s", "SHAKE-128s"]
EMPTY_CONTEXT_SETS = ["SHA2-128s", "SHAKE-128s"]

KINDS = [  # the start of NIST's reason text, to one token. A prefix and not a
    # substring: "invalid signature - too large" contains "valid signature".
    ("valid signature and message", "valid"),
    ("modified message", "modified-message"),
    ("modified signature - R", "modified-R"),
    ("modified signature - SIGFORS", "modified-SIGFORS"),
    ("modified signature - SIGHT", "modified-SIGHT"),
    ("invalid signature - too small", "too-small"),
    ("invalid signature - too large", "too-large"),
]


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
    if isinstance(prompt, list):
        prompt = prompt[-1]
    if isinstance(expected, list):
        expected = expected[-1]
    results = {(g["tgId"], t["tcId"]): t for g in expected["testGroups"] for t in g["tests"]}
    for g in prompt["testGroups"]:
        for t in g["tests"]:
            t.update(results.get((g["tgId"], t["tcId"]), {}))
    return prompt["testGroups"]


def hx(t: dict, name: str) -> str:
    v = t.get(name, "")
    return v.lower() if isinstance(v, str) and v else "-"


def pure_external(g: dict) -> bool:
    return str(g.get("signatureInterface", "")).lower() == "external" \
        and str(g.get("preHash", "")).lower() == "pure"


def short_set(g: dict) -> str:
    return str(g.get("parameterSet", "")).removeprefix("SLH-DSA-")


def kind(reason: str) -> str:
    for text, token in KINDS:
        if reason.startswith(text):
            return token
    return ""


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    base = sys.argv[1]
    gen = load(os.path.join(base, "SLH-DSA-sigGen-FIPS205"))
    ver = load(os.path.join(base, "SLH-DSA-sigVer-FIPS205"))

    chosen: dict[tuple[str, str], dict] = {}
    for g in gen:
        if not g.get("deterministic") or not pure_external(g):
            continue
        ps = short_set(g)
        for t in g["tests"]:
            if hx(t, "sk") == "-" or hx(t, "pk") == "-" or hx(t, "signature") == "-":
                continue
            ml = len(t.get("message", ""))
            k = (ps, "short")
            if k not in chosen or ml < len(chosen[k].get("message", "")):
                chosen[k] = t
            if ps in EMPTY_CONTEXT_SETS and hx(t, "context") == "-":
                k = (ps, "empty")
                if k not in chosen or ml < len(chosen[k].get("message", "")):
                    chosen[k] = t

    out: list[str] = []
    for ps in SETS:
        picks = [chosen.get((ps, "short")), chosen.get((ps, "empty"))]
        seen = set()
        for t in picks:
            if t is None or t["tcId"] in seen:
                continue
            seen.add(t["tcId"])
            out.append(" ".join(["G", ps, hx(t, "context"), hx(t, "message"),
                                 hx(t, "sk"), hx(t, "pk"), hx(t, "signature")]))

    best: dict[tuple[str, str], tuple[dict, bool]] = {}
    for g in ver:
        ps = short_set(g)
        if not pure_external(g) or ps not in VERIFY_SETS:
            continue
        for t in g["tests"]:
            kd = kind(str(t.get("reason", "")))
            if not kd or hx(t, "pk") == "-" or hx(t, "signature") == "-":
                continue
            k = (ps, kd)
            if k not in best or len(t.get("message", "")) < len(best[k][0].get("message", "")):
                best[k] = (t, bool(t.get("testPassed")))
    for ps in VERIFY_SETS:
        for _, kd in KINDS:
            if (ps, kd) not in best:
                continue
            t, passed = best[(ps, kd)]
            out.append(" ".join(["V", ps, hx(t, "context"), hx(t, "message"),
                                 hx(t, "pk"), hx(t, "signature"),
                                 "1" if passed else "0", kd]))

    gens = sum(1 for l in out if l[0] == "G")
    vers = len(out) - gens
    print(f"# SLH-DSA known answers: {gens} generations, {vers} verifications.")
    print("# Extracted by scripts/extract_slh_dsa_kat.py from NIST ACVP-Server")
    print("# SLH-DSA-sigGen-FIPS205 and SLH-DSA-sigVer-FIPS205.")
    print("# Format: see the script. NIST test vectors are public domain.")
    for l in out:
        print(l)
    sys.stderr.write(f"{gens} sigGen, {vers} sigVer vectors\n")
    return 0 if gens >= len(SETS) and vers else 1


if __name__ == "__main__":
    sys.exit(main())
