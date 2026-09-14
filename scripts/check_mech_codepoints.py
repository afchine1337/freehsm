#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
"""Check every PKCS#11 constant in this module against the OASIS header.

Mechanisms from the generator's table, and every CK*_ constant #defined in
src/ and include/: name must exist in the header, value must match.

## Why this exists alongside audit_constants.py

audit_constants.py compares against pkcs11-check's raw/types_std.py, a
partial extraction of the OASIS header. A name that table does not carry is
ambiguous -- it may be a module-local alias, or one the extraction missed --
so that script counts it and moves on. 32 constants were in that category.

On 2026-09-14 five real defects were sitting in it:

    CKM_KMAC128       0x4080   unassigned
    CKM_KMAC256       0x4081   unassigned
    CKM_NIST_PRF_KDF  0x384    unassigned
    CKM_X25519_DERIVE 0x1052   is CKM_ECMQV_DERIVE
    CKM_X448_DERIVE   0x1054   is CKM_RSA_AES_KEY_WRAP

The last two were the CMAC/GMAC inversion in service: C_GetMechanismList
answered with ECMQV's code point and the module performed X25519 under it.

The header carries all 542 names, so here "not in the reference" means
something, and the skip category disappears.

## What counts as a failure

  - a name the header knows, with a different value
  - a name the header does not know, below CKM_VENDOR_DEFINED (0x80000000)
  - a vendor-range value that collides with a standard name

Module-local aliases are recognised by suffix -- the module #defines
CKM_SHA256_RSA_PKCS_LIST, CKA_EC_PARAMS_QUERY, CKM_HKDF_KEY_GEN_OP and so
on to avoid colliding with a platform header -- and are checked against
their base name, which is the point of having them.

## What this does not check

Whether the mechanism is implemented. That is
tests/test_advertised_operational's job, and the two questions are
different: KMAC was implemented correctly on a code point that does not
exist, which is exactly why it looked finished.

Usage:
    python3 scripts/check_mech_codepoints.py path/to/pkcs11t.h

The header is not vendored -- it carries its own licence, and a network
dependency inside a check is its own fragility. Fetch it from:

    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/csd01/include/pkcs11-v3.2/pkcs11t.h

Exit status 0 when everything matches, 1 otherwise.
"""
from __future__ import annotations

import glob
import re
import sys
from pathlib import Path

VENDOR_DEFINED = 0x80000000

# Module-local shadow aliases. Same list as audit_constants.py; a name
# ending in one of these is checked against the name without it.
SUFFIXES = re.compile(
    r"_(LIST|ATTR|OP|QUERY|KT|TMPL|MECH|INIT_VAL|CREATEOBJECT)$")

# Local names whose base spelling differs from the header's. Each line is a
# stated equivalence, checked like any other: the value still has to match.
# They are listed rather than pattern-matched so that adding one is a
# decision someone made, not a rule that quietly absorbs the next mistake.
ALIASES = {
    "CKM_SHA1":                "CKM_SHA_1",
    "CKM_SHA1_HMAC":           "CKM_SHA_1_HMAC",
    "CKM_ECDSA_BARE":          "CKM_ECDSA",
    "CKM_RSA_KEY_PAIR_GEN":    "CKM_RSA_PKCS_KEY_PAIR_GEN",
    "CKA_ALWAYS_AUTH":         "CKA_ALWAYS_AUTHENTICATE",
}

# CKF_ is not one namespace. Slot, token, session and mechanism flags are
# disjoint spaces that overlap by design -- CKF_HW = 0x1 as a mechanism flag
# and CKF_TOKEN_PRESENT = 0x1 as a slot flag are both correct. So a CKF_
# value is checked against its own name and never reported as "this value is
# really that other name", which for this prefix would be noise.
NO_VALUE_HINT = ("CKF",)

HEADER_RE = re.compile(
    r"^\s*#define\s+(CK[A-Z]+_[A-Za-z0-9_]+)\s+0x([0-9a-fA-F]+)UL", re.M
)
# CKA_WRAP_TEMPLATE and friends are defined as (CKF_ARRAY_ATTRIBUTE|0x212UL).
# Missing this form is what made CKA_UNWRAP_TEMPLATE_ATTR look invented.
HEADER_ARRAY_RE = re.compile(
    r"^\s*#define\s+(CKA_[A-Za-z0-9_]+)\s+\(\s*CKF_ARRAY_ATTRIBUTE\s*\|\s*"
    r"0x([0-9a-fA-F]+)UL\s*\)", re.M
)
CKF_ARRAY_ATTRIBUTE = 0x40000000
SOURCE_RE = re.compile(
    r"^\s*#define\s+(CK[A-Z]+_[A-Za-z0-9_]+)\s+(0x[0-9a-fA-F]+)", re.M
)
MECH_RE = re.compile(r'Mech\(\s*"(CKM_[A-Za-z0-9_]+)"\s*,\s*(0x[0-9a-fA-F]+)', re.M)


def family(name: str) -> str:
    return name.split("_", 1)[0]


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("usage: check_mech_codepoints.py path/to/pkcs11t.h")

    here = Path(__file__).resolve().parent
    root = here.parent

    text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    header = {n: int(v, 16) for n, v in HEADER_RE.findall(text)}
    for n, v in HEADER_ARRAY_RE.findall(text):
        header[n] = CKF_ARRAY_ATTRIBUTE | int(v, 16)
    if "CKM_VENDOR_DEFINED" not in header:
        sys.exit(f"{sys.argv[1]}: does not look like a pkcs11t.h")

    # value -> names, per family, for saying what a wrong value actually means
    by_value: dict[tuple[str, int], str] = {}
    for n, v in header.items():
        by_value.setdefault((family(n), v), n)

    entries: list[tuple[str, int, str]] = []
    for n, v in MECH_RE.findall((here / "gen_p11_thunks.py").read_text()):
        entries.append((n, int(v, 16), "gen_p11_thunks.py"))
    for pattern in ("src/*.c", "src/**/*.c", "include/*.h"):
        for f in glob.glob(str(root / pattern), recursive=True):
            src = Path(f).read_text(encoding="utf-8", errors="replace")
            for n, v in SOURCE_RE.findall(src):
                entries.append((n, int(v, 16), Path(f).name))
    if not entries:
        sys.exit("no constants found -- run from the repository")

    problems: list[str] = []
    checked = vendor = 0
    seen: set[tuple[str, int, str]] = set()

    for name, value, where in entries:
        if (name, value, where) in seen:
            continue
        seen.add((name, value, where))
        base = SUFFIXES.sub("", name)
        base = ALIASES.get(base, base)
        hint = family(base) not in NO_VALUE_HINT

        if value >= VENDOR_DEFINED:
            vendor += 1
            clash = by_value.get((family(base), value)) if hint else None
            if clash:
                problems.append(
                    f"{name} = {value:#x} ({where}) is in the vendor range "
                    f"but collides with {clash}")
            continue

        want = header.get(base)
        if want is None:
            other = by_value.get((family(base), value)) if hint else None
            detail = (f"; {value:#x} is {other}" if other
                      else f"; {value:#x} is unassigned")
            problems.append(f"{name} ({where}) is not a PKCS#11 constant{detail}")
        elif want != value:
            other = by_value.get((family(base), value)) if hint else None
            problems.append(
                f"{name} = {value:#x} ({where}) but the header says {want:#x}"
                + (f"; {value:#x} is {other}" if other else ""))
        else:
            checked += 1

    print(f"{checked} constants match, {vendor} vendor-defined, "
          f"{len(header)} names in the header")
    if problems:
        print()
        for p in sorted(problems):
            print(f"  FAIL  {p}")
        print(f"\n{len(problems)} problem(s)")
        return 1
    print("nothing unchecked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
