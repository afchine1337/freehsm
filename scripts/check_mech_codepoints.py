#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
"""Check every mechanism and key-type code point against the OASIS header.

On 2026-09-14 this module was found to advertise CKM_KMAC128 = 0x4080 and
CKM_KMAC256 = 0x4081. Neither is a PKCS#11 mechanism: the OASIS v3.2
pkcs11t.h has no KMAC of any spelling, and the standard range it defines
ends at CKM_PUB_KEY_FROM_PRIV_KEY = 0x403A. The entries had sat in the
table citing SP 800-185 -- the standard for the algorithm, which says
nothing about a code point.

That was found by hand, by applying a rule this project wrote for itself
after advertising CMAC under CKM_AES_XCBC_MAC's value. The rule had been in
the comments for two months and had caught nothing, because a rule that
depends on someone remembering to apply it is a habit, not a check.

Usage:
    python3 scripts/check_mech_codepoints.py path/to/pkcs11t.h

The header is not vendored here -- it carries its own licence and a network
dependency inside a check is its own kind of fragility. Fetch it from:

    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/csd01/include/pkcs11-v3.2/pkcs11t.h

Exit status 0 when every value matches, 1 otherwise.

What is checked:
  - a mechanism named in gen_p11_thunks.py must exist in the header, and
    its value must match
  - a value at or above CKM_VENDOR_DEFINED (0x80000000) is exempt from
    existing, because that range is ours by definition -- but it must NOT
    collide with a standard name
  - a mechanism absent from the header and below the vendor range is the
    KMAC case, and is what this script exists to refuse

What is not checked: whether the mechanism is implemented. That is
tests/test_advertised_operational's job, and the two questions are
different -- KMAC was implemented correctly on a code point that does not
exist, which is exactly why it looked finished.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

VENDOR_DEFINED = 0x80000000

DEFINE_RE = re.compile(
    r"^\s*#define\s+(CK[MK]_[A-Za-z0-9_]+)\s+0x([0-9a-fA-F]+)UL", re.M
)
MECH_RE = re.compile(
    r'Mech\(\s*"(CKM_[A-Za-z0-9_]+)"\s*,\s*(0x[0-9a-fA-F]+)', re.M
)


def load_header(path: Path) -> dict[str, int]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out: dict[str, int] = {}
    for name, value in DEFINE_RE.findall(text):
        out[name] = int(value, 16)
    if not out:
        sys.exit(f"{path}: no CKM_/CKK_ defines found -- wrong file?")
    return out


def load_table(path: Path) -> list[tuple[str, int]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    entries = [(n, int(v, 16)) for n, v in MECH_RE.findall(text)]
    if not entries:
        sys.exit(f"{path}: no Mech(...) entries found -- wrong file?")
    return entries


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__.strip().splitlines()[0] + "\n\nusage: "
                 "check_mech_codepoints.py path/to/pkcs11t.h")

    here = Path(__file__).resolve().parent
    header = load_header(Path(sys.argv[1]))
    table = load_table(here / "gen_p11_thunks.py")
    by_value = {v: k for k, v in header.items() if k.startswith("CKM_")}

    problems: list[str] = []
    vendor = 0

    for name, value in table:
        if value >= VENDOR_DEFINED:
            vendor += 1
            clash = by_value.get(value)
            if clash:
                problems.append(
                    f"{name} = {value:#x} is in the vendor range but collides "
                    f"with {clash}")
            continue

        want = header.get(name)
        if want is None:
            other = by_value.get(value)
            detail = (f"; {value:#x} is {other} in the header"
                      if other else f"; {value:#x} is unassigned")
            problems.append(
                f"{name} is not a PKCS#11 mechanism{detail}")
        elif want != value:
            problems.append(
                f"{name} = {value:#x} but the header says {want:#x}")

    print(f"{len(table)} mechanisms in the table, {vendor} vendor-defined, "
          f"{len(header)} names in the header")

    if problems:
        print()
        for p in problems:
            print(f"  FAIL  {p}")
        print(f"\n{len(problems)} problem(s)")
        return 1

    print("all code points match the header")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
