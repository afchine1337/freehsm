#!/usr/bin/env python3
"""Diff every PKCS#11 constant #defined in this module against an
authoritative spec table, and fail loudly on any divergence.

Motivation (#125): three separate bugs in one day came from constants written
from memory rather than checked -- CKA_PARAMETER_SET sitting on CKA_MODIFIABLE's
code point, AES-CMAC advertised under CKM_AES_XCBC_MAC, and a family of wrap
CKR codes that each decoded to a different error. Each was found only when a
test happened to trip over it. This script finds them all at once, before they
ship.

The reference table is pkcs11-check's raw/types_std.py, which is derived from
the OASIS spec; its AES-MAC and CKR values were cross-checked by hand against
the OASIS pkcs11t.h.

Usage:
  python3 scripts/audit_constants.py --spec /path/to/pkcs11_check/raw/types_std.py
Exit code 1 on any divergence, so it can gate CI.
"""
import argparse, glob, os, re, sys

SUFFIXES = re.compile(r'_(LIST|ATTR|OP)$')   # module-local shadow aliases

def load_spec(path):
    table = {}
    for m in re.finditer(r'^(CK[A-Z]+_\w+)\s*=\s*CK\w+\(\s*(0x[0-9A-Fa-f]+)',
                         open(path).read(), re.M):
        table[m.group(1)] = int(m.group(2), 16)
    return table

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True, help="pkcs11-check raw/types_std.py")
    ap.add_argument("--sources", nargs="*", default=["src/*.c", "include/*.h"])
    args = ap.parse_args()

    if not os.path.isfile(args.spec):
        print(f"audit_constants: reference table not found: {args.spec!r}",
              file=sys.stderr)
        return 2
    spec = load_spec(args.spec)
    if not spec:
        print(f"audit_constants: no constants parsed from {args.spec} -- "
              "wrong file, or its format changed", file=sys.stderr)
        return 2

    bad, ok, unchecked = [], 0, 0
    for pattern in args.sources:
        for f in glob.glob(pattern):
            for m in re.finditer(r'^\s*#define\s+(CK[A-Z]+_\w+)\s+(0x[0-9A-Fa-f]+)',
                                 open(f).read(), re.M):
                name, val = m.group(1), int(m.group(2), 16)
                base = SUFFIXES.sub('', name)
                if base not in spec:
                    # Counted, not checked.
                    #
                    # The reference is pkcs11-check's types_std.py, a partial
                    # extraction of the OASIS header, so a name it does not
                    # carry may be ours or may be one the extraction missed.
                    # This script cannot tell the two apart and passes both.
                    #
                    # On 2026-09-14 that let CKM_KMAC128/256 through on
                    # unassigned values and CKM_X25519_DERIVE / CKM_X448_DERIVE
                    # through on CKM_ECMQV_DERIVE's and
                    # CKM_RSA_AES_KEY_WRAP's. All five were filed here, under
                    # a label that makes an invented code point look
                    # deliberate.
                    #
                    # Mechanisms are now checked against the full OASIS header
                    # by scripts/check_mech_codepoints.py, which can tell the
                    # difference. This counter is left as a count and its name
                    # corrected: it is not evidence that anything is local.
                    unchecked += 1
                    continue
                if val == spec[base]:
                    ok += 1
                else:
                    clash = [k for k, v in spec.items()
                             if v == val and k.split('_')[0] == base.split('_')[0]]
                    bad.append((name, val, spec[base], clash[0] if clash else "?", f))

    print(f"[audit_constants] {ok} conform, {unchecked} not in the reference "
          f"(unchecked here -- see check_mech_codepoints.py), "
          f"{len(bad)} divergent")
    if bad:
        print(f"\n{'constant':<38} {'module':>9} {'spec':>9}  {'module value actually means':<34} file")
        print("-" * 132)
        for name, val, want, clash, f in sorted(bad):
            print(f"{name:<38} {hex(val):>9} {hex(want):>9}  {clash:<34} {f}")
        print("\nA constant whose value belongs to a different name is an interop bug:")
        print("callers get a different algorithm or error than they asked for.")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
