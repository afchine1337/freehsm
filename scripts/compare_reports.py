#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# compare_reports.py --- diff two pkcs11-check runs by node-id.
#
# Two independent implementations of one specification, driven by the same
# vectors. Where they disagree on a test case, one of them is wrong, and
# finding out which is worth more to both than either report alone.
#
# This is not a scoreboard. A module that passes more tests than another may
# simply advertise more mechanisms; a module that skips a family is not failing
# it. What the tool reports is *divergence on a shared test case*, which is the
# only comparison that means anything.
#
# Usage:
#   scripts/compare_reports.py A/report.jsonl B/report.jsonl
#   scripts/compare_reports.py A/report.jsonl B/report.jsonl --outcomes-only
#
# See docs/CROSS_VALIDATION.md for what a divergence does and does not prove.
# ===========================================================================
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter


def load(path: str) -> dict[str, str]:
    """node-id -> outcome, for the call phase only.

    setup/teardown reports share the node-id and would overwrite the result
    that matters. report.jsonl is a raw pytest --report-log, so it carries all
    three phases.
    """
    out: dict[str, str] = {}
    with open(path, errors="replace") as fh:
        for line in fh:
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("$report_type") != "TestReport":
                continue
            if d.get("when") != "call":
                continue
            nid = d.get("nodeid")
            if not nid:
                continue
            outcome = d.get("outcome", "?")
            # pytest marks xfail as "skipped" with a wasxfail attribute.
            if outcome == "skipped" and d.get("wasxfail") is not None:
                outcome = "xfail"
            out[nid] = outcome
    return out


def provenance(report_path: str) -> str:
    """The provenance.txt beside a report, if run_pkcs11_check.sh wrote one."""
    p = os.path.join(os.path.dirname(os.path.abspath(report_path)), "provenance.txt")
    if not os.path.exists(p):
        return "(no provenance.txt --- was this run made by run_pkcs11_check.sh?)"
    return open(p, errors="replace").read().rstrip()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Diff two pkcs11-check runs by node-id.")
    ap.add_argument("a", help="first report.jsonl")
    ap.add_argument("b", help="second report.jsonl")
    ap.add_argument("--outcomes-only", action="store_true",
                    help="skip the present-in-one-only section")
    ap.add_argument("--limit", type=int, default=40,
                    help="max lines per section (default 40)")
    args = ap.parse_args()

    A, B = load(args.a), load(args.b)

    print("=" * 72)
    print(f"A  {args.a}")
    for line in provenance(args.a).splitlines():
        print(f"   {line}")
    print()
    print(f"B  {args.b}")
    for line in provenance(args.b).splitlines():
        print(f"   {line}")
    print("=" * 72)
    print()
    print(f"A: {len(A):7d} test cases     B: {len(B):7d} test cases")

    for label, d in (("A", A), ("B", B)):
        c = Counter(d.values())
        parts = "  ".join(f"{k}={v}" for k, v in sorted(c.items()))
        print(f"{label}: {parts}")
    print()

    shared = set(A) & set(B)
    only_a = sorted(set(A) - set(B))
    only_b = sorted(set(B) - set(A))
    diverged = sorted(n for n in shared if A[n] != B[n])

    print(f"shared test cases : {len(shared)}")
    print(f"only in A         : {len(only_a)}")
    print(f"only in B         : {len(only_b)}")
    print(f"DIVERGENT         : {len(diverged)}")
    print()

    if diverged:
        print("-" * 72)
        print("Divergent outcomes on shared cases --- the part that means something.")
        print("One of the two is wrong on each of these, or the specification is")
        print("ambiguous and both are defensible. Read the vector before deciding.")
        print("-" * 72)
        # Group by the transition, so one repeated behaviour reads as one thing.
        by_pair: dict[tuple[str, str], list[str]] = {}
        for n in diverged:
            by_pair.setdefault((A[n], B[n]), []).append(n)
        for (oa, ob), nodes in sorted(by_pair.items(), key=lambda kv: -len(kv[1])):
            print(f"\n  A={oa} -> B={ob}   ({len(nodes)} cases)")
            for n in nodes[:args.limit]:
                print(f"      {n}")
            if len(nodes) > args.limit:
                print(f"      ... and {len(nodes) - args.limit} more")
        print()

    if not args.outcomes_only and (only_a or only_b):
        print("-" * 72)
        print("Present in one run only. Usually different advertised mechanisms or")
        print("different corpora --- check both provenance blocks above before")
        print("reading anything into it.")
        print("-" * 72)
        for label, lst in (("only in A", only_a), ("only in B", only_b)):
            if not lst:
                continue
            files = Counter(n.split("::")[0] for n in lst)
            print(f"\n  {label}: {len(lst)} cases across {len(files)} files")
            for f, k in files.most_common(args.limit):
                print(f"      {k:6d}  {f}")
        print()

    return 1 if diverged else 0


if __name__ == "__main__":
    sys.exit(main())
