#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
"""Fail on a pkcs11-check failure nobody has accounted for.

    scripts/pkcs11_check_gate.py reports/X/report.jsonl --profile all-mechanisms

The pkcs11-check job does not gate on counts, and should not: a large xfail
count is the harness describing what PKCS#11 cannot express. But a *failure*
is the harness saying the module did something wrong, and between 2026-09-27
and 2026-09-29 nine of them sat in the all-mechanisms profile, which no CI job
built. Most had been there for weeks.

So this gates on node-ids, not totals. Every failure must appear in
tests/pkcs11_check_known_failures.txt for this profile, with a reason, or the
job fails and names it. A listed failure that no longer fails is reported but
does not fail the job: it means the list can shrink, which is good news that
should still be acted on.

Node-ids are normalised and the log reduced by the same code
scripts/diff_pkcs11_runs.py uses, so the two tools cannot disagree about what
a test is called or what its outcome was.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from diff_pkcs11_runs import load, normalise        # noqa: E402

PROFILES = ("nist-approved-only", "all-mechanisms")
FAILED = ("failed", "error")


def known_for(path: Path, profile: str) -> set[str]:
    known: set[str] = set()
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()     # node-ids never contain '#'
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or (parts[0] != "*" and parts[0] not in PROFILES):
            sys.exit(f"{path}:{n}: expected '<profile|*> <node-id>', got: {raw!r}")
        if parts[0] in ("*", profile):
            known.add(normalise(parts[1].strip()))
    return known


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("report", type=Path, help="pkcs11-check report.jsonl (or .gz)")
    p.add_argument("--profile", required=True, choices=PROFILES)
    p.add_argument("--known", type=Path,
                   default=Path(__file__).resolve().parent.parent
                           / "tests" / "pkcs11_check_known_failures.txt")
    args = p.parse_args(argv)

    outcomes = load(args.report)
    if not outcomes:
        print(f"::error::{args.report} holds no test outcomes -- the harness did not run")
        return 1
    known = known_for(args.known, args.profile)
    failed = {nid for nid, o in outcomes.items() if o in FAILED}

    new = sorted(failed - known)
    fixed = sorted(nid for nid in known if nid in outcomes and nid not in failed)

    print(f"  profile {args.profile}: {len(outcomes)} tests, {len(failed)} failed, "
          f"{len(failed & known)} of them known")
    for nid in fixed:
        print(f"::notice::listed as a known failure but did not fail: {nid} "
              f"-- remove it from {args.known.name}")
    for nid in new:
        print(f"::error::new pkcs11-check failure ({args.profile}): {nid}")
    if new:
        print(f"\n  {len(new)} failure(s) not in {args.known.name}. Read each one; "
              "fix the module, or list it there with the reason it is not ours.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
