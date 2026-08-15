#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# tests/wycheproof/run_wycheproof.py --- Wycheproof orchestrator
#
# Discovers test vectors under tests/wycheproof/vectors/, dispatches each
# one to the matching adapter under tests/wycheproof/adapters/, and
# accumulates a global pass/fail report.
#
# Exit code :
#     0  --- every "valid" vector accepted and every "invalid" rejected
#     1  --- at least one violation (P1 incident, see README)
#     2  --- runner / module setup failure (P0)
#
# Usage :
#     ./run_wycheproof.py --module /path/to/libfreehsm-fips.so [--smoke] [--only <name>]
#
# The "smoke" mode picks the first 10 % of each schema's tests, capped at
# 50, to keep wall-clock under ~30 seconds for per-push CI.
# ===========================================================================

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
VECTORS_DIR = HERE / "vectors"
ADAPTERS_DIR = HERE / "adapters"
RESULTS_DIR = HERE / "results"
sys.path.insert(0, str(ADAPTERS_DIR))


# --- Adapter registry ------------------------------------------------------
#
# Each adapter declares the JSON `algorithm` strings it handles. When a
# vector file's `algorithm` field matches, the adapter's run() callable is
# invoked with (testGroup, test) and must return one of:
#     "match"     --- the module accepted/rejected as expected
#     "violation" --- the module disagreed with the expected result
#     "skip"      --- the test is out of scope (e.g. unsupported curve)
# ---------------------------------------------------------------------------

@dataclass
class AdapterStats:
    match: int = 0
    violation: int = 0
    skip: int = 0
    violations: list = field(default_factory=list)


class Adapter:
    """Base class. Subclasses live under adapters/ and import this."""

    name: str = "abstract"
    algorithms: tuple[str, ...] = ()

    def __init__(self, module_path: str):
        self.module_path = module_path

    def run(self, group: dict, test: dict) -> str:
        raise NotImplementedError


def discover_adapters(only: str | None = None) -> list[type[Adapter]]:
    import importlib

    found = []
    for path in sorted(ADAPTERS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        modname = path.stem
        if only and modname != only:
            continue
        mod = importlib.import_module(modname)
        if hasattr(mod, "ADAPTER"):
            found.append(mod.ADAPTER)
    return found


# --- Main loop -------------------------------------------------------------

def run_file(adapter: Adapter, path: Path, smoke: bool) -> AdapterStats:
    stats = AdapterStats()
    with path.open() as f:
        data = json.load(f)

    if data.get("algorithm") not in adapter.algorithms:
        return stats

    # Schema-level dispatch : Wycheproof ships two ECDSA file variants
    # under the same `algorithm = "ECDSA"` label : EcdsaVerify (DER
    # signatures) and EcdsaP1363Verify (raw r||s signatures). The
    # adapter declares which schemas it consumes via the optional
    # `schemas` tuple ; files not in the tuple are skipped (counted as
    # no stats), so a P1363 adapter can be added separately without the
    # DER adapter scoring its tests as hard-fail.
    schemas = getattr(adapter, "schemas", None)
    if schemas is not None:
        if data.get("schema") not in schemas:
            return stats

    groups = data.get("testGroups", [])
    file_algo = data.get("algorithm")
    for group in groups:
        # Make the file-level 'algorithm' available to the adapter via
        # the group dict (some Wycheproof MAC files only carry the
        # algorithm at the file level).
        group.setdefault("_algorithm", file_algo)
        tests = group.get("tests", [])
        if smoke:
            n = max(1, min(50, len(tests) // 10))
            tests = tests[:n]
        for test in tests:
            try:
                outcome = adapter.run(group, test)
            except Exception as exc:  # noqa: BLE001
                outcome = "violation"
                stats.violations.append({
                    "file": path.name,
                    "tcId": test.get("tcId"),
                    "reason": f"adapter raised : {exc!r}",
                })
            if outcome == "match":
                stats.match += 1
            elif outcome == "violation":
                stats.violation += 1
                stats.violations.append({
                    "file": path.name,
                    "tcId": test.get("tcId"),
                    "comment": test.get("comment", ""),
                    "expected": test.get("result"),
                })
            else:
                stats.skip += 1
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", required=True,
                        help="path to libfreehsm-fips.so")
    parser.add_argument("--smoke", action="store_true",
                        help="run only ~10 %% of vectors per file")
    parser.add_argument("--only", default=None,
                        help="run a single adapter by name (no .py)")
    args = parser.parse_args()

    if not Path(args.module).exists():
        print(f"ERROR : module {args.module} not found", file=sys.stderr)
        return 2
    if not VECTORS_DIR.exists():
        print("ERROR : vectors/ is empty. Run ./fetch_vectors.sh first.",
              file=sys.stderr)
        return 2

    adapter_classes = discover_adapters(args.only)
    if not adapter_classes:
        print("ERROR : no adapters discovered", file=sys.stderr)
        return 2

    adapters = [cls(args.module) for cls in adapter_classes]
    files = sorted(VECTORS_DIR.glob("*.json"))

    overall: dict[str, AdapterStats] = defaultdict(AdapterStats)
    t_start = time.time()
    for adapter in adapters:
        for f in files:
            stats = run_file(adapter, f, args.smoke)
            overall[adapter.name].match += stats.match
            overall[adapter.name].violation += stats.violation
            overall[adapter.name].skip += stats.skip
            overall[adapter.name].violations.extend(stats.violations)
    elapsed = time.time() - t_start

    # --- Report ------------------------------------------------------------
    print()
    print("=" * 72)
    print("WYCHEPROOF SUMMARY")
    print("=" * 72)
    print(f"  module    : {args.module}")
    print(f"  mode      : {'smoke' if args.smoke else 'full'}")
    print(f"  elapsed   : {elapsed:.1f} s")
    print()
    total_violations = 0
    for name, st in sorted(overall.items()):
        print(f"  {name:12s}  match={st.match:6d}  viol={st.violation:4d}  skip={st.skip:5d}")
        total_violations += st.violation
    print()

    # Adapter-level diagnostics : tells us if violations are DER-parser
    # artefacts or real C_Verify divergences.
    for adapter in adapters:
        diag = getattr(adapter, "diag", None)
        if not diag:
            continue
        print(f"  --- {adapter.name} DER classification ---")
        for k, v in diag.items():
            if v:
                print(f"    {k:32s} {v:6d}")
        print()

    # --- Violation categorization -----------------------------------------
    # Group violations by (expected, comment-prefix) so the operator can
    # see at a glance whether the divergences are :
    #   - "expected=invalid" failures : module accepted a bad signature
    #     (false positive --- potentially exploitable)
    #   - "expected=valid"   failures : module rejected a good signature
    #     (false negative --- broken implementation)
    # Comment prefix is the first 4 words ; this folds the ~3000 unique
    # Wycheproof comments down to a few dozen categories.
    if total_violations > 0:
        print("  --- violation breakdown (top 15 categories) ---")
        buckets: dict[tuple, int] = defaultdict(int)
        for name, st in sorted(overall.items()):
            for v in st.violations:
                comment = (v.get("comment") or "").strip()
                # Adapter-internal exceptions get their own bucket and a
                # longer slice so we can see the actual symbol / message.
                is_adapter = False
                if not comment and "reason" in v:
                    comment = v["reason"]
                    is_adapter = True
                if is_adapter:
                    # Drop the long .so path prefix so the actual error
                    # message (symbol name, etc.) is visible inside our
                    # display window.
                    short = comment.replace(
                        "/__w/freehsm-c/freehsm-c/libfreehsm-fips.so",
                        "[lib]",
                    )
                    prefix = short[:150] or "(no comment)"
                else:
                    prefix = " ".join(comment.split()[:4]) or "(no comment)"
                key = (v.get("expected", "?"), prefix)
                buckets[key] += 1
        for (expected, prefix), n in sorted(
                buckets.items(), key=lambda x: -x[1])[:15]:
            label = {
                "valid":      "FN good-sig-rejected",
                "invalid":    "FP bad-sig-accepted ",
                "acceptable": "?? acceptable-divrg ",
            }.get(expected, f"?? {expected:18s}")
            print(f"    {n:5d}  {label}  : {prefix}")
        print()

    # Dump a JSON report for CI artefacts.
    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / ("smoke.json" if args.smoke else "full.json")
    with out.open("w") as f:
        json.dump({
            name: {
                "match": st.match,
                "violation": st.violation,
                "skip": st.skip,
                "violations": st.violations,
            }
            for name, st in overall.items()
        }, f, indent=2)
    print(f"  report    : {out}")
    print("=" * 72)

    return 0 if total_violations == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
