#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# pkcs11_check_summary.py --- print an outcome tally from a pkcs11-check
# report. Used by scripts/run_pkcs11_check.sh (#125).
#
# Supports two report formats:
#   * pytest --report-log JSONL (newer pkcs11-check : report.jsonl), one
#     JSON object per line with "$report_type"; the per-test outcome is
#     the "call" phase (or a "setup" failure/error when the call never
#     runs).
#   * the older single-object / concatenated JSON report (results.json).
# The runner passes whichever exists; we auto-detect by content.
# ===========================================================================
import json
import sys
from collections import Counter


def tally_jsonl(lines):
    """pytest --report-log : reduce to one outcome per nodeid."""
    per = {}   # nodeid -> outcome (call wins ; else setup error/fail)
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("$report_type") != "TestReport":
            continue
        nid = o.get("nodeid", "")
        when = o.get("when")
        outcome = o.get("outcome")
        if when == "call":
            per[nid] = outcome
        elif when == "setup" and outcome in ("failed", "error"):
            per.setdefault(nid, outcome)
    return Counter(per.values())


def tally_raw(text):
    """Older results.json : walk any dict for outcome/result/status."""
    def walk(node):
        if isinstance(node, dict):
            oc = node.get("outcome") or node.get("result") or node.get("status")
            if isinstance(oc, str):
                yield oc.lower()
            for v in node.values():
                yield from walk(v)
        elif isinstance(node, list):
            for v in node:
                yield from walk(v)
    dec = json.JSONDecoder()
    idx, n = 0, len(text)
    objs = []
    while idx < n:
        while idx < n and text[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        try:
            obj, end = dec.raw_decode(text, idx)
        except json.JSONDecodeError:
            break
        objs.append(obj)
        idx = end
    c = Counter()
    for o in objs:
        c.update(walk(o))
    return c


def main():
    if len(sys.argv) < 2:
        print("usage: pkcs11_check_summary.py REPORT", file=sys.stderr)
        return 2
    try:
        text = open(sys.argv[1], "r", encoding="utf-8", errors="replace").read()
    except OSError as exc:
        print(f"  (report open failed: {exc}; see run.log)")
        return 0
    if '"$report_type"' in text:
        counts = tally_jsonl(text.splitlines())
    else:
        counts = tally_raw(text)
    if not counts:
        print("  (no per-test outcomes found in report; see run.log)")
        return 0
    order = {"crashed": 0, "error": 1, "failed": 2, "passed": 3,
             "xfailed": 4, "skipped": 5}
    for name, num in sorted(counts.items(), key=lambda kv: (order.get(kv[0], 9), -kv[1])):
        print(f"  {name:12s} {num}")
    crashed = counts.get("crashed", 0)
    print()
    print(f"  => crashed={crashed} (target: 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
