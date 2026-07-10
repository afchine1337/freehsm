#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# pkcs11_check_summary.py --- print an outcome tally from a pkcs11-check
# JSON report. Used by scripts/run_pkcs11_check.sh (#125).
#
# The report is a pretty-printed JSON object (and pkcs11-check may append
# extra data after it), so a plain json.load() fails with "Extra data".
# We decode the first JSON value with raw_decode() and walk it for any
# "outcome" field, tallying crashed / error / failed / passed / xfailed.
# Kept as a standalone script (not a shell heredoc) so CRLF / whitespace
# in the runner cannot break the here-document delimiter.
# ===========================================================================
import json
import sys
from collections import Counter


def walk(node):
    if isinstance(node, dict):
        outcome = node.get("outcome") or node.get("result") or node.get("status")
        if isinstance(outcome, str):
            yield outcome.lower()
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def load_first_json(path):
    raw = open(path, "r", encoding="utf-8", errors="replace").read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Extra data after the first object, or JSONL: decode the first
        # value, then also fold in any subsequent whitespace-separated
        # JSON values (JSONL rows).
        dec = json.JSONDecoder()
        objs = []
        idx = 0
        n = len(raw)
        while idx < n:
            while idx < n and raw[idx] in " \t\r\n":
                idx += 1
            if idx >= n:
                break
            try:
                obj, end = dec.raw_decode(raw, idx)
            except json.JSONDecodeError:
                break
            objs.append(obj)
            idx = end
        return objs if len(objs) != 1 else objs[0]


def main():
    if len(sys.argv) < 2:
        print("usage: pkcs11_check_summary.py REPORT.json", file=sys.stderr)
        return 2
    try:
        data = load_first_json(sys.argv[1])
    except Exception as exc:  # noqa: BLE001 - summary must never hard-fail
        print(f"  (report parse failed: {exc}; see run.log)")
        return 0
    counts = Counter(walk(data))
    if not counts:
        print("  (no per-test outcomes found in report; see run.log)")
        return 0
    order = {"crashed": 0, "error": 1, "failed": 2, "passed": 3, "xfailed": 4}
    for name, num in sorted(counts.items(), key=lambda kv: (order.get(kv[0], 9), -kv[1])):
        print(f"  {name:12s} {num}")
    crashed = counts.get("crashed", 0)
    print()
    print(f"  => crashed={crashed} (target: 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
