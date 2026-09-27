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
#
# On memory: report.jsonl was 356 MB after the full corpus run of 2026-09-19
# (one JSON object per phase per test). This script used to read it with
# open(...).read(), then test the whole string for a marker, then splitlines()
# it into a list of millions of strings, to produce a tally of a few integers.
# Measured on that file: peak RSS 767 MiB before, 39 MiB after -- 2.2x the
# file, against a working set that does not depend on its size. The reduction
# is per-line and bounded by the number of test ids, so nothing needs the file
# resident. Streaming is not an optimisation here; it is the shape the
# computation already had.
import itertools
import json
import sys
from collections import Counter

# How many leading non-empty lines to inspect when deciding which format this
# is. pytest --report-log opens with a SessionStart object carrying
# "$report_type", so one would do; a handful costs nothing and does not
# depend on that staying true. The old results.json is a single JSON document,
# pretty-printed or not, and never carries the marker.
_SNIFF_LINES = 8


def reduce_jsonl(lines):
    """pytest --report-log : reduce to one outcome per nodeid.

    Returns the {nodeid: outcome} map. tally_jsonl() counts it; diff_pkcs11_runs.py
    compares two of them. Exposed rather than copied: an ad-hoc re-implementation
    of this reduction on 2026-09-27 counted setup and teardown as passes and
    reported "18 KMAC tests passed" for a mechanism the module does not have.
    One phase rule, one place.

    An xfail is separated from a skip. pytest reports both with
    `outcome: "skipped"` and distinguishes them only by a `wasxfail` field, so
    tallying the outcome alone folds them together -- and they are not the same
    thing. A skip means the case did not run; an xfail means it ran, deviated,
    and the harness classified the deviation as expected. The `order` dict below
    has listed "xfailed" since this script was written, for a key nothing
    produced.

    On the 0.2.1 corpus that merge reported `skipped 37313` where the truth is
    23 208 skipped and 14 200 xfail: a 61/39 split presented as one number. The
    harness's own report prints them apart, so the two disagreed, and the
    disagreement was in this file.

    Against `results.json` for the same run, this now agrees exactly on passed,
    failed and xfailed, and is 8 short on skipped. Those 8 are not lost here:
    `report.jsonl` carries 92 601 distinct node-ids where `results.json` counts
    92 609 tests, so eight tests have no record in the log at all. Recorded so
    the next reader does not look for them in this function. Reporting a run
    whose per-test log is missing eight tests is a question for upstream, and
    a small instance of the thing this project keeps meeting: the tests that
    say nothing are the ones worth finding.
    """
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
            if outcome == "skipped" and o.get("wasxfail") is not None:
                outcome = "xfailed"
            per[nid] = outcome
        elif when == "setup" and outcome in ("failed", "error", "skipped"):
            # "skipped" belongs here too. A test skipped at setup never reaches
            # a call phase, so keeping only failed/error dropped it entirely:
            # 87 tests on the 0.2.1 corpus, and with the 8 the report.jsonl
            # itself does not carry, 95 of 92 609 went uncounted. The tally
            # summed to 92 514 while the harness's own results.json summed to
            # 92 609, and neither number said the other was missing anything.
            per.setdefault(nid, outcome)
    return per


def tally_jsonl(lines):
    """The counts, for the summary. The map lives in reduce_jsonl()."""
    return Counter(reduce_jsonl(lines).values())


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


def tally_report(path):
    """Decide the format from the first few lines, then tally without
    holding the report in memory when it is JSONL."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        head = []
        for line in fh:
            if line.strip():
                head.append(line)
                if len(head) >= _SNIFF_LINES:
                    break
        if not head:
            return Counter()
        if any('"$report_type"' in ln for ln in head):
            # The sniffed lines have been consumed from the iterator, so put
            # them back in front of it rather than seeking: they carry
            # TestReport objects once the run is short enough to fit inside
            # _SNIFF_LINES, and dropping them would silently under-count.
            return tally_jsonl(itertools.chain(head, fh))

    # The older results.json is a single JSON document, which raw_decode wants
    # as one string. It is the small format -- a few hundred kilobytes -- and
    # nothing streams a document whose structure is only known at the end.
    # Reopened rather than rewound: mixing iteration and seek on a text file
    # is a rule with exceptions, and this does not need to know them.
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return tally_raw(fh.read())


def main():
    if len(sys.argv) < 2:
        print("usage: pkcs11_check_summary.py REPORT", file=sys.stderr)
        return 2
    try:
        counts = tally_report(sys.argv[1])
    except OSError as exc:
        print(f"  (report open failed: {exc}; see run.log)")
        return 0
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
