#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# violations_md.py --- turn a Wycheproof report into the body of a failure
# notice.
#
# The nightly workflow opens an issue when the suite goes red, and the log is
# the wrong thing to paste into it: twenty-six lines of counters, then a
# truncated "violation breakdown" that names one category and stops. The
# report says which vector, in which file, with the comment the corpus
# carries. That is what a reader needs at 8am.
#
# Lives here rather than inside the workflow because a heredoc nested in a
# YAML block scalar is one indentation change away from being invalid, and
# because a script in the tree can be run against a report by hand:
#
#     python3 tests/wycheproof/violations_md.py tests/wycheproof/results/full.json
#
# Prints nothing and exits 0 when there are no violations, so the caller can
# use it unconditionally.
# ===========================================================================
from __future__ import annotations

import json
import sys
from pathlib import Path

PER_ADAPTER = 10        # enough to see the shape; the artefact has the rest


def render(report: dict) -> str:
    out: list[str] = []
    for name, res in sorted(report.items()):
        if not isinstance(res, dict):
            continue
        n = res.get("violation", 0)
        if not n:
            continue
        items = res.get("violations", [])
        out.append(f"### {name} --- {n} violation(s)\n")
        for item in items[:PER_ADAPTER]:
            f = item.get("file", "?")
            t = item.get("tcId", "?")
            c = item.get("comment", "").strip()
            e = item.get("expected", "")
            out.append(f"- `{f}` tcId {t} (expected {e}) --- {c}")
        if len(items) > PER_ADAPTER:
            out.append(f"- ... and {len(items) - PER_ADAPTER} more")
        out.append("")
    return "\n".join(out)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: violations_md.py REPORT.json", file=sys.stderr)
        return 2
    p = Path(sys.argv[1])
    if not p.exists():
        # Not an error: the suite can fail before it writes a report, and the
        # caller wants a body either way. Saying so is more useful than an
        # empty section.
        print("No report was produced --- the run failed before or during the"
              " suite, so the log is the only evidence.")
        return 0
    try:
        report = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        print(f"The report at `{p}` does not parse: {exc}")
        return 0
    body = render(report)
    if body:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
