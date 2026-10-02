#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
"""Every test binary `make tests` builds is one it runs, and the reverse.

The Makefile lists the test binaries once, in TEST_BINS, and runs each of them
on its own line in the `tests` recipe, because each needs its own environment.
That is two places, and they drifted: test_conf had a build rule and was in
neither list for a while, and until 2026-10-02 test_session_cap and
test_fork_child were built by `make tests` and run by nothing. A test that is
built and never run passes every time.

This reads both and fails, naming the binary, when they disagree. Run by CI's
lint job.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

MAKEFILE = Path(__file__).resolve().parent.parent / "Makefile"


def test_bins(text: str) -> list[str]:
    """The TEST_BINS assignment, continuation lines joined."""
    m = re.search(r"^TEST_BINS\s*=\s*((?:.*\\\n)*.*)$", text, re.M)
    if not m:
        sys.exit("check_test_lists: no TEST_BINS in the Makefile")
    return m.group(1).replace("\\\n", " ").split()


def recipe_runs(text: str) -> set[str]:
    """Binaries the `tests` recipe executes as ./tests/NAME."""
    lines = text.split("\n")
    start = next((i for i, ln in enumerate(lines) if ln.startswith("tests:")), None)
    if start is None:
        sys.exit("check_test_lists: no `tests:` rule in the Makefile")
    runs: set[str] = set()
    for ln in lines[start + 1:]:
        if ln.startswith("\t") or ln.startswith("#") or not ln.strip():
            runs.update(re.findall(r"\./(tests/[A-Za-z0-9_]+)\b(?!\.)", ln))
            continue
        break
    return runs


def main() -> int:
    text = MAKEFILE.read_text(encoding="utf-8").replace("\r\n", "\n")
    built = test_bins(text)
    run = recipe_runs(text)
    never_run = [b for b in built if b not in run]
    not_built = sorted(run - set(built))
    for b in never_run:
        print(f"check_test_lists: {b} is in TEST_BINS and the tests recipe never runs it")
    for b in not_built:
        print(f"check_test_lists: the tests recipe runs {b}, which is not in TEST_BINS")
    if never_run or not_built:
        return 1
    print(f"check_test_lists: {len(built)} test binaries, each built and run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
