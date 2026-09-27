#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
"""What moved between two pkcs11-check runs, by node-id.

Two totals cannot say what changed. On 2026-09-27 the corpus went from 55 202
passed under 0.2.0 to 55 199 under 0.2.1, and nothing in the tree could say
which three tests that was -- no earlier report had been kept in a form that
could be diffed, so a -3 went into the CHANGELOG as unattributed. This exists
so that does not happen at the next reference change.

It also partitions a skip set, which is what docs/ROADMAP.md asks for under
"2105 pkcs11-check tests report nothing". Run the corpus once per build
profile and diff:

    scripts/diff_pkcs11_runs.py approved.jsonl.gz all-mechanisms.jsonl.gz

A test that is skipped in the approved run and passes in the all-mechanisms one
was skipped because the profile does not advertise the mechanism -- correct and
permanent. One that stays skipped in both is either a real gap or nothing to do
with this module, and that is the set worth reading.

Accepts a raw report.jsonl, a .gz of one, or the outcomes.tsv.gz written into
reports/pkcs11-check-0NN by hand. The phase reduction is imported from
pkcs11_check_summary.reduce_jsonl rather than repeated: this file had a
second copy of that rule for about ten minutes, and the copy was wrong.
"""
from __future__ import annotations

import argparse
import gzip
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pkcs11_check_summary import reduce_jsonl        # noqa: E402


def normalise(nid: str) -> str:
    """Drop the part of a node-id that describes the environment, not the test.

    pytest builds a node-id from the file path it collected, so the same test
    is called

        src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py::TestEcdhKeyAgreement

    when the harness is run from a checkout, and

        home/u/.venvs/p11check/lib/python3.13/site-packages/pkcs11_check/testcases/...

    when it is run from an installed venv -- and the second form carries the
    Python minor version, so it changes on an interpreter upgrade alone.

    Without this the first real use of this script compared 0.1.9 against 0.2.1
    and reported that all 96 525 tests had moved: the two runs shared not one
    node-id, because one had been run from src/ and the other from a venv. A
    diff tool that reports everything as changed is not reporting.

    Everything before `pkcs11_check/` is dropped. What remains is the package's
    own path, which is what identifies the test.
    """
    marker = "pkcs11_check/"
    i = nid.find(marker)
    return nid[i:] if i >= 0 else nid


def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def load(path: Path) -> dict[str, str]:
    """{nodeid: outcome}, from a report log or from an outcomes.tsv."""
    with _open(path) as fh:
        first = fh.readline()
        fh.seek(0)
        # outcomes.tsv: "<outcome>\t<nodeid>", comments with #. A report log is
        # JSON, so it starts with {. Sniffing beats a flag the caller forgets.
        if first.lstrip().startswith("{"):
            return {normalise(k): v for k, v in reduce_jsonl(fh).items()}
        per: dict[str, str] = {}
        for line in fh:
            if line.startswith("#") or "\t" not in line:
                continue
            outcome, nid = line.rstrip("\n").split("\t", 1)
            per[normalise(nid)] = outcome
    return per


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("before", type=Path)
    p.add_argument("after", type=Path)
    p.add_argument("--show", metavar="FROM:TO",
                   help="list the node-ids of one transition, e.g. skipped:passed")
    p.add_argument("--limit", type=int, default=40,
                   help="how many node-ids to list with --show (0 = all)")
    args = p.parse_args(argv)

    a, b = load(args.before), load(args.after)
    print(f"  before : {len(a):7d} tests  {args.before}")
    print(f"  after  : {len(b):7d} tests  {args.after}")

    moved: Counter[tuple[str, str]] = Counter()
    for nid in a.keys() | b.keys():
        # A test present in one run only is a transition too, and the one most
        # worth seeing: it means the corpus changed, not the module.
        oa, ob = a.get(nid, "(absent)"), b.get(nid, "(absent)")
        if oa != ob:
            moved[(oa, ob)] += 1

    if not moved:
        print("\n  nothing moved: every node-id has the same outcome in both runs")
        return 0

    print(f"\n  {sum(moved.values())} test(s) moved:\n")
    for (oa, ob), n in moved.most_common():
        print(f"    {n:7d}  {oa} -> {ob}")

    if args.show:
        want = tuple(args.show.split(":", 1))
        if len(want) != 2:
            print("\n  --show wants FROM:TO", file=sys.stderr)
            return 2
        hits = sorted(nid for nid in a.keys() | b.keys()
                      if (a.get(nid, "(absent)"), b.get(nid, "(absent)")) == want)
        print(f"\n  {len(hits)} node-id(s) for {want[0]} -> {want[1]}:")
        shown = hits if args.limit == 0 else hits[:args.limit]
        for nid in shown:
            print(f"    {nid.split('::', 1)[-1]}")
        if len(shown) < len(hits):
            print(f"    ... {len(hits) - len(shown)} more (--limit 0 for all)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
