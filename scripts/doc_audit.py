#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""
Check the documentation against the repository it describes.

Written after five stale claims were found by accident in one afternoon --
REST_API_DESIGN.md and DOC_INDEX.md still saying the service did not exist,
ROADMAP.md and P11_KIT_REMOTING.md still saying the p11-kit patch was not
submitted, RELEASE_v2.0.0-beta.md saying OCSP does not ship. Five found by
chance means more were there, and a check that runs is worth more than an
afternoon of reading that will not be repeated.

Three checks, in order of how mechanical they are:

  flags   every --option cited next to one of our tools must appear in that
          tool's own --help. This is the check that would have caught
          `fhsm-token --gen-pin`, which was written into a deployment
          procedure and does not exist.

  paths   every repository path cited in `backticks` must exist. External
          projects and history are excluded, because a CHANGELOG naming a file
          deleted two releases ago is correct.

  status  every "not built", "not implemented", "not submitted" and their
          relatives, listed for a human to confirm. This one cannot be decided
          by machine -- most such lines are true and load-bearing -- so it
          reports rather than fails.

Exit status is 1 if `flags` or `paths` found anything. `status` never fails the
run; it is a reading list.

Usage:
    scripts/doc_audit.py [--build DIR]

--build names a directory holding built tools (default: the repository root),
because the flag check has to run them.
"""

import argparse
import os
import re
import subprocess
import sys

TOOLS = ["fhsm-token", "fhsm-csr", "fhsm-ca", "fhsm-sign",
         "fhsm-service", "freehsm-audit"]

# History describes the past. A file it names may be long gone and the text
# still correct.
HISTORICAL = ("CHANGELOG.md", "RELEASE_v1")

# Cited in issue drafts and gap analyses; they belong to other projects.
FOREIGN = re.compile(
    r"^(raw/|_probes/|src/pkcs11_check/|src/algParams|src/testvectors|"
    r"doc/files\.md$|rpc-message\.c$|output_length\.py$|/etc/)")

STATUS = re.compile(
    r"not (yet )?(built|implemented|written|submitted|shipped|done)"
    r"|does not (ship|exist)|is planned|to be written|TODO|FIXME",
    re.I)

# A line that explains a deliberate absence is not a stale claim.
DELIBERATE = re.compile(
    r"~~|deliberately|on purpose|by design|chose|decided|rather than|"
    r"because|never be|will not", re.I)


def repo_root():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(here)


def doc_files(root):
    out = []
    for d in (os.path.join(root, "docs"), root):
        for f in sorted(os.listdir(d)):
            if f.endswith(".md") and not f.startswith(HISTORICAL):
                out.append(os.path.join(d, f))
    return out


def real_flags(build, tool):
    path = os.path.join(build, "tools", tool)
    if not os.path.exists(path):
        path = os.path.join(build, "service", tool)
    if not os.path.exists(path):
        return None
    env = dict(os.environ, FHSM_INTEGRITY_ALLOW_UNSIGNED="1")
    try:
        p = subprocess.run([path, "--help"], capture_output=True, timeout=30,
                           env=env, text=True)
    except Exception:
        return None
    return set(re.findall(r"--[a-z0-9][a-z0-9-]*", p.stdout + p.stderr))


def check_flags(root, build):
    real = {t: real_flags(build, t) for t in TOOLS}
    missing_tools = [t for t, v in real.items() if v is None]
    bad = []
    flag = re.compile(r"--[a-z0-9][a-z0-9-]*")
    for f in doc_files(root):
        cur = None
        for n, line in enumerate(open(f, encoding="utf-8", errors="replace"), 1):
            hits = [t for t in TOOLS if t in line]
            if hits:
                # The last one named on the line owns the flags after it. A
                # line naming two tools is why this is a heuristic and why the
                # report gives file:line rather than a verdict.
                cur = max(hits, key=lambda t: line.rfind(t))
            elif not line.lstrip().startswith("--") and "\\" not in line:
                cur = None
            if cur and real.get(cur):
                for fl in flag.findall(line):
                    if fl not in real[cur]:
                        bad.append((cur, fl, os.path.basename(f), n))
    return bad, missing_tools


def check_paths(root):
    have = set()
    for r, dirs, fs in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", ".obj")]
        for name in fs + dirs:
            rel = os.path.relpath(os.path.join(r, name), root)
            have.add(rel)
            have.add(name)
    pat = re.compile(
        r"`([A-Za-z0-9_./-]+\.(?:c|h|md|sh|py|service|yml|yaml|cnf|patch)|"
        r"(?:src|docs|tests|tools|include|kat|scripts|service|systemd|probes|"
        r"contrib|fuzz)/[A-Za-z0-9_./-]*)`")
    # A line that says the file is missing is not a stale claim about it. This
    # matters more than it sounds: the honest fix for a broken citation is often
    # to say "this does not exist", and a checker that then flags the honesty
    # pushes people back towards the lie.
    admits = re.compile(r"does not exist|is not written|unwritten|not met|"
                        r"to be written|will be created|does not ship", re.I)
    bad = []
    for f in doc_files(root):
        for n, line in enumerate(open(f, encoding="utf-8", errors="replace"), 1):
            if admits.search(line):
                continue
            for m in pat.findall(line):
                p = (m[0] if isinstance(m, tuple) else m).rstrip("/")
                if not p or " " in p or FOREIGN.match(p):
                    continue
                if p in have or os.path.basename(p) in have:
                    continue
                # A build product is not a missing file: `tests/bench_fsync_floor`
                # is absent from a clean tree and present after make, and its
                # source is right there. Without this the report is mostly
                # binaries, and a checker that cries wolf gets ignored -- which
                # is how this kind of tool fails.
                if any((p + ext) in have or os.path.basename(p + ext) in have
                       for ext in (".c", ".sh", ".py")):
                    continue
                if any(x.endswith("/" + p) for x in have):
                    continue
                bad.append((p, os.path.basename(f), n))
    return bad


def check_status(root):
    out = []
    for f in doc_files(root):
        for n, line in enumerate(open(f, encoding="utf-8", errors="replace"), 1):
            if STATUS.search(line) and not DELIBERATE.search(line):
                out.append((os.path.basename(f), n, line.strip()[:96]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default=None)
    ap.add_argument("--status", action="store_true",
                    help="also print the status-claim reading list")
    a = ap.parse_args()
    root = repo_root()
    build = a.build or root
    rc = 0

    bad, missing = check_flags(root, build)
    print("== options documented but absent from --help ==")
    if missing:
        print("   (not built, not checked: %s)" % ", ".join(missing))
    for t, fl, f, n in bad:
        print("   %-15s %-20s %s:%d" % (t, fl, f, n))
    if bad:
        rc = 1
    else:
        print("   none")

    bad = check_paths(root)
    print("\n== repository paths cited that do not exist ==")
    for p, f, n in bad:
        print("   %-44s %s:%d" % (p, f, n))
    if bad:
        rc = 1
    else:
        print("   none")

    if a.status:
        rows = check_status(root)
        print("\n== status claims to confirm by hand (%d) ==" % len(rows))
        for f, n, line in rows:
            print("   %s:%d  %s" % (f, n, line))

    return rc


if __name__ == "__main__":
    sys.exit(main())
