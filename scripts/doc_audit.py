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
    r"doc/files\.md$|rpc-message\.c$|output_length\.py$|"
    # Absolute paths belong to the host, not to us.
    r"/|"
    # A bare `.fr.md` is the tail of `[X](X.fr.md)` caught by the pattern, not
    # a citation. Guarding the extractor is cheaper than reading the noise.
    r"\.fr\.md$|"
    # pkcs11-check's own tree, quoted in issue and PR drafts aimed at it.
    r"docs/providers\.md$|tests/test_wrap_context_cache\.py$)")

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

    # Files that belong to the host, not to this repository. The bare-filename
    # branch above matches any `something.cnf`, and OpenSSL's two configuration
    # files are named constantly in the FIPS documents -- correctly, and about
    # /usr/lib/ssl rather than about anything here. Reporting them as missing
    # repository paths trains the reader to skim the list, which is how the
    # real entries in it stop being read.
    SYSTEM_FILES = {
        "openssl.cnf",        # the host OpenSSL configuration
        "fipsmodule.cnf",     # written by `openssl fipsinstall`, never shipped
    }
    # A line that says the file is missing is not a stale claim about it. This
    # matters more than it sounds: the honest fix for a broken citation is often
    # to say "this does not exist", and a checker that then flags the honesty
    # pushes people back towards the lie.
    admits = re.compile(
        # English
        r"does not exist|is not written|unwritten|not met|to be written|"
        r"will be created|does not ship|never (been )?written|was named here|"
        r"not built|has never existed|withdrawn|"
        # Near-misses found 2026-09-02. Four of the six "unkept promises" in
        # the report were already honest and the filter simply did not match
        # the words used: "has not been written", "is still to be created",
        # "(to write)", "created at the first external contribution". The
        # checker was under-matching, not the documents over-claiming -- and
        # a report padded with entries that are already correct is a report
        # nobody finishes reading.
        r"has not been written|(still )?to be created|\(to write\)|"
        r"created at the first|not yet written|not yet created|"
        r"was planned|is planned|remains? to be|no such file|"
        # Français -- the docs are bilingual, and a filter that only reads
        # English flags the honest French half.
        r"n'existe pas|n'a jamais (été écrit|existé)|jamais écrit|"
        r"a été nommé ici|non construit|à la main|procédure manuelle",
        re.I)
    # An explicit, file-scoped waiver:
    #
    #     <!-- doc-audit: allow tests/test_smoke.tampered -- historical record -->
    #
    # The prose filter below guesses at English, and guessing loses: four
    # honest admissions were flagged on 2026-09-02 because they said "has not
    # been written" and "(to write)" rather than the exact words in the list,
    # and widening the list to catch them is a race nobody wins. A waiver says
    # what it means, is greppable, and carries its reason on the same line --
    # which is the point, because a silent exemption is worse than a noisy
    # false positive. The prose filter stays for the ordinary case.
    waiver = re.compile(r"doc-audit:\s*allow\s+(\S+)")

    bad = []
    for f in doc_files(root):
        lines = open(f, encoding="utf-8", errors="replace").readlines()
        allowed = set(waiver.findall("".join(lines)))
        for n, line in enumerate(lines, 1):
            # Look at the neighbours, not just the line.
            #
            # The admission and the path it excuses are one sentence, and a
            # sentence wraps. Reading a single line flagged four entries whose
            # very next line said "and that file was never written" -- the
            # checker demanding honesty in a shape it could see rather than
            # honesty. A window of one line either side is enough for prose
            # and still narrow enough that an admission about a DIFFERENT file
            # two paragraphs away cannot silence this one.
            window = "".join(lines[max(0, n - 2):n + 1])
            if admits.search(window):
                continue
            for m in pat.findall(line):
                p = (m[0] if isinstance(m, tuple) else m).rstrip("/")
                if not p or " " in p or FOREIGN.match(p):
                    continue
                if p in have or os.path.basename(p) in have:
                    continue
                if os.path.basename(p) in SYSTEM_FILES:
                    continue
                if p in allowed:
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
