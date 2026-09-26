#!/usr/bin/env bash
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# run_pkcs11_check.sh --- Drive Denis Mingulov's pkcs11-check harness
# against libfreehsm.so (#125). Shared by `make pkcs11-check` and
# .github/workflows/pkcs11-check.yml.
#
#  pkcs11-check is an external, vendor-neutral behavioral test client
#  (>100k checks : spec conformance, CKR negatives, security, fuzz,
#  Wycheproof / ACVP vector corpora). Large xfail/fail counts are
#  NORMAL : findings are evidence to investigate, not a verdict (see
#  pkcs11-check docs/interpreting-results.md). This script therefore
#  gates on "the harness ran to completion and produced a report", NOT
#  on a zero-failure count. Regression gating against a baseline is a
#  follow-up (pkcs11-check compare-results).
#
#  Prereqs : pkcs11-tool (opensc), pkcs11-check (pip install
#  pkcs11-check, Python >= 3.12), a built module.
#
#  Usage :
#    scripts/run_pkcs11_check.sh [module.so] [reports_dir]
#
#  Env :
#    FHSM_PKCS11CHECK_MATCH   optional -k/--match filter expression
#    FHSM_ALLOW_UNSIGNED=1    set FHSM_INTEGRITY_ALLOW_UNSIGNED for the
#                             module (only needed if it was NOT signed
#                             with `make integrity`)
# ===========================================================================
# This is a bash script, not a POSIX one: `local`, arrays and `${a[@]}` all
# appear below. Run it directly (the shebang is bash) or as `bash <script>`.
#
# Invoked as `sh <script>` on Debian it is dash that reads it, and dash parses
# command by command -- so it runs happily through token provisioning and dies
# 260 lines later on `MATCH_ARGS=()` with "Syntax error: \"(\" unexpected",
# after the side effects and nowhere near the cause. Observed 2026-09-26.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "run_pkcs11_check.sh needs bash (it uses arrays and \`local\`)." >&2
    echo "Run:  scripts/run_pkcs11_check.sh   or   bash scripts/run_pkcs11_check.sh" >&2
    exit 2
fi

set -u

MODULE="${1:-./libfreehsm.so}"
REPORTS="${2:-./reports/pkcs11-check}"
SO_PIN="00000000"     # same conventions as tests/coverage_matrix.sh
USER_PIN="user0000"

command -v pkcs11-tool  >/dev/null || { echo "FATAL: pkcs11-tool (opensc) missing" >&2; exit 2; }
command -v pkcs11-check >/dev/null || { echo "FATAL: pkcs11-check missing (pip install pkcs11-check)" >&2; exit 2; }
[ -f "$MODULE" ] || { echo "FATAL: module $MODULE missing (run make first)" >&2; exit 2; }

MODULE="$(readlink -f "$MODULE")"

# Is this module instrumented?
#
# `make asan` deliberately leaves an instrumented tree, and pkcs11-tool is an
# ordinary binary that dlopen()s the module. ASan's runtime has to be loaded
# before libc for its interceptors to take, so the combination fails with
#
#   ASan runtime does not come first in initial library list
#   FATAL: C_InitToken failed
#
# which names neither the cause nor the fix unless the reader already knows
# both. That cost a run three times in one week, always the same way: an
# `asan` target followed by a harness invocation with no rebuild in between.
#
# The Makefile's build-mode stamp catches this for `make`, but nothing
# catches it for a consumer of the .so. So the question is asked here.
# Answered with a refusal rather than an automatic LD_PRELOAD: the harness
# measures the module a caller would load, and an instrumented build is a
# different one -- slower, differently laid out, and not what any of the
# recorded numbers were taken against. Running the corpus under ASan is a
# worthwhile thing to do; it is just not this script's job to do it by
# accident.
if command -v nm >/dev/null && nm -D "$MODULE" 2>/dev/null | grep -q '__asan_init'; then
    cat >&2 <<EOF
FATAL: $MODULE is instrumented (AddressSanitizer).

  pkcs11-tool is not, and ASan's runtime must load before libc, so the
  harness would fail with "ASan runtime does not come first" and a bare
  C_InitToken failure.

  Rebuild first:   make && make integrity
  Then re-run this script.

  To run the corpus under ASan on purpose, preload the runtime yourself:
    LD_PRELOAD=\$(gcc -print-file-name=libasan.so) ASAN_OPTIONS=detect_leaks=0 $0 ...
  Those numbers are not comparable with the ordinary ones.
EOF
    exit 2
fi

mkdir -p "$REPORTS"
TOKENS_DIR="$(mktemp -d /tmp/fhsm-p11check.XXXXXX)"
trap 'rm -rf "$TOKENS_DIR"' EXIT

# Which harness produced these numbers?
#
# pkcs11-check does print its own version -- "provenance: pkcs11-check X.Y.Z"
# near the top of its output, so it is in run.log. What it is NOT in is
# report.jsonl, which is a raw pytest --report-log carrying pytest_version and
# nothing else, and report.jsonl is the file that gets attached to an issue or
# read back months later.
#
# On 2026-09-07 that distinction cost an hour: the CI workflows pin
# pkcs11-check==0.1.9, this script took whatever was on PATH, a venv still held
# 0.1.8, and two runs were compared as if only the module had changed. The
# provenance line was sitting in run.log the whole time; nobody had a reason to
# scroll back to it, because nothing downstream ever mentioned a version.
#
# Ask the interpreter named in the harness's own shebang. The ambient python3
# may hold a different installation, or none at all -- which is exactly how
# the wrong version got read that morning.
# The interpreter that owns the harness installation.
#
# Not python3. On this machine `pkcs11-check` resolves to ~/.local/bin with a
# shebang pointing into a venv, while its sibling `pkcs11-check-report` in the
# same directory points at a python that does not have the module and fails
# with ModuleNotFoundError. Same package, two entry points, two interpreters.
# Asking the shebang of the one we know works, and then running everything
# through it, sidesteps the whole question.
harness_python() {
    local bin py
    bin="$(command -v pkcs11-check)" || { echo python3; return; }
    py=""
    if head -c2 "$bin" 2>/dev/null | grep -q '#!'; then
        py="$(head -1 "$bin" | sed 's|^#!||; s| .*||')"
    fi
    [ -n "$py" ] && [ -x "$py" ] || py=python3
    echo "$py"
}

HARNESS_PY="$(harness_python)"

p11c_version() {
    "$HARNESS_PY" - <<'PY' 2>/dev/null
import importlib.metadata as m
try:
    print(m.version("pkcs11-check"))
except Exception:
    print("unknown")
PY
}

HARNESS_VERSION="$(p11c_version || echo unknown)"
[ -n "$HARNESS_VERSION" ] || HARNESS_VERSION="unknown"
# What .github/workflows/{ci,pkcs11-check}.yml pin. Override when testing a
# candidate; the point is that a mismatch is stated, not that it is forbidden.
#
# Moved to 0.2.0 on 2026-09-19, with the workflows, in the same commit. This
# default is the only thing that tells an operator their harness is not the
# one CI uses, so a stale default is worse than none: it states a mismatch
# that is not there and stays quiet about the one that is. Between this
# morning and that commit it did exactly that -- every run printed a warning
# about 0.1.9 while 0.1.9 was the version nothing used any more.
# What the workflows actually pin. Not overridable, because this is a fact
# about the repository and not a preference of the run.
WORKFLOW_PIN="0.2.0"

# What this run compares against. FHSM_PKCS11CHECK_EXPECT exists so a run can
# be made against an unpinned harness without the warning drowning the output.
#
# It used to be the same variable as the line below printed, so
# `FHSM_PKCS11CHECK_EXPECT=0.2.1` made the provenance line read
# "(workflows pin 0.2.1)" while the workflows pinned 0.2.0. The override
# silenced the warning and then falsified the one line written precisely so a
# later reader could tell whether two runs are comparable. Observed
# 2026-09-26, by the person who had set the variable one command earlier.
EXPECTED_VERSION="${FHSM_PKCS11CHECK_EXPECT:-$WORKFLOW_PIN}"

# Everything a later reader needs to know whether two runs are comparable.
#
# The harness version is the one that bit us, but it is not the only variable.
# docs/PKCS11_CHECK_FINDINGS.md carries two sections dated the same day, one
# saying the run used OpenSSL 3.5.6 and the other 3.5.7; nothing recorded at
# the time can settle which. The module digest is here for the same reason --
# "v2.0.3" names a version, not a build.
OPENSSL_VERSION="$(openssl version 2>/dev/null || echo unknown)"
MODULE_SHA="$(sha256sum "$MODULE" 2>/dev/null | awk '{print $1}')"
[ -n "$MODULE_SHA" ] || MODULE_SHA="unknown"

# Is this module built from the tree as it stands?
#
# On 2026-09-11 a twenty-minute run measured a binary built before the change
# it was meant to test. The report was exact and the conclusion was drawn
# from it: the counts had not moved, so the fix had not worked. The fix was
# fine; the module was stale. Nothing in the report could have said so --
# module-sha256 was recorded and compared to nothing.
#
# The cheap test is mtime: if any source, header or the generator is newer
# than the module, the module cannot be the module those sources produce.
# It costs no build, and it catches precisely the failure that happened.
# Source files are compared, not the sha256 of a rebuild: a rebuild inside a
# measurement script would change what is being measured.
#
# A run against a module from somewhere else -- a released artefact, another
# machine -- is legitimate and common, so a module outside this tree is
# reported and not refused. Only a local module older than the local sources
# is refused, because that one is always a mistake.
STALE=""
if [ -z "${FHSM_ALLOW_STALE_MODULE:-}" ]; then
    NEWER="$(find src include scripts Makefile -newer "$MODULE" \
                  \( -name '*.c' -o -name '*.h' -o -name '*.py' -o -name 'Makefile' \) \
                  -print 2>/dev/null | head -5)"
    if [ -n "$NEWER" ]; then
        STALE="yes"
        echo "FATAL: $MODULE is older than the sources in this tree." >&2
        echo "" >&2
        echo "$NEWER" | sed 's/^/  newer: /' >&2
        echo "" >&2
        echo "  Measuring it would describe a binary that no longer exists." >&2
        echo "  Run: make && make integrity" >&2
        echo "" >&2
        echo "  If the module is deliberately from elsewhere -- a released" >&2
        echo "  artefact, another machine -- set FHSM_ALLOW_STALE_MODULE=1," >&2
        echo "  and say so in whatever the run is written up as." >&2
        exit 2
    fi
fi

{
    echo "pkcs11-check $HARNESS_VERSION"
    echo "openssl      $OPENSSL_VERSION"
    echo "module       $MODULE"
    echo "module-sha256 $MODULE_SHA"
    echo "module-vs-tree $([ -n "$STALE" ] && echo "STALE (override)" || echo "up to date")"
    echo "date         $(date -Is)"
} > "$REPORTS/provenance.txt"

echo "== harness =="
echo "  pkcs11-check : $HARNESS_VERSION   (workflows pin $WORKFLOW_PIN)"
if [ "$EXPECTED_VERSION" != "$WORKFLOW_PIN" ]; then
    echo "  NOTE : FHSM_PKCS11CHECK_EXPECT=$EXPECTED_VERSION overrides the"
    echo "         comparison. The workflow pin above is unchanged."
fi
echo "  openssl      : $OPENSSL_VERSION"
echo "  module       : $MODULE"
echo "  sha256       : $MODULE_SHA"
if [ "$HARNESS_VERSION" != "$EXPECTED_VERSION" ]; then
    echo "  NOTE : this is not the pinned version. The run is still valid --"
    echo "         but counts from it are not comparable to a pinned run, and"
    echo "         any finding written up from it must say which version."
fi

# Purge pkcs11-check's isolation state + per-file report cache. These
# hidden files (gitignored, so `make clean` never touches them) carry
# the crash/outcome records of the PREVIOUS run ; the mixed-isolation
# aggregator would otherwise re-report stale crashes even after the
# underlying defect is fixed and the module rebuilt. Always start clean.
rm -f  .pkcs11-check-isolation-*.json 2>/dev/null || true
rm -rf .*.report-records ..*.report-records "$REPORTS"/*.report-records 2>/dev/null || true

# Environment for the module.
#
# These two settings are not independent, and until 2026-09-02 this block
# treated them as if they were. FHSM_INTEGRITY_ALLOW_UNSIGNED is what makes
# src/fhsm_crypto.c SKIP OSSL_PROVIDER_load(NULL, "fips"). Without it -- i.e.
# against a signed module -- the provider is loaded, and OPENSSL_CONF=/dev/null
# means there is no configuration to load it from. C_Initialize then fails,
# printing nothing: that path has no message, unlike the audit-key and
# tokens-directory failures beside it.
#
# The comment that stood here recommended running this harness against a
# signed module, in the same breath as forcing the one setting that makes a
# signed module impossible to initialise. The recommended configuration was
# the one configuration that could not work.
#
# So: /dev/null only on the unsigned path, where the provider is never loaded
# and the isolation is free. On the signed path the ambient configuration is
# left alone, because the module needs it.
export FHSM_TOKENS_DIR="$TOKENS_DIR"
if [ "${FHSM_ALLOW_UNSIGNED:-0}" = "1" ]; then
    export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
    export OPENSSL_CONF="${OPENSSL_CONF:-/dev/null}"
    echo "NOTE: unsigned module --- FHSM_INTEGRITY_ALLOW_UNSIGNED=1, OPENSSL_CONF=${OPENSSL_CONF}"
else
    echo "NOTE: signed module --- FIPS provider will be loaded, OPENSSL_CONF=${OPENSSL_CONF:-<system default>}"
fi

echo "== Initializing token (pkcs11-tool) =="
pkcs11-tool --module "$MODULE" --slot 0 --init-token \
            --label "p11check" --so-pin "$SO_PIN" \
    || { echo "FATAL: C_InitToken failed" >&2; exit 2; }
pkcs11-tool --module "$MODULE" --slot 0 --login --so-pin "$SO_PIN" \
            --init-pin --new-pin "$USER_PIN" \
    || { echo "FATAL: C_InitPIN failed" >&2; exit 2; }

echo "== Running pkcs11-check =="
MATCH_ARGS=()
[ -n "${FHSM_PKCS11CHECK_MATCH:-}" ] && MATCH_ARGS=(--match "$FHSM_PKCS11CHECK_MATCH")

pkcs11-check test \
    --module "$MODULE" \
    --slot 0 \
    --pin "$USER_PIN" \
    "${MATCH_ARGS[@]}" \
    --output json  --output-file "$REPORTS/results.json"  \
    2>&1 | tee "$REPORTS/run.log"
RC_JSON=$?

# Second pass not needed for JUnit : derive it in-run next time the
# tool supports multi-output ; for now re-emit is too costly, the JSON
# + log are the canonical artifacts.

# Select the report to summarise. Newer pkcs11-check versions write a
# pytest --report-log at report.jsonl (the accurate per-test report) and
# ALSO an aggregate results.json whose counts are not per-test ; older
# versions write only results.json. Prefer report.jsonl when present, and
# require it to be at least as new as results.json so we never read a
# stale prior run.
REPORT_FILE=""
if [ -s "$REPORTS/report.jsonl" ]; then
    REPORT_FILE="$REPORTS/report.jsonl"
elif [ -s "$REPORTS/results.json" ]; then
    REPORT_FILE="$REPORTS/results.json"
fi
if [ -z "$REPORT_FILE" ]; then
    echo "FATAL: pkcs11-check did not produce a report (exit=$RC_JSON) --- harness crash?" >&2
    exit 1
fi

echo "== Summary =="
# Standalone parser (no shell heredoc : avoids CRLF / delimiter fragility).
# Handles both the pytest --report-log JSONL and the legacy results.json.
SUMMARY_PY="$(dirname "$0")/pkcs11_check_summary.py"
if [ -f "$SUMMARY_PY" ]; then
    python3 "$SUMMARY_PY" "$REPORT_FILE" || true
else
    echo "  (summary script $SUMMARY_PY missing; see run.log)"
fi

# The conformance report --- the richest view the harness produces, and one
# this project had never generated.
#
# petrn ran it in issue #10 and reported 35 failures and 3 crashes over 111,736
# vectors, against the 2 failures and 0 crashes our own summary was printing.
# The counts are not in the same unit, and the vector sets are not the same
# size, but the point stands: the tool knows how to say more about this module
# than we were asking it. It also classifies severity, lists mechanisms that
# are advertised and then reject the canonical operation, and separates honest
# deviations from spec violations -- none of which our summary script does.
#
# Run through HARNESS_PY rather than the `pkcs11-check-report` on PATH: see the
# note on harness_python above for why that one may be broken.
echo
echo "== Conformance report =="
if "$HARNESS_PY" -c 'import pkcs11_check.report' 2>/dev/null; then
    PROVIDER="${FHSM_REPORT_PROVIDER:-freehsm}"
    if "$HARNESS_PY" -m pkcs11_check.report \
            --report-log   "$REPORTS/report.jsonl" \
            --results-json "$REPORTS/results.json" \
            --provider     "$PROVIDER" \
            --out          "$REPORTS" >/dev/null 2>&1; then
        echo "  $REPORTS/$PROVIDER.md"
        # The headline line, so the run says it without opening the file.
        sed -n '/^passed /p' "$REPORTS/$PROVIDER.md" 2>/dev/null | sed 's/^/  /'
    else
        echo "  (report generation failed --- the counts above stand on their own)"
    fi
else
    echo "  (pkcs11_check.report not importable --- skipped)"
fi

echo
# Restate the harness version here, next to the counts. The banner at the top
# scrolls away behind several hundred lines of test output, and the counts are
# what gets pasted into an issue or a findings document -- so the version has
# to travel with them, not with the header nobody copies.
echo "Harness: pkcs11-check $HARNESS_VERSION   module: $MODULE"
echo "Report: $REPORT_FILE (findings are evidence, not a gate)"
exit 0
