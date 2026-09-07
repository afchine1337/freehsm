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
set -u

MODULE="${1:-./libfreehsm.so}"
REPORTS="${2:-./reports/pkcs11-check}"
SO_PIN="00000000"     # same conventions as tests/coverage_matrix.sh
USER_PIN="user0000"

command -v pkcs11-tool  >/dev/null || { echo "FATAL: pkcs11-tool (opensc) missing" >&2; exit 2; }
command -v pkcs11-check >/dev/null || { echo "FATAL: pkcs11-check missing (pip install pkcs11-check)" >&2; exit 2; }
[ -f "$MODULE" ] || { echo "FATAL: module $MODULE missing (run make first)" >&2; exit 2; }

MODULE="$(readlink -f "$MODULE")"
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
p11c_version() {
    local bin py
    bin="$(command -v pkcs11-check)" || return 1
    py=""
    if head -c2 "$bin" 2>/dev/null | grep -q '#!'; then
        py="$(head -1 "$bin" | sed 's|^#!||; s| .*||')"
    fi
    [ -n "$py" ] && [ -x "$py" ] || py=python3
    "$py" - <<'PY' 2>/dev/null
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
EXPECTED_VERSION="${FHSM_PKCS11CHECK_EXPECT:-0.1.9}"

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

{
    echo "pkcs11-check $HARNESS_VERSION"
    echo "openssl      $OPENSSL_VERSION"
    echo "module       $MODULE"
    echo "module-sha256 $MODULE_SHA"
    echo "date         $(date -Is)"
} > "$REPORTS/provenance.txt"

echo "== harness =="
echo "  pkcs11-check : $HARNESS_VERSION   (workflows pin $EXPECTED_VERSION)"
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

# Restate the harness version here, next to the counts. The banner at the top
# scrolls away behind several hundred lines of test output, and the counts are
# what gets pasted into an issue or a findings document -- so the version has
# to travel with them, not with the header nobody copies.
echo "Harness: pkcs11-check $HARNESS_VERSION   module: $MODULE"
echo "Report: $REPORT_FILE (findings are evidence, not a gate)"
exit 0
