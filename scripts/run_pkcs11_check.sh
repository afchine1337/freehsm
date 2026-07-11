#!/usr/bin/env bash
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# run_pkcs11_check.sh --- Drive Denis Mingulov's pkcs11-check harness
# against libfreehsm-fips.so (#125). Shared by `make pkcs11-check` and
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

MODULE="${1:-./libfreehsm-fips.so}"
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

# Purge pkcs11-check's isolation state + per-file report cache. These
# hidden files (gitignored, so `make clean` never touches them) carry
# the crash/outcome records of the PREVIOUS run ; the mixed-isolation
# aggregator would otherwise re-report stale crashes even after the
# underlying defect is fixed and the module rebuilt. Always start clean.
rm -f  .pkcs11-check-isolation-*.json 2>/dev/null || true
rm -rf .*.report-records ..*.report-records "$REPORTS"/*.report-records 2>/dev/null || true

# Environment for the module. OPENSSL_CONF=/dev/null keeps EVP fetches
# on the default provider in legacy/dev mode (same rationale as
# coverage_matrix.sh). If the module was digest-signed (make
# integrity), no integrity escape hatch is needed --- that is the
# recommended way to run this harness.
export FHSM_TOKENS_DIR="$TOKENS_DIR"
export OPENSSL_CONF="${OPENSSL_CONF:-/dev/null}"
if [ "${FHSM_ALLOW_UNSIGNED:-0}" = "1" ]; then
    export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
    echo "NOTE: running with FHSM_INTEGRITY_ALLOW_UNSIGNED=1 (unsigned module)"
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

# Select the freshest report the harness produced. Newer pkcs11-check
# versions write a pytest --report-log at report.jsonl and no longer
# update results.json ; older ones write results.json. Prefer whichever
# is newest so the summary never reflects a stale prior run.
REPORT_FILE=""
newest=0
for cand in "$REPORTS/report.jsonl" "$REPORTS/results.json"; do
    if [ -s "$cand" ]; then
        m=$(stat -c %Y "$cand" 2>/dev/null || echo 0)
        if [ "$m" -ge "$newest" ]; then newest=$m; REPORT_FILE="$cand"; fi
    fi
done
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

echo "Report: $REPORT_FILE (findings are evidence, not a gate)"
exit 0
