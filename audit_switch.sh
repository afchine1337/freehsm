#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Simorgh Labs
#
# Switching the audit log off is enforced in C_Initialize, so it can only be
# tested by starting the module. This drives the real thing through
# fhsm-token, which is what an operator would type.
#
#   audit_switch.sh mandatory   expects FHSM_AUDIT=off to be REFUSED
#   audit_switch.sh optional    expects it to be HONOURED, loudly
#
# The mode is an argument rather than something the script sniffs, because a
# script that decides for itself what the build is would pass either way.
set -u
MODE="${1:-mandatory}"
LIB="${LIB:-./libfreehsm-fips.so}"
TOOL="${TOOL:-./tools/fhsm-token}"
fail=0

say() { printf '  %-62s %s\n' "$1" "$2"; }
ok()  { if [ "$1" = 0 ]; then say "$2" OK; else say "$2" FAIL; fail=$((fail+1)); fi; }

export FHSM_INTEGRITY_ALLOW_UNSIGNED=1

# The script drives the real module through a tool, so a missing tool is a
# missing test rather than a passing one. `make tests` did not build the tools
# when this was written, and every assertion below reported FAIL for the same
# uninteresting reason.
if [ ! -x "$TOOL" ]; then
    echo "audit_switch.sh: $TOOL is not built -- run 'make all' first" >&2
    exit 2
fi
if [ ! -f "$LIB" ]; then
    echo "audit_switch.sh: $LIB is missing -- run 'make all' first" >&2
    exit 2
fi

echo "The audit switch, through C_Initialize  (expecting: $MODE)"
echo

# --- the log on by default ---------------------------------------------------
D=$(mktemp -d)
out=$(FHSM_TOKENS_DIR="$D" "$TOOL" info --module "$LIB" 2>&1); rc=$?
ok $rc "the module starts with the log on"
echo "$out" | grep -q "audit log is OFF"
ok $((1-$?)) "  and does not claim to be off"
rm -rf "$D"

# --- FHSM_AUDIT=off ----------------------------------------------------------
D=$(mktemp -d)
out=$(FHSM_TOKENS_DIR="$D" FHSM_AUDIT=off "$TOOL" info --module "$LIB" 2>&1); rc=$?

if [ "$MODE" = mandatory ]; then
    [ $rc -ne 0 ]
    ok $? "FHSM_AUDIT=off is refused"
    echo "$out" | grep -q "refused by this build"
    ok $? "  and the refusal says why, and how to allow it"
    echo "$out" | grep -q "FHSM_AUDIT_MANDATORY=0"
    ok $? "  naming the build flag rather than leaving it to be guessed"
else
    [ $rc -eq 0 ]
    ok $? "FHSM_AUDIT=off is honoured"
    echo "$out" | grep -q "audit log is OFF"
    ok $? "  and it is announced, not silent"
    echo "$out" | grep -q "nothing to review"
    ok $? "  saying what is lost, not just that a flag was set"
fi
rm -rf "$D"

# --- the old silent switch ---------------------------------------------------
# /dev/null still works: refusing it would break a legitimate FIFO target. What
# changed is that the module says it is a stream and not a log, which is the
# whole difference between an operator's choice and an accident.
D=$(mktemp -d)
out=$(FHSM_TOKENS_DIR="$D" FHSM_AUDIT_LOG=/dev/null "$TOOL" info --module "$LIB" 2>&1); rc=$?
ok $rc "a stream target still starts the module"
echo "$out" | grep -q "not a regular"
ok $? "  and is announced as a stream, not a log"
rm -rf "$D"

echo
if [ $fail -eq 0 ]; then echo "PASS : 0 failure(s)"; else echo "FAIL : $fail failure(s)"; fi
exit $((fail > 0))
