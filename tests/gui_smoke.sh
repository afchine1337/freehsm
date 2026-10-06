#!/bin/sh
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# tests/gui_smoke.sh --- does fhsm-gui start, and close cleanly, with no display?
#
# docs/fhsm-gui-plan.md left this open: the window's logic is tested through
# tools/pkiops (tests/test_pkiops.c) and the command-line tools, and nothing
# ever opened the window itself. The bugs that reached a person anyway were
# the window's own: GTK criticals on close, from widgets touched while being
# destroyed, found on 2026-10-02 by closing it by hand. A program can work
# and still print those, so this does not stop at the exit code: anything GTK
# or GLib reports at CRITICAL or WARNING is a failure.
#
# How: a virtual X server (xvfb-run) and a private session bus
# (dbus-run-session), the window started, and app.quit sent over that bus --
# the same path as Ctrl+Q and the close button, through on_close.
#
# Needs: xvfb-run (xvfb, xauth), dbus-run-session (dbus), gapplication
# (libglib2.0-bin). Exit 0 pass, 1 fail, 77 a tool is missing (skipped).
set -u

GUI=${GUI:-./tools/fhsm-gui}
for t in xvfb-run dbus-run-session gapplication; do
    command -v "$t" >/dev/null 2>&1 || { echo "gui_smoke: skipped, no $t"; exit 77; }
done
[ -x "$GUI" ] || { echo "gui_smoke: $GUI is not built (make gui)"; exit 1; }

log=$(mktemp)
trap 'rm -f "$log"' EXIT

# The cairo renderer, not GL: under Xvfb GL is software at best, and a
# renderer's complaints about it would say nothing about this program.
# GTK_A11Y=none: no accessibility bus in a container, and its absence is
# reported as a warning that is not ours either.
GSK_RENDERER=cairo GTK_A11Y=none NO_AT_BRIDGE=1 \
dbus-run-session -- xvfb-run -a sh -c '
    "$1" >"$2" 2>&1 &
    pid=$!
    # The application answers on the bus once it has started; until then the
    # action has nowhere to go. Ten seconds, in fifths.
    i=0
    until gapplication action com.chaharsou.FhsmGui quit 2>/dev/null; do
        i=$((i + 1))
        if [ $i -ge 50 ] || ! kill -0 $pid 2>/dev/null; then
            echo "gui_smoke: the window never answered on the session bus" >>"$2"
            kill $pid 2>/dev/null
            break
        fi
        sleep 0.2
    done
    # And it must then exit by itself, within ten seconds.
    i=0
    while kill -0 $pid 2>/dev/null; do
        i=$((i + 1))
        if [ $i -ge 50 ]; then
            echo "gui_smoke: still running ten seconds after app.quit" >>"$2"
            kill $pid
            break
        fi
        sleep 0.2
    done
    wait $pid
' sh "$GUI" "$log"
rc=$?

fails=0
if [ $rc -ne 0 ]; then
    echo "gui_smoke: fhsm-gui exited with status $rc"
    fails=1
fi
if grep -E "CRITICAL|WARNING|gui_smoke:" "$log" >/dev/null; then
    echo "gui_smoke: reported while starting or closing:"
    sed 's/^/    /' "$log"
    fails=1
fi
if [ $fails -ne 0 ]; then
    echo "gui_smoke : FAIL"
    exit 1
fi
echo "gui_smoke : the window started and closed cleanly"
echo "gui_smoke : PASS"
