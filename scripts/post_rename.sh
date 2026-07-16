#!/usr/bin/env bash
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# post_rename.sh --- repo-side fixups to run IMMEDIATELY AFTER the
# freehsm-c -> freehsm renames on GitHub / GitLab / Codeberg.
#
# Why a script rather than a commit made in advance: mirror.yml hard-codes the
# GitLab and Codeberg push URLs, and GitLab does NOT redirect git remotes on
# rename (GitHub does). Landing the new URLs before the rename breaks the
# mirror; landing them after is a one-liner. So this waits.
#
# Idempotent: safe to run twice. Prints what it changed.
#
# Usage:  bash scripts/post_rename.sh [--check]
#           --check : report only, change nothing (exit 1 if work remains)
# ===========================================================================
set -eu

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

OLD="freehsm-c"
NEW="freehsm"
rc=0

say() { printf '  %s\n' "$*"; }

# --- 1. mirror.yml push URLs -------------------------------------------------
# These are the only hard-coded repo URLs that break on rename. The ghcr.io
# image names (freehsm-c-build / freehsm-c-test) are image names, not repo
# names: they keep working after the rename and are deliberately left alone.
for pair in "gitlab.com:afchine.mad" "codeberg.org:afchine1337"; do
    host="${pair%%:*}"; ns="${pair##*:}"
    if grep -q "git@${host}:${ns}/${OLD}.git" .github/workflows/mirror.yml 2>/dev/null; then
        if [ "$CHECK" = 1 ]; then
            say "TODO  mirror.yml still points at git@${host}:${ns}/${OLD}.git"
            rc=1
        else
            sed -i "s|git@${host}:${ns}/${OLD}\.git|git@${host}:${ns}/${NEW}.git|g" \
                .github/workflows/mirror.yml
            say "done  mirror.yml -> git@${host}:${ns}/${NEW}.git"
        fi
    else
        say "ok    mirror.yml already points at ${host}/${ns}/${NEW}"
    fi
done

# --- 2. local remotes --------------------------------------------------------
# GitHub redirects, so this is cosmetic there; GitLab and Codeberg do not.
for r in origin gitlab codeberg; do
    url=$(git remote get-url "$r" 2>/dev/null || true)
    [ -z "$url" ] && { say "skip  remote '$r' not configured"; continue; }
    case "$url" in
        *"/${OLD}.git")
            if [ "$CHECK" = 1 ]; then
                say "TODO  remote $r still $url"; rc=1
            else
                git remote set-url "$r" "${url%/${OLD}.git}/${NEW}.git"
                say "done  remote $r -> $(git remote get-url "$r")"
            fi
            ;;
        *) say "ok    remote $r -> $url" ;;
    esac
done

# --- 3. the README already advertises the new name ---------------------------
# Phase 3 of REBRAND_CHECKLIST.md was committed before Phase 2, so until the
# rename lands the badges 404. Verify they resolve now.
if command -v curl >/dev/null 2>&1; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 10 \
        "https://github.com/afchine1337/${NEW}" || echo "000")
    if [ "$code" = "200" ]; then
        say "ok    https://github.com/afchine1337/${NEW} -> 200 (README badges live)"
    else
        say "TODO  https://github.com/afchine1337/${NEW} -> ${code} : rename not done yet"
        rc=1
    fi
fi

[ "$CHECK" = 1 ] && exit $rc
exit 0
