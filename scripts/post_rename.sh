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

# --- 0. Refuse to run before the renames actually happened --------------------
# Applying the new URLs while the repo is still called freehsm-c points every
# remote at a repository that does not exist: the next push fails with
# "Repository not found", and mirror.yml is left broken in the working tree.
# The first version of this script printed the 404 as a TODO and then applied
# the changes anyway, which is exactly the state it should have prevented.
# --check still reports (that is its job); apply mode aborts.
if [ "$CHECK" = 0 ] && command -v curl >/dev/null 2>&1; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 10 \
        "https://github.com/afchine1337/${NEW}" || echo "000")
    if [ "$code" != "200" ]; then
        cat >&2 <<MSG
post_rename: refusing to run -- https://github.com/afchine1337/${NEW} -> ${code}

  The repository has not been renamed yet, so pointing the remotes and
  mirror.yml at "${NEW}" would break every push. Do the renames first:

    GitHub   : Settings -> rename ${OLD} -> ${NEW}
    GitLab   : Settings -> General -> path ${OLD} -> ${NEW}
    Codeberg : Settings -> rename ${OLD} -> ${NEW}

  Then run this script again. Use --check to inspect without changing anything.
MSG
        exit 2
    fi
fi

# --- 1. mirror.yml push URLs -------------------------------------------------
# These are the only hard-coded repo URLs that BREAK on rename -- GitLab does
# not redirect git remotes. They are not the only ones that go STALE, and this
# comment said they were until 2026-09-27, when five more turned up: REUSE.toml,
# Dockerfile.test's OCI source label, two URLs printed by
# setup-release-secrets.sh and one by tag-rc.sh. GitHub redirects, so nothing
# failed and nothing complained -- which is why section 4 below now sweeps for
# them instead of this comment claiming there are none.
#
# The ghcr.io image names (freehsm-c-build / freehsm-c-test) are image names,
# not repo names: they keep working after the rename and are deliberately left
# alone. Section 4 excludes them by name for that reason.
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

# --- 4. any remaining reference to the old repository ------------------------
# A redirect is not a fix. It works until somebody registers a repository at
# the old name, and it hides the staleness meanwhile: five references survived
# the rename here because nothing ever failed.
#
# Excluded, deliberately:
#   ghcr.io image names        freehsm-c-build / freehsm-c-test really exist
#   the tarball prefix         `make dist` still produces freehsm-c-src.tar.xz
#   CHANGELOG / RELEASE_v*     dated records; the URLs were right then
#   SECURITY.md's clone notice names the repo as it was called in June
#   docs/blog/*                dated posts; same rule as the CHANGELOG
#   pr_pkcs11check_*.md        a PR draft whose subject IS the rename, and
#                              which shows the old URL as the line it removes
#   reports/, .git/            not source
stale=$(grep -rn "github\.com/afchine1337/${OLD}\b" . 2>/dev/null \
    | grep -v '/\.git/\|/reports/\|^\./CHANGELOG\.md\|^\./RELEASE_v\|^\./SECURITY\.md' \
    | grep -v '/docs/blog/\|^\./pr_pkcs11check_' \
    | grep -v "${OLD}-build\|${OLD}-test\|${OLD}-src\.tar" \
    | cut -c1-140 || true)

if [ -n "$stale" ]; then
    say "TODO  references to github.com/afchine1337/${OLD} remain:"
    printf '%s\n' "$stale" | sed 's/^/        /'
    rc=1
else
    say "ok    no stale github.com/afchine1337/${OLD} reference outside the exclusions"
fi

[ "$CHECK" = 1 ] && exit $rc
exit 0
