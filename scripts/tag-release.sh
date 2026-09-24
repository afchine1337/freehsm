#!/usr/bin/env bash
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# tag-release.sh --- run the pre-flight, and tag only if it passes.
#
#  Written after v2.2.0, which was tagged and pushed while release.sh was
#  printing "1 check(s) failed -- NOT ready to tag". Nothing was wrong with
#  the check. The commands had been handed over on separate lines, the gate
#  failed, and the next line ran anyway.
#
#  release.sh is deliberately read-only -- "it checks, prints the commands,
#  and stops" -- and that is worth keeping: it is also how you ask whether a
#  tree is ready without intending to tag anything. So this script does not
#  change it. It calls it, and acts only on exit 0.
#
#  The gate and the action are now one process. There is no line to run
#  anyway.
#
#  What this adds on top of the pre-flight, and only that:
#
#    * that HEAD is main and is what origin is about to receive. release.sh
#      checks the tree is clean; clean is not current, and a tag on a commit
#      behind origin/main names a tree nobody reviewed;
#    * verifies the signature it just made, rather than assuming `git tag -s`
#      succeeded because it printed nothing;
#    * confirms the tag reached the remote. release.sh prints that advice; a
#      printed instruction is what this script exists to stop relying on.
#
#  Not here, because release.sh already does it: tree state, build profile,
#  the version string and macros, the CHANGELOG section, the signing key, the
#  build and unit tests, the reproducibility reference, and whether the tag
#  already exists locally or on origin. The first draft of this file re-checked
#  the last of those, from a partial reading of release.sh. Two copies of one
#  rule is the defect this project spends its time removing; there is no
#  version of that which is acceptable in the script whose job is to stop
#  rules from being skipped.
#
#  Usage:  scripts/tag-release.sh 2.2.0
#          scripts/tag-release.sh 2.2.0 --dry-run
#
#  --dry-run runs the pre-flight and every read-only check, and stops before
#  the first git write. Use it when you want the answer without the act.
# ===========================================================================
set -u

VERSION="${1:-}"
DRY=0
[ "${2:-}" = "--dry-run" ] && DRY=1
[ -n "$VERSION" ] || {
    echo "usage: $0 <version> [--dry-run]   (e.g. 2.2.0)" >&2
    exit 2
}

TAG="v$VERSION"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
cd "$REPO" || exit 2

say()  { printf '\n\033[1m%s\033[0m\n' "$1"; }
bad()  { printf '  \033[31mNON\033[0m   %s\n' "$1" >&2; }
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$1"; }

# --- the gate ------------------------------------------------------------
#
# Not `|| true`, not a captured exit code examined later. The script stops
# here, and the rest of the file is unreachable when the pre-flight says no.
if ! bash "$HERE/release.sh" "$VERSION"; then
    say "tag-release: the pre-flight said no. Nothing was written."
    exit 1
fi

say "── the pre-flight above printed these commands; this script runs them ──"

# --- HEAD must be what origin will receive -------------------------------
#
# release.sh checks the tree is clean. Clean is not the same as current: a
# tag on a commit behind origin/main publishes a tree nobody reviewed, and
# the push that follows would fast-forward past it without comment.
git fetch --quiet origin || { bad "git fetch origin failed"; exit 1; }
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
    bad "on branch '$BRANCH', not main. Releases are tagged from main."
    exit 1
fi
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)
BASE=$(git merge-base HEAD origin/main)
if [ "$LOCAL" = "$REMOTE" ]; then
    ok "main is level with origin/main"
elif [ "$BASE" = "$REMOTE" ]; then
    ok "main is ahead of origin/main -- the push below will carry it"
else
    bad "main has diverged from origin/main, or is behind it.
        Reconcile before tagging: a tag is a promise about a commit, and
        right now it is not clear which commit that is."
    exit 1
fi

if [ "$DRY" -eq 1 ]; then
    say "tag-release: --dry-run. Everything above passed; nothing was written."
    echo "  Re-run without --dry-run to tag and push $TAG."
    exit 0
fi

# --- write ---------------------------------------------------------------
say "tagging $TAG"
git tag -s "$TAG" -m "FreeHSM $TAG --- PKCS#11 v3.2 software HSM, Simorgh Labs" \
    || { bad "git tag -s failed -- is the signing key available?"; exit 1; }

# Verified rather than assumed. An unsigned tag on a project whose whole
# story is "this artefact is the one that was built and measured" is worse
# than no tag.
git tag -v "$TAG" >/dev/null 2>&1 \
    || { bad "$TAG does not verify. Removing it."; git tag -d "$TAG"; exit 1; }
ok "$TAG created and verifies"

say "pushing main, then $TAG"
git push origin main || { bad "push of main failed -- $TAG stays local"; exit 1; }
git push origin "$TAG" || { bad "push of $TAG failed"; exit 1; }

# --- confirm it landed ---------------------------------------------------
#
# "A push that does not report the tag has not pushed the tag" -- release.sh
# says so and then leaves it to the reader. Asking the remote is two seconds
# and it is the only evidence that any of the above worked.
if git ls-remote --tags origin 2>/dev/null | grep -qE "refs/tags/$TAG\$"; then
    ok "$TAG is on origin"
else
    bad "$TAG is NOT on origin despite a push that reported success.
        Do not publish a release against it until this is understood."
    exit 1
fi

cat <<EOF

== $TAG tagged, pushed and confirmed ==

Still yours to do, in this order:

  1. reopen the CHANGELOG, so the next commits have somewhere to go:

        ## [Unreleased]

        ## [$VERSION] --- $(date +%F)

  2. gh release create $TAG --title "FreeHSM $TAG" \\
         --notes-file <(tail -n +5 RELEASE_$TAG.md) --verify-tag

  3. gh issue list --state open --limit 30

     Tell every reporter whose fix this release carries, by name, in their
     issue -- and let them close it. ACKNOWLEDGEMENTS.md records who found
     what; keep it current in the same pass.

  4. if the release carries a security fix, publish the advisory only now.
     "Patched versions: $VERSION" has to name something that exists.
EOF
