#!/usr/bin/env bash
# ===========================================================================
# scripts/tag-rc.sh
#
# Push an annotated, GPG-signed release-candidate tag (vX.Y.Z-rcN) to
# trigger the release.yml workflow without committing a real release.
# This is the rehearsal step before tagging the real vX.Y.Z.
#
# Usage:
#   ./scripts/tag-rc.sh v1.1.1-rc1 "Test the release pipeline"
#
# Pre-requisites :
#   - RELEASE_GPG_KEY + RELEASE_GPG_PASSPHRASE configured in GitHub
#     Secrets (use scripts/setup-release-secrets.sh first).
#   - main branch up to date and pushed.
#   - GPG key 743A6A5904A1461A646408DE48560162DBBF28A2 in your keyring.
# ===========================================================================

set -euo pipefail

TAG="${1:-}"
MSG="${2:-}"

if [[ -z "$TAG" || -z "$MSG" ]]; then
    cat <<EOF >&2
Usage: $0 <tag> <message>

Examples:
   $0 v1.1.1-rc1 "Dry-run of the release pipeline"
   $0 v1.1.1-rc2 "Second RC after fixing tarball signature"

Naming :
   - vX.Y.Z-rcN  : release candidate (pre-release on GitHub Releases)
   - vX.Y.Z      : real release

The release.yml workflow triggers on any tag matching v* so this script
exercises the full path including GPG-signature of tarballs.
EOF
    exit 1
fi

if ! [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]]; then
    echo "ERROR: tag must match v<MAJOR>.<MINOR>.<PATCH>[-rcN]" >&2
    exit 2
fi

# Confirm main is clean and pushed.
if ! git diff-index --quiet HEAD --; then
    echo "ERROR: working tree dirty — commit or stash first." >&2
    exit 3
fi

LOCAL_HEAD=$(git rev-parse HEAD)
REMOTE_HEAD=$(git rev-parse origin/main)
if [[ "$LOCAL_HEAD" != "$REMOTE_HEAD" ]]; then
    echo "ERROR: local main ($LOCAL_HEAD) != origin/main ($REMOTE_HEAD)." >&2
    echo "       Push main first :  git push origin main" >&2
    exit 4
fi

# Tag locally (GPG-signed annotated).
echo "Creating signed tag $TAG ..."
git tag -s -a "$TAG" -m "$MSG"

# Confirm the signature is valid before pushing.
git tag --verify "$TAG" || {
    echo "ERROR: tag signature verification failed locally." >&2
    git tag -d "$TAG"
    exit 5
}

# Push the tag.
echo "Pushing $TAG to origin..."
git push origin "$TAG"

cat <<EOF

==============================================================================
Tag $TAG pushed.

Watch the workflow at :
   https://github.com/afchine1337/freehsm-c/actions/workflows/release.yml

Expected stages :
   1. Verify tag GPG signature                  — should match Ed25519 fpr.
   2. Reproducible build in pinned Docker image — produces libfreehsm-fips.so.
   3. Sign + embed integrity digest             — re-builds with the digest in
                                                  the .fhsm_digest section.
   4. Build source + binary tarballs            — both reproducible.
   5. Sign tarballs with RELEASE_GPG_KEY        — produces .asc detached sigs.
   6. Publish GitHub Release                    — auto-marked as pre-release
                                                  if tag matches *-rc*.

If anything fails :
   - Inspect the Actions log on the failed step.
   - If you need to retry, DELETE the tag locally and remotely and re-run :
         git tag -d $TAG
         git push --delete origin $TAG
         # fix the issue, then re-run this script.

==============================================================================
EOF
