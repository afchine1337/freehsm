#!/usr/bin/env bash
# ===========================================================================
# scripts/tag-v1.1.0-FIPS.sh
#
# Tag and sign the v1.1.0-FIPS release. Run this from the project root,
# AFTER all commits for the release have landed on main.
#
# Pre-requisites :
#   - GPG private key configured (git config user.signingkey ...)
#   - All changes committed
#   - On the main branch
#   - tests/coverage_matrix.sh PASS
#
# Effect :
#   - Verifies the build is reproducible.
#   - Creates an annotated, GPG-signed tag.
#   - Prints push instructions (does NOT push automatically).
#
# Usage :
#   ./scripts/tag-v1.1.0-FIPS.sh
# ===========================================================================
set -euo pipefail

TAG="v1.1.0-FIPS"
AUTHOR='Afchine Madjlessi <afchine.mad@gmail.com>'

echo "==> Pre-flight checks"

# 1. Must be on main.
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
    echo "ERROR : not on main (current : $BRANCH)" >&2
    exit 1
fi

# 2. Working tree must be clean.
if ! git diff-index --quiet HEAD --; then
    echo "ERROR : working tree has uncommitted changes" >&2
    git status --short
    exit 1
fi

# 3. Tag must not already exist locally OR remotely.
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "ERROR : tag $TAG already exists locally" >&2
    exit 1
fi
if git ls-remote --tags origin "$TAG" | grep -q "$TAG"; then
    echo "ERROR : tag $TAG already exists on origin" >&2
    exit 1
fi

# 4. GPG signing key must be configured.
SIGNING_KEY=$(git config --get user.signingkey || true)
if [ -z "$SIGNING_KEY" ]; then
    echo "ERROR : no GPG signing key configured (git config user.signingkey)" >&2
    exit 1
fi
echo "   GPG signing key : $SIGNING_KEY"

# 5. Author email matches expected.
EMAIL=$(git config --get user.email || true)
if [ "$EMAIL" != "afchine.mad@gmail.com" ]; then
    echo "WARNING : git user.email is '$EMAIL', expected 'afchine.mad@gmail.com'"
    read -p "Continue anyway? [y/N] " ANSWER
    [ "$ANSWER" = "y" ] || exit 1
fi

echo "==> Building and verifying"

# 6. Clean build must succeed.
make clean
make
test -f libfreehsm-fips.so

# 7. Sign integrity digest.
make integrity

# 8. test_smoke is dev-only ; skip its integrity check.
FHSM_INTEGRITY_ALLOW_UNSIGNED=1 ./tests/test_smoke
echo "   test_smoke : OK"

echo "==> Creating signed tag"

# 9. Compose the tag message from RELEASE_v1.1.0-FIPS.md.
MSG_FILE=$(mktemp)
{
    echo "FreeHSM C $TAG"
    echo ""
    echo "Released by $AUTHOR"
    echo ""
    cat RELEASE_v1.1.0-FIPS.md | head -80
} > "$MSG_FILE"

git tag -s "$TAG" -F "$MSG_FILE"
rm -f "$MSG_FILE"

echo "   Tag created : $TAG"
echo ""
git show "$TAG" | head -20
echo ""

echo "==> Next steps"
cat <<EOF

Tag $TAG created locally and GPG-signed.

To publish :

  1. Push the tag to origin :
        git push origin $TAG

  2. The release workflow (.github/workflows/release.yml) will :
        - Verify the tag signature
        - Build reproducibly
        - Create source + binary tarballs
        - Sign them with the RELEASE_GPG_KEY secret
        - Publish to GitHub Releases

  3. After the workflow finishes, verify the published artefacts :
        gpg --verify freehsm-c-$TAG-src.tar.xz.asc

  4. Announce on the project channels with the digest of
     libfreehsm-fips.so :
EOF
sha256sum libfreehsm-fips.so
