#!/usr/bin/env bash
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# release.sh --- pre-flight checks for a signed release.
#
#  Written after the v1.6.0 release, which took two retags. None of the three
#  mistakes was interesting and all were mechanically detectable:
#
#    1. a sed that did not match, so the version string stayed at the previous
#       release. v1.5.0 had shipped identifying itself as 1.4.0-FIPS for the
#       same reason, unnoticed for two weeks;
#    2. the CHANGELOG step, a comment in a copy-pasted block, skipped three
#       times running -- the tag ended up on a tree whose changelog said
#       "Unreleased";
#    3. `git push --follow-tags` silently refusing to overwrite a tag that
#       already existed on the remote, leaving the published v1.6.0 pointing
#       at the wrong commit.
#
#  This script refuses to sign anything until those cannot happen. It performs
#  no git write operations: it checks, prints the commands, and stops.
#
#  Usage:  scripts/release.sh 1.6.0
# ===========================================================================
set -u

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version>   (e.g. 1.6.0)" >&2; exit 2; }

TAG="v$VERSION"
HDR="include/fhsm_common.h"
GEN="src/gen/fhsm_dispatch.c"
CHANGELOG="CHANGELOG.md"
fails=0

ok()   { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
bad()  { printf '  \033[31mNON\033[0m   %s\n' "$1"; fails=$((fails+1)); }
warn() { printf '  \033[33m?\033[0m     %s\n' "$1"; }

echo "== Pre-flight $TAG =="

# --- 1. tree state -------------------------------------------------------
if [ -z "$(git status --porcelain)" ]; then
    ok "working tree clean"
else
    bad "working tree dirty -- commit or stash first"
fi

# --- 2. build profile ----------------------------------------------------
# The one check that cannot be recovered after the fact: an interop build
# ships the non-approved mechanisms live while every visible sign says
# fips-strict.
if grep -q 'fhsm_build_fips_strict = 1' "$GEN" 2>/dev/null; then
    ok "build profile is fips-strict"
else
    bad "profile is NOT fips-strict -- run: make generate PROFILE=fips-strict"
fi

# --- 3. version string ---------------------------------------------------
CUR=$(awk -F'"' '/FHSM_VERSION_STRING/{print $2; exit}' "$HDR" 2>/dev/null)
if [ "$CUR" = "$VERSION-FIPS" ]; then
    ok "FHSM_VERSION_STRING = $CUR"
else
    bad "FHSM_VERSION_STRING is \"$CUR\", expected \"$VERSION-FIPS\" ($HDR)"
fi

# --- 4. changelog --------------------------------------------------------
# The tag must not land on a tree whose changelog still says Unreleased.
if grep -qE "^## \[$VERSION\]" "$CHANGELOG" 2>/dev/null; then
    ok "CHANGELOG has a [$VERSION] section"
else
    bad "CHANGELOG has no '## [$VERSION]' section"
fi
if awk "/^## \[$VERSION\]/{f=1;next} /^## /{f=0} f&&NF{n++} END{exit !(n>0)}" "$CHANGELOG" 2>/dev/null; then
    ok "the [$VERSION] section is not empty"
else
    bad "the [$VERSION] section is empty"
fi

# --- 5. tag availability, locally AND on the remote ----------------------
# --follow-tags will not overwrite an existing remote tag and does not say so.
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    bad "tag $TAG already exists locally -- git tag -d $TAG"
else
    ok "tag $TAG free locally"
fi
if git ls-remote --tags origin 2>/dev/null | grep -q "refs/tags/$TAG\$"; then
    bad "tag $TAG already exists on origin -- git push origin :refs/tags/$TAG"
else
    ok "tag $TAG free on origin"
fi

# --- 6. signing key ------------------------------------------------------
if git config --get user.signingkey >/dev/null 2>&1 || gpg --list-secret-keys >/dev/null 2>&1; then
    ok "a signing key is available"
else
    warn "no signing key found -- git tag -s will fail"
fi

# --- 7. build, tests, integrity LAST -------------------------------------
# Order matters: make integrity must be the last command that touches the
# .so, or the signature covers a file that is then replaced.
echo
echo "== Build and tests =="
if make clean >/dev/null 2>&1 && make >/tmp/rel_build.log 2>&1; then
    W=$(grep -ci 'warning:' /tmp/rel_build.log)
    [ "$W" -eq 0 ] && ok "clean build, 0 warnings" || bad "$W warning(s) -- /tmp/rel_build.log"
else
    bad "build failed -- /tmp/rel_build.log"
fi

t_pass=0; t_fail=0
for t in tests/test_*; do
    # Skip sources, build artefacts (test_smoke.sha256, .tampered), the
    # concurrency test (needs a TSAN build) and test_integrity (driven by
    # `make test-integrity` below, which sets up the three states it needs).
    case "$t" in
        *.*)            continue ;;
        *concurrency*)  continue ;;
        *test_integrity) continue ;;
    esac
    [ -x "$t" ] || continue
    D=$(mktemp -d)
    if FHSM_TOKENS_DIR="$D" "./$t" >/dev/null 2>&1; then t_pass=$((t_pass+1))
    else t_fail=$((t_fail+1)); echo "        failing: $(basename "$t")"; fi
    rm -rf "$D"
done
[ "$t_fail" -eq 0 ] && ok "unit tests $t_pass/$t_pass" || bad "unit tests $t_pass ok, $t_fail failing"

if make test-integrity >/tmp/rel_selftest.log 2>&1; then
    ok "integrity self-test (unsigned / signed / tampered)"
else
    bad "make test-integrity failed -- /tmp/rel_selftest.log"
fi

if make integrity >/tmp/rel_integrity.log 2>&1; then
    ok "module signed (integrity ran last)"
else
    bad "make integrity failed -- /tmp/rel_integrity.log"
fi
if grep -qi "clock skew" /tmp/rel_build.log /tmp/rel_integrity.log 2>/dev/null; then
    warn "make reported clock skew -- the build may be incomplete, check the VM clock"
fi

# --- verdict -------------------------------------------------------------
echo
if [ "$fails" -ne 0 ]; then
    echo "== $fails check(s) failed -- NOT ready to tag =="
    exit 1
fi
cat <<EOF
== ready to tag $TAG ==

Run the harness first and confirm the failure count is what you expect:

    FHSM_ALLOW_UNSIGNED=1 bash scripts/run_pkcs11_check.sh \\
        ./libfreehsm-fips.so ./reports/pkcs11-check

Then:

    git add -A && git commit -S -m "release: $TAG"
    git tag -s $TAG -m "FreeHSM / Simorgh PKI $TAG"
    git tag -v $TAG
    git push origin main --follow-tags
    git ls-remote --tags origin | grep $TAG   # confirm it actually went

This script writes nothing to git on purpose. The last line matters: a push
that does not report the tag has not pushed the tag.
EOF
