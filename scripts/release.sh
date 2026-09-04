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
#          scripts/release.sh 2.0.0-beta   (pre-release suffixes allowed)
# ===========================================================================
set -u

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version>   (e.g. 1.6.0)" >&2; exit 2; }

TAG="v$VERSION"
# The macros feed CK_VERSION bytes in C_GetInfo, C_GetSlotInfo and
# C_GetTokenInfo. They are numbers and cannot carry a pre-release suffix, so
# comparing them against a version like 2.0.0-beta compares two different
# kinds of thing and always fails. Strip the suffix for that one check, and
# only for it: the version STRING must still match in full, suffix included,
# because that is the field a human reads.
VERSION_NUM="${VERSION%%-*}"
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
# Was `"$VERSION-FIPS"`. The suffix is gone from the header as of v2.0.0:
# it named a certification the project does not hold, and it reached the
# soname and the tarball prefix through FHSM_VERSION_STRING.
if [ "$CUR" = "$VERSION" ]; then
    ok "FHSM_VERSION_STRING = $CUR"
else
    bad "FHSM_VERSION_STRING is \"$CUR\", expected \"$VERSION\" ($HDR)"
fi

# --- 3b. version macros --------------------------------------------------
# FHSM_VERSION_MINOR feeds libraryVersion and firmwareVersion in C_GetInfo,
# C_GetSlotInfo and C_GetTokenInfo. v1.6.0 shipped with the string bumped and
# the macros left at 1.5.0, so for two weeks the module answered "1.5" to
# every caller that asked it through the standard API while everything else
# -- filename, tarball, build seed, tag -- said 1.6.0. Checking only the
# string is checking the one field no consumer reads programmatically.
V_MAJ=$(awk '/FHSM_VERSION_MAJOR/{print $3; exit}' "$HDR" 2>/dev/null)
V_MIN=$(awk '/FHSM_VERSION_MINOR/{print $3; exit}' "$HDR" 2>/dev/null)
V_PAT=$(awk '/FHSM_VERSION_PATCH/{print $3; exit}' "$HDR" 2>/dev/null)
if [ "$V_MAJ.$V_MIN.$V_PAT" = "$VERSION_NUM" ]; then
    ok "version macros = $V_MAJ.$V_MIN.$V_PAT"
else
    bad "version macros are $V_MAJ.$V_MIN.$V_PAT, expected $VERSION_NUM ($HDR)"
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
    # FHSM_INTEGRITY_ALLOW_UNSIGNED is required here and was missing.
    #
    # Step 7 builds with `make clean && make`, deliberately leaving signing for
    # last so the signature covers the file that ships. But these test binaries
    # link the module's objects and therefore carry their OWN .fhsm_digest,
    # all-zero on a fresh build -- so every one of them fails C_Initialize with
    # FHSM_RV_INTEGRITY_FAILED. Running them straight, rather than through
    # `make tests` whose recipes set this, reimplemented the target and got it
    # wrong: 15 of 37 "failing" on a tree where `make tests` is green.
    #
    # Skipping the check here costs nothing, because it is exercised twice
    # immediately below and neither exercise is weakened by this line:
    # `make test-integrity` drives unsigned/signed/tampered without any bypass,
    # and the signed-module check reads .fhsm_digest back out of the shipped
    # .so. What this loop is for is the functional suite.
    if FHSM_TOKENS_DIR="$D" FHSM_INTEGRITY_ALLOW_UNSIGNED=1 "./$t" >/dev/null 2>&1
    then t_pass=$((t_pass+1))
    else t_fail=$((t_fail+1)); echo "        failing: $(basename "$t")"; fi
    rm -rf "$D"
done
[ "$t_fail" -eq 0 ] && ok "unit tests $t_pass/$t_pass" || bad "unit tests $t_pass ok, $t_fail failing"

if make test-integrity >/tmp/rel_selftest.log 2>&1; then
    ok "integrity self-test (unsigned / signed / tampered)"
else
    bad "make test-integrity failed -- /tmp/rel_selftest.log"
fi

# Sign, then ask whether it is signed. Those are two different questions and
# this used to conflate them: scripts/sign_module.sh exits 3 -- not 0 -- when
# the module already carries a digest, so on any second run of this pre-flight
# the `else` branch fired and reported "make integrity failed" for a module
# that was signed. A zero exit was never the assurance wanted here.
make integrity >/tmp/rel_integrity.log 2>&1; rel_rc=$?
if [ "$rel_rc" != 0 ] && [ "$rel_rc" != 3 ]; then
    bad "make integrity failed (rc=$rel_rc) -- /tmp/rel_integrity.log"
else
    rel_lib=$(sed -n 's/^LIB[[:space:]]*=[[:space:]]*//p' Makefile | head -1)
    rel_lib=${rel_lib:-libfreehsm.so}
    rel_d=$(objcopy --dump-section .fhsm_digest=/dev/stdout "$rel_lib" /dev/null \
            2>/dev/null | od -An -tx1 -v | tr -d ' \n')
    case "$rel_d" in
        "")     bad "no .fhsm_digest section in $rel_lib" ;;
        *[!0]*) ok  "module signed, digest read back (${rel_d:0:16}...)" ;;
        *)      bad "$rel_lib carries the all-zero placeholder -- it is NOT signed" ;;
    esac
fi
if grep -qi "clock skew" /tmp/rel_build.log /tmp/rel_integrity.log 2>/dev/null; then
    warn "make reported clock skew -- the build may be incomplete, check the VM clock"
fi

# --- 8. the reproducibility reference ------------------------------------
#
# docs/ROADMAP.md, 2026-08-15: dist/refs/ held nothing but .gitkeep across six
# tagged releases, so `make dist-verify` always took its fallback branch --
# build twice in the same container on the same day and compare. That proves
# the build is deterministic. It does not prove the published artefact can be
# reproduced, which is the property a third party actually wants: take the tag,
# rebuild it months later, obtain the bytes that were published.
#
# Nothing was hiding it. The fallback prints which branch it took, and
# `make dist-baseline` has always existed to record a reference. This script
# simply never asked whether one had been recorded, and a step that is
# available and never required is a step that does not happen. So it is
# required here, which is the only place that can make it happen.
echo
echo "== Reproducibility =="
REF="dist/refs/v${VERSION}.sha256"
if [ -f "$REF" ]; then
    ok "reference recorded: $REF"
    # Three outcomes, not two. This block had two, and conflated the third
    # with a real mismatch:
    #
    #   compared, agrees      -> ok
    #   compared, DIFFERS     -> bad. The artefact does not reproduce, which
    #                            is the whole point of the file.
    #   could not compare     -> warn, naming why. Docker absent, a daemon
    #                            that will not answer, a bind mount the
    #                            container cannot enter -- none of these is a
    #                            statement about the build.
    #
    # The distinction was not academic on 2026-09-02: dist-verify failed here
    # with `cd: /src: Permission denied`, the container unable to enter the
    # mounted tree, and the run was reported as a reproducibility failure. It
    # was a report about the machine. A check that cannot separate "the
    # property does not hold" from "I could not look" is the shape of defect
    # this whole pre-flight exists to catch, and it was in the pre-flight.
    if command -v docker >/dev/null 2>&1; then
        if make dist-verify >/tmp/rel_repro.log 2>&1; then
            if grep -q "reference found" /tmp/rel_repro.log; then
                ok "local build matches the recorded reference"
            else
                # The reference exists and dist-verify still fell back. That
                # means the two disagree about the version string, which is
                # the failure mode that made the recipe compare against
                # dist/refs/v.sha256 -- a file that cannot exist.
                bad "dist-verify fell back despite $REF -- version mismatch?"
            fi
        elif grep -qiE "digest divergence|FAIL : digest" /tmp/rel_repro.log; then
            # It looked, and the answer is no. This is the failure the file
            # exists to produce, and it must not be softened.
            bad "the local build does NOT reproduce $REF -- /tmp/rel_repro.log
        Either the source changed without a version bump, or the toolchain
        drifted. Do not tag until it is known which."
        else
            warn "could not compare here -- dist-verify did not get as far as
        a digest. Last line: $(tail -2 /tmp/rel_repro.log | head -1)
        Full log: /tmp/rel_repro.log. This says nothing about the build.
        release.yml compares inside the image at tag time and refuses to
        publish on a mismatch, so the comparison still happens."
        fi
    else
        # This was a failure -- "a reference nobody checked is the same
        # non-verification in a new place". That was right when nothing else
        # compared. It is no longer: .github/workflows/release.yml now refuses
        # to publish a build that does not match this file, and that check
        # cannot be skipped by tagging from a machine without Docker. So the
        # comparison still happens; it happens there. A warning states what
        # this run did and did not establish.
        warn "docker not found -- not compared here.
        release.yml will compare and will refuse to publish on a mismatch."
    fi
else
    bad "no reproducibility reference at $REF
        Produce one in the same image the release uses -- no Docker needed
        locally -- by running the 'Reproducibility baseline' workflow on this
        commit, then commit what it uploads:
            gh workflow run baseline.yml
            git add $REF
        With Docker on this machine, 'make dist-baseline' does the same.
        Six releases shipped without this. This one does not."
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
        ./libfreehsm.so ./reports/pkcs11-check

Then:

    git add -A && git commit -S -m "release: $TAG"
    git tag -s $TAG -m "FreeHSM $TAG --- PKCS#11 v3.2 software HSM, Simorgh Labs"
    git tag -v $TAG
    git push origin main --follow-tags
    git ls-remote --tags origin | grep $TAG   # confirm it actually went

This script writes nothing to git on purpose. The last line matters: a push
that does not report the tag has not pushed the tag.

Once the release is published, before you close anything:

    gh issue list --state open --limit 30

Tell every reporter whose fix this release carries, by name, in their issue --
and let THEM close it. On 2026-09-03 an issue was closed on a reporter who was
running the release while the fix existed only on main; he was right to reopen
it. Three others had been fixed for weeks with nobody told.

A fix nobody can download is not a fix, and a fix nobody hears about is not
much better. ACKNOWLEDGEMENTS.md records who found what; keep it current in the
same pass.
EOF
