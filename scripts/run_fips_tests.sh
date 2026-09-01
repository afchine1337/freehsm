#!/usr/bin/env bash
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# run_fips_tests.sh --- run the suite with the OpenSSL FIPS provider loaded.
#
#  WHY THIS DID NOT EXIST
#
#  src/fhsm_crypto.c skips the provider entirely in dev mode:
#
#      int dev_mode = (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED") != NULL);
#      if (!dev_mode) {
#          g_fips_prov = OSSL_PROVIDER_load(NULL, "fips");
#
#  and FHSM_INTEGRITY_ALLOW_UNSIGNED=1 is set on every test recipe in the
#  Makefile, in run_pkcs11_check.sh and in the CI workflows, with
#  OPENSSL_CONF=/dev/null alongside it. Neither is a defect -- the shortcut is
#  deliberate, and /dev/null keeps EVP fetches reproducible. The consequence is
#  what nobody had written down: no test had ever run this module with the
#  FIPS provider loaded. docs/FIPS_140_3_SECURITY_TARGET.md says all
#  FIPS-relevant computation is delegated to that provider. That is true of the
#  code and, until this script, unobserved in operation.
#
#  What `make tests` proves about fips-strict is that the module REFUSES
#  non-approved mechanisms. That is a test of the refusal, not of the
#  delegation.
#
#  THE CHECK THAT MAKES THIS WORTH RUNNING
#
#  WHAT THE FIRST RUN GOT WRONG, AND WHY IT IS RECORDED HERE
#
#  The first version counted tests that did NOT print the module's "dev mode
#  active" notice and called them FIPS runs: 16 fell back, 21 "passed with the
#  provider loaded". Both numbers were wrong, in opposite directions.
#
#    * The 21 had told us nothing. A test that never reaches crypto_init_once
#      prints no notice, and silence was being read as proof. The script
#      written to stop this project mistaking an absence in the output for an
#      absence in the world was making that mistake itself.
#
#    * The 16 were not a per-run accident either. The notice only prints when
#      FHSM_INTEGRITY_ALLOW_UNSIGNED is in the environment, and this script
#      never set it -- it merely failed to remove it, and inherited it from the
#      caller's shell. Not setting a variable is not the same as unsetting it,
#      and a control that depends on what the caller does not have exported is
#      not a control. It is unset below.
#
#  THE STRUCTURAL PART, WHICH IS THE REAL FINDING
#
#  Only the shipped .so is signed by `make integrity`. A test binary linked
#  statically against $(LIB_OBJ) keeps the all-zero .fhsm_digest placeholder
#  (Makefile, note above tests/test_smoke), so do_verify() returns
#  INTEGRITY_FAILED unless the bypass is set -- and the bypass is exactly what
#  makes the module skip the provider. Those tests therefore CANNOT be a FIPS
#  run, by construction, however this script is invoked. Reporting them as
#  failures every time would be noise; they are named once, as a limit.
#
#  So the measurement is: a positive probe that the signed module really loads
#  the provider, then the dlopen-based tests, which are the ones for which the
#  question has an answer.
# ===========================================================================
set -uo pipefail
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJ"

# The whole point. Not "do not set it" -- remove it, whatever the caller had.
unset FHSM_INTEGRITY_ALLOW_UNSIGNED
unset FHSM_KAT_ALLOW_FAIL
# OPENSSL_CONF is deliberately NOT forced to /dev/null here: the configuration
# is what activates the provider.
unset OPENSSL_CONF

# The Makefile runs every test under $(TEST_LD), which REPLACES the caller's
# LD_LIBRARY_PATH so the tests resolve the OpenSSL they were built against.
# Do the same here rather than hope the system one matches.
OSSL_PREFIX=$(sed -n 's/^OPENSSL_PREFIX[[:space:]]*[?:]\?=[[:space:]]*//p' Makefile | head -1)
export LD_LIBRARY_PATH=".${OSSL_PREFIX:+:$OSSL_PREFIX/lib64:$OSSL_PREFIX/lib}"
TEST_LD_ENV=""   # exported above; kept as a seam if that ever needs to differ

# Read the module's name from the Makefile rather than hard-coding it, so a
# profile that renames it does not leave this script measuring a stale file.
LIB_SO=$(sed -n 's/^LIB[[:space:]]*=[[:space:]]*//p' Makefile | head -1)
LIB_SO=${LIB_SO:-libfreehsm-fips.so}
[ -f "$LIB_SO" ] || { printf '  \033[31mNON\033[0m   %s not built -- run make first\n' "$LIB_SO"; exit 2; }

fails=0
ok()  { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
bad() { printf '  \033[31mNON\033[0m   %s\n' "$1"; fails=$((fails+1)); }

echo "== The FIPS provider =="

# --- 1. is it there at all ------------------------------------------------
if openssl list -providers 2>/dev/null | grep -q '^  fips$'; then
    ok "openssl reports a fips provider"
else
    bad "no fips provider in \`openssl list -providers\`
        On Debian the module is packaged (openssl-provider-fips) but its
        install status must be generated once, and that step will not run
        while the stale one is being included:
            sudo cp /usr/lib/ssl/fipsmodule.cnf /usr/lib/ssl/fipsmodule.cnf.bak
            sudo OPENSSL_CONF=/dev/null openssl fipsinstall \\
                 -out /usr/lib/ssl/fipsmodule.cnf \\
                 -module \$(openssl version -m | sed 's/MODULESDIR: //; s/\"//g')/fips.so"
    echo
    echo "== $fails check(s) failed -- the environment is not the one the"
    echo "   Security Target describes, so nothing below would mean anything =="
    exit 2
fi

# --- 2. the module must be signed ----------------------------------------
# Not a nicety: FHSM_INTEGRITY_ALLOW_UNSIGNED is precisely what makes the
# module skip the provider, so an unsigned run cannot be a FIPS run.
#
# This first ran `make integrity` and treated a zero exit as "it is signed".
# Two things wrong with that, and the second is the one to remember.
#
#   `make integrity` SIGNS the module -- it is an action, not a question. It
#   passed on the first execution because the module was unsigned and it
#   signed it; it failed on the second because sign_module.sh refuses to
#   overwrite an existing digest without --force and exits 3. So the check
#   could only ever pass when the property it asserts did not hold, and
#   passing it meant the artefact under test had just been modified by the
#   test. A pre-flight script must not write to the thing it is measuring.
#
# Read the section instead. Nothing is changed, and the answer does not
# depend on what the module was before the script ran.
digest=$(objcopy --dump-section .fhsm_digest=/dev/stdout "$LIB_SO" /dev/null \
         2>/dev/null | xxd -p | tr -d '\n')
case "$digest" in
    "")
        bad "no .fhsm_digest section in $LIB_SO -- rebuild with src/fhsm_integrity.c"
        exit 2 ;;
    *[!0]*)
        ok "module signed (digest ${digest:0:16}...)" ;;
    *)
        bad "$LIB_SO carries the all-zero placeholder -- it is unsigned.
        Sign it and run this again:  make integrity"
        exit 2 ;;
esac

# --- 3. positive proof, before any counting -------------------------------
# The signed module, opened the way a real caller opens it. If this says no,
# nothing below can be a FIPS run and the counts would be decoration.
echo
echo "== Does the signed module load the provider? =="
# Always ask make, never "build it if the file is missing": a probe left over
# from another tree or another OpenSSL prefix is present, and would be run.
make tests/probe_fips_loaded >/tmp/fips_probe_build.log 2>&1 \
    || { bad "could not build tests/probe_fips_loaded -- see /tmp/fips_probe_build.log"; exit 2; }
probe_out=$($TEST_LD_ENV ./tests/probe_fips_loaded ./libfreehsm-fips.so 2>&1)
probe_rc=$?
case "$probe_rc" in
    0) ok "$probe_out" ;;
    1) bad "$probe_out
        The module initialised and the provider is not there. This is the
        delegation claim in docs/FIPS_140_3_SECURITY_TARGET.md failing in
        operation, and it is the finding this script was written to get." ;;
    *) bad "could not ask: $probe_out"; exit 2 ;;
esac

# --- 4. classify by the artefact, not by the source text ------------------
#
# The first version asked whether the .c contained the string "dlopen". That
# misfiled test_fork_child and test_session_cap, which open the module through
# a helper in tools/p11_util.h and never write the word themselves. They were
# then reported as "no .fhsm_digest section, cannot be signed" -- true, and
# beside the point: they link `-ldl` and nothing of ours, so there is nothing
# in them to sign and never was. Grepping the source for a call is guessing at
# a property of the binary.
#
# Ask the binary instead. The .fhsm_digest section is present exactly when the
# test embeds our integrity code, which is exactly when it must be signed to
# run without the bypass:
#
#   section present -> the module is IN this binary  -> sign a copy, run that
#   section absent  -> the module is the .so it opens -> run it as it is
#
# One property, read off the artefact, deciding both paths.
echo
echo "== The suite, with the provider loaded =="
pass=0; fail=0; fellback=0; embedded=""
for t in tests/test_*; do
    case "$t" in
        *.*) continue ;; *concurrency*) continue ;;
    esac
    [ -x "$t" ] || continue
    name=$(basename "$t")

    # test_integrity is the test OF the integrity check, and `make
    # test-integrity` already drives it through unsigned, signed and tampered
    # -- with an argv it requires and this loop does not pass. Signing it here
    # would also fail, because that target signs it in place and
    # sign_module.sh will not overwrite a digest. It has its own target; leave
    # it there.
    [ "$name" = "test_integrity" ] && continue

    if readelf -SW "$t" 2>/dev/null | grep -q '\.fhsm_digest'; then
        embedded="$embedded $name"
        continue
    fi
    # test_p11_loader takes the module path, as it does in the Makefile.
    arg=""; [ "$name" = "test_p11_loader" ] && arg="./libfreehsm-fips.so"
    D=$(mktemp -d)
    out=$(FHSM_TOKENS_DIR="$D" $TEST_LD_ENV "./$t" $arg 2>&1); rc=$?
    rm -rf "$D"
    # Belt and braces: the notice must not appear, and it cannot now that the
    # variable is unset -- if it does, something re-set it and that is a bug
    # in this script, not in the module.
    if printf '%s' "$out" | grep -q "dev mode active"; then
        printf '  \033[33m?\033[0m     %-28s fell back despite the unset\n' "$name"
        fellback=$((fellback+1))
    elif [ "$rc" = 0 ]; then
        printf '  \033[32mOK\033[0m    %-28s opens the signed .so\n' "$name"
        pass=$((pass+1))
    else
        printf '  \033[31mNON\033[0m   %-28s rc=%d\n' "$name" "$rc"
        printf '%s\n' "$out" | sed -n '1,6p' | sed 's/^/            /'
        fail=$((fail+1))
    fi
done

echo
[ "$fellback" -eq 0 ] && ok "no test fell back to dev mode" \
                      || bad "$fellback test(s) fell back -- the unset above did not hold"
[ "$fail" -eq 0 ] && ok "$pass test(s) passed against the FIPS provider" \
                  || bad "$pass passed, $fail failed against the FIPS provider"

# --- 5. the tests that embed the module, signed as copies -----------------
#
# These carry $(LIB_OBJ) and therefore an all-zero .fhsm_digest, so they need
# the bypass -- which is what skips the provider. They were reported as an
# unreachable limit until `make test-integrity` showed the way out: it signs
# the TEST BINARY with the same scripts/sign_module.sh that signs the .so, and
# runs it under env -u. sign_module.sh patches any ELF carrying the section,
# and the Makefile comment above that target has said so all along.
#
# Signing them in place would be the wrong move. `make tests` would then need
# a FIPS provider on every developer's machine and in CI, or would put the
# bypass back and undo the point; a relink would leave an unsigned binary that
# sign_module.sh refuses to re-sign without --force; and signed artefacts
# would sit in the tree between runs. So each is copied to a temporary
# directory and the COPY is signed. Nothing in tests/ is touched, the copy is
# fresh every time so --force never arises, and the whole thing is removed on
# exit.
#
# cwd stays at the project root, so relative paths inside a test still
# resolve. Only the binary lives elsewhere.
echo
echo "== The tests that embed the module, signed as copies =="
SIGNDIR=$(mktemp -d)
trap 'rm -rf "$SIGNDIR"' EXIT
spass=0; sfail=0

for name in $embedded; do
    cp "tests/$name" "$SIGNDIR/$name" || { bad "cannot copy $name"; continue; }

    # Exit 3 is sign_module.sh refusing to overwrite an existing digest. On a
    # fresh copy that means the ORIGINAL was already signed -- `make
    # test-integrity` signs in place -- which is not a problem here: a signed
    # binary is precisely what this section wants. Anything else is.
    sign_out=$(bash scripts/sign_module.sh "$SIGNDIR/$name" 2>&1); sign_rc=$?
    if [ "$sign_rc" != 0 ] && [ "$sign_rc" != 3 ]; then
        printf '  \033[31mNON\033[0m   %-28s signing failed (rc=%d)\n' "$name" "$sign_rc"
        printf '%s\n' "$sign_out" | sed -n '1,4p' | sed 's/^/            /'
        sfail=$((sfail+1)); continue
    fi

    D=$(mktemp -d)
    out=$(FHSM_TOKENS_DIR="$D" "$SIGNDIR/$name" 2>&1); rc=$?
    rm -rf "$D"

    if printf '%s' "$out" | grep -q "dev mode active"; then
        printf '  \033[33m?\033[0m     %-28s fell back despite being signed\n' "$name"
        fellback=$((fellback+1))
    elif [ "$rc" = 0 ]; then
        printf '  \033[32mOK\033[0m    %-28s signed copy, provider loaded\n' "$name"
        spass=$((spass+1))
    else
        printf '  \033[31mNON\033[0m   %-28s rc=%d\n' "$name" "$rc"
        printf '%s\n' "$out" | sed -n '1,8p' | sed 's/^/            /'
        sfail=$((sfail+1))
    fi
done

echo
if [ "$sfail" -eq 0 ]; then
    ok "$spass of these passed against the FIPS provider too"
else
    bad "$spass passed, $sfail failed among the signed copies.
        These have never run in this configuration, so a failure here is a
        first observation rather than a regression: read what it says before
        changing anything. A mechanism the module offers that the provider
        does not serve looks exactly like this."
fi

echo
echo "  Total against the provider: $((pass + spass)) of $((pass + spass + fail + sfail))"
echo "  Not counted: test_integrity, which make test-integrity drives through"
echo "               unsigned / signed / tampered on its own."

echo
if [ "$fails" -eq 0 ]; then
    echo "== the delegation is exercised, not just specified =="
    exit 0
fi
echo "== $fails check(s) failed =="
echo
echo "A failure here is informative rather than bad news. The suite has never"
echo "run in this environment, so a mechanism the module offers that the FIPS"
echo "provider does not serve shows up now, at a desk, instead of in a"
echo "deployment. Record what fails before changing anything: the list is the"
echo "first measurement of what fips-strict actually is."
exit 1
