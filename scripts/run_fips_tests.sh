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
#  A script that merely runs the tests in a different environment can pass
#  because the module quietly fell back to dev mode -- which is exactly the
#  shape of failure this whole exercise is about. So the first thing it does is
#  assert that the provider is really there, and every test run is checked for
#  the module's own fallback notice. An absence in the output is not an absence
#  in the world, so the absence is asserted rather than assumed.
# ===========================================================================
set -uo pipefail
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJ"

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
if make integrity >/tmp/fips_integrity.log 2>&1; then
    ok "module signed (make integrity)"
else
    bad "make integrity failed -- /tmp/fips_integrity.log"
    exit 2
fi

# --- 3. run, with neither escape hatch ------------------------------------
# No FHSM_INTEGRITY_ALLOW_UNSIGNED, so the provider is loaded.
# No OPENSSL_CONF=/dev/null, so the configuration that activates it is read.
echo
echo "== The suite, with the provider loaded =="
pass=0; fail=0; fellback=0
for t in tests/test_*; do
    case "$t" in
        *.*) continue ;; *concurrency*) continue ;;
    esac
    [ -x "$t" ] || continue
    D=$(mktemp -d)
    out=$(FHSM_TOKENS_DIR="$D" "./$t" 2>&1); rc=$?
    rm -rf "$D"
    name=$(basename "$t")
    # The module prints this when it falls back. A test that passed after
    # falling back has told us nothing about the delegation.
    if printf '%s' "$out" | grep -q "dev mode active"; then
        printf '  \033[33m?\033[0m     %-28s fell back to dev mode\n' "$name"
        fellback=$((fellback+1))
    elif [ "$rc" = 0 ]; then
        pass=$((pass+1))
    else
        printf '        %-28s rc=%d\n' "$name" "$rc"
        fail=$((fail+1))
    fi
done

echo
[ "$fellback" -eq 0 ]
ok_or_bad=$?
if [ "$fellback" -eq 0 ]; then
    ok "no test fell back to dev mode"
else
    bad "$fellback test(s) fell back -- they ran without the provider"
fi
[ "$fail" -eq 0 ] && ok "$pass test(s) passed with the provider loaded" \
                  || bad "$pass passed, $fail failed with the provider loaded"

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
