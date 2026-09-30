#!/usr/bin/env bash
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# ci_install_openssl_fips.sh --- OpenSSL with its FIPS provider, installed at
# the prefix the Makefile already defaults to (/usr/local/ssl), for CI jobs
# that must initialise a SIGNED module.
#
# Why this exists. A signed module loads the FIPS provider in C_Initialize and
# refuses to start without it (CKR_PROVIDER_UNAVAILABLE). No CI image has one:
# Dockerfile.build installs libssl-dev and nothing else, whatever its header
# says, and every job that initialises the module sets
# FHSM_INTEGRITY_ALLOW_UNSIGNED, which skips the provider. So the one path a
# deployment runs had never run in CI. Found on 2026-09-30, when the first job
# to try it -- pkcs11-check-signed -- failed at C_InitToken in both profiles.
#
# The maintainer's workstation runs OpenSSL 3.5.7 built with enable-fips at
# this prefix, and this reproduces that: same version, same prefix, same
# configuration file location. The configuration is the prefix's own
# openssl.cnf -- the default of THIS libcrypto -- and OPENSSL_CONF is not set:
# the harness is Python, and the OpenSSL inside its `cryptography` wheel reads
# OPENSSL_CONF too, and would try to activate a FIPS provider it does not have.
#
# The tarball is checked against a pinned SHA-256, taken on 2026-09-30 from
# both github.com/openssl/openssl/releases and openssl.org/source, which agreed.
#
# Idempotent: when the prefix already holds fips.so (a CI cache hit), only the
# configuration is rewritten and checked.
# ===========================================================================
set -euo pipefail

VERSION=3.5.7
SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
PREFIX="${OPENSSL_PREFIX:-/usr/local/ssl}"
URL="https://github.com/openssl/openssl/releases/download/openssl-${VERSION}/openssl-${VERSION}.tar.gz"

if [ ! -f "$PREFIX/lib64/ossl-modules/fips.so" ]; then
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    echo "== OpenSSL ${VERSION} with enable-fips -> ${PREFIX}"
    curl -fsSL --retry 3 -o "$work/openssl.tar.gz" "$URL"
    echo "${SHA256}  $work/openssl.tar.gz" | sha256sum -c -
    tar -xzf "$work/openssl.tar.gz" -C "$work"
    (
        cd "$work/openssl-${VERSION}"
        ./Configure enable-fips --prefix="$PREFIX" --openssldir="$PREFIX" \
                    --libdir=lib64 >"$work/configure.log"
        make -j"$(nproc)" >"$work/build.log" 2>&1 \
            || { tail -40 "$work/build.log"; exit 1; }
        # install_fips runs `openssl fipsinstall`, which writes
        # $PREFIX/fipsmodule.cnf with the MAC of the fips.so it installs.
        make install_sw install_ssldirs install_fips >"$work/install.log" 2>&1 \
            || { tail -40 "$work/install.log"; exit 1; }
    )
else
    echo "== OpenSSL ${VERSION} FIPS provider already at ${PREFIX} (cache)"
fi

# Activate the provider in the prefix's own openssl.cnf. The shipped template
# carries both lines commented out; the edit is checked rather than trusted,
# so a template that changes shape fails here and not at C_InitToken.
cnf="$PREFIX/openssl.cnf"
sed -i -e "s|^# \.include fipsmodule\.cnf|.include $PREFIX/fipsmodule.cnf|" \
       -e 's|^# fips = fips_sect|fips = fips_sect|' "$cnf"
grep -q "^\.include $PREFIX/fipsmodule\.cnf" "$cnf" \
    || { echo "::error::$cnf: the fipsmodule.cnf include was not enabled"; exit 1; }
grep -q '^fips = fips_sect' "$cnf" \
    || { echo "::error::$cnf: the fips provider was not enabled"; exit 1; }

# Prove it before anything depends on it: the provider must load and pass its
# self-test through this configuration.
"$PREFIX/bin/openssl" version
LD_LIBRARY_PATH="$PREFIX/lib64" "$PREFIX/bin/openssl" list -providers \
    | tee /dev/stderr | grep -A3 -i 'fips' | grep -qi 'status: active' \
    || { echo "::error::the FIPS provider does not load from $cnf"; exit 1; }
echo "== FIPS provider active from $cnf"
