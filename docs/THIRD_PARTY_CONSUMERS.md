<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Consumers we did not write

Measured 2026-09-01, Debian 13, OpenSSL 3.5.6.

A test suite written alongside a module tests what its author expected. A
consumer written by someone else calls what the specification says, in the
order it likes, and asks questions nobody here thought to ask. `p11-kit` was
the first of those and found a real limit — its RPC allow-list drops every
post-quantum mechanism, so remoting this module reaches RSA and ECDSA only
(`docs/P11_KIT_REMOTING.md`). This file records the next two.

Neither was run before. Both were installed on the development VM the whole
time.

## OpenSC `pkcs11-tool` — works

    pkcs11-tool --module ./libfreehsm.so --login --pin ... \
                --keypairgen --key-type EC:prime256v1 --label ec-plain

Generated the pair, read both objects back with their usage and access flags,
the `EC_POINT`, the `EC_PARAMS` OID, and built correct RFC 7512 URIs:

    pkcs11:model=FreeHSM-C-v1;manufacturer=Simorgh%20Labs;serial=FHSM-...;
    token=freehsm;object=ec-plain;type=private

It also printed two warnings, and they were ours:

    C_GetAttributeValue(SIGN_RECOVER)   failed: CKR_ATTRIBUTE_TYPE_INVALID
    C_GetAttributeValue(VERIFY_RECOVER) failed: CKR_ATTRIBUTE_TYPE_INVALID

`src/fhsm_pkcs11.c` wired seven usage attributes — `CKA_ENCRYPT`, `DECRYPT`,
`SIGN`, `VERIFY`, `WRAP`, `UNWRAP`, `DERIVE` — and not `CKA_SIGN_RECOVER`
(0x109) or `CKA_VERIFY_RECOVER` (0x10B). PKCS#11 defines both for every key
object. This module implements neither recover operation and never will, but
"not supported" and "I do not know this attribute" are different answers, and
a caller asking about capabilities got the second. **Fixed**: both now return
`CK_FALSE`. Seven wired and two unwired is the shape this project keeps
finding, and it took a third party to see it from outside.

## `pkcs11-provider` — works, except on a token holding a composite key

    export PKCS11_PROVIDER_MODULE=$PWD/libfreehsm.so
    openssl storeutl -provider pkcs11 -provider default -text \
        "pkcs11:?pin-value=..."

With an ordinary EC key in the token: the provider loads the module, opens the
slot, reads its label, asks for the PIN, and `openssl` prints the P-256 public
key, its SPKI in PEM, and the private key with its URI. `Total found: 2`. An
OpenSSL application can use this module as a key store.

With a composite key in the token, the whole slot fails:

    p11prov_obj_find ... objects.c:1184: Failed to store object
    store_fetch      ... store.c:144:   Failed to load keys from slot (0)

Not the composite key alone — everything. A token with an EC key *and* a
composite key enumerates nothing.

**Whose limit this is.** `CKK_COMPOSITE_MLDSA65_ED25519` is `0x80004202`, and
`0x80000000` is `CKK_VENDOR_DEFINED`. PKCS#11 reserves that range so that a
module may hold objects a generic caller does not understand, and a consumer
walking a token is expected to skip what it cannot use. Failing the entire slot
on one unrecognised object is a robustness problem in the enumeration, not a
statement about the object. The same shape as the p11-kit finding, and
reportable on the same grounds.

Establishing it took a badly designed experiment first: the discriminating run
is a token holding *only* an ordinary key, and the first attempt left the
composite key in place alongside it, which decided nothing.

## What this does not say

`pkcs11-tool` generated an ordinary EC key here. No tool in this repository
does — `fhsm-csr keygen` makes composite pairs, so every token these tools
build contains an object `pkcs11-provider` will refuse. In practice that means
an OpenSSL application can use a FreeHSM token today only if the token was
provisioned by something else.

Signing through either consumer was not attempted. Enumeration is not use.

## To reproduce

    # third consumer, and the attribute warnings that are now fixed
    pkcs11-tool --module ./libfreehsm.so --login --pin userpin1234 \
                --keypairgen --key-type EC:prime256v1 --label ec-plain

    # second consumer, on a token with no composite object
    openssl storeutl -provider pkcs11 -provider default -text \
        "pkcs11:?pin-value=userpin1234"

Both need `FHSM_TOKENS_DIR` and, on an unsigned build,
`FHSM_INTEGRITY_ALLOW_UNSIGNED=1` — in the environment of *every* command, not
just the one that creates the token. Setting it on only one of two lines is how
the first attempt produced `Module initialization failed`, which was the
integrity check doing its job.
