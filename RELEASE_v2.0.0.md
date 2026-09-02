<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.0.0

The release the v2.0 line was for, without the beta suffix: `fhsm-token`,
`fhsm-csr`, `fhsm-ca` and `fhsm-sign` on top of a Composite ML-DSA
implementation that matches the draft's own Appendix D vectors byte for byte,
and `fhsm-service` behind them.

What separates this from `v2.0.0-beta` is not features. It is that four claims
the beta made on paper have been measured, and three of them turned out to
need correcting rather than confirming. That is the whole of the difference,
and it is set out below before anything else.

---

## What the beta asserted, and what measuring it found

### The FIPS provider — asserted, now observed

`docs/FIPS_140_3_SECURITY_TARGET.md` has always said that all FIPS-relevant
computation is delegated to the FIPS-validated OpenSSL FIPS provider. That was
true of the code and had never been seen to happen: every test recipe sets
`FHSM_INTEGRITY_ALLOW_UNSIGNED=1`, which is exactly what makes
`src/fhsm_crypto.c` skip `OSSL_PROVIDER_load(NULL, "fips")`. No test had ever
run this module with that provider loaded.

`scripts/run_fips_tests.sh` now stands the environment up and measures it:
**37 of 37 tests pass with the provider genuinely loaded, none fall back.**
The ones that could have exposed a mechanism the module offers and the
provider does not serve — `test_fips_digests`, `test_composite_p11`, the three
legacy-mechanism tests — did not.

Proof is positive rather than inferred: `tests/probe_fips_loaded` opens the
signed `.so`, calls `C_Initialize`, then asks
`OSSL_PROVIDER_available(NULL, "fips")`.

### Composite key generation and `fhsm_drbg` — the remedy was wrong

The beta said key generation does not draw from this module's DRBG, and
prescribed "a library context backed by `fhsm_drbg`". Measured against the FIPS
provider, that remedy does not work: the DRBG is live and callable, and
neither `RAND_bytes_ex` nor key generation reaches it. Why the two diverge is
not established and is not claimed.

**The framing was the error.** FIPS 140-3 puts the DRBG inside the validated
boundary, and per the Security Target that boundary is the OpenSSL FIPS
provider. Keys coming from *its* approved DRBG is the delegation working, not
a gap in it. §10.2 of the composite draft says the same independently: the
ML-DSA seed "MUST be the direct output of a FIPS-approved Deterministic Random
Bit Generator". `fhsm_drbg` is not one.

`fhsm_drbg` keeps its proper scope: what the module itself produces — serial
numbers, object ids, blob nonces.

**Still true, and now stated as a property rather than an unfinished step:** in
`interop`, or any build without the FIPS provider, key material comes from
OpenSSL's default RAND.

### Reproducibility — the anchor was impossible, not merely missing

`docs/ROADMAP.md` had asked since 2026-08-15 for a reference digest at
`dist/refs/vX.Y.Z.sha256`. Six tagged releases went out without one, and the
reason was one line in `.gitignore`: `dist/`, with no negation. **The reference
could not be committed** — not by someone who forgot, by someone trying.

Fixed, and the anchor now exists in force:
`.github/workflows/baseline.yml` produces the reference inside the same image
the release runs in, signing before hashing and requiring two builds to agree;
`release.yml` compares its build against it and **fails when the file is
absent or the digests differ**. A missing reference is a failure, not a skip.

### The proxy — measured, and one row of the guide was wrong

`docs/DEPLOYING_THE_SERVICE.md` said that when the proxy sets
`X-FHSM-Client-Subject` and the client also sends one, two headers reach the
daemon and it answers 400. Measured against nginx 1.18.0 by
`tests/proxy_nginx.sh`: **one** header arrives, carrying the proxy's value.
`proxy_set_header` replaces — which the configuration comment three lines below
that table already said. The 400 is kept and re-attributed to a proxy that
*adds* rather than replaces.

The subject-format table was right, exactly. And the hole the guide describes —
omit the one line and the client is whoever it says — is now asserted rather
than described: `CN=attacker,O=Example,C=FR` arrives intact.

---

## Read these before deploying it

### `fhsm-service` has still never run behind a proxy

The proxy *configuration* is measured, and that is where the security boundary
is: a header nginx never rewrites is indistinguishable, from inside the daemon,
from one nginx wrote. What has not been done is running `fhsm-service` itself
behind that configuration, end to end, with a token and a policy.

Its own guards are tested — `tests/service_guards.sh`, `service_budget.sh`,
`service_public.sh`, ThreadSanitizer clean under a saturating load — and no
deployment of it has been made or measured. Treat it as the part of this
release with the least operational evidence behind it.

### The specification is not published, and interop-only is a decision

`draft-ietf-lamps-pq-composite-sigs-19` is in the RFC Editor queue. Checked
2026-09-02: still `-19`, state moved 2026-08-26 to *In Progress (First Edit)*,
IANA at `RFC-Ed-Ack`, no RFC number assigned.

Two consequences with different fates. **Interoperability** — third-party CAs
accepting these requests — depends on publication and will lift.
**Membership of `fips-strict` does not, and will not.** §10.2 of the draft
disclaims its own standing before setting out a design goal addressed to
implementers seeking certification; FreeHSM seeks none. A mechanism enters
`fips-strict` by being approved, not by a specification arguing that it ought
to be. `CKM_COMPOSITE_MLDSA65_ED25519` is interop-only as a settled choice.

This is not a limitation of the implementation: the composite signatures match
the draft's Appendix D vectors byte for byte.

### Not certified, and not seeking certification

FreeHSM holds no certificate and will not pursue one. The evaluation documents
are published as worked examples; see *Certification* in `README.md`. Every one
of them now carries that notice — `docs/FIPS_140_3.md` was the last without it,
while its opening lines read "Target validation" and "Validation authority",
which read cold as a live engagement.

---

## Also in this release since the beta

* **`POST /ocsp` on the public listener**, answering from the same code
  `fhsm-ca ocsp-respond` uses, with the revocation database re-read on every
  query so a revocation takes effect without a restart.
* **A queue in front of the workers**, with `503` and `Retry-After` when it is
  full, and read/write deadlines so a connection that sends nothing cannot
  occupy a worker. Four silent connections used to stop the service.
* **`CKA_SIGN_RECOVER` and `CKA_VERIFY_RECOVER`** now answer `CK_FALSE`
  instead of `CKR_ATTRIBUTE_TYPE_INVALID` — found by OpenSC's `pkcs11-tool`,
  which is to say from outside.
* **Third-party consumers exercised**: `pkcs11-tool` works; `pkcs11-provider`
  works on a token with no composite object and fails the whole slot when one
  is present, which is a robustness limit in its enumeration and is reported as
  such (`docs/THIRD_PARTY_CONSUMERS.md`).
* **The release path no longer swallows a failed `make integrity`.** It ran
  `make integrity || echo "WARN..."` from a job that runs *inside* the image;
  a failed signing would have published an unsigned module, which cannot
  initialise at all. Three further occurrences of the same shape were found and
  fixed in `ci.yml` and `scripts/release.sh`.

The full list is in `CHANGELOG.md` — 72 entries under this version.

---

## Upgrading from v2.0.0-beta

A drop-in `.so` replacement; PKCS#11 wire compatibility is unchanged. The
token store format is unchanged. `fhsm-service` gains `--queue-depth`,
`--revocation-db`, `--ocsp-label`, `--responder-cert` and `--ocsp-days`; none
is required to keep an existing deployment working, and `LimitNOFILE=4096` is
now set in the shipped unit.

## Verifying this release

    scripts/release.sh 2.0.0

The pre-flight refuses to declare the tree ready without a reproducibility
reference at `dist/refs/v2.0.0.sha256`, and the release workflow refuses to
publish a build that does not match it. Both are new in this release, and both
exist because the property they check had been asserted six times without
being verified once.
