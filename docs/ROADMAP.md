# Simorgh Labs / FreeHSM — Roadmap

Authoritative, living roadmap. Provenance: the phased plan from the planning
session, reconciled against what has actually shipped, plus the commercial-HSM
design study (`docs/DESIGN_NOTES_COMMERCIAL_HSM.md`), the rebrand plan
(`../REBRAND_CHECKLIST.md`), the brand reference
(`docs/SIMORGH_LABS_BRAND_REFERENCE.md`), the pkcs11-check campaign
(`docs/PKCS11_CHECK_CAMPAIGN.md` + `PKCS11_CHECK_FINDINGS.md`), and the
the CC/CMVP evidence checklist (`docs/CST_LAB_SUBMISSION_CHECKLIST.md`, kept
as a methodological reference — no submission is planned).

**Mission.** FreeHSM exists to put auditable cryptography within reach of public
bodies, universities and countries that cannot buy a certified module. It is
built to FIPS 140-3 Level 1 and CC EAL4+ requirements and documented with their
methodologies; it holds no certificate and will not pursue one. A certificate
costs more than this project will ever have, and that cost is precisely the
barrier this project exists to route around. Nothing on this roadmap should read
as working towards a submission.

Legend: ✅ done · 🟡 partial · ⏳ pending · ♻ continuous

---

## Layering (keep these categories clean)

* **FreeHSM** — the HSM *library* (`libfreehsm.so`), PKCS#11 v3.2, built
  to FIPS 140-3 / CC EAL4+ requirements and documented with their evidence
  methodologies. Not certified. Apache-2.0.
* **The command-line tools** — `fhsm-token`, `fhsm-csr`, `fhsm-ca`,
  `fhsm-sign`, and the `fhsm-service` daemon. These **ship**, as part of
  FreeHSM and under the same licence. They are what #112 and #123 built.
* **Simorgh PKI** — the *product* on top: an operator, IaC modules, packaging,
  support. **Not built. Do not describe it as existing.**

  The distinction is worth keeping sharp in both directions. Saying the PKI
  product exists would be a claim about something nobody can download; saying
  the tooling does not exist has become equally untrue, and this line said
  exactly that until 2026-08-30 — after `fhsm-ca` had issued certificates,
  published CRLs and signed OCSP responses for weeks.
* Anti-pattern to avoid (study): do **not** blur HSM and KMS. KMS-like features
  (policy engine, cross-cloud key sync, FPE) are a **post-v2.0** tier.

---

## Status at a glance

Phases 1–3 are essentially **complete**. The remaining real work is **Phase 4
(v2.0 = PKI tool + signing tool)**, the **rebrand mechanics** (repo rename +
domains — content is already rebranded), and two small threads (#126, #116).

---

## Phase 1 — before v1.5.0 (critical)

| # | Task | Effort | Status |
|---|---|---|---|
| #118 | Audit primacy claim "first OSS PKI + PQC composite" | ~4h | ✅ `docs/PRIMACY_AUDIT_PQC_COMPOSITE.md` — claim revised (pivoted to "PKI + signing + composite") |
| — | Rebrand migration (repo `freehsm-c`→`freehsm`, brand everywhere) | ~10–12h | ✅ Content rebrand ✅, and the **repo rename is done on all three forges** — verified 2026-08-03 by `scripts/post_rename.sh --check`: mirror URLs, all three remotes, and a live 200 on `github.com/afchine1337/freehsm`. The domain purchases are **cancelled** (2026-08-03): the project uses `chaharsou.com`, already owned and already linking to the repository. Nothing pending. |

## Phase 2 — v1.5.0 (target 2026-07-20)

| # | Task | Effort | Status |
|---|---|---|---|
| #113 | Design notes "lessons from Trustway / Safenet / CipherTrust" | ~3h | ✅ `docs/DESIGN_NOTES_COMMERCIAL_HSM.md` |
| #108 | Token-store format doc (`TOKEN_STORE_FORMAT.md`) | ~2–3h | ✅ shipped |
| #110 | `CKO_CERTIFICATE` object support | ~3–4h | ✅ shipped (parser + store) |
| #125 | Integrate Denis Mingulov's pkcs11-check into CI | ~3–5h | ✅ shipped — plus a full hardening campaign (**361→<50 failures, 7→0 crashes**) |

## Phase 3 — v1.6.0 (target 2026-08-10)

| # | Task | Effort | Status |
|---|---|---|---|
| #107 | Session keys (`CKA_TOKEN=FALSE`) vs token keys | ~4h | ✅ session-object lifecycle implemented during #125 |
| #109 | TPM 2.0 sealing backend (machine-bound vault) | ~8h | ✅ three defects fixed, and **validated end-to-end against a real TPM 2.0** on 2026-08-03 — `scripts/validate_tpm_sealing.sh`, 9/9 phases including the PCR-change and reboot cycle. See below |
| #127 | Private-key values in the secure heap, not plain `malloc` | ~6h | ✅ v1.6.0 — arena 8 MiB, exhaustion is a hard `CKR_DEVICE_MEMORY`, `tests/test_secure_heap` |
| #128 | The shipped `freehsm.conf` was read by nothing | ~4h | ✅ v1.6.0 — real parser (`src/fhsm_conf.c`), two live keys, `tests/test_conf`; the install path bug (`$(PREFIX)/etc` vs `/etc/freehsm`) fixed after. **It did not "fail permissive"** — that claim was wrong and is retracted in the note below |

### #109 — validated against a real TPM 2.0 (2026-08-03)

The three defects are fixed, covered by regression tests that were checked
against the old code and fail on it, and the whole sealing lifecycle has now
been exercised against a real TPM 2.0 — a software-emulated one in a VM, which
is adequate here and in one respect better than discrete hardware: the
PCR-change scenario needs PCRs 0-7 to move and then return, which in a VM is an
extend plus a reboot rather than a firmware update on a machine you depend on.
What an emulated TPM cannot speak to is the hardware root of trust, which is not
what #109 is about.

`scripts/validate_tpm_sealing.sh`, nine phases, all passed:

| | |
|---|---|
| sealed companion written | 252 bytes — a real `TPM2B_PUBLIC` + `TPM2B_PRIVATE` |
| `/var/lib/freehsm/tpm` after sealing | **does not exist** — the DEK never reached a filesystem (#109.1) |
| login, healthy TPM | `CKR_OK`, unseal and constant-time DEK compare both real |
| PCR 7 extended, 8 logins with the **correct** PIN | `CKR_DEVICE_ERROR` ×8 (#109.3) |
| after reboot, correct PIN | `CKR_OK` — **the token reopens, no lockout** |
| after reboot, wrong PIN | `CKR_PIN_INCORRECT` — the counter still works |

The lockout row is the one that matters. `FHSM_PIN_MAX_FAILED` is 5: under the
old code the fifth of those eight attempts would have returned `CKR_PIN_LOCKED`
and the token would have been dead, killed by a PCR extension — the moral
equivalent of a BIOS update nobody would have connected to their HSM. The
exponential throttle would have made it unusable well before the fifth.

Two operator-facing gaps surfaced only because this was run for real, and both
are now in `docs/AGD_OPE.md`:

* **The persistent primary key at `0x81010001` must exist and the module does
  not create it.** The test TPM had no persistent handles at all, so every seal
  would have failed. Nothing in the documentation said to provision it.
* **The process running the module must be in the `tss` group.** `/dev/tpmrm0`
  is `crw-rw---- root tss` on Debian; without membership every TPM call fails
  with a TCTI permission error, which surfaces as `CKR_DEVICE_ERROR` with
  `tpm-unseal-failed` — the same signal as moved PCRs. Check the group before
  suspecting the PCRs.

`tests/test_tpm` and `tests/tpm2-stub.sh` remain what they were and are still
worth having: CI has no TPM, and the stub keeps the plumbing, the blob packing,
the thread-collision guard and the lockout policy under test on every commit. It
still proves nothing about PCR binding or the sealing crypto. That part is now
covered by the script above, run by hand, and the ROADMAP no longer claims
otherwise.

One thing left standing, deliberately: `TPM_PARENT_HANDLE` is hard-coded to
`0x81010001`. An operator whose TPM already uses that handle has no way to say
so. It belongs in `freehsm.conf` next to `secure_heap_kb` and `mode`, and is not
there yet.

### #127 — secure storage of decrypted private-key material (noted 2026-07-21)

At rest the object blob is AES-256-GCM under a DEK that is PBKDF2-wrapped
(200 000 iters) by the PIN, and the live DEK sits in the OpenSSL secure heap
(`mmap`+`mlock`, swap-excluded, zeroized on logout — `src/fhsm_memory.c`).

The gap: once a token is loaded, each object's decrypted value (`o->value` in
`src/fhsm_token.c`, lines ~390/435/487/1165) is a plain `malloc`. It is
zeroized on free, but while live it is **pageable** — the DEK is protected from
swap, the key material it protects is not. A module that `mlock`s the vault key
and leaves the private keys it guards in swappable memory is protecting the safe
and setting the jewels beside it.

Fix options:
1. Route `o->value` for `FHSM_OBJF_SENSITIVE` objects through
   `fhsm_secure_malloc`. Clean, but the secure-heap arena is fixed size
   (`FHSM_SECURE_HEAP_BYTES`); with `FHSM_MAX_OBJECTS=256` x
   `FHSM_OBJ_VALUE_MAX=2 MiB` the arena must be sized or the per-object value
   capped. Needs a little sizing design, not a one-line swap.
2. Minimum: document the limitation in `SECURITY.md` so nobody discovers it in
   an audit -- what the module keeps out of swap and what it does not.

Not a correctness bug (encrypt/decrypt round-trips are exact); it is a gap
between what the module protects and what it implies it protects. Surfaced
during the #125 close-out while auditing private-object storage.

**Sizing measured 2026-07-24** (DER private keys, OpenSSL 3.5.6), against the
current `FHSM_SECURE_HEAP_BYTES` = 256 KiB arena, for a full token of 256
sensitive objects:

| all 256 objects are | total | vs arena |
|---|---|---|
| AES-256 (32 B) | 8 KB | 0.03x |
| EC P-521 (223 B) | 57 KB | 0.2x |
| RSA-2048 (1 191 B) | 305 KB | 1.2x |
| RSA-4096 (2 347 B) | 601 KB | 2.3x |
| ML-KEM-1024 (3 266 B) | 836 KB | 3.2x |
| ML-DSA-87 (4 962 B) | **1.21 MiB** | **4.8x** |

So the clean option is viable but the arena must grow to ~2 MiB.

**Decision taken 2026-07-24 — exhaustion is a hard failure.** When the arena is
full, loading a sensitive object returns `CKR_DEVICE_MEMORY`; there is no
silent fallback to `malloc`. If the module cannot keep a private key out of
swap, it does not load it and says so. Falling back quietly would rebuild
exactly the lie this ticket exists to remove — a guarantee that holds until it
quietly does not. The cost is that an over-full token is unusable until the
operator raises `secure_heap_kb`, which is a configuration error with a clear
message, not a silent downgrade. Note that #128 must land first: the knob that would configure
this (`secure_heap_kb`) is advertised in the shipped config and read by nothing.

### #128 — the shipped config file is inert (noted 2026-07-24, heading corrected 2026-08-03)

`make install` writes `/etc/freehsm/freehsm.conf` containing nine keys:

```
fips_strict, audit_mandatory, secure_heap_kb, pin_max_failed,
pin_throttle_base_ms, pin_throttle_max_ms, pbkdf2_iterations,
tokens_dir, audit_dir
```

**None of them is read by any code.** The only key any parser looks for is
`mode` (`src/fhsm_mode.c`, `conf_says_fips()`), and `mode` is not in the file we
ship.

Two consequences, one benign and one not:

* `secure_heap_kb` is exactly the knob #127 needs, advertised and inert.
* An operator who writes `fips_strict = true` intending to harden the module
  gets **legacy mode**: the parser wants `mode = fips`, does not find it, and
  `compute_mode_locked()` falls through to `g_is_fips = 0`. The config file
  promises a control nothing enforces, and it fails in the permissive
  direction.

**Impact measured 2026-07-24 — this is truth-in-advertising, not a bypass.**
In an interop build, `FHSM_MODE` changes nothing on the PKCS#11 surface:

| interop build | mechanisms | GetMechanismInfo(RSA_PKCS) | C_EncryptInit |
|---|---|---|---|
| `FHSM_MODE` absent | 71 | 0x0 | callable |
| `FHSM_MODE=fips` | 71 | 0x0 | callable |
| `FHSM_MODE=legacy` | 71 | 0x0 | callable |

Because the enforcement that matters is compile-time on both paths:
advertisement goes through `fhsm_mech_advertised()`, a pointer comparison
against `dispatch_reject_fips` fixed when the table is generated; and the crypto
API gates on `fhsm_build_fips_strict`. The runtime mode reaches only the
KAT/dispatch path, which the PKCS#11 entry points do not use.

So the FIPS enforcement is sound and no non-approved mechanism escapes through
a misread config. What is broken is narrower and still worth fixing: the file we
ship promises runtime controls that do not exist, and the one key a parser does
read (`mode`) is absent from it and affects far less than its name suggests. It
is the same claim-what-you-cannot-enforce shape as the rest of #125, moved down
to the configuration layer.

Every shipped key names a real concept, but all are compile-time constants or
env vars: `secure_heap_kb` -> `FHSM_SECURE_HEAP_BYTES`, `pin_max_failed` ->
`FHSM_PIN_MAX_FAILED`, `pbkdf2_iterations` -> a hardcoded 200 000,
`tokens_dir` -> the `FHSM_TOKENS_DIR` env var, `audit_dir` -> nothing at all.

`audit_mandatory` used to be listed here as "a constant a comment describes as
aspirational", which it was. It is now enforced — `FHSM_AUDIT_MANDATORY`
decides whether `FHSM_AUDIT=off` is honoured, and the module refuses to start
when it is not (`docs/AUDIT_DURABILITY.md`). **It stays a build setting rather
than becoming a config key**, and that is deliberate: it is the distributor's
decision that nobody downstream may turn the record off, and a decision the
operator can edit into a file is not the distributor's. So the count of dead
keys is eight, not nine, and one of them was resolved by moving it out of the
configuration layer rather than into it.

Fix shape: a real config parser reading the keys we actually ship, or a shipped
file containing only keys that exist. Either is defensible; shipping eight dead
keys and reading a ninth that is absent is not. Whichever is chosen, the
`mode`/`fips_strict` naming has to converge on one spelling.

## Phase 4 — v2.0.0-beta (target 2026-09-01) — **the MVP focus now**

| # | Task | Effort | Status |
|---|---|---|---|
| #112 | PKI tool (`fhsm-ca`, `fhsm-csr`, cert lifecycle, OCSP) + PQC composite sigs | ~14h **+ ~8h** | 🟡 Composite ML-DSA conforming and PKCS#11-reachable; `fhsm-csr` (keygen, PKCS#10, self-signed root), `fhsm-ca issue` (proof of possession verified, CA-set extensions, random serials, `subjectAltName`, `cRLDistributionPoints` over HTTP and LDAP) and revocation (`revoke` + `crl`, hand-assembled `TBSCertList` checked byte for byte against OpenSSL) all ship — the revocation chain is now closed both in the code and to a third party, since a verifier can find the list. **OCSP ships too** (`ocsp-respond`, request file in, signed response out; `unknown` for a foreign issuer, nonce echoed per RFC 8954, checked byte for byte against OpenSSL on Ed25519). **The delegated responder ships too** (`issue --profile ocsp-responder` sets `extendedKeyUsage OCSPSigning` and `id-pkix-ocsp-nocheck`, 30-day default with a NOTE past 90; `ocsp-respond --responder-cert` refuses a certificate without the EKU or issued by another CA, and says that the issuer check compares names and not signatures). **Remaining: anything that listens — behind #111.** Note also that a composite signature cannot be made through `p11-kit server`: its RPC allow-list drops every post-quantum mechanism, so remoting the module reaches RSA and ECDSA only (`docs/P11_KIT_REMOTING.md`). A patch that lifts that limit is in `contrib/p11-kit/` -- built, measured, p11-kit's own suite passing (44/44 on master; the 525 figure was 0.24.0, where the patch had a bug master's suite caught), and **submitted on 2026-08-22**: issue [#778](https://github.com/p11-glue/p11-kit/issues/778) and PR [#779](https://github.com/p11-glue/p11-kit/issues/779). It overlaps [#745](https://github.com/p11-glue/p11-kit/issues/745) (mingulov), acknowledged on ours, with a technical objection raised on theirs. No maintainer response to either as of 2026-08-30 |
| #123 | Signing tool `fhsm-sign` L1+L2 (raw + CMS/PKCS#7), PQC-ready | ~10h | ✅ **shipped** — L1 detached raw signatures with streaming multipart, L2 detached CMS `SignedData` with signed attributes and a verifier that needs neither token nor key. Both assembled by hand where OpenSSL refuses a composite algorithm, and checked against its own output byte for byte |

### #112 — the composite signatures have to be built before the CA (2026-08-03)

Scoping #112 started by reading `draft-ietf-lamps-pq-composite-sigs-19` (IESG
state: RFC Editor Queue) against what the module actually does. They do not
match. `CKM_HYBRID_ED25519_ML_DSA_65` signs the bare message with both keys and
concatenates; the draft signs a message representative
`M' = Prefix || Label || len(ctx) || ctx || PH(M)`, passes the per-algorithm
Label down as the ML-DSA ctx, and serializes `(mldsaSig, tradSig)` under a
registered composite OID. Full analysis in `docs/COMPOSITE_SIGS_GAP.md`.

The mechanism itself is fine as a locally-designed PQ/T hybrid and keeps its
place. What was wrong was three citations claiming it followed the draft; those
are corrected.

**Consequence for this task.** A CA cannot issue draft-conforming composite
certificates on top of a non-conforming primitive, and a CA whose certificates
nothing else can verify is worth less than no CA. So the order is:

0. Composite ML-DSA proper. **The specification inputs are now all collected**
   (`COMPOSITE_SIGS_GAP.md`): OID `1.3.6.1.5.5.7.6.48`, Label
   `COMPSIG-MLDSA65-Ed25519-SHA512`, pre-hash SHA-512, and the exact `M'`
   construction. §10.4 recommends this very combination for applications that
   need SUF-CMA, and both its primitives are already in the module. Only the
   Appendix E test vectors remain to fetch. Roughly 8 hours, and it is the first
   thing that gets built.
1. `fhsm-csr` and certificate issuance on top of it.
2. Revocation, then OCSP. Both ship. OCSP was ordered behind #111 on the
   assumption that it is a network service; it is not, or need not be. The
   signed object is what OCSP is for, and `fhsm-ca ocsp-respond` produces it
   from a request file. Serving it over HTTP is a separate concern that a web
   server already solves, and keeping it separate meant OCSP did not have to
   wait for the service work at all. **What still waits for #111 is a
   responder that listens** — and a delegated responder certificate, which is
   what keeps the CA key offline in a serious deployment.

   One thing found while building them, worth recording because it shapes any
   future structure signed with a composite algorithm: OpenSSL can be made to
   emit a *certificate* carrying an algorithm it does not implement, because
   `X509_get0_tbs_sigalg` reaches the inner `AlgorithmIdentifier`. There is no
   CRL equivalent, so a `TBSCertList` has to be assembled by hand. The
   arrangement that makes that safe — hand-assemble only the envelopes, let
   OpenSSL encode every value, then require the result to match OpenSSL's own
   output byte for byte on an algorithm it *does* implement — is the pattern
   to reuse rather than rediscover.

The upside of finding this now: Appendix E is 150 pages of test vectors, so for
once the implementation can be checked against someone else's numbers instead of
our own. The existing KATs never caught this because they are self-generated —
they prove our verify accepts our sign, which any self-consistent construction
satisfies, including a wrong one.

**Claim discipline until then.** `PRIMACY_AUDIT_PQC_COMPOSITE.md` §5 rests on
"PQC composite signatures out-of-the-box". That describes a future release. No
README, announcement or landing text may say this module implements composite
signatures until the conforming one ships.

## Release process

`scripts/release.sh <version>` runs the pre-flight checks and refuses to
proceed until they pass. It performs **no git write operations** -- it checks,
prints the commands, and stops.

Written after v1.6.0, which took two retags for three uninteresting and
mechanically detectable reasons: a `sed` that did not match so the version
string stayed at the previous release (v1.5.0 had shipped identifying itself as
`1.4.0-FIPS` for two weeks for the same reason); the CHANGELOG step, a comment
in a copy-pasted block, skipped three times running; and
`git push --follow-tags` silently declining to overwrite a tag that already
existed on the remote, leaving the published tag on the wrong commit.

The check that cannot be recovered afterwards is the build profile: an interop
build ships the non-approved mechanisms live while every visible sign says
fips-strict.

### The reproducibility claim has never been anchored (noted 2026-08-15)

`dist/refs/` has held nothing but `.gitkeep` since 10 June, across six tagged
releases. `make dist-verify` therefore always took its fallback branch, which
builds twice in the same container on the same day and compares the two. That
proves the build is deterministic. It does not prove the published artefact can
be reproduced, which is the property a third party actually wants: take the
v1.5.0 tag, rebuild it today, obtain the bytes that were published in July.

Nothing was hiding this. The fallback prints which branch it took, `make
dist-baseline` exists to record a reference, and the release pre-flight simply
never asks whether one was recorded. A step that is available and never
required is a step that does not happen.

**Required as of 2026-09-01.** `scripts/release.sh` now has a check 8 that
fails when `dist/refs/v<VERSION>.sha256` is absent, and fails again if the
reference exists but nothing compared against it — a reference nobody checked
is the same non-verification in a new place. Both directions were exercised
before the check was committed.

The half of the property that was in doubt turns out to hold. Two builds of the
same tree in two different directories produce a bit-identical
`libfreehsm.so`:

    ee49f922f2db7b1d9a59c9a14cb994e9b6321a13d3e9630d29ae621db7b2f4d6

so `-ffile-prefix-map`, `--build-id=none`, `-frandom-seed` and the pinned
`SOURCE_DATE_EPOCH` are doing what they were added for. What was missing was
never the determinism; it was the anchor, and the requirement that one exist.

**The containerised build cannot have run.** `scripts/build_reproducible.sh`
mounts the tree `-v "${PROJ_ROOT}:/src:ro"` and the image's ENTRYPOINT is
`cd /src && make clean && make all && ...`. `make all` has to write objects,
the shared object, and everything `make generate` produces --
`include/fhsm_pkcs11_mechanisms.h`, `src/gen/fhsm_dispatch.c`,
`docs/MECHANISMS.md` -- all of them under `/src`. On a read-only mount none of
that is possible. The ENTRYPOINT is unchanged since v1.1.0 and `dist/refs/`
has never received a commit, so the honest reading is that this path has never
completed once.

That is also why the three defects below went unseen: they sit downstream of a
step that always failed first.

Fixing it is deferred, deliberately, because it touches the guarantee the
project advertises and deserves its own sitting. Three shapes to weigh:

* drop `:ro` -- one character, and gives up the property that a build cannot
  mutate its own source;
* copy `/src` to a writable directory inside the container and build there --
  keeps the source immutable, no Makefile change beyond `OBJDIR`;
* make the build entirely out of tree, objects and generated files and
  artefact alike -- the cleanest, and the most work.

Three defects found while looking at it, the last two fixed the same day:

* `dist-verify`, `dist_baseline.sh` and `dist_verify_ref.sh` each read the
  version with `grep -oP 'FHSM_VERSION_STRING\s*=\s*"\K[^"]+'`, which requires
  an `=` that a `#define` does not have. The pattern never matched. The recipe
  looked for `dist/refs/v.sha256` and the two scripts would have written and
  read `unknown` -- different wrong names, so a recorded baseline would never
  have been found even once it existed. Both now use the same `awk` form the
  rest of the file has always used.
* Objects moved out of tree the same day (`OBJDIR`), which is exactly the kind
  of change that can leak a path into a binary. It did not, but only the
  build-twice check could say so, because there is no reference to compare
  against.

What remains, and is not yet scheduled:

1. Record a reference for the current release and commit it under `dist/refs/`.
2. Make the release pre-flight refuse a tag whose reference is missing, in the
   same spirit as the profile and CHANGELOG checks.
3. Decide whether references for the six already-published releases are worth
   reconstructing. Rebuilding v1.1.0 in the pinned container is cheap; whether
   the result is meaningful depends on whether that container image is itself
   still reproducible, which nobody has checked.

Until (1) and (2) are done, "reproducible build" should be read as
"deterministic build", and the documentation should say so rather than let a
reader supply the stronger meaning on their own.

### The audit log (found missing 2026-08-17, implemented 2026-08-18)

**Status: written, chained, verifiable.** What follows is the record of what
was wrong, kept because the shape of the failure is instructive and because an
evaluator reading `git log` will find the same story.

`fhsm_audit_open()` was defined in `src/fhsm_audit.c`, declared in the header,
and **called from nowhere**. `g_audit_fd` therefore stays at `-1`, and
`fhsm_audit_event()` opens with a guard that returns `FHSM_RV_OK` and writes
nothing. Forty-nine call sites across `fhsm_pkcs11.c`, `fhsm_token.c` and
`fhsm_state.c` are silently inert.

Verified empirically, not only by reading: a full session — `C_InitToken`, SO
login, `C_InitPIN`, user login, key generation, attribute reads — produces
`slot0.tok` and no log anywhere on the filesystem.

`FHSM_AUDIT_MANDATORY` is defined as `1` in `fhsm_common.h` and read by no
code. The backpressure `fhsm_audit.h` describes — *"the module is latched into
the ERROR state ... no security-relevant action is allowed without a durable
trace"* — is not implemented either.

Found while correcting a mistyped command in `AGD_OPE` §4.3, which told the
Security Officer to review this log weekly. Both AGD manuals and both AGD_PRE
acceptance lists have been corrected to say plainly that the control does not
exist; the procedures are kept as the specification the implementation must
satisfy.

**Both open questions are now decided and implemented.**

*The key* is its own, never the token DEK — deriving it from the DEK would have
made the log writable only while logged in, leaving `login_fail`,
`login_locked` and `integrity_fail` untraceable, which are precisely the events
§4.3 tells the SO to investigate. It is sealed to the TPM when
`FHSM_TPM_SEALING` is on, and a 0600 file otherwise, so the control works by
default rather than only where someone enabled it. Four conditions refuse to
start rather than degrade quietly: a key readable by others, a blob that will
not unseal, sealing requested and unavailable, a key of the wrong size.

*The backpressure* latches `ERROR`, unconditionally, as the header always
promised. A full disk stops the module; that is defensible for an HSM and is
now stated in AGD_OPE §4.3 rather than discovered. Proved by lowering
`RLIMIT_FSIZE`, which fails at the same point a full disk does.

Wiring it up exposed what the dead guard had been hiding:

* **Five malformed call sites**, none of which had ever run, because
  `fhsm_audit_event` returned before reading its arguments. One passed an int
  where a `char *` was expected — written as if the API were `printf`. Fixed,
  and `__attribute__((sentinel))` now makes the compiler refuse the whole
  class; proved able to fail by removing one `NULL`.
* **Unbounded recursion in the backpressure itself**: a failed write latched
  ERROR, which emitted a state_transition event, whose write failed. Stack
  overflow, measured as a SIGSEGV the first time a write was made to fail.
  Guarded per-thread in the writer; the state machine now emits only on a real
  transition.
* **The chain restarted at every process start**, appending a second chain to
  the same file while `seq` went back to 1. `fhsm_audit_open` now resumes from
  the last line.
* **`fhsm_audit_verify` was a stub returning OK** without reading its
  arguments, and `tools/freehsm-audit` computed a different HMAC from a
  different chain head — two independent disagreements, neither visible while
  no log existed. Both now agree, and `tests/test_audit_verify.c` runs both
  against the same real log.

---

### The audit log's one uncloseable gap: truncation at the end (measured 2026-08-18)

The chain detects a modified record, a deleted one, an inserted one and a
reordered one -- `tests/test_audit_verify.c` proves all four against both
verifiers. It does not detect a log cut short at the end, and no check confined
to the file can: what remains is a shorter chain that verifies perfectly,
which is indistinguishable from a log that simply stopped there. It is the
same file.

The test asserts that case as *passing*, deliberately, so the limitation is
restated by every run rather than being absent from the list.

Closing it needs an anchor the forger does not control -- the last seq and
hmac, themselves authenticated, kept outside the log:

* **A companion file, updated on every event.** Detects truncation as long as
  the attacker lacks the chaining key, since the anchor is HMAC'd too. Costs
  one more `fsync` per event: about 2.7 ms on the measurement in
  `docs/TOKEN_STORE_FORMAT.md`, which roughly doubles the per-event cost.
* **Shipping the log off the host.** Detects it properly and also survives the
  host being taken, but adds a network dependency to a control that currently
  has none -- and belongs with #111 rather than before it.

Neither is chosen yet. Stating the gap is worth more than picking the cheaper
answer quietly.

---

### The fips-strict profile has never run against the FIPS provider (2026-09-01)

Found while asking a narrower question -- whether an external RAND could be
used for key generation under FIPS. The answer to that is still unknown. What
turned up instead is why it could not be asked here.

`src/fhsm_crypto.c` skips the provider entirely in dev mode:

    int dev_mode = (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED") != NULL);
    if (!dev_mode) {
        g_fips_prov = OSSL_PROVIDER_load(NULL, "fips");

and `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` is set on **every** test recipe in the
Makefile, in `scripts/run_pkcs11_check.sh`, and in the CI workflows.
`OPENSSL_CONF=/dev/null` is set alongside it, so no configuration could
activate the provider even if the shortcut did not exist.

Neither is a defect. The dev-mode shortcut is deliberate and its comment
explains it; `/dev/null` keeps EVP fetches on the default provider so the
harness is reproducible. What is missing is anywhere that says what follows:
**no test has ever run this module with the FIPS provider loaded.** The claim
in `docs/FIPS_140_3_SECURITY_TARGET.md` -- "all FIPS-relevant computations are
delegated to the FIPS-validated OpenSSL FIPS provider" -- is true of the code
and unobserved in operation. What `make tests` proves about `fips-strict` is
that the module *refuses* non-approved mechanisms, which is a test of the
refusal and not of the delegation.

This is the recurring shape at the level of the whole suite: a control wired to
a path no test reaches.

Attempted 2026-09-01 on the dev VM (Debian 13, OpenSSL 3.5.6, `fips.so` present
in the modules directory):

    openssl fipsinstall -out ... -module .../fips.so
    Failed to load FIPS module
    SELF_TEST_post:invalid state ; OSSL_provider_init_int:self test post failure

so the provider will not initialise there at all. Whether that is a version
mismatch between `fips.so` and the loaded `libcrypto`, or a module Debian ships
without intending it to be usable, is not yet established. Either way the
environment the Security Target describes has not been stood up.

### What reading the release path turned up (2026-09-01)

The Docker image is not the missing piece, and an earlier note here implying
otherwise was wrong. `build-image.yml` publishes
`ghcr.io/<owner>/freehsm-c-build:debian13-openssl-3.5`, and both `ci.yml`'s
`reproducibility` job and the whole of `release.yml` run **inside** it. The
published artefact is already built in the pinned environment.

Four things came out of reading it properly.

**Fixed in this pass.** `release.yml` ran
`make integrity || echo "WARN: ... (expected outside Docker image)"`. The
parenthetical was false — the job runs inside the image — and the `||` meant
a failed signing published an **unsigned** module, which carries the all-zero
`.fhsm_digest` and cannot initialise at all. Now its own step, with no `||`,
followed by one that reads the section back: a zero exit from `make integrity`
would not have been the assurance anyway, since `sign_module.sh` exits 3 when
the module is already signed.

Looking for the same defect elsewhere found it three more times, which is why
it was worth looking. `ci.yml` piped `make integrity` through `tee` in two
steps; a `run:` block uses `bash -e {0}` and therefore has no `pipefail`, so
the step took `tee`'s exit status and a failed signing passed — including in
the step that feeds the artefact upload, and thence the reproducibility job's
`build1`. `scripts/release.sh` treated any non-zero exit as failure and so
reported "make integrity failed" on every second run of the pre-flight. The
pattern is the one this project keeps meeting: a control wired to some of the
paths that reach a state and not the rest.

**The anchor, and why six releases went without it.** `release.yml` computed
`sha256sum libfreehsm.so` and published it beside the file — a receipt
that the download matches what was built, not an anchor that rebuilding the
tag in six months yields the same bytes. Nothing compared against a committed
reference.

Two things kept `dist/refs/` empty, and neither was reluctance.

The first was one line in `.gitignore`:

    dist/

with no negation anywhere in the file. **The reference could not be
committed** — not by someone who forgot, by someone actively trying.
`make dist-baseline` would write the file, print `NEXT STEPS: git add ...`,
and git would silently decline. The requirement was written down, the producer
existed, the pre-flight came to insist on it, and the door was locked. Nobody
had opened the directory to check, including the note above this one, which
said `dist/refs/` "held nothing but `.gitkeep`" — a guess. It did not exist.

`dist/` excludes the *directory*, and git does not descend into an excluded
directory, so `!dist/refs/*.sha256` alone would have changed nothing. The same
trap the `tests/` block was rewritten four times for, and whose comment says
so. Now `dist/*` with the path re-admitted down to the references, checked
with `git check-ignore` rather than read.

The second was that `make dist-baseline` needs Docker on the release machine,
and the dev VM has none. The documented path required something absent, and
the undocumented consequence was that no reference was produced.
`.github/workflows/baseline.yml` now produces it in the same image
`release.yml` runs in, on demand: it signs before hashing (the published
artefact is the signed one), builds twice and requires agreement before
printing anything, and refuses to overwrite an existing reference without an
explicit input.

`release.yml` compares against `dist/refs/v$VERSION.sha256` and fails when it
is absent or differs — a missing reference is a failure, not a skip, since
`if [ -f ... ]` there would recreate the situation this closes. It also fails
when the tag and `FHSM_VERSION_STRING` disagree.

**Still to do**, and it belongs to #172: the anchor that matters is v2.0.0's,
and it can only be taken once the version is bumped. Run the baseline
workflow, commit what it uploads, then tag. Until then `scripts/release.sh`
fails check 8, correctly.

**What the CI reproducibility job actually proves.** Two builds, same image,
same commit, compared. Determinism — which was never the part in doubt.

**A knob nobody reads.** `SOURCE_DATE_EPOCH` is `1717977600` in `ci.yml` and
`release.yml`, against `1735689600` in the image's own `ENV`. Inert today: the
Makefile reads it only in the `dist` target (tar mtime), the `.so` gets its
determinism from `REPRO_FLAGS`, and `release.yml` builds its tarball with
`git archive`. It contradicts the image and would begin to matter silently the
day anything calls `make dist` in CI. Left in place with a comment at the
point of use; it belongs to the anchor decision above.

---

**Before v2.0.0 drops the beta suffix**, one of these has to happen:
1. stand the provider up (a container with a known-good FIPS build if the VM
   will not), run the suite signed and without the dev-mode variable, and
   record what it says; or
2. state plainly, in the release notes and in the Security Target, that the
   operational environment is specified and not yet exercised.

The second is honest and cheap. The first is what the document currently
implies has already happened.

### Key generation and `fhsm_drbg`: the remedy was wrong, not the diagnosis (2026-09-01)

`RELEASE_v2.0.0-beta.md` said composite key generation does not draw from this
module's DRBG, and prescribed "a library context backed by `fhsm_drbg`".
`tests/probe_keygen_drbg.c` had already widened the diagnosis: all five
`EVP_PKEY_Q_keygen(NULL, ...)` calls in `src/fhsm_pkcs11.c` are on that path,
not only the composite one, and each draws a fixed 96 bytes — a cost that
cannot be key material.

The prescription was then measured, against the FIPS provider that #173 stood
up the same morning:

    control  RAND_bytes_ex(ctx): rc=1, drew 0 byte(s)
    r_generate entered 0 time(s), r_instantiate 0
    direct   EVP_RAND_generate: rc=1, entered 1 more time
    RSA-2048 / RSA-4096 / EC P-256 / ML-DSA-65 : 0 bytes each

The DRBG is live and callable — a direct generate on the public RAND enters it
and succeeds — and neither `RAND_bytes_ex` nor key generation reaches it while
the FIPS provider is loaded. Under `default`, on the same code, both do
(31574 / 77772 / 32 / 32, tracking key size).

**So a private `OSSL_LIB_CTX` with `RAND_set_DRBG_type` does not deliver the
property under FIPS.** Why it diverges is not established, and
`probes/spike_provider_rand.c` deliberately stops there: it does not change
the design decision, and claiming a mechanism we have not shown would be worse
than saying nothing.

**And the framing was the real error.** FIPS 140-3 requires the DRBG to sit
inside the validated boundary. Per `docs/FIPS_140_3_SECURITY_TARGET.md` the
validated module here *is* the OpenSSL FIPS provider — that is the delegation
#173 observed in operation. Keys generated by that provider coming from *its*
approved DRBG is that delegation working. Routing them through `fhsm_drbg`
would undo it. `fhsm_drbg` is the module's own generator for the things the
module itself produces — serial numbers (#124), object ids, blob nonces — and
that is the whole of its proper job.

What remains true and worth stating in the release notes: in `interop`, or in
any build without the FIPS provider, key material comes from OpenSSL's default
RAND. Not weak, not `fhsm_drbg`, and no longer described as a step that merely
has not been taken.

`tests/probe_keygen_drbg.c` stays as a watch. Its numbers are expected to stay
equal now, and the reason has changed from "nobody wired it" to "wiring it
would be wrong under FIPS".

### Resolved the same day (2026-09-01)

The first option happened. The `fipsinstall` failure above was a stale
`fipsmodule.cnf` being included while the new one was written; regenerating it
with `OPENSSL_CONF=/dev/null` made the provider active on the dev VM.
`scripts/run_fips_tests.sh` then measured, and the delegation holds.

The first pass covered only the tests that open the `.so` -- fourteen of them,
all passing, none falling back. The claim in the Security Target became
observed rather than only specified, including for `test_fips_digests`,
`test_composite_p11` and the three legacy-mechanism tests: the ones that could
have shown a mechanism the module offers and the provider does not serve. None
did.

**And then the rest of the suite, the same day.** The tests that link
`$(LIB_OBJ)` carry the all-zero `.fhsm_digest`, so they need the bypass that
skips the provider, and they were written up here as an unreachable limit.

They were not. The mechanism was already in the tree, wired to exactly one
test. `make test-integrity` signs the *test binary* --
`scripts/sign_module.sh ./tests/test_integrity` -- and runs it under
`env -u FHSM_INTEGRITY_ALLOW_UNSIGNED`. `sign_module.sh` patches any ELF
carrying the section, not only the `.so`, and the comment above that target
has said so since it was written. A capability connected to one of the paths
that needed it and not the rest: the recurring shape, this time in the build.

`scripts/run_fips_tests.sh` now copies each such binary to a temporary
directory and signs the **copy**. Signing in place would be wrong three times
over — `make tests` would need a FIPS provider on every developer machine and
in CI, a relink would leave an unsigned binary `sign_module.sh` refuses to
re-sign without `--force`, and signed artefacts would sit in `tests/` between
runs. On a fresh copy none of that arises. The working directory stays at the
project root so relative paths inside a test still resolve.

Final measurement, whole suite:

    16 tests open the signed .so                pass
    21 tests embed the module, signed as copies pass
    0 fell back to dev mode

`test_integrity` is not counted: `make test-integrity` drives it through
unsigned, signed and tampered on its own, and does so correctly.

One method note, because the first classification was wrong in an instructive
way. The split was made by grepping each `.c` for the string `dlopen`, which
misfiled `test_fork_child` and `test_session_cap` — they reach the module
through a helper in `tools/p11_util.h` and never write the word. Reading the
binary for a `.fhsm_digest` section answers the same question about the
artefact rather than about the source text, and puts them where they belong.

## Continuous / parallel

| # | Task | Cadence | Status |
|---|---|---|---|
| #116 | PQC watch (NIST + ANSSI + IETF + industry) → `docs/PQC_VEILLE.md` | quarterly ~1h | ♻ doc created 2026-07-24 (first entry: Wycheproof SLH-DSA absent, ML-DSA present) |
| #126 | PR to Denis's pkcs11-check README mentioning FreeHSM | after #125 | ✅ **already done, by him** — FreeHSM has been in `docs/providers.md` since `91f6853`. He also vendor-neutralized the README, so the task as written no longer applies. What remains is a courtesy PR: our repo was renamed `freehsm-c` → `freehsm` (`pr_pkcs11check_freehsm_url.md`) |

## Deferred — post-v2.0 stable

| # | Task | When | Notes |
|---|---|---|---|
| #106 | Exhaustive CC ATE_FUN test book | v2.0 stable +6mo | Worth doing for its own sake: a functional test book to CC ATE_FUN structure is both a real assurance gain and a teaching artefact. **Not for a submission** — there will not be one. |
| #111-prep | Thread-safety of the PKCS#11 layer (blocks #111) | ~10h | 🟡 v1.6.0 — the two lazy-init races fixed, `make TSAN=1` + `tests/test_concurrency` in tree. Points 2–5 of the note (session binding, per-identity throttle, audit actor) are REST-layer work and stay with #111 |
| #111 | Network HSM via REST API | v2.5+ | **Design decided, nothing built** — see [`REST_API_DESIGN.md`](REST_API_DESIGN.md). Four of the five prerequisites are closed, the audit log included. Measured first (`probes/rest/`): a stateless API does **not** make the login stateless, so authorisation has to live in the service on the client certificate, not on the token being logged in. Remaining: the per-identity throttle, and where the daemon's PIN comes from |

### #111-prep — the network boundary stresses things the single-process model hides (noted 2026-07-21)

PKCS#11's model is one process per application, so today each client has its own
copy of the module state and the absence of locking in `fhsm_pkcs11.c` is
harmless. A REST server inverts that: **one process serves N concurrent
clients**, and the module-level mutable state becomes shared. Do not start #111
until this is done and proven under ThreadSanitizer — exposing a
not-thread-safe core over a network is building the facade before the
foundations.

Consolidation points, in priority order:

1. **Locking — done 2026-07-24, and my reasoning here was wrong.** I had
   written that because `fhsm_pkcs11.c` contains no `pthread_mutex`,
   `g_op_*` / `g_slots` / `g_finds` were shared mutable state and "two
   concurrent requests are a data race, not a hypothesis". Absence of a mutex
   does not imply sharing: `op_slot()` returns `&table[hSession]` and `g_finds`
   is indexed the same way, so that state is **partitioned by session handle**,
   and handle allocation is serialised in `fhsm_session.c`. Eight threads x 40
   loops of concurrent digest, encrypt and find operations run clean under TSan.

   Two real races did exist, both lazy initialisation reached from
   `C_OpenSession` outside any lock: `fhsm_slot_table_init_once()` guarded on a
   bare flag instead of `pthread_once`, and `fhsm_slot_token()` did
   test-load-assign on `g_slots[slot].token` — two threads could both call
   `fhsm_token_load` and both assign, leaking one token and leaving two
   `fhsm_token_t` objects for the same file with independent object stores and
   login state. Fixed with `pthread_once` and a mutex; 12 runs clean afterwards
   against 5 warnings on two of three runs before.

   The method mattered more than the fix. The first test reported nothing,
   because main had completed the lazy init before the threads started and the
   window was already shut. Releasing them from a `pthread_barrier` made both
   races appear, and even then only intermittently. A race TSan does not observe
   is indistinguishable from no race — which is how this would have reached
   production and surfaced under load. `make TSAN=1` and
   `tests/test_concurrency` are in the tree.
2. **Session binding.** `CK_SESSION_HANDLE` is a process-local integer. Over the
   wire it must be bound to an authenticated client, or client A presents
   handle 3 and reads client B's session. The REST layer owns a
   client→sessions table, and the `C_CloseSession` teardown must also fire when
   a network connection drops, not only on an explicit call.
3. **Per-identity throttle.** The anti-brute-force throttle counts failures per
   token and survives restart (good), but not per source. A distributed
   attacker bypasses a global counter, and one noisy client can lock out a
   legitimate one. Needs a per-identity throttle at the REST layer on top of the
   token's.
4. **#127 is promoted from nice-to-have to prerequisite.** Decrypted private-key
   values in pageable `malloc` are a gap locally; on a server holding tokens
   open for many clients the swap-exposure window grows enormously. Ship #127
   before, or with, #111.
5. **Audit gains an actor.** `fhsm_audit.c` logs events but not who requested
   them. A network HSM needs client identity and request origin on every entry,
   or the log says "a signature happened" without saying by whom — the one
   question a network audit exists to answer.

---

## New design decisions to fold in (study Category B)

* **B1** Diátaxis documentation architecture.
* **B2** Portable key-blob format + `fhsm-export` / `fhsm-import` (sovereignty = freedom to migrate).
* **B3** Structured JSON logs (ECS/OTel) + Prometheus `/metrics`.
* **B4** Multi-source entropy pool (kernel DRBG + jitterentropy + TPM RNG + optional YubiKey/OpenTitan).
* **B5** K8s operator + Terraform provider + Ansible collection + Helm.
* **B6** SIEM plugins (Splunk/Datadog/Sentinel/QRadar) — Tier-4 monetization.
* **B7** Multilingual Tier-2 support (EN/FR/Persan/Arabic).
* **B8** Tier-2 SLA: 4h critical / 24h high / 5 business days medium-low.
* **B9** v3.x horizon: KMS + VM encryption + file encryption.

## Marketing claims (study Category C) — ready for the v2.0-beta landing

6 direct, defensible framings (verbatim in `docs/DESIGN_NOTES_COMMERCIAL_HSM.md`
§Category C): 20-year PKCS#11 lead, 23 signed releases + 3 GHSAs in 6 weeks vs
one version / 2 years, open token-store + migration tool, TPM tamper-resistance
at ~100× lower TCO, one year of incumbent maintenance ≈ a full EAL4+ evidence
package, "integrated crypto-engineering stack" vs "boxed HSM".

---

## The strongest insight — timing is the hidden strength

Bull/Atos Trustway has been in expert-flight for years and **no OSS project has
seriously taken over**. Each of these is individually a strong differentiator;
together they have **no OSS or commercial equivalent on the target geography**:

* 6-week release cadence vs their 2 years
* PKCS#11 v3.2 vs their v2.20
* integrated PKI + signing vs a boxed HSM
* DevOps-native vs zero cloud
* multilingual vs French-only
* **PQC composite** vs PQC-raw-only

The French OIV / defence / defence-industry market is actively looking for a
Proteccio alternative for exactly these reasons. The response arrives right as
they start searching. Entry window 2026–2027 (see GTM phasing).

## Go-to-market (study Category D)

| Phase | Timing | Action |
|---|---|---|
| 1 | v2.0-beta (2026-09) | Public announce, positioning vs Proteccio (claims C1–C6) |
| 2 | v2.0 stable (2026-12) | Reach the users this is for: public bodies, universities, teaching, and administrations without a certification budget |
| 3 | 2027-Q1 | Present at FIC 2027 (Lille) |
| 4 | 2027-Q2 | *(removed — an ANSSI CC EAL4+ evaluation is not affordable and is not the objective; see Mission above)* |
| 5 | 2027-Q3/Q4 | MENA / Africa (GISEC, Black Hat MEA, Africa Cyber Defense Forum) |

## Honest scope boundary (study Category E)

Target the ~99% of the market that does **not** need FIPS 140-3 Level 3
*physical* security. Not matched (and that's fine): dedicated hardware TRNG,
physical tamper detection with auto-zeroization, Level 3 physical posture.
Compensated with TPM measured boot + integrity attestation + audit-log tamper
evidence; a physically compromised host is a lost host in our model.
