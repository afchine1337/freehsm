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

* **FreeHSM** — the HSM *library* (`libfreehsm-fips.so`), PKCS#11 v3.2, built
  to FIPS 140-3 / CC EAL4+ requirements and documented with their evidence
  methodologies. Not certified. Apache-2.0.
* **Simorgh PKI** — planned tooling on top: CA + signing tool + operator + IaC
  modules (#112). **Not built.** Do not describe it as existing.
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
`tokens_dir` -> the `FHSM_TOKENS_DIR` env var, `audit_mandatory` -> a constant a
comment describes as aspirational, `audit_dir` -> nothing at all.

Fix shape: a real config parser reading the keys we actually ship, or a shipped
file containing only keys that exist. Either is defensible; shipping nine dead
keys and reading a tenth that is absent is not. Whichever is chosen, the
`mode`/`fips_strict` naming has to converge on one spelling.

## Phase 4 — v2.0.0-beta (target 2026-09-01) — **the MVP focus now**

| # | Task | Effort | Status |
|---|---|---|---|
| #112 | PKI tool (`fhsm-ca`, `fhsm-csr`, cert lifecycle, OCSP) + PQC composite sigs | ~14h **+ ~8h** | 🟡 Composite ML-DSA conforming and PKCS#11-reachable; `fhsm-csr` (keygen, PKCS#10, self-signed root), `fhsm-ca issue` (proof of possession verified, CA-set extensions, random serials, `subjectAltName`, `cRLDistributionPoints` over HTTP and LDAP) and revocation (`revoke` + `crl`, hand-assembled `TBSCertList` checked byte for byte against OpenSSL) all ship — the revocation chain is now closed both in the code and to a third party, since a verifier can find the list. **Remaining: OCSP, which stays behind the network work in #111** |
| #123 | Signing tool `fhsm-sign` L1+L2 (raw + CMS/PKCS#7), PQC-ready | ~10h | ⏳ **MVP multiplier** |

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
2. Revocation, then OCSP — OCSP is a network service and #111 is deliberately
   after the MVP, so CRL first. **CRLs now ship**; OCSP stays where it was,
   behind the service work.

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
| #111 | Network HSM via REST API | v2.5+ | The big architectural leap — wait for MVP validation **and #111-prep** |

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
