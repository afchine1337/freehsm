<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# FreeHSM v2.0.3

Third release in two days. The reason is the same each time: the people finding
these things run published binaries, and a fix on a branch does not reach them.

The module's cryptography is unchanged from v2.0.0. Two things change that a
consumer will see, and two claims are corrected — one of them in an evaluation
document.

---

## A module in test mode says so, where consumers read

Setting `FHSM_INTEGRITY_ALLOW_UNSIGNED` is a legitimate thing to do: it is how
you run a third-party test suite against a module you have just built. What was
wrong is that nothing downstream of the shell that set it would ever know.

    production        Library  FreeHSM C PKCS#11 module
                      Model    FreeHSM-C-v1

    bypass active     Library  FreeHSM C - TEST MODE, NOT PROD
                      Model    FreeHSM-TESTMODE

The module already warned on stderr. That is not a channel — a pipe, a
`2>/dev/null` or a harness that captures output all swallow it, and the reader
who most needs the warning is the least likely to be watching a terminal.
`CK_INFO.libraryDescription` is what `pkcs11-tool --show-info` prints, what
p11-kit lists, and what an application records when it logs which module it
loaded. It follows the module everywhere.

Suggested by the reporter of issue #3, whose own use of the bypass was
deliberate and correct.

## "FIPS 140-3" is out of the product name

`libraryDescription` read `FreeHSM C (FIPS 140-3)`. That is the first field an
evaluator or a packager sees, and it reads as a certification. FreeHSM holds
none and will not seek one — README, AGD_PRE, AGD_OPE, the Security Target and
every release note say so, and a 32-octet field cannot carry the qualification
those documents give.

Third artefact the claim has come out of: the library filename in v2.0.0, the
signed tag message on 2026-09-03, this. The standard is what the design targets,
not something the artefact may assert about itself.

Fourth, found while cleaning the documentation for this release: the English
README's first descriptive sentence said the module was *"designed to pass a
FIPS 140-3 Level 1 evaluation and an augmented Common Criteria EAL4+
certification"*. The French README has said the opposite for months. Corrected
to what is true — written to those methodologies, not to obtain either
certificate — and the French status table, which still listed CMVP and CC lab
submission as pending work rather than abandoned, now says so.

## The documentation stopped arguing with people who are not here

Several living documents were written as though this project were selling
something.

`docs/DESIGN_NOTES_COMMERCIAL_HSM.md` — notes taken from operating a commercial
network HSM — carried an indicative price table, six ready-to-use marketing
framings, an argument that a named company was a weakening incumbent resting on
third-party staffing rumours, support SLAs for an offer that has never been
sold, and a market entry window. All removed. What is kept is what can be
checked: the interfaces the product exposes and the interface version it ships,
its key hierarchy and restore semantics — which are good design and worth
adopting with published primitives — its documentation structure, its release
cadence with the trade-off stated in both directions, its cryptographic surface
including the post-quantum algorithms it does have, and the three properties a
hardware HSM has that no software module can have.

`docs/PRIMACY_AUDIT_PQC_COMPOSITE.md` was worse, and more interesting. It did
one good thing: in July it falsified *"first OSS PKI with PQC composite"*, which
was live in the README at the time, and had it removed. Then, having killed one
primacy claim, it constructed a narrower one and worked out the phrasing that
would survive an audit. That is not the same activity as finding out what is
true. The research it produced is kept — a dated, sourced picture of which
projects implement composite signatures, including the correction that SoftHSM2
does have ML-DSA and ML-KEM behind build flags, which stays visible because the
error had been used in an argument. The conclusion is now a rule: **FreeHSM
makes no primacy claim of any kind**, and does not describe this module as
implementing composite signatures, because it does not.

The roadmap's mission now names who this is for — researchers, students,
teaching institutions, public bodies and universities, and countries that cannot
buy a certified module — and states the two rules that follow: no value
judgements about companies, and no primacy claims. Other people's products may
be described where the description is checkable. They are not to be ranked, and
not to be used as a foil.

Nothing in the code changed for any of this. It is recorded here because a
reader who downloads a module is entitled to know what its documentation
claimed yesterday.

## The coverage matrix called itself evidence — twice wrongly

`tests/coverage_matrix.sh` exports three escapes by default:
`FHSM_INTEGRITY_ALLOW_UNSIGNED=1`, `FHSM_KAT_ALLOW_FAIL=1` and
`OPENSSL_CONF=/dev/null`. So the integrity self-test is skipped, a failing
known-answer test does not stop the module, and every EVP fetch is served
outside the boundary the Security Target defines. Its header nonetheless
claimed *"Self-attestation for FIPS 140-3 §7.11 functional testing"* and
*"Pre-cert evidence for the NIST CST lab"*, and
`docs/CST_LAB_SUBMISSION_CHECKLIST.md` listed it as a submission item.

That was corrected — and the correction was wrong in turn. It said the counts
inside the boundary were unknown. They are now measured:

    mode : evidence    PASS = 24   FAIL = 0   SKIP = 9   (total 33)

identical to the default run. **Nothing in this matrix depends on the three
escapes.** So the original claim was *true and unfounded*, which is a different
fault from being false: it was removed because nobody had checked. It can be
made again, on one condition — the matrix submitted must be one produced with
`FHSM_COV_EVIDENCE=1`, and the report header now states which mode produced it.

The switch had to be built before the measurement was possible. The three
defaults are `${VAR:-1}`, and `:-` substitutes on unset as well as on empty, so
unsetting them re-applied them; three call sites each re-applied the same four
assignments. One `cov_env` now decides the child environment.

## `make dist-verify` reproduces, and someone else proved it

The Docker entrypoint hashed the module **before** signing it, while
`baseline.yml` — which writes `dist/refs/` — signs first. Two artefacts, one
number, and the comparison could never agree. Fixed; image tag
`freehsm-build:1.1.0` → `1.2.0` so a cached image cannot mask it.

That was the fourth defect stacked on this path in three days, and the first
found here rather than by the external user who reported the other three. With
it closed, **four independent environments produced the same bytes for v2.0.2**
— including one machine unaffiliated with this project. See
`docs/REPRODUCIBLE_BUILD.md` §8. It is the row §7 has asked an evaluator to
produce since the document was written, and which nobody had ever produced.

## Also

* `make integrity` is idempotent. `sign_module.sh` exits 3 for "already
  signed", which is a state and not a failure; `release.sh` and `release.yml`
  both learned that on 2026-09-01 while the target they worked around did not,
  so running the documented command twice in a row failed.
* `xxd` removed from its last two sites. It is a separate package on Debian
  trixie and absent from the build image; in `run_fips_tests.sh` its absence
  produced an empty string that the script read as "no `.fhsm_digest` section",
  reporting a missing section rather than a missing tool.
* The matrix's identity assertion checked `libraryDescription` while recorded
  as "Manufacturer reported", and would have passed a module whose
  `manufacturerID` was empty. Now two assertions, each named for what it tests.
* **`ACKNOWLEDGEMENTS.md`** — who found what, specifically. Most of what has
  been fixed since v1.4.0 came from outside this project.

## Known and unchanged

`CK_TOKEN_INFO.model` still reads `FreeHSM-C-v1` on a v2.0.x module, against
its own comment ("stable across minor versions of the same major series").
Consumers may match on that string, so correcting it is an interface decision
rather than a fix to fold into a patch release.

## Verifying this release

    scripts/release.sh 2.0.3
