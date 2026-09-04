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
