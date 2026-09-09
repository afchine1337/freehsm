<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Cross-validating two PKCS#11 modules

FreeHSM can be used as a reference implementation against which to test another
PKCS#11 module — including a hardware HSM.

The idea is ordinary and old: two independent implementations of one
specification, driven by the same test vectors. Where they agree, the vector
says little. Where they **disagree on a case both executed**, one of them is
wrong, or the specification is ambiguous enough that both are defensible. Either
finding is worth more than either report read alone.

This document describes the method, and — more importantly — what a divergence
does not prove.

---

## What this is not

**Not a benchmark, and not a scoreboard.** A module that passes more test cases
than another usually advertises more mechanisms; one that skips a whole family
is not failing it. Comparing totals is meaningless and this project does not do
it.

**Not a conformance verdict.** `pkcs11-check`'s own guidance applies: findings
are evidence to investigate, not judgements. A divergence tells you where to
look, not who is right.

**Not a claim about anyone's product.** FreeHSM holds no certification and seeks
none. If a divergence shows FreeHSM to be wrong, that is the ordinary outcome of
the exercise and the reason it is worth running.

---

## Method

Both modules are driven by Denis Mingulov's
[`pkcs11-check`](https://github.com/mingulov/pkcs11-check), which is
vendor-neutral and reads no FreeHSM code.

### 1. One harness, one corpus, for both runs

    pip install 'pkcs11-check==0.1.9'
    pkcs11-check fetch-data all
    pkcs11-check fetch-data --status

`fetch-data` is not optional. Without it the harness runs its embedded corpus —
about 4,000 vectors of 111,700 — and says nothing about the difference. This
project published counts for two months without noticing.

### 2. Run against each module

    bash scripts/run_pkcs11_check.sh /path/to/libfreehsm.so   ./reports/freehsm
    bash scripts/run_pkcs11_check.sh /path/to/other-module.so ./reports/other

The script writes `provenance.txt` beside each report: harness version, OpenSSL
version, module path and **module SHA-256**. Two runs whose provenance differs
in more than the module are not comparable, and the next step prints both blocks
so you can see it before reading anything else.

### 3. Diff by node-id

    scripts/compare_reports.py reports/freehsm/report.jsonl \
                              reports/other/report.jsonl

It reports four numbers — shared cases, present-in-A-only, present-in-B-only,
and **divergent** — then lists the divergences grouped by transition, so one
repeated behaviour reads as one thing rather than as forty findings.

Exit status is 1 when anything diverged, so it can gate a pipeline.

---

## Reading the output

### Divergence on a shared case

The section that matters. Both modules executed the case, and they disagree.

Three explanations, in the order worth checking:

1. **One implementation is wrong.** Read the vector and the specification
   clause. This is the productive outcome, whichever module it lands on.
2. **The specification is ambiguous.** PKCS#11 leaves real latitude —
   which error code to return, what to do with a parameter a mechanism does not
   use. Two defensible readings look identical to the harness.
3. **A deliberate position.** FreeHSM refuses short GCM IVs and refuses to
   unwrap with `CKA_SENSITIVE=False`; both are documented in
   `docs/PKCS11_CHECK_FINDINGS.md` as decisions, not defects. Another module may
   have its own, undocumented.

### Present in one run only

Almost always different advertised mechanisms, and almost never interesting.
The harness gates its cases on `C_GetMechanismList`, so a module that does not
offer ML-DSA has no ML-DSA cases at all — neither passing nor failing.

Read the two provenance blocks first. Different OpenSSL versions, different
harness versions, or one run made with `fetch-data` and one without will all
produce large asymmetries that say nothing about either module.

---

## A worked example

On 2026-09-09, two runs of FreeHSM against itself, two hours apart, differing
only in one commit:

    A: failed=10  passed=42355  skipped=29383  xfail=20223
    B: failed=2   passed=42363  skipped=29383  xfail=20223

    shared test cases : 91971
    only in A         : 0
    only in B         : 0
    DIVERGENT         : 8

      A=failed -> B=passed   (8 cases)
          test_error_path_kwp.py::TestCorruptedUnwrap::test_corrupted_unwrap[decrypt-kwp-aiv]
          ...[decrypt-kwp-padding]
          ...[decrypt-kwp-truncate]
          ...[decrypt-kwp-extend]
          ...[decrypt-kwp-length]
          ...[decrypt-kwp-random]
          ...[decrypt-kwp-all_ff]
          ...[decrypt-kwp-all_zeros]

Eight divergences, one cause: `C_Decrypt` had been writing into the caller's
buffer before the AES-KWP integrity check, on all eight forms of corruption the
harness tries. Zero cases present in one run only, because the module advertised
the same mechanisms both times.

That is what a clean comparison looks like: the difference is confined to what
actually changed, and the grouping names the behaviour rather than listing eight
symptoms.

---

## Prerequisites for a comparison that means something

* **Same harness version.** `pkcs11-check` 0.1.9 closed three failures that
  0.1.8 reported, with the module unchanged. `provenance.txt` records it.
* **Same corpus.** Both runs with `fetch-data all`, or neither.
* **Same OpenSSL, ideally.** Both modules delegate primitives; a version
  difference is a third variable.
* **Note each module's profile.** FreeHSM built `fips-strict` refuses
  mechanisms that the same source built `interop` accepts. A hardware module
  usually has an equivalent switch.
* **Keep the reports.** They are the only thing that lets a later run be
  compared to this one. Not in `/tmp`: a reboot cost this project a full-corpus
  measurement it could not explain afterwards.

---

## If you find a divergence in FreeHSM's favour

Tell us anyway. A module that only hears about its own defects gets a distorted
picture of where it stands, and a divergence that turns out to be FreeHSM's
error is the more useful of the two outcomes for us.

`SECURITY.md` covers anything that looks like a vulnerability; ordinary findings
belong in a GitHub issue. Reporters are credited by name in
`ACKNOWLEDGEMENTS.md`, with what they found — and not credited at all if they
prefer, which is worth saying explicitly for anyone testing on an employer's
time.
