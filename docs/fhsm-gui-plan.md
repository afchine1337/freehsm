# A desktop interface for the PKI tools — plan

Status: proposed, 2026-10-02. Nothing here is built yet.

## What is being asked

A graphical interface over what `fhsm-token`, `fhsm-csr`, `fhsm-ca` and
`fhsm-sign` do: token and keys, requests and issuance, revocation and OCSP,
signing. In two stages: first a tool for exploring the module, which shows
each PKCS#11 call it makes; then a tool for the operator of a small
certification authority, which guides and refuses mistakes.

## Decisions taken

| | Decision | Why |
|---|---|---|
| Form | Desktop application | No port is opened, so it is outside what `docs/ROADMAP.md` puts behind #111 ("anything that listens"); the PIN never leaves the process. |
| Toolkit | GTK 4, in C | The project's language, so the operations library is called directly. Native on Debian; LGPL, compatible with Apache-2.0. |
| Algorithms | The composite only, at first | What the tools do today: `FHSM_COMPOSITE_MLDSA65_ED25519_SHA512` is the only algorithm the PKI layer knows. Classical algorithms come later, in that layer, for the tools and the interface at once. |
| Name | `fhsm-gui` | Descriptive. Nothing that suggests a "Simorgh PKI" product, which does not exist. |

## What exists, and what is missing

**Exists, and is reused as it is.**

- `tools/p11_util.h` loads any PKCS#11 module with `dlopen`, drives it through
  standard calls only, and holds the "exactly one key with this label" rule
  and the PIN policy in one place. The tools work against any module that
  implements the composite mechanism, a hardware HSM included; so will the
  interface.
- `src/fhsm_composite.c` and `src/fhsm_revocation.c` encode everything: CSR,
  self-signed root, issued certificate, CRL, OCSP response, CMS, and the
  revocation database. They link standalone against libcrypto.

**Missing: the layer between the two.** The orchestration -- find the key by
label, sign through the module from a callback, read and write files, update
the revocation database -- lives in each tool's `cmd_*(argc, argv)`, about
1,400 lines across four tools. It cannot be called from an interface as it
stands, for two reasons:

1. **Errors end the process.** 35 `die()` calls in the tools and 10 `exit()`
   in `p11_util.h`. In a window, any refused PIN or missing key would close
   the application.
2. **Argument parsing and work are one function.** The interface has values,
   not an `argv`.

Calling the tools as subprocesses instead is not an option: they read the PIN
from `FHSM_PIN`, so the interface would have to put it in a child's
environment -- the thing the project's PIN rule forbids -- and would then be
parsing text written for people.

## Architecture

Three layers, and each tool ends up the thinnest one.

```
  fhsm-token  fhsm-csr  fhsm-ca  fhsm-sign      fhsm-gui (GTK 4)
       \          |        |        /               |
        argv -> values, print results          widgets -> values
                     \                         /
                      tools/pkiops.{c,h}   (new)
                operations: fhsm_rv_t + an error message, no exit,
                no stdout; the PIN in as bytes, never stored
                     /                         \
          tools/p11_util.h                src/fhsm_composite.c
          (module, slots, sessions,       src/fhsm_revocation.c
           find-by-label)                 (encoding)
```

**`tools/pkiops.{c,h}`.** One function per operation the tools offer today:
token info and init, keygen, CSR, self-signed root, issue, revoke, CRL, OCSP
response, sign and verify (raw and CMS). Each returns `fhsm_rv_t` and writes a
human-readable reason into a caller-supplied buffer. None prints, none exits,
none reads the environment. A PIN arrives as a pointer and a length, and the
caller zeroes it.

**The tools** keep their exact interface -- arguments, the PIN from
`FHSM_PIN`, output, exit codes -- and become argument parsing plus one call.
That is the regression net for the extraction: the existing tests that drive
the tools (`tests/audit_switch.sh`, `make revocation-db`, `make
ocsp-delegated`, the service tests) must pass unchanged, and a byte comparison
of tool output before and after, on a fixed token, shows nothing moved.

**`fhsm-gui`** calls `pkiops` from a worker thread (`GTask`): a PIN derivation
is 200,000 PBKDF2 iterations and an ML-DSA signature is not instant, and the
window must not freeze.

### The PIN

Typed into a `GtkPasswordEntry`, copied into a buffer the interface owns,
passed to `C_Login`, and the buffer and the entry cleared immediately after.
This is weaker than the module's own handling, and the plan says so rather
than hides it: GTK keeps entry text in ordinary heap memory, may copy it
internally, and none of it is locked against swapping. What the interface
guarantees is narrower -- the PIN is never in an argument, never in an
environment variable, never written to disk, and held for as short a time as
the toolkit allows. That limit goes in the interface's own documentation.

### The call log (stage 1)

`p11_util.h` already calls the module through a table of function pointers.
The exploration interface wraps that table: each call is recorded with its
name, a summary of its arguments, its `CK_RV` and its duration, and shown in a
pane. Never recorded: the PIN, `CKA_VALUE`, any private or secret material --
the same rule as the module's audit log.

## Stages

0. **Extract `pkiops`.** No interface yet. The four tools rewritten over it,
   the regression net green, the byte comparison clean. This is most of the
   risk and all of it is testable without a window.
1. **Exploration.** Load a module, list slots and tokens, log in, list keys,
   generate a key, the call log. Read-mostly.
2. **Requests and issuance.** CSR, self-signed root, issue a certificate.
3. **Revocation.** Revoke, publish a CRL, answer an OCSP request.
4. **Signing.** Sign and verify a file, raw and CMS.
5. **Operator mode.** Guided flows over the same operations, and refusals
   where the command line trusts its user: a certificate without a revocation
   pointer, a CRL left to expire, a key label reused.

   As built: a switch in the window, not a separate program. Operator mode
   swaps the Certificates and Revocation tabs for three guided ones (CA,
   Issue, Revoke) that work for one CA set once: its key, certificate,
   database, the file where its CRL is published, and that file's URLs. The
   refusals block; there is no "continue anyway", because exploration mode
   and the command-line tools remain for the exception. The CRL's expiry is
   read from the published file itself -- nothing new in the revocation
   database, whose format fhsm-ca and fhsm-service share -- re-read every
   minute, with a warning once less than a third of its validity is left.
   Issuing is refused while that file is missing or expired, so a CA's first
   act after its root is to publish an empty CRL. Every file the window
   writes is written to a temporary name and renamed into place.

## Open questions

- **Profile.** The composite exists only in `all-mechanisms` builds. Whether a
  signed `all-mechanisms` module can sign with it under the FIPS provider was
  to be measured, not assumed: the service tests refuse a
  `nist-approved-only` module for exactly this reason.

  Measured 2026-10-04, Debian 13, the packaged OpenSSL FIPS provider, a
  signed `all-mechanisms` build, `scripts/run_fips_tests.sh`: **it can.**
  The provider was shown loaded before anything was counted, no test fell
  back to the integrity bypass, and every composite test passed against it
  -- `test_composite_p11` and `test_pkiops` through the signed `.so`, and
  signed copies of `test_composite_sign`, `_cms`, `_crl`, `_csr`, `_issue`,
  `_ocsp`, `_prehash`, `_mprime` and `_x509`. ML-DSA-65 and Ed25519 are
  both served by that provider. 62 of 64 tests passed; the two that did not
  are about other mechanisms, recorded in `PKCS11_CHECK_FINDINGS.md`.
- **Testing the window.** The logic is tested through `pkiops` and the tools.
  Settled after stage 5: `tests/gui_smoke.sh` starts the window under Xvfb
  with a private session bus, closes it with `app.quit`, and fails on any
  GTK or GLib CRITICAL or WARNING -- the class of bug, close-time criticals,
  that reached a person on 2026-10-02. CI job `gui-smoke`.
- **Packaging.** Debian first; nothing else is planned.

## Alternatives set aside

- **Driving the command-line tools** -- the PIN would travel through a child's
  environment, and the interface would parse output written for people.
- **A local web interface** -- a listening service, behind #111, with an
  authentication model to design first.
- **Qt** -- more comfortable to write, but C++ in a C project, and a binding
  layer to the operations library.
