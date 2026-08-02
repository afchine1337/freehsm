---
title: "Count the paths"
date: 2026-08-02
tags: [freehsm, pkcs11, fips, security, release]
---

# Count the paths

Two releases went out this week, and neither changelog is the interesting part.

v1.5.0 fixed something worth stating plainly, because it had shipped in every
signed build for months. A FIPS 140-3 module must verify its own integrity at
start-up: hash the binary, compare against an embedded digest, refuse to run on
a mismatch. FreeHSM had that check. It had never verified anything. A comment
above the digest slot explained that a `volatile` qualifier prevented the
compiler from folding the value — the rationale was written, the keyword was
not there, and GCC folded byte zero to a literal. Every correctly signed build
failed its own integrity check on that one byte, invisibly, because the entire
toolchain runs with the check's bypass enabled.

A mechanism exercised only from behind its own bypass is not exercised.

v1.6.0 fixes three memory- and concurrency-safety defects, raises the object
capacity, and adds RSA interop mechanisms. And putting the two releases side by
side is what made the pattern visible: seven of the defects in this campaign
are the same shape, and I only started finding them reliably once I could name
it.

**A control wired to some of the paths that reach a state, and not the rest.**

## The tally

Shipped, and found by the harness or by instrumentation:

| Control | Covered |
|---|---|
| `CKA_TRUSTED` | 1 of 3 creation paths |
| `CKA_UNWRAP_TEMPLATE` | 2 of 3 |
| `fhsm_check_ro_token` | 3 of 6 |
| `fhsm_apply_token_scope` | 5 of 6 |
| input length bound | 2 of 8 entry points |
| the `prelim` bound | enforced on the write, not the read |

Caught during implementation, before shipping, by counting the sites instead of
trusting a search-and-replace:

| Control | Covered on first attempt |
|---|---|
| object metadata attributes | 6 of 8 creation paths |

Seven instances. Each one, alone, looks like an oversight; seven is a property
of the codebase. PKCS#11 has six routes to "an object now exists" and eight to
"data was submitted to an operation", and nothing in C makes a rule follow a
state. You write the check where you happen to be looking.

The last row of the first table is the same shape seen sideways: a bound applied
to one direction of an access and not the other. `C_FindObjectsInit` bounded its
writes into a buffer and then read back a count that could exceed it, returning
stack bytes to the caller as object handles.

## What it cost

The input-length one is the sharpest. `C_Encrypt` and `C_Decrypt` have rejected
lengths above 2 GiB since last year's input-validation work. `C_Sign`,
`C_Verify`, `C_Digest` and their three `*Update` variants never got it.

So a caller passes `ulDataLen = ISIZE_MAX` against a demand-zero mapping and the
module starts hashing. Not a wrong return code — a hang, until something kills
it. A denial of service from a single argument, on six of eight entry points.

The other two in v1.6.0:

**Decrypted private keys lived in pageable memory.** At rest, the object store
is AES-256-GCM under a PBKDF2-wrapped key, and that key sits in an `mlock`-ed
arena, excluded from swap. Every decrypted object value — private keys included
— was a plain `malloc` block. Zeroized on free, pageable while live. We locked
the vault key and left the jewels beside it.

**Two lazy initialisations with no lock.** Unreachable under PKCS#11's
one-process-per-application model, where a single thread gets there first.
Behind a network front end they are routine: two threads both find the slot
empty, both load the token, both assign. One leaks; the module ends up with two
objects for the same file, each with its own object store and its own login
state.

## How they were found, which matters more

Not by reading the code. I had read all of it, some of it many times.

The input-length one came from **listing all eight entry points and checking
each**, instead of reading the two I suspected. That is a dull technique and it
is the only one that has worked.

The races came from ThreadSanitizer — but the first version of the concurrency
test reported nothing, and I nearly concluded the module was thread-safe. It
was not the code that was clean: the main thread had completed the lazy
initialisation before the workers started, so the window was shut before anyone
looked. Releasing them from a `pthread_barrier` made both races appear, and even
then only intermittently — five warnings on two runs out of three.

A race the tool does not observe is indistinguishable from no race. That is
exactly how it would have reached production and surfaced under load.

The private-key one came from being asked how private objects are stored — a
question I could only answer properly by reading the allocation sites, which is
when I noticed the DEK and the keys it protects were in different heaps.

## What I got wrong

Three times I stated a diagnosis before measuring, and the measurement corrected
me. The config file did not "fail permissive" as I had written — the FIPS
enforcement is compile-time and sound; what was actually wrong was narrower,
nine config keys that no code read. The absence of a mutex in the PKCS#11 layer
did not mean its state was racing — it is partitioned by session handle. And
when the module failed to start I blamed the arena I had just changed; it was
the FIPS provider, absent from the machine.

I also introduced two defects while fixing others. `secure_heap_kb = 100`
aborted the module, because OpenSSL's arena requires a power-of-two size and I
had bounded the range but not the shape. A configuration typo must not crash an
HSM.

The corrections are the useful part. Every one came from running something
rather than reasoning about it.

## Where it stands

361 → 2 real failures against Denis Mingulov's vendor-neutral `pkcs11-check`.
Crashes 7 → 0. The two that remain are documented design positions — the Tookan
unwrap default and GCM IV reuse detection — not backlog.

None of this would have surfaced without Denis Mingulov's `pkcs11-check`. It is
a vendor-neutral behavioural harness — over a hundred thousand checks, written
against the specification rather than against any implementation — and it found
in days what our own suite had missed for months. Its documentation asks you to
read findings as evidence to triage rather than as a verdict, and that framing
shaped how this entire campaign was run.

Two of our remaining failures turned out to be his rather than ours: tests that
asked a module to encrypt with a mechanism it only advertises for signing. I
sent a report with the `C_GetMechanismInfo` dump. It was fixed in 0.1.8 within
hours, and more thoroughly than I had proposed — checking the operation flag
rather than mere mechanism presence, applied across every RSA cipher test, plus
the second suggestion I had made almost in passing. That is a maintainer paying
close attention, and it is the reason a tool like this is worth building on.

A `_Static_assert` added in v1.6.0 then refused to compile the CI build, which
forces a large object count — and that override turned out to be a workaround
from when the default was 64, whose own comment said the real fix was destroying
session objects on close. That fix landed two releases ago. The assert did not
just catch a mismatch; it exhumed a workaround that had outlived its reason.

## The line

Every one of these was a control that existed. Written, commented, sometimes
tested. Just not present on every path that could reach the thing it protects.

The habit that finds them is not cleverness. It is enumerating the ways in --
every creation path, every entry point, both directions of an access -- and
checking each one, including the ones you are confident about. That is where
six of the seven came from.

Count the paths. It is dull, and it is the only thing that has worked.

---

*FreeHSM is an Apache-2.0 PKCS#11 library, published by Simorgh Labs. FIPS
140-3 and CC EAL4+ are targets, not claims: nothing here is certified.*
