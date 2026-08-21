<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Simorgh Labs
-->
# The audit log's durability, and what it costs (#111)

**Status: decided and built.**

The previous measurement left this as the largest open question in #111: one
`fsync` per event caps the whole module at ~250 signatures/s, against ~1350
when the durable write is removed. A factor of five, traded against the
property the log exists for. `docs/RATE_LIMIT.md` recorded it; this settles it.

---

## First, the ordering — because it decides what each policy loses

In `C_Sign` the audit line is written **after** the signature is computed and
**before** the function returns. So on a power loss the two possible states are
not symmetric:

| | what is lost |
|---|---|
| **Today** — `fsync` before returning | At worst a record of an operation whose result the caller never received. A record with no delivery. |
| **Batched** — return, sync later | At worst a signature the client is holding, with no record that it was ever made. A delivery with no record. |

The first is harmless and self-evident on inspection: an entry exists for
something nobody used. The second is precisely the failure the log exists to
prevent, and it is undetectable afterwards — the missing line looks exactly
like an operation that never happened.

That asymmetry, not the throughput, is what makes this decidable. **A signature
must not reach a client before the record of it is durable.**

---

## What was measured

### Changing the syscall buys nothing

Per 302-byte append, 300 appends, on the same host as `probes/rest/`:

| | |
|---|---|
| `write` only, no durability | 0.001 ms — 1 844 000 lines/s |
| `write` + `fsync` (today) | 2.764 ms — 362 lines/s |
| `write` + `fdatasync` | 2.474 ms — 404 lines/s |
| `write` + `fdatasync`, file preallocated | 3.274 ms — 305 lines/s |
| `O_DSYNC`, no explicit sync | 2.832 ms — 353 lines/s |
| `O_DSYNC`, preallocated | 2.799 ms — 357 lines/s |

Everything lands between 2.5 and 3.3 ms. `fdatasync` is marginally cheaper than
`fsync`; preallocating — the trick that helps databases — did not help here and
was slightly worse. The cost is the durability barrier itself, not the call
used to request it. **There is no cheaper syscall.**

### Sharing the barrier buys almost everything

The barrier is expensive and *the same barrier serves every write that is
already pending*. Writers that arrive while one `fsync` is in flight can wait
for the next one instead of queueing their own — and still return only after a
barrier that covered their own write. The guarantee is unchanged; what changes
is how many barriers it takes.

| threads | `fsync` per writer | group commit | barriers used |
|---|---|---|---|
| 1 | 392 lines/s | 358 lines/s | 60 for 60 |
| 2 | 373 lines/s | **488** lines/s | 90 for 120 |
| 4 | 399 lines/s | **783** lines/s | 113 for 240 |
| 8 | 363 lines/s | **1469** lines/s | 118 for 480 |

At eight concurrent writers: four times the throughput, 118 barriers instead of
480, and every writer still returned after a barrier that covered it.

At one writer it is 9 % *slower* — the mutex and condition variable cost
something when there is nobody to share with. Worth stating plainly: this helps
a concurrent service and mildly penalises a single-threaded tool.

**So the ~250 sig/s plateau was never the price of durability. It was the price
of not sharing the barrier.** The current code holds the audit mutex across the
`fsync`, which is what serialises every other writer behind it.

---

## The decision

1. **Every event keeps a durable barrier before the operation returns.** No
   batching that lets a signature outrun its record. The asymmetry above is not
   a close call.
2. **The barrier is shared.** `fhsm_audit_event` releases the audit mutex
   across the barrier and lets concurrent writers be covered by one already in
   flight. Lines are still written under the mutex, so file order and HMAC
   order still agree — but the chain is *not* simply unaffected, as this point
   claimed before it was built: releasing the mutex means another writer reads
   the chain head mid-barrier, so the head has to advance before the barrier
   rather than after. See below.
3. **`fdatasync` rather than `fsync`**, as the marginally cheaper call with the
   same meaning for an append-only file. Worth ~10 %, and free.
4. **No preallocation.** Measured, did not help, and it would make the file
   size stop being a truthful indication of how much log there is.
5. The single-writer regression is accepted. A tool signing one certificate
   does not care about a fraction of a millisecond; a service serving eight
   clients cares about 242 → 674 sig/s.

### Built, and what it did to the module

| threads | before | after | with no durable write at all |
|---|---|---|---|
| 1 | 199 sig/s | 222 sig/s | 558 sig/s |
| 2 | 267 sig/s | 324 sig/s | 859 sig/s |
| 4 | 247 sig/s | **493** sig/s | 1359 sig/s |
| 8 | 242 sig/s | **674** sig/s | 1145 sig/s |

2.8× at eight concurrent signers, and the median latency there fell from 30.3
to 10.8 ms. The remaining gap to the third column is the rest of the module's
locking plus the barriers that still have to happen — this closed most of the
distance, not all of it.

The single-writer figure came out slightly *better* here and slightly worse in
the microbenchmark. Both are inside the run-to-run spread; the honest statement
is that group commit does not measurably help one writer and may cost it a
little, which is the trade named above.

**The ordering is the delicate part, and it is not the waiting.** The mutex is
released while the barrier runs, so another writer takes the lock and reads
`g_prev_hmac` in the middle of it. The chain therefore has to advance *before*
the barrier rather than after. Get that wrong and two lines claim the same
predecessor: every event still returns `OK`, the log still looks well-formed,
and only the verifier disagrees.

`tests/test_audit_concurrent.c`, eight threads × forty events. It asserts that
every event succeeded, that the barriers were shared (79 for 320, so the
sharing is observable rather than assumed), that the **chain verifies over the
whole file**, and that no line was lost. Two mutations, each caught by the
assertion meant for it:

* barrier back inside the lock → 320 barriers for 320 events, second assertion
  fails;
* chain advanced after the barrier → chain breaks at line 2, third assertion
  fails while the first, second and fourth still pass.

Clean under `SANITIZE=1`, and clean under ThreadSanitizer — which needs
`setarch -R` in a container, otherwise TSAN aborts on the memory layout before
it runs a single line.

---

## The defect found on the way — fixed

`fhsm_audit_event` checked `write()` and latched ERROR when it failed, then
called `fsync()` and threw the answer away.

On most filesystems a deferred write error is reported at `fsync` and nowhere
else. So the control that exists to stop the module when the log cannot be
written was wired to the call that usually succeeds, and not to the call that
usually reports. Both `fsync` calls in the key-provisioning code check their
return; this was the third and the only one that did not — the same shape as
#61, #49 and the `ulPinLen` defect.

Fixed: a failed `fsync` reports failure and latches ERROR, exactly as a failed
write does.

`tests/test_audit_fsync.c` stages it portably. `fsync` on a pipe returns
EINVAL while `write` to it succeeds, so the log is pointed at a FIFO with a
reader draining it: every write lands, every barrier fails, and nothing in the
audit code knows it is not a file. Four assertions; two fail with the check
removed.

---

## One log per opening — the defect that only shows with two processes

A hash chain has exactly one author by construction. Nothing here required it.
Two processes each opened the log, each resumed the chain from the tail of the
file, and from then on each believed itself the successor of the same line:

```
lines written by two processes : 60 (expected 60)
chain verifies                : NO
first broken line             : 2
```

Sequentially, the same two processes produce a chain that verifies. So it is
the concurrency, not the resume. Found through `p11-kit server`, which forks a
child per client and makes the situation systematic — but two `fhsm-sign`
invocations in a script do the same thing, so this is not a p11-kit problem.

Note what the group commit above does *not* do: it orders writers within one
process. It says nothing about two processes, and looking at the wrong axis is
why this was not seen while that work was being done.

### Why not simply refuse the second opening

That was the first instinct and it was wrong. `C_Initialize` opens the log, so
an exclusive lock would make `fhsm-sign` fail while `fhsm-ca` is running.
Concurrent tools are a Monday-morning script, not a corner case. Locking
between processes instead would put a file lock on a path that already costs
3 ms. So: **each opening creates its own file**, `base.NNNNNN`, with `O_EXCL`.
Every file then has a single author from line 1 and needs no coordination at
all — no lock, no restriction on concurrency, nothing on the hot path.

`chain_resume()` went with it. Resuming existed only to share one file between
openings; each log now starts at the chain head, and the function that made the
sharing possible is the function that made it dangerous.

### The numbering is not decoration

With one file, deleting the middle breaks the chain and deleting the tail is
undetectable — a gap already recorded. With per-file logs, deleting a whole
file would remove a process's entire history while every remaining chain still
verified. That would be a *new* way to erase history, and a worse one.

Sequence numbers make it a hole between 6 and 8, which `freehsm-audit verify
<directory>` reports and exits non-zero for. Deleting the highest-numbered
files leaves no hole — the same end-of-log truncation a single file already
permits. **The scheme reproduces the existing limit rather than adding one**,
and that is what makes it acceptable.

### What it costs the operator

Two things, both real.

*Ordering between files.* Within a file `seq` gives the order. Between files
there is only `ts`, which is `CLOCK_REALTIME` and moves under `date -s`.
"Review the log weekly" becomes "review the logs", merged on a clock an
attacker with root can shift. Stated here rather than discovered.

*One more file per start.* A daemon restarted three times leaves three logs.
That is the honest consequence of one author per chain, and archival has to
account for it.

A base that already exists and is **not** a regular file — a FIFO, `/dev/null`,
a character device — is opened as given, with no numbering and no chain to
resume. It is a stream, not a log, and the operator asked for it by naming one.

`fhsm_audit_current_path()` reports the file actually opened, because the caller
passed a base and should not have to reconstruct the naming rule.
`tests/test_audit_multiproc.c` asserts the three properties that matter: every
file verifies alone, the numbering is contiguous, no line was lost. It fails on
the first of those against the old single-file behaviour.

---

## Still open, and deliberately separate

**Whether the audit log should be optional at all.** The cost measured here is
real — a durable line costs more than the signature it records — and an
operator whose threat model does not include "who asked for this" is paying for
nothing. `FHSM_AUDIT_MANDATORY` already exists in `include/fhsm_common.h` as a
constant set to 1, referenced in three comments and **enforced nowhere**;
`docs/ROADMAP.md` calls it "a constant a comment describes as aspirational".

Meanwhile `FHSM_AUDIT_LOG=/dev/null` switches the log off today: silently,
undocumented, with the module still claiming a guarantee it is not providing.
That is the worst of both.

Making the switch real is a separate task, and its shape is already decided:
**optional, and explicit.** Off must be loud — announced at start-up, visible
in the token's flags, and never the accidental result of a path. The default
stays on for `fips-strict`; whether `interop` differs is an open question.

---

## Not measured here

**Confirmed on a second host, and here is what that took.** The figures above
come from a 2-core sandbox. Re-measured on a Debian 13 VM over VirtualBox,
ext4, five runs: **3.44 – 3.57 ms** per line, against 2.49 – 2.86 in the
sandbox. Same order, ~25 % slower for a virtualised disk, and a tighter spread
than the sandbox managed — 4 % across five runs. The ratio to the ~1 ms
signature holds, so the decision holds.

Getting there took one wrong turn worth recording. The first attempt on that VM
reported **0.003 ms** per line — a thousand times faster, which is not a fast
disk but no barrier at all. `mktemp -d` had landed in `/tmp`, which is `tmpfs`
by default on current Debian, so `fdatasync` returned without making anything
durable. The bench now names the filesystem it measured and refuses to let such
a number stand; see `docs/AGD_OPE.md` §4.2b, because an operator can do the same
thing to a real deployment by pointing `FHSM_AUDIT_LOG` at the wrong place, and
nothing would report it.

**Still not measured: storage a deployment would actually use.** Both hosts are
virtual machines. A hypervisor that acknowledges barriers without honouring
them produces the tmpfs result with none of the warning signs, and VirtualBox's
host I/O cache does exactly that. The absolutes should be taken again on the
hardware, or on something that has been proven to honour a barrier.

~~**Whether the module's own signing path can proceed during a barrier.**~~
Measured after building it: partly. 242 → 674 sig/s at eight threads, against
1145 with no durable write. So a signature can proceed during a barrier, and
something else — the rest of the module's locking — still costs the remaining
distance. Finding what is the next measurement, and it is now a normal
performance question rather than a design one.

---

## See also

* `docs/RATE_LIMIT.md` — where this was left open, and why it stopped being a
  tuning question.
* `docs/REST_API_DESIGN.md` §Scaling — the plateau this explains.
* `tests/bench_audit_rate.c` — the per-line cost.
* `probes/rest/README.md` — the last section, on what the log does to every
  number in that file.
