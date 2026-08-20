<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Simorgh Labs
-->
# The audit log's durability, and what it costs (#111)

**Status: decided, not built** — except for one defect found on the way, which
is fixed.

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
   across the `fsync` and lets concurrent writers be covered by a barrier
   already in flight. The chain is unaffected: lines are written under the
   mutex, so file order and HMAC order still agree — only the waiting moves
   outside.
3. **`fdatasync` rather than `fsync`**, as the marginally cheaper call with the
   same meaning for an append-only file. Worth ~10 %, and free.
4. **No preallocation.** Measured, did not help, and it would make the file
   size stop being a truthful indication of how much log there is.
5. The single-writer regression is accepted. A tool signing one certificate
   does not care about 0.2 ms; a service serving eight clients cares about a
   factor of four.

Not built. Point 2 is a real change to a file that latches the module into
ERROR when it goes wrong, and it deserves its own task with a concurrency test
— including one that asserts a writer cannot return before a barrier that
covered it, which is the property the whole design rests on.

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

## Not measured here

**Any of this on real deployment storage.** Every number above comes from a
2-core VM. The whole decision turns on the cost of one barrier, which is a
property of the disk, the filesystem and whether a write cache is honestly
reporting. The ratios should hold; the absolutes will not.

**Whether the module's own signing path can proceed during a barrier.** Group
commit helps only if a thread can compute a signature while another is inside
`fsync`. The audit mutex is not the only lock in the module, and the
measurement above is of the log alone, not of the module.

---

## See also

* `docs/RATE_LIMIT.md` — where this was left open, and why it stopped being a
  tuning question.
* `docs/REST_API_DESIGN.md` §Scaling — the plateau this explains.
* `tests/bench_audit_rate.c` — the per-line cost.
* `probes/rest/README.md` — the last section, on what the log does to every
  number in that file.
