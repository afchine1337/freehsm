# `output_length` probe always exits 1 — `BufferError` in teardown, after a correct measurement

> **Status: NOT SENT.** Written 2026-08-03, corrected 2026-08-16, held back
> deliberately. See "Why this is not sent" at the end. The corrections are
> kept in place rather than tidied away, because the first version of this
> report asserted the opposite of what is now measured, and a reader who only
> sees the conclusion cannot tell which parts were checked.

**Harness version:** re-verified against `main` at `05e707c` (2026-08-03).
The probe file itself is unchanged since `3e6552e` (2026-07-07), so this
applies to v0.1.8 and to current `main` alike.
**Component:** `src/pkcs11_check/testcases/_probes/output_length.py`,
`_run_oracle` teardown
**Affected tests:** `TestEncryptOutputLengthTruncation::test_encrypt_oversized_length_rejects_or_honors`,
`TestDecryptOutputLengthTruncation::test_decrypt_oversized_length_rejects_or_honors`
(and the AES-OFB/CFB siblings)
**Effect:** these tests fail for any module that does not crash, including a
conforming one — and cannot report the truncation they exist to detect

Hello Denis,

Short version: the probe measures correctly, prints the right answer, then
raises in its own cleanup. Every run exits 1, so the test always fails,
whatever the module did.

## Observed

Against FreeHSM, harness v0.1.8:

```
Failed: C_Encrypt(AES_CTR, ulDataLen=0x100000008): subprocess failed with exit code 1
stdout: TARGET_RV:0x00000021
TARGET_RV_NAME:CKR_DATA_LEN_RANGE
```

`CKR_DATA_LEN_RANGE` is in `_OUTPUT_LENGTH_REJECT_RVS`, so
`classify_negative_rv` would have passed it. The verdict never ran: the probe
process died first.

## Cause

`_run_oracle` passes the demand-zero buffers through `ctypes.cast`:

```python
in_view  = (ctypes.c_ubyte * OVERSIZE_WRITE_LEN).from_buffer(in_mm)
out_view = (ctypes.c_ubyte * OVERSIZE_WRITE_LEN).from_buffer(out_mm)
rv = getattr(raw, op_fn)(
    sh,
    ctypes.cast(in_view,  ctypes.POINTER(ctypes.c_ubyte)),
    OVERSIZE_WRITE_LEN,
    ctypes.cast(out_view, ctypes.POINTER(ctypes.c_ubyte)),
    ctypes.byref(out_len),
)
...
finally:
    if in_view is not None:  del in_view
    ...
    if in_mm is not None:    in_mm.close()      # <-- raises here
```

`ctypes.cast` on a `from_buffer` array puts the view into a **reference
cycle**: the pointer keeps the array alive through its `_objects`, and the
array holds the mmap's buffer export. `del in_view` drops one name; it cannot
break a cycle. So the export is still outstanding when `close()` runs:

```
BufferError: cannot close exported pointers exist
```

and the probe exits 1 having already printed its result.

Because the first `close()` raises, the second mmap is never closed either —
the `finally` has no inner `try`.

## Measured

The reference behaviour, isolated from any PKCS#11 module. Same code shape as
`_run_oracle`: two demand-zero mmaps, two `from_buffer` views, `ctypes.cast`
on each, then `del` and `close()`. Run under three interpreters, with the
callee once a plain Python function and once a real foreign function
(`libc.memset` with `argtypes = [POINTER(c_ubyte), c_int, c_size_t]`), and
with the cast result once bound to a name and explicitly deleted, once left
anonymous:

| Python | callee | cast bound to a name | `gc.collect()` before `close()` | result |
|---|---|---|---|---|
| 3.10.12 | Python | no  | no  | **BufferError** |
| 3.10.12 | Python | no  | yes | close() OK |
| 3.10.12 | Python | yes | no  | **BufferError** |
| 3.10.12 | Python | yes | yes | close() OK |
| 3.10.12 | foreign | no  | no  | **BufferError** |
| 3.10.12 | foreign | no  | yes | close() OK |
| 3.10.12 | foreign | yes | no  | **BufferError** |
| 3.10.12 | foreign | yes | yes | close() OK |
| 3.12.13 | *(all eight)* | | | identical |
| 3.13.15 | *(all eight)* | | | identical |

Twenty-four runs, no variation. Deleting the cast result by name does not
help, which is what identifies this as a cycle rather than a stray reference.

**Correction to the first version of this report.** It stated that
`gc.collect()` before `close()` "does not help either" and that the cast
objects are "argument temporaries, already released when the `finally` runs".
Both are wrong. `gc.collect()` fixes it in every configuration above, and the
export survives precisely because the objects are *not* released — they are in
a cycle that refcounting cannot collect. The earlier claim came from a
reproduction that had its own retained references, and I did not catch it.

## Two fixes, and one that does not work

**Drop the `cast` and pass the array.** `raw` declares its argument types —
`metadata_std.FUNCTION_SIGNATURES["C_Encrypt"]` gives `CK_BYTE_PTR`, and
`raw/api.py` sets `func.argtypes` from it — so ctypes converts the array to a
pointer itself, without building the `_objects` cycle. Measured: `close()`
succeeds. This is the smaller and more honest change; it removes the cause
instead of cleaning up after it.

**Or `gc.collect()` before `close()`.** One line, works everywhere above.
Costs a collection per probe run, which is nothing at this scale.

**`ctypes.byref(view)` does not work**, and the first version of this report
recommended it. It does not type-check against the declared argtypes:

```
ctypes.ArgumentError: argument 1: TypeError: expected LP_c_ubyte instance
instead of pointer to c_ubyte_Array_4194312
```

`byref` yields a pointer *to the array*, not to its first element. The earlier
table listing it as "OK" was measured without argtypes in play, which is not
the situation in the probe.

One objection worth answering before it costs you time:
`_probes/_ckr_ctypes.py` builds its signatures from `type(a)` and says
explicitly not to switch to static argtypes. That is a different code path —
this probe goes through `raw`, which does declare them — so passing the array
is safe here and would not be in that bootstrap.

`output_length.py` is the only probe under `_probes/` combining
`from_buffer`, `ctypes.cast` and an explicit `close()`, so the blast radius
looks limited to this file.

## Why it matters beyond a red line in a report

A module that *does* truncate would print `TARGET_RV:0x0` and `UNDERFILL:1`,
then die in exactly the same place. The finding would sit in the captured
stdout while the test was reported as "subprocess failed", not as
`accepted_invalid`. The probe cannot currently deliver the verdict it was
written for, in either direction.

## What I did not verify

**I never ran the real probe.** Allocating the two 4 GiB demand-zero mappings
fails in the environment I had (`OSError: Cannot allocate memory`, 3.5 GiB
available). The reference-counting behaviour above was therefore measured at
4 MiB. Buffer exports do not depend on mapping size, so the mechanism carries
over — but the end-to-end claim rests on reading `_run_oracle` plus the
failing run quoted at the top, not on an execution of the probe itself with
the fix applied.

On a host with the memory, the check is: apply either fix, run the probe,
confirm exit 0 with `TARGET_RV` intact.

## For the record, on our side

FreeHSM rejects `ulDataLen = 2**32 + 8` on AES-CTR with `CKR_DATA_LEN_RANGE`.
We verified that independently of the harness, in C, with the same two 4 GiB
demand-zero mappings and the same counter block. The guard has been in
`C_Encrypt`/`C_Decrypt` since July and its code comment names this test — it
was added because of the earlier output-length report. So the test did its
job; it just cannot say so.

## Why this is not sent

Three reasons, recorded so the decision is not re-taken by default.

Of the last three things we prepared for you, two were already done on your
side before we wrote them: the CBC-PAD fix landed in `ad93ff9` four days
before we described it, and the FreeHSM repository link was updated by you in
`e3b8019` after our rename. A third unsolicited report, with no reply to the
previous one, stops being contribution and becomes pressure.

The subject does not justify it either. This is a cleanup defect in a test
harness, not a flaw in anything anyone deploys.

And `main` has been quiet since 2026-08-03. Holiday is the ordinary
explanation, and it is not a reason to add to an inbox.

Held for when there is an occasion — a reply, a release, or a question that
this answers. The content above is ready; check the probe file has not moved
before sending.

— Afchine Madjlessi, Simorgh Labs
