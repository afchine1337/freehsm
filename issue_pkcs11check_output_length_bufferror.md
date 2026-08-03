# `output_length` probe always exits 1 — `BufferError` in teardown, after a correct measurement

**Version:** `413222e` (v0.1.8)
**Component:** `src/pkcs11_check/testcases/_probes/output_length.py`, `_run_oracle` teardown
**Affected tests:** `TestEncryptOutputLengthTruncation::test_encrypt_oversized_length_rejects_or_honors`,
`TestDecryptOutputLengthTruncation::test_decrypt_oversized_length_rejects_or_honors` (and the AES-OFB/CFB siblings)
**Effect:** these tests fail for any module that does not crash, including a conforming one — and cannot report the truncation they exist to detect

Hello Denis,

Short version: the probe measures correctly, prints the right answer, then raises
in its own cleanup. Every run exits 1, so the test always fails, whatever the
module did.

## Observed

Against FreeHSM, harness v0.1.8:

```
Failed: C_Encrypt(AES_CTR, ulDataLen=0x100000008): subprocess failed with exit code 1
stdout: TARGET_RV:0x00000021
TARGET_RV_NAME:CKR_DATA_LEN_RANGE
```

`CKR_DATA_LEN_RANGE` is in `_OUTPUT_LENGTH_REJECT_RVS`, so `classify_negative_rv`
would have passed it. The verdict never ran: the probe process died first.

## Cause

`_run_oracle` (output_length.py, ~lines 188-221) passes the demand-zero buffers
through `ctypes.cast`:

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

`ctypes.cast` on a `from_buffer` array leaves the mmap's buffer export
outstanding. `del in_view` does not clear it, so `in_mm.close()` raises

```
BufferError: cannot close exported pointers exist
```

and the probe exits 1 having already printed its result.

## Reproduced in isolation

No PKCS#11 module involved — the exact code shape from `_run_oracle`, with the
FFI call replaced by a function returning `0x21`:

```
TARGET_RV:0x00000021
TARGET_RV_NAME:CKR_DATA_LEN_RANGE
Traceback (most recent call last):
  File "repro.py", line 37, in <module>
    if in_mm is not None:    in_mm.close()
BufferError: cannot close exported pointers exist
exit code = 1
```

Same stdout, same exception, same exit code as the real run.

Note that the cast objects are argument temporaries, already released when the
`finally` runs — the export survives them, and `gc.collect()` before `close()`
does not help either. I checked; it was my first guess and it was wrong.

## What works

Measured, same harness code, four variants:

| call form | `mmap.close()` |
|---|---|
| `ctypes.cast(view, POINTER(c_ubyte))` — current | **BufferError** |
| `ctypes.byref(view)` | OK |
| pass the array directly | OK |
| no FFI call at all (control) | OK |

`ctypes.byref(in_view)` is the smallest change and works: ctypes passes the
address exactly as `cast` did, and the export is released. Swapping the two
`cast` calls for `byref` makes the reproduction exit 0 with its output intact.

A `try/except BufferError` around `close()` also silences it, but leaves the
mapping alive until process exit — fine for a short-lived probe, though it hides
rather than fixes.

`output_length.py` is the only probe under `_probes/` that combines
`from_buffer`, `ctypes.cast` and an explicit `close()`, so the blast radius looks
limited to this file.

## Why it matters beyond a red line in a report

A module that *does* truncate would print `TARGET_RV:0x0` and `UNDERFILL:1`, and
then die in exactly the same place. The finding would be in the captured stdout
and the test would still be reported as "subprocess failed", not as
`accepted_invalid`. The probe cannot currently deliver the verdict it was written
for, in either direction.

## For the record, on our side

FreeHSM rejects `ulDataLen = 2**32 + 8` on AES-CTR with `CKR_DATA_LEN_RANGE`. We
verified that independently of the harness, in C, with the same two 4 GiB
demand-zero mappings and the same counter block. The guard has been in
`C_Encrypt`/`C_Decrypt` since July and its code comment names this test — it was
added because of the earlier output-length report. So the test did its job; it
just cannot say so.

Thanks again — and sorry for the noise if you already have this.

— Afchine Madjlessi, Simorgh Labs
