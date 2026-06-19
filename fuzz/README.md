# FreeHSM C — Structured fuzzing (#191)

libFuzzer + ASAN + UBSAN harnesses on the PKCS#11 v3.2 parser surfaces
that take untrusted input from a calling application :

| Harness | Target | Surface |
|---|---|---|
| `fuzz_ecdsa_raw` | `fhsm_ecdsa_der_to_raw`, `fhsm_ecdsa_raw_to_der` | DER ECDSA-Sig-Value ↔ raw r‖s wire format conversion (PKCS#11 v3.2 §6.13) |
| `fuzz_pq_params` | `fhsm_parse_pq_params` | `CK_ML_DSA_PARAMS` / `CK_SLH_DSA_PARAMS` 24-byte struct decoder (PKCS#11 v3.2 §6.18 / §6.19) |
| `fuzz_attr_template` | `fhsm_find_attr`, `fhsm_strip_octet_string_inline` | `CK_ATTRIBUTE[]` template lookup + DER OCTET STRING wrapper stripper |

The harnesses are sanitizer-instrumented (`-fsanitize=fuzzer,address,undefined`)
so any out-of-bounds read, signed-integer overflow, uninitialised value, or
use-after-free is flagged as a crash with a full stack trace.

## Toolchain

| Component | Version | Debian package |
|---|---|---|
| clang | ≥ 12 | `clang` |
| OpenSSL dev | 3.x | `libssl-dev` (or custom build at `/usr/local/ssl`) |

## Build

```bash
# All three harnesses
make -f fuzz/Makefile.fuzz

# Single target
make -f fuzz/Makefile.fuzz fuzz/fuzz_ecdsa_raw
```

Output : three sanitizer-instrumented executables in `fuzz/`.

## Run

Short run (good for a developer machine, ~5 min) :

```bash
./fuzz/fuzz_ecdsa_raw     fuzz/corpus/ecdsa_raw     -max_total_time=300
./fuzz/fuzz_pq_params     fuzz/corpus/pq_params     -max_total_time=300
./fuzz/fuzz_attr_template fuzz/corpus/attr_template -max_total_time=300
```

Long run (CI nightly, 1 h each) :

```bash
./fuzz/fuzz_ecdsa_raw fuzz/corpus/ecdsa_raw -max_total_time=3600 \
    -print_final_stats=1
```

Common flags :

| Flag | Meaning |
|---|---|
| `-max_total_time=N` | Stop after N seconds. |
| `-max_len=N` | Cap input size at N bytes. Default 4 096. |
| `-print_final_stats=1` | Print coverage / exec counts on exit. |
| `-jobs=N -workers=N` | Run N parallel workers. |
| `-rss_limit_mb=2048` | OOM threshold per worker. |

## Triage

When libFuzzer finds a crash, it writes a reproducer file in the cwd :

```
crash-<sha1-of-input>
leak-<sha1-of-input>
oom-<sha1-of-input>
timeout-<sha1-of-input>
```

To reproduce :

```bash
./fuzz/fuzz_ecdsa_raw crash-1f4...
```

The sanitizer output identifies the bug (ASAN report, UBSAN report,
libFuzzer-internal crash) with file:line and a full stack trace.

To minimize a crash (shrink the input to the smallest reproducer that
still crashes) :

```bash
./fuzz/fuzz_ecdsa_raw -minimize_crash=1 -runs=1000000 crash-1f4...
```

The minimised reproducer goes into `minimized-from-<original-name>`.

## Crash policy

Any crash on the production code surfaces these harnesses target
**must** be treated as a security finding :

1. **Triage** the reproducer in a private GitHub issue.
2. **Confirm** the bug is in the target helper, not in OpenSSL or
   libc.
3. **Fix** in `src/fhsm_*.c` ; **add a regression test** in
   `tests/` that exercises the minimised reproducer.
4. **Backport** the fix to all supported release branches if the
   surface is reachable in any deployed configuration.
5. **CVE** if the surface is reachable from an untrusted PKCS#11
   caller (e.g. a remote signing request via a network HSM proxy).
   Coordinate disclosure per `SECURITY.md`.

The CC EAL4+ ALC_DVS evidence base expects every reported crash to be
followed by a tracked corrective action ; do not close issues
silently.

## Property invariants checked

Beyond plain memory-safety (sanitizer-flagged), each harness checks
structural invariants that should hold for every input :

**`fuzz_ecdsa_raw`** :
- **Round-trip closure** : `der_to_raw(raw_to_der(r‖s)) == r‖s` for
  every well-formed `r‖s` with components ≤ curve order. Violation =
  silent corruption of an ECDSA signature in production.
- **Length-vs-buffer accounting** : `der_to_raw` on a truncated input
  must not access bytes beyond `der_len`. Violation = OOB read.

**`fuzz_pq_params`** :
- **No-context invariant** : when `*out_have == 0`, `*out_ctx_len == 0`
  must hold (the parser must not leave a partial context in the
  output). Violation = potentially leaking stack memory across PKCS#11
  calls.
- **Bounds clamp** : `*out_ctx_len <= out_ctx_cap` on every output.
  Violation = OOB write inside the harness scratch.
- **HedgeVariant verbatim** : when `*out_have == 1`,
  `*out_hedge_variant == params[0]`. Violation = silent corruption of
  the FIPS 204 / 205 hedge selector.
- **Rejection on short input** : `param_len < 24` must produce
  `*out_have = 0, *out_ctx_len = 0`. Same for `param_ptr = NULL`.
  Violation = parser accepts undersized struct.

**`fuzz_attr_template`** :
- **Range invariant on `fhsm_find_attr`** : return value is always in
  `{-1, 0, 1, …, count-1}`. Violation = OOB write somewhere
  downstream that uses the index.
- **Type match** : when `fhsm_find_attr` returns `idx >= 0`,
  `template[idx].type` equals the requested type. Violation = silent
  type confusion bug.
- **OCTET-STRING pointer arithmetic** : on accept,
  `out` is in `[data, data + size]` and `(out - data) + out_len ==
  size` (no slack). Violation = parser allows length-vs-buffer
  discrepancy that would cause OOB read downstream.

## Seed corpora

Each harness ships with 2–4 seed inputs in
`fuzz/corpus/<harness>/`. These bootstrap libFuzzer's coverage map ;
the fuzzer mutates them to discover new code paths.

Adding a seed (e.g. an interesting crash reducer found by hand) :

```bash
cp my-interesting-input fuzz/corpus/ecdsa_raw/seed_my_input
```

The seed corpus is committed to git so CI fuzz runs start from the
same baseline as developer machines.

## CI integration

`.github/workflows/fuzz.yml` runs short fuzz runs on every push to
`main` (5 min per harness, fail on crash) and longer runs nightly (1 h
per harness, upload corpus + crashes as artifacts).

The nightly run discovers and minimises new crashes ; the
short-on-push run catches regressions introduced by code changes that
affect a parser surface.

## Maintenance

The harnesses use **layout-compatible mirrors** of the parser helpers
defined in `src/fhsm_*.c` (see `include/fhsm_attr_utils.h` and the
extracted TUs `src/fhsm_ecdsa_raw.c` / `src/fhsm_pq_params.c`). When
the production code changes :

| Production change | Action |
|---|---|
| ECDSA helpers (`fhsm_ecdsa_*`) | None : `src/fhsm_ecdsa_raw.c` is the production code linked into the harness. |
| PQ params parser (`fhsm_parse_pq_params`) | None : same, linked into harness. |
| `find_attr` (still inline in `src/fhsm_pkcs11.c`) | Re-sync `fhsm_find_attr` in `include/fhsm_attr_utils.h`. |
| `fhsm_strip_octet_string` (still inline in `src/fhsm_pkcs11.c`) | Re-sync `fhsm_strip_octet_string_inline` in `include/fhsm_attr_utils.h`. |

Once `C_CreateObject` itself is decomposed (see roadmap), the two
inline mirrors collapse into a single production TU and the
maintenance row goes away.
