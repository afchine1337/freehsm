# PR notes — two small corrections to pkcs11-check

Two changes, neither of them a request to add us: you already did that.

## 1. `docs/providers.md` — our repository was renamed

```diff
-| FreeHSM (C) *(ASAN)* | C | [afchine1337/freehsm-c](https://github.com/afchine1337/freehsm-c) |
+| FreeHSM (C) *(ASAN)* | C | [afchine1337/freehsm](https://github.com/afchine1337/freehsm) |
```

The repository moved from `freehsm-c` to `freehsm` during a rebrand. GitHub
redirects renamed repositories, so the current link is not broken — this is
tidiness, not a fix, and entirely at your discretion.

The label `FreeHSM (C)` is still correct and worth keeping: there is a separate
Python implementation, and the C one is what you exercise.

## 2. `tests/test_wrap_context_cache.py` — a vendor name left in prose

Line 4 of the module docstring:

> ...leaking objects (observed as `CKR_HOST_MEMORY` on freehsm-c) and...

`4ae72ae` ("vendor-neutralize provider names in prose, fingerprint env, and
conformance gating") appears to have missed this one. It is the only remaining
provider name in prose outside `docs/providers.md` and the CHANGELOG, where
naming is deliberate.

Suggested:

```diff
-round-trips per KAT vector, leaking objects (observed as CKR_HOST_MEMORY on freehsm-c) and
+round-trips per KAT vector, leaking objects (observed as CKR_HOST_MEMORY on one provider) and
```

We noticed it only because it is our name; the point is your own stated policy
rather than any objection from us. If you would rather keep the attribution, we
have no issue with it — the leak was real and it was ours.

---

For context, since it explains why we were reading this closely: we ran v0.1.8
against FreeHSM today. 4 failed, 1697 passed, 0 crashed. Two of the four are
positions we hold deliberately and have documented (the Tookan unwrap-template
default, and GCM IV-reuse detection). The other two are the subject of a
separate issue about the `output_length` probe.

— Afchine Madjlessi, Simorgh Labs
