<!--
SPDX-FileCopyrightText: 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0

A record of what was sent upstream, not a set of drafts. Both comments below
were posted on 22 August 2026 and are public. Do not edit them here expecting
that to change anything; the copies that matter are on GitHub.
-->

# Two comments on the overlap with p11-kit #745

After opening #779 we found #745 (mingulov, "Add basic PQC support"), open
since 11 March 2026 and covering much of the same ground. Two comments went
out on 22 August 2026:

| | where | what it does |
|---|---|---|
| **A** | [#779](https://github.com/p11-glue/p11-kit/issues/779) — our own PR | acknowledges the duplication before anyone else has to point it out, and says what is left in #779 that #745 does not cover |
| **B** | [#745](https://github.com/p11-glue/p11-kit/issues/745) — mingulov's PR | the technical question: `CKM_ML_DSA`, `CKM_SLH_DSA` and the `CKM_HASH_*` family should not be on the no-parameter list |

Posting A first was deliberate. Owning the duplication on our own thread costs
nothing; being told about it costs the benefit of the doubt.

## Verified after the fact — 27 August 2026

Both comments assert things about #745's branch. Five days after sending them,
those assertions were checked against the branch itself, commit `7fb676d`,
`p11-kit/rpc-message.c`. **They hold.**

* `mechanism_has_no_parameters()` begins at line 2425. Lines 2555-2582 list
  `CKM_ML_DSA` and `CKM_SLH_DSA` **bare** — not only the `_KEY_PAIR_GEN`
  forms — together with the whole `CKM_HASH_ML_DSA_*` and
  `CKM_HASH_SLH_DSA_*` family. Comment B's central claim is about what that
  branch actually does, and it is accurate.
* Standard `CKM_SHA3_*` is still absent from that function on that branch;
  only `CKM_IBM_SHA3_*` is present. Comment A's first point holds.
* #745's integration tests (`test-kryoptic.sh`, `test-nss-softokn.sh`) cover
  generate, export, import roundtrip and RPC forwarding. **None of them signs
  at all.** Comment B said "none signs with a context", which understates it:
  a silent context drop could not surface in that suite by any route.

Checking claims after publishing them is the wrong order. It happened to come
out right here; the discipline is to check first.

## One thing the sent version of A got weaker than it should have

A ends with:

> #745 is the bigger piece of work and should go first.

That was written before we knew #745 had stalled: `ueno` reviewed it
favourably on 12 March, mingulov rebased the same day, two CodeQL notices were
answered on 24 March, and review was re-requested from `ueno` on 8 April.
Nothing since, and at least one approving review is required to merge. As
written, A chains #779 to a review that has not moved in months.

The accurate position is that parts 1 to 3 of #779 stand on their own and do
not depend on #745 landing, so either order works.

**Do not edit the posted comment to say so.** Reworking an ordering offer after
the fact draws more attention than it earns, and remarking publicly on a
stalled review reads as pressure on volunteers. Say it in the thread when
someone replies — it will be a natural thing to mention then.

## What was actually sent

Reproduced so the repository holds a copy. If these differ from what is on
GitHub, GitHub is right.

---

### A — posted on #779, 22 August 2026

I have just found #745, which has been open since March and covers a good deal
of this. That is my fault for not searching before opening; apologies to
@mingulov for the duplication.

Read together, I think the overlap is smaller than it looks and the two are
complementary:

**#745 does better** — the mechanism enumeration itself, and far more besides:
`generate-keypair`, import/export, attribute value-type mapping, and real
integration tests against kryoptic and NSS. Nothing here improves on that.

**What is left in this PR that #745 does not cover:**

1. **Standard `CKM_SHA3_*`.** #745 adds the PQC families; the SHA-3 digests and
   HMACs, in PKCS#11 since 3.0, are still absent from the list — while
   `CKM_IBM_SHA3_*` is present.

2. **Mechanisms nobody enumerated.** This is the substantive difference.
   #745 extends the allow-list; this PR changes the *question* the allow-list
   answers, from "is this type known" to "can this call be serialised", which
   is true whenever the caller supplied no parameter. That carries vendor
   mechanisms — the case that motivated me, a module using a private mechanism
   value for composite ML-DSA + Ed25519 signatures — and it will keep carrying
   the next standard mechanism without anyone editing a list.

3. **`C_GetMechanismList` stops being trimmed** (part 4), which is separable
   and which I am happy to drop.

I have also left a comment on #745 about `CKM_ML_DSA` and the `CKM_HASH_*`
family, which I believe should not be on the no-parameter list. That is a
question about that PR rather than a claim about this one.

Happy to rebase this on top of #745 once it lands, reduced to parts 1, 2 and 3,
if the maintainers prefer that order. #745 is the bigger piece of work and
should go first.

---

### B — posted on #745, 22 August 2026

Very useful work — thank you for doing it. One narrow question about the
no-parameter list, and I should disclose that I have an overlapping PR (#779),
so please weigh this accordingly.

`CKM_ML_DSA` and `CKM_SLH_DSA` take an optional `CK_SIGN_ADDITIONAL_CONTEXT`,
and the `CKM_HASH_ML_DSA_*` / `CKM_HASH_SLH_DSA_*` family takes
`CK_HASH_SIGN_ADDITIONAL_CONTEXT` (PKCS#11 3.2, §6.18 and §6.19):

```c
struct CK_SIGN_ADDITIONAL_CONTEXT {
    CK_HEDGE_TYPE hedgeVariant;
    CK_BYTE      *pContext;
    CK_ULONG      ulContextLen;
};
```

With those mechanisms in `mechanism_has_no_parameters()`,
`p11_rpc_buffer_add_mechanism()` writes nothing after the mechanism type and
`p11_rpc_buffer_get_mechanism()` returns before reading a parameter. So a
caller that passes a context — or a non-default `hedgeVariant` — has it
dropped, and the token signs with an empty context and the default hedging
instead. The call succeeds and returns a signature that verifies against
something other than what the caller asked for.

That seems worse than the failure it replaces: today the call is refused, which
is visible.

The key-pair generators are unaffected (`CKM_ML_DSA_KEY_PAIR_GEN`,
`CKM_SLH_DSA_KEY_PAIR_GEN`, `CKM_ML_KEM_KEY_PAIR_GEN` genuinely take no
parameter), and I believe `CKM_HSS`, `CKM_XMSS` and `CKM_XMSSMT` are fine too.
It is specifically the signing mechanisms with the optional context.

The integration tests would not catch it: they generate, export and import, and
none signs with a context, so the drop is silent there as well.

Two ways to handle it that I can see:

- **A serialiser for the context**, in the style of
  `p11_rpc_buffer_add_ibm_kyber_mechanism_value`, so the parameter travels.
  That is the complete fix and more work.
- **A parameter-aware admission test**, which is what #779 does: a mechanism
  not on either list is still carried when the caller supplied no parameter,
  and refused when they did. Those mechanisms then work in their common,
  contextless form without the silent-drop risk — no context, it crosses; with
  a context, `CKR_MECHANISM_INVALID` rather than a wrong signature.

Either way I think `CKM_ML_DSA`, `CKM_SLH_DSA` and the `CKM_HASH_*` entries
want removing from the no-parameter list. Happy to be told I have misread the
spec here.
