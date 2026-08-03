# `test_cbc_pad_all_last_block_positions` misses the oracle ~28% of the time

**Component:** `src/pkcs11_check/testcases/security/test_padding_oracle.py`
**Severity of the affected test:** `CRITICAL`
**Type:** false negative — the test passes when the finding is present

Hello Denis,

Following the earlier reports: this one is not a bug in the module under test,
it is arithmetic in the test itself, and it cost us a few days of chasing a
finding that appeared and disappeared. You will probably want to fix it because
a `CRITICAL` test that silently passes is worse than one that is missing.

## What happens

`TestAESPaddingOracle::test_cbc_pad_all_last_block_positions` reported the
Vaudenay channel against our module during one campaign, then reported nothing
on a later run against a build that had not touched the AES-CBC-PAD path at
all. We treated it as unexplained and kept the finding open rather than drop it.

The explanation is the detection probability.

The test corrupts one byte of the **last** ciphertext block. In CBC that
randomises the whole final plaintext block, so the question is how often a
uniformly random 16-byte block happens to carry valid PKCS#7 padding:

    P = sum_{n=1..16} 256^-n = (1/256) * (1 - 256^-16)/(1 - 1/256) = 1/255 ~= 0.392%

Over `trials = 20` x 16 positions = 320 probes:

    P(no probe lands on valid padding) = (1 - 1/255)^320 ~= 28%

So the test misses roughly **one run in three or four**.

## What the docstring says

> with ~6/256 ≈ 2.3% chance per probe of producing CKR_OK, the chance that all
> 320 land on CKR_ENCRYPTED_DATA_INVALID is about 0.05%. Effectively-deterministic
> detection.

0.05% is exactly `(1 - 6/256)^320`, so the conclusion follows correctly from the
premise — the premise is the problem. The per-probe rate is `1/255`, not
`6/256`; the two differ by a factor of six, and 0.05% becomes 28%.

I could not work out where `6/256` comes from. It is not the rate for a random
block, and it is not the rate for any single padding length.

## Measured

We measured the module's real behaviour directly rather than argue from theory
(105 600 corruption probes, three independent runs, AES-256, fresh IV per trial):

| | |
|---|---|
| accidentally-valid paddings | 433 |
| probes | 105 600 |
| observed rate | 0.0041 — one in 244 |
| 95% CI | one in 271 … one in 222 |
| theoretical 1/255 | 0.00392 — inside the interval |
| `CKR_OK` with plaintext matching the original | 0 |
| rejections other than `CKR_ENCRYPTED_DATA_INVALID` | 0 |

Theory and measurement agree. Our module's behaviour never changed between your
two runs; the test simply landed on the 28% branch the second time.

## Suggested fixes

Whichever you prefer — they are not exclusive:

1. **Raise the probe count.** For a 1-in-10 000 miss rate you need
   `n >= ln(1e-4)/ln(1 - 1/255) ~= 2350` probes, so `trials = 150` rather than 20.
   That is ~2350 decryptions; on our module the whole sweep runs in well under a
   second, and CBC decryption is cheap on any implementation.

2. **Do not rely on chance at all.** Rather than hoping a random corruption
   produces valid padding, construct one. Take the ciphertext `C1 || C2` and
   replace `C1` so that the final block decrypts to a chosen pad — the standard
   Vaudenay construction. Deterministic, one probe, and it also measures the
   thing the test is really about. This is more work than (1).

3. **At minimum, correct the docstring**, and report the achieved detection
   probability in the test output. A reader who sees `320 probes, 0 hits` should
   be told that is a 28% event, not a 0.05% one.

Point (3) matters even if you do (1) or (2): the number in the docstring is what
a downstream reader uses to decide whether a green run means anything.

## Also worth noting, and in your favour

The same measurement is a good advertisement for the test's *other* branch. When
we checked whether our module was merely failing to validate padding at all —
which would have been the much worse finding your `CKR_OK_DIFFERENT` path is
designed to catch — the numbers ruled it out cleanly: 99.6% of corruptions
refused, residual matching theory, no corrupted ciphertext ever decrypting back
to the original plaintext. That distinction between "leaks one bit" and "does
not check at all" is a genuinely good piece of design in the test, and it is why
we now carry our own regression version of it.

Separately: `test_aes_cbc_pad_decrypt_timing_sanity` once reported a 22.5x
valid/invalid ratio against our module. Measured over 48 000 decryptions we see
1.03x (986 ns against 1014 ns). We cannot rule out a few percent with our
measurement method, but a 22x difference was not real. That test may deserve the
same look as this one.

Thanks again for the harness — the three defects your earlier findings surfaced
in our TPM path and our object store were all real, and none of them would have
been found without it.

— Afchine Madjlessi, Simorgh Labs
