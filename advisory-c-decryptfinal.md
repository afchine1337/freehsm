# Draft GitHub security advisory — C_DecryptFinal out-of-bounds write

Paste into the advisory form at
https://github.com/afchine1337/freehsm/security/advisories/new

Delete this file once the advisory is published; SECURITY.md carries the
permanent record.

---

**Title**

    C_DecryptFinal writes past the caller's output buffer (AES-CBC-PAD)

**Ecosystem / package** — Other / `freehsm-c`

**Affected versions** — `>= 1.1.0, <= 2.1.0` — every published release. The
call is present in `0c0f5df`, the initial open-source release.

**Patched versions** — `2.2.0`

The fix ships in a minor rather than a patch release because the same release
adds two observable capabilities (multipart asymmetric signing and
verification; RSA private-key import from components). The security fix itself
touches only `C_DecryptFinal` and `C_DecryptUpdate` and is independent of
them.

**Severity** — High

**CWE** — CWE-787 Out-of-bounds Write

**CVE** — none requested, consistent with the project's posture on
self-disclosed defects

---

## Description

`C_DecryptFinal` had no output-size check. It called `EVP_DecryptFinal_ex`
directly into the caller's `pLastPart` buffer and reported the length
afterwards:

```c
int out_len = 0;
int ok = EVP_DecryptFinal_ex(op->cipher_ctx, pLast, &out_len);
*pulLastLen = (CK_ULONG)out_len;
```

For `CKM_AES_CBC_PAD`, the block held back by the padded decrypt yields 0 to 15
bytes once padding is removed. All of them were written, regardless of what the
caller had declared in `pulLastPartLen`.

### The specification's own sizing pattern led into it

PKCS#11 §5.2 has a caller ask for the required length with a NULL buffer,
allocate that much, and call again. `C_DecryptFinal` answered a flat `0` to
that question.

An application following the documented two-call pattern therefore allocated
nothing and then had up to fifteen bytes written into it. An application that
guessed a generous buffer instead was unaffected. The correct usage was the
reachable one.

### Impact

The write lands in the **caller's** buffer. The module knows neither its size
nor its storage class, and in practice it is frequently heap. Unlike
[GHSA-833h-crp9-f378](https://github.com/afchine1337/freehsm/security/advisories/GHSA-833h-crp9-f378),
which overflowed a stack buffer inside the module and was converted into an
abort by `_FORTIFY_SOURCE` and the stack protector, nothing in our build
detects this one. It is silent.

Reachable by any application performing multipart `CKM_AES_CBC_PAD`
decryption. The ciphertext arrives from outside by the nature of decryption;
it determines the padding, which determines how many bytes are written. An
attacker who does not hold the key cannot steer the length precisely — a
legitimate peer's message does so as a matter of course.

### Patch

The size query now answers the real bound. An undersized buffer is refused with
`CKR_BUFFER_TOO_SMALL` and a length the caller can retry with; the operation
and its held-back block stay alive for that retry, as §5.2 requires. When the
padding does not verify, the answer is taken from a copy of the cipher context
rather than by calling the real `Final` with an undersized buffer and trusting
it not to write on failure.

Regression coverage: `tests/test_cbc_pad_update_size.c`, including the guard
cases for both `C_DecryptUpdate` and `C_DecryptFinal`.

### Workaround

If you cannot upgrade: size the `C_DecryptFinal` output buffer to at least one
cipher block (16 bytes for AES) rather than to the value returned by its size
query. Single-part `C_Decrypt` is unaffected.

### How it was found, and why it took this long

A second defect was standing in front of it. `C_DecryptUpdate` refused
undersized buffers against `ulEncLen` + one block — the bound belonging to
`C_EncryptUpdate`, which decryption cannot reach, since each ciphertext block
yields one plaintext block and padding only removes bytes. Nothing was
overrun there, but `pkcs11-check`'s probe was refused at its *setup* step and
never reached `C_DecryptFinal`.

The module passed four full-corpus runs in that state. Correcting the refusal
exposed the write within the hour.

A guard that is wrong in the refusing direction is not the harmless kind.

### Credit

Found through Denis Mingulov's `pkcs11-check`, probe
`aes_cbc_pad_decrypt_final_buffer_too_small`.
