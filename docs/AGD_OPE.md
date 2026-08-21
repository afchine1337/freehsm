# FreeHSM C --- Operational User Guidance (CC EAL4+ AGD_OPE.1)

> **Not certified, and not seeking certification.** FreeHSM is built to the
> requirements of FIPS 140-3 Level 1 and Common Criteria EAL4+, and documented
> with their methodologies. It holds no certificate and will not pursue one: a
> certificate costs more than this project will ever have, and that cost is
> exactly the barrier that keeps public bodies, universities and developing
> countries away from auditable cryptography. What a certificate attests,
> discipline can make verifiable — by anyone, at no cost.
>
> This document is an evaluation deliverable and is written, as the methodology
> requires, as though a certificate existed. Read "certified" throughout as
> "the configuration this module is built to". It is published as a worked
> example, not as part of a submission.

**TOE :** FreeHSM Cryptographic Module (the version you built ; `v1.0.0-FIPS`
in earlier drafts was a placeholder and never existed as a release)
**Audience :** Security Officer (SO) and User operators of an installed TOE
**Prerequisites :** the TOE has been installed and brought to the secure operational state per `docs/AGD_PRE.md`

This document tells operators which services they may call, what arguments are accepted, what each error means, and how to respond when things go wrong. Read it once before first use ; keep it within reach during operations.

---

## 1. Roles & responsibilities

| Role          | Identifier  | Allowed services                                                                |
|---------------|-------------|---------------------------------------------------------------------------------|
| Security Officer (CO) | `CKU_SO`    | `C_InitToken`, `C_InitPIN`, `C_SetPIN` (own), audit review                |
| User                  | `CKU_USER`  | `C_GenerateKey`, `C_GenerateKeyPair`, `C_Encrypt`/`Decrypt`, `C_Sign`/`Verify`, `C_Digest`, `C_DeriveKey`, `C_Wrap`/`Unwrap`, `C_SetPIN` (own) |

Anonymous (pre-login) services :

| Service          | Purpose                              |
|------------------|--------------------------------------|
| `C_Initialize`   | Module bring-up (called once per process) |
| `C_GetInfo`      | Module identity                     |
| `C_GetSlotList`  | Enumerate slots                     |
| `C_GetSlotInfo`  | Slot status                         |
| `C_GetTokenInfo` | Token status (incl. PIN counters)   |
| `C_OpenSession`  | Open a session for login            |
| `C_CloseSession` | Close a session                     |
| `C_GetMechanismList` | List dispatchable CKM_*         |
| `C_GetMechanismInfo` | Per-mechanism flags & key range |

## 2. Common operator workflow

```c
#include <pkcs11.h>

CK_FUNCTION_LIST_PTR p11;
C_GetFunctionList(&p11);          /* loaded from libfreehsm-fips.so */
p11->C_Initialize(NULL);          /* triggers integrity check + KAT  */

CK_SESSION_HANDLE s;
p11->C_OpenSession(slot, CKF_RW_SESSION|CKF_SERIAL_SESSION,
                    NULL, NULL, &s);
p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin));

/* ... call C_GenerateKey, C_Encrypt, etc. ... */

p11->C_Logout(s);                  /* zeroizes DEK in this session   */
p11->C_CloseSession(s);
p11->C_Finalize(NULL);
```

After `C_Finalize` the process must not call any other `C_*` function until a new `C_Initialize`. Doing so returns `CKR_CRYPTOKI_NOT_INITIALIZED (0x190)`.

## 3. Mechanism selection guidance

Pick mechanisms from the **approved set** listed in `docs/MECHANISMS.md` and `docs/FIPS_140_3.md` §4. The mapping below summarises the canonical choice per use case.

| Use case                              | Recommended mechanism                  |
|---------------------------------------|----------------------------------------|
| Symmetric encryption at rest          | `CKM_AES_GCM` (96-bit IV, 128-bit tag) — **not** `CKM_AES_CBC_PAD`, see §3.1 |
| Symmetric encryption in transit       | `CKM_AES_GCM` or `CKM_AES_CCM`         |
| Symmetric authentication              | `CKM_SHA256_HMAC` or `CKM_AES_CMAC`    |
| Streaming MAC (large messages)        | `CKM_KMAC128` / `CKM_KMAC256`          |
| Asymmetric signature (classical)      | `CKM_SHA384_RSA_PKCS_PSS` or `CKM_ECDSA_SHA384` |
| Asymmetric signature (PQ)             | `CKM_ML_DSA` (parameter set ML-DSA-65) |
| Asymmetric signature (hybrid)         | `CKM_HYBRID_ED25519_ML_DSA_65`         |
| Key encapsulation (classical)         | `CKM_ECDH1_DERIVE` over P-256/384 or `CKM_X25519_DERIVE` |
| Key encapsulation (PQ)                | `CKM_ML_KEM` (parameter set ML-KEM-768) |
| Key encapsulation (hybrid)            | `CKM_HYBRID_X25519_ML_KEM_768`         |
| Password-based KEK derivation         | `CKM_PKCS5_PBKD2` with ≥ 200 000 iter  |
| Key derivation in a protocol          | `CKM_HKDF_DERIVE` (SHA-256+)           |

Any mechanism not in the approved list (e.g. `CKM_MD5`, `CKM_DES3_CBC`, `CKM_RSA_PKCS`) is **rejected at dispatch** in approved mode and returns `FHSM_RV_FIPS_NOT_APPROVED (0x80000003)`.

### 3.1 Approved is not the same as safe for your use case

Two mechanisms in the approved set carry a caveat that FIPS approval does not
express, because approval is about the algorithm and the caveat is about the
protocol you build with it. Both are usable and neither is a defect in the
module; the choice belongs to you.

**`CKM_AES_CBC_PAD` is a padding oracle.** Decryption tells the caller whether
the PKCS#7 padding was well-formed — `CKR_OK` when it was, `CKR_ENCRYPTED_DATA_INVALID`
when it was not. That single bit, repeated over chosen ciphertexts, recovers
plaintext byte by byte (Vaudenay 2002; POODLE, CVE-2014-3566). It is inherent:
CBC-PAD carries no authentication tag, so there is no way for `C_Decrypt` to
distinguish "corrupted" from "not for you" without saying which, and returning
garbage plaintext instead would be worse for every honest caller.

Measured on this module: 99.6% of corrupted ciphertexts are refused, and the
0.4% that decrypt are the ones whose random final block happens to carry valid
padding — the theoretical rate for any correct implementation. The module is
behaving as specified. The exposure is in the protocol.

> **Use `CKM_AES_GCM` or `CKM_AES_KEY_WRAP` wherever an attacker can submit
> ciphertexts of their choosing and observe whether decryption succeeded.**
> `CKM_AES_CBC_PAD` is appropriate for data you decrypt for yourself — a
> file at rest, a backup — where no adversary drives the decryption.

**`CKM_AES_CBC` and `CKM_AES_CTR` provide no integrity at all.** No oracle,
because there is no padding to check, but also no detection of tampering: a
flipped ciphertext bit becomes a flipped plaintext bit under CTR, silently.
Pair them with `CKM_SHA256_HMAC` over the ciphertext (encrypt-then-MAC,
RFC 7366) or use `CKM_AES_GCM`, which does both in one pass.

See R2 in `docs/PKCS11_CHECK_FINDINGS.md` for the measurement, and
`tests/test_cbc_pad_oracle.c` for the regression guard.

## 4. Security advice (operator-actionable)

### 4.1 PIN management

- Minimum PIN length is **8 octets**, enforced by `fhsm_token.c::fhsm_token_init`. Stronger PINs (≥ 12 chars, mixed case + digits + punctuation) are strongly recommended for High-Value-Asset (HVA) deployments.
- Never reuse a PIN across slots. The exponential-throttle defense is per-slot.
- After **5 consecutive failures**, the role is locked. The User PIN is unlocked by the SO via `C_InitPIN`. The SO PIN is unlocked only by `C_InitToken`, **which destroys all objects on the slot** --- so a SO lockout is functionally a re-bootstrapping.

### 4.2 Throttle handling (transient delay)

Between attempts, `C_Login` may return `FHSM_RV_PIN_THROTTLED (0x80000004)` with a wait time exposed via the `pinStatus.throttle_*_remaining` fields of `C_GetTokenInfo`. The client SHOULD :

1. Display the wait time to the human operator.
2. Sleep for the indicated number of milliseconds.
3. Retry exactly once.

Repeatedly hammering through the throttle does not change the outcome. The
failure **count** is persisted in the token file, so a restart does not reset
it, and on load the delay is re-imposed from that count — restarting is not a
way to skip a wait that was earned.

The deadline itself is **not** persisted, and this is a correction. It used to
be, in the `CLOCK_MONOTONIC` domain, so that `date -s` could not shorten a
cooldown. That reasoning was sound; its consequence was not examined.
`CLOCK_MONOTONIC` restarts at boot and the file does not, so a deadline written
after thirty days of uptime was still thirty days in the future when the next
boot read it: **a 500 ms cooldown became a 29.8-day refusal of the correct
PIN**, reported as `PIN_THROTTLED` with nothing to explain it. The same shape as
the unseal defect in §"TPM sealing" below — a routine event locking out an
operator who had done nothing wrong. The delay is now derived from the count
instead of stored, capped at 60 000 ms as documented, and `date -s` still
changes nothing.

If you are running a build from before this correction and a token reports
`PIN_THROTTLED` for far longer than 60 seconds, that is this defect. The
cooldown clears once the machine has been up as long as the boot that wrote it;
upgrading and reloading the token clears it immediately.

### 4.2b Where the audit log lives

**Do not put the audit log on `tmpfs`, and check rather than assume.**

The log's guarantee is that a line is durable before the operation it records
returns — see `docs/AUDIT_DURABILITY.md`. On a volatile filesystem `fdatasync`
returns immediately without a barrier, so the guarantee is silently absent:
nothing errors, nothing is logged about it, and the log looks entirely normal
until a power loss takes the last of it.

This is easy to do by accident. `/tmp` is `tmpfs` by default on current Debian,
and `FHSM_AUDIT_LOG` can point the log somewhere other than the tokens
directory. The symptom is a log that is implausibly fast:

```
stat -f -c '%T' "$FHSM_TOKENS_DIR"      # or the directory FHSM_AUDIT_LOG names
make tests/bench_audit_rate
FHSM_TOKENS_DIR=/var/lib/freehsm LD_LIBRARY_PATH=. ./tests/bench_audit_rate
```

A durable barrier costs milliseconds. Microseconds mean no barrier happened —
the benchmark says so in as many words, and prints the filesystem it measured.
The same caution applies to a hypervisor that acknowledges barriers without
honouring them; VirtualBox's host I/O cache does exactly that.

### 4.2c The log is a set of files, not one file

Each opening of the module creates its own log, `audit.log.NNNNNN`, because a
hash chain has exactly one author: two processes sharing one file each resumed
the chain from its tail and each believed itself the successor of the same
line, which destroyed it. Two ordinary tools running at once were enough.

For you this means:

```
freehsm-audit verify /var/lib/freehsm/audit  <audit_key_hex>
```

A directory verifies every numbered log in it, **and reports holes in the
numbering**. A hole means a file was removed: each remaining chain still
verifies on its own, so the numbering is the only thing that shows the
deletion. Missing numbers at the *end* leave no hole — that is the same
end-of-log truncation described in §4.3, not a new weakness.

Two consequences to plan for:

* **A restart leaves a new file.** A daemon restarted three times leaves three
  logs. Archive the set, not the file.
* **Between two files, only the timestamp orders events.** Inside a file `seq`
  is authoritative; across files you are merging on `ts`, which is wall-clock
  and can be moved by anyone who can set the clock. Take that into account when
  reconstructing an incident across a restart.

### 4.3 Audit log review

> **The audit log is produced, and the chain is verifiable.** The warning that
> stood here — that no log was written and the control could not be relied on —
> no longer applies. `C_Initialize` opens the log, the chain survives restarts,
> a failed write latches the module into `ERROR`, and both verifiers detect a
> modified, deleted, inserted or reordered record.
>
> Three limits remain, and an operator should know them before relying on this:
>
> 1. **A log truncated at the end is not detected**, and cannot be from the file
>    alone: what remains is a shorter chain that verifies perfectly, which is
>    indistinguishable from a log that stopped there. Mitigate by archiving
>    (step 3 below) and by comparing the archived record count over time — a
>    `seq` that goes backwards between two archives is the signal.
> 2. **A start-up integrity or KAT failure is not logged.** The log is opened
>    after the crypto layer, because chaining an entry needs HMAC. If the
>    self-test fails, the primitives that would authenticate the entry are the
>    ones that just failed. The module latches `ERROR` and refuses everything,
>    so the condition is observable — but the reason will not be in the log.
>    Read the process's stderr and `C_GetTokenInfo` flags in that case.
> 3. **The chaining key does not defend against a live root.** Sealed to the
>    TPM it resists an attacker who takes the disk or changes the boot chain;
>    it is unsealed into process memory to be used at all. See §4.4.

The audit log lives at `{tokens_dir}/audit.log`, or wherever `FHSM_AUDIT_LOG`
points, HMAC-chained. The SO MUST :

1. Periodically (recommended : weekly) verify the chain with the supplied
   verifier. Note the syntax: `verify` is a subcommand, and the 32-byte audit
   key is a required argument — the binary is `freehsm-audit`, and no
   `freehsm-audit-verify` exists.
   ```bash
   freehsm-audit verify /var/lib/freehsm/audit/slot0.audit.log <audit_key_hex_64>
   ```
2. Investigate every `login_fail`, `login_locked`, `login_throttled`, and `integrity_fail` event.
3. Archive monthly logs to immutable storage (WORM bucket, append-only volume) per the site's retention policy.

A broken chain is a **critical security event** : the on-disk log has been
tampered with by someone with write access to the audit directory. The verifier
names the first line at fault and what it found — an altered record, a
`prev_hmac` that does not follow, or a `seq` out of step. Take the system
offline and follow the incident response procedure (`SECURITY.md`).

### 4.4 The audit key

The chain is authenticated by a 32-byte key, provisioned on first start and
recovered afterwards. It is **not** derived from the token DEK: that would make
the log writable only while logged in, and `login_fail`, `login_locked` and
`integrity_fail` — the three events step 2 above tells you to investigate —
would never be recorded.

| Where it lives | When |
|---|---|
| `{tokens_dir}/audit.key.tpm`, sealed | `FHSM_TPM_SEALING=1` and a TPM is present |
| `{tokens_dir}/audit.key`, mode 0600 | otherwise |

The module refuses to start rather than degrade quietly:

* a key file readable by group or others is refused — a chaining key everyone
  can read is a chain everyone can forge ;
* a sealed blob that will not unseal is refused, rather than replaced by a
  fresh key that would silently start a second chain in the same file ;
* sealing requested and unavailable is refused, rather than falling back to a
  key in the clear.

To verify a log you need that key. Read it with `xxd -p -c 32
{tokens_dir}/audit.key` on the host, or unseal it there. **A log archived
without its key cannot be verified later** — archive the two separately, and
never on the same medium.

### 4.4 Token backup

Token files are encrypted at rest under the operator PIN(s). Backups are therefore as safe as the PIN strength, **but only if the backup retains the same access controls** :

- Use `cp --preserve=mode,ownership,timestamps` (or `rsync -a`).
- Store backups on encrypted media (LUKS, GCM-encrypted tar, KMS-sealed envelope).
- Never copy the audit log without the corresponding token file --- the integrity chain depends on the token's DEK-derived HMAC key.

### 4.5 Logout discipline

After every operation sequence :

```c
p11->C_Logout(s);
p11->C_CloseSession(s);
```

`C_Logout` zeroizes the DEK in process memory. `C_CloseSession` zeroizes the session-local key buffers. Failing to log out *does not* leak material on a process crash (the secure heap is process-local), but it does leave the audit trail with an unclosed session.

## 5. Service reference (selected)

### 5.1 `C_GenerateKey` (AES-256)

```c
CK_MECHANISM mech    = { CKM_AES_KEY_GEN, NULL, 0 };
CK_OBJECT_HANDLE key = 0;
CK_ULONG keylen      = 32;
CK_BBOOL true_       = CK_TRUE;
CK_ATTRIBUTE templ[] = {
    { CKA_VALUE_LEN, &keylen, sizeof(keylen) },
    { CKA_TOKEN,     &true_,  sizeof(true_)  },   /* persist */
    { CKA_ENCRYPT,   &true_,  sizeof(true_)  },
    { CKA_DECRYPT,   &true_,  sizeof(true_)  },
};
p11->C_GenerateKey(s, &mech, templ, 4, &key);
```

Returns `CKR_OK` and a non-zero `key` handle. The key material lives in the secure heap until the slot is logged out.

### 5.2 `C_Encrypt` (AES-GCM)

```c
CK_GCM_PARAMS gcm = {
    .pIv      = iv,   .ulIvLen      = 12,
    .pAAD     = aad,  .ulAADLen     = sizeof(aad),
    .ulTagBits = 128,
};
CK_MECHANISM mech = { CKM_AES_GCM, &gcm, sizeof(gcm) };

p11->C_EncryptInit(s, &mech, key);
p11->C_Encrypt(s, plaintext, plen, ciphertext, &clen);
```

`clen` on entry is the output buffer capacity ; on exit it is the actual ciphertext length (plaintext length + 16 for the tag). For multi-part processing, use `C_EncryptUpdate`/`C_EncryptFinal`.

### 5.3 `C_Sign` (ECDSA-P-384 + SHA-384)

```c
CK_MECHANISM mech = { CKM_ECDSA_SHA384, NULL, 0 };
p11->C_SignInit(s, &mech, priv_key);
p11->C_Sign(s, msg, msg_len, sig, &sig_len);
```

## 6. Error response

| `CK_RV` (hex) | Symbol                          | Operator action                                                |
|---------------|---------------------------------|----------------------------------------------------------------|
| `0x00`        | `CKR_OK`                        | continue                                                       |
| `0x05`        | `CKR_GENERAL_ERROR`             | check syslog ; if recurring, contact vendor                    |
| `0x06`        | `CKR_FUNCTION_FAILED`           | retry once ; if persists, file a support ticket               |
| `0x60`        | `CKR_KEY_HANDLE_INVALID`        | handle expired (session closed?) ; restart sequence            |
| `0x70`        | `CKR_MECHANISM_INVALID`         | not in `C_GetMechanismList` ; pick approved mechanism          |
| `0xA0`        | `CKR_PIN_INCORRECT`             | retry with correct PIN ; mind the throttle                     |
| `0xA4`        | `CKR_PIN_LOCKED`                | call SO to unlock with `C_InitPIN`                             |
| `0xB3`        | `CKR_SESSION_HANDLE_INVALID`    | open a fresh session                                           |
| `0x101`       | `CKR_USER_NOT_LOGGED_IN`        | `C_Login` first                                                |
| `0x190`       | `CKR_CRYPTOKI_NOT_INITIALIZED`  | `C_Initialize` first ; do NOT call after `C_Finalize`          |
| `0x80000001`  | `FHSM_RV_KAT_FAILED`            | **Critical** : module halted ; do not reuse ; reinstall        |
| `0x80000002`  | `FHSM_RV_INTEGRITY_FAILED`      | **Critical** : binary tampered ; reinstall from verified bundle |
| `0x80000003`  | `FHSM_RV_FIPS_NOT_APPROVED`     | switch to an approved mechanism                                |
| `0x80000004`  | `FHSM_RV_PIN_THROTTLED`         | wait the indicated milliseconds, retry once                    |
| `0x80000007`  | `FHSM_RV_SECURE_HEAP_EXHAUSTED` | reduce key inventory or raise `secure_heap_kb`                  |
| `0x80000008`  | `FHSM_RV_RNG_FAILURE`           | **Critical** : DRBG failed self-test ; restart the process     |

Critical errors latch the module ERROR state. The only recovery is to restart the process (per FIPS 140-3 §7.10.5). The operator MUST also examine the audit log to determine the root cause before relaunching.

## 7. Routine maintenance

| Frequency | Task                                                                 |
|-----------|----------------------------------------------------------------------|
| Daily     | Confirm `freehsm-bound-service` is healthy ; check syslog for FHSM warnings |
| Weekly    | Verify each slot's audit chain ; archive log if it exceeds rotation threshold |
| Monthly   | Rotate User PINs as per site policy ; review audit aggregates for anomalies |
| Quarterly | Test `make repro` against a fresh checkout ; confirm digest still matches deployed binary |
| Yearly    | Re-run penetration-testing tooling ; update OE.OS / OE.OPENSSL pins if needed (triggers re-evaluation per ALC_CMC.md §8) |

## 7bis. Runtime modes (v1.1.0)

The module selects between **legacy** (default) and **FIPS strict** mode at runtime. The choice is read from the `FHSM_MODE` environment variable first, then from the `mode =` directive in `/etc/freehsm/freehsm.conf`.

| Mode | Activation | Behaviour |
|---|---|---|
| `legacy` (default) | nothing, or `FHSM_MODE=legacy` | All declared mechanisms callable. MD5 and SHA-1 (digest) route to `fhsm_legacy_dispatch`. DES, 3DES, RC4 currently return `CKR_MECHANISM_INVALID` (handlers reserved for future wiring). |
| `fips` (= strict) | `FHSM_MODE=fips` or `mode = fips` in conf | Every non-FIPS-approved mechanism returns `CKR_MECHANISM_INVALID` regardless of OpenSC's negotiation table. Conforms to SP 800-131A Rev. 3. |

For FIPS 140-3 evaluation runs the operator MUST set `FHSM_MODE=fips` (or write `mode = fips` in the conf) BEFORE any `C_Initialize`. The mode is cached on first lookup, so changing the variable after init has no effect.

### Hardware-backed sealing (opt-in)

| Variable | Effect |
|---|---|
| `FHSM_TPM_SEALING=1` | At token init, the DEK is sealed to the host TPM 2.0 (PCRs 0-7). A companion `{slot}.tok.tpm` file is written next to the token. At login, the PBKDF2-unwrapped DEK is compared to the TPM-unsealed DEK. A mismatch, or an unseal that fails, refuses the login with `CKR_DEVICE_ERROR` — **read the note below before enabling this**. |
| `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` | **DEV-ONLY** : bypasses every integrity-failure path (see §8 below) — this variable IS FORBIDDEN in production. |

#### Before enabling: the module's process needs TPM access

`FHSM_TPM_SEALING=1` makes the module shell out to `tpm2`, which opens
`/dev/tpmrm0`. On Debian and Ubuntu that node is `crw-rw---- root tss`, so the
account running the PKCS#11 application must be in the `tss` group:

```
id -Gn | tr ' ' '\n' | grep -qx tss || sudo usermod -aG tss "$(id -un)"
```

Group membership is established at login, so an existing session will not pick
it up; `newgrp tss` gives the current shell the new group without logging out.

Do not work around this by running the application as root. The token files
would be created root-owned and the service would then need root for every
subsequent operation, which is a larger concession than the one being avoided.

Without the group, every TPM call fails with a TCTI permission error and the
module reports `CKR_DEVICE_ERROR` with `tpm-unseal-failed` in the audit log --
the same signal as moved PCRs, so check the group before suspecting the PCRs.

#### Before enabling: the TPM must have a persistent primary key

Sealing binds to a persistent primary key at handle `0x81010001`. **The module
does not create it**, and if it is missing every seal fails. Nothing said so
until the sealing path was first exercised against real hardware; this is that
omission being corrected.

```
tpm2 readpublic -c 0x81010001            # present?  if not:
tpm2 createprimary -C o -g sha256 -G ecc -c /tmp/primary.ctx
tpm2 evictcontrol  -C o -c /tmp/primary.ctx 0x81010001
```

The handle is compile-time (`TPM_PARENT_HANDLE` in `src/fhsm_tpm.c`). An
operator whose TPM already uses `0x81010001` for something else currently has no
way to say so — that belongs in `freehsm.conf` and is not there yet.

`scripts/validate_tpm_sealing.sh` checks for the handle and offers to provision
it, and exercises the whole sealing lifecycle against a real TPM including the
PCR-change scenario below. Run it before trusting `FHSM_TPM_SEALING` with
anything.

#### What a PCR change means for you (#109)

Sealing binds the DEK to PCRs 0 through 7. Those registers measure firmware and
early boot: a BIOS/UEFI update, a Secure Boot key rotation, a bootloader or
kernel change will move at least one of them. When that happens the TPM refuses
to release the sealed DEK, and **every login on that token fails until you act**,
even with the correct PIN.

This is the intended behaviour of measured boot, not a fault. What you get back
is `CKR_DEVICE_ERROR`, deliberately distinct from `CKR_PIN_INCORRECT`:

| Return | Meaning | What to do |
|---|---|---|
| `CKR_PIN_INCORRECT` / `CKR_PIN_LOCKED` | The PIN was wrong. | Normal PIN handling. |
| `CKR_DEVICE_ERROR` | The PIN was right; the TPM side failed. | See below. |

Three causes produce `CKR_DEVICE_ERROR`, and the audit log distinguishes them:

* `tpm-unseal-failed` — the TPM could not release the key. Almost always moved
  PCRs after a firmware or kernel update; also seen when the TPM is absent or
  the resource manager is not running.
* `tpm-dek-mismatch` — the TPM released a key, but it is not the key the token
  store holds. The two are supposed to be the same. **Treat this as a possible
  substituted token file or sealed blob and investigate before proceeding.**
* `tpm-required-but-missing` — `FHSM_TPM_SEALING=1` but this token has no
  `.tpm` companion. It was created without sealing.

**Recovery from a firmware update.** The DEK is still recoverable from the token
file with the PIN — sealing is a second factor, not the only copy. Take a backup
of `{slot}.tok` and `{slot}.tok.tpm`, then either roll the firmware change back
so the PCRs return to their sealed values, or re-seal the token under the new
measurements. Losing the `.tpm` file alone does not lose the token; losing the
token file does.

**A failed unseal does not consume a PIN attempt.** Before v1.7.0 it did, and
the throttle escalated with it, so a routine firmware update locked the token
permanently for an operator who had done nothing wrong. That was a denial of
service and it is fixed. A genuinely wrong PIN still counts, throttles and
locks exactly as documented in §5.

**Take a backup before enabling `FHSM_TPM_SEALING` on a token that matters.**

### Hardened DRBG

The `fhsm_rng_bytes` API now routes through `fhsm_drbg_bytes` which adds (a) multi-source entropy seeding, (b) SP 800-90B health tests (RCT, APT, CRNGT), (c) auto-reseed every 1 MiB of output or every hour. Any health-test alarm latches the module to `FHSM_STATE_ERROR` and forces a service restart. See [`RNG.md`](RNG.md).

### Pair-wise consistency check

Every `C_GenerateKeyPair` (RSA, EC, ML-KEM, ML-DSA, SLH-DSA) is followed by an automatic sign-verify (or encap-decap) round-trip with the freshly-generated key. Failure latches ERROR. Cost : ~5 ms for RSA-2048, sub-ms for EC, ~50 ms for SLH-DSA-128s.

## 8. Forbidden actions

The following actions **invalidate** the certified configuration and **forfeit** the FIPS / CC certificate :

- Setting `mode = legacy` (or leaving `FHSM_MODE` unset) for a deployment claiming FIPS 140-3 conformance.
- Setting `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` in any production context.
- Replacing `libfreehsm-fips.so` with any other binary, even patched.
- Modifying any file in `/opt/freehsm/etc/`.
- Loading an OpenSSL provider other than the validated FIPS provider.
- Disabling `mlock` capability on the host.
- Disabling audit (`audit_mandatory=false`).
- Operating the host without controlled physical access (violates OE.PHYS).

A site that performs any of the above is operating *outside* the certified TOE and may not advertise FIPS 140-3 / CC EAL4+ compliance.
