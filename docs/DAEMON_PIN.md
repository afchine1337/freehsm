<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Simorgh Labs
-->
# Where the daemon's token PIN comes from (#111)

**Status: decided, not built.** This closes the first of the three items left
open by `docs/REST_API_DESIGN.md`. It is step zero of the service: without an
answer there is nothing to start.

The constraint that shaped it is old and not negotiable: **the PIN is never a
command-line argument**, because arguments are visible in `ps` to every user on
the machine. That is why `--pin` exists on none of the four tools, and a daemon
does not get an exemption.

---

## First, what the PIN is actually protecting

Two things were read out of the code before any option was compared, because
they bound how much this decision can be worth.

**The daemon logs in exactly once.** `t->logged_in` is set by
`fhsm_token_login()` and cleared only by `fhsm_token_logout()` or
`fhsm_token_close()`; there is no timeout and no expiry anywhere in
`src/fhsm_session.c` or `src/fhsm_token.c`. Login state is per token per
application, and the daemon is one application — measured in
`probes/rest/03_login_shared`. So the PIN is needed for a few milliseconds at
start-up and never again for the life of the process.

**The secret that lives for the life of the process is the DEK, not the PIN.**
From login to logout the unwrapped DEK sits in the token's secure-heap arena,
because every object read needs it. Whoever can read the daemon's memory has
the DEK, and with the DEK they do not need the PIN at all.

Those two facts put a ceiling on this decision, and it should be stated before
the options rather than discovered after:

> The PIN source protects the `.tok` file **copied off the machine**, and it
> decides **who can start the service**. It does not protect a running daemon
> from anyone who is already on the host with sufficient privileges. Any
> argument for one option over another that rests on runtime protection is
> arguing about the wrong secret.

---

## Second, the daemon's PIN should not be a human PIN

An operator PIN is a compromise between memorability and entropy. Nothing about
a daemon needs it to be memorable. So:

* 32 bytes from `fhsm_drbg_bytes()` — the module's own DRBG, the one with the
  SP 800-90B health tests, for the same reason serial numbers come from it.
* Base64-encoded: **44 characters**, comfortably inside `FHSM_PIN_MAX_LEN`
  (64), and made only of characters that cannot be a NUL.

Not hex, which would be exactly 64 characters — at the limit, with no headroom
if the bound ever moves.

The NUL point is not decorative. `C_InitToken`, `C_InitPIN` and `C_SetPIN` now
refuse a PIN containing a NUL byte, because the token stores it as a C string
and would otherwise keep a silently shorter secret. Raw 32 random bytes would
hit that refusal about one time in eight. Encoding is not a stylistic
preference here, it is what makes the value storable at all.

This also means the operator never sees, types or knows the daemon's PIN, which
removes a whole class of operational mistake: it cannot be reused elsewhere,
written down, or shared.

---

## The three options

### A. Entered by the operator at start

**What it gives.** The strongest possible binding: the service runs only when a
human decided it should. Nothing on disk is enough to start it.

**What it costs, and this is decisive.** No unattended restart. Not after a
reboot, not after an OOM kill, not after a `systemctl restart` from a
configuration-management run at 03:00. For a signing service whose whole point
is to be available to other machines, "someone must be at the console" is not
an availability property, it is an outage waiting for a power cut.

**Verdict.** Kept as a supported mode, not the default. It is the right answer
for an offline root CA that signs four times a year, and the wrong one for the
service this document is about.

### B. Sealed to the TPM with our own `fhsm_tpm_seal()`

**What exists already.** `src/fhsm_tpm.c` seals a 32-byte secret and unseals it
with no operator present; `fhsm_audit_key_provision()` in `src/fhsm_audit.c`
already uses exactly this to recover the audit chaining key at start-up. The
machinery is written, tested, and has a substitute for hosts without a TPM.
A 32-byte secret is *precisely* what `fhsm_tpm_seal` takes — the daemon PIN
proposed above fits it with nothing left over.

**What it costs.** Our sealing policy binds PCRs 0..7 — firmware, bootloader,
kernel, initrd — as documented in `include/fhsm_tpm.h`. That is the right
policy for the DEK, where refusing to unseal after the boot chain changed is
the entire point. For a daemon PIN it means:

> **After a kernel or initrd update, the service does not start.**

`apt upgrade` becomes an outage that looks like a security alert. The operator
has to be at the console to re-seal — which is option A, arrived at by
accident, on the day nobody expected it.

`FHSM_TPM_PCRS` can narrow the selection, and there is a defensible narrower
set. But choosing it is a security decision we would be making on the
operator's behalf, and getting it wrong is invisible until an update.

**Verdict.** Correct machinery, wrong policy for this secret. Available for an
operator who wants the boot chain to gate the service and accepts what that
means for updates.

### C. A systemd encrypted credential — **recommended**

`LoadCredentialEncrypted=fhsm-pin:/etc/credstore.encrypted/fhsm-pin.cred`, read
by the daemon from `$CREDENTIALS_DIRECTORY/fhsm-pin` at start-up, used once,
zeroized.

Verified against the systemd documentation rather than assumed:

* **Encryption.** AES256-GCM. The key is derived from the TPM2 chip, or from
  `/var/lib/systemd/credential.secret` (root-only), or — the default when a
  TPM2 exists and `/var/lib/systemd/` is on persistent media — **both**. So the
  ciphertext is useless on any other machine, and useless without the TPM.
* **It survives updates.** `--tpm2-pcrs=` "binds the encryption key to no PCRs
  at all (this is also the default if this option is not used)". That is the
  exact difference from option B, and it is the reason for the recommendation.
  An operator who *wants* PCR binding can add it, and `--tpm2-public-key-pcrs=`
  exists precisely so that binding survives signed updates.
* **The plaintext never reaches the disk or the environment.** Credentials are
  exposed as a file readable only by the service's user, **not propagated down
  the process tree** the way an environment variable is, and an access check is
  enforced by the kernel on each access. With `PrivateMounts=`, the directory
  is invisible to every other service.
* **Unswappable memory, when it can be.** systemd backs credentials with
  `ramfs` "if permissions allow it", and `systemd-creds list` reports each one
  as `secure` (unswappable), `weak` (any other memory) or `insecure` (mode not
  0400). The AGD procedure must have the operator read that column rather than
  assume `secure` — a credential silently landing in `weak` is exactly the kind
  of downgrade this project keeps finding.
* **It is released on deactivation** and immutable while the service runs.

**What it costs.** A hard dependency on systemd for the recommended deployment
path. That is worth naming plainly in a project whose mission is public bodies
and universities — but those are precisely the estates where the unit file is
already the deployment artefact.

---

## The decision

1. The daemon's PIN is **machine-generated**: 32 DRBG bytes, base64, 44
   characters. The operator never sees it.
2. The default deployment reads it from a **systemd encrypted credential**.
3. **Operator-entered** is supported for deployments that want a human in the
   loop, and is the right answer for an offline CA.
4. **`fhsm_tpm_seal`** is offered for operators who want the boot chain to gate
   the service, with the update consequence stated in the AGD rather than
   discovered.
5. Whichever the source, the daemon **zeroizes the PIN as soon as `C_Login`
   returns**. It is dead weight after that, and the DEK is what matters.

---

## What the daemon refuses

* **To start without a PIN source configured.** Not "start read-only", not
  "start and ask later" — refuse, naming the three options.
* **To accept the PIN in an argument or an environment variable it inherited.**
  The argument is the old rule. The environment is the new one: systemd's own
  documentation gives inheritance down the process tree as the reason
  credentials exist, and a daemon that reads `$FHSM_PIN` hands the secret to
  every child it ever spawns.
* **To retry a failed login in a loop.** The token throttles after
  `FHSM_PIN_MAX_FAILED` (5) consecutive failures and then locks. A service
  under a systemd restart loop would burn those five attempts in seconds and
  lock the token — turning a misconfigured credential into a destroyed
  deployment. One attempt, then refuse to start and say why.
* **To log the PIN, its length, or its hash**, at any level.

---

## Not measured here

The unseal cost of option B on real hardware. `include/fhsm_tpm.h` estimates
~50 ms for the tpm2-tools spawn; there is no TPM in the environment where this
was written, so that figure is inherited from the header, not measured. It only
matters at start-up, once, alongside a `C_Initialize` that already costs
203–288 ms — so it is unlikely to change the decision, and it should still be
measured before the AGD quotes a start-up time.

---

## See also

* `docs/REST_API_DESIGN.md` — the service this is step zero of.
* `probes/rest/03_login_shared` — why one login covers the process's life.
* `include/fhsm_tpm.h` — the PCR 0..7 sealing policy, and `FHSM_TPM_PCRS`.
* [systemd credentials](https://systemd.io/CREDENTIALS/) and
  [`systemd-creds(1)`](https://man7.org/linux/man-pages/man1/systemd-creds.1.html).
