# FreeHSM C --- Preparative Procedures (CC EAL4+ AGD_PRE.1)

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
**Audience :** system administrator deploying the TOE for the first time
**Prerequisites :** root access on the target host ; familiarity with PKCS#11

This document describes how to receive, verify, install, and configure the TOE into a secure operational state. After completing every step here, an administrator may move on to `docs/AGD_OPE.md` for day-to-day operation.

---

## 1. Operational environment prerequisites (OE)

The Security Target (`docs/EAL4_PLUS.md` §3.2) lists six operational-environment objectives. Confirm each before installing :

| OE id        | Requirement                                                     | Verification                                                     |
|--------------|-----------------------------------------------------------------|------------------------------------------------------------------|
| **OE.OS**    | Linux ≥ 5.4 with `mlock` capability, **64-bit only** (x86_64 or aarch64) | `uname -rm ; getcap /usr/local/lib/libfreehsm.so`     |
| **OE.STORAGE** | Local filesystem with atomic `rename` (ext4/xfs)               | `findmnt -T /var/lib/freehsm -o FSTYPE`                          |
| **OE.OPENSSL** | OpenSSL ≥ 3.0 with FIPS provider loaded and active             | `openssl list -providers \| grep -A2 fips`                        |
| **OE.OP**    | Administrator trained, controls authentication credentials       | (procedural --- see §6)                                          |
| **OE.PHYS**  | Host physically protected (locked rack / authorized access)     | (procedural --- site security)                                  |
| **OE.HARDWARE** | CPU with AES-NI (x86_64) or ARMv8 Crypto Ext.                | `grep aes /proc/cpuinfo \| head -1`                              |

If any verification fails, **do not proceed** : the TOE will not enter its claimed secure state.

## 2. Delivery verification

The TOE is delivered as four files, published on the source forges with the signed release tag :

```
libfreehsm.so              # the cryptographic module
libfreehsm.so.sha256       # detached digest, GPG-signed
freehsm-c-src.tar.xz            # reproducible source archive
freehsm-c-src.tar.xz.sha256     # detached digest, GPG-signed
RELEASE_NOTES.md
ACCEPTANCE.txt
Dockerfile.build.image-digest
```

### 2.1 Channel authentication

All files MUST be downloaded over **HTTPS** with TLS 1.3, with certificate validation enabled. Refuse self-signed certificates.

### 2.2 Origin authentication

Verify each `*.sha256` file is signed by the release key whose fingerprint is published on the project website (and reproduced in `docs/ALC_CMC.md` §7) :

```bash
gpg --import freehsm-release-pubkey.asc
gpg --verify libfreehsm.so.sha256
# Expected output : Good signature from "FreeHSM Release Manager <release@freehsm.example>"
gpg --verify freehsm-c-src.tar.xz.sha256
```

Refuse delivery if either signature does not validate.

### 2.3 Integrity check

```bash
sha256sum -c libfreehsm.so.sha256
# Expected : libfreehsm.so: OK

sha256sum -c freehsm-c-src.tar.xz.sha256
# Expected : freehsm-c-src.tar.xz: OK
```

### 2.4 Optional : rebuild from source

The strongest assurance is to rebuild the binary from the source archive and confirm bit-identical output :

```bash
tar xf freehsm-c-src.tar.xz
cd freehsm-c-1.0.0-FIPS
make dist-verify     # rebuild twice in pinned Docker, assert identical SHA-256
```

The resulting `libfreehsm.so` SHA-256 MUST match the value in `libfreehsm.so.sha256`. See `docs/REPRODUCIBLE_BUILD.md` for the full procedure.

## 3. Installation

### 3.1 Directory layout

Create the production tree under `/opt/freehsm` :

```bash
sudo install -d -o root -g root -m 755 /opt/freehsm/{lib,bin,etc}
sudo install -d -o freehsm -g freehsm -m 700 \
    /var/lib/freehsm/{tokens,audit,kek}
```

| Path                          | Owner       | Mode | Purpose                                |
|-------------------------------|-------------|------|----------------------------------------|
| `/opt/freehsm/lib/libfreehsm.so` | root       | 0755 | The cryptographic module             |
| `/etc/freehsm/freehsm.conf`            | root       | 0644 | Module config, the only path read     |
| `/var/lib/freehsm/tokens/slot*.tok`     | freehsm    | 0600 | Encrypted token files                |
| `/var/lib/freehsm/audit/slot*.audit.log` | freehsm   | 0600 | HMAC-chained audit logs              |
| `/var/lib/freehsm/kek/*.kek`            | freehsm    | 0600 | Local KMS KEK material (if used)     |

### 3.2 Module installation

#### The module does not require a dedicated user

Read this before the commands below, because the commands alone give the wrong
impression and did so for at least one reader (issue #1).

FreeHSM is an ordinary PKCS#11 module. **Any user who can read the `.so` and
read/write a tokens directory can use it**, which is how PKCS#11 modules are
normally used. The tokens directory comes from `FHSM_TOKENS_DIR`, falling back
to a compile-time `/var/lib/freehsm/tokens`. For per-user or per-application
use, point it somewhere that user owns:

```bash
FHSM_TOKENS_DIR="$HOME/.local/share/freehsm/tokens" \
    pkcs11-tool --module /opt/freehsm/lib/libfreehsm.so --show-info
```

The `freehsm` user below belongs to a **shared, multi-tenant deployment** —
typically `fhsm-service`, where one daemon holds the tokens on behalf of
several callers and the token files must not be readable by those callers. It
is a deployment posture for that case, not a requirement of the module. The
rest of this section assumes that posture because the evaluated configuration
is a service deployment; adapt it if yours is not.

```bash
sudo install -o root -g root -m 0755 libfreehsm.so \
    /opt/freehsm/lib/libfreehsm.so

# For a shared deployment only: a dedicated unprivileged user under which the
# HSM-using daemon runs, owning /var/lib/freehsm and holding CAP_IPC_LOCK.
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/freehsm freehsm
sudo setcap 'cap_ipc_lock=+ep' /opt/freehsm/lib/libfreehsm.so
```

### 3.3 OpenSSL FIPS provider activation

Confirm the OS-provided OpenSSL has the FIPS provider enabled :

```bash
openssl list -providers
# Expected output must include :
#   Providers:
#     fips
#       name: OpenSSL FIPS Provider
#       version: 3.0.13
#       status: active
```

If not active, follow `docs/REPRODUCIBLE_BUILD.md` §3 to rebuild OpenSSL with `enable-fips` and patch `/etc/ssl/openssl.cnf` to activate the provider.

#### 3.3.0 Use OpenSSL 3.5.7 or later — observed, not diagnosed

**On OpenSSL 3.5.6, `C_GenerateKeyPair` for RSA-2048 fails with
`CKR_FUNCTION_FAILED` while EC, AES, HMAC and ECDH all succeed.** The same
module, byte for byte, generates RSA keys correctly on 3.5.7.

Reported and isolated by an external user (issue #5) across several days. The
attribution is clean — between the failing run and the passing one, only the
OpenSSL version changed — but **the cause is not established**, and it is not
simply "3.5.6 cannot do it": `openssl genpkey -algorithm RSA -provider fips`
generates a key perfectly well on 3.5.6. It fails only through this module,
which additionally loads the `base` provider, sets `fips=yes` as the default
property, and enables OpenSSL's global secure heap. Something in that
combination is involved; which part is unknown.

A module built against 3.5.6 will therefore pass every self-test and fail the
first RSA key generation. If you are on 3.5.6, upgrade before deploying. As of
v2.0.2 the module prints OpenSSL's own error stack on that path, so anyone who
meets it can send the reason rather than the symptom.

#### 3.3.1 After every OpenSSL upgrade — `fipsmodule.cnf` must be regenerated

**Run §3.3 again after any OpenSSL package update, before anything else.** An
upgrade replaces `fips.so` but does not touch `fipsmodule.cnf`, which holds the
MAC of the *previous* module. The provider then fails its own integrity check
and simply does not appear:

```bash
openssl fipsinstall -verify \
  -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so \
  -in /etc/ssl/fipsmodule.cnf
# Module integrity mismatch
# VERIFY FAILED
```

Three things make this worth its own section rather than a line.

**FreeHSM will not tell you.** A signed module loads the FIPS provider during
`C_Initialize`. When the load fails, `C_Initialize` returns
`CKR_FUNCTION_FAILED` and prints nothing — unlike the audit-key and
tokens-directory failures beside it, which each name themselves. Observed
2026-09-03 on Debian 13, OpenSSL 3.5.6 → 3.5.7: forty minutes to reach a cause
the module already knew.

**`fipsinstall` cannot repair what your configuration has already broken.**
It loads `fips.so` through the ambient `openssl.cnf`, which activates the
provider from the stale `fipsmodule.cnf`; the module enters an error state and
the tool meant to fix it can no longer open it:

```
Failed to load FIPS module
INSTALL FAILED
SELF_TEST_post:invalid state
```

Run it outside the configuration. Note that `sudo` clears the environment, so
the assignment must be inside it:

```bash
sudo env OPENSSL_CONF=/dev/null openssl fipsinstall \
  -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so \
  -out /usr/lib/ssl/fipsmodule.cnf
openssl list -providers          # fips … status: active
```

**There must be exactly one `.include`.** A host can accumulate two
`fipsmodule.cnf` at different paths, both included from `openssl.cnf` —
`[fips_sect]` defined twice, and the first one read wins whether or not it is
the valid one. Check before regenerating, and keep one:

```bash
grep -n '^\.include' /etc/ssl/openssl.cnf
readlink -f /usr/lib/ssl        # if not /etc/ssl, the two paths are two files
```

### 3.4 Verifying module identity

```bash
readelf -p .comment /opt/freehsm/lib/libfreehsm.so
# Expected : GCC 12.2.0 ; binutils 2.40 ; (matches Dockerfile.build pins)

readelf -S /opt/freehsm/lib/libfreehsm.so | grep -A1 .fhsm_digest
# Expected : a 48-byte read-only section --- the embedded integrity digest
```

If `.fhsm_digest` is all zeros, the module was **not signed** and will refuse to initialize in shipping mode :

```bash
objcopy -O binary --only-section=.fhsm_digest \
    /opt/freehsm/lib/libfreehsm.so /dev/stdout | xxd
# Expected (signed)   : 48 bytes of hex data --- the SHA-384 self-digest
# All-zero            : refuse to deploy.
```

Extract by section name rather than by offset. This section was documented with
a hardcoded `xxd -s 0x2000 -l 32` until 2026-09-26, which was wrong twice over:
the digest has been SHA-384 and 48 bytes since 4b91308, and the offset moves
with the build --- it is 0x4b2a0 in the current one. An operator running the
old command read 32 bytes of unrelated data and concluded signed or unsigned
from it.

A `readelf -p .gnu.version_d ... | grep -F "1.0.0-FIPS"` check stood here too.
The binary has no `.gnu.version_d` section and carries no `-FIPS` suffix since
v2.0.0, so the command could only ever print nothing.

## 4. Initial configuration

### 4.1 Module configuration

`make install` writes `/etc/freehsm/freehsm.conf`. That is the path the module
reads ; nothing else is consulted.

```
# Runtime mode: strict | permissive. Overridden by FHSM_MODE.
# fips and legacy are the former spellings and still work.
mode = strict

# mlock(2)-ed secure heap holding key material, in KiB.
# Range 64..65536, rounded up to a power of two.
secure_heap_kb = 8192
```

**Only these two keys are read.** Earlier revisions of this guide listed nine —
`fips_strict`, `audit_mandatory`, `pin_max_failed`, `pin_throttle_base_ms`,
`pin_throttle_max_ms`, `pbkdf2_iterations`, `tokens_dir`, `audit_dir` — at a
path the module never opened. None of them had any effect. An operator who
hardened the module by editing that file changed nothing (#128).

`audit_mandatory` is now real, but as a **build** setting rather than a
configuration key: `-DFHSM_AUDIT_MANDATORY=0` at compile time decides whether
this installation may run without an audit log at all, and the default is that
it may not. That is deliberate — it is the distributor's decision, not the
operator's, and a decision the operator could edit into a file would not be the
distributor's. What the operator controls is `FHSM_AUDIT=off`, and only where
the build allows it. See `docs/AUDIT_DURABILITY.md`.

The remaining parameters are set at build time or through the environment :

| Parameter | Where it is set |
|---|---|
| PIN failure limit, throttle curve | compile-time (`FHSM_PIN_MAX_FAILED` and the throttle constants) |
| PBKDF2 iteration count | compile-time, 200 000 |
| token directory | `FHSM_TOKENS_DIR` environment variable |
| approved-mechanism set | build profile, `make generate PROFILE=nist-approved-only` |

Note the scope of `mode` : it selects KAT/dispatch behaviour. **Which mechanisms
the PKCS#11 API advertises and executes is fixed when the module is built** and
cannot be changed from this file. A deployment that must refuse non-approved
mechanisms has to be built with `PROFILE=nist-approved-only` — verify with
`make show-profile`, which prints the requested profile, the profile the
generated sources were produced for, and the `fhsm_build_fips_strict` value read
back out of the binary.

These values are the defaults the module is intended to be validated with.
**FreeHSM is not currently FIPS 140-3 validated**; this guide is written for the
configuration submitted for validation, and changing these values would place a
deployment outside that configuration once validation is obtained. Raising
`pbkdf2_iterations` is the only change that is conservative in the meantime, and
it requires a rebuild.

### 4.2 First-boot integrity verification

Confirm `C_Initialize` succeeds and the integrity self-test passes :

```bash
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm.so \
    --show-info
```

**The slots will report `uninitialized`, and no token will be present. That is
correct at this point, not a fault.** A FreeHSM slot holds a token once one has
been created in it; until then there is nothing to find, and `C_GetSlotList`
with `tokenPresent = CK_TRUE` returns none. It surprises people used to
thinking of a software token as always there — a reader reported exactly that
in issue #3 — because "soft token" suggests permanence and the file does not
exist yet. §4.3 creates it.

If `C_Initialize` itself fails, the module now says why on stderr: an unsigned
module, a module altered after signing, a missing `.fhsm_digest` section, a
FIPS provider that will not load, and a tokens directory it cannot use each
name themselves. If you get a bare return code with no message, the build
predates v2.0.2 and the cause is one of those five.

Expected output excerpt :

```
Cryptoki version 3.2
Manufacturer     Simorgh Labs
Library          libfreehsm.so <version>-FIPS
Using slot 0 with a present token (0x0)
```

If `C_Initialize` returns `0x00000005` (`CKR_GENERAL_ERROR`) or `0x80000002` (`FHSM_RV_INTEGRITY_FAILED`), the module aborted POST. Examine `/var/log/syslog` and `/var/lib/freehsm/audit/boot.log` for the error before retrying. Do **not** attempt a workaround : a failing POST is FIPS-mandated and means the binary is not trustworthy.

### 4.3 Token initialization (CO bootstrapping)

Before any user can log in, the administrator must create a token and set the Security Officer (SO) PIN.

```bash
# Generate a strong SO PIN out-of-band (≥ 12 characters, mixed case, digits,
# symbols ; entered via terminal, NOT shell history) :
read -s -p "SO PIN > " SO_PIN ; echo

sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm.so \
    --init-token --label "prod-slot-0" --so-pin "$SO_PIN"
unset SO_PIN
```

Verify the token state :

```bash
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm.so \
    --list-slots
# Expected : Slot 0 (0x0): present, label "prod-slot-0"
```

### 4.4 User PIN initialization (delegated)

The SO then sets a user PIN for the day-to-day operator. The User PIN MUST differ from the SO PIN.

```bash
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm.so \
    --so-pin "$SO_PIN" --init-pin --new-pin "$USER_PIN"
```

After this step, the User role can log in for cryptographic operations ; only the SO can re-initialize the token or unlock the User PIN.

## 5. Reaching the *secure operational state*

The TOE is in its secure operational state when **all** of the following hold simultaneously :

1. `C_Initialize` returned `CKR_OK`.
2. `fhsm_kat_results()` reports every approved primitive as `passed=1`.
3. `fhsm_integrity_is_signed()` returns 1.
4. The module state (introspected via vendor helper `fhsm_state_get()`) is `INITIALIZED` or `AUTHENTICATED`.
5. `/var/lib/freehsm/audit/slot0.audit.log` contains a `module_init` event with `result=OK`.
6. `mode = strict` is set in `/etc/freehsm/freehsm.conf`, **and** the module was built with `PROFILE=nist-approved-only` — the file alone does not restrict the mechanism set (`make show-profile` confirms both). `mode = fips` is the former spelling and still works, with a note naming the replacement.

If any of these is false, the system is **not** in the certified state and must be re-installed before exposing it to users.

## 6. Operator responsibilities (procedural)

The administrator confirms in writing (audit trail) that :

- Operators are trained on `docs/AGD_OPE.md` before being granted credentials.
- PINs are transmitted to operators over an authenticated channel and never written down.
- The audit log is reviewed at least weekly (cf. `AGD_OPE.md` §6).
- Backup of the token files is performed under the **same access controls** as the live store ; backups copied to media must be encrypted at rest.

## 7. Debian 13 porting notes (gcc-14 / dash / OpenSSL 3.5)

This section records the divergences met when moving a build station from
Debian 12 / gcc-12 / OpenSSL 3.0 to a Debian 13 / gcc-14 / OpenSSL 3.5 target.
The module stays reproducible on both distributions; the adjustments below are
already on `main`.

### 7.1 Compilation (gcc-14)

gcc-14 enables by default several warnings gcc-12 passed over in silence. The
build is `-Werror`, so each category was cleared with a targeted fix:

| Warning | Cause | Remedy |
|---|---|---|
| `-Wmissing-prototypes` on the `C_*` | Exported symbols with no local declaration | Forward declarations marked `FHSM_EXPORT` in `src/fhsm_pkcs11.c` |
| `-Wstringop-truncation` on `strncpy(dst, src, n-1); dst[n-1]=0` | gcc-14 refuses even the "safe manual" pattern | Replaced by `snprintf(dst, n, "%s", src)` in `fhsm_integrity.c` and `fhsm_state.c` |
| `-Werror=array-bounds` on `memcpy(dst, "literal", 32)` | `_FORTIFY_SOURCE=2` sees an OOB read when the literal is shorter than 32 | Helper `fhsm_pack_field(dst, src, n)` using `strlen()`, which defeats the static inference |
| `-Wmisleading-indentation` | Three statements on one line in `fhsm_dispatch_hybrid.c` | Split into three lines |
| `-Wredundant-decls` on `dispatch_reject_fips` | The table generator emitted the declaration twice | Patch to `scripts/gen_p11_thunks.py` (skip inside the `extern` loop) |

### 7.2 The Makefile and `dash`

`/bin/sh` is **`dash`** on Debian, not bash, and dash refuses several
constructions that are valid elsewhere:

- multi-line `<<-EOF` heredocs combined with `if/then/fi` continued by `\`
- `$(...)` substitution spanning several physical lines

The `install` target was rewritten without `if/then/fi` and without heredocs,
using `test X || command` and `printf '...\n...\n'` instead. Nothing needs to
change if you target bash explicitly, but the port keeps dash compatibility so
that minimal containers stay easy to deploy to.

### 7.3 The OpenSSL 3.5 FIPS provider

OpenSSL 3.5 still ships the FIPS provider but Debian 13 installs no
configuration for it. Without one, `OSSL_PROVIDER_load(NULL, "fips")` can
return a handle that looks active while serving no algorithm at all — every
KAT then fails and `C_Initialize` returns `FHSM_RV_KAT_FAILED` (`0x80000001`).

**Activating the FIPS provider on Debian 13:**

```bash
# Locate the module
sudo find / -name "fips.so" 2>/dev/null
# /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so

# Generate fipsmodule.cnf (computes the provider's integrity MAC)
sudo openssl fipsinstall \
    -out /usr/lib/ssl/fipsmodule.cnf \
    -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so

# Enable it in /etc/ssl/openssl.cnf: uncomment "fips = fips_sect" and
# include fipsmodule.cnf at the top of the file.
echo ".include /usr/lib/ssl/fipsmodule.cnf" | sudo tee -a /etc/ssl/openssl.cnf
sudo sed -i 's/^# fips = fips_sect/fips = fips_sect/' /etc/ssl/openssl.cnf

# Verify
openssl list -providers | grep -A2 fips
# Expected:
#   fips
#     name: OpenSSL FIPS Provider
#     status: active
```

### 7.4 PBKDF2 and the FIPS thresholds

The OpenSSL 3.x FIPS provider enforces the NIST SP 800-132 §5 thresholds on
PBKDF2:

- password **≥ 14 bytes**
- salt **≥ 16 bytes** (128 bits)
- iterations ≥ 1000

The KAT vectors in `kat/fhsm_kat_vectors.c` were adjusted accordingly
(`"passwordPASSWORDpassword"` / `"saltSALTsaltSALTsalt"` at 200 000
iterations). Any PBKDF2 vector added later must respect these thresholds or it
will fail the FIPS self-test.

### 7.5 The `FHSM_INTEGRITY_ALLOW_UNSIGNED` variable

This environment variable bypasses `fhsm_integrity_verify()` **only** when the
`.fhsm_digest` section is entirely zero — an unsigned development build. On a
signed build (non-zero digest) the variable is ignored.

**Legitimate use:** debugging a developer build between `make` and
`make integrity`.

**Strictly forbidden in production and on a certified build.** The TOE operator
confirms at delivery that the variable is set nowhere in `/etc/environment`,
`/etc/profile.d/`, systemd unit files, or cgroups:

```bash
sudo grep -r FHSM_INTEGRITY_ALLOW_UNSIGNED /etc/ /lib/systemd/ /usr/lib/systemd/ || \
    echo "OK : variable absent from the system PATH"
```

### 7.5bis The `FHSM_KAT_ALLOW_FAIL` variable

This environment variable, **effective only if `FHSM_INTEGRITY_ALLOW_UNSIGNED=1`
is set as well**, lets `fhsm_crypto_init()` continue initialising after a Known
Answer Test has failed. Its only reason to exist is running external test
harnesses (Wycheproof, fuzz, interop) against an unsigned development image in
a container where the OpenSSL FIPS provider layer is not configured.

**Legitimate use:** the `wycheproof.yml` workflow, in a Debian 13 build
container with no OpenSSL FIPS provider configured, where some KATs fail by
construction.

**Strictly forbidden in production and on a certified build**: FIPS 140-3
§7.10.2 requires any KAT failure to latch the ERROR state. Pre-delivery check:

```bash
sudo grep -r FHSM_KAT_ALLOW_FAIL /etc/ /lib/systemd/ /usr/lib/systemd/ || \
    echo "OK : variable absent from the system PATH"
```

When the bypass is active `libfreehsm.so` writes an explicit warning to
`stderr` along with the list of failing KATs, which makes any such run
audit-traceable and rules out confusion with a conformant build.

### 7.6 Diagnostics: externalised KAT harness

`fhsm_kat_results()` is exported (`visibility=default`) so that an external
harness can read the KAT report after `C_Initialize` **without** exposing any
key material. For diagnostics only:

```c
const fhsm_kat_result_t *r = fhsm_kat_results(&n);
for (size_t i = 0; i < n; ++i)
    printf("%-20s %s\n", r[i].algorithm, r[i].passed ? "PASS" : "FAIL");
```

The report is produced by `tests/test_smoke`, shipped in the distribution. (A
`tests/kat_report.c` was named here; it was never written.) In production the
report is also written to the audit log under the `FHSM_EV_KAT_REPORT` event
with the chain's HMAC, so calling the harness is not necessary.

### 7.7 PKCS#11 ABI compatibility

The C binding of the PKCS#11 structures uses `unsigned char` (= `CK_BYTE`) for
each field of a `CK_VERSION` — one byte per field, two bytes total. Any code
using `unsigned short` (two bytes per field) shifts every field downstream by
two bytes (`manufacturerID`, `libraryDescription`, and the rest), with two
visible effects:

- `pkcs11-tool --show-info` prints `Cryptoki version X.0` instead of `X.Y`
- the ASCII fields look empty because they begin with `\x00`

This rule is enforced by code review (CC EAL4+ ALC_DVS.1 §review procedure) on
any PR touching `src/fhsm_pkcs11.c`.

## 8. Cryptographic end-to-end validation

This section describes the operational cryptographic verification procedure: prove, through interoperability with a third-party implementation, that the module produces cryptographic artifacts conforming to standards. This is the equivalent of *Functional Acceptance Testing* before production rollout.

### 8.1 ECDSA-SHA256 test: HSM signs, external OpenSSL verifies

```bash
# 1. Generate the EC P-256 key pair
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm.so \
    --slot 0 --login --pin "$USER_PIN" \
    --keypairgen --key-type EC:secp256r1 --label "val-ecdsa" --id 03

# 2. Sign a message
echo -n "operational validation test" > /tmp/msg.bin
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm.so \
    --slot 0 --login --pin "$USER_PIN" \
    --sign --mechanism ECDSA-SHA256 \
    --input-file /tmp/msg.bin --output-file /tmp/sig.bin \
    --id 03

# 3. Export the public key
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm.so \
    --slot 0 --login --pin "$USER_PIN" \
    --read-object --type pubkey --id 03 \
    --output-file /tmp/pub.der

# 4. Validate with external OpenSSL (explicit default provider because
#    a FIPS-only config doesn't load the file store loader)
sudo openssl pkeyutl -provider default -verify \
    -pubin -inkey /tmp/pub.der -keyform DER \
    -rawin -in /tmp/msg.bin -sigfile /tmp/sig.bin \
    -digest sha256

# Expected : "Signature Verified Successfully"
```

### 8.2 RSA-PKCS-OAEP test: external OpenSSL encrypts, HSM decrypts

This test proves that the private key never left the HSM in cleartext and that the module can consume ciphertext produced elsewhere.

```bash
# 1. Generate the RSA-2048 key pair
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm.so \
    --slot 0 --login --pin "$USER_PIN" \
    --keypairgen --key-type rsa:2048 --label "val-rsa" --id 04

# 2. Export the public key
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm.so \
    --slot 0 --login --pin "$USER_PIN" \
    --read-object --type pubkey --id 04 \
    --output-file /tmp/pub-rsa.der

# 3. OpenSSL encrypts a payload with RSA-OAEP-SHA256
echo -n "ultra-secret-payload" > /tmp/plain.bin
openssl pkeyutl -provider default -encrypt \
    -pubin -inkey /tmp/pub-rsa.der -keyform DER \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 \
    -in /tmp/plain.bin -out /tmp/ct.bin

# 4. The HSM decrypts
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm.so \
    --slot 0 --login --pin "$USER_PIN" \
    --decrypt --mechanism RSA-PKCS-OAEP --hash-algorithm SHA256 \
    --input-file /tmp/ct.bin --output-file /tmp/recovered.bin \
    --id 04

# 5. Plaintext must be identical
sudo cmp /tmp/plain.bin /tmp/recovered.bin && echo "ROUND-TRIP OK"
```

### 8.3 Acceptance criteria

The module is *operationally validated* when **all** of the following criteria hold simultaneously:

1. `pkcs11-tool --show-info` displays `Cryptoki version 3.2 / Manufacturer FreeHSM C (FIPS 140-3)`.
2. `pkcs11-tool --list-mechanisms` enumerates at least the 17 FIPS-approved wired mechanisms.
3. Test §8.1 outputs `Signature Verified Successfully` --- proof that an independent third party accepts the ECDSA signature produced by the module.
4. Test §8.2 outputs `ROUND-TRIP OK` --- proof that the RSA private key remains internal to the HSM and that the module correctly decrypts external input.
5. `make integrity` reports a non-zero digest (= 32 hex bytes) in the `.fhsm_digest` section.
6. `fhsm_kat_results()` after `C_Initialize` reports `passed=1` for all 15 KATs (6 smoke + 9 CAVP SHA-256).
7. The audit log contains `module_init` / `login_ok` / `sign` records with an
   intact HMAC chain. This criterion was struck as impossible to satisfy; it is
   restored, the log now being written and verifiable.
   ```bash
   # the key, on the host
   KEY=$(xxd -p -c 32 /var/lib/freehsm/tokens/audit.key)
   freehsm-audit verify /var/lib/freehsm/tokens/audit.log $KEY
   freehsm-audit dump   /var/lib/freehsm/tokens/audit.log | head
   ```
   `verify` is a subcommand and the key is required. Expect
   `verify: N records OK, chain intact` and a zero exit status.

   Two things to record in the acceptance report rather than discover later: a
   log truncated at the end is not detected, and a start-up integrity failure
   will not appear in it. See `AGD_OPE.md` §4.3.

### 8.4 Automated suite

The `tests/full_crypto_pkcs11.sh` script automates §8.1, §8.2 and extends to AES-GCM, AES-CBC-PAD, AES-CTR, AES-CMAC, SHA-{256,384,512}, HMAC-SHA-256, ECDH1-COFACTOR-DERIVE, ML-DSA. Run:

```bash
sudo install -m 755 tests/full_crypto_pkcs11.sh /tmp/fc.sh
sudo bash /tmp/fc.sh
```

Expected output:
```
SUMMARY : N / N assertions PASS
```

Any `FAIL` assertion must be documented and resolved before production deployment. The preserved `tokens_dir` (path printed on failure) allows post-test state inspection for diagnostic.

## 9. De-installation

```bash
# Stop any service holding the module
sudo systemctl stop freehsm-bound-service

# Securely wipe SSP material on disk
sudo shred -uvz /var/lib/freehsm/tokens/*.tok
sudo shred -uvz /var/lib/freehsm/audit/*.audit.log
sudo shred -uvz /var/lib/freehsm/kek/*.kek

# Remove the module
sudo rm /opt/freehsm/lib/libfreehsm.so /etc/freehsm/freehsm.conf
sudo rmdir /opt/freehsm/{lib,etc,bin}
sudo userdel freehsm
sudo rm -rf /var/lib/freehsm
```

`shred` is sufficient on ext4/xfs without copy-on-write semantics. On btrfs / ZFS, additionally trim the underlying device or rotate the volume key.
