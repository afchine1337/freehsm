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
| **OE.OS**    | Linux ≥ 5.4 with `mlock` capability                              | `uname -r ; getcap /usr/local/lib/libfreehsm-fips.so`            |
| **OE.STORAGE** | Local filesystem with atomic `rename` (ext4/xfs)               | `findmnt -T /var/lib/freehsm -o FSTYPE`                          |
| **OE.OPENSSL** | OpenSSL ≥ 3.0 with FIPS provider loaded and active             | `openssl list -providers \| grep -A2 fips`                        |
| **OE.OP**    | Administrator trained, controls authentication credentials       | (procedural --- see §6)                                          |
| **OE.PHYS**  | Host physically protected (locked rack / authorized access)     | (procedural --- site security)                                  |
| **OE.HARDWARE** | CPU with AES-NI (x86_64) or ARMv8 Crypto Ext.                | `grep aes /proc/cpuinfo \| head -1`                              |

If any verification fails, **do not proceed** : the TOE will not enter its claimed secure state.

## 2. Delivery verification

The TOE is delivered as four files, published on the source forges with the signed release tag :

```
libfreehsm-fips.so              # the cryptographic module
libfreehsm-fips.so.sha256       # detached digest, GPG-signed
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
gpg --verify libfreehsm-fips.so.sha256
# Expected output : Good signature from "FreeHSM Release Manager <release@freehsm.example>"
gpg --verify freehsm-c-src.tar.xz.sha256
```

Refuse delivery if either signature does not validate.

### 2.3 Integrity check

```bash
sha256sum -c libfreehsm-fips.so.sha256
# Expected : libfreehsm-fips.so: OK

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

The resulting `libfreehsm-fips.so` SHA-256 MUST match the value in `libfreehsm-fips.so.sha256`. See `docs/REPRODUCIBLE_BUILD.md` for the full procedure.

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
| `/opt/freehsm/lib/libfreehsm-fips.so` | root       | 0755 | The cryptographic module             |
| `/etc/freehsm/freehsm.conf`            | root       | 0644 | Module config, the only path read     |
| `/var/lib/freehsm/tokens/slot*.tok`     | freehsm    | 0600 | Encrypted token files                |
| `/var/lib/freehsm/audit/slot*.audit.log` | freehsm   | 0600 | HMAC-chained audit logs              |
| `/var/lib/freehsm/kek/*.kek`            | freehsm    | 0600 | Local KMS KEK material (if used)     |

### 3.2 Module installation

```bash
sudo install -o root -g root -m 0755 libfreehsm-fips.so \
    /opt/freehsm/lib/libfreehsm-fips.so

# Create a dedicated unprivileged user under which any HSM-using daemon
# will run. The user MUST own /var/lib/freehsm and have CAP_IPC_LOCK.
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/freehsm freehsm
sudo setcap 'cap_ipc_lock=+ep' /opt/freehsm/lib/libfreehsm-fips.so
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

### 3.4 Verifying module identity

```bash
readelf -p .comment /opt/freehsm/lib/libfreehsm-fips.so
# Expected : GCC 12.2.0 ; binutils 2.40 ; (matches Dockerfile.build pins)

readelf -p .gnu.version_d /opt/freehsm/lib/libfreehsm-fips.so | grep -F "1.0.0-FIPS"
# Expected : the SONAME version embedded by the linker

readelf -S /opt/freehsm/lib/libfreehsm-fips.so | grep .fhsm_digest
# Expected : a 32-byte read-only section --- this is the embedded integrity digest
```

If `.fhsm_digest` is all zeros, the module was **not signed** and will refuse to initialize in shipping mode :

```bash
xxd -s 0x2000 -l 32 /opt/freehsm/lib/libfreehsm-fips.so
# Expected (signed) : 32 bytes of hex data (the SHA-256 self-digest)
# All-zero ⇒ refuse to deploy.
```

## 4. Initial configuration

### 4.1 Module configuration

`make install` writes `/etc/freehsm/freehsm.conf`. That is the path the module
reads ; nothing else is consulted.

```
# Runtime mode: fips | legacy. Overridden by FHSM_MODE.
mode = fips

# mlock(2)-ed secure heap holding key material, in KiB.
# Range 64..65536, rounded up to a power of two.
secure_heap_kb = 8192
```

**Only these two keys are read.** Earlier revisions of this guide listed nine —
`fips_strict`, `audit_mandatory`, `pin_max_failed`, `pin_throttle_base_ms`,
`pin_throttle_max_ms`, `pbkdf2_iterations`, `tokens_dir`, `audit_dir` — at a
path the module never opened. None of them had any effect. An operator who
hardened the module by editing that file changed nothing (#128).

The remaining parameters are set at build time or through the environment :

| Parameter | Where it is set |
|---|---|
| PIN failure limit, throttle curve | compile-time (`FHSM_PIN_MAX_FAILED` and the throttle constants) |
| PBKDF2 iteration count | compile-time, 200 000 |
| token directory | `FHSM_TOKENS_DIR` environment variable |
| approved-mechanism set | build profile, `make generate PROFILE=fips-strict` |

Note the scope of `mode` : it selects KAT/dispatch behaviour. **Which mechanisms
the PKCS#11 API advertises and executes is fixed when the module is built** and
cannot be changed from this file. A deployment that must refuse non-approved
mechanisms has to be built with `PROFILE=fips-strict` — verify with
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
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --show-info
```

Expected output excerpt :

```
Cryptoki version 3.2
Manufacturer     FreeHSM C (FIPS 140-3 candidate)
Library          libfreehsm-fips.so <version>-FIPS
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
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --init-token --label "prod-slot-0" --so-pin "$SO_PIN"
unset SO_PIN
```

Verify the token state :

```bash
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --list-slots
# Expected : Slot 0 (0x0): present, label "prod-slot-0"
```

### 4.4 User PIN initialization (delegated)

The SO then sets a user PIN for the day-to-day operator. The User PIN MUST differ from the SO PIN.

```bash
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
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
6. `mode = fips` is set in `/etc/freehsm/freehsm.conf`, **and** the module was built with `PROFILE=fips-strict` — the file alone does not restrict the mechanism set (`make show-profile` confirms both).

If any of these is false, the system is **not** in the certified state and must be re-installed before exposing it to users.

## 6. Operator responsibilities (procedural)

The administrator confirms in writing (audit trail) that :

- Operators are trained on `docs/AGD_OPE.md` before being granted credentials.
- PINs are transmitted to operators over an authenticated channel and never written down.
- The audit log is reviewed at least weekly (cf. `AGD_OPE.md` §6).
- Backup of the token files is performed under the **same access controls** as the live store ; backups copied to media must be encrypted at rest.

## 7. Cryptographic end-to-end validation

This section describes the operational cryptographic verification procedure: prove, through interoperability with a third-party implementation, that the module produces cryptographic artifacts conforming to standards. This is the equivalent of *Functional Acceptance Testing* before production rollout.

### 7.1 ECDSA-SHA256 test: HSM signs, external OpenSSL verifies

```bash
# 1. Generate the EC P-256 key pair
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --slot 0 --login --pin "$USER_PIN" \
    --keypairgen --key-type EC:secp256r1 --label "val-ecdsa" --id 03

# 2. Sign a message
echo -n "operational validation test" > /tmp/msg.bin
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --slot 0 --login --pin "$USER_PIN" \
    --sign --mechanism ECDSA-SHA256 \
    --input-file /tmp/msg.bin --output-file /tmp/sig.bin \
    --id 03

# 3. Export the public key
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
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

### 7.2 RSA-PKCS-OAEP test: external OpenSSL encrypts, HSM decrypts

This test proves that the private key never left the HSM in cleartext and that the module can consume ciphertext produced elsewhere.

```bash
# 1. Generate the RSA-2048 key pair
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --slot 0 --login --pin "$USER_PIN" \
    --keypairgen --key-type rsa:2048 --label "val-rsa" --id 04

# 2. Export the public key
sudo -u freehsm pkcs11-tool \
    --module /opt/freehsm/lib/libfreehsm-fips.so \
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
    --module /opt/freehsm/lib/libfreehsm-fips.so \
    --slot 0 --login --pin "$USER_PIN" \
    --decrypt --mechanism RSA-PKCS-OAEP --hash-algorithm SHA256 \
    --input-file /tmp/ct.bin --output-file /tmp/recovered.bin \
    --id 04

# 5. Plaintext must be identical
sudo cmp /tmp/plain.bin /tmp/recovered.bin && echo "ROUND-TRIP OK"
```

### 7.3 Acceptance criteria

The module is *operationally validated* when **all** of the following criteria hold simultaneously:

1. `pkcs11-tool --show-info` displays `Cryptoki version 3.2 / Manufacturer FreeHSM C (FIPS 140-3)`.
2. `pkcs11-tool --list-mechanisms` enumerates at least the 17 FIPS-approved wired mechanisms.
3. Test §7.1 outputs `Signature Verified Successfully` --- proof that an independent third party accepts the ECDSA signature produced by the module.
4. Test §7.2 outputs `ROUND-TRIP OK` --- proof that the RSA private key remains internal to the HSM and that the module correctly decrypts external input.
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

### 7.4 Automated suite

The `tests/full_crypto_pkcs11.sh` script automates §7.1, §7.2 and extends to AES-GCM, AES-CBC, AES-CTR, AES-CMAC, SHA-{256,384,512}, HMAC-SHA-256, ECDH1_DERIVE, ML-DSA. Run:

```bash
sudo install -m 755 tests/full_crypto_pkcs11.sh /tmp/fc.sh
sudo bash /tmp/fc.sh
```

Expected output:
```
SUMMARY : N / N assertions PASS
```

Any `FAIL` assertion must be documented and resolved before production deployment. The preserved `tokens_dir` (path printed on failure) allows post-test state inspection for diagnostic.

## 8. De-installation

```bash
# Stop any service holding the module
sudo systemctl stop freehsm-bound-service

# Securely wipe SSP material on disk
sudo shred -uvz /var/lib/freehsm/tokens/*.tok
sudo shred -uvz /var/lib/freehsm/audit/*.audit.log
sudo shred -uvz /var/lib/freehsm/kek/*.kek

# Remove the module
sudo rm /opt/freehsm/lib/libfreehsm-fips.so /etc/freehsm/freehsm.conf
sudo rmdir /opt/freehsm/{lib,etc,bin}
sudo userdel freehsm
sudo rm -rf /var/lib/freehsm
```

`shred` is sufficient on ext4/xfs without copy-on-write semantics. On btrfs / ZFS, additionally trim the underlying device or rotate the volume key.
