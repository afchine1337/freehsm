# Key management and file encryption — plan

Status: accepted 2026-10-09. Stages 0 and 1 built the same day; stage 1 also
brought, at the user's request, an attribute view for every object and
operator-mode re-initialisation of a token seen empty.

## What is being asked

Four additions to `fhsm-gui`: delete objects from the token, generate
symmetric and asymmetric keys for purposes other than signing, encrypt a file
and decrypt it. Each with a command-line equivalent, as every other tab has.

## Decisions taken

| | Decision | Why |
|---|---|---|
| What is encrypted | Files. First with an AES key held by the token, then for a public-key recipient (hybrid). | A file is what the other tabs work on, and what an operator has. |
| Keys generated | AES-128 and AES-256; generic secret for HMAC; RSA 3072 for OAEP; ML-KEM-768 and ML-KEM-1024. | Asked for, all four families. |
| Deletion | Keys and certificates on the token, one confirmation naming the object. In operator mode, the CA's key and certificate are refused. | Deletion cannot be undone; the confirmation is the only chance to read what is about to go. |
| Command line | A new tool, `fhsm-crypt`, over the same `pkiops` functions. | Keeps the rule the window was built on: every operation scriptable and tested in CI without a display. |

## What exists, and what is missing

**In the module, everything.** `C_DestroyObject`; `CKM_AES_KEY_GEN` and
`CKM_GENERIC_SECRET_KEY_GEN`; AES-GCM, single-part and multipart; AES key
wrap through `C_WrapKey` and through `C_Encrypt` (#14); RSA-OAEP;
`CKM_ML_KEM_KEY_PAIR_GEN` with `C_EncapsulateKey` and `C_DecapsulateKey`;
certificate objects.

**In `pkiops`, three gaps.**

1. Keys are generated for signing only. `pkiops_keygen_alg` knows nine
   signature algorithms; nothing makes a secret key or an encryption pair.
2. Nothing lists or deletes. `pkiops_keys` lists key objects and nothing
   else; certificate objects are invisible to it, and there is no destroy.
3. Nothing encrypts.

## Architecture

The same three layers as the rest of the window: `pkiops` does the work,
`fhsm-crypt` maps an `argv` onto it, the window maps widgets onto it. No
operation is written twice.

`fhsm-crypt` commands, settled in stage 0:

    fhsm-crypt list     [--class key|cert|all]
    fhsm-crypt keygen   --label L --alg aes128|aes256|hmac|rsa-oaep|ml-kem-768|ml-kem-1024
    fhsm-crypt delete   --label L [--class ...] [--yes]
    fhsm-crypt encrypt  --key L  --in F --out F.p7m
    fhsm-crypt encrypt  --cert C.pem --in F --out F.p7m
    fhsm-crypt decrypt  --key L  --in F.p7m --out F

The signature algorithms stay with `fhsm-csr keygen --alg`; `fhsm-crypt keygen`
refuses them by name and says where they are, as `fhsm-csr csr --alg` does
today.

### The file format

**CMS `AuthEnvelopedData` (RFC 5083), content AES-256-GCM (RFC 5084).** One
format for every recipient kind, read back by `openssl cms -decrypt`:

| recipient | `RecipientInfo` | the content key travels |
|---|---|---|
| AES key on the token | `KEKRecipientInfo` | wrapped with AES-KW (RFC 3394) by the token key |
| RSA public key | `KeyTransRecipientInfo` | RSA-OAEP, SHA-256 (RFC 3560) |
| ML-KEM public key | `KEMRecipientInfo` (RFC 9629) | ML-KEM, then a KDF and AES-KW |

What stays on the token, and what does not. The long-term key -- the AES key,
the RSA or ML-KEM private key -- never leaves it: every wrap or unwrap of the
content key, and every decapsulation, is a call to the module. The content key
is fresh for each file and lives in the process for the time it takes to
encrypt or decrypt that file. That is how hybrid encryption works in every
CMS implementation, and it is what lets a 4 GB file be encrypted without four
billion calls across the PKCS#11 boundary. It is cleansed when the operation
ends.

Encrypting for an RSA or ML-KEM recipient needs only the public key, from the
token or from a certificate file: anyone can encrypt for the CA operator
without access to the token.

### Deletion

`pkiops_objects` lists key and certificate objects with their class, type,
label and `CKA_ID`; `pkiops_destroy` destroys one handle. The window shows the
objects that share a label together -- a private key, its public half, a
certificate -- and asks which of them to delete, each one named in the
confirmation. Nothing is pre-selected beyond the row clicked.

Operator mode refuses to delete the configured CA's private key, public key
and certificate, with no "delete anyway": exploration mode and `fhsm-crypt`
remain for the exception, as for the other operator refusals.

## Stages

0. **Listing and deletion.** `pkiops_objects`, `pkiops_destroy`, `fhsm-crypt
   list` and `delete`, a delete button on the Token tab with its
   confirmation, the operator-mode refusal. Testable without a window.
1. **Symmetric keys.** AES-128/256 and HMAC generic secrets: sensitive, not
   extractable, `CKA_ENCRYPT`/`CKA_DECRYPT` and `CKA_WRAP`/`CKA_UNWRAP` for
   AES, `CKA_SIGN`/`CKA_VERIFY` for HMAC. `fhsm-crypt keygen`, and the Token
   tab's key generation gains them.
2. **Encryption with a token AES key.** `KEKRecipientInfo`, round trip
   through `fhsm-crypt`, and interoperability measured both ways against
   `openssl cms` with an extractable test key.
3. **RSA-OAEP.** Key pair generation (`CKA_ALLOWED_MECHANISMS` =
   `CKM_RSA_PKCS_OAEP`, so the key cannot sign), `KeyTransRecipientInfo`,
   encryption for a key on the token or a certificate file.
4. **ML-KEM.** Key pair generation and `KEMRecipientInfo`, if the probe in
   the open questions says OpenSSL can carry it.
5. **The Encryption tab,** documentation (`FHSM_CRYPT.md`, `FHSM_GUI.md`) and
   the smoke test.

Each stage brings its tests, as the classic-algorithms work did: a `pkiops`
test in C, and a shell test that checks the files with the `openssl` command
line.

## Open questions

- **Which CMS calls let the token hold the key-encryption key.** OpenSSL's CMS
  API wraps and unwraps the content key itself when given the key-encryption
  key's bytes, which a sensitive token key never yields. Settled by a probe at
  the start of stage 2: either OpenSSL lets the content key be supplied and
  the `RecipientInfo` be filled with the token's result, or the
  `RecipientInfo` is assembled here, the way `fhsm_composite.c` assembles
  certificates. The format does not change either way.
- **`KEMRecipientInfo` in OpenSSL 3.5.** RFC 9629 support, and ML-KEM in it,
  are to be measured on the Debian 13 build, not assumed. If it is absent,
  stage 4 is either assembled here or left until it arrives -- a decision to
  take with the measurement in hand.
- **HMAC.** Keys are generated; no MAC operation is in scope. Whether
  `fhsm-crypt` should compute and check an HMAC over a file is left open.
- **Profiles.** AES, HMAC, RSA-OAEP and ML-KEM are all in
  `nist-approved-only`; nothing here needs `all-mechanisms`.

## Alternatives set aside

- **A format of our own** (magic, IV, wrapped key, ciphertext, tag). Simpler
  to write, and nothing else could read it: a file encrypted for a recipient
  would need FreeHSM to open, which is the opposite of what encryption for a
  recipient is for.
- **Encrypting the content on the token.** Every block through the PKCS#11
  boundary, for no gain: the content key is single-use and the long-term key
  never leaves the token either way.
- **Keeping `keygen` in `fhsm-csr` for every key.** That tool makes requests,
  and a key that cannot sign cannot make one.
