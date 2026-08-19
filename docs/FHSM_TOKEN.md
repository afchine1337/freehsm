<!--
Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# `fhsm-token` — provisioning a token

Initialises a token, sets its user PIN, and reports what state a slot is in.
This is the first command an operator runs; everything else in this project
assumes a provisioned token.

## Why it exists

It should have existed from the start. `FHSM_CSR.md` told anyone hitting
`CKR_TOKEN_NOT_PRESENT` to *"initialise it first (`C_InitToken`, or the
module's own provisioning tool)"* — and there was no such tool. Every
documented path into this project's own tooling began with a step that could
not be taken.

It went unnoticed because the test suite calls `C_InitToken` directly from C,
so nothing that ran regularly ever needed the missing piece. It surfaced the
first time someone followed the manual instead.

---

## Synopsis

```
fhsm-token init [--label TEXT] [--slot N] [--module PATH] [--force]
fhsm-token info [--slot N] [--module PATH]
```

Both PINs come from the environment:

| Variable | Meaning |
|---|---|
| `FHSM_SO_PIN` | Security Officer PIN — initialises the token, can reset the user PIN |
| `FHSM_PIN` | user PIN — what applications log in with |

Neither can be passed as an argument, and passing one is refused rather than
ignored: an argument is visible in `ps` to every user on the machine. That rule
matters more here than in the other tools, because `init` is the only command
that handles the SO PIN.

---

## A first token, end to end

```bash
export FHSM_SO_PIN='…'
export FHSM_PIN='…'

fhsm-token info                        # is this slot blank?
fhsm-token init --label "prod-ca"
fhsm-token info                        # initialised: yes, user PIN: set

fhsm-csr keygen --label root-ca        # now the rest of the tooling works
```

---

## `init` destroys

`C_InitToken` erases every object on the token. That is what the operation
means in PKCS#11, not a quirk of this implementation.

So `init` refuses to run against an already-initialised token unless `--force`
is given, and says which token it found:

```
fhsm-token: slot 0 already holds an initialised token ("prod-ca").
  Re-initialising DESTROYS every key on it. If that is what you
  want, pass --force. If you meant to look, use `fhsm-token info`.
```

`init` and `info` differ by four characters, and one of them loses a CA key.

---

## `info`

Prints the label, manufacturer, model, serial, PIN-length bounds, and three
states worth knowing before anything else fails:

* **initialised** — whether `C_InitToken` has ever run
* **user PIN** — whether `C_InitPIN` has ever run
* **locked** — shown only when the SO or user PIN has been locked out by
  failed attempts

### Which slot

`--slot` takes a `CK_SLOT_ID` as the module reports it through
`C_GetSlotList`, not a position in a list. Omitted, the tools enumerate:

* `fhsm-csr`, `fhsm-ca`, `fhsm-sign` use the slot holding a token, and
  **refuse when several do**, listing them with their labels. Signing with a
  key the operator did not choose is invisible until someone reads the
  certificate.
* `fhsm-token init` takes the lowest slot with no token. Where every slot
  holds one it refuses, since any choice would destroy keys.
* `fhsm-token info` prints the slot it read.

So on a module with one token, `--slot` is never needed; on one with several,
it is compulsory and the refusal tells you the values to choose from.

A blank slot reports `initialised: no` rather than an error. That is
deliberate on the module's side too: applications call `C_GetTokenInfo` before
`C_InitToken` to discover whether a slot needs provisioning, so returning
`CKR_TOKEN_NOT_PRESENT` there would make bootstrap impossible.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Usage error, or a PIN missing from the environment |
| `2` | Module could not be loaded, or a PKCS#11 call failed |
| `5` | The token is already initialised and `--force` was not given |

---

## See also

* [`FHSM_CSR.md`](FHSM_CSR.md) — requests, certificates, revocation lists
* [`FHSM_SIGN.md`](FHSM_SIGN.md) — detached signatures over arbitrary data
* [`AGD_OPE.md`](AGD_OPE.md) — operational guidance, including what
  `FHSM_INTEGRITY_ALLOW_UNSIGNED` is for and why it is forbidden in production
