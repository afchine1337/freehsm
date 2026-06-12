#!/usr/bin/env bash
# ===========================================================================
# scripts/setup-release-secrets.sh
#
# Helper to export the release GPG key and prepare the strings to paste
# into GitHub Secrets for the release.yml workflow.
#
#   GitHub repo -> Settings -> Secrets and variables -> Actions
#     RELEASE_GPG_KEY        : full ASCII-armored private key block
#     RELEASE_GPG_PASSPHRASE : passphrase for that key (single line)
#
# Usage:
#   ./scripts/setup-release-secrets.sh <KEY_ID>
#
# Example:
#   ./scripts/setup-release-secrets.sh 743A6A5904A1461A646408DE48560162DBBF28A2
#
# This script :
#   1. Validates the key exists in your keyring.
#   2. Writes the ASCII-armored private key to
#      ~/.freehsm-secrets/RELEASE_GPG_KEY (chmod 600).
#   3. Prints next steps including a one-liner to clipboard-copy the key
#      (using xclip on Linux, pbcopy on macOS).
#
# SECURITY :
#   - This file lives in the repo but does NOT touch any secret material
#     except writing to ~/.freehsm-secrets/ which is .gitignore-d
#     globally.
#   - The exported private key file is shred-deleted at script end if
#     CLEANUP=1 is set.
# ===========================================================================

set -euo pipefail

KEY_ID="${1:-}"
if [[ -z "$KEY_ID" ]]; then
    echo "Usage: $0 <KEY_ID>" >&2
    echo "Example: $0 743A6A5904A1461A646408DE48560162DBBF28A2" >&2
    exit 1
fi

SECRETS_DIR="${HOME}/.freehsm-secrets"
KEY_FILE="${SECRETS_DIR}/RELEASE_GPG_KEY"
PASS_FILE="${SECRETS_DIR}/RELEASE_GPG_PASSPHRASE"

# 1. Validate the key exists and is a primary key.
if ! gpg --list-secret-keys "$KEY_ID" >/dev/null 2>&1; then
    echo "ERROR: no secret key with ID $KEY_ID in your keyring." >&2
    echo "Generate one with:  gpg --quick-generate-key 'Afchine Madjlessi <afchine.mad@gmail.com>' ed25519 sign 2y" >&2
    exit 2
fi

# 2. Prepare the secrets directory.
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# 3. Export the ASCII-armored private key.
echo "Exporting private key $KEY_ID to $KEY_FILE..."
gpg --armor --export-secret-keys "$KEY_ID" > "$KEY_FILE"
chmod 600 "$KEY_FILE"

# Sanity check : armored block must contain the begin/end markers.
if ! grep -q "BEGIN PGP PRIVATE KEY BLOCK" "$KEY_FILE"; then
    echo "ERROR: export failed (no PGP block found in $KEY_FILE)." >&2
    exit 3
fi
if ! grep -q "END PGP PRIVATE KEY BLOCK" "$KEY_FILE"; then
    echo "ERROR: export truncated (no END marker in $KEY_FILE)." >&2
    exit 4
fi

# 4. Prompt for the passphrase if not already cached.
if [[ ! -s "$PASS_FILE" ]]; then
    echo
    echo "Enter the passphrase for $KEY_ID (typed silently, written to $PASS_FILE)."
    read -srp "Passphrase: " PASS
    echo
    if [[ -z "$PASS" ]]; then
        echo "ERROR: empty passphrase rejected." >&2
        exit 5
    fi
    printf '%s' "$PASS" > "$PASS_FILE"
    chmod 600 "$PASS_FILE"
    unset PASS
fi

# 5. Print the next steps for the user.
cat <<EOF

==============================================================================
DONE. Two files are ready in $SECRETS_DIR :
   $KEY_FILE     ($(wc -l < "$KEY_FILE") lines, ASCII-armored)
   $PASS_FILE    ($(wc -c < "$PASS_FILE") bytes, single line)

NEXT STEPS — go to:
   https://github.com/afchine1337/freehsm-c/settings/secrets/actions

For each secret, click "New repository secret":

  --- RELEASE_GPG_KEY ---
  Name  : RELEASE_GPG_KEY
  Value : Paste the FULL contents of $KEY_FILE, including the
          -----BEGIN PGP PRIVATE KEY BLOCK----- and
          -----END PGP PRIVATE KEY BLOCK----- markers, with all newlines.

  --- RELEASE_GPG_PASSPHRASE ---
  Name  : RELEASE_GPG_PASSPHRASE
  Value : Paste the contents of $PASS_FILE (single line, no trailing
          newline).

CLIPBOARD HELPERS (Linux) :
   cat $KEY_FILE  | xclip -selection clipboard
   cat $PASS_FILE | xclip -selection clipboard

CLIPBOARD HELPERS (macOS) :
   cat $KEY_FILE  | pbcopy
   cat $PASS_FILE | pbcopy

Then paste in the GitHub UI textarea. DO NOT paste from a browser
display of the file — that strips newlines and the workflow will
fail with "secret key not found".

VERIFY the workflow can decrypt the key once you push a tag like
v1.1.1-rc1 :
   git tag -a v1.1.1-rc1 -m "Test release pipeline" -s
   git push origin v1.1.1-rc1
The release workflow will appear under :
   https://github.com/afchine1337/freehsm-c/actions/workflows/release.yml

If CLEANUP=1 was set, the key file is now shredded :
EOF

if [[ "${CLEANUP:-0}" == "1" ]]; then
    if command -v shred >/dev/null 2>&1; then
        shred -u "$KEY_FILE"
        shred -u "$PASS_FILE"
        echo "   ${KEY_FILE} : shredded"
        echo "   ${PASS_FILE} : shredded"
    else
        rm -f "$KEY_FILE" "$PASS_FILE"
        echo "   ${KEY_FILE} : removed (shred not available)"
        echo "   ${PASS_FILE} : removed (shred not available)"
    fi
fi

echo "=============================================================================="
