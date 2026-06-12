#!/usr/bin/env bash
# ===========================================================================
# scripts/add_copyright_header.sh
#
# Prepend the Apache-2.0 + SPDX copyright header to every C/H source file
# that does not already contain "SPDX-License-Identifier" on the first 30
# lines. Idempotent : re-running the script is a no-op once the headers
# are in place.
#
# Usage :
#     ./scripts/add_copyright_header.sh [--check]
#
#   --check : list files that would be modified, do not write.
#
# CI integration : run with --check on every PR ; fail if any new file
# misses the header.
# ===========================================================================
set -euo pipefail

CHECK_MODE=0
[ "${1:-}" = "--check" ] && CHECK_MODE=1

YEAR=$(date +%Y)
AUTHOR='Afchine Madjlessi <afchine.mad@gmail.com>'

HEADER=$(cat <<EOF
/* ===========================================================================
 * Copyright ${YEAR} ${AUTHOR}
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */

EOF
)

# Find all C/H source files under src/, include/, kat/, tests/, tools/,
# excluding auto-generated files (src/gen/) and third-party (none here).
mapfile -t FILES < <(find src include kat tests tools \
    -type f \( -name '*.c' -o -name '*.h' \) \
    ! -path 'src/gen/*' \
    | sort)

MISSING=()
for f in "${FILES[@]}"; do
    if ! head -30 "$f" | grep -q "SPDX-License-Identifier"; then
        MISSING+=("$f")
    fi
done

if [ ${#MISSING[@]} -eq 0 ]; then
    echo "[copyright-header] All ${#FILES[@]} files already have SPDX header. OK."
    exit 0
fi

if [ "$CHECK_MODE" = "1" ]; then
    echo "[copyright-header] CHECK : ${#MISSING[@]} files MISSING the SPDX header :"
    printf '  %s\n' "${MISSING[@]}"
    exit 1
fi

echo "[copyright-header] Adding header to ${#MISSING[@]} files..."
for f in "${MISSING[@]}"; do
    tmp=$(mktemp)
    printf '%s\n' "$HEADER" > "$tmp"
    cat "$f" >> "$tmp"
    mv "$tmp" "$f"
    echo "  + $f"
done
echo "[copyright-header] Done."
