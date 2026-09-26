#!/usr/bin/env python3
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
"""Do the bilingual evaluation documents still say the same thing?

CONTRIBUTING.md requires every change to a CC document to be made in both
languages. That is a review rule, and a review rule is enforced by remembering
-- which is the thing this repository spends its days replacing with guards.

It was not remembered. docs/FIPS_140_3.fr.md listed KMAC128/KMAC256 as
approved algorithms for three months after the KMAC mechanisms were removed
from the module, because they rested on code points that do not exist in
pkcs11t.h v3.2. The English policy never had the row. A Security Policy
claiming an algorithm the module does not implement is a serious defect, and
nothing in the tree could see it: the twins are prose, and prose differs by
design.

## What is comparable across a translation

Not the sentences, and not the table headers -- "Entropy source" is
"Source d'entropie" and that is correct. What does not translate:

  * identifiers in backticks: `CKM_SHA_1_HMAC`, `C_Digest`, `FHSM_OBJF2_*`
  * standards references: FIPS 198-1, SP 800-131A, RFC 5869, ISO/IEC 19790
  * PKCS#11 and CK_ names appearing bare in tables: KMAC, ML-KEM, CKM_AES_GCM

Those three sets are the claims. A name in one twin and not the other is
either a translation the other is missing or a claim only one of them makes,
and both are worth a look.

## What this deliberately does not do

It does not compare counts of anything, or require the same order. A
translated document legitimately splits a sentence in two or merges a table
note into a paragraph. Reporting that would produce noise, and a check that
cries wolf is uninstalled within a month.

Exit status: 0 when every pair agrees, 1 otherwise. Run with --verbose to see
the matched sets rather than only the differences.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Identifiers in backticks. Restricted to things that look like code rather
# than any backticked word: a French twin may quote `approuvé` and mean it.
RE_BACKTICK = re.compile(r"`([A-Za-z_][A-Za-z0-9_./-]{2,})`")
#
# The `(?:[a-z_]+/)*` prefix is what lets a path with a directory in it
# through. Without it the final alternative required the filename to start
# the string, so `src/gen/fhsm_dispatch.c` was silently not a claim while
# `fhsm_dispatch.c` was -- and a check that skips the qualified form skips
# exactly the case where the two twins disagree about WHERE something lives.
#
# Found on 2026-09-26: ARCHITECTURE.md named `src/fhsm_dispatch.c`, a file
# that does not exist, while the French twin named `src/gen/fhsm_dispatch.c`,
# which does. The twins disagreed, one of them was wrong, and this check ran
# green over it because of the anchor.
_CODEY = re.compile(
    r"^(CK[AMKORSU]?_|C_[A-Z]|FHSM_|fhsm_"
    r"|(?:\.?[a-z_]+/)*[a-z_][a-z0-9_-]*\.(c|h|py|sh|md|json|yml))")

# Standards. The spellings are fixed by the standards bodies, not by us, which
# is what makes them comparable at all.
RE_STANDARD = re.compile(
    r"\b(?:FIPS\s?\d{3}(?:-\d)?|SP\s?800-\d{1,3}[A-Za-z]?|RFC\s?\d{3,5}"
    r"|ISO/IEC\s?\d{4,5}(?:-\d)?|PKCS#11|NIST\s?SP\s?800-\d{1,3})"
)

# Bare algorithm and mechanism names that appear in tables without backticks.
# Closed list on purpose: an open one would match ordinary words in one
# language and not the other.
BARE_NAMES = (
    "KMAC128", "KMAC256", "KMAC", "ML-KEM", "ML-DSA", "SLH-DSA", "EdDSA",
    "ECDSA", "RSA-PSS", "CTR_DRBG", "HKDF", "PBKDF2", "HMAC", "AES-GCM",
    "SHA-1", "MD5", "SHA-2", "SHA-3", "SHAKE128", "SHAKE256",
    "Ed25519", "Ed448", "X25519", "X448",
)


# A twin that says it is a pointer rather than a translation. MECHANISMS.fr.md
# is one: the generator emits English only, and the French file exists to send
# the reader there. Comparing their claims would report the whole mechanism
# table as missing, every time, for ever.
RE_POINTER = re.compile(r"<!--\s*doc-twins:\s*pointer")

# "C_Encrypt/Decrypt" and "C_GenerateKey/KeyPair" are one identifier written as
# two, and the twins use the shorthand in different places. It is dropped
# rather than expanded.
#
# The first version expanded it, by taking the prefix of the head and gluing
# the tail on. That reads C_Encrypt/Decrypt correctly and turns
# C_GenerateKey/KeyPair into "C_KeyPair" -- a symbol that exists nowhere,
# invented by a rule that could not know whether the prefix was "C_" or
# "C_Generate". A checker that fabricates names to compare them is worse than
# one that admits it cannot read an abbreviation.
def _is_shorthand(name: str) -> bool:
    return "/" in name and not name.lower().endswith(
        (".c", ".h", ".py", ".sh", ".md", ".json", ".yml"))


def claims(text: str) -> dict[str, set[str]]:
    """The language-invariant claims a document makes."""
    ticked = {m for m in RE_BACKTICK.findall(text)
              if _CODEY.match(m) and not _is_shorthand(m)}
    standards = {re.sub(r"\s+", " ", m).strip() for m in RE_STANDARD.findall(text)}
    bare = {n for n in BARE_NAMES if re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", text)}
    return {"identifiers": ticked, "standards": standards, "algorithms": bare}


def compare(en: Path, fr: Path, verbose: bool) -> list[str] | None:
    en_text, fr_text = en.read_text(encoding="utf-8"), fr.read_text(encoding="utf-8")
    if RE_POINTER.search(fr_text) or RE_POINTER.search(en_text):
        if verbose:
            print(f"{en.name} <-> {fr.name}: pointer pair, not compared")
        return None
    a, b = claims(en_text), claims(fr_text)
    problems: list[str] = []
    for kind in ("identifiers", "standards", "algorithms"):
        only_en, only_fr = sorted(a[kind] - b[kind]), sorted(b[kind] - a[kind])
        if verbose:
            print(f"    {kind}: {len(a[kind])} en / {len(b[kind])} fr, "
                  f"{len(a[kind] & b[kind])} shared")
        if only_en:
            problems.append(f"  {kind} in {en.name} only: {', '.join(only_en)}")
        if only_fr:
            problems.append(f"  {kind} in {fr.name} only: {', '.join(only_fr)}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--docs", default="docs", help="directory holding the twins")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    root = Path(args.docs)
    pairs = []
    for fr in sorted(root.glob("*.fr.md")):
        en = fr.with_name(fr.name[: -len(".fr.md")] + ".md")
        if en.exists():
            pairs.append((en, fr))

    if not pairs:
        print(f"[check_doc_twins] no bilingual pairs under {root}", file=sys.stderr)
        return 1

    bad = 0
    skipped = 0
    for en, fr in pairs:
        problems = compare(en, fr, args.verbose)
        if problems is None:
            skipped += 1
        elif problems:
            bad += 1
            print(f"{en.name} <-> {fr.name}")
            for p in problems:
                print(p)
        elif args.verbose:
            print(f"{en.name} <-> {fr.name}: agree")

    print(f"\n[check_doc_twins] {len(pairs)} pair(s), {bad} with differences, "
          f"{skipped} pointer pair(s) not compared")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
