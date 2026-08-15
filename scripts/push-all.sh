#!/bin/bash
set -e
for r in origin gitlab codeberg; do
  echo "=== pushing to $r ==="
  git push "$r" main 2>&1 || true
  git push "$r" --tags 2>&1 || true
done
