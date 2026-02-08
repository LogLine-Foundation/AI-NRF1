#!/usr/bin/env bash
set -euo pipefail
# Compute SHA256/SHA512 for every file in dist/
# Output files: dist/CHECKSUMS.sha256, dist/CHECKSUMS.sha512

DIST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/dist"
mkdir -p "$DIST"

# sha256
: > "$DIST/CHECKSUMS.sha256"
for f in "$DIST"/*; do
  [ -f "$f" ] || continue
  sha256sum "$f" >> "$DIST/CHECKSUMS.sha256"
done

# sha512
: > "$DIST/CHECKSUMS.sha512"
for f in "$DIST"/*; do
  [ -f "$f" ] || continue
  sha512sum "$f" >> "$DIST/CHECKSUMS.sha512"
done

echo "Wrote $DIST/CHECKSUMS.sha256 and $DIST/CHECKSUMS.sha512"
