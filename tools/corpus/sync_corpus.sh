#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="$ROOT/impl/rust/nrf-core/fuzz/corpus/decode_value/generated"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

echo "Generating deterministic random corpus..."
python3 "$ROOT/tools/corpus/generate_random_corpus.py" -n 128 -o "$OUTDIR"

echo "Corpus generated at $OUTDIR"
# Basic sanity: list and compute a manifest hash (deterministic set content)
MANIFEST="$(mktemp)"
find "$OUTDIR" -type f -name 'generated_*' -print0 | sort -z | xargs -0 sha256sum > "$MANIFEST"
echo "Manifest hash:"
sha256sum "$MANIFEST" || true

# Optionally, compare against tracked files to enforce up-to-date corpus (in CI we just fail if diff exists)
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if ! git diff --quiet -- "$OUTDIR" ; then
    echo "ERROR: Generated corpus differs from committed files. Run tools/corpus/sync_corpus.sh and commit." >&2
    git status --short "$OUTDIR" || true
    exit 1
  fi
fi
