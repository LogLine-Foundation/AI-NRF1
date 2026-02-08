#!/usr/bin/env bash
set -euo pipefail

# Orchestrates building the Autobundle release after all gates pass.
# Produces: dist/ai-nrf1_autobundle_${GITHUB_SHA:-local}.zip

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

SHA="${GITHUB_SHA:-local}"
OUT="$DIST/ai-nrf1_autobundle_${SHA}.zip"

# Collect artifacts (adjust paths if your layout differs)
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Core specs & docs
mkdir -p "$TMP/specs" "$TMP/docs" "$TMP/examples"
cp -r "$ROOT/specs" "$TMP/" || true
cp -r "$ROOT/docs" "$TMP/" || true
cp -r "$ROOT/examples" "$TMP/" || true

# Rust core crates (source + Cargo.lock for reproducibility)
mkdir -p "$TMP/impl/rust"
cp -r "$ROOT/impl/rust/nrf-core" "$TMP/impl/rust/" || true
cp -r "$ROOT/impl/rust/receipts" "$TMP/impl/rust/" 2>/dev/null || true
cp -r "$ROOT/impl/rust/policy-engine" "$TMP/impl/rust/" 2>/dev/null || true

# Python ref (source + pinned deps if any)
mkdir -p "$TMP/impl/python"
cp -r "$ROOT/impl/python" "$TMP/impl/" || true

# CLI binaries if available
if [ -f "$ROOT/tools/nrf1-cli/target/release/nrf1" ]; then
  mkdir -p "$TMP/bin"
  cp "$ROOT/tools/nrf1-cli/target/release/nrf1" "$TMP/bin/"
fi

# Test vectors & fuzz corpus (minimized + fixed) for offline reproduction
mkdir -p "$TMP/testdata"
cp -r "$ROOT/impl/rust/nrf-core/tests/vectors" "$TMP/testdata/" || true
cp -r "$ROOT/impl/rust/nrf-core/fuzz/crashers_minimized" "$TMP/testdata/" 2>/dev/null || true
cp -r "$ROOT/impl/rust/nrf-core/fuzz/crashers_fixed" "$TMP/testdata/" 2>/dev/null || true

# CI workflows (as documentation of the quality bar)
mkdir -p "$TMP/.github/workflows"
cp -r "$ROOT/.github/workflows" "$TMP/.github/" || true

# LICENSE + README
for f in README.md LICENSE SECURITY.md; do
  [ -f "$ROOT/$f" ] && cp "$ROOT/$f" "$TMP/"
done

# Pack
( cd "$TMP" && zip -qr "$OUT" . )
echo "Autobundle created at: $OUT"
