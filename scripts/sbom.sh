#!/usr/bin/env bash
set -euo pipefail
# Generate SBOMs (CycloneDX JSON + SPDX tag-value) into dist/sbom/
# Requires syft. If syft not found, exits with message (non-fatal if called with --best-effort)

BEST_EFFORT=0
if [[ "${1:-}" == "--best-effort" ]]; then
  BEST_EFFORT=1
  shift || true
fi

if ! command -v syft >/dev/null 2>&1; then
  echo "syft not found. Install: https://github.com/anchore/syft"
  if [[ $BEST_EFFORT -eq 1 ]]; then
    echo "(best-effort) skipping SBOM generation"
    exit 0
  fi
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist/sbom"
mkdir -p "$DIST"

# Target 1: workspace source tree
syft dir:"$ROOT" -o cyclonedx-json > "$DIST/workspace.cdx.json"
syft dir:"$ROOT" -o spdx-tag-value > "$DIST/workspace.spdx"

# Target 2: CLI binary if present
if [[ -f "$ROOT/tools/nrf1-cli/target/release/nrf1" ]]; then
  syft file:"$ROOT/tools/nrf1-cli/target/release/nrf1" -o cyclonedx-json > "$DIST/nrf1.cdx.json" || true
  syft file:"$ROOT/tools/nrf1-cli/target/release/nrf1" -o spdx-tag-value > "$DIST/nrf1.spdx" || true
fi

echo "SBOMs written to $DIST"
