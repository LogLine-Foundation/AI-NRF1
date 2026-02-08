#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IN="$ROOT/impl/rust/nrf-core/fuzz/crashers"
OUT="$ROOT/impl/rust/nrf-core/fuzz/crashers_minimized"
mkdir -p "$OUT"
found=0
for f in $(find "$IN" -type f -name "*.nrf" 2>/dev/null || true); do
  found=1
  base=$(basename "$f")
  echo "Minimizing $base ..."
  python3 "$ROOT/tools/crash/minimize_case.py" "$f" -o "$OUT/$base"
done
if [ $found -eq 0 ]; then
  echo "No crashers found under $IN"
fi
