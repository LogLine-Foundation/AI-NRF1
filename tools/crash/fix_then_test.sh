#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIN="$ROOT/impl/rust/nrf-core/fuzz/crashers_minimized"
FIX="$ROOT/impl/rust/nrf-core/fuzz/crashers_fixed"
TESTS="$ROOT/impl/rust/nrf-core/tests/regressions"
TRACK="$ROOT/tools/crash/CRASHERS.toml"

mkdir -p "$FIX" "$TESTS"

# small inline parser to toggle status=fixed for a given file in TOML
toml_set_fixed() {
  local file="$1"
  if [ ! -f "$TRACK" ]; then return; fi
  tmp="$(mktemp)"
  awk -v target="$file" '
    BEGIN { inblk=0; }
    /^\[\[crasher\]\]/ { 
      if (inblk && match(file,"^$")) {print "status = \"fixed\""} 
      inblk=1; print; next 
    }
    /^file\s*=\s*"/ {
      file=$0; gsub(/.*=\s*"/,"",file); gsub(/".*/,"",file);
      print $0; next
    }
    /^status\s*=\s*"/ {
      if (inblk && file==target) { print "status = \"fixed\""; next }
    }
    { print }
  ' "$TRACK" > "$tmp" || true
  mv "$tmp" "$TRACK"
}

# function to run predicate via minimizer (prints True/False)
pred_ok() {
  local f="$1"
  python3 "$ROOT/tools/crash/minimize_case.py" "$f" -o "$f.tmp" | grep -q "still failing: True"
  local rc=$?
  rm -f "$f.tmp" || true
  return $rc
}

changed=0
for f in $(find "$MIN" -maxdepth 1 -type f -name "*.nrf" | sort); do
  base="$(basename "$f")"
  if pred_ok "$f"; then
    echo "Still failing: $base"
    continue
  fi
  echo "➡️  Fixed detected: $base"
  # move to fixed
  mv "$f" "$FIX/$base"
  # generate regression test
  python3 "$ROOT/tools/crash/generate_regression.py" "$base" -o "$TESTS/reg_${base%.nrf}.rs"
  # update tracker
  toml_set_fixed "$base" || true
  changed=1
done

if [ $changed -eq 0 ]; then
  echo "No fixed crashers detected."
else
  echo "Fixed crashers moved and tests created in $TESTS."
fi
