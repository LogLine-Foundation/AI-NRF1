#!/usr/bin/env bash
set -euo pipefail
jq -e '
  .trace.prompt_hash | test("^b3:[a-f0-9]{64}$") and
  .rt.binary_sha256  | test("^sha256:[a-f0-9]{64}$")
' artifacts/last_receipt.json > /dev/null
echo "ok: trace fields present"
