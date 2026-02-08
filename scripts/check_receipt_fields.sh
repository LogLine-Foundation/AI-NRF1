#!/usr/bin/env bash
set -euo pipefail
REC="${1:-examples/receipts/passport.receipt.json}"

if jq -e 'has("ghost")' "$REC" >/dev/null; then
  jq -e '.ghost|has("budget") and has("counter") and has("cost_ms") and has("window_day")' "$REC" >/dev/null
fi

if jq -e 'has("chain")' "$REC" >/dev/null; then
  jq -e '.chain.prev_cid|test("^b3:[0-9a-f]{64}$") and .chain.link_hash|test("^b3:[0-9a-f]{64}$")' "$REC" >/dev/null
fi

echo "✅ receipt fields ok"
