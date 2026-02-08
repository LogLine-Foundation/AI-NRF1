#!/usr/bin/env bash
set -euo pipefail
P95=$(jq -r '.metrics.p95_latency_ms // empty' artifacts/last_metrics.json)
[[ -z "$P95" ]] && { echo "skip: no metrics"; exit 0; }
PROFILE=$(jq -r '.engine.profile' artifacts/last_receipt.json)
if [[ "$PROFILE" == "LLM-Engine" ]]; then
  awk -v x="$P95" 'BEGIN{ exit !(x<=1500) }'
  echo "ok: latency p95<=1500ms (Engine)"
else
  awk -v x="$P95" 'BEGIN{ exit !(x<=3000) }'
  echo "ok: latency p95<=3000ms (Smart)"
fi
