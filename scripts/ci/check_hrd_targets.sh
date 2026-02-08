#!/usr/bin/env bash
set -euo pipefail
R=$(jq -r '.usage.hrd_score' artifacts/last_receipt.json)
P=$(jq -r '.engine.profile' artifacts/last_receipt.json)
if [[ "$P" == "LLM-Engine" ]]; then
  awk -v r="$R" 'BEGIN{ exit !(r>=0.85) }'
  echo "ok: HRD>=0.85 (Engine)"
else
  awk -v r="$R" 'BEGIN{ exit !(r>=0.80) }'
  echo "ok: HRD>=0.80 (Smart)"
fi
