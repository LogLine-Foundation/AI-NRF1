#!/usr/bin/env bash
set -euo pipefail
PROFILE=$(jq -r '.engine.profile' artifacts/last_receipt.json)
if [[ "$PROFILE" == "LLM-Smart" ]]; then
  jq -e '.engine.model_sha256 | test("^sha256:[a-f0-9]{64}$")' artifacts/last_receipt.json > /dev/null
  echo "ok: model_sha256 present for LLM-Smart"
else
  echo "skip: not LLM-Smart"
fi
