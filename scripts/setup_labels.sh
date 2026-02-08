#!/usr/bin/env bash
# Requires: gh (GitHub CLI)
# Usage: ./scripts/setup_labels.sh <org> <repo>
set -euo pipefail
ORG="${1:?org}"; REPO="${2:?repo}"
J=".github/labels.json"
for row in $(jq -c '.[]' "$J"); do
  name=$(echo "$row" | jq -r '.name')
  color=$(echo "$row" | jq -r '.color')
  desc=$(echo "$row" | jq -r '.description')
  gh label create "$name" -R "$ORG/$REPO" -c "$color" -d "$desc" || gh label edit "$name" -R "$ORG/$REPO" -c "$color" -d "$desc"
done
echo "Labels ensured on $ORG/$REPO"
