
#!/usr/bin/env bash
set -euo pipefail
# assumes keys and dist already exist from previous steps (sign/verify/pack)
mkdir -p samples/receipts
cp -f dist/allow.signed.json samples/receipts/allow.signed.json
cp -f dist/allow.nrf        samples/receipts/allow.nrf
cp -f keys/ed25519.pk       samples/receipts/pubkey.pk
