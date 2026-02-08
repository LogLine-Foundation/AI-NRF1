# ainrf1 CLI — Judge & Bundle

```bash
# 1) Canoniza → NRF
ainrf1 sanitize samples/input/model_card.json --out artifacts/ctx.nrf

# 2a) Julga em modo Smart (local)
ainrf1 judge artifacts/ctx.nrf   --manifest manifests/engine/llm-smart.yaml   --out artifacts/receipt_smart.nrf   --emit-json artifacts/last_receipt.json

# 2b) OU julga em modo Engine (premium)
ainrf1 judge artifacts/ctx.nrf   --manifest manifests/engine/llm-engine.yaml   --out artifacts/receipt_engine.nrf   --emit-json artifacts/last_receipt.json

# 3) Bundle e verificação (offline)
ainrf1 bundle artifacts/receipt_engine.nrf --include-context --out artifacts/passport.zip
ainrf1 verify artifacts/passport.zip
```
