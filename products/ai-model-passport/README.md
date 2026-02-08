# AI Model Passport (Flagship)

## What it is
Signed, canonical **receipts** attesting to model provenance and compliance, with offline verification.

## Why it’s different
- **Canonical NRF‑1.1 bytes** under every claim (no dashboards required).
- **Certified Runtime** (binary sha256) and **model sha256** embedded in receipts.
- **Air‑gapped verification**: `ainrf1 verify` runs without internet.

## Minimal Flow
```bash
ainrf1 canon model-card.json -o context.nrf
ainrf1 judge context.nrf --policy eu-ai-act@1 --engine ollama --model llama3:8b --model-path ./models/llama-3-8b.gguf --out receipt.json
ainrf1 bundle --receipt receipt.json --context context.nrf -o passport.tgz
ainrf1 verify --bundle passport.tgz --known-runtime <sha256>
```
