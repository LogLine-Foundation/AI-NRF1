# Release: v0.3.9 (BASE sealed)

**Date:** 2026-02-08
**Channel:** BASE (sealed core)

## 🚀 Highlights
- **NRF‑1.1 Core spec sealed**: wire format, error taxonomy, ABNF, NFC/BOM, minimal varint32.
- **JSON↔NRF import (normative)**: floats rejected; integers must be Int64 range; keys NFC + sorted.
- **Security considerations**: Unicode pin, timestamp trust, small‑domain hashing, deterministic runtime notes.
- **LLM Pocket Guide**: zero‑choice cheatsheet for emission/audit of NRF bytes.
- **Positioning**: README updated with tagline + differentiation vs “AI Model Passport”, SLSA/in‑toto/SPDX.
- **AI Model Passport scaffolding**: product README + example E2E structure (canon → judge → bundle → verify).

## ✅ What’s Included
- `specs/nrf1.1-core.md`
- `specs/nrf1.1-mapping-json.md`
- `specs/security-considerations.md`
- `specs/nrf1.1-llm-guide.md`
- `products/ai-model-passport/README.md`
- `examples/model-passport/README.md`

## 🔐 Canonical Rules (must-pass)
- Hashes are **always** computed over full NRF stream bytes (magic + value).
- Strings must be **UTF‑8 NFC**, and **must not** contain U+FEFF (BOM).
- varint32 is **unsigned LEB128** and **must be minimal**; non‑minimal encodings are rejected.
- Maps: keys are **Strings**; **sorted** by raw bytes; **no duplicates**.
- Only **Int64** (8‑byte big‑endian). **No floats** in core; use fixed‑point at higher layer.

## 🧪 Conformance Gate (CI target)
- Decode/encode round‑trip identity for all valid vectors.
- `encode(decode(x)) == x` and `decode(encode(v)) == v` for vectors.
- Each invalid vector maps to the named error (`NonMinimalVarint`, `NotNFC`, etc.).

## 🧰 Install / Quickstart
```bash
# (placeholder) build CLI
cargo build -p ainrf1 --release

# Canonicalize JSON
ainrf1 canon examples/model-passport/input/model-card.json -o context.nrf

# Judge (engine local or mock until engine wired)
ainrf1 judge context.nrf --policy eu-ai-act@1 --engine local --model ./models/llama-3-8b.gguf --out receipt.json

# Bundle and verify offline
ainrf1 bundle --receipt receipt.json --context context.nrf -o passport.tgz
ainrf1 verify --bundle passport.tgz --allow-runtime-sha256 <sha256-of-runtime>
```

## 📦 Release Artifacts (target)
- `ai-nrf1-v0.3.9-x86_64-unknown-linux-gnu.tar.gz` (CLI)
- `ai-nrf1-v0.3.9-aarch64-apple-darwin.tar.gz` (CLI)
- `nrf-core-v0.3.9.crate` (Rust core crate)
- `CHANGELOG.md` + `SBOM.cdx.json`

## 🔜 Next (Passport M1 – MARKET open)
- Policy packs: `pack-provenance@1`, `pack-compliance/eu-ai-act@1`
- Benchkits (basic/medium/complex)
- GitHub Action `ainrf1-action`
- Docker images (runtime + offline verifier)
- PDF+Badge (QR → CID), Product page

---
**Identity:** LogLine / AI‑NRF1 — Canonical Receipt Infrastructure for AI and Regulated Systems.
