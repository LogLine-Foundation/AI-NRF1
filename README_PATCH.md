# README Patch — Positioning & Differentiation

## Tagline (replace first H1 subtitle)
**AI‑NRF1: Canonical Receipt Infrastructure for AI and Regulated Systems.**
One logical value → one encoding → one hash → one receipt.

## New: How we differ from “AI Model Passport”, SLSA/in‑toto/SPDX
- **Canonical substrate, not a dashboard.** We pin *facts* as NRF‑1.1 bytes and compute CIDs over those bytes. Dashboards are optional, proofs are primary.
- **Air‑gapped verification.** `ainrf1 verify` runs offline with signatures and allowlists; no SaaS dependency.
- **LLM‑first, zero‑choice.** Spec fits in a single context window; models can emit/inspect receipts deterministically.
- **Deterministic runtime.** Certified Runtime embeds `binary_sha256` and `model_sha256` in receipts for replayability.

## Naming note
- On‑wire format keeps the name **NRF‑1.1**.
- Project branding: **AI‑NRF1** (or “LogLine NRF‑1.1”) to avoid confusion with unrelated scientific NRF1 terms.
