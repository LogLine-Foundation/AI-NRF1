# LLM Engine Mode — HRD (High-Reasoning Density)

Flow: dirty → sanitize (TDLN) → NRF context (CID) → LLM judgment (ReasoningBit) → Signed Receipt (with Certified Runtime) → Offline Bundle.

## ReasoningBit v1 (summary)
- `context_cid: b3:*`
- `prompt_hash: blake3(rendered_prompt)`
- `model: String`
- `judgment: { verdict: PASS|FAIL|NEEDS_REVIEW, confidence: [0..1], reasoning: String }`
- `usage: { input_tokens, output_tokens, hrd_score }`
- `signature?: Bytes` (optional, wrapper/oracle)

Determinism: seed=0, temperature=0, top_p=1. Use `model_hash` for local models to make the proof portable.
