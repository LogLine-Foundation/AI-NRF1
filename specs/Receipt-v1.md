# Receipt v1 — Certified Runtime + URL + CID/DID

Wire format: NRF Map. All hashes/signatures over **NRF bytes without `sig`** (`receipt_cid` is computed on that).

## Fields
- `v: "receipt-v1"`
- `t: Int64` nanos (UTC)
- `body: any` (decision/policy/context)
- `issuer_did: String` (DID of signer)
- `subject_did?: String`
- `kid?: String` (key id for rotation)
- `receipt_cid: String` = `b3:` + hex(BLAKE3(NRF_without_sig))
- `prev?: String` (chain)
- `nonce: Bytes(16)` (random)
- `rt: Map` (Certified Runtime)
  - `name: String`, `version: String`, `commit?: String`
  - `binary_sha256: Bytes(32)` — hash of executable/container/wasm actually executed
  - `env: Map<String,String>` — deterministic env (engine, model, model_hash, seed, temperature, top_p, toolchain_sha256, ...)
  - `certs: Array<Bytes>` — cosign/rekor/intoto bundles (optional but recommended)
- `url: String` — viewer/artifact URL for this receipt/bundle
- `sig: Bytes(64)` — Ed25519 over `BLAKE3(NRF_without_sig)`

## Errors
MissingCertifiedRuntime, InvalidRuntimeHash, UnknownRuntime, InvalidRuntimeCerts, InvalidReceiptURL.

## Determinism
- Reasoning runs: seed=0, temperature=0, top_p=1.
- Include `model_hash` (sha256 of gguf) in `rt.env` for local models.

## Security Notes
- Domain separation for signatures is advised (`context = "receipt.v1"` prepended before hashing in SDKs).
- Allowlist runtime hashes in CI; require cosign/rekor for production.
