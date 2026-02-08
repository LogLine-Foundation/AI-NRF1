# Security Policy

## Supported
- Specs and schemas in this repo.
- Reference CLI/SDK when present.

## Reporting a Vulnerability
Email: security@ubl.agency. Use PGP if desired (publish fingerprint on the site). We aim to acknowledge within 72h.

## Hardening Baselines
- All hashes/signatures over NRF bytes.
- Receipt MUST include `rt.binary_sha256`.
- Deterministic LLM params (seed=0, temperature=0, top_p=1) for proofs.
- Production: runtime allowlist and cosign/rekor verification recommended.
