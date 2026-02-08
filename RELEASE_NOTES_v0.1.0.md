# Release Notes — v0.1.0

Initial public release.

## Highlights
- NRF-1.1 **normative spec** com MUST de hashing sobre bytes NRF (§5).
- **Interoperability Guide** (CBOR/MsgPack/Bencode), mantendo NRF como wire canônico.
- **LogLine binding**: onde e como os hashes/assinaturas usam NRF.
- **Rust crate** + testes e **Python checker**.
- **CLI** (`nrf1 canon`) com conversões NRF↔CBOR (subset estrito) por feature flag.
- **CI** (GitHub Actions), exemplos, vetores, docs de contribuição e segurança.

## Breaking changes
- n/a (primeira versão pública).

## Upgrade notes
- Se você já tem payloads experimentais, re-encode usando o crate para garantir **canonicidade** e recomputar hashes.
