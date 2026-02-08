# Conformance Kit
- Golden vectors for NRF-1.1 (valid/invalid).
- Property tests: decode(encode(v)) == v; encode(decode(bytes_valid)) == bytes_valid.
- Fuzz corpus seeds under `corpus/` for `NonMinimalVarint`, `InvalidUTF8`, `NotNFC`, `BOMPresent`, `UnsortedKeys`, etc.
- Runtime allowlist check: `rt.binary_sha256` MUST be in `allowlist.json` for production.
