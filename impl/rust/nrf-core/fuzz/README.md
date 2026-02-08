# Fuzzing `nrf-core` (decoder)

We use `cargo-fuzz` (libFuzzer) to fuzz `nrf_core::decode` against arbitrary byte inputs.

## Quick start

```bash
cd impl/rust/nrf-core
cargo install cargo-fuzz
cargo fuzz run decode_value -- -max_total_time=30
```

The seed corpus lives under `fuzz/corpus/decode_value/` and includes both valid and invalid NRF-1.1 samples.

## CI

CI runs a short fuzz session on every PR (see `.github/workflows/ci-fuzz.yml`). Increase the time budget when debugging locally.

## Targets

- `decode_value`: feeds whole byte streams to the top-level `decode` function.
- `varint32`: exercises the varint32 parser via a feature-gated helper.

## Corpus

The `corpus/decode_value/` directory is auto-seeded from any available test vectors
(e.g., `impl/rust/nrf-core/tests/vectors/*.{nrf,bin,hex,txt}`) when present.
