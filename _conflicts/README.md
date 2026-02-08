# NRF-1.1 — Canonical Binary Encoding (LLM-first, Zero-Choice)

[![CI](https://img.shields.io/github/actions/workflow/status/<org>/AI-NRF1/ci.yml?branch=main)](https://github.com/<org>/AI-NRF1/actions)
[![Crates.io](https://img.shields.io/crates/v/ai-nrf1.svg)](https://crates.io/crates/ai-nrf1)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](./LICENSE-MIT)


**One value → one byte stream → one hash.** This repository hosts the normative spec, interoperability guidance, and reference implementations.

## Structure
- `specs/NRF-1.1-spec.md` — **normative** canonical encoding
- `specs/NRF-1.1-Interop.md` — **informative** import/export profiles (CBOR/MsgPack/Bencode)
- `specs/NRF-1.1-in-LogLine.md` — **informative** binding to LogLine content-addresses
- `impl/rust/` — Rust reference implementation + tests
- `impl/python/nrf1_check.py` — tiny Python cross-check encoder/decoder

## Licensing
Dual-licensed under **MIT** or **Apache-2.0** at your option.


## CLI
Build with CBOR compatibility:
```
cd impl/rust/ai-nrf1
cargo build --features compat_cbor --bin ai-nrf1
```
Examples:
```
# NRF → CBOR
cat sample.nrf | target/debug/ai-nrf1 canon --in nrf --out cbor > sample.cbor

# CBOR → NRF (strict subset)
cat sample.cbor | target/debug/ai-nrf1 canon --in cbor --out nrf > sample.nrf
```

- `specs/NRF-1.1-LLM-First.md` — why NRF is LLM-first
- `specs/NRF-1.1-Benefits.md` — practical advantages


## Quickstart
```bash
# Rust tests
cd impl/rust/ai-nrf1
cargo test

# CBOR interop & CLI (optional)
cargo build --features compat_cbor --bin ai-nrf1
echo -n -e '\x6e\x72\x66\x31\x00' | target/debug/ai-nrf1 canon --in nrf --out cbor > /dev/null
```

## Continuous Integration
GitHub Actions workflow runs core tests and compat_cbor tests on every push/PR.

## Community
- See `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `SECURITY.md`.

