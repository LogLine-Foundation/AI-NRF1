# Conformance Vectors

This folder contains **golden hex** NRF-1.1 streams (include magic `6e726631`).

- `valid/*.hex` — must **round-trip** byte-identically.
- `invalid/*.hex` — must be **rejected** by the decoder.

Source of truth: `specs/nrf1.1-core.md §8 Test Vectors`.
