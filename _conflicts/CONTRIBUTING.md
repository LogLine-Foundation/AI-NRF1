# Contributing to NRF-1.1

Thanks for helping! 🎉

## Getting started
- Rust: `cd impl/rust/ai-nrf1 && cargo test`
- Python cross-check: `python impl/python/nrf1_check.py`

## Feature flags
- `compat_cbor`: enable CBOR import/export (strict subset) and `nrf1` CLI conversions.
  - Build: `cargo build --features compat_cbor --bin ai-nrf1`

## Coding guidelines
- Keep the **core small and strict** — zero-choice behavior is non-negotiable.
- Favor **explicit errors** over silent coercions.
- Add **round-trip** and **canonicality** tests for every change.
- When adding interop, treat it as **strict subsets** with clear rejections.

## Versioning
- Spec version: `specs/NRF-1.1-spec.md` (normative).
- Crate version uses SemVer; bump **minor** for new features, **patch** for fixes.

## Commit hygiene
- Conventional commits recommended: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.

## PR checklist
- [ ] Tests added/updated (Rust).
- [ ] Interop vectors (when relevant).
- [ ] README/specs updated (if needed).
