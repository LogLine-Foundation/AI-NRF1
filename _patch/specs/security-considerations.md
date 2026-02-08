# Security Considerations

## Unicode & Strings
- NFC normalization locks canonical form; reference Unicode 15.1. Future Unicode versions MAY introduce new compositions; encoders SHOULD pin the Unicode version to avoid drift.
- Reject BOM (U+FEFF) anywhere. Reject ill‑formed UTF‑8. Consider policy‑level constraints for confusables (homoglyph attacks).

## Hashing & Small Domains
- Hashing small enumerations does not provide privacy; attackers can brute‑force. Avoid hashing sensitive low‑entropy fields directly or salt at higher layers.

## Time & Timestamps
- Receipt timestamps reflect the signer’s clock. For strong claims, anchor receipt CID to an external time source (public ledger/notary).

## Determinism & Runtimes
- Policy runtimes MUST be pure/deterministic: no wall‑clock, no randomness (unless seeded and recorded), no environment variability.
