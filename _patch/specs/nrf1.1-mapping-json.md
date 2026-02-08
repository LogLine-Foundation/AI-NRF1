# Mapping JSON ↔ NRF‑1.1 (Normative, Import‑Only)

## Scope
- JSON → NRF is **strict**. Any JSON value not representable in NRF MUST fail.
- NRF → JSON is faithful except that Bytes become base64 strings with a `"__bytes__"` wrapper (or map to hex if explicitly requested).

## Mapping
- `null` → `Null`
- `true/false` → `True/False`
- JSON numbers:
  - MUST be integers in range [−2^63, 2^63−1] with no leading zeros (except 0).
  - Encoded as `Int64`. Non‑integers (floats, exponent forms) MUST be rejected.
- JSON strings:
  - MUST be valid UTF‑8 and NFC; otherwise reject.
  - Encoded as `String` (tag 0x04).
- JSON arrays → `Array`
- JSON objects:
  - Keys MUST be strings meeting NFC/BOM rules.
  - Encoder MUST sort keys by raw UTF‑8 bytes and reject duplicates.

## Examples
- JSON `{ "a": 1 }` → NRF: `07 01 04 01 61 03 00 00 00 00 00 00 00 01` (excluding magic).
- JSON `{ "x": 1.0 }` → **Reject** (float).
