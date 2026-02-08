\
# NRF-1.1 JSON Mapping (Canonical, LLM-First)
*Version:* 1.1 • *Updated:* 2026-02-08

This document specifies the **single** JSON mapping profile used by the CLI (`nrf1 encode|decode`) and examples.
The intent is **zero choices** and reversibility for round trips JSON ↔ NRF-1.1.


## 1. Type Mapping (Normative)

| JSON form                              | NRF-1.1 type                  | Notes |
|----------------------------------------|-------------------------------|-------|
| `null`                                 | Null (`0x00`)                 | — |
| `true` / `false`                       | Bool (`0x02` / `0x01`)        | — |
| JSON integer `-2^63 .. 2^63-1`         | Int64 (`0x03`)                | Rejected if outside range or non-integer (e.g., `1.0`) |
| JSON number with fraction/exponent     | **Rejected**                  | Floats are disallowed in the core |
| JSON string `"..."`                    | String (`0x04`)               | MUST be valid UTF‑8 and NFC; BOM forbidden |
| JSON array `[ ... ]`                   | Array (`0x06`)                | Elements in order |
| JSON object `{{ "k": v, ... }}`        | Map (`0x07`)                  | Keys MUST be strings; ordering is canonicalized by UTF‑8 byte sort |
| JSON object `{{"$bytes":"<hex>"}}`     | Bytes (`0x05`)                | **The only accepted JSON form for bytes** |

**Bytes convention (only one):** JSON object with a **single** key `"$bytes"` and a **lowercase** hex string value with even length (`[0-9a-f]+`).\
Any other representation (base64, arrays of numbers, etc.) is **rejected** to maintain zero-choice canon.


## 2. Encoder Behavior (JSON → NRF)

- Reject if:
  - Any number is non-integer or out of `i64` range.
  - Any key is not a string.
  - Any string fails UTF‑8 or NFC (or contains U+FEFF).
  - `"$bytes"` object has extra keys, non-hex, odd length, or uppercase hex.
- For maps, key order in the input is ignored; the NRF encoding sorts by raw UTF‑8 bytes.
- All lengths/counts use **minimal varint32** encoding (see core spec).


## 3. Decoder Behavior (NRF → JSON)

- `Bytes` are **always** rendered as `{{"$bytes":"<hex-lower>"}}`.
- Other types map as the JSON types above; map output order is **not** specified (JSON has no canonical key order), but re-encoding preserves canonical NRF bytes.


## 4. Examples

### 4.1 Bytes
JSON → NRF:
```json
{{"$bytes":"48656c6c6f"}}
```
decodes to NRF:
```
05 05 48 65 6c 6c 6f
```

NRF (bytes "hello") → JSON:
```json
{{"$bytes":"48656c6c6f"}}
```

### 4.2 Mixed
```json
{{
  "name": "test",
  "payload": {{"$bytes":"00ff10"}},
  "vals": [1, null, true, {{"$bytes":"ab"}}]
}}
```
Produces an NRF map (`0x07`) with 3 pairs, keys sorted by UTF‑8 bytes.


## 5. Rationale

- Hex‑only bytes is **LLM‑friendly** and deterministic for humans/agents.
- Disallowing floats at the mapping layer aligns with NRF-1.1 core’s determinism.
- Returning bytes as `{{"$bytes":"hex"}}` avoids JSON string ambiguities or accidental transcoding.

**Unicode normalization version.** All NFC checks in NRF‑1.1 are defined against **Unicode 15.1**.
If a future Unicode revision introduces changes that would alter NFC outcomes, a new NRF minor version
(e.g., 1.2) MUST be used to adopt those changes. Implementations MUST treat non‑NFC strings as invalid,
and MUST NOT silently normalize input at decode time (reject instead). Encoders SHOULD normalize to NFC.
