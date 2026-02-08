# NRF-1.1 Interoperability Guide (Informative)

**Rule of Rules:** the canonical hash/signature is **always** computed over **NRF-1.1 bytes**. Import/export exists for interoperability only.

## Import Profiles

### CBOR-NRF (strict subset)
- Allowed: `null`, `true/false`, **int (fits i64)**, **tstr** (UTF‑8 **NFC**, **no BOM**), **bstr**, `array`, `map`.
- Disallowed: floats, tags, indefinite/streaming (no `break`), semantic/date.
- Maps: keys must be `tstr`, **byte‑wise UTF‑8 order**, **no duplicates**.
- Map to NRF `Value`: `null→Null`, bool→`Bool`, int→`Int(i64)`, `tstr→String`, `bstr→Bytes`, etc.
- Error mapping: `NotNFC`, `BOMPresent`, `NonStringKey`, `UnsortedKeys`, `DuplicateKey`, `InvalidTypeTag`.

### MessagePack (strict subset)
- Allowed: `nil`, bool, **int64**, `str` (UTF‑8 **NFC**, **no BOM**), `bin`, `array`, `map`.
- Disallowed: floats, ext types.
- Maps: keys `str`, **byte order**, **no duplicates**.

### Bencode
- `int`→`Int`, `list`→`Array`, `dict`→`Map`.
- `byte-string`: if **UTF‑8 NFC no‑BOM** → `String`; otherwise **reject** (recommended) for keys, or map to `Bytes` for values if the integration allows.
- Dicts are already byte‑ordered; must verify no duplicates.

## Export Profiles
- **CBOR-NRF deterministic emitter** (optional) to serve CBOR‑only consumers, still computing the official hash over **NRF**.

## Test Vectors
Provide pairs `(input_format_bytes → NRF.Value → NRF.hex)` including both valid and rejection cases (non‑NFC, BOM, unordered maps, int out of range, floats/tags/indefinite).

## Security Notes
Limit sizes/depth, validate NFC/BOM strictly, fuzz decoders, reject non‑canonical encodings.
