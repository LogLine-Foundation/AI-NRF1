# NRF-1.1 — Canonical Binary Encoding (No-Decisions)
Status: Stable • Scope: Wire format core

## 1. Goals
- Canonicality: same value ⇒ same bytes ⇒ same hash.
- Simplicity: 7 tags, zero choices.
- LLM-friendly: spec fits in a single context window.

## 2. Stream
`magic(4) + value` where magic = 0x6E 0x72 0x66 0x31 ("nrf1"). No trailing bytes allowed.

## 3. Types (1-byte tag)
00 Null | 01 False | 02 True | 03 Int64 (8B BE two’s complement)
04 String (varint32 len + UTF-8 NFC, no BOM)
05 Bytes (varint32 len + raw)
06 Array (varint32 count + N values)
07 Map (varint32 pairs + N (key,value)); keys are **String**, unique, sorted by raw UTF-8 bytes (unsigned, memcmp order).

## 4. Varint32
Unsigned LEB128 (1–5 bytes). **Minimal** encoding is REQUIRED; non-minimal is INVALID.
- Value 0..127: single byte `0xxxxxxx`
- Continuation: bit7=1 means more bytes follow.
- Reject encodings with redundant 0-continuations or more than 5 bytes.

## 5. Strings
- MUST be well-formed UTF‑8
- MUST be NFC normalized
- MUST NOT contain U+FEFF (BOM) anywhere
- `len` MUST match byte count of UTF‑8 payload

## 6. Canon law (hashing/signing)
- **All hashes and signatures are computed over NRF bytes.**
- Import from CBOR/JSON/etc ⇒ canonicalize to NRF first, then hash.
- ABNF in §10 defines the exact wire grammar.

## 7. Decoder MUST reject
InvalidMagic, InvalidTypeTag, NonMinimalVarint, InvalidUTF8, NotNFC, BOMPresent,
NonStringKey, UnsortedKeys, DuplicateKey, UnexpectedEOF, TrailingData.

## 8. Limits
Lengths/counts ≤ 2^32−1 (by varint32). Depth is implementation-defined (≥64 recommended).
Total stream size: implementation-defined caps recommended.

## 9. Test vectors
See /specs/NRF-1.1-test-vectors.md (valid/invalid hex).

## 10. ABNF (wire-level)
```
stream      = magic value
magic       = %x6E.72.66.31        ; "nrf1"

value       = null / false / true / int64 / string / bytes / array / map

null        = %x00
false       = %x01
true        = %x02
int64       = %x03 8OCTET          ; big-endian two’s complement
string      = %x04 varint32 *OCTET ; UTF-8 NFC, no BOM
bytes       = %x05 varint32 *OCTET
array       = %x06 varint32 *value
map         = %x07 varint32 *(string value)  ; keys sorted, unique

varint32    = 1*5leb128-byte       ; minimal form only
leb128-byte = OCTET                ; bit7 is continuation
```
