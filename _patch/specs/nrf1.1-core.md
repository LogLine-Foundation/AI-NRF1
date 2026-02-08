# NRF‑1.1 Core Specification (Wire Format)

**Goal:** One logical value → one canonical byte sequence → one hash.

## 1. Stream Layout
```
+----------+--------+
| Magic(4) | Value  |
+----------+--------+
```
- Magic: ASCII `nrf1` = `0x6e 0x72 0x66 0x31`.
- Decoder MUST reject: wrong magic, empty stream, trailing data after the single root value.

## 2. Types and Tags
| Tag | Type   | Payload                                        |
|-----|--------|-------------------------------------------------|
| 00  | Null   | —                                               |
| 01  | False  | —                                               |
| 02  | True   | —                                               |
| 03  | Int64  | 8 bytes, two’s complement, **big‑endian**       |
| 04  | String | varint32 byte_length + UTF‑8 NFC bytes (no BOM) |
| 05  | Bytes  | varint32 byte_length + raw bytes                |
| 06  | Array  | varint32 count + N values                       |
| 07  | Map    | varint32 count + N key–value pairs              |

Unknown type tags (not 0x00–0x07) MUST be rejected.

## 3. varint32 (Unsigned LEB128, Minimal)
- 1–5 bytes, 7 bits data per byte, MSB=continuation.
- **Minimal encoding is REQUIRED.** Leading zero‑continuations are invalid (except value 0 → `0x00`). First byte `0x80` is invalid (non‑minimal zero).
- Decoders MUST reject encodings that use more bytes than minimal.

## 4. String
- UTF‑8, **NFC normalized** (Unicode 15.1).
- **Forbidden:** any U+FEFF (BOM) at any position; ill‑formed UTF‑8.
- `byte_length` MUST equal the exact number of following bytes.

## 5. Map
- Keys are **Strings** (type tag `0x04`), otherwise **reject** (`NonStringKey`).
- Keys MUST be **sorted by raw UTF‑8 bytes** (unsigned lexicographic). Duplicate keys are **reject**.
- Map encodes as: `0x07` + count + (key value){count}.

## 6. Canonicality
- Fixed Int64 eliminates integer width ambiguity.
- Minimal varint32 forbids padding.
- Strings are NFC; maps are sorted and unique.
- Therefore: byte‑identity == logical identity.

## 7. Errors (normative)
`InvalidMagic`, `InvalidTypeTag`, `NonMinimalVarint`, `UnexpectedEOF`, `InvalidUTF8`, `NotNFC`, `BOMPresent`, `NonStringKey`, `UnsortedKeys`, `DuplicateKey`, `TrailingData`.

## 8. Interop Rule (normative)
**Hash is ALWAYS computed over NRF‑1.1 bytes.** Importers from JSON/CBOR/MsgPack MUST fail on values not representable in NRF (e.g., floats).

## 9. ABNF‑like Grammar
```
stream     = magic value
magic      = %x6E.72.66.31
value      = null / false / true / int64 / string / bytes / array / map
null       = %x00
false      = %x01
true       = %x02
int64      = %x03 8OCTET
string     = %x04 varint32 *OCTET      ; UTF‑8 NFC, no BOM
bytes      = %x05 varint32 *OCTET
array      = %x06 varint32 *value
map        = %x07 varint32 *(string value) ; keys sorted, unique
```
