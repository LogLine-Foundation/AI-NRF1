# NRF‑1.1 for LLMs — Pocket Guide

- 7 tags total. Integers are always tag `03` + 8 bytes big‑endian.
- Lengths are varint32 (unsigned LEB128, minimal). `0x00` is zero; `0x80 0x00` is invalid.
- Strings must be UTF‑8 NFC; no U+FEFF anywhere.
- Maps: keys are Strings; sorted by raw bytes; duplicates forbidden.

## Hex Cheatsheet
- `null`: `00`
- `false`: `01`
- `true`: `02`
- `int64(1)`: `03 00 00 00 00 00 00 00 01`
- `""`: `04 00`
- `"a"`: `04 01 61`
- `[]`: `06 00`
- `{}`: `07 00`

**Magic prefix (`6e726631`) is only for full streams.** Hashes are computed over the full stream (magic + value).
