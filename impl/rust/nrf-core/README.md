# nrf-core

Reference implementation of **NRF-1.1** canonical encoding.

- 7 types, single encoding each
- Int64 (8 bytes, big-endian)
- Strings: UTF-8, NFC, no BOM
- varint32 (unsigned LEB128) with **minimal** encoding
- Maps: string keys only, **sorted** by raw UTF-8 bytes, **unique**
- Magic `nrf1` prefix, single root value, no trailing bytes

## Hashing
Use `hash_value(&Value)` or `hash_bytes(&[u8])`.
Hash is computed over **full NRF bytes**, including the magic prefix.
