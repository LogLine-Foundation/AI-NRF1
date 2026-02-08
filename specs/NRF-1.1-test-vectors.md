# NRF-1.1 Test Vectors (Hex)

## Valid (root includes magic `6E726631`)
- Null: `6E726631 00`
- True: `6E726631 02`
- Int 42: `6E726631 03 00000000 0000002A`
- Int −1: `6E726631 03 FFFFFFFFFFFFFFFF`
- Empty string: `6E726631 04 00`
- "hello": `6E726631 04 05 68 65 6C 6C 6F`
- Empty array: `6E726631 06 00`
- [true, 42]: `6E726631 06 02 02 03 00000000 0000002A`
- Empty map: `6E726631 07 00`
- Map {"name":"test","value":42}:
```
6E726631 07 02
04 04 6E616D65  04 04 74657374
04 05 76616C7565 03 00000000 0000002A
```

## Invalid (MUST reject)
- Wrong magic: `6E726632 00` → InvalidMagic
- Unknown type tag: `6E726631 08` → InvalidTypeTag
- Non-minimal varint (len 0 as 0x80 0x00): `6E726631 04 80 00` → NonMinimalVarint
- Duplicate key:
```
6E726631 07 02
04 01 61 02
04 01 61 01
```
→ DuplicateKey
- Unsorted keys:
```
6E726631 07 02
04 01 62 02
04 01 61 01
```
→ UnsortedKeys
- Truncated int: `6E726631 03 00000000 0000` → UnexpectedEOF
- Trailing data: `6E726631 00 FF` → TrailingData
