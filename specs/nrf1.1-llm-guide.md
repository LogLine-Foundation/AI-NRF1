# NRF‑1.1 — LLM Guide (Pocket Edition)
_Update: 2026-02-08 18:26:02Z_

This pocket guide gives **copy‑pasteable** examples an LLM can follow to **emit** and **audit** NRF‑1.1 bytes.
All examples use the **magic** `6E 72 66 31` (`"nrf1"`) followed by exactly one value.

---

## 1) JSON → NRF (canonical hex)

Below are **canonical** encodings. If your output differs by even one byte, it’s non‑canonical.

### J→H‑01 — `null`
```
JSON:
null

NRF‑hex:
6E726631 00
```

### J→H‑02 — `true`
```
JSON:
true

NRF‑hex:
6E726631 02
```

### J→H‑03 — integer `42`
```
JSON:
42

NRF‑hex:
6E726631 03 00000000 0000002A
```

### J→H‑04 — string `"hello"`
```
JSON:
"hello"

NRF‑hex:
6E726631 04 05 68656C6C6F
```

### J→H‑05 — array `[true, 42]`
```
JSON:
[ true, 42 ]

NRF‑hex:
6E726631 06 02  02  03 00000000 0000002A
```

### (bonus) J→H‑06 — map `{"name":"test","value":42}`
```
JSON:
{ "name": "test", "value": 42 }

NRF‑hex:
6E726631 07 02
  04 04 6E616D65      # "name"
  04 04 74657374      # "test"
  04 05 76616C7565    # "value"
  03 00000000 0000002A
```

### (bonus) J→H‑07 — nested `{"a":[1,{"b":null}]}`
```
JSON:
{ "a": [1, { "b": null } ] }

NRF‑hex:
6E726631 07 01
  04 01 61          # "a"
  06 02             # array(2)
    03 00000000 00000001
    07 01           # map(1)
      04 01 62      # "b"
      00            # null
```

---

## 2) NRF (hex) → Tree (human view)

Given NRF‑hex, reconstruct the logical value. The **type tags** are:
`00=null, 01=false, 02=true, 03=int64, 04=string, 05=bytes, 06=array, 07=map`.

### H→T‑01 — `6E726631 00`
```
Value: null
```

### H→T‑02 — `6E726631 02`
```
Value: true
```

### H→T‑03 — `6E726631 03 000000000000002A`
```
Value: 42
(03 = Int64, big‑endian two’s complement, 8 bytes)
```

### H→T‑04 — `6E726631 04 05 68656C6C6F`
```
Value: "hello"
(04 = String, varint32 length=0x05=5, then UTF‑8 bytes)
```

### H→T‑05 — `6E726631 07 02  04 04 6E616D65  04 04 74657374  04 05 76616C7565  03 000000000000002A`
```
Value:
{
  "name": "test",
  "value": 42
}
(Keys are strings, sorted by raw UTF‑8 bytes; here "name" (0x6E…) < "value" (0x76…))
```

---

## 3) Canon rules an LLM MUST obey

1. **Exactly one encoding per value.** No alternatives.
2. **Int64 only:** 8‑byte, big‑endian two’s complement (tag `03`).
3. **varint32 = minimal.** Never emit non‑minimal forms (e.g., `8000` for zero).
4. **Strings:** valid UTF‑8, **NFC**, **no U+FEFF** anywhere.
5. **Maps:** keys **must** be strings, **sorted** by raw UTF‑8 bytes, and **unique**.
6. **No trailing bytes** after the root value.
7. **Magic first:** `6E 72 66 31`.

---

## 4) Quick self‑checks (no runtime)

- Count the **array/map lengths** against the number of child values you actually emit.
- Re‑encode integers as exactly **8 bytes**; negative `-1` is `FF…FF` (8×).
- For strings, verify NFC by re‑composing (e.g., “é” must be single code point U+00E9, not `65 CC 81`).

---

## 5) Minimal prompts

**Encode JSON → NRF‑hex**  
“Given JSON X, output the NRF‑1.1 hex: start with `6E726631`, then exactly one value using the tags above. varint32 must be minimal; strings UTF‑8 NFC; maps sorted, unique keys. Output only uppercase hex with spaces as in the examples.”

**Decode NRF‑hex → tree**  
“Given NRF‑1.1 hex, parse `6E726631`, then the tag. Show the logical value. If non‑minimal varint, non‑string key in map, unsorted/duplicate keys, invalid UTF‑8/NFC, or trailing data: respond `INVALID(<ErrorName>)`.”

---

### Appendix: Error names
`InvalidMagic, InvalidTypeTag, NonMinimalVarint, UnexpectedEOF, InvalidUTF8, NotNFC, BOMPresent, NonStringKey, UnsortedKeys, DuplicateKey, TrailingData`

> These examples correspond 1‑to‑1 with the **conformance vectors** in `tests/vectors/`.
