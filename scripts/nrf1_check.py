
#!/usr/bin/env python3
"""
nrf1_check.py - Python reference checker for NRF-1.1

Usage:
  python scripts/nrf1_check.py              # runs over tests/vectors
  python scripts/nrf1_check.py <file.hex>   # checks a single hex vector
Exits non-zero on failure.
"""

import sys, os, glob, re, binascii, json, unicodedata
from dataclasses import dataclass
from typing import Tuple, List, Dict, Union

MAGIC = b"nrf1"

class Error(Exception): pass
class InvalidMagic(Error): pass
class InvalidTypeTag(Error): pass
class NonMinimalVarint(Error): pass
class UnexpectedEOF(Error): pass
class InvalidUTF8(Error): pass
class NotNFC(Error): pass
class BOMPresent(Error): pass
class NonStringKey(Error): pass
class UnsortedKeys(Error): pass
class DuplicateKey(Error): pass
class TrailingData(Error): pass

# ---- Value model ----
@dataclass
class VNull: pass
@dataclass
class VBool: v: bool
@dataclass
class VInt: v: int
@dataclass
class VString: s: str
@dataclass
class VBytes: b: bytes
@dataclass
class VArray: items: list
@dataclass
class VMap: pairs: Dict[str, 'Value']

Value = Union[VNull, VBool, VInt, VString, VBytes, VArray, VMap]

def read_varint32(buf: bytes, i: int) -> Tuple[int, int]:
    res = 0
    shift = 0
    for count in range(5):
        if i >= len(buf): raise UnexpectedEOF()
        b = buf[i]; i += 1
        payload = b & 0x7F
        # non-minimal rules
        if count == 0 and b == 0x80: raise NonMinimalVarint()
        if count > 0 and b == 0x00: raise NonMinimalVarint()
        res |= (payload << shift)
        shift += 7
        if (b & 0x80) == 0:
            return res, i
    raise NonMinimalVarint()

def write_varint32(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError("varint32 out of range")
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n == 0:
            out.append(byte)
            break
        out.append(0x80 | byte)
    return bytes(out)

def decode_value(buf: bytes, i: int) -> Tuple[Value, int]:
    if i >= len(buf): raise UnexpectedEOF()
    tag = buf[i]; i += 1
    if tag == 0x00: return VNull(), i
    if tag == 0x01: return VBool(False), i
    if tag == 0x02: return VBool(True), i
    if tag == 0x03:
        if i + 8 > len(buf): raise UnexpectedEOF()
        n = int.from_bytes(buf[i:i+8], 'big', signed=True)
        i += 8
        return VInt(n), i
    if tag == 0x04:
        ln, i = read_varint32(buf, i)
        if i + ln > len(buf): raise UnexpectedEOF()
        b = buf[i:i+ln]; i += ln
        try:
            s = b.decode('utf-8')
        except UnicodeDecodeError:
            raise InvalidUTF8()
        if '\ufeff' in s: raise BOMPresent()
        if unicodedata.normalize('NFC', s) != s:
            raise NotNFC()
        return VString(s), i
    if tag == 0x05:
        ln, i = read_varint32(buf, i)
        if i + ln > len(buf): raise UnexpectedEOF()
        b = buf[i:i+ln]; i += ln
        return VBytes(b), i
    if tag == 0x06:
        count, i = read_varint32(buf, i)
        items = []
        for _ in range(count):
            v, i = decode_value(buf, i)
            items.append(v)
        return VArray(items), i
    if tag == 0x07:
        count, i = read_varint32(buf, i)
        pairs = {}
        prev_key = None
        for _ in range(count):
            if i >= len(buf): raise UnexpectedEOF()
            key_tag = buf[i]; i += 1
            if key_tag != 0x04: raise NonStringKey()
            ln, i = read_varint32(buf, i)
            if i + ln > len(buf): raise UnexpectedEOF()
            kb = buf[i:i+ln]; i += ln
            try:
                ks = kb.decode('utf-8')
            except UnicodeDecodeError:
                raise InvalidUTF8()
            if '\ufeff' in ks: raise BOMPresent()
            if unicodedata.normalize('NFC', ks) != ks:
                raise NotNFC()
            if prev_key is not None:
                if prev_key == ks: raise DuplicateKey()
                if prev_key.encode('utf-8') > ks.encode('utf-8'):
                    raise UnsortedKeys()
            prev_key = ks
            val, i = decode_value(buf, i)
            if ks in pairs: raise DuplicateKey()
            pairs[ks] = val
        return VMap(pairs), i
    raise InvalidTypeTag(tag)

def encode_value(v: Value) -> bytes:
    out = bytearray()
    if isinstance(v, VNull):
        out.append(0x00)
    elif isinstance(v, VBool):
        out.append(0x02 if v.v else 0x01)
    elif isinstance(v, VInt):
        out.append(0x03); out += int(v.v).to_bytes(8, 'big', signed=True)
    elif isinstance(v, VString):
        out.append(0x04)
        b = v.s.encode('utf-8')
        if unicodedata.normalize('NFC', v.s) != v.s:
            raise NotNFC()
        if '\ufeff' in v.s: raise BOMPresent()
        out += write_varint32(len(b)); out += b
    elif isinstance(v, VBytes):
        out.append(0x05); out += write_varint32(len(v.b)); out += v.b
    elif isinstance(v, VArray):
        out.append(0x06); out += write_varint32(len(v.items))
        for it in v.items: out += encode_value(it)
    elif isinstance(v, VMap):
        out.append(0x07)
        keys = list(v.pairs.keys())
        # sort by raw UTF-8 bytes
        keys.sort(key=lambda k: k.encode('utf-8'))
        # assert strictly increasing and unique
        for i_k in range(1, len(keys)):
            if keys[i_k-1].encode('utf-8') >= keys[i_k].encode('utf-8'):
                raise UnsortedKeys()
        out += write_varint32(len(keys))
        for k in keys:
            kb = k.encode('utf-8')
            if unicodedata.normalize('NFC', k) != k:
                raise NotNFC()
            if '\ufeff' in k: raise BOMPresent()
            out.append(0x04); out += write_varint32(len(kb)); out += kb
            out += encode_value(v.pairs[k])
    else:
        raise Error("Unknown value type")
    return bytes(out)

def decode_stream(buf: bytes) -> Value:
    if len(buf) < 4: raise InvalidMagic()
    if buf[:4] != MAGIC: raise InvalidMagic()
    v, i = decode_value(buf, 4)
    if i != len(buf):
        raise TrailingData()
    return v

def encode_stream(v: Value) -> bytes:
    return MAGIC + encode_value(v)

def parse_hex_file(path: str) -> bytes:
    s = open(path, 'r', encoding='utf-8').read()
    hex_str = re.sub(r'[^0-9A-Fa-f]', '', s)
    if len(hex_str) % 2 != 0:
        raise ValueError("odd hex length in " + path)
    return binascii.unhexlify(hex_str)

def roundtrip_bytes(b: bytes) -> bytes:
    v = decode_stream(b)
    out = encode_stream(v)
    return out

def run_vectors(root: str) -> int:
    ok = 0; bad = 0
    valid = sorted(glob.glob(os.path.join(root, "valid", "*.hex")))
    invalid = sorted(glob.glob(os.path.join(root, "invalid", "*.hex")))
    # valid: must decode and re-encode to identical bytes
    for p in valid:
        b = parse_hex_file(p)
        try:
            out = roundtrip_bytes(b)
            if out != b:
                print(f"[FAIL] re-encode mismatch: {os.path.basename(p)}")
                bad += 1
            else:
                ok += 1
        except Exception as e:
            print(f"[FAIL] valid vector rejected: {os.path.basename(p)} -> {e.__class__.__name__}")
            bad += 1
    # invalid: must be rejected
    for p in invalid:
        b = parse_hex_file(p)
        try:
            _ = roundtrip_bytes(b)
            print(f"[FAIL] invalid vector accepted: {os.path.basename(p)}")
            bad += 1
        except Exception:
            ok += 1
    if bad:
        print(f"\nSummary: {ok} ok, {bad} failed")
        return 1
    print(f"\nSummary: {ok} ok, {bad} failed")
    return 0

def main():
    if len(sys.argv) == 2 and sys.argv[1].endswith(".hex"):
        b = parse_hex_file(sys.argv[1])
        try:
            out = roundtrip_bytes(b)
        except Exception as e:
            print(f"Rejected: {e.__class__.__name__}")
            sys.exit(1)
        if out != b:
            print("Mismatch after re-encode")
            sys.exit(1)
        print("OK")
        sys.exit(0)
    root = os.path.join("tests", "vectors")
    sys.exit(run_vectors(root))

if __name__ == "__main__":
    main()
