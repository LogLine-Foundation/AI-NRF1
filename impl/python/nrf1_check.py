# nrf1_check.py — mini encoder/decoder NRF-1.1 (para cross-check em CI)
from __future__ import annotations
import struct
import unicodedata

MAGIC = b"nrf1"

T_NULL=0x00; T_FALSE=0x01; T_TRUE=0x02; T_INT64=0x03; T_STRING=0x04; T_BYTES=0x05; T_ARRAY=0x06; T_MAP=0x07

class NrfError(Exception): pass

def _enc_varint32(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFF:
        raise NrfError("varint32 out of range")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n == 0:
            out.append(b)
            break
        out.append(b | 0x80)
    return bytes(out)

def _dec_varint32(b: bytes, i: int) -> tuple[int,int]:
    res = 0
    shift = 0
    for idx in range(5):
        if i >= len(b): raise NrfError("UnexpectedEOF")
        byte = b[i]; i += 1
        if idx == 0 and byte == 0x80:
            raise NrfError("NonMinimalVarint")
        res |= (byte & 0x7F) << shift
        cont = (byte & 0x80) != 0
        shift += 7
        if not cont:
            return res, i
        if idx == 4:
            if (byte & 0x80) or (byte & 0xF0):
                raise NrfError("NonMinimalVarint")
            return res, i
    raise NrfError("NonMinimalVarint")

def _ensure_string_rules(s: str):
    if '\ufeff' in s:
        raise NrfError("BOMPresent")
    if unicodedata.normalize('NFC', s) != s:
        raise NrfError("NotNFC")

def encode(value) -> bytes:
    return MAGIC + _enc_value(value)

def _enc_value(v) -> bytes:
    if v is None:
        return bytes([T_NULL])
    if v is False:
        return bytes([T_FALSE])
    if v is True:
        return bytes([T_TRUE])
    if isinstance(v, int):
        return bytes([T_INT64]) + struct.pack(">q", v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        _ensure_string_rules(v)
        return bytes([T_STRING]) + _enc_varint32(len(b)) + b
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return bytes([T_BYTES]) + _enc_varint32(len(b)) + b
    if isinstance(v, list):
        parts = [bytes([T_ARRAY]), _enc_varint32(len(v))]
        parts += [_enc_value(x) for x in v]
        return b"".join(parts)
    if isinstance(v, dict):
        for k in v.keys():
            if not isinstance(k, str):
                raise NrfError("NonStringKey")
            _ensure_string_rules(k)
        items = []
        for k in sorted(v.keys(), key=lambda s: s.encode("utf-8")):
            kb = k.encode("utf-8")
            items.append(bytes([T_STRING]) + _enc_varint32(len(kb)) + kb)
            items.append(_enc_value(v[k]))
        return bytes([T_MAP]) + _enc_varint32(len(v)) + b"".join(items)
    raise TypeError("unsupported type")

def decode(b: bytes):
    if len(b) < 4 or b[:4] != MAGIC:
        raise NrfError("InvalidMagic")
    v, i = _dec_value(b, 4)
    if i != len(b):
        raise NrfError("TrailingData")
    return v

def _dec_value(b: bytes, i: int):
    if i >= len(b): raise NrfError("UnexpectedEOF")
    tag = b[i]; i += 1
    if tag == T_NULL: return None, i
    if tag == T_FALSE: return False, i
    if tag == T_TRUE: return True, i
    if tag == T_INT64:
        if i+8 > len(b): raise NrfError("UnexpectedEOF")
        n = struct.unpack(">q", b[i:i+8])[0]; i+=8
        return n, i
    if tag == T_STRING:
        n, i = _dec_varint32(b, i)
        if i+n > len(b): raise NrfError("UnexpectedEOF")
        s = b[i:i+n].decode("utf-8", "strict"); i += n
        _ensure_string_rules(s)
        return s, i
    if tag == T_BYTES:
        n, i = _dec_varint32(b, i)
        if i+n > len(b): raise NrfError("UnexpectedEOF")
        v = b[i:i+n]; i += n
        return v, i
    if tag == T_ARRAY:
        n, i = _dec_varint32(b, i)
        out = []
        for _ in range(n):
            x, i = _dec_value(b, i)
            out.append(x)
        return out, i
    if tag == T_MAP:
        n, i = _dec_varint32(b, i)
        prev = None
        out = {}
        for _ in range(n):
            if i >= len(b): raise NrfError("UnexpectedEOF")
            if b[i] != T_STRING: raise NrfError("NonStringKey")
            k, i = _dec_value(b, i)
            kb = k.encode("utf-8")
            if prev is not None:
                if kb == prev: raise NrfError("DuplicateKey")
                if kb < prev: raise NrfError("UnsortedKeys")
            prev = kb
            val, i = _dec_value(b, i)
            out[k] = val
        return out, i
    raise NrfError(f"InvalidTypeTag({hex(tag)})")

if __name__ == '__main__':
    v = {"name":"test","value":42}
    enc = encode(v)
    dec = decode(enc)
    assert v == dec
    print(enc.hex())
    print("OK")
