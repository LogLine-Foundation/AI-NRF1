
import struct

MAGIC = b"nrf1"

TAG_NULL  = 0x00
TAG_FALSE = 0x01
TAG_TRUE  = 0x02
TAG_I64   = 0x03
TAG_STR   = 0x04
TAG_BYTES = 0x05
TAG_ARR   = 0x06
TAG_MAP   = 0x07

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

def _read_exact(b, off, n):
    if off + n > len(b):
        raise UnexpectedEOF()
    return b[off:off+n], off + n

def _decode_varint32(b, off):
    result = 0
    shift = 0
    for i in range(5):
        bs, off = _read_exact(b, off, 1)
        byte = bs[0]
        payload = byte & 0x7F
        if i > 0 and byte == 0x00:
            raise NonMinimalVarint()
        if i == 0 and byte == 0x80:
            raise NonMinimalVarint()
        result |= (payload << shift)
        if (byte & 0x80) == 0:
            return result, off
        shift += 7
    raise NonMinimalVarint()

def _encode_varint32(n: int) -> bytes:
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

def _is_nfc(s: str) -> bool:
    # Minimal NFC check without external deps: Python's unicodedata.normalize
    import unicodedata
    return s == unicodedata.normalize('NFC', s)

def _check_string_rules(s: str):
    if '\ufeff' in s:
        raise BOMPresent()
    if not _is_nfc(s):
        raise NotNFC()

def decode(data: bytes):
    off = 0
    m, off = _read_exact(data, off, 4)
    if m != MAGIC:
        raise InvalidMagic()
    value, off = _decode_value(data, off)
    if off != len(data):
        raise TrailingData()
    return value

def _decode_value(b, off):
    tagb, off = _read_exact(b, off, 1)
    tag = tagb[0]
    if tag == TAG_NULL:
        return None, off
    elif tag == TAG_FALSE:
        return False, off
    elif tag == TAG_TRUE:
        return True, off
    elif tag == TAG_I64:
        bs, off = _read_exact(b, off, 8)
        return struct.unpack(">q", bs)[0], off
    elif tag == TAG_STR:
        ln, off = _decode_varint32(b, off)
        bs, off = _read_exact(b, off, ln)
        try:
            s = bs.decode("utf-8")
        except UnicodeDecodeError:
            raise InvalidUTF8()
        _check_string_rules(s)
        return s, off
    elif tag == TAG_BYTES:
        ln, off = _decode_varint32(b, off)
        bs, off = _read_exact(b, off, ln)
        return {"$bytes": bs.hex()}, off
    elif tag == TAG_ARR:
        n, off = _decode_varint32(b, off)
        arr = []
        for _ in range(n):
            v, off = _decode_value(b, off)
            arr.append(v)
        return arr, off
    elif tag == TAG_MAP:
        n, off = _decode_varint32(b, off)
        prev = None
        m = {}
        for _ in range(n):
            # key must be a string
            tagb2, off = _read_exact(b, off, 1)
            if tagb2[0] != TAG_STR:
                raise NonStringKey()
            ln, off = _decode_varint32(b, off)
            kbs, off = _read_exact(b, off, ln)
            try:
                key = kbs.decode("utf-8")
            except UnicodeDecodeError:
                raise InvalidUTF8()
            _check_string_rules(key)
            if prev is not None:
                if prev == key:
                    raise DuplicateKey()
                if prev.encode("utf-8") > key.encode("utf-8"):
                    raise UnsortedKeys()
            prev = key
            v, off = _decode_value(b, off)
            if key in m:
                raise DuplicateKey()
            m[key] = v
        return m, off
    else:
        raise InvalidTypeTag(tag)

def encode(value):
    out = bytearray()
    out += MAGIC
    _encode_value(out, value)
    return bytes(out)

def _encode_value(out, v):
    import unicodedata
    if v is None:
        out.append(TAG_NULL)
    elif v is False:
        out.append(TAG_FALSE)
    elif v is True:
        out.append(TAG_TRUE)
    elif isinstance(v, bool):
        out.append(TAG_TRUE if v else TAG_FALSE)
    elif isinstance(v, int):
        out.append(TAG_I64)
        out += struct.pack(">q", int(v))
    elif isinstance(v, str):
        if '\ufeff' in v:
            raise BOMPresent()
        if not _is_nfc(v):
            raise NotNFC()
        out.append(TAG_STR)
        bs = v.encode("utf-8")
        out += _encode_varint32(len(bs))
        out += bs
    elif isinstance(v, dict) and set(v.keys()) == {"$bytes"} and isinstance(v["$bytes"], str):
        hx = v["$bytes"]
        # enforce lowercase even-length
        if any(c.isalpha() and c != c.lower() for c in hx):
            raise ValueError("bytes hex must be lowercase")
        if len(hx) % 2 != 0:
            raise ValueError("bytes hex length must be even")
        try:
            raw = bytes.fromhex(hx)
        except Exception:
            raise ValueError("invalid hex")
        out.append(TAG_BYTES)
        out += _encode_varint32(len(raw))
        out += raw
    elif isinstance(v, list):
        out.append(TAG_ARR)
        out += _encode_varint32(len(v))
        for it in v:
            _encode_value(out, it)
    elif isinstance(v, dict):
        out.append(TAG_MAP)
        # sort keys by raw UTF-8 bytes
        keys = list(v.keys())
        for k in keys:
            if not isinstance(k, str):
                raise NonStringKey()
            _check_string_rules(k)
        keys.sort(key=lambda s: s.encode("utf-8"))
        out += _encode_varint32(len(keys))
        last = None
        for k in keys:
            if last is not None and last == k:
                raise DuplicateKey()
            if last is not None and last.encode("utf-8") > k.encode("utf-8"):
                raise UnsortedKeys()
            last = k
            # key
            bs = k.encode("utf-8")
            out.append(TAG_STR)
            out += _encode_varint32(len(bs))
            out += bs
            # value
            _encode_value(out, v[k])
    else:
        raise TypeError(f"unsupported type: {type(v)}")
