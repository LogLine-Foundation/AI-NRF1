use std::collections::BTreeMap;
use std::io;
/// Magic "nrf1"
pub const MAGIC: [u8; 4] = *b"nrf1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("InvalidMagic")]
    InvalidMagic,
    #[error("InvalidTypeTag({0:#04x})")]
    InvalidTypeTag(u8),
    #[error("NonMinimalVarint")]
    NonMinimalVarint,
    #[error("UnexpectedEOF")]
    UnexpectedEOF,
    #[error("InvalidUTF8")]
    InvalidUTF8,
    #[error("NotNFC")]
    NotNFC,
    #[error("BOMPresent")]
    BOMPresent,
    #[error("NonStringKey")]
    NonStringKey,
    #[error("UnsortedKeys")]
    UnsortedKeys,
    #[error("DuplicateKey")]
    DuplicateKey,
    #[error("TrailingData")]
    TrailingData,
    #[error("DepthExceeded")]
    DepthExceeded,
    #[error("SizeExceeded")]
    SizeExceeded,
    #[error("Io({0})")]
    Io(String),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Error::UnexpectedEOF
        } else {
            Error::Io(e.to_string())
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Encode value with magic prefix.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&MAGIC);
    encode_value(&mut buf, value);
    buf
}

fn encode_value(buf: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => buf.push(0x00),
        Value::Bool(false) => buf.push(0x01),
        Value::Bool(true) => buf.push(0x02),
        Value::Int(n) => {
            buf.push(0x03);
            buf.extend_from_slice(&n.to_be_bytes());
        }
        Value::String(s) => {
            buf.push(0x04);
            encode_varint32(buf, s.len() as u32);
            buf.extend_from_slice(s.as_bytes());
        }
        Value::Bytes(b) => {
            buf.push(0x05);
            encode_varint32(buf, b.len() as u32);
            buf.extend_from_slice(b);
        }
        Value::Array(items) => {
            buf.push(0x06);
            encode_varint32(buf, items.len() as u32);
            for it in items {
                encode_value(buf, it);
            }
        }
        Value::Map(m) => {
            buf.push(0x07);
            encode_varint32(buf, m.len() as u32);
            for (k, val) in m {
                // key is encoded as String
                buf.push(0x04);
                encode_varint32(buf, k.len() as u32);
                buf.extend_from_slice(k.as_bytes());
                encode_value(buf, val);
            }
        }
    }
}

/// Decode from full buffer (with magic) and reject trailing bytes.
pub fn decode(data: &[u8]) -> Result<Value> {
    if data.len() < 4 {
        return Err(Error::InvalidMagic);
    }
    if data[..4] != MAGIC {
        return Err(Error::InvalidMagic);
    }
    let mut cur = &data[4..];
    let v = decode_value(&mut cur, 0)?;
    if !cur.is_empty() {
        return Err(Error::TrailingData);
    }
    Ok(v)
}

const MAX_DEPTH_DEFAULT: usize = 256;

fn decode_value(cur: &mut &[u8], depth: usize) -> Result<Value> {
    if depth > MAX_DEPTH_DEFAULT {
        return Err(Error::DepthExceeded);
    }
    if cur.is_empty() {
        return Err(Error::UnexpectedEOF);
    }
    let tag = cur[0];
    *cur = &cur[1..];
    match tag {
        0x00 => Ok(Value::Null),
        0x01 => Ok(Value::Bool(false)),
        0x02 => Ok(Value::Bool(true)),
        0x03 => {
            if cur.len() < 8 {
                return Err(Error::UnexpectedEOF);
            }
            let (num, rest) = cur.split_at(8);
            *cur = rest;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(num);
            Ok(Value::Int(i64::from_be_bytes(arr)))
        }
        0x04 => {
            let len = decode_varint32(cur)? as usize;
            if cur.len() < len {
                return Err(Error::UnexpectedEOF);
            }
            let (bytes, rest) = cur.split_at(len);
            *cur = rest;
            let s = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUTF8)?;
            if s.chars().any(|c| c == '\u{FEFF}') {
                return Err(Error::BOMPresent);
            }
            if !unicode_normalization::is_nfc(s) {
                return Err(Error::NotNFC);
            }
            Ok(Value::String(s.to_string()))
        }
        0x05 => {
            let len = decode_varint32(cur)? as usize;
            if cur.len() < len {
                return Err(Error::UnexpectedEOF);
            }
            let (bytes, rest) = cur.split_at(len);
            *cur = rest;
            Ok(Value::Bytes(bytes.to_vec()))
        }
        0x06 => {
            let count = decode_varint32(cur)? as usize;
            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                v.push(decode_value(cur, depth + 1)?);
            }
            Ok(Value::Array(v))
        }
        0x07 => {
            let count = decode_varint32(cur)? as usize;
            let mut map = BTreeMap::new();
            let mut prev: Option<Vec<u8>> = None;
            for _ in 0..count {
                // key must be a string (0x04)
                if cur.is_empty() {
                    return Err(Error::UnexpectedEOF);
                }
                let key_tag = cur[0];
                *cur = &cur[1..];
                if key_tag != 0x04 {
                    return Err(Error::NonStringKey);
                }
                let klen = decode_varint32(cur)? as usize;
                if cur.len() < klen {
                    return Err(Error::UnexpectedEOF);
                }
                let (kbytes, rest) = cur.split_at(klen);
                *cur = rest;
                let kstr = std::str::from_utf8(kbytes).map_err(|_| Error::InvalidUTF8)?;
                if kstr.chars().any(|c| c == '\u{FEFF}') {
                    return Err(Error::BOMPresent);
                }
                if !unicode_normalization::is_nfc(kstr) {
                    return Err(Error::NotNFC);
                }
                if let Some(prevb) = prev.as_ref() {
                    match prevb.as_slice().cmp(kbytes) {
                        std::cmp::Ordering::Less => {}
                        std::cmp::Ordering::Equal => return Err(Error::DuplicateKey),
                        std::cmp::Ordering::Greater => return Err(Error::UnsortedKeys),
                    }
                }
                prev = Some(kbytes.to_vec());
                let val = decode_value(cur, depth + 1)?;
                map.insert(kstr.to_string(), val);
            }
            Ok(Value::Map(map))
        }
        _ => Err(Error::InvalidTypeTag(tag)),
    }
}

pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

pub fn hash_value(v: &Value) -> [u8; 32] {
    let bytes = encode(v);
    hash_bytes(&bytes)
}

// ----- varint32 (unsigned LEB128 minimal) -----

fn decode_varint32(cur: &mut &[u8]) -> Result<u32> {
    let mut result: u32 = 0;
    let mut shift = 0u32;
    for i in 0..5 {
        if cur.is_empty() {
            return Err(Error::UnexpectedEOF);
        }
        let byte = cur[0];
        *cur = &cur[1..];
        let payload = (byte & 0x7F) as u32;

        // First byte 0x80 => Non-minimal (0 with continuation)
        if i == 0 && byte == 0x80 {
            return Err(Error::NonMinimalVarint);
        }
        // Disallow 0x00 as a continuation byte (leading zero in base-128)
        if i > 0 && byte == 0x00 {
            return Err(Error::NonMinimalVarint);
        }

        result |= payload << shift;
        if (byte & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(Error::NonMinimalVarint)
}

fn encode_varint32(buf: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_simple() {
        let mut map = BTreeMap::new();
        map.insert("name".into(), Value::String("test".into()));
        map.insert("value".into(), Value::Int(42));
        let v = Value::Map(map);
        let enc = encode(&v);
        let dec = decode(&enc).unwrap();
        assert_eq!(v, dec);
        assert_eq!(enc, encode(&dec));
    }
}

// --- Fuzz-only exposure (feature: fuzz_expose) ---
#[cfg(feature = "fuzz_expose")]
pub fn _fuzz_decode_varint32(bytes: &[u8]) -> Result<u32> {
    use std::io::Read;
    let mut slice = bytes;
    // decode_varint32 takes &mut R: Read
    decode_varint32(&mut slice)
}
